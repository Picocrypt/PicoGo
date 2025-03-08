package encryption

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

type keys struct {
	key        [32]byte
	macKey     [32]byte
	serpentKey [32]byte
	denyKey    [32]byte
	hkdf       io.Reader
	keyRef     [64]byte
	keyfileRef [32]byte
}

func xor(a, b [32]byte) [32]byte {
	var result [32]byte
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func generateKeyfileKey(ordered bool, keyfiles []io.Reader) ([32]byte, error) {
	if len(keyfiles) == 0 {
		return [32]byte{}, nil
	}

	hashes := make([][32]byte, len(keyfiles))
	hasher := sha3.New256()
	for i, file := range keyfiles {
		if err := computeHash(hasher, file, hashes[i][:]); err != nil {
			return [32]byte{}, err
		}
		if !ordered {
			hasher.Reset()
		}
	}

	if ordered {
		key := [32]byte{}
		copy(key[:], hasher.Sum(nil))
		return key, nil
	}

	key := [32]byte{}
	for _, hash := range hashes {
		key = xor(key, hash)
	}
	if hasDuplicates(hashes) {
		return key, ErrDuplicateKeyfiles
	}
	return key, nil
}

func hasDuplicates(hashes [][32]byte) bool {
	hashSet := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		hashStr := string(hash[:])
		if _, exists := hashSet[hashStr]; exists {
			return true
		}
		hashSet[hashStr] = struct{}{}
	}
	return false
}

func argon2IDKey(password string, salt [16]byte, iterations uint32, parallelism uint8) [32]byte {
	var key [32]byte
	copy(key[:], argon2.IDKey([]byte(password), salt[:], iterations, 1<<20, parallelism, 32))
	return key
}

var argonKey = argon2IDKey

func generatePasswordKey(password string, salt [16]byte, paranoid bool) [32]byte {
	iterations := uint32(4)
	parallelism := uint8(4)
	if paranoid {
		iterations = 8
		parallelism = 8
	}
	return argonKey(password, salt, iterations, parallelism)
}

func generateDenyKey(password string, salt [16]byte) [32]byte {
	return argonKey(password, salt, 4, 4)
}

func newKeys(settings Settings, seeds seeds, password string, keyfiles []io.Reader) (keys, error) {
	keyfileKey, err := generateKeyfileKey(settings.OrderedKf, keyfiles)
	if err != nil && !errors.Is(err, ErrDuplicateKeyfiles) {
		return keys{}, fmt.Errorf("creating keys: %w", err)
	}
	duplicateKeyfiles := errors.Is(err, ErrDuplicateKeyfiles)

	passwordKey := generatePasswordKey(password, seeds.Salt, settings.Paranoid)

	var keyRef [64]byte
	err = computeHash(sha3.New512(), bytes.NewBuffer(passwordKey[:]), keyRef[:])
	if err != nil {
		return keys{}, fmt.Errorf("creating keys: %w", err)
	}
	var keyfileRef [32]byte
	if len(keyfiles) > 0 {
		computeHash(sha3.New256(), bytes.NewBuffer(keyfileKey[:]), keyfileRef[:])
	}

	key := xor(keyfileKey, passwordKey)

	var denyKey [32]byte
	if settings.Deniability {
		denyKey = generateDenyKey(password, seeds.DenySalt)
	}

	hkdf := hkdf.New(sha3.New256, key[:], seeds.HkdfSalt[:], nil)
	var macKey [32]byte
	if _, err := io.ReadFull(hkdf, macKey[:]); err != nil {
		return keys{}, fmt.Errorf("filling macKey: %w", err)
	}
	var serpentKey [32]byte
	if _, err := io.ReadFull(hkdf, serpentKey[:]); err != nil {
		return keys{}, fmt.Errorf("filling serpentKey: %w", err)
	}

	keys := keys{
		key:        key,
		macKey:     macKey,
		serpentKey: serpentKey,
		denyKey:    denyKey,
		hkdf:       hkdf,
		keyRef:     keyRef,
		keyfileRef: keyfileRef,
	}

	if duplicateKeyfiles {
		return keys, ErrDuplicateKeyfiles
	}
	return keys, nil
}

func computeHash(hasher hash.Hash, src io.Reader, dest []byte) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("reading src: %w", err)
	}
	_, err = hasher.Write(data)
	if err != nil {
		return fmt.Errorf("hashing src: %w", err)
	}
	copy(dest, hasher.Sum(nil))
	return nil
}
