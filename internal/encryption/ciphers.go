package encryption

import (
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/Picocrypt/serpent"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/sha3"
)

const resetNonceAt = int64(60 * (1 << 30))

type nonceManager interface {
	nonce(i int) ([24]byte, error)
}

type ivManager interface {
	iv(i int) ([16]byte, error)
}

type nonceIvManager struct {
	chachaNonces [][24]byte
	serpentIVs   [][16]byte
	seeds        *seeds
	hkdf         io.Reader
}

func (nm *nonceIvManager) extendTo(i int) error {
	if len(nm.chachaNonces) == 0 {
		nm.chachaNonces = [][24]byte{nm.seeds.Nonce}
		nm.serpentIVs = [][16]byte{nm.seeds.SerpentIV}
	}
	for i >= len(nm.chachaNonces) {
		chachaNonce := [24]byte{}
		serpentIV := [16]byte{}
		_, err := io.ReadFull(nm.hkdf, chachaNonce[:])
		if err != nil {
			return err
		}
		_, err = io.ReadFull(nm.hkdf, serpentIV[:])
		if err != nil {
			return err
		}
		nm.chachaNonces = append(nm.chachaNonces, chachaNonce)
		nm.serpentIVs = append(nm.serpentIVs, serpentIV)
	}
	return nil
}

func (nm *nonceIvManager) nonce(i int) ([24]byte, error) {
	err := nm.extendTo(i)
	if err != nil {
		return [24]byte{}, err
	}
	return nm.chachaNonces[i], nil
}

func (nm *nonceIvManager) iv(i int) ([16]byte, error) {
	err := nm.extendTo(i)
	if err != nil {
		return [16]byte{}, err
	}
	return nm.serpentIVs[i], nil
}

func newNonceManager(hkdf io.Reader, seeds *seeds) *nonceIvManager {
	nm := &nonceIvManager{
		seeds: seeds,
		hkdf:  hkdf,
	}
	return nm
}

type denyNonceManager struct {
	nonces [][24]byte
	header *header
}

func (dnm *denyNonceManager) extendTo(i int) error {
	if len(dnm.nonces) == 0 {
		dnm.nonces = append(dnm.nonces, dnm.header.seeds.DenyNonce)
	}
	for i >= len(dnm.nonces) {
		previous := dnm.nonces[len(dnm.nonces)-1]
		tmp := sha3.New256()
		_, err := tmp.Write(previous[:])
		if err != nil {
			return err
		}
		nonce := [24]byte{}
		copy(nonce[:], tmp.Sum(nil))
		dnm.nonces = append(dnm.nonces, nonce)
	}
	return nil
}

func (dnm *denyNonceManager) nonce(i int) ([24]byte, error) {
	err := dnm.extendTo(i)
	if err != nil {
		return [24]byte{}, err
	}
	return dnm.nonces[i], nil
}

type serpentCipher struct {
	serpentBlock cipher.Block
	cipher       cipher.Stream
	ivManager    ivManager
	header       *header
}

func (sc *serpentCipher) reset(i int) error {
	serpentIV, err := sc.ivManager.iv(i)
	if err != nil {
		return err
	}
	sc.cipher = cipher.NewCTR(sc.serpentBlock, serpentIV[:])
	return nil
}

func (sc *serpentCipher) xor(p []byte) {
	sc.cipher.XORKeyStream(p, p)
}

type chachaCipher struct {
	cipher       *chacha20.Cipher
	nonceManager nonceManager
	key          []byte
}

func (cc *chachaCipher) reset(i int) error {
	nonce, err := cc.nonceManager.nonce(i)
	if err != nil {
		return err
	}
	cc.cipher, err = chacha20.NewUnauthenticatedCipher(cc.key[:], nonce[:])
	return err
}

func (cc *chachaCipher) xor(p []byte) {
	cc.cipher.XORKeyStream(p, p)
}

type xorCipher interface {
	xor(p []byte)
	reset(i int) error
}

type rotatingCipher struct {
	xorCipher
	writtenCounter int64
	resetCounter   int
	initialised    bool
}

func (rc *rotatingCipher) stream(p []byte) ([]byte, error) {
	if !rc.initialised {
		err := rc.xorCipher.reset(0)
		if err != nil {
			return nil, err
		}
		rc.initialised = true
	}
	i := int64(0)
	for i < int64(len(p)) {
		j := int64(len(p)) - i
		if j > (resetNonceAt - rc.writtenCounter) {
			j = resetNonceAt - rc.writtenCounter
		}
		rc.xor(p[i : i+j])
		rc.writtenCounter += j
		if rc.writtenCounter == resetNonceAt {
			rc.writtenCounter = 0
			rc.resetCounter++
			err := rc.reset(rc.resetCounter)
			if err != nil {
				return nil, err
			}
		}
		i += j
	}
	return p, nil
}

func (rc *rotatingCipher) flush() ([]byte, error) {
	return nil, nil
}

func newDeniabilityStream(password string, header *header) streamerFlusher {
	nonceManager := denyNonceManager{header: header}
	denyKey := generateDenyKey(password, header.seeds.DenySalt)
	return &rotatingCipher{
		xorCipher: &chachaCipher{
			nonceManager: &nonceManager,
			key:          denyKey[:],
		},
	}
}

func newEncryptionStreams(keys keys, header *header) ([]streamerFlusher, error) {
	nonceIvManager := newNonceManager(keys.hkdf, &(header.seeds))
	chachaStream := &rotatingCipher{
		xorCipher: &chachaCipher{
			nonceManager: nonceIvManager,
			key:          keys.key[:],
		},
	}
	if !header.settings.Paranoid {
		return []streamerFlusher{chachaStream}, nil
	}
	sb, err := serpent.NewCipher(keys.serpentKey[:])
	if err != nil {
		return nil, fmt.Errorf("creating serpent cipher: %w", err)
	}
	serpentStream := &rotatingCipher{
		xorCipher: &serpentCipher{
			serpentBlock: sb,
			ivManager:    nonceIvManager,
			header:       header,
			cipher:       nil, // will be set during streaming
		},
	}
	return []streamerFlusher{chachaStream, serpentStream}, nil
}
