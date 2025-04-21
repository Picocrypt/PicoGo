package encryption

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"testing"
)

func TestFileTooShort(t *testing.T) {
	argonKey = argon2IDKey
	for size := range []int{0, 10} {
		invalidData := make([]byte, size)
		_, err := rand.Read(invalidData)
		if err != nil {
			t.Fatal("creating random data:", err)
		}
		_, err = Decrypt("password", []io.Reader{}, bytes.NewBuffer(invalidData), bytes.NewBuffer([]byte{}), false, nil)
		if !errors.Is(err, ErrFileTooShort) {
			t.Fatal("expected ErrFileTooShort, got", err)
		}
	}
}

func TestHeaderCorrupted(t *testing.T) {
	argonKey = argon2IDKey
	invalidData := make([]byte, 1000)
	_, err := rand.Read(invalidData)
	if err != nil {
		t.Fatal("creating random data:", err)
	}
	_, err = Decrypt("password", []io.Reader{}, bytes.NewBuffer(invalidData), bytes.NewBuffer([]byte{}), false, nil)
	if !errors.Is(err, ErrHeaderCorrupted) {
		t.Fatal("expected ErrHeaderCorrupted, got", err)
	}
}

func TestIncorrectPassword(t *testing.T) {
	argonKey = argon2IDKey
	reader, err := os.Open("picocrypt_samples/v1.48/base1000.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	_, err = Decrypt("wrong-password", []io.Reader{}, reader, bytes.NewBuffer([]byte{}), false, nil)
	if !errors.Is(err, ErrIncorrectPassword) {
		t.Fatal("expected wrong password, got", err)
	}
}

func TestIncorrectKeyfiles(t *testing.T) {
	argonKey = argon2IDKey
	reader, err := os.Open("picocrypt_samples/v1.48/base0_kf12o.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	wrongKeyfileData := make([]byte, 100)
	rand.Read(wrongKeyfileData)
	defer reader.Close()
	_, err = Decrypt("password", []io.Reader{bytes.NewBuffer(wrongKeyfileData)}, reader, bytes.NewBuffer([]byte{}), false, nil)
	if !errors.Is(err, ErrIncorrectOrMisorderedKeyfiles) {
		t.Fatal("expected wrong keyfieles, got", err)
	}
}

func TestKeyfilesRequired(t *testing.T) {
	argonKey = argon2IDKey
	reader, err := os.Open("picocrypt_samples/v1.48/base0_kf12o.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	_, err = Decrypt("password", []io.Reader{}, reader, bytes.NewBuffer([]byte{}), false, nil)
	if !errors.Is(err, ErrKeyfilesRequired) {
		t.Fatal("expected required keyfiles, got", err)
	}
}

func TestDuplicateKeyfiles(t *testing.T) {
	argonKey = argon2IDKey
	keyfileData := make([]byte, 100)
	rand.Read(keyfileData)
	keyfiles := []io.Reader{}
	for range 2 {
		buff := make([]byte, len(keyfileData))
		copy(buff, keyfileData)
		keyfiles = append(keyfiles, bytes.NewBuffer(buff))
	}
	_, err := EncryptHeadless(
		bytes.NewBuffer([]byte{}),
		"test-password",
		keyfiles,
		Settings{},
		bytes.NewBuffer([]byte{}),
		nil,
	)
	if !errors.Is(err, ErrDuplicateKeyfiles) {
		t.Fatal("expected ErrDuplicateKeyfiles, got", err)
	}
}

func TestKeyfilesNotRequired(t *testing.T) {
	argonKey = argon2IDKey
	reader, err := os.Open("picocrypt_samples/v1.48/base1000.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	_, err = Decrypt("password", []io.Reader{bytes.NewBuffer([]byte{})}, reader, bytes.NewBuffer([]byte{}), false, nil)
	if !errors.Is(err, ErrKeyfilesNotRequired) {
		t.Fatal("expected ErrKeyfilesNotRequired, got", err)
	}
}

func TestCorrupted(t *testing.T) {
	argonKey = argon2IDKey
	reader, err := os.Open("picocrypt_samples/v1.48/base1000.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	r := bytes.NewBuffer([]byte{})
	_, err = io.Copy(r, reader)
	if err != nil {
		t.Fatal("reading file:", err)
	}
	rawBytes := r.Bytes()
	copy(rawBytes[:], []byte("corrupted"))
	corruptedReader := bytes.NewBuffer(rawBytes)
	_, err = Decrypt("qwerty", []io.Reader{}, corruptedReader, bytes.NewBuffer([]byte{}), false, nil)
	if !errors.Is(err, ErrHeaderCorrupted) {
		t.Fatal("expected ErrHeaderCorrupted, got", err)
	}
}

func TestDamagedButRecoverable(t *testing.T) {
	argonKey = argon2IDKey
	reader, err := os.Open("picocrypt_samples/v1.48/base1000_r.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()

	encryptedData, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal("reading file:", err)
	}

	encryptedData[1000] = byte(int(encryptedData[1000]) + 1)

	damaged, err := Decrypt("password", []io.Reader{}, bytes.NewBuffer(encryptedData), bytes.NewBuffer([]byte{}), false, nil)
	if err != nil {
		t.Fatal("expected no error, got", err)
	}
	if !damaged {
		t.Fatal("expected damage")
	}
}

func TestCommentsTooLong(t *testing.T) {
	argonKey = argon2IDKey
	comments := make([]byte, maxCommentsLength+1)
	_, err := EncryptHeadless(
		bytes.NewBuffer([]byte{}),
		"test-password",
		[]io.Reader{},
		Settings{Comments: string(comments)},
		bytes.NewBuffer([]byte{}),
		nil,
	)
	if !errors.Is(err, ErrCommentsTooLong) {
		t.Fatal("expected ErrCommentsTooLong, got", err)
	}
}
