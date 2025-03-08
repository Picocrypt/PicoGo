package encryption

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestXor(t *testing.T) {
	zeros := [32]byte{}
	ones := [32]byte{}
	for i := 0; i < len(ones); i++ {
		ones[i] = 255
	}

	result := xor(zeros, zeros)
	if !bytes.Equal(zeros[:], result[:]) {
		t.Fatal("xor zeros with zeros should be zero")
	}

	result = xor(ones, ones)
	if !bytes.Equal(zeros[:], result[:]) {
		t.Fatal("xor ones with ones should be zero")
	}

	result = xor(zeros, ones)
	if !bytes.Equal(ones[:], result[:]) {
		t.Fatal("xor zeros with ones should be ones")
	}

	result = xor(ones, zeros)
	if !bytes.Equal(ones[:], result[:]) {
		t.Fatal("xor ones with zeros should be zero")
	}
}

func TestGenKeyfileKeyOrdered(t *testing.T) {
	kf1 := make([]byte, 100)
	rand.Read(kf1)
	kf2 := make([]byte, 200)
	rand.Read(kf2)

	kf12 := []io.Reader{bytes.NewBuffer(kf1), bytes.NewBuffer(kf2)}
	key12, err := generateKeyfileKey(true, kf12)
	if err != nil {
		t.Fatal("generating keyfile key:", err)
	}

	kf21 := []io.Reader{bytes.NewBuffer(kf2), bytes.NewBuffer(kf1)}
	key21, err := generateKeyfileKey(true, kf21)
	if err != nil {
		t.Fatal("generating keyfile key:", err)
	}

	if bytes.Equal(key12[:], key21[:]) {
		t.Fatal("key order should change result")
	}
}

func TestGenKeyfileKeyUnordered(t *testing.T) {
	kf1 := make([]byte, 100)
	rand.Read(kf1)
	kf2 := make([]byte, 200)
	rand.Read(kf2)

	kf12 := []io.Reader{bytes.NewBuffer(kf1), bytes.NewBuffer(kf2)}
	key12, err := generateKeyfileKey(false, kf12)
	if err != nil {
		t.Fatal("generating keyfile key:", err)
	}

	kf21 := []io.Reader{bytes.NewBuffer(kf2), bytes.NewBuffer(kf1)}
	key21, err := generateKeyfileKey(false, kf21)
	if err != nil {
		t.Fatal("generating keyfile key:", err)
	}

	if !bytes.Equal(key12[:], key21[:]) {
		t.Fatal("key order should not change result")
	}
}

func TestGenKeyfileKeyDuplicated(t *testing.T) {
	kf1 := make([]byte, 100)
	kf2 := make([]byte, 100)
	kf3 := make([]byte, 100)
	rand.Read(kf1)
	copy(kf2[:], kf1[:])
	rand.Read(kf3)
	key, err := generateKeyfileKey(
		false,
		[]io.Reader{bytes.NewBuffer(kf1), bytes.NewBuffer(kf2), bytes.NewBuffer(kf3)},
	)
	if !errors.Is(err, ErrDuplicateKeyfiles) {
		t.Fatal("expected duplicate keyfile error")
	}
	if bytes.Equal(key[:], make([]byte, 32)) {
		t.Fatal("key should still be generated")
	}
}
