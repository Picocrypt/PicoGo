package encryption

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	mrand "math/rand/v2"
	"testing"

	"golang.org/x/crypto/sha3"
)

func shaArgonKey(password string, salt [16]byte, iterations uint32, parallelism uint8) [32]byte {
	// faster stand-in for testing
	data := append(append(append([]byte(password), salt[:]...), byte(iterations)), byte(parallelism))
	hasher := sha3.New256()
	_, err := hasher.Write(data)
	if err != nil {
		panic(err)
	}
	key := [32]byte{}
	copy(key[:], hasher.Sum(nil))
	return key
}

func allSettings() []Settings {
	settings := []Settings{}
	for _, comments := range []string{"", "test"} {
		for _, reedSolomon := range []bool{true, false} {
			for _, paranoid := range []bool{true, false} {
				for _, orderedKf := range []bool{true, false} {
					for _, deniability := range []bool{true, false} {
						s := Settings{comments, reedSolomon, paranoid, orderedKf, deniability}
						settings = append(settings, s)
					}
				}
			}
		}
	}
	return settings
}

func getKeyfiles(settings Settings, numKeyfiles int, t *testing.T) ([]io.Reader, []io.Reader) {
	kf1, kf2 := []io.Reader{}, []io.Reader{}
	for i := 0; i < numKeyfiles; i++ {
		key1 := make([]byte, 100)
		_, err := rand.Read(key1)
		if err != nil {
			t.Fatal(err)
		}
		key2 := make([]byte, len(key1))
		copy(key2, key1)
		kf1 = append(kf1, bytes.NewBuffer(key1))
		kf2 = append(kf2, bytes.NewBuffer(key2))
	}
	if !settings.OrderedKf {
		for i := len(kf2) - 1; i > 0; i-- {
			j := mrand.IntN(i + 1)
			kf2[i], kf2[int(j)] = kf2[int(j)], kf2[i]
		}
	}
	return kf1, kf2
}

func randomPassword() string {
	password := ""
	n := mrand.IntN(100) + 1
	for i := 0; i < n; i++ {
		char := mrand.IntN(128)
		password += string(byte(char))
	}
	return password
}

func randomData(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func buff(data []byte) *bytes.Buffer {
	d := make([]byte, len(data))
	copy(d, data)
	return bytes.NewBuffer(d)
}

func testConsistency(settings Settings, size int, numKeyfiles int, t *testing.T) {
	original, err := randomData(size)
	if err != nil {
		t.Fatal("opening file:", err)
	}

	password := randomPassword()
	kf1, kf2 := getKeyfiles(settings, numKeyfiles, t)

	headless := bytes.NewBuffer([]byte{})
	header, err := EncryptHeadless(buff(original), password, kf1, settings, headless)
	if err != nil {
		t.Fatal(err)
	}
	headlessLen := headless.Len()
	headed := bytes.NewBuffer([]byte{})
	err = PrependHeader(headless, headed, header)
	if err != nil {
		t.Fatal(err)
	}
	encryptedLen := headed.Len()
	encrypted, err := io.ReadAll(headed)
	if err != nil {
		t.Fatal(err)
	}
	decrypted := bytes.NewBuffer([]byte{})
	Decrypt(password, kf2, buff(encrypted), decrypted, false)

	result, err := io.ReadAll(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, original) {
		log.Println("original length:", len(original))
		log.Println("headless length:", headlessLen)
		log.Println("headed length:", encryptedLen)
		log.Println("decrypted length:", len(result))
		log.Println("missing bytes:", len(original)-len(result))
		t.Fatal("decryption does not match")
	}

}

func TestConsistencyEmptyFile(t *testing.T) {
	// test for an empty file
	argonKey = shaArgonKey
	for _, settings := range allSettings() {
		for numKeyfiles := range 3 {
			testConsistency(settings, 0, numKeyfiles, t)
		}
	}
}

func TestConsistencySmallFile(t *testing.T) {
	// test for a file size less than readSize
	argonKey = shaArgonKey
	for _, settings := range allSettings() {
		for numKeyfiles := range 3 {
			testConsistency(settings, readSize/2, numKeyfiles, t)
		}
	}
}

func TestConsistencyLargeFile(t *testing.T) {
	// test for a file size greater than readSize
	argonKey = shaArgonKey
	for _, settings := range allSettings() {
		for numKeyfiles := range 3 {
			testConsistency(settings, readSize*2+500, numKeyfiles, t)
		}
	}
}

func TestConsistencyReadSize(t *testing.T) {
	// test for a file exactly at readSize
	argonKey = shaArgonKey
	for _, settings := range allSettings() {
		for numKeyfiles := range 3 {
			testConsistency(settings, readSize, numKeyfiles, t)
		}
	}
}
