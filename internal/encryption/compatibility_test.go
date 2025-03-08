package encryption

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
)

type keyArgs struct {
	password    string
	salt        [16]byte
	iterations  uint32
	parallelism uint8
}

func lookupArgonKey(password string, salt [16]byte, iterations uint32, parallelism uint8) [32]byte {
	args := keyArgs{password, salt, iterations, parallelism}
	table := make(map[keyArgs][32]byte)
	table[keyArgs{"abc123", [16]byte{139, 9, 66, 42, 143, 202, 60, 149, 150, 243, 219, 17, 53, 178, 5, 89}, 4, 4}] = [32]byte{149, 203, 18, 247, 176, 38, 51, 122, 15, 193, 129, 177, 190, 156, 144, 121, 232, 184, 87, 110, 150, 163, 252, 17, 51, 0, 1, 22, 167, 113, 200, 69}
	table[keyArgs{"qwerty", [16]byte{94, 19, 33, 165, 131, 26, 172, 132, 99, 112, 102, 97, 148, 159, 65, 140}, 4, 4}] = [32]byte{254, 86, 74, 75, 204, 49, 39, 245, 149, 249, 38, 69, 175, 195, 207, 233, 140, 161, 229, 64, 0, 79, 36, 183, 31, 27, 232, 110, 213, 166, 41, 83}
	table[keyArgs{"I'm not paranoid, you are", [16]byte{162, 150, 109, 97, 169, 82, 134, 25, 60, 99, 20, 6, 60, 88, 89, 154}, 8, 8}] = [32]byte{12, 36, 77, 206, 14, 157, 139, 149, 51, 122, 233, 116, 25, 150, 73, 103, 119, 43, 29, 80, 25, 172, 123, 231, 24, 182, 42, 193, 45, 41, 8, 151}
	table[keyArgs{"comment-test!", [16]byte{100, 163, 13, 69, 61, 147, 102, 52, 96, 120, 244, 173, 128, 92, 68, 193}, 4, 4}] = [32]byte{226, 252, 143, 9, 105, 115, 73, 207, 76, 180, 33, 131, 178, 124, 43, 149, 99, 128, 132, 237, 246, 233, 103, 219, 176, 31, 120, 57, 1, 233, 206, 240}
	table[keyArgs{"=-0987654321`+_)(*&^%$#@!~", [16]byte{235, 137, 163, 53, 171, 95, 213, 102, 190, 174, 200, 232, 49, 135, 110, 142}, 4, 4}] = [32]byte{98, 88, 236, 113, 181, 17, 11, 184, 136, 21, 171, 20, 160, 196, 139, 1, 226, 23, 34, 78, 54, 254, 83, 28, 42, 179, 138, 47, 10, 217, 163, 79}
	table[keyArgs{"=-0987654321`+_)(*&^%$#@!~", [16]byte{61, 62, 113, 22, 68, 242, 140, 228, 240, 166, 180, 220, 228, 186, 203, 93}, 4, 4}] = [32]byte{33, 121, 96, 185, 152, 192, 95, 13, 7, 92, 137, 44, 108, 43, 27, 80, 20, 185, 151, 134, 210, 31, 70, 12, 69, 145, 182, 124, 168, 203, 244, 211}
	table[keyArgs{"\\][|}{", [16]byte{114, 104, 213, 163, 217, 21, 198, 48, 239, 131, 234, 100, 46, 34, 116, 23}, 4, 4}] = [32]byte{251, 126, 192, 62, 80, 1, 114, 229, 168, 88, 223, 148, 63, 218, 221, 187, 78, 127, 196, 241, 207, 156, 74, 221, 250, 217, 128, 50, 22, 8, 247, 123}
	table[keyArgs{"qazwsx", [16]byte{148, 72, 62, 54, 90, 62, 67, 88, 36, 240, 75, 16, 15, 44, 151, 86}, 4, 4}] = [32]byte{2, 114, 15, 159, 125, 17, 140, 14, 183, 134, 239, 86, 20, 129, 170, 101, 43, 154, 90, 58, 92, 46, 234, 136, 113, 75, 157, 10, 73, 82, 52, 230}
	table[keyArgs{"qazwsx", [16]byte{152, 18, 236, 243, 6, 44, 244, 107, 242, 102, 218, 65, 81, 27, 90, 27}, 8, 8}] = [32]byte{
		110, 254, 3, 57, 78, 8, 12, 26, 121, 152, 197, 37, 159, 127, 157, 186, 194, 249, 102, 81, 218, 38, 38, 135, 200, 108, 168, 201, 193, 144, 123, 201}
	table[keyArgs{",./<>?", [16]byte{168, 111, 27, 242, 118, 225, 254, 203, 189, 20, 76, 220, 75, 75, 233, 179}, 4, 4}] = [32]byte{29, 66, 217, 82, 103, 108, 255, 17, 152, 35, 194, 67, 185, 169, 70, 183, 96, 125, 134, 116, 153, 183, 178, 103, 68, 164, 35, 111, 147, 163, 76, 245}
	key, ok := table[args]
	if !ok {
		copy(key[:], argon2.IDKey([]byte(password), salt[:], iterations, 1<<20, parallelism, 32))
		log.Println(password)
		log.Println(salt)
		log.Println(iterations)
		log.Println(parallelism)
		log.Println(key)
		panic("no matching key in lookup table")
	}
	return key
}

type Example struct {
	decrypted string
	encrypted string
	password  string
	keyfiles  []string
	header    header
}

func encryptWithSeeds(
	seeds seeds,
	in io.Reader,
	password string,
	keyfiles []io.Reader,
	settings Settings,
	out io.Writer,
) ([]byte, error) {
	stream, err := makeEncryptStream(settings, seeds, password, keyfiles)
	if err != nil {
		return nil, fmt.Errorf("creating encrypt stream: %w", err)
	}
	buf := make([]byte, readSize)
	for {
		eof := false
		n, err := in.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				eof = true
			} else {
				return nil, fmt.Errorf("reading input: %w", err)
			}
		}
		data, err := stream.stream(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("encrypting input: %w", err)
		}
		_, err = out.Write(data)
		if err != nil {
			return nil, fmt.Errorf("writing encrypted data: %w", err)
		}
		if eof {
			break
		}
	}

	data, err := stream.flush()
	if err != nil {
		return nil, fmt.Errorf("flushing encryptor: %w", err)
	}
	_, err = out.Write(data)
	if err != nil {
		return nil, fmt.Errorf("writing encrypted data: %w", err)
	}
	headerBytes, err := stream.header.bytes(password)
	if err != nil {
		return nil, fmt.Errorf("making header: %w", err)
	}
	return headerBytes, nil
}

func makeExample(
	decrypted string,
	encrypted string,
	password string,
	keyfiles []string,
) (Example, error) {
	r, err := os.Open("examples/" + encrypted)
	if err != nil {
		return Example{}, err
	}
	defer r.Close()
	header, err := getHeader(r, password)
	if err != nil {
		return Example{}, err
	}
	return Example{decrypted, encrypted, password, keyfiles, header}, nil
}

func testEncryption(example Example, t *testing.T) {
	kf := []io.Reader{}
	for _, name := range example.keyfiles {
		k, err := os.Open("examples/" + name)
		if err != nil {
			t.Fatal("opening keyfile: %w", err)
		}
		defer k.Close()
		kf = append(kf, k)
	}

	d, err := getDecryptedData(example)
	if err != nil {
		t.Fatal("reading decrypted data: %w", err)
	}
	r := bytes.NewBuffer(d)
	headless := bytes.NewBuffer([]byte{})

	headerBytes, err := encryptWithSeeds(
		example.header.seeds,
		r,
		example.password,
		kf,
		example.header.settings,
		headless,
	)
	if err != nil {
		t.Fatal("encrypting data", err)
	}

	headed := bytes.NewBuffer([]byte{})
	err = PrependHeader(headless, headed, headerBytes)
	if err != nil {
		t.Fatal("adding header:", err)
	}

	result, err := io.ReadAll(headed)
	if err != nil {
		t.Fatal("extracting result:", err)
	}
	expected, err := getEncryptedData(example)
	if err != nil {
		t.Fatal("reading encrypted data: %w", err)
	}
	if !bytes.Equal(result, expected) {
		log.Println("Len result:  ", len(result))
		log.Println("Len expected:", len(expected))
		for i := 0; i < len(result); i++ {
			if result[i] != expected[i] {
				log.Println("first err at ", i)
				break
			}
		}
		t.Fatal("encrypted data does not match")
	}

}

func testDecryption(example Example, t *testing.T) {
	r, err := os.Open("examples/" + example.encrypted)
	if err != nil {
		t.Fatal("opening decrypted file: %w", err)
	}
	defer r.Close()

	kf := []io.Reader{}
	for _, name := range example.keyfiles {
		k, err := os.Open("examples/" + name)
		if err != nil {
			t.Fatal("opening keyfile: %w", err)
		}
		defer k.Close()
		kf = append(kf, k)
	}

	w := bytes.NewBuffer([]byte{})
	damaged, err := Decrypt(example.password, kf, r, w, false, false, nil)
	if damaged {
		t.Fatal("damaged data")
	}
	if err != nil {
		t.Fatal("decrypting:", err)
	}
	result, err := io.ReadAll(w)
	if err != nil {
		t.Fatal("extracting result:", err)
	}

	expected, err := getDecryptedData(example)
	if err != nil {
		t.Fatal("reading decrypted file: %w", err)
	}
	if !bytes.Equal(result, expected) {
		log.Println("Len result:  ", len(result))
		log.Println("Len expected:", len(expected))
		log.Println("Start of result:", result[:10])
		log.Println("Start of expected:", expected[:10])
		t.Fatal("decrypted data does not match")
	}
}

func getDecryptedData(example Example) ([]byte, error) {
	r, err := os.Open("examples/" + example.decrypted)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getEncryptedData(example Example) ([]byte, error) {
	r, err := os.Open("examples/" + example.encrypted)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func TestCompatibility001(t *testing.T) {
	argonKey = lookupArgonKey
	example, err := makeExample("empty.txt", "test001.txt.pcv", "abc123", []string{})
	if err != nil {
		t.Fatal("loading example:", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility002(t *testing.T) {
	// Testing standard settings on file that requires near-1Mb flag
	argonKey = lookupArgonKey
	example, err := makeExample("random1048570", "test002.pcv", "qwerty", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility003(t *testing.T) {
	// Testing paranoid mode
	argonKey = lookupArgonKey
	example, err := makeExample("random1048570", "test003.pcv", "I'm not paranoid, you are", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility004(t *testing.T) {
	// Testing comments
	argonKey = lookupArgonKey
	example, err := makeExample("random1048570", "test004.pcv", "comment-test!", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility005(t *testing.T) {
	// Testing deniability
	argonKey = lookupArgonKey
	example, err := makeExample("random1048570", "test005.pcv", "=-0987654321`+_)(*&^%$#@!~", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}

func TestCompatibility006(t *testing.T) {
	// Testing reed solomon
	argonKey = lookupArgonKey
	example, err := makeExample("random1048570", "test006.pcv", "\\][|}{", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}

func TestCompatibility007(t *testing.T) {
	// Testing paranoid + reed solomon + deniability on file that includes near-1MiB flag
	argonKey = lookupArgonKey
	example, err := makeExample("random1048570", "test007.pcv", "qazwsx", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}

func TestCompatibility008(t *testing.T) {
	// Testing ordered keyfiles
	argonKey = lookupArgonKey
	example, err := makeExample("random1048570", "test008.pcv", ",./<>?", []string{"keyfile1.key", "keyfile2.key"})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}
