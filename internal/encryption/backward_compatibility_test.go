// Test for combatibility with Picocrypt
package encryption

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
)

var compatibilityVersions = []string{"v1.47", "v1.48"}

/* Decrypt files encrypted by Picocrypt

To generate the test files, choose a version of Picocrypt and rotate through each file under
picocrypt_samples/basefiles. The file sizes tested are:
- 0 bytes. While encrypted empyt files is not really meaningful, encryption should still work
- 1000 bytes. Just a generic small file of data
- 1048570 bytes. This should trigger the extra flag for Reed-Solomon encoding that Picocrypt uses

Encrypt each file with password "password". Append the following strings to the filename to indicate
what other encryption settings were used. Note that only the keyfile settings are actually used in
the test because the others can be derived from the header data. The non-keyfile suffixes are just
for reference to check what combinations of settings are being tested.
- "_c" indicates that comments were used
- "_p" indicates that paranoid mode was used
- "_r" indicates that Reed-Solomon encoding was used
- "_d" indicates that deniability mode was used
- "_kf1" indicates that keyfile 1 was used
- "_kf12" indicates that keyfiles 1 and 2 were used
- "_kf12o" indicates that keyfiles 1 and 2 were used, and the keyfiles were ordered

The encrypted files should be stored under picocrypt_samples/<version>/
*/

func getTestKeyfiles(name string) []io.Reader {
	kf := []io.Reader{}
	usesKf1 := strings.Contains(name, "kf1")
	usesKf2 := strings.Contains(name, "kf12")
	for i, used := range []bool{usesKf1, usesKf2} {
		if !used {
			continue
		}
		r, err := os.Open("picocrypt_samples/keyfiles/keyfile" + strconv.Itoa(i+1))
		if err != nil {
			log.Fatal("opening keyfile: %w", err)
		}
		defer r.Close()
		buf := bytes.NewBuffer([]byte{})
		_, err = io.Copy(buf, r)
		if err != nil {
			log.Fatal("reading keyfile: %w", err)
		}
		kf = append(kf, buf)
	}
	return kf
}

func getBaseData(name string) []byte {
	basename := strings.SplitN(name, ".", 2)[0]
	if strings.Contains(basename, "_") {
		basename = strings.SplitN(basename, "_", 2)[0]
	}
	r, err := os.Open("picocrypt_samples/basefiles/" + basename)
	if err != nil {
		log.Fatal("opening file: %w", err)
	}
	defer r.Close()
	buf := bytes.NewBuffer([]byte{})
	_, err = io.Copy(buf, r)
	if err != nil {
		log.Fatal("reading file: %w", err)
	}
	return buf.Bytes()
}

func TestDecryptingPicocryptFiles(t *testing.T) {
	for _, version := range compatibilityVersions {
		files, err := os.ReadDir("picocrypt_samples/" + version)
		if err != nil {
			t.Fatal("reading directory: %w", err)
		}
		for _, file := range files {
			if !(strings.HasSuffix(file.Name(), ".pcv")) {
				continue
			}
			t.Run(version+":"+file.Name(), func(t *testing.T) {
				r, err := os.Open("picocrypt_samples/" + version + "/" + file.Name())
				if err != nil {
					t.Fatal("opening encrypted file: %w", err)
				}
				defer r.Close()
				w := bytes.NewBuffer([]byte{})
				kf := getTestKeyfiles(file.Name())
				damaged, err := Decrypt("password", kf, r, w, false, nil)
				if damaged {
					t.Fatal("damaged data")
				}
				if err != nil {
					t.Fatal("decrypting:", err)
				}
				result := w.Bytes()
				expected := getBaseData(file.Name())
				if !bytes.Equal(result, expected) {
					t.Fatal("decrypted data does not match")
				}
			})
		}
	}
}

/* Test encryption parity with Picocrypt

Given the same header (seeds, settings, etc), same password, and same keyfiles, the encryption
package should produce exactly the same output as Picocrypt. Run through each file in the
latest version and ensure that the encrypted data matches exactly.
*/

func extractSettings(path string) (Settings, seeds) {
	r, err := os.Open(path)
	if err != nil {
		log.Fatal("opening file: %w", err)
	}
	defer r.Close()
	header, err := getHeader(r, "password")
	if err != nil {
		log.Fatal("reading header: %w", err)
	}
	return header.settings, header.seeds
}

func TestEncryptedFilesMatchPicocrypt(t *testing.T) {
	latestVersion := compatibilityVersions[len(compatibilityVersions)-1]
	files, err := os.ReadDir("picocrypt_samples/" + latestVersion)
	if err != nil {
		t.Fatal("reading directory: %w", err)
	}
	for _, file := range files {
		if !(strings.HasSuffix(file.Name(), ".pcv")) {
			continue
		}
		t.Run("encrypting:"+file.Name(), func(t *testing.T) {
			path := "picocrypt_samples/" + latestVersion + "/" + file.Name()
			settings, seeds := extractSettings(path)
			kf := getTestKeyfiles(file.Name())
			w := bytes.NewBuffer([]byte{})
			header, err := encryptWithSeeds(
				bytes.NewBuffer(getBaseData(file.Name())),
				"password",
				kf,
				settings,
				w,
				nil,
				seeds,
			)
			if err != nil {
				t.Fatal("encrypting:", err)
			}
			full := bytes.NewBuffer([]byte{})
			err = PrependHeader(bytes.NewBuffer(w.Bytes()), full, header)
			if err != nil {
				t.Fatal("prepending header:", err)
			}
			result := full.Bytes()

			r, err := os.Open(path)
			if err != nil {
				t.Fatal("opening encrypted file: %w", err)
			}
			defer r.Close()
			buf := bytes.NewBuffer([]byte{})
			_, err = io.Copy(buf, r)
			if err != nil {
				t.Fatal("reading file: %w", err)
			}
			expected := buf.Bytes()

			if !bytes.Equal(result, expected) {
				log.Println("encrypted data does not match")
				log.Println("len expected:", len(expected))
				log.Println("len result:", len(result))
				// find where they first differ
				for i := 0; i < len(expected) && i < len(result); i++ {
					if expected[i] != result[i] {
						log.Println("first difference at", i)
						log.Println("expected:", expected[i])
						log.Println("result:", result[i])
						break
					}
				}
				t.Fatal("encrypted data does not match")
			}
		})
	}
}

/* Compare encryption and decryption for very large files

The encryption and decryption methods rotate the nonces every 60 GB. To accurately test this,
encrypt/decrypt files larger than 60 GB. Instead of adding files that large to the repository,
create a test that simulates this behavior. These tests will generate files of zeros, encrypt
them, and then decrypt them. The sha256 of the encrypted and decrypted files are compared against
expected values generated by hand, following these steps:

1. Create a file of zeros (bash ex: dd if=/dev/zero of=zerofile bs=1M count=62464)
2. Get the sha256 of the file (bash ex: sha256sum zerofile)
3. Encrypt the file using the latest Picocrypt version. This is a long test, so only check against
   one version
4. Get the sha256sum of the encrypted file (bash ex: sha256sum zerofile.pcv)
5. Save the header bytes from the encrypted file (bash ex: head -c 789 zerofile.pcv > zerofile.header).
6. Create a test with the header bytes and the sha256sums
*/

type zeroReader struct {
	size    int64
	counter int64
}

func (z *zeroReader) Read(p []byte) (n int, err error) {
	if z.counter == z.size {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 0
		z.counter++
		if z.counter == z.size {
			return i + 1, nil
		}
	}
	return len(p), nil
}

type shaDecryptWriter struct {
	decryptStream *decryptStream
	encryptedSha  hash.Hash
	decryptedSha  hash.Hash
}

func (s *shaDecryptWriter) Write(p []byte) (int, error) {
	_, err := s.encryptedSha.Write(p)
	if err != nil {
		return 0, err
	}
	decoded, err := s.decryptStream.stream(p)
	if err != nil {
		return 0, err
	}
	_, err = s.decryptedSha.Write(decoded)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *shaDecryptWriter) shas() ([]byte, []byte, error) {
	decoded, err := s.decryptStream.flush()
	if err != nil {
		return nil, nil, err
	}
	_, err = s.decryptedSha.Write(decoded)
	if err != nil {
		return nil, nil, err
	}
	return s.encryptedSha.Sum(nil), s.decryptedSha.Sum(nil), nil
}

func compareShas(
	t *testing.T,
	password string,
	headerFilename string,
	encodedSha string,
	decodedSha string,
	zeroFileSize int64,
) {
	headerReader, err := os.Open(headerFilename)
	if err != nil {
		t.Fatal("opening header file:", err)
	}
	defer headerReader.Close()
	headerBytes, err := io.ReadAll(headerReader)
	if err != nil {
		t.Fatal("reading header:", err)
	}

	damageTracker := &damageTracker{}
	writer := &shaDecryptWriter{makeDecryptStream(password, nil, damageTracker), sha256.New(), sha256.New()}
	_, err = writer.Write(headerBytes)
	if err != nil {
		t.Fatal("writing header:", err)
	}
	if !writer.decryptStream.headerStream.isDone() {
		t.Fatal("header stream should be done")
	}

	_, err = encryptWithSeeds(
		&zeroReader{size: zeroFileSize},
		password,
		[]io.Reader{},
		writer.decryptStream.headerStream.header.settings,
		writer,
		nil,
		writer.decryptStream.headerStream.header.seeds,
	)
	if err != nil {
		t.Fatal("encrypting:", err)
	}

	eSha, dSha, err := writer.shas()
	if err != nil {
		t.Fatal("getting shas:", err)
	}
	if hex.EncodeToString(eSha) != encodedSha {
		t.Fatal("encoded sha256 does not match")
	}
	if hex.EncodeToString(dSha) != decodedSha {
		t.Fatal("decoded sha256 does not match")
	}
}

func TestSmallFileSha(t *testing.T) {
	// Test 1K file of zeros, for debugging
	compareShas(
		t,
		"password",
		"examples/smallfile.header",
		"b501219c59855b8ba2e00fe2cc9ec9fd0b189f16a750f4593fd79964d2bed427",
		"5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
		(1 << 10), // 1K
	)
}

func TestLargeFileSha(t *testing.T) {
	// Test 65GB file of zeros
	compareShas(
		t,
		"password",
		"examples/largefile.header",
		"b65d470bfb6c9e07f09811244597f88177ba4cc68ae101002d5c5c8a6cf08500",
		"f3f0d678fa138e4581ed15ec63f8cb965e5d7b722db7d5fc4877e763163d399c",
		65498251264,
	)
}
