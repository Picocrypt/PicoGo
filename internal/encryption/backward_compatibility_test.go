// Test for decryption combatibility with Picocrypt
package encryption

import (
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
)

func getTestKeyfiles(name string) []io.Reader {
	kf := []io.Reader{}
	usesKf1 := strings.Contains(name, "kf1")
	usesKf2 := strings.Contains(name, "kf2")
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
	// split name at first underscore
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

func TestV1_47(t *testing.T) {
	// Decrypt all files in picrocrypt/samples/v1.47

	// List files in directory
	files, err := os.ReadDir("picocrypt_samples/v1.47")
	if err != nil {
		t.Fatal("reading directory: %w", err)
	}
	// Loop through files
	for _, file := range files {
		if !(strings.HasSuffix(file.Name(), ".pcv")) {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			r, err := os.Open("picocrypt_samples/v1.47/" + file.Name())
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
