package encryption

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func chunk(data []byte) [][]byte {
	chunks := [][]byte{}
	idx := 0
	for i := 0; ; i = i*2 + 1 {
		end := idx + i
		if end < len(data) {
			chunks = append(chunks, data[idx:end])
		} else {
			chunks = append(chunks, data[idx:])
			break
		}
		idx = end
	}
	return chunks
}

func TestRSEncodeDecodeMatch(t *testing.T) {
	data := make([]byte, 25)
	rand.Read(data)
	dataRS := make([]byte, len(data)+10)

	rsEncode(dataRS, data)
	if !bytes.Equal(data, dataRS[:len(data)]) {
		t.Fatal("Beginning bytes should match")
	}

	recover := make([]byte, len(data))
	damaged, _, err := rsDecode(recover, dataRS, false)
	if damaged {
		t.Fatal("data should not be damaged")
	}
	if err != nil {
		t.Fatal("decoding: ", err)
	}
	if !bytes.Equal(data, recover) {
		t.Fatal("data should match")
	}

	dataRS[0] = dataRS[0] + 1 // slightly damage data
	damaged, _, err = rsDecode(recover, dataRS, false)
	if !damaged {
		t.Fatal("should be damaged")
	}
	if err != nil {
		t.Fatal("should be recoverable")
	}
	if !bytes.Equal(data, recover) {
		t.Fatal("data should match")
	}

	rand.Read(dataRS[:]) // major damage
	damaged, corrupted, err := rsDecode(recover, dataRS, false)
	if !damaged {
		t.Fatal("should be damaged")
	}
	if !corrupted {
		t.Fatal("should be corrupted")
	}
	if err != nil {
		t.Fatal("should be no error, got", err)
	}
	if bytes.Equal(data, recover) {
		t.Fatal("data shouldn't match")
	}
	if !bytes.Equal(recover, dataRS[:len(data)]) {
		t.Fatal("should return first bytes as guess")
	}
}

func TestRSBodyMatch(t *testing.T) {
	origData := make([]byte, 1234)
	rand.Read(origData)

	// should be able to encode it in any size chunks
	chunks := chunk(origData)
	encoder := makeRSEncodeStream()
	encodedData := []byte{}
	for _, c := range chunks {
		p, err := encoder.stream(c)
		if err != nil {
			t.Fatal(err)
		}
		encodedData = append(encodedData, p...)
	}
	p, err := encoder.flush()
	if err != nil {
		t.Fatal(err)
	}
	encodedData = append(encodedData, p...)

	// sanity check the size of encodedData
	numChunks := len(origData)/128 + 1
	if len(encodedData) != numChunks*136 {
		t.Fatal("Encoded wrong number of chunks")
	}

	damageTracker := damageTracker{}
	fullDecode := func(data []byte) ([]byte, bool) {
		// should be able to decode in any size chunks
		decoder := makeRSDecodeStream(false, &damageTracker)
		decodedData := []byte{}
		decodeChunks := chunk(data)
		for _, c := range decodeChunks {
			p, err := decoder.stream(c)
			if err != nil {
				t.Fatal(err)
			}
			decodedData = append(decodedData, p...)
		}
		p, err := decoder.flush()
		if err != nil {
			t.Fatal(err)
		}
		decodedData = append(decodedData, p...)
		return decodedData, damageTracker.damage
	}

	// decoding the encoded data should work without error
	decodedData, _ := fullDecode(encodedData)
	if !bytes.Equal(origData, decodedData) {
		t.Fatal("Original data differs from decoded data")
	}

	// decoded slightly damaged data should work
	encodedData[5] = encodedData[5] + 1
	decodedData, damaged := fullDecode(encodedData)
	if !bytes.Equal(origData, decodedData) {
		t.Fatal("Original data differs from decoded data")
	}
	if !damaged {
		t.Fatal("Should be damaged")
	}

	// a large error is irrecoverable
	rand.Read(encodedData[:chunkSize])
	decodedData, damaged = fullDecode(encodedData)
	if bytes.Equal(origData, decodedData) {
		t.Fatal("Original data should differ from decoded data")
	}
	if !damaged {
		t.Fatal("Should be corrupted")
	}
}
