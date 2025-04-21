package encryption

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/Picocrypt/infectious"
)

const (
	chunkSize   = 128
	encodedSize = 136
)

var (
	fecs   = make(map[[2]int]*infectious.FEC)
	fecsMu sync.Mutex
)

func getFEC(encoded, decoded []byte) (*infectious.FEC, error) {
	size := [2]int{len(decoded), len(encoded)}

	fecsMu.Lock()
	defer fecsMu.Unlock()

	fec := fecs[size]
	if fec != nil {
		return fec, nil
	}

	fec, err := infectious.NewFEC(size[0], size[1])
	if err != nil {
		return fec, err
	}

	fecs[size] = fec
	return fec, nil
}

func rsEncode(dst, src []byte) error {
	fec, err := getFEC(dst, src)
	if err != nil {
		return fmt.Errorf("getting FEC: %w", err)
	}
	return fec.Encode(src, func(s infectious.Share) { dst[s.Number] = s.Data[0] })
}

func rsDecode(dst, src []byte, skip bool) (bool, bool, error) {
	if skip {
		copy(dst, src[:len(dst)])
		return false, false, nil
	}

	// Encoding is much faster than decoding. Try re-encoding the original
	// bytes and if the result matches, there must have been no corruption.
	recoded := make([]byte, len(src))
	rsEncode(recoded, src[:len(dst)])
	if bytes.Equal(recoded, src) {
		copy(dst, src[:len(dst)])
		return false, false, nil
	}

	// Attempt to recover damaged data
	fec, err := getFEC(src, dst)
	if err != nil {
		return true, false, fmt.Errorf("getting FEC: %w", err)
	}
	tmp := make([]infectious.Share, fec.Total())
	for i := 0; i < fec.Total(); i++ {
		tmp[i].Number = i
		tmp[i].Data = []byte{src[i]}
	}
	res, err := fec.Decode(nil, tmp)
	if err == nil {
		copy(dst, res)
		return true, false, nil
	}

	// Fully corrupted - use a best guess
	copy(dst, src[:len(dst)])
	return true, true, nil
}

type rsEncodeStream struct {
	buff          []byte
	chunksEncoded int64
	header        *header
}

func (r *rsEncodeStream) stream(p []byte) ([]byte, error) {
	r.buff = append(r.buff, p...)
	nChunks := len(r.buff) / chunkSize
	rsData := make([]byte, nChunks*encodedSize)
	for i := 0; i < nChunks; i++ {
		err := rsEncode(rsData[i*encodedSize:(i+1)*encodedSize], r.buff[i*chunkSize:(i+1)*chunkSize])
		if err != nil {
			return nil, err
		}
	}
	r.buff = r.buff[nChunks*chunkSize:]
	r.chunksEncoded += int64(nChunks)
	return rsData, nil
}

func (r *rsEncodeStream) flush() ([]byte, error) {
	// Skip if exactly the right number of chunks encoded and there is no buffer data
	exactMiB := r.chunksEncoded%((1<<20)/chunkSize) == 0
	if exactMiB && len(r.buff) == 0 {
		return nil, nil
	}
	padding := make([]byte, chunkSize-len(r.buff))
	for i := range padding {
		padding[i] = byte(chunkSize - len(r.buff))
	}
	dst := make([]byte, encodedSize)
	err := rsEncode(dst, append(r.buff, padding...))
	if err != nil {
		return nil, fmt.Errorf("encoding final chunk: %w", err)
	}
	return dst, nil
}

type rsDecodeStream struct {
	buff          []byte
	skip          bool
	damageTracker *damageTracker
	header        *header
	chunksDecoded int64
}

func (r *rsDecodeStream) stream(p []byte) ([]byte, error) {
	r.buff = append(r.buff, p...)
	nChunks := len(r.buff) / encodedSize
	// The last chunk might be padded, so keep it in the buffer for flush
	if ((len(r.buff) % encodedSize) == 0) && (nChunks > 0) {
		nChunks -= 1
	}
	rsData := make([]byte, nChunks*chunkSize)
	for i := 0; i < nChunks; i++ {
		src := r.buff[i*encodedSize : (i+1)*encodedSize]
		dst := rsData[i*chunkSize : (i+1)*chunkSize]
		damaged, _, err := rsDecode(dst, src, r.skip)
		r.damageTracker.damage = r.damageTracker.damage || damaged
		if err != nil {
			return nil, err
		}
	}
	r.chunksDecoded += int64(nChunks)
	r.buff = r.buff[nChunks*encodedSize:]
	return rsData, nil
}

func (r *rsDecodeStream) flush() ([]byte, error) {
	if len(r.buff) == 0 {
		return nil, nil
	}
	if len(r.buff) != encodedSize {
		return nil, ErrBodyCorrupted
	}
	res := make([]byte, chunkSize)
	damaged, _, err := rsDecode(res, r.buff, r.skip)
	r.damageTracker.damage = r.damageTracker.damage || damaged
	if err != nil {
		return nil, err
	}
	// The last chunk is padded unless there is an exact multiple of MiB of decoded data
	// and the nearMiBFlag is not set
	exactMiB := (r.chunksDecoded+1)%((1<<20)/chunkSize) == 0
	if exactMiB && !r.header.nearMiBFlag {
		return res, nil
	}
	keep := chunkSize - int(res[chunkSize-1])
	if (keep >= 0) && (keep < chunkSize) {
		return res[:keep], err
	}
	return nil, ErrBodyCorrupted
}

func makeRSEncodeStream(header *header) *rsEncodeStream {
	return &rsEncodeStream{header: header}
}

func makeRSDecodeStream(skip bool, header *header, damageTracker *damageTracker) *rsDecodeStream {
	return &rsDecodeStream{skip: skip, damageTracker: damageTracker, header: header}
}
