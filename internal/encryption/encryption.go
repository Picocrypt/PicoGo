package encryption

import (
	"errors"
	"fmt"
	"io"
)

const readSize = 1 << 20
const maxCommentsLength = 99999

var ErrFileTooShort = errors.New("file too short")
var ErrIncorrectPassword = errors.New("incorrect password")
var ErrIncorrectKeyfiles = errors.New("incorrect keyfiles")
var ErrIncorrectOrMisorderedKeyfiles = errors.New("incorrect or misordered keyfiles")
var ErrKeyfilesRequired = errors.New("missing required keyfiles")
var ErrDuplicateKeyfiles = errors.New("duplicate keyfiles")
var ErrKeyfilesNotRequired = errors.New("keyfiles not required")
var ErrHeaderCorrupted = errors.New("header corrupted")
var ErrBodyCorrupted = errors.New("body corrupted")
var ErrCommentsTooLong = errors.New("comments exceed maximum length")

type Settings struct {
	Comments    string
	ReedSolomon bool
	Paranoid    bool
	OrderedKf   bool
	Deniability bool
}

func Decrypt(
	pw string,
	kf []io.Reader,
	r io.Reader,
	w io.Writer,
	skipReedSolomon bool,
) (bool, error) {

	damageTracker := damageTracker{}
	decryptStream := makeDecryptStream(pw, kf, &damageTracker)

	for {
		p := make([]byte, readSize)
		n, err := r.Read(p)
		eof := false
		if err != nil {
			if errors.Is(err, io.EOF) {
				eof = true
			} else {
				return false, fmt.Errorf("reading input: %w", err)
			}
		}
		p, err = decryptStream.stream(p[:n])
		if err != nil {
			return damageTracker.damage, err
		}
		_, err = w.Write(p)
		if err != nil {
			return damageTracker.damage, err
		}
		if eof {
			p, err := decryptStream.flush()
			if (err == nil) || errors.Is(err, ErrBodyCorrupted) {
				_, e := w.Write(p)
				return damageTracker.damage, e
			}
			return damageTracker.damage, err
		}
	}
}

func GetEncryptionSettings(r io.Reader) (Settings, error) {
	header, err := getHeader(r, "")
	if errors.Is(err, ErrFileTooShort) {
		return Settings{Deniability: true}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("reading header: %w", err)
	}
	return header.settings, nil
}

func EncryptHeadless(
	in io.Reader,
	password string,
	keyfiles []io.Reader,
	settings Settings,
	out io.Writer,
) ([]byte, error) {
	if len(settings.Comments) > maxCommentsLength {
		return nil, ErrCommentsTooLong
	}
	seeds, err := randomSeeds()
	if err != nil {
		return nil, fmt.Errorf("generating seeds: %w", err)
	}
	return encryptWithSeeds(in, password, keyfiles, settings, out, seeds)
}

func encryptWithSeeds(
	in io.Reader,
	password string,
	keyfiles []io.Reader,
	settings Settings,
	out io.Writer,
	seeds seeds,
) ([]byte, error) {
	encryptionStream, err := makeEncryptStream(settings, seeds, password, keyfiles)
	if err != nil {
		return nil, fmt.Errorf("making encryption stream: %w", err)
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
		p, err := encryptionStream.stream(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("encrypting input: %w", err)
		}
		_, err = out.Write(p)
		if err != nil {
			return nil, fmt.Errorf("writing output: %w", err)
		}
		if eof {
			break
		}
	}

	p, err := encryptionStream.flush()
	if err != nil {
		return nil, fmt.Errorf("closing encryptor: %w", err)
	}
	_, err = out.Write(p)
	if err != nil {
		return nil, fmt.Errorf("writing output: %w", err)
	}

	headerBytes, err := encryptionStream.header.bytes(password)
	if err != nil {
		return nil, fmt.Errorf("making header: %w", err)
	}
	return headerBytes, nil
}

func PrependHeader(
	headless io.Reader,
	headed io.Writer,
	header []byte,
) error {
	_, err := headed.Write(header)
	if err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	for {
		data := make([]byte, readSize)
		n, err := headless.Read(data)
		eof := err == io.EOF
		if (err != nil) && (err != io.EOF) {
			return fmt.Errorf("reading body data: %w", err)
		}
		data = data[:n]

		_, err = headed.Write(data)
		if err != nil {
			return fmt.Errorf("writing body data: %w", err)
		}

		if eof {
			break
		}
	}
	return nil
}

func HeaderSize(settings Settings) int {
	size := baseHeaderSize + 3*len(settings.Comments)
	if settings.Deniability {
		size += len(seeds{}.DenyNonce) + len(seeds{}.DenySalt)
	}
	return size
}
