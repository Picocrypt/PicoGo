package ui

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// Large enough for most files without using too much memory
const maxPreviewSize = 64 * 1024 * 1024

var ErrPreviewMemoryExceeded = errors.New("preview buffer size exceeded")

type previewBuffer struct {
	buf bytes.Buffer
}

func (b *previewBuffer) Write(p []byte) (n int, err error) {
	if b.buf.Len()+len(p) > maxPreviewSize {
		return 0, ErrPreviewMemoryExceeded
	}
	return b.buf.Write(p)
}

type CopyTo interface {
	CopyTo(dest io.Writer) error
}

func tempUri(app fyne.App) (fyne.URI, error) {
	return storage.Child(app.Storage().RootURI(), "temp")
}

func tempFileWriter(app fyne.App) (fyne.URIWriteCloser, error) {
	uri, err := tempUri(app)
	if err != nil {
		return nil, err
	}
	return storage.Writer(uri)
}

func tempFileReader(app fyne.App) (fyne.URIReadCloser, error) {
	uri, err := tempUri(app)
	if err != nil {
		return nil, err
	}
	return storage.Reader(uri)
}

type DecryptedData struct {
	buf      previewBuffer
	file     fyne.URIWriteCloser
	inMemory bool
	app      fyne.App
	name     string
}

func (d *DecryptedData) Write(p []byte) (n int, err error) {
	if d.inMemory {
		return d.buf.Write(p)
	}
	if d.file == nil {
		writer, err := tempFileWriter(d.app)
		if err != nil {
			return 0, err
		}
		d.file = writer
	}
	return d.file.Write(p)
}

func (d *DecryptedData) Close() error {
	if d.file != nil {
		return d.file.Close()
	}
	return nil
}

func (d *DecryptedData) CopyTo(dest io.Writer) error {
	if d.inMemory {
		_, err := io.Copy(dest, &d.buf.buf)
		return err
	}
	reader, err := tempFileReader(d.app)
	if reader != nil {
		defer reader.Close()
	}
	if err != nil {
		return err
	}
	_, err = io.Copy(dest, reader)
	return err
}

func (d *DecryptedData) PreviewFunc() func() {
	if !d.inMemory {
		return nil
	}
	validImage := isImage(d.name)
	validText := utf8.Valid(d.buf.buf.Bytes())
	if !(validImage || validText) {
		return nil
	}
	return func() {
		w := d.app.NewWindow("Preview")
		if isImage(d.name) {
			reader := bytes.NewReader(d.buf.buf.Bytes())
			image := canvas.NewImageFromReader(reader, d.name)
			image.SetMinSize(fyne.NewSize(400, 400))
			image.FillMode = canvas.ImageFillContain
			w.SetContent(
				container.New(
					layout.NewVBoxLayout(),
					image,
				),
			)
		} else {
			w.SetContent(
				container.New(
					layout.NewVBoxLayout(),
					widget.NewRichTextWithText(string(d.buf.buf.Bytes())),
				),
			)
		}
		fyne.Do(w.Show)
	}
}

func NewDecryptedData(name string, inMemory bool, app fyne.App) *DecryptedData {
	return &DecryptedData{
		inMemory: inMemory,
		buf:      previewBuffer{bytes.Buffer{}},
		app:      app,
		name:     name,
	}
}

type EncryptedData struct {
	Header []byte
	file   fyne.URIWriteCloser
	app    fyne.App
}

func (e *EncryptedData) Write(p []byte) (n int, err error) {
	if e.file == nil {
		writer, err := tempFileWriter(e.app)
		if err != nil {
			return 0, fmt.Errorf("opening encryption data file: %w", err)
		}
		e.file = writer
	}
	return e.file.Write(p)
}

func (e *EncryptedData) Close() error {
	if e.file != nil {
		return e.file.Close()
	}
	return nil
}

func (e *EncryptedData) CopyTo(dest io.Writer) error {
	reader, err := tempFileReader(e.app)
	if reader != nil {
		defer reader.Close()
	}
	if err != nil {
		return fmt.Errorf("opening encryption data file: %w", err)
	}
	_, err = io.Copy(dest, bytes.NewReader(e.Header))
	if err != nil {
		return fmt.Errorf("copying header: %w", err)
	}
	_, err = io.Copy(dest, reader)
	if err != nil {
		return fmt.Errorf("copying body: %w", err)
	}
	return nil
}

func NewEncryptedData(app fyne.App) *EncryptedData {
	return &EncryptedData{
		Header: make([]byte, 0),
		app:    app,
	}
}

func ClearTempFile(app fyne.App) error {
	// Fyne does not provide a way to actually delete a file, so just overwrite it
	// with a single byte.
	writer, err := tempFileWriter(app)
	if writer != nil {
		defer writer.Close()
	}
	if err != nil {
		return fmt.Errorf("opening temp file: %w", err)
	}
	_, err = writer.Write([]byte{0})
	if err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	return nil
}

func isImage(name string) bool {
	for _, ext := range []string{".png", ".jpg", ".jpeg", "svg"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
