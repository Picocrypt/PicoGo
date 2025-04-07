package ui

import (
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"

	"github.com/picocrypt/picogo/internal/encryption"
)

const PicoGoVersion = "v0.1.1"

var fileDescCount int
var fileDescMutex sync.Mutex

func nextFileDescID() int {
	fileDescMutex.Lock()
	defer fileDescMutex.Unlock()
	fileDescCount++
	return fileDescCount
}

type fileDesc struct {
	name string
	uri  string
	id   int
}

func (f *fileDesc) Name() string {
	return f.name
}

func (f *fileDesc) Uri() string {
	return f.uri
}

func NewFileDesc(uri fyne.URI) fileDesc {
	return fileDesc{
		name: uri.Name(),
		uri:  uri.String(),
		id:   nextFileDescID(),
	}
}

type State struct {
	input           *fileDesc
	SaveAs          *fileDesc
	Comments        string
	ReedSolomon     bool
	Deniability     bool
	Paranoid        bool
	OrderedKeyfiles bool
	Keyfiles        []fileDesc
	Password        string
	ConfirmPassword string
}

func (s *State) Input() *fileDesc {
	return s.input
}

func (s *State) IsEncrypting() bool {
	if s.input == nil {
		return false
	}
	return strings.HasSuffix(s.input.Name(), ".pcv")
}

func (s *State) IsDecrypting() bool {
	if s.input == nil {
		return false
	}
	return !strings.HasSuffix(s.input.Name(), ".pcv")
}

func (s *State) SetInput(input fyne.URI) error {
	s.Clear()
	inputDesc := NewFileDesc(input)
	s.input = &inputDesc

	if s.IsDecrypting() {
		reader, err := storage.Reader(input)
		if reader != nil {
			defer reader.Close()
		}
		if err != nil {
			return err
		}
		settings, err := encryption.GetEncryptionSettings(reader)
		if err != nil {
			return err
		}
		s.Comments = settings.Comments
		s.ReedSolomon = settings.ReedSolomon
		s.Deniability = settings.Deniability
		s.Paranoid = settings.Paranoid
		s.OrderedKeyfiles = settings.OrderedKf
	}
	return nil
}

func (s *State) AddKeyfile(uri fyne.URI) {
	s.Keyfiles = append(s.Keyfiles, NewFileDesc(uri))
}

func (s *State) Clear() {
	s.input = nil
	s.SaveAs = nil
	s.Comments = ""
	s.ReedSolomon = false
	s.Deniability = false
	s.Paranoid = false
	s.OrderedKeyfiles = false
	s.Keyfiles = nil
	s.Password = ""
	s.ConfirmPassword = ""
}
