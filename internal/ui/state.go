package ui

import (
	"fmt"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/picocrypt/picogo/internal/encryption"
)

const PicoGoVersion = "v0.1.2"

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
	FileName        *widget.Label
	input           *fileDesc
	SaveAs          *fileDesc
	Comments        *widget.Entry
	ReedSolomon     *widget.Check
	Deniability     *widget.Check
	Paranoid        *widget.Check
	OrderedKeyfiles *widget.Check
	Keyfiles        []fileDesc
	KeyfileText     *widget.Entry
	Password        *widget.Entry
	ConfirmPassword *widget.Entry
	WorkBtn         *widget.Button
}

func NewState() *State {
	state := State{
		FileName:        widget.NewLabel(""),
		input:           nil,
		SaveAs:          nil,
		Comments:        makeComments(),
		ReedSolomon:     widget.NewCheck("Reed-Solomon", nil),
		Deniability:     widget.NewCheck("Deniability", nil),
		Paranoid:        widget.NewCheck("Paranoid", nil),
		OrderedKeyfiles: widget.NewCheck("Require correct order", nil),
		Keyfiles:        []fileDesc{},
		KeyfileText:     keyfileText(),
		Password:        makePassword(),
		ConfirmPassword: makeConfirmPassword(),
		WorkBtn:         widget.NewButton("Encrypt", nil),
	}
	state.Deniability.OnChanged = func(checked bool) { state.updateComments() }
	return &state
}

func (s *State) updateComments() {
	if s.Deniability.Checked {
		s.Comments.SetText("")
		s.Comments.SetPlaceHolder("Comments are disabled in deniability mode")
		s.Comments.Disable()
	} else {
		s.Comments.SetPlaceHolder("Comments are not encrypted")
		s.Comments.Enable()
	}
}

func (s *State) Input() *fileDesc {
	return s.input
}

func (s *State) IsEncrypting() bool {
	if s.input == nil {
		return false
	}
	return !strings.HasSuffix(s.input.Name(), ".pcv")
}

func (s *State) IsDecrypting() bool {
	if s.input == nil {
		return false
	}
	return strings.HasSuffix(s.input.Name(), ".pcv")
}

func (s *State) SetInput(input fyne.URI) error {
	inputDesc := NewFileDesc(input)
	s.input = &inputDesc

	settings := encryption.Settings{
		Comments:    "",
		ReedSolomon: false,
		Deniability: false,
		Paranoid:    false,
	}
	if s.IsDecrypting() {
		reader, err := storage.Reader(input)
		if reader != nil {
			defer reader.Close()
		}
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		settings, err = encryption.GetEncryptionSettings(reader)
		if err != nil {
			return fmt.Errorf("failed to get encryption settings: %w", err)
		}
	}

	s.FileName.SetText(s.input.Name())

	// Set Deniability before Comments to overwrite the result of the callback
	s.ReedSolomon.SetChecked(settings.ReedSolomon)
	s.Deniability.SetChecked(settings.Deniability)
	s.Paranoid.SetChecked(settings.Paranoid)
	if s.IsEncrypting() {
		s.ReedSolomon.Enable()
		s.Deniability.Enable()
		s.Paranoid.Enable()
	} else {
		s.ReedSolomon.Disable()
		s.Deniability.Disable()
		s.Paranoid.Disable()
	}

	s.Comments.SetText(settings.Comments)
	if s.IsEncrypting() {
		if settings.Deniability {
			s.Comments.SetText("")
			s.Comments.SetPlaceHolder("Comments are disabled in deniability mode")
			s.Comments.Disable()
		} else {
			s.Comments.SetPlaceHolder("Comments are not encrypted")
			s.Comments.Enable()
		}
	} else {
		s.Comments.SetPlaceHolder("")
		s.Comments.SetPlaceHolder("")
		s.Comments.Disable()
	}

	s.OrderedKeyfiles.Enable()

	if s.IsEncrypting() {
		s.ConfirmPassword.SetPlaceHolder("Confirm password")
		s.ConfirmPassword.Enable()
	} else {
		s.ConfirmPassword.SetPlaceHolder("Not required")
		s.ConfirmPassword.Disable()
	}

	if s.IsEncrypting() {
		s.WorkBtn.SetText("Encrypt")
		s.WorkBtn.Enable()
	} else {
		s.WorkBtn.SetText("Decrypt")
		s.WorkBtn.Enable()
	}

	return nil
}

func (s *State) AddKeyfile(uri fyne.URI) {
	s.Keyfiles = append(s.Keyfiles, NewFileDesc(uri))
	names := []string{}
	for _, kf := range s.Keyfiles {
		names = append(names, kf.Name())
	}
	msg := strings.Join(names, "\n")
	fyne.Do(func() { s.KeyfileText.SetText(msg) })
}

func (s *State) ClearKeyfiles() {
	s.Keyfiles = []fileDesc{}
	fyne.Do(func() { s.KeyfileText.SetText("No keyfiles added") })
}

func (s *State) Clear() {
	s.input = nil
	s.SaveAs = nil
	s.Keyfiles = nil
	fyne.DoAndWait(func() {
		s.FileName.SetText("")
		s.Comments.SetText("")
		s.ReedSolomon.SetChecked(false)
		s.Deniability.SetChecked(false)
		s.Paranoid.SetChecked(false)
		s.OrderedKeyfiles.SetChecked(false)
		s.Password.SetText("")
		s.ConfirmPassword.SetText("")
	})
}
