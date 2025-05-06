package ui

import (
	"fmt"
	"log"
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
	log.Println("Set input to", input)
	s.Clear()
	inputDesc := NewFileDesc(input)
	s.input = &inputDesc
	fyne.Do(func() { s.FileName.SetText(inputDesc.Name()) })

	// Update checkboxes
	fyne.Do(func() {
		boxes := []*widget.Check{
			s.ReedSolomon,
			s.Deniability,
			s.Paranoid,
			s.OrderedKeyfiles,
		}
		if s.IsEncrypting() {
			for _, box := range boxes {
				box.Enable()
				box.Refresh()
			}
		} else {
			for _, box := range boxes {
				box.Disable()
				box.Refresh()
			}
		}
		s.updateComments()
	})

	// Update Confirm field visibility
	if s.IsEncrypting() {
		if s.ConfirmPassword.Hidden {
			fyne.Do(func() { s.ConfirmPassword.Show() })
		}
	} else {
		if !s.ConfirmPassword.Hidden {
			fyne.Do(func() { s.ConfirmPassword.Hide() })
		}
	}

	if s.IsDecrypting() {
		reader, err := storage.Reader(input)
		if reader != nil {
			defer reader.Close()
		}
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		settings, err := encryption.GetEncryptionSettings(reader)
		if err != nil {
			return fmt.Errorf("failed to get encryption settings: %w", err)
		}
		fyne.Do(func() {
			s.Comments.SetText(settings.Comments)
			s.ReedSolomon.SetChecked(settings.ReedSolomon)
			s.Deniability.SetChecked(settings.Deniability)
			s.Paranoid.SetChecked(settings.Paranoid)
			s.OrderedKeyfiles.SetChecked(settings.OrderedKf)
		})
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
	fyne.Do(func() {
		s.FileName.SetText("")
		s.input = nil
		s.SaveAs = nil
		s.Comments.SetText("")
		s.ReedSolomon.SetChecked(false)
		s.Deniability.SetChecked(false)
		s.Paranoid.SetChecked(false)
		s.OrderedKeyfiles.SetChecked(false)
		s.Keyfiles = nil
		s.Password.SetText("")
		s.ConfirmPassword.SetText("")
	})
}
