package ui

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type UpdateMethods struct {
	funcs []func()
}

func (u *UpdateMethods) Add(f func()) {
	u.funcs = append(u.funcs, f)
}

func (u *UpdateMethods) Update() {
	for _, f := range u.funcs {
		f()
	}
}

func keyfileText() *widget.Entry {
	text := widget.NewMultiLineEntry()
	text.Disable()
	text.SetPlaceHolder("No keyfiles added")
	return text
}

func keyfileAddCallback(state *State, logger *Logger, window fyne.Window, textUpdate func()) func(fyne.URIReadCloser, error) {
	return func(reader fyne.URIReadCloser, err error) {
		defer textUpdate()
		if reader != nil {
			defer reader.Close()
		}
		if err != nil {
			logger.Log("Adding keyfile failed", *state, err)
			dialog.ShowError(fmt.Errorf("adding keyfile: %w", err), window)
			return
		}
		if reader != nil {
			state.AddKeyfile(reader.URI())
			logger.Log("Adding keyfile complete", *state, nil)
		} else {
			logger.Log("Adding keyfile canceled", *state, nil)
		}
	}
}

func keyfileAddBtn(state *State, logger *Logger, window fyne.Window, textUpdate func()) *widget.Button {
	btn := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		fd := dialog.NewFileOpen(keyfileAddCallback(state, logger, window, textUpdate), window)
		fd.Show()
	})
	return btn
}

func keyfileCreateCallback(state *State, logger *Logger, window fyne.Window, textUpdate func()) func(fyne.URIWriteCloser, error) {
	return func(writer fyne.URIWriteCloser, err error) {
		defer textUpdate()
		if writer != nil {
			defer writer.Close()
		}
		if err != nil {
			logger.Log("Creating keyfile failed", *state, err)
			dialog.ShowError(fmt.Errorf("creating keyfile: %w", err), window)
			return
		}
		if writer != nil {
			data := make([]byte, 32)
			_, err := rand.Read(data)
			if err != nil {
				logger.Log("Creating keyfile data failed", *state, err)
				dialog.ShowError(fmt.Errorf("creating keyfile: %w", err), window)
				return
			}
			_, err = writer.Write(data)
			if err != nil {
				logger.Log("Writing keyfile failed", *state, err)
				dialog.ShowError(fmt.Errorf("writing keyfile: %w", err), window)
				return
			}
			state.AddKeyfile(writer.URI())
			logger.Log("Created keyfile", *state, nil)
		} else {
			logger.Log("Creating keyfile canceled", *state, nil)
		}
	}
}

func keyfileCreateBtn(state *State, logger *Logger, window fyne.Window, textUpdate func()) *widget.Button {
	btn := widget.NewButtonWithIcon("Create", theme.ContentAddIcon(), func() {
		fd := dialog.NewFileSave(keyfileCreateCallback(state, logger, window, textUpdate), window)
		fd.SetFileName("Keyfile")
		fd.Show()
	})
	return btn
}

func keyfileClearCallback(state *State, logger *Logger, textUpdate func()) func() {
	return func() {
		defer textUpdate()
		logger.Log("Clearing keyfiles", *state, nil)
		state.Keyfiles = state.Keyfiles[:0]
	}
}

func keyfileClearBtn(state *State, logger *Logger, textUpdate func()) *widget.Button {
	btn := widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), keyfileClearCallback(state, logger, textUpdate))
	return btn
}

func keyfileOrderedCallback(state *State) func(bool) {
	return func(checked bool) {
		(*state).OrderedKeyfiles = checked
	}
}

func keyfileOrderedCheck(state *State) *widget.Check {
	orderedKeyfiles := widget.NewCheck("Require correct order", keyfileOrderedCallback(state))
	orderedKeyfiles.SetChecked(state.OrderedKeyfiles)
	if state.IsDecrypting() {
		orderedKeyfiles.Disable()
	}
	return orderedKeyfiles
}

func keyfileTextUpdate(state *State, text *widget.Entry) func() {
	return func() {
		names := []string{}
		for _, kf := range state.Keyfiles {
			names = append(names, kf.Name())
		}
		msg := strings.Join(names, "\n")
		if text.Text != msg {
			text.Text = msg
			text.Refresh()
		}
	}
}

func MakeKeyfileBtn(logger *Logger, state *State, updates *UpdateMethods, window fyne.Window) *widget.Button {
	btn := widget.NewButtonWithIcon("Keyfile", theme.ContentAddIcon(), func() {
		text := keyfileText()
		textUpdate := keyfileTextUpdate(state, text)
		textUpdate()
		c := container.New(
			layout.NewVBoxLayout(),
			keyfileOrderedCheck(state),
			text,
			container.New(
				layout.NewHBoxLayout(),
				keyfileAddBtn(state, logger, window, textUpdate),
				keyfileCreateBtn(state, logger, window, textUpdate),
				keyfileClearBtn(state, logger, textUpdate),
			),
		)
		dialog.ShowCustom("Keyfiles", "Done", c, window)
	})
	updates.Add(func() {
		btnName := "Keyfiles [" + strconv.Itoa(len(state.Keyfiles)) + "]"
		if btn.Text != btnName {
			btn.Text = btnName
			btn.Refresh()
		}
		shouldEnable := state.IsEncrypting() || state.IsDecrypting()
		if shouldEnable && btn.Disabled() {
			btn.Enable()
		}
		if !shouldEnable && !btn.Disabled() {
			btn.Disable()
		}
	})
	return btn
}
