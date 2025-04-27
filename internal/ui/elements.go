package ui

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
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

type KeyfileElement struct {
	text      *widget.Entry
	addBtn    *widget.Button
	createBtn *widget.Button
	clearBtn  *widget.Button
	state     *State
}

func (k *KeyfileElement) UpdateText() {
	names := []string{}
	for _, kf := range k.state.Keyfiles {
		names = append(names, kf.Name())
	}
	text := strings.Join(names, "\n")
	if k.text.Text != text {
		k.text.Text = text
		k.text.Refresh()
	}
}

func (k *KeyfileElement) Container() fyne.CanvasObject {
	c := container.New(
		layout.NewVBoxLayout(),
		keyfileOrderedCheck(k.state),
		k.text,
		container.New(layout.NewHBoxLayout(), k.addBtn, k.createBtn, k.clearBtn),
	)
	return c
}

func keyfileText() *widget.Entry {
	text := widget.NewMultiLineEntry()
	text.Disable()
	text.SetPlaceHolder("No keyfiles added")
	return text
}

func keyfileAddBtn(state *State, logger *Logger, window fyne.Window) *widget.Button {
	btn := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
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
		}, window)
		fd.Show()
	})
	return btn
}

func keyfileCreateBtn(state *State, logger *Logger, window fyne.Window) *widget.Button {
	btn := widget.NewButtonWithIcon("Create", theme.ContentAddIcon(), func() {
		fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
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
		}, window)
		fd.SetFileName("Keyfile")
		fd.Show()
	})
	return btn
}

func keyfileClearBtn(state *State, logger *Logger) *widget.Button {
	btn := widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), func() {
		state.Keyfiles = state.Keyfiles[:0]
		logger.Log("Cleared keyfiles", *state, nil)
	})
	return btn
}

func keyfileOrderedCheck(state *State) *widget.Check {
	orderedKeyfiles := widget.NewCheckWithData("Require correct order", binding.BindBool(&(*state).OrderedKeyfiles))
	if state.IsDecrypting() {
		orderedKeyfiles.Disable()
	}
	return orderedKeyfiles
}

func makeKeyfileElement(logger *Logger, state *State, window fyne.Window) *KeyfileElement {
	element := &KeyfileElement{
		state:     state,
		text:      keyfileText(),
		addBtn:    keyfileAddBtn(state, logger, window),
		createBtn: keyfileCreateBtn(state, logger, window),
		clearBtn:  keyfileClearBtn(state, logger),
	}
	return element
}

func MakeKeyfileBtn(logger *Logger, state *State, updates *UpdateMethods, window fyne.Window) *widget.Button {
	element := makeKeyfileElement(logger, state, window)
	btn := widget.NewButtonWithIcon("Keyfile", theme.ContentAddIcon(), func() {
		c := element.Container()
		dialog.ShowCustom("Keyfiles", "Done", c, window)
	})
	updates.Add(func() {
		element.UpdateText()
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
