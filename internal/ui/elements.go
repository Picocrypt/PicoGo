package ui

import (
	"crypto/rand"
	"errors"
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

func MakeInfoBtn(w fyne.Window) *widget.Button { // coverage-ignore
	btn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		title := "PicoGo " + PicoGoVersion
		message := "This app is not sponsored or supported by Picocrypt. It is a 3rd party " +
			"app written to make Picocrypt files more easily accessible on mobile devices.\n\n" +
			"If you have any problems, please report them so that they can be fixed."
		confirm := dialog.NewInformation(title, message, w)
		confirm.Show()
	})
	return btn
}

func writeLogsCallback(logger *Logger, window fyne.Window) func(fyne.URIWriteCloser, error) {
	return func(writer fyne.URIWriteCloser, err error) {
		if writer != nil {
			defer writer.Close()
		}
		if err != nil { // coverage-ignore
			logger.Log("Writing logs failed", State{}, err)
			dialog.ShowError(fmt.Errorf("writing logs: %w", err), window)
			return
		}
		if writer != nil {
			writer.Write([]byte(logger.CsvString()))
		}
	}
}

func writeLogs(logger *Logger, window fyne.Window) { // coverage-ignore
	d := dialog.NewFileSave(writeLogsCallback(logger, window), window)
	d.SetFileName("picogo-logs.csv")
	d.Show()
}

func MakeLogBtn(logger *Logger, w fyne.Window) *widget.Button { // coverage-ignore
	btn := widget.NewButtonWithIcon("", theme.MailSendIcon(), func() {
		title := "Save Logs"
		message := "Save log data to assist with issue reporting. Sensitive data (passwords, file names, etc.) " +
			"will not be recorded, but you should still review the logs before sharing to ensure you are " +
			"comfortable with the data being shared."
		text := widget.NewLabel(message)
		text.Wrapping = fyne.TextWrapWord
		dialog.ShowCustomConfirm(title, "Save Logs", "Dismiss", text, func(b bool) {
			if b {
				writeLogs(logger, w)
			}
		}, w)
	})
	return btn
}

func filePickerCallback(state *State, logger *Logger, w fyne.Window) func(fyne.URIReadCloser, error) {
	return func(reader fyne.URIReadCloser, err error) {
		if reader != nil {
			defer reader.Close()
		}
		if err != nil { // coverage-ignore
			logger.Log("Choosing file to encrypt/decrypt failed", *state, err)
			dialog.ShowError(fmt.Errorf("choosing file: %w", err), w)
			return
		}
		if reader == nil {
			logger.Log("Choosing file to encrypt/decrypt failed", *state, errors.New("no file chosen"))
			return
		}
		err = state.SetInput(reader.URI())
		logger.Log("Setting file to encrypt/decrypt", *state, err)
		if err != nil { // coverage-ignore
			dialog.ShowError(fmt.Errorf("choosing file: %w", err), w)
		}
	}
}

func MakeFilePicker(state *State, logger *Logger, w fyne.Window) *widget.Button { // coverage-ignore
	picker := widget.NewButtonWithIcon("Choose File", theme.FileIcon(), func() {
		fd := dialog.NewFileOpen(filePickerCallback(state, logger, w), w)
		fd.Show()
	})
	return picker
}

func filenameUpdate(entry *widget.Entry, state *State) func() {
	return func() {
		input := state.Input()
		text := ""
		if input != nil {
			text = input.Name()
		}
		if entry.Text != text {
			entry.Text = text
			entry.Refresh()
		}
	}
}

func MakeFileName(state *State, updates *UpdateMethods) *widget.Entry {
	filename := widget.NewEntry()
	filename.Disable()
	filename.SetPlaceHolder("No file chosen")
	updates.Add(filenameUpdate(filename, state))
	return filename
}

func updateComments(entry *widget.Entry, binding binding.ExternalString, state *State) func() {
	return func() {
		shouldEnable := state.IsEncrypting() && !state.Deniability
		placeholder := ""
		if state.IsEncrypting() && state.Deniability {
			placeholder = "Comments are disabled in deniability mode"
			state.Comments = ""
		} else if state.IsEncrypting() {
			placeholder = "Comments are not encrypted"
		}
		binding.Reload()
		refresh := false
		if placeholder != entry.PlaceHolder {
			entry.PlaceHolder = placeholder
			refresh = true
		}
		if shouldEnable && entry.Disabled() {
			entry.Enable()
			refresh = true
		}
		if !shouldEnable && !entry.Disabled() {
			entry.Disable()
			refresh = true
		}
		if refresh {
			entry.Refresh()
		}
	}
}

func MakeComments(state *State, updates *UpdateMethods) *widget.Entry {
	comments := widget.NewMultiLineEntry()
	binding := binding.BindString(&state.Comments)
	comments.Bind(binding)
	comments.Validator = nil
	comments.Wrapping = fyne.TextWrapWord
	updates.Add(updateComments(comments, binding, state))
	return comments
}

func MakeSettingCheck(name string, b *bool, state *State, updates *UpdateMethods) *widget.Check {
	binding := binding.BindBool(b)
	check := widget.NewCheckWithData(name, binding)
	updates.Add(func() {
		binding.Reload()
		if state.IsEncrypting() {
			if check.Disabled() {
				check.Enable()
			}
		} else if !check.Disabled() {
			check.Disable()
		}
	})
	return check
}

func keyfileText() *widget.Entry { // coverage-ignore
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
		if err != nil { // coverage-ignore
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

func keyfileAddBtn(state *State, logger *Logger, window fyne.Window, textUpdate func()) *widget.Button { // coverage-ignore
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
		if err != nil { // coverage-ignore
			logger.Log("Creating keyfile failed", *state, err)
			dialog.ShowError(fmt.Errorf("creating keyfile: %w", err), window)
			return
		}
		if writer != nil {
			data := make([]byte, 32)
			_, err := rand.Read(data)
			if err != nil { // coverage-ignore
				logger.Log("Creating keyfile data failed", *state, err)
				dialog.ShowError(fmt.Errorf("creating keyfile: %w", err), window)
				return
			}
			_, err = writer.Write(data)
			if err != nil { // coverage-ignore
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

func keyfileCreateBtn(state *State, logger *Logger, window fyne.Window, textUpdate func()) *widget.Button { // coverage-ignore
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

func keyfileClearBtn(state *State, logger *Logger, textUpdate func()) *widget.Button { // coverage-ignore
	btn := widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), keyfileClearCallback(state, logger, textUpdate))
	return btn
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

func MakeKeyfileBtn(logger *Logger, state *State, updates *UpdateMethods, window fyne.Window) *widget.Button { // coverage-ignore
	btn := widget.NewButtonWithIcon("Keyfile", theme.ContentAddIcon(), func() {
		text := keyfileText()
		textUpdate := keyfileTextUpdate(state, text)
		textUpdate()
		c := container.New(
			layout.NewVBoxLayout(),
			MakeSettingCheck("Require order", &state.OrderedKeyfiles, state, updates),
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

func MakePassword(state *State, updates *UpdateMethods) *widget.Entry {
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Password")
	binding := binding.BindString(&state.Password)
	password.Bind(binding)
	password.Validator = nil
	updates.Add(func() {
		binding.Reload()
		if state.IsDecrypting() || state.IsEncrypting() {
			if password.Disabled() {
				password.Enable()
			}
		} else if !password.Disabled() {
			password.Disable()
		}
	})
	return password
}

func MakeConfirmPassword(state *State, updates *UpdateMethods) *widget.Entry {
	confirm := widget.NewPasswordEntry()
	confirm.SetPlaceHolder("Confirm password")
	binding := binding.BindString(&state.ConfirmPassword)
	confirm.Bind(binding)
	confirm.Validator = nil
	updates.Add(func() {
		binding.Reload()
		if state.IsEncrypting() {
			if !confirm.Visible() {
				confirm.Show()
			}
		} else if confirm.Visible() {
			confirm.Hide()
		}
	})
	return confirm
}

func workBtnCallback(state *State, logger *Logger, w fyne.Window, encrypt func(), decrypt func()) func() {
	return func() {
		if !(state.IsEncrypting() || state.IsDecrypting()) {
			// This should never happen (the button should be hidden), but check in case
			// there is a race condition
			logger.Log("Encrypt/Decrypt button pressed", *state, errors.New("button should be hidden"))
			dialog.ShowError(errors.New("no file chosen"), w)
			return
		}
		if state.IsEncrypting() {
			if state.Password != state.ConfirmPassword {
				logger.Log("Encrypt/Decrypt button pressed", *state, errors.New("passwords do not match"))
				dialog.ShowError(errors.New("passwords do not match"), w)
			} else if state.Password == "" {
				logger.Log("Encrypt/Decrypt button pressed", *state, errors.New("password cannot be blank"))
				dialog.ShowError(errors.New("password cannot be blank"), w)
			} else {
				logger.Log("Encrypt/Decrypt button pressed (encrypting)", *state, nil)
				encrypt()
			}
			return
		}
		logger.Log("Encrypt/Decrypt button pressed (decrypting)", *state, nil)
		decrypt()
	}
}

func MakeWorkBtn(logger *Logger, state *State, w fyne.Window, encrypt func(), decrypt func(), updates *UpdateMethods) *widget.Button {
	workBtn := widget.NewButton("Encrypt/Decrypt", func() {
		workBtnCallback(state, logger, w, encrypt, decrypt)()
	})
	updates.Add(func() {
		text := ""
		if state.IsEncrypting() {
			text = "Encrypt"
		} else if state.IsDecrypting() {
			text = "Decrypt"
		}
		if workBtn.Text != text {
			workBtn.Text = text
			workBtn.Refresh()
		}
		if text == "" && workBtn.Visible() {
			workBtn.Hide()
		}
		if text != "" && !workBtn.Visible() {
			workBtn.Show()
		}
	})
	return workBtn
}
