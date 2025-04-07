package main

import (
	"crypto/rand"
	"errors"
	"image/color"
	"io"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/picocrypt/picogo/internal/encryption"
	"github.com/picocrypt/picogo/internal/ui"
)

type myTheme struct{}

func (m myTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xff}
	default:
		return theme.DarkTheme().Color(name, variant)
	}
}
func (m myTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DarkTheme().Font(style)
}
func (m myTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DarkTheme().Icon(name)
}
func (m myTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DarkTheme().Size(name) * 1.5
}

var _ fyne.Theme = (*myTheme)(nil)

func uriReadCloser(uri string) (fyne.URIReadCloser, error) {
	fullUri, err := storage.ParseURI(uri)
	if err != nil {
		return nil, err
	}
	return storage.Reader(fullUri)
}

func uriWriteCloser(uri string) (fyne.URIWriteCloser, error) {
	fullUri, err := storage.ParseURI(uri)
	if err != nil {
		return nil, err
	}
	return storage.Writer(fullUri)
}

type State struct {
	InputURI        string
	InputName       string
	SaveAsURI       string
	Comments        string
	ReedSolomon     bool
	Deniability     bool
	Paranoid        bool
	OrderedKeyfiles bool
	IsEncrypting    bool
	IsDecrypting    bool
	KeyfileURIs     []string
	KeyfileNames    []string
	Password        string
	ConfirmPassword string
}

func (s *State) SetInputURI(input fyne.URI) error {
	s.Clear()
	s.InputURI = input.String()
	s.InputName = input.Name()
	s.IsEncrypting = input.Extension() != ".pcv"
	s.IsDecrypting = !s.IsEncrypting

	if s.IsDecrypting {
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

func (s *State) AddKeyfileURI(uri fyne.URI) {
	s.KeyfileNames = append(s.KeyfileNames, uri.Name())
	s.KeyfileURIs = append(s.KeyfileURIs, uri.String())
}

func (s *State) Clear() {
	s.InputURI = ""
	s.InputName = ""
	s.SaveAsURI = ""
	s.Comments = ""
	s.ReedSolomon = false
	s.Deniability = false
	s.Paranoid = false
	s.OrderedKeyfiles = false
	s.IsEncrypting = false
	s.IsDecrypting = false
	s.KeyfileURIs = []string{}
	s.KeyfileNames = []string{}
	s.Password = ""
	s.ConfirmPassword = ""
}

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

func clearFile(uri fyne.URI) error {
	writer, err := storage.Writer(uri)
	if writer != nil {
		defer writer.Close()
	}
	if err != nil {
		return err
	}
	_, err = writer.Write(make([]byte, 1))
	return err
}

func getHeadlessURI(app fyne.App) (fyne.URI, error) {
	return storage.Child(app.Storage().RootURI(), "headless")
}

func clearHeadlessFile(app fyne.App) error {
	headlessURI, err := getHeadlessURI(app)
	if err != nil {
		return err
	}
	return clearFile(headlessURI)
}

func getOutputURI(app fyne.App) (fyne.URI, error) {
	return storage.Child(app.Storage().RootURI(), "output")
}

func clearOutputFile(app fyne.App) error {
	outputURI, err := getOutputURI(app)
	if err != nil {
		return err
	}
	return clearFile(outputURI)
}

func chooseSaveAs(state *State, window fyne.Window) {
	d := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if writer != nil {
			defer writer.Close()
		}
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		if writer != nil {
			state.SaveAsURI = writer.URI().String()
		}
	}, window)
	if state.IsEncrypting {
		d.SetFileName(state.InputName + ".pcv")
	} else {
		// remove .pcv from the end of the filename
		d.SetFileName(state.InputName[:len(state.InputName)-4])
	}
	d.Show()
}

func saveOutput(state *State, window fyne.Window, app fyne.App) {
	if state.SaveAsURI == "" {
		return
	}
	defer func() { state.SaveAsURI = "" }()
	outputURI, err := getOutputURI(app)
	if err != nil {
		dialog.ShowError(err, window)
		return
	}
	output, err := storage.Reader(outputURI)
	if output != nil {
		defer output.Close()
	}
	if err != nil {
		dialog.ShowError(err, window)
		return
	}
	saveAs, err := uriWriteCloser(state.SaveAsURI)
	if saveAs != nil {
		defer saveAs.Close()
	}
	if err != nil {
		dialog.ShowError(err, window)
		return
	}
	errCh := make(chan error)
	go func() {
		_, err := io.Copy(saveAs, output)
		errCh <- err
	}()

	// progress bar
	d := dialog.NewCustomWithoutButtons(
		"Saving",
		container.New(layout.NewVBoxLayout(), widget.NewProgressBarInfinite()),
		window,
	)
	d.Show()

	// Block until completion
	for {
		select {
		case err := <-errCh:
			d.Hide()
			if err != nil {
				dialog.ShowError(err, window)
			}
			err = clearOutputFile(app)
			if err != nil {
				dialog.ShowError(err, window)
			}
			return
		default:
			time.Sleep(time.Second / 10)
		}
	}
}

func encrypt(state *State, win fyne.Window, app fyne.App) {
	updateCh := make(chan encryption.Update)
	errCh := make(chan error)

	go func() {
		headlessURI, err := getHeadlessURI(app)
		if err != nil {
			errCh <- err
			return
		}
		input, err := uriReadCloser(state.InputURI)
		if input != nil {
			defer input.Close()
		}
		if err != nil {
			errCh <- err
			return
		}

		headlessWriter, err := storage.Writer(headlessURI)
		if headlessWriter != nil {
			defer clearHeadlessFile(app)
			defer headlessWriter.Close()
		}
		if err != nil {
			errCh <- err
			return
		}

		keyfiles := []io.Reader{}
		for i := 0; i < len(state.KeyfileURIs); i++ {
			r, err := uriReadCloser(state.KeyfileURIs[i])
			if r != nil {
				defer r.Close()
			}
			if err != nil {
				errCh <- err
				return
			}
			keyfiles = append(keyfiles, r)
		}
		settings := encryption.Settings{
			Comments:    state.Comments,
			ReedSolomon: state.ReedSolomon,
			Paranoid:    state.Paranoid,
			OrderedKf:   state.OrderedKeyfiles,
			Deniability: state.Deniability,
		}
		header, err := encryption.EncryptHeadless(
			input, state.Password, keyfiles, settings, headlessWriter, updateCh,
		)
		if err != nil {
			errCh <- err
			return
		}

		headlessReader, err := storage.Reader(headlessURI)
		if headlessReader != nil {
			defer headlessReader.Close()
		}
		if err != nil {
			errCh <- err
			return
		}

		outputURI, err := getOutputURI(app)
		if err != nil {
			errCh <- err
			return
		}
		output, err := storage.Writer(outputURI)
		if output != nil {
			defer output.Close()
		}
		if err != nil {
			errCh <- err
			return
		}

		err = encryption.PrependHeader(headlessReader, output, header)
		errCh <- err
	}()

	// Show progress, blocking until completion
	status := widget.NewLabel("")
	d := dialog.NewCustomWithoutButtons(
		"Encrypting",
		container.New(layout.NewVBoxLayout(), widget.NewProgressBarInfinite(), status),
		win,
	)
	d.Show()
	var encryptErr error
	for {
		doBreak := false
		select {
		case update := <-updateCh:
			status.SetText(update.Status)
		case err := <-errCh:
			d.Hide()
			encryptErr = err
			doBreak = true
		default:
			time.Sleep(time.Second / 10)
		}
		if doBreak {
			break
		}
	}
	if encryptErr != nil {
		dialog.ShowError(encryptErr, win)
		return
	}
	text := widget.NewLabel(state.InputName + " has been encrypted.")
	text.Wrapping = fyne.TextWrapWord
	dialog.ShowCustomConfirm(
		"Encryption Complete",
		"Save",
		"Cancel",
		text,
		func(b bool) {
			if b {
				chooseSaveAs(state, win)
			}
		},
		win,
	)
}

func tryDecrypt(
	state *State,
	recoveryMode bool,
	w fyne.Window,
	app fyne.App,
) (bool, error) {
	input, err := uriReadCloser(state.InputURI)
	if err != nil {
		return false, err
	}
	defer input.Close()

	keyfiles := []io.Reader{}
	for i := 0; i < len(state.KeyfileURIs); i++ {
		r, err := uriReadCloser(state.KeyfileURIs[i])
		if err != nil {
			return false, err
		}
		defer r.Close()
		keyfiles = append(keyfiles, r)
	}

	outputURI, err := getOutputURI(app)
	if err != nil {
		return false, err
	}
	output, err := uriWriteCloser(outputURI.String())
	if err != nil {
		return false, err
	}
	defer output.Close()

	updateCh := make(chan encryption.Update)
	errCh := make(chan struct {
		bool
		error
	})
	go func() {
		damaged, err := encryption.Decrypt(state.Password, keyfiles, input, output, recoveryMode, updateCh)
		errCh <- struct {
			bool
			error
		}{damaged, err}
	}()

	// Block until completion
	status := widget.NewLabel("")
	d := dialog.NewCustomWithoutButtons(
		"Decrypting",
		container.New(layout.NewVBoxLayout(), widget.NewProgressBarInfinite(), status),
		w,
	)
	d.Show()
	for {
		select {
		case update := <-updateCh:
			status.SetText(update.Status)
		case err := <-errCh:
			d.Hide()
			return err.bool, err.error
		default:
			time.Sleep(time.Second / 10)
		}
	}
}

func decrypt(state *State, win fyne.Window, app fyne.App) {
	damaged, err := tryDecrypt(state, false, win, app)
	recoveryMode := false
	recoveryCanceled := false
	if errors.Is(err, encryption.ErrBodyCorrupted) {
		// Offer to try again in recovery mode
		text := widget.NewLabel("The file is damaged. Would you like to try again in recovery mode?")
		text.Wrapping = fyne.TextWrapWord
		doneCh := make(chan struct{})
		dialog.ShowCustomConfirm(
			"Damaged File",
			"Recover",
			"Cancel",
			text,
			func(b bool) {
				if b {
					recoveryMode = true
					damaged, err = tryDecrypt(state, true, win, app)
				} else {
					recoveryCanceled = true
				}
				doneCh <- struct{}{}
			},
			win,
		)
		<-doneCh
	}
	if recoveryCanceled {
		return
	}

	msg := ""
	save := false
	if err == nil && !damaged {
		msg = state.InputName + " has been decrypted."
		save = true
	} else if err == nil && damaged {
		msg = state.InputName + " has been decrypted successfully, but it is damaged. Consider re-encryting and replacing the damaged file."
		save = true
	} else {
		switch {
		case errors.Is(err, encryption.ErrBodyCorrupted):
			if recoveryMode {
				msg = "The file is too damaged to recover. Would you like to save the partially recovered file?"
				save = true
			} else {
				msg = "The file is too damaged to recover."
				save = false
			}
		case errors.Is(err, encryption.ErrIncorrectKeyfiles):
			msg = "One or more keyfiles are incorrect."
			save = false
		case errors.Is(err, encryption.ErrIncorrectPassword):
			msg = "The password is incorrect."
			save = false
		case errors.Is(err, encryption.ErrKeyfilesNotRequired):
			msg = "Keyfiles are not required to decrypt this file. Please remove them and try again."
			save = false
		case errors.Is(err, encryption.ErrKeyfilesRequired):
			msg = "Keyfiles are required to decrypt this file. Please add them and try again."
			save = false
		default:
			msg = "Error while decrypting: " + err.Error()
		}
	}
	if save {
		text := widget.NewLabel(msg)
		text.Wrapping = fyne.TextWrapWord
		dialog.ShowCustomConfirm(
			"Decryption Complete",
			"Save",
			"Cancel",
			text,
			func(b bool) {
				if b {
					chooseSaveAs(state, win)
				}
			},
			win,
		)
	} else {
		dialog.ShowError(errors.New(msg), win)
	}
}

func border() *canvas.Rectangle {
	b := canvas.NewRectangle(color.White)
	b.FillColor = color.Transparent
	b.StrokeColor = color.White
	b.StrokeWidth = 1
	return b
}

func makeKeyfileBtn(state *State, window fyne.Window) *widget.Button {
	btn := widget.NewButtonWithIcon("Keyfile", theme.ContentAddIcon(), func() {
		text := widget.NewMultiLineEntry()
		text.Disable()
		updateText := func() {
			text.SetText(strings.Join(state.KeyfileNames, "\n"))
		}
		updateText()
		addBtn := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
			fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if reader != nil {
					defer reader.Close()
				}
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				if reader != nil {
					state.AddKeyfileURI(reader.URI())
					updateText()
				}
			}, window)
			fd.Show()
		})
		createBtn := widget.NewButtonWithIcon("Create", theme.ContentAddIcon(), func() {
			fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
				if writer != nil {
					defer writer.Close()
				}
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				if writer != nil {
					data := make([]byte, 32)
					_, err := rand.Read(data)
					if err != nil {
						dialog.ShowError(err, window)
						return
					}
					_, err = writer.Write(data)
					if err != nil {
						dialog.ShowError(err, window)
						return
					}
					state.AddKeyfileURI(writer.URI())
					updateText()
				}
			}, window)
			fd.SetFileName("Keyfile")
			fd.Show()
		})
		clearBtn := widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), func() {
			state.KeyfileURIs = []string{}
			state.KeyfileNames = []string{}
			updateText()
		})
		orderedKeyfiles := widget.NewCheckWithData("Require correct order", binding.BindBool(&(*state).OrderedKeyfiles))
		if state.IsDecrypting {
			orderedKeyfiles.Disable()
		}
		c := container.New(
			layout.NewVBoxLayout(),
			orderedKeyfiles,
			text,
			container.New(
				layout.NewHBoxLayout(),
				addBtn,
				createBtn,
				clearBtn,
			),
		)
		dialog.ShowCustom("Keyfiles", "Done", c, window)
	})
	return btn
}

var developmentWarningShown = false

func developmentWarning(win fyne.Window) {
	if !developmentWarningShown {
		dialog.ShowInformation(
			"Warning",
			"This app is in early development and has not been thoroughly tested",
			win,
		)
		developmentWarningShown = true
	}
}

func writeLogs(logger ui.Logger, window fyne.Window) {
	d := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if writer != nil {
			defer writer.Close()
		}
		if err != nil {
			return
		}
		if writer != nil {
			writer.Write([]byte(logger.CsvString()))
		}
	}, window)
	d.SetFileName("picogo-logs.csv")
	d.Show()
}

func main() {
	a := app.New()
	a.Settings().SetTheme(&myTheme{})
	w := a.NewWindow("PicoGo")
	logger := ui.Logger{}

	state := State{}
	updates := UpdateMethods{}

	info := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		title := "PicoGo " + ui.PicoGoVersion
		message := "This app is not sponsored or supported by Picocrypt. It is a 3rd party " +
			"app written to make Picocrypt files more easily accessible on mobile devices.\n\n" +
			"If you have any problems, please report them so that they can be fixed."
		confirm := dialog.NewInformation(title, message, w)
		confirm.Show()
	})
	logBtn := widget.NewButtonWithIcon("", theme.MailSendIcon(), func() {
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
	info_row := container.New(
		layout.NewHBoxLayout(),
		info,
		logBtn,
		layout.NewSpacer(),
	)

	picker := widget.NewButtonWithIcon("Choose File", theme.FileIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if reader != nil {
				defer reader.Close()
			}
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}
			err = state.SetInputURI(reader.URI())
			if err != nil {
				dialog.ShowError(err, w)
			}
		}, w)
		fd.Show()
	})

	filenameBinding := binding.BindString(&state.InputName)
	filename := widget.NewEntryWithData(filenameBinding)
	filename.Disable()
	comments := widget.NewMultiLineEntry()
	commentsBinding := binding.BindString(&state.Comments)
	comments.Bind(commentsBinding)
	comments.Validator = nil
	comments.Wrapping = fyne.TextWrapWord
	file_row := container.New(
		layout.NewStackLayout(),
		border(),
		container.New(
			layout.NewFormLayout(),
			widget.NewLabel("File"), container.NewPadded(container.NewPadded(filename)),
			widget.NewLabel("Comments"), container.NewPadded(container.NewPadded(comments)),
		),
	)
	updates.Add(func() {
		filenameBinding.Reload()
		if state.IsEncrypting {
			if state.Deniability {
				state.Comments = ""
				commentsBinding.Reload()
				comments.Disable()
				comments.SetPlaceHolder("Comments are disabled in deniability mode")
			} else {
				comments.Enable()
				comments.SetPlaceHolder("Comments are not encrypted")
			}
		} else {
			commentsBinding.Reload()
			comments.Disable()
			comments.SetPlaceHolder("")
		}
	})

	// Advanced encryption settings
	reedSolomonBinding := binding.BindBool(&state.ReedSolomon)
	paranoidBinding := binding.BindBool(&state.Paranoid)
	deniabilityBinding := binding.BindBool(&state.Deniability)
	updates.Add(func() {
		reedSolomonBinding.Reload()
		paranoidBinding.Reload()
		deniabilityBinding.Reload()
	})
	reedSolomonCheck := widget.NewCheckWithData("Reed Solomon", reedSolomonBinding)
	paranoidCheck := widget.NewCheckWithData("Paranoid", paranoidBinding)
	deniabilityCheck := widget.NewCheckWithData("Deniability", deniabilityBinding)
	updates.Add(func() {
		checks := []*widget.Check{reedSolomonCheck, paranoidCheck, deniabilityCheck}
		for _, check := range checks {
			if state.IsEncrypting {
				check.Enable()
			} else {
				check.Disable()
			}
		}
	})
	keyfileBtn := makeKeyfileBtn(&state, w)
	updates.Add(func() {
		keyfileBtn.SetText("Keyfiles [" + strconv.Itoa(len(state.KeyfileURIs)) + "]")
		if state.IsEncrypting || state.IsDecrypting {
			keyfileBtn.Enable()
		} else {
			keyfileBtn.Disable()
		}
	})
	advanced_settings_row := container.New(
		layout.NewStackLayout(),
		border(),
		container.New(
			layout.NewVBoxLayout(),
			widget.NewRichTextFromMarkdown("### Advanced Settings"),
			container.New(
				layout.NewGridLayoutWithColumns(2),
				container.New(
					layout.NewVBoxLayout(),
					reedSolomonCheck,
					paranoidCheck,
					deniabilityCheck,
				),
				container.NewPadded(
					container.New(
						layout.NewVBoxLayout(),
						keyfileBtn,
					),
				),
			),
		),
	)

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Password")
	passwordBinding := binding.BindString(&state.Password)
	password.Bind(passwordBinding)
	password.Validator = nil
	updates.Add(func() {
		if state.IsDecrypting || state.IsEncrypting {
			password.Enable()
		} else {
			password.Disable()
		}
	})
	confirm := widget.NewPasswordEntry()
	confirm.SetPlaceHolder("Confirm password")
	confirmBinding := binding.BindString(&state.ConfirmPassword)
	confirm.Bind(confirmBinding)
	confirm.Validator = nil
	updates.Add(func() {
		passwordBinding.Reload()
		confirmBinding.Reload()
		if state.IsEncrypting {
			confirm.Show()
		} else {
			confirm.Hide()
		}
	})
	passwordRow := container.New(
		layout.NewStackLayout(),
		border(),
		container.NewPadded(container.NewPadded(
			container.New(
				layout.NewVBoxLayout(),
				password,
				confirm,
			),
		)),
	)

	workBtn := widget.NewButton("Encrypt/Decrypt", func() {
		if !(state.IsEncrypting || state.IsDecrypting) {
			// This should never happen (the button should be hidden), but check in case
			// there is a race condition
			dialog.ShowError(errors.New("no file chosen"), w)
			return
		}
		if state.IsEncrypting {
			if state.Password != state.ConfirmPassword {
				dialog.ShowError(errors.New("passwords do not match"), w)
			} else if state.Password == "" {
				dialog.ShowError(errors.New("password cannot be blank"), w)
			} else {
				encrypt(&state, w, a)
			}
			return
		}
		decrypt(&state, w, a)
	})
	updates.Add(func() {
		if state.IsEncrypting {
			workBtn.SetText("Encrypt")
			workBtn.Show()
		} else if state.IsDecrypting {
			workBtn.SetText("Decrypt")
			workBtn.Show()
		} else {
			workBtn.Hide()
		}
	})

	w.SetContent(
		container.New(
			layout.NewVBoxLayout(),
			info_row,
			picker,
			file_row,
			advanced_settings_row,
			passwordRow,
			workBtn,
		),
	)

	updates.Add(func() {
		developmentWarning(w)
	})

	updates.Add(func() {
		saveOutput(&state, w, a)
	})

	go func() {
		for {
			updates.Update()
			time.Sleep(time.Second / 10)
		}
	}()
	w.ShowAndRun()
}
