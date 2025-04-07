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

func chooseSaveAs(logger *ui.Logger, state *ui.State, window fyne.Window) {
	d := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if writer != nil {
			defer writer.Close()
		}
		logger.Log("Chose save as", *state, err)
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		if writer != nil {
			saveAs := ui.NewFileDesc(writer.URI())
			state.SaveAs = &saveAs
			logger.Log("Set save as", *state, nil)
		} else {
			logger.Log("Set save as", *state, errors.New("no file chosen"))
		}
	}, window)
	if state.IsEncrypting() {
		d.SetFileName(state.Input().Name() + ".pcv")
	} else {
		// remove .pcv from the end of the filename
		d.SetFileName(state.Input().Name()[:len(state.Input().Name())-4])
	}
	d.Show()
}

func saveOutput(logger *ui.Logger, state *ui.State, window fyne.Window, app fyne.App) {
	if state.SaveAs == nil {
		return
	}
	defer func() { state.SaveAs = nil }()
	logger.Log("Saving output", *state, nil)
	outputURI, err := getOutputURI(app)
	if err != nil {
		logger.Log("Saving output: get output URI", *state, err)
		dialog.ShowError(err, window)
		return
	}
	output, err := storage.Reader(outputURI)
	if output != nil {
		defer output.Close()
	}
	if err != nil {
		logger.Log("Saving output: get output reader", *state, err)
		dialog.ShowError(err, window)
		return
	}
	saveAs, err := uriWriteCloser(state.SaveAs.Uri())
	if saveAs != nil {
		defer saveAs.Close()
	}
	if err != nil {
		logger.Log("Saving output: get save as writer", *state, err)
		dialog.ShowError(err, window)
		return
	}
	errCh := make(chan error)
	go func() {
		_, err := io.Copy(saveAs, output)
		logger.Log("Saving output: copy", *state, err)
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
				logger.Log("Saving output: copy (external)", *state, err)
				dialog.ShowError(err, window)
			}
			err = clearOutputFile(app)
			logger.Log("Saving output: clear output file", *state, err)
			if err != nil {
				dialog.ShowError(err, window)
			}
			return
		default:
			time.Sleep(time.Second / 10)
		}
	}
}

func encrypt(logger *ui.Logger, state *ui.State, win fyne.Window, app fyne.App) {
	updateCh := make(chan encryption.Update)
	errCh := make(chan error)

	go func() {
		logger.Log("encrypt: start", *state, nil)
		headlessURI, err := getHeadlessURI(app)
		if err != nil {
			logger.Log("encrypt: get headless URI", *state, err)
			errCh <- err
			return
		}
		input, err := uriReadCloser(state.Input().Uri())
		if input != nil {
			defer input.Close()
		}
		if err != nil {
			logger.Log("encrypt: get input reader", *state, err)
			errCh <- err
			return
		}

		headlessWriter, err := storage.Writer(headlessURI)
		if headlessWriter != nil {
			defer clearHeadlessFile(app)
			defer headlessWriter.Close()
		}
		if err != nil {
			logger.Log("encrypt: get headless writer", *state, err)
			errCh <- err
			return
		}

		keyfiles := []io.Reader{}
		for i := 0; i < len(state.Keyfiles); i++ {
			r, err := uriReadCloser(state.Keyfiles[i].Uri())
			if r != nil {
				defer r.Close()
			}
			logger.Log("encrypt: get keyfile reader "+strconv.Itoa(i), *state, err)
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
		logger.Log("encrypt: encrypt headless", *state, err)
		if err != nil {
			errCh <- err
			return
		}

		headlessReader, err := storage.Reader(headlessURI)
		logger.Log("encrypt: get headless reader", *state, err)
		if headlessReader != nil {
			defer headlessReader.Close()
		}
		if err != nil {
			errCh <- err
			return
		}

		outputURI, err := getOutputURI(app)
		logger.Log("encrypt: get output URI", *state, err)
		if err != nil {
			errCh <- err
			return
		}
		output, err := storage.Writer(outputURI)
		logger.Log("encrypt: get output writer", *state, err)
		if output != nil {
			defer output.Close()
		}
		if err != nil {
			errCh <- err
			return
		}

		err = encryption.PrependHeader(headlessReader, output, header)
		logger.Log("encrypt: prepend header", *state, err)
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
	logger.Log("encrypt: encryption complete", *state, encryptErr)
	if encryptErr != nil {
		dialog.ShowError(encryptErr, win)
		return
	}
	text := widget.NewLabel(state.Input().Name() + " has been encrypted.")
	text.Wrapping = fyne.TextWrapWord
	dialog.ShowCustomConfirm(
		"Encryption Complete",
		"Save",
		"Cancel",
		text,
		func(b bool) {
			if b {
				chooseSaveAs(logger, state, win)
			}
		},
		win,
	)
}

func tryDecrypt(
	logger *ui.Logger,
	state *ui.State,
	recoveryMode bool,
	w fyne.Window,
	app fyne.App,
) (bool, error) {
	input, err := uriReadCloser(state.Input().Uri())
	logger.Log("tryDecrypt: get input reader", *state, err)
	if err != nil {
		return false, err
	}
	defer input.Close()

	keyfiles := []io.Reader{}
	for i := 0; i < len(state.Keyfiles); i++ {
		r, err := uriReadCloser(state.Keyfiles[i].Uri())
		logger.Log("tryDecrypt: get keyfile reader "+strconv.Itoa(i), *state, err)
		if err != nil {
			return false, err
		}
		defer r.Close()
		keyfiles = append(keyfiles, r)
	}

	outputURI, err := getOutputURI(app)
	logger.Log("tryDecrypt: get output URI", *state, err)
	if err != nil {
		return false, err
	}
	output, err := uriWriteCloser(outputURI.String())
	logger.Log("tryDecrypt: get output writer", *state, err)
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
		logger.Log("tryDecrypt: decrypt start", *state, nil)
		damaged, err := encryption.Decrypt(state.Password, keyfiles, input, output, recoveryMode, updateCh)
		logger.Log("tryDecrypt: decrypt complete", *state, err)
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
			logger.Log("tryDecrypt: complete", *state, err.error)
			return err.bool, err.error
		default:
			time.Sleep(time.Second / 10)
		}
	}
}

func decrypt(logger *ui.Logger, state *ui.State, win fyne.Window, app fyne.App) {
	damaged, err := tryDecrypt(logger, state, false, win, app)
	logger.Log("decrypt: tryDecrypt complete", *state, err)
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
					logger.Log("decrypt: try again in recovery mode", *state, nil)
					recoveryMode = true
					damaged, err = tryDecrypt(logger, state, true, win, app)
					logger.Log("decrypt: try again in recovery mode complete", *state, err)
				} else {
					logger.Log("decrypt: recovery mode canceled", *state, nil)
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

	logger.Log("decrypt: handling result (damaged:"+strconv.FormatBool(damaged)+")", *state, err)
	msg := ""
	save := false
	if err == nil && !damaged {
		msg = state.Input().Name() + " has been decrypted."
		save = true
	} else if err == nil && damaged {
		msg = state.Input().Name() + " has been decrypted successfully, but it is damaged. Consider re-encryting and replacing the damaged file."
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
					chooseSaveAs(logger, state, win)
				} else {
					logger.Log("decrypt: save canceled", *state, nil)
				}
			},
			win,
		)
	} else {
		logger.Log("decrypt: cannot save", *state, err)
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

func makeKeyfileBtn(logger *ui.Logger, state *ui.State, window fyne.Window) *widget.Button {
	btn := widget.NewButtonWithIcon("Keyfile", theme.ContentAddIcon(), func() {
		text := widget.NewMultiLineEntry()
		text.Disable()
		updateText := func() {
			names := []string{}
			for _, k := range state.Keyfiles {
				names = append(names, k.Name())
			}
			text.SetText(strings.Join(names, "\n"))
		}
		updateText()
		addBtn := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
			fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if reader != nil {
					defer reader.Close()
				}
				logger.Log("Adding keyfile", *state, err)
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				if reader != nil {
					state.AddKeyfile(reader.URI())
					logger.Log("Adding keyfile: complete", *state, nil)
					updateText()
				} else {
					logger.Log("Adding keyfile: canceled", *state, nil)
				}
			}, window)
			fd.Show()
		})
		createBtn := widget.NewButtonWithIcon("Create", theme.ContentAddIcon(), func() {
			fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
				if writer != nil {
					defer writer.Close()
				}
				logger.Log("Creating keyfile", *state, err)
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				if writer != nil {
					data := make([]byte, 32)
					_, err := rand.Read(data)
					if err != nil {
						logger.Log("Creating keyfile: random data", *state, err)
						dialog.ShowError(err, window)
						return
					}
					_, err = writer.Write(data)
					if err != nil {
						logger.Log("Creating keyfile: write", *state, err)
						dialog.ShowError(err, window)
						return
					}
					state.AddKeyfile(writer.URI())
					logger.Log("Creating keyfile: complete", *state, nil)
					updateText()
				} else {
					logger.Log("Creating keyfile: canceled", *state, nil)
				}
			}, window)
			fd.SetFileName("Keyfile")
			fd.Show()
		})
		clearBtn := widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), func() {
			state.Keyfiles = state.Keyfiles[:0]
			logger.Log("Clearing keyfiles", *state, nil)
			updateText()
		})
		orderedKeyfiles := widget.NewCheckWithData("Require correct order", binding.BindBool(&(*state).OrderedKeyfiles))
		if state.IsDecrypting() {
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

	state := ui.State{}
	updates := UpdateMethods{}

	logger := ui.Logger{}
	logger.Log("Starting PicoGo", state, nil)

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
				logger.Log("Choosing file to encrypt/decrypt", state, err)
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				logger.Log("Choosing file to encrypt/decrypt", state, errors.New("no file chosen"))
				return
			}
			err = state.SetInput(reader.URI())
			logger.Log("Setting file to encrypt/decrypt", state, err)
			if err != nil {
				dialog.ShowError(err, w)
			}
		}, w)
		fd.Show()
	})

	filename := widget.NewEntry()
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
		input := state.Input()
		if input == nil {
			filename.SetText("")
		} else {
			filename.SetText(input.Name())
		}
		if state.IsEncrypting() {
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
			if state.IsEncrypting() {
				check.Enable()
			} else {
				check.Disable()
			}
		}
	})
	keyfileBtn := makeKeyfileBtn(&logger, &state, w)
	updates.Add(func() {
		keyfileBtn.SetText("Keyfiles [" + strconv.Itoa(len(state.Keyfiles)) + "]")
		if state.IsEncrypting() || state.IsDecrypting() {
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
		if state.IsDecrypting() || state.IsEncrypting() {
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
		if state.IsEncrypting() {
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
		if !(state.IsEncrypting() || state.IsDecrypting()) {
			// This should never happen (the button should be hidden), but check in case
			// there is a race condition
			logger.Log("Encrypt/Decrypt button pressed", state, errors.New("button should be hidden"))
			dialog.ShowError(errors.New("no file chosen"), w)
			return
		}
		if state.IsEncrypting() {
			if state.Password != state.ConfirmPassword {
				logger.Log("Encrypt/Decrypt button pressed", state, errors.New("passwords do not match"))
				dialog.ShowError(errors.New("passwords do not match"), w)
			} else if state.Password == "" {
				logger.Log("Encrypt/Decrypt button pressed", state, errors.New("password cannot be blank"))
				dialog.ShowError(errors.New("password cannot be blank"), w)
			} else {
				logger.Log("Encrypt/Decrypt button pressed (encrypting)", state, nil)
				encrypt(&logger, &state, w, a)
			}
			return
		}
		logger.Log("Encrypt/Decrypt button pressed (decrypting)", state, nil)
		decrypt(&logger, &state, w, a)
	})
	updates.Add(func() {
		if state.IsEncrypting() {
			workBtn.SetText("Encrypt")
			workBtn.Show()
		} else if state.IsDecrypting() {
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
		saveOutput(&logger, &state, w, a)
	})

	go func() {
		for {
			updates.Update()
			time.Sleep(time.Second / 10)
		}
	}()
	w.ShowAndRun()
}
