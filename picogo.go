package main

import (
	"errors"
	"fmt"
	"image/color"
	"io"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
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
		if err != nil {
			logger.Log("Failed while choosing where to save output", *state, err)
			dialog.ShowError(fmt.Errorf("choosing output file: %w", err), window)
			return
		}
		if writer != nil {
			saveAs := ui.NewFileDesc(writer.URI())
			state.SaveAs = &saveAs
			logger.Log("Chose where to save output", *state, nil)
		} else {
			logger.Log("Canceled choosing where to save output", *state, nil)
		}
	}, window)
	if input := state.Input(); input == nil {
		logger.Log("Failed to seed filename", *state, errors.New("input is nil"))
	} else {
		if state.IsEncrypting() {
			d.SetFileName(input.Name() + ".pcv")
		} else {
			d.SetFileName(input.Name()[:len(state.Input().Name())-4])

		}
	}
	fyne.Do(d.Show)
}

func saveOutput(logger *ui.Logger, state *ui.State, window fyne.Window, app fyne.App) {
	if state.SaveAs == nil {
		return
	}
	defer func() { state.SaveAs = nil }()
	outputURI, err := getOutputURI(app)
	if err != nil {
		logger.Log("Get output uri", *state, err)
		dialog.ShowError(fmt.Errorf("finding output file: %w", err), window)
		return
	}
	output, err := storage.Reader(outputURI)
	if output != nil {
		defer output.Close()
	}
	if err != nil {
		logger.Log("Get output reader", *state, err)
		dialog.ShowError(fmt.Errorf("opening output file: %w", err), window)
		return
	}
	saveAs, err := uriWriteCloser(state.SaveAs.Uri())
	if saveAs != nil {
		defer saveAs.Close()
	}
	if err != nil {
		logger.Log("Get save as writer", *state, err)
		dialog.ShowError(fmt.Errorf("opening save-as file: %w", err), window)
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
				logger.Log("Saving output", *state, err)
				dialog.ShowError(fmt.Errorf("copying output: %w", err), window)
			}
			err = clearOutputFile(app)
			if err != nil {
				logger.Log("Clearing output file", *state, err)
				dialog.ShowError(fmt.Errorf("cleaning tmp file: %w", err), window)
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
		logger.Log("Start encryption routine", *state, nil)
		headlessURI, err := getHeadlessURI(app)
		if err != nil {
			logger.Log("Get headless URI", *state, err)
			errCh <- err
			return
		}
		input, err := uriReadCloser(state.Input().Uri())
		if input != nil {
			defer input.Close()
		}
		if err != nil {
			logger.Log("Get input reader", *state, err)
			errCh <- err
			return
		}

		headlessWriter, err := storage.Writer(headlessURI)
		if headlessWriter != nil {
			defer clearHeadlessFile(app)
			defer headlessWriter.Close()
		}
		if err != nil {
			logger.Log("Get headless writer", *state, err)
			errCh <- err
			return
		}

		keyfiles := []io.Reader{}
		for i := 0; i < len(state.Keyfiles); i++ {
			r, err := uriReadCloser(state.Keyfiles[i].Uri())
			if r != nil {
				defer r.Close()
			}
			if err != nil {
				logger.Log("Get keyfile reader "+strconv.Itoa(i), *state, err)
				errCh <- err
				return
			}
			keyfiles = append(keyfiles, r)
		}
		settings := encryption.Settings{
			Comments:    state.Comments.Text,
			ReedSolomon: state.ReedSolomon.Checked,
			Paranoid:    state.Paranoid.Checked,
			OrderedKf:   state.OrderedKeyfiles.Checked,
			Deniability: state.Deniability.Checked,
		}
		header, err := encryption.EncryptHeadless(
			input, state.Password.Text, keyfiles, settings, headlessWriter, updateCh,
		)
		if err != nil {
			logger.Log("Encrypt headless", *state, err)
			errCh <- err
			return
		}

		headlessReader, err := storage.Reader(headlessURI)
		if headlessReader != nil {
			defer headlessReader.Close()
		}
		if err != nil {
			logger.Log("Get headless reader", *state, err)
			errCh <- err
			return
		}

		outputURI, err := getOutputURI(app)
		if err != nil {
			logger.Log("Get output uri", *state, err)
			errCh <- err
			return
		}
		output, err := storage.Writer(outputURI)
		if output != nil {
			defer output.Close()
		}
		if err != nil {
			logger.Log("Get output writer", *state, err)
			errCh <- err
			return
		}

		err = encryption.PrependHeader(headlessReader, output, header)
		if err != nil {
			logger.Log("Prepend header", *state, err)
		}
		errCh <- err
	}()

	// Show progress, blocking until completion
	status := widget.NewLabel("")
	d := dialog.NewCustomWithoutButtons(
		"Encrypting",
		container.New(layout.NewVBoxLayout(), widget.NewProgressBarInfinite(), status),
		win,
	)
	fyne.Do(d.Show)
	var encryptErr error
	for {
		doBreak := false
		select {
		case update := <-updateCh:
			fyne.Do(func() { status.SetText(update.Status) })
		case err := <-errCh:
			fyne.Do(d.Dismiss)
			encryptErr = err
			doBreak = true
		default:
			time.Sleep(time.Second / 10)
		}
		if doBreak {
			break
		}
	}
	logger.Log("Complete encryption", *state, encryptErr)
	if encryptErr != nil {
		dialog.ShowError(fmt.Errorf("encrypting: %w", encryptErr), win)
		return
	}
	text := widget.NewLabel(state.Input().Name() + " has been encrypted.")
	text.Wrapping = fyne.TextWrapWord
	fyne.Do(func() {
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
	})
}

func tryDecrypt(
	logger *ui.Logger,
	state *ui.State,
	recoveryMode bool,
	w fyne.Window,
	app fyne.App,
) (bool, error) {
	input, err := uriReadCloser(state.Input().Uri())
	if err != nil {
		logger.Log("Get input reader", *state, err)
		return false, err
	}
	defer input.Close()

	keyfiles := []io.Reader{}
	for i := 0; i < len(state.Keyfiles); i++ {
		r, err := uriReadCloser(state.Keyfiles[i].Uri())
		if err != nil {
			logger.Log("Get keyfile reader "+strconv.Itoa(i), *state, err)
			return false, err
		}
		defer r.Close()
		keyfiles = append(keyfiles, r)
	}

	outputURI, err := getOutputURI(app)
	if err != nil {
		logger.Log("Get output URI", *state, err)
		return false, err
	}
	output, err := uriWriteCloser(outputURI.String())
	if err != nil {
		logger.Log("Get output writer", *state, err)
		return false, err
	}
	defer output.Close()

	updateCh := make(chan encryption.Update)
	errCh := make(chan struct {
		bool
		error
	})
	go func() {
		logger.Log("Decryption routine start", *state, nil)
		damaged, err := encryption.Decrypt(state.Password.Text, keyfiles, input, output, recoveryMode, updateCh)
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
	fyne.Do(d.Show)
	for {
		select {
		case update := <-updateCh:
			fyne.Do(func() { status.SetText(update.Status) })
		case err := <-errCh:
			fyne.Do(d.Dismiss)
			logger.Log("Decryption routine end", *state, err.error)
			return err.bool, err.error
		default:
			time.Sleep(time.Second / 10)
		}
	}
}

func decrypt(logger *ui.Logger, state *ui.State, win fyne.Window, app fyne.App) {
	damaged, err := tryDecrypt(logger, state, false, win, app)
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
					logger.Log("Retrying decryption in recovery mode", *state, nil)
					recoveryMode = true
					damaged, err = tryDecrypt(logger, state, true, win, app)
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

	logger.Log("Handle decryption result (damaged:"+strconv.FormatBool(damaged)+")", *state, err)
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

func main() {
	a := app.New()
	a.Settings().SetTheme(&myTheme{})
	w := a.NewWindow("PicoGo")
	state := ui.NewState()
	updates := ui.UpdateMethods{}

	logger := ui.Logger{}
	logger.Log("Starting PicoGo", *state, nil)

	infoBtn := ui.MakeInfoBtn(w)
	logBtn := ui.MakeLogBtn(&logger, w)
	info_row := container.New(
		layout.NewHBoxLayout(),
		infoBtn,
		logBtn,
		layout.NewSpacer(),
	)

	picker := ui.MakeFilePicker(state, &logger, w)
	file_row := container.New(
		layout.NewStackLayout(),
		border(),
		container.New(
			layout.NewFormLayout(),
			widget.NewLabel("File"), container.NewPadded(container.NewPadded(state.FileName)),
			widget.NewLabel("Comments"), container.NewPadded(container.NewPadded(state.Comments)),
		),
	)

	// Advanced encryption settings
	advanced_settings_row := container.New(
		layout.NewStackLayout(),
		border(),
		container.New(
			layout.NewVBoxLayout(),
			container.New(
				layout.NewVBoxLayout(),
				widget.NewRichTextFromMarkdown("### Settings"),
				container.New(
					layout.NewHBoxLayout(),
					state.ReedSolomon,
					state.Paranoid,
					state.Deniability,
				),
			),
		),
	)
	keyfiles := container.New(
		layout.NewStackLayout(),
		border(),
		container.NewPadded(
			container.New(
				layout.NewVBoxLayout(),
				widget.NewRichTextFromMarkdown("### Keyfiles"),
				container.NewPadded(
					container.NewBorder(
						nil,
						nil,
						container.New(
							layout.NewVBoxLayout(),
							ui.KeyfileAddBtn(state, &logger, w),
							ui.KeyfileCreateBtn(state, &logger, w),
							ui.KeyfileClearBtn(state, &logger),
						),
						nil,
						container.NewPadded(
							container.New(
								layout.NewVBoxLayout(),
								state.OrderedKeyfiles,
								state.KeyfileText,
							),
						),
					),
				),
			),
		),
	)

	passwordRow := container.New(
		layout.NewStackLayout(),
		border(),
		container.NewPadded(container.NewPadded(
			container.New(
				layout.NewVBoxLayout(),
				state.Password,
				state.ConfirmPassword,
			),
		)),
	)

	workBtn := ui.MakeWorkBtn(
		&logger,
		state,
		w,
		func() { go func() { encrypt(&logger, state, w, a) }() },
		func() { go func() { decrypt(&logger, state, w, a) }() },
		&updates,
	)

	w.SetContent(
		container.New(
			layout.NewVBoxLayout(),
			info_row,
			picker,
			file_row,
			advanced_settings_row,
			keyfiles,
			passwordRow,
			workBtn,
		),
	)

	updates.Add(func() {
		developmentWarning(w)
	})

	updates.Add(func() {
		saveOutput(&logger, state, w, a)
	})

	go func() {
		for {
			fyne.Do(updates.Update)
			time.Sleep(time.Second / 10)
		}
	}()
	w.ShowAndRun()
}
