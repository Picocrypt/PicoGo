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
	"fyne.io/fyne/v2/widget"

	"github.com/picocrypt/picogo/internal/encryption"
	"github.com/picocrypt/picogo/internal/ui"
)

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

func chooseSaveAs(logger *ui.Logger, state *ui.State, window fyne.Window, app fyne.App) {
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
			go func() {
				saveOutput(logger, state, window, app)
			}()
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
	counter := ui.ByteCounter{}
	go func() {
		_, err := io.Copy(io.MultiWriter(&counter, saveAs), output)
		errCh <- err
	}()

	progress := widget.NewLabel("")
	d := dialog.NewCustomWithoutButtons(
		"Saving",
		container.New(layout.NewVBoxLayout(), progress),
		window,
	)
	fyne.Do(d.Show)

	// Block until completion
	for {
		select {
		case err := <-errCh:
			fyne.Do(d.Dismiss)
			if err != nil {
				logger.Log("Saving output", *state, err)
				dialog.ShowError(fmt.Errorf("copying output: %w", err), window)
			}
			err = clearOutputFile(app)
			if err != nil {
				logger.Log("Clearing output file", *state, err)
				dialog.ShowError(fmt.Errorf("cleaning tmp file: %w", err), window)
			}
			state.Clear()
			return
		default:
			time.Sleep(time.Second / 4)
			fyne.Do(func() {
				progress.SetText("Total: " + counter.Total() + "\nRate:   " + counter.Rate())
			})
		}
	}
}

func encrypt(logger *ui.Logger, state *ui.State, win fyne.Window, app fyne.App) {
	errCh := make(chan error)
	counter := ui.ByteCounter{}

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
			input, state.Password.Text, keyfiles, settings, io.MultiWriter(headlessWriter, &counter),
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

	progress := widget.NewLabel("")
	d := dialog.NewCustomWithoutButtons("Encrypting", container.New(layout.NewVBoxLayout(), progress), win)
	fyne.Do(d.Show)
	var encryptErr error
	for {
		doBreak := false
		select {
		case err := <-errCh:
			fyne.Do(d.Dismiss)
			encryptErr = err
			doBreak = true
		default:
			time.Sleep(time.Second / 4)
			fyne.Do(func() { progress.SetText("Total: " + counter.Total() + "\nRate: " + counter.Rate()) })
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
					chooseSaveAs(logger, state, win, app)
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

	errCh := make(chan struct {
		bool
		error
	})
	counter := ui.ByteCounter{}
	go func() {
		logger.Log("Decryption routine start", *state, nil)
		damaged, err := encryption.Decrypt(
			state.Password.Text,
			keyfiles,
			input,
			io.MultiWriter(output, &counter),
			recoveryMode,
		)
		errCh <- struct {
			bool
			error
		}{damaged, err}
	}()

	// Block until completion
	progress := widget.NewLabel("")
	d := dialog.NewCustomWithoutButtons("Decrypting", container.New(layout.NewVBoxLayout(), progress), w)
	fyne.Do(d.Show)
	for {
		select {
		case err := <-errCh:
			fyne.Do(d.Dismiss)
			logger.Log("Decryption routine end", *state, err.error)
			return err.bool, err.error
		default:
			time.Sleep(time.Second / 4)
			fyne.Do(func() {
				progress.SetText("Total: " + counter.Total() + "\nRate: " + counter.Rate())
			})
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
					chooseSaveAs(logger, state, win, app)
				}
			},
			win,
		)
	} else {
		dialog.ShowError(errors.New(msg), win)
	}
}

func wrapWithBorder(c fyne.CanvasObject) *fyne.Container {
	border := canvas.NewRectangle(color.White)
	border.FillColor = color.Transparent
	border.StrokeColor = color.White
	border.StrokeWidth = 1
	return container.New(
		layout.NewStackLayout(),
		border,
		container.NewPadded(c),
	)
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
	theme := ui.NewTheme(1.0)
	a.Settings().SetTheme(theme)
	w := a.NewWindow("PicoGo")
	state := ui.NewState(a)

	logger := ui.Logger{}
	logger.Log("Starting PicoGo", *state, nil)

	infoBtn := ui.MakeInfoBtn(w)
	logBtn := ui.MakeLogBtn(&logger, w)
	info_row := container.New(
		layout.NewHBoxLayout(),
		infoBtn,
		logBtn,
		ui.MakeSettingsBtn(state.Settings, w),
		layout.NewSpacer(),
	)

	picker := ui.MakeFilePicker(state, &logger, w)
	fileRow := wrapWithBorder(
		container.New(
			layout.NewFormLayout(),
			widget.NewLabel("File"), container.NewPadded(container.NewPadded(state.FileName)),
			widget.NewLabel("Comments"), container.NewPadded(container.NewPadded(state.Comments)),
		),
	)

	// Advanced encryption settings
	advSettingsRow := wrapWithBorder(
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
	keyfiles := wrapWithBorder(
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
	)

	passwordRow := wrapWithBorder(
		container.NewPadded(container.NewPadded(
			container.New(
				layout.NewVBoxLayout(),
				state.Password,
				state.ConfirmPassword,
			),
		)),
	)

	state.WorkBtn.OnTapped = ui.WorkBtnCallback(
		state,
		&logger,
		w,
		func() { go func() { encrypt(&logger, state, w, a) }() },
		func() { go func() { decrypt(&logger, state, w, a) }() },
	)

	body := container.New(
		layout.NewVBoxLayout(),
		info_row,
		picker,
		fileRow,
		advSettingsRow,
		keyfiles,
		passwordRow,
		state.WorkBtn,
	)
	minSize := body.MinSize()
	w.SetContent(container.NewScroll(container.New(layout.NewVBoxLayout(), body)))

	go func() {
		for {
			// On android, users can change device settings that will scale the size
			// of the widgets. This can lead to parts of the app going off screen.
			// To work around this, continuously check the size of the window and scale
			// the theme to fit.
			// - continuous checking is required for desktop because the user may change
			//   the window size. On android, the app is always full screen, so this should
			//   only have effect the first loop.
			// - only update the theme if the scale is more than 1% different from the current
			//   scale. This is to prevent constant updates to the theme.
			time.Sleep(time.Second / 10.0)
			currentSize := w.Canvas().Content().Size()
			targetScale := min(currentSize.Width/minSize.Width, currentSize.Height/minSize.Height)
			currentScale := theme.Scale
			if targetScale > currentScale*1.01 || targetScale < currentScale*0.99 {
				theme.Scale = targetScale
				fyne.Do(func() { a.Settings().SetTheme(theme) })
			}
		}
	}()
	fyne.Do(func() { developmentWarning(w) })
	w.ShowAndRun()
}
