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

func getHeadlessURI(app fyne.App) (fyne.URI, error) {
	return storage.Child(app.Storage().RootURI(), "headless")
}

func getOutputURI(app fyne.App) (fyne.URI, error) {
	return storage.Child(app.Storage().RootURI(), "output")
}

func chooseSaveAs(logger *ui.Logger, state *ui.State, window fyne.Window, app fyne.App, data ui.CopyTo) {
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
				saveOutput(logger, state, window, app, data)
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

func saveOutput(logger *ui.Logger, state *ui.State, window fyne.Window, app fyne.App, data ui.CopyTo) {
	defer func() { state.SaveAs = nil }()
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
		errCh <- data.CopyTo(io.MultiWriter(saveAs, &counter))
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
			err = ui.ClearTempFile(app)
			if err != nil {
				logger.Log("Clearing temp file", *state, err)
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
	encryptedData := ui.NewEncryptedData(app)

	go func() {
		logger.Log("Start encryption routine", *state, nil)
		defer encryptedData.Close()
		input, err := uriReadCloser(state.Input().Uri())
		if input != nil {
			defer input.Close()
		}
		if err != nil {
			logger.Log("Get input reader", *state, err)
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
			input, state.Password.Text, keyfiles, settings, io.MultiWriter(encryptedData, &counter),
		)
		if err != nil {
			logger.Log("Encrypt headless", *state, err)
			errCh <- err
			return
		}
		encryptedData.Header = header
		errCh <- nil
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
					chooseSaveAs(logger, state, win, app, encryptedData)
				}
			},
			win,
		)
	})
}

func tryDecrypt(
	logger *ui.Logger,
	state *ui.State,
	w fyne.Window,
	app fyne.App,
	decryptedData *ui.DecryptedData,
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
			io.MultiWriter(decryptedData, &counter),
			true,
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
	decryptedData := ui.NewDecryptedData(state.Settings.PreviewMode.Checked, app)
	damaged, err := tryDecrypt(logger, state, win, app, decryptedData)
	decryptedData.Close()

	retryCanceled := false
	if errors.Is(err, ui.ErrPreviewMemoryExceeded) {
		// Offer to try again without preview mode
		text := widget.NewLabel("The file is too large to preview. Would you like to try again without preview mode?\n\nNote: you can turn off preview mode by default in the settings.")
		text.Wrapping = fyne.TextWrapWord
		doneCh := make(chan struct{})
		go func() {
			d := dialog.NewCustomConfirm(
				"Preview Memory Exceeded",
				"Retry",
				"Cancel",
				text,
				func(b bool) {
					go func() {
						if b {
							decryptedData = ui.NewDecryptedData(false, app)
							logger.Log("Retrying without preview mode", *state, nil)
							damaged, err = tryDecrypt(logger, state, win, app, decryptedData)
						} else {
							retryCanceled = true
						}
						doneCh <- struct{}{}
					}()
				},
				win,
			)
			fyne.Do(d.Show)
		}()
		<-doneCh
	}
	if retryCanceled {
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
			msg = "The file is too damaged to recover. Would you like to save the partially recovered file?"
			save = true
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
		d := dialog.NewCustomConfirm(
			"Decryption Complete",
			"Save",
			"Cancel",
			text,
			func(b bool) {
				if b {
					chooseSaveAs(logger, state, win, app, decryptedData)
				}
			},
			win,
		)
		fyne.Do(d.Show)
	} else {
		fyne.Do(func() { dialog.ShowError(errors.New(msg), win) })
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

	state.WorkBtn.OnTapped = ui.WorkBtnCallback(
		state,
		&logger,
		w,
		func() { go func() { encrypt(&logger, state, w, a) }() },
		func() { go func() { decrypt(&logger, state, w, a) }() },
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
			state.WorkBtn,
		),
	)

	fyne.Do(func() { developmentWarning(w) })
	w.ShowAndRun()
}
