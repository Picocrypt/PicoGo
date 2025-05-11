package ui

import (
	"log"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
)

func MakeURI(name string) fyne.URI {
	uri, err := storage.ParseURI("file://" + name)
	if err != nil {
		log.Println("Error creating URI:", err)
		panic(err)
	}
	return uri
}

type TestReadWriteCloser struct {
	bytesWritten int
	bytesRead    int
	isClosed     bool
}

func (t *TestReadWriteCloser) Read(p []byte) (n int, err error) {
	t.bytesRead += len(p)
	return len(p), nil
}

func (t *TestReadWriteCloser) Write(p []byte) (n int, err error) {
	t.bytesWritten += len(p)
	return len(p), nil
}

func (t *TestReadWriteCloser) Close() error {
	t.isClosed = true
	return nil
}

func (t *TestReadWriteCloser) URI() fyne.URI {
	return MakeURI("test")
}

func TestWriteLogsCallback(t *testing.T) {
	logger := Logger{}
	app := test.NewApp()
	window := app.NewWindow("Test Window")
	callback := writeLogsCallback(&logger, window)

	test := TestReadWriteCloser{}
	callback(&test, nil)
	if !test.isClosed {
		t.Errorf("Expected TestReadWriteCloser to be closed, but it was not.")
	}
	if test.bytesWritten == 0 {
		t.Errorf("Expected some bytes to be written, but none were.")
	}
}

func TestFilePickerCallback(t *testing.T) {
	logger := Logger{}
	app := test.NewApp()
	window := app.NewWindow("Test Window")
	state := NewState()
	callback := filePickerCallback(state, &logger, window)
	test := TestReadWriteCloser{}

	// Test canceling the file picker
	if state.Input() != nil {
		t.Errorf("State should not be initialized with an input")
	}
	callback(nil, nil)
	if state.Input() != nil {
		t.Errorf("State should not be updated with an input")
	}

	if state.Input() != nil {
		t.Errorf("State should not be initialized with an input")
	}
	callback(&test, nil)
	if !test.isClosed {
		t.Errorf("Resource must be closed")
	}
	if test.bytesRead != 0 {
		t.Errorf("Chosen file should not be read yet")
	}
	if state.Input() == nil {
		t.Errorf("State should be updated with an input")
	}
}

func TestFilename(t *testing.T) {
	state := NewState()
	if state.FileName.Text != "" {
		t.Errorf("Filename should be empty")
	}

	state.SetInput(MakeURI("test-filename"))
	if state.FileName.Text != "test-filename" {
		t.Errorf("Filname should match input")
	}

	state.SetInput(MakeURI("test-filename-2"))
	if state.FileName.Text != "test-filename-2" {
		t.Errorf("Filname should match input")
	}
}

func TestComments(t *testing.T) {
	state := NewState()

	state.SetInput(MakeURI("test"))
	if !state.IsEncrypting() {
		t.Errorf("State should be encrypting")
	}
	if state.Comments.Text != "" {
		t.Errorf("Comments should be empty")
	}
	if state.Comments.Disabled() {
		t.Errorf("Comments should be enabled")
	}
	if state.Comments.PlaceHolder != "Comments are not encrypted" {
		t.Errorf("Comments should warn user that they are not encrypted")
	}

	// Choosing deniability should disable comments
	state.Deniability.SetChecked(true)
	if state.Comments.Text != "" {
		t.Errorf("Comments should be empty")
	}
	if !state.Comments.Disabled() {
		t.Errorf("Comments should be disabled")
	}
	if state.Comments.PlaceHolder != "Comments are disabled in deniability mode" {
		t.Errorf("Comments should warn user that they are disabled")
	}
	if state.Comments.Text != "" {
		t.Errorf("State should be updated with comments")
	}

	// Switching to decrypting mode should disable comments
	state.SetInput(MakeURI("test.pcv"))
	if !state.IsDecrypting() {
		t.Errorf("State should be decrypting")
	}
	if state.Comments.Text != "" {
		t.Errorf("Comments should be empty")
	}
	if !state.Comments.Disabled() {
		t.Errorf("Comments should be disabled")
	}
}

func TestKeyfileAddCallback(t *testing.T) {
	state := NewState()
	app := test.NewApp()
	window := app.NewWindow("Test Window")
	logger := Logger{}
	callback := keyfileAddCallback(state, &logger, window)

	callback(nil, nil)
	reader := TestReadWriteCloser{}
	callback(&reader, nil)
	if !reader.isClosed {
		t.Errorf("Expected TestReadWriteCloser to be closed, but it was not.")
	}
	if reader.bytesRead != 0 {
		t.Errorf("Keyfile should not be read yet")
	}
	if len(state.Keyfiles) != 1 {
		t.Errorf("Expected one keyfile to be added, but got %d", len(state.Keyfiles))
	}
}

func TestKeyfileCreateCallback(t *testing.T) {
	state := NewState()
	app := test.NewApp()
	window := app.NewWindow("Test Window")
	logger := Logger{}
	callback := keyfileCreateCallback(state, &logger, window)

	callback(nil, nil)
	reader := TestReadWriteCloser{}
	callback(&reader, nil)
	if !reader.isClosed {
		t.Errorf("Expected TestReadWriteCloser to be closed, but it was not.")
	}
	if reader.bytesWritten != 32 {
		t.Errorf("Should have written 32 bytes, but wrote %d", reader.bytesWritten)
	}
	if len(state.Keyfiles) != 1 {
		t.Errorf("Expected one keyfile to be added, but got %d", len(state.Keyfiles))
	}
}

func TestKeyfileClearCallback(t *testing.T) {
	state := NewState()
	logger := Logger{}
	callback := keyfileClearCallback(state, &logger)

	state.AddKeyfile(MakeURI("test-keyfile"))
	if len(state.Keyfiles) != 1 {
		t.Errorf("Expected one keyfile, but got %d", len(state.Keyfiles))
	}
	callback()
	if len(state.Keyfiles) != 0 {
		t.Errorf("Expected no keyfiles, but got %d", len(state.Keyfiles))
	}
}

func TestKeyfileTextUpdate(t *testing.T) {
	state := NewState()
	if state.KeyfileText.Text != "" {
		t.Errorf("Text should be empty")
	}

	state.AddKeyfile(MakeURI("test-keyfile-1"))
	state.AddKeyfile(MakeURI("test-keyfile-2"))
	if state.KeyfileText.Text != "test-keyfile-1\ntest-keyfile-2" {
		t.Errorf("Text should be updated to show keyfiles")
	}
}

func TestPasswordEntry(t *testing.T) {
	state := NewState()
	if state.Password.Text != "" {
		t.Errorf("Password should be empty")
	}

	// Test enabling / disabling
	state.SetInput(MakeURI("test.pcv"))
	if state.Password.Disabled() {
		t.Errorf("Password should be enabled")
	}
	state.SetInput(MakeURI("test"))
	if state.Password.Disabled() {
		t.Errorf("Password should be enabled")
	}
}

func TestConfirmEntry(t *testing.T) {
	state := NewState()
	if state.ConfirmPassword.Text != "" {
		t.Errorf("Confirm should be empty")
	}

	// Test enabling / disabling
	state.SetInput(MakeURI("test.pcv"))
	if !state.IsDecrypting() {
		t.Errorf("State should be decrypting")
	}
	if !state.ConfirmPassword.Disabled() {
		t.Errorf("Confirm should not be enabled for decrypting")
	}
	state.SetInput(MakeURI("test"))
	if !state.IsEncrypting() {
		t.Errorf("State should be encrypting")
	}
	if !state.ConfirmPassword.Visible() {
		t.Errorf("Confirm should be visible for encrypting")
	}
}

func TestWorkBtn(t *testing.T) {
	state := NewState()
	logger := Logger{}
	app := test.NewApp()
	window := app.NewWindow("Test Window")
	encryptCalled := false
	encrypt := func() {
		encryptCalled = true
	}
	decryptCalled := false
	decrypt := func() {
		decryptCalled = true
	}
	state.WorkBtn.OnTapped = WorkBtnCallback(state, &logger, window, encrypt, decrypt)

	// Set state to encrypting
	state.SetInput(MakeURI("test"))
	if state.WorkBtn.Disabled() {
		t.Errorf("Work button should be enabled")
	}
	if state.WorkBtn.Text != "Encrypt" {
		t.Errorf("Work button should say 'Encrypt'")
	}

	// Test mismatched passwords
	state.Password.Text = "test-password"
	state.ConfirmPassword.Text = "test-confirm"
	test.Tap(state.WorkBtn)
	if encryptCalled || decryptCalled {
		t.Errorf("Encrypt or decrypt should not be called")
	}

	// Match passwords
	state.ConfirmPassword.Text = "test-password"
	test.Tap(state.WorkBtn)
	if !encryptCalled || decryptCalled {
		t.Errorf("Only encrypt should be called")
	}

	// Set state to decrypting
	state.SetInput(MakeURI("test.pcv"))
	if state.WorkBtn.Disabled() {
		t.Errorf("Work button should be visible")
	}
	if state.WorkBtn.Text != "Decrypt" {
		t.Errorf("Work button should say 'Decrypt'")
	}

	// Test decrypting
	encryptCalled = false
	decryptCalled = false
	test.Tap(state.WorkBtn)
	if encryptCalled || !decryptCalled {
		t.Errorf("Only decrypt should be called")
	}
}
