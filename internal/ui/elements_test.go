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
	state := State{}
	callback := filePickerCallback(&state, &logger, window)
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
	state := State{}
	updates := UpdateMethods{}
	filename := MakeFileName(&state, &updates)

	updates.Update()
	if !filename.Disabled() {
		t.Errorf("Filename should always be disabled")
	}
	if filename.Text != "" {
		t.Errorf("Filename should be empty")
	}

	state.SetInput(MakeURI("test-filename"))
	updates.Update()
	if filename.Text != "test-filename" {
		t.Errorf("Filname should match input")
	}

	state.SetInput(MakeURI("test-filename-2"))
	updates.Update()
	if filename.Text != "test-filename-2" {
		t.Errorf("Filname should match input")
	}
}

func TestComments(t *testing.T) {
	state := State{}
	updates := UpdateMethods{}
	comments := MakeComments(&state, &updates)

	state.SetInput(MakeURI("test"))
	if !state.IsEncrypting() {
		t.Errorf("State should be encrypting")
	}
	updates.Update()
	if comments.Text != "" {
		t.Errorf("Comments should be empty")
	}
	if comments.Disabled() {
		t.Errorf("Comments should be enabled")
	}
	if comments.PlaceHolder != "Comments are not encrypted" {
		t.Errorf("Comments should warn user that they are not encrypted")
	}

	// Simulate adding comments
	test.Type(comments, "test-comments")
	updates.Update()
	if comments.Text != "test-comments" {
		t.Errorf("Comments should be maintained")
	}
	if state.Comments != "test-comments" {
		t.Errorf("State should be updated with comments")
	}

	// Choosing deniability should disable comments
	state.Deniability = true
	updates.Update()
	if comments.Text != "" {
		t.Errorf("Comments should be empty")
	}
	if !comments.Disabled() {
		t.Errorf("Comments should be disabled")
	}
	if comments.PlaceHolder != "Comments are disabled in deniability mode" {
		t.Errorf("Comments should warn user that they are disabled")
	}
	if state.Comments != "" {
		t.Errorf("State should be updated with comments")
	}

	// Switching to decrypting mode should disable comments
	state.SetInput(MakeURI("test.pcv"))
	updates.Update()
	if !state.IsDecrypting() {
		t.Errorf("State should be decrypting")
	}
	if comments.Text != "" {
		t.Errorf("Comments should be empty")
	}
	if !comments.Disabled() {
		t.Errorf("Comments should be disabled")
	}
	if comments.PlaceHolder != "" {
		t.Errorf("Comments should not have a placeholder")
	}
}

func TestMakeSettingCheck(t *testing.T) {
	state := State{}
	updates := UpdateMethods{}
	check := MakeSettingCheck("test-check", &state.ReedSolomon, &state, &updates)

	updates.Update()
	if check.Text != "test-check" {
		t.Errorf("Text should match argument")
	}

	// Changing the check should update the state
	if state.ReedSolomon {
		t.Errorf("State should not be initialized with ReedSolomon")
	}
	check.SetChecked(true)
	updates.Update()
	if !state.ReedSolomon {
		t.Errorf("State should be updated with ReedSolomon")
	}
	check.SetChecked(false)
	updates.Update()
	if state.ReedSolomon {
		t.Errorf("State should be updated with ReedSolomon")
	}

	// Check correct disabling of the check
	state.SetInput(MakeURI("test"))
	updates.Update()
	if check.Disabled() {
		t.Errorf("Check should be enabled")
	}
	state.SetInput(MakeURI("test.pcv"))
	updates.Update()
	if !check.Disabled() {
		t.Errorf("Check should be disabled")
	}
}

func TestKeyfileAddCallback(t *testing.T) {
	state := State{}
	app := test.NewApp()
	window := app.NewWindow("Test Window")
	logger := Logger{}
	updateCalled := false
	textUpdate := func() {
		updateCalled = true
	}
	callback := keyfileAddCallback(&state, &logger, window, textUpdate)

	callback(nil, nil)
	if !updateCalled {
		t.Errorf("Update function should be called")
	}

	updateCalled = false
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
	state := State{}
	app := test.NewApp()
	window := app.NewWindow("Test Window")
	logger := Logger{}
	updateCalled := false
	textUpdate := func() {
		updateCalled = true
	}
	callback := keyfileCreateCallback(&state, &logger, window, textUpdate)

	callback(nil, nil)
	if !updateCalled {
		t.Errorf("Update function should be called")
	}

	updateCalled = false
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
	state := State{}
	logger := Logger{}
	updateCalled := false
	textUpdate := func() {
		updateCalled = true
	}
	callback := keyfileClearCallback(&state, &logger, textUpdate)

	state.AddKeyfile(MakeURI("test-keyfile"))
	if len(state.Keyfiles) != 1 {
		t.Errorf("Expected one keyfile, but got %d", len(state.Keyfiles))
	}
	callback()
	if !updateCalled {
		t.Errorf("Update function should be called")
	}
	if len(state.Keyfiles) != 0 {
		t.Errorf("Expected no keyfiles, but got %d", len(state.Keyfiles))
	}
}

func TestKeyfileTextUpdate(t *testing.T) {
	state := State{}
	text := keyfileText()
	update := keyfileTextUpdate(&state, text)

	update()
	if text.Text != "" {
		t.Errorf("Text should be empty")
	}

	state.AddKeyfile(MakeURI("test-keyfile-1"))
	state.AddKeyfile(MakeURI("test-keyfile-2"))
	update()
	if text.Text != "test-keyfile-1\ntest-keyfile-2" {
		t.Errorf("Text should be updated to show keyfiles")
	}
}

func TestPasswordEntry(t *testing.T) {
	state := State{}
	updates := UpdateMethods{}
	password := MakePassword(&state, &updates)

	updates.Update()
	if password.Text != "" {
		t.Errorf("Password should be empty")
	}

	// Test enabling / disabling
	if state.IsEncrypting() || state.IsDecrypting() {
		t.Errorf("State should not be encrypting or decrypting yet")
	}
	if !password.Disabled() {
		t.Errorf("Password should be enabled")
	}
	state.SetInput(MakeURI("test.pcv"))
	updates.Update()
	if password.Disabled() {
		t.Errorf("Password should be enabled")
	}

	// Type a password
	test.Type(password, "test-password")
	updates.Update()
	if password.Text != "test-password" {
		t.Errorf("Password should be maintained")
	}
	if state.Password != "test-password" {
		t.Errorf("State should be updated with password")
	}
}

func TestConfirmEntry(t *testing.T) {
	state := State{}
	updates := UpdateMethods{}
	confirm := MakeConfirmPassword(&state, &updates)

	updates.Update()
	if confirm.Text != "" {
		t.Errorf("Confirm should be empty")
	}

	// Test enabling / disabling
	if state.IsEncrypting() || state.IsDecrypting() {
		t.Errorf("State should not be encrypting or decrypting yet")
	}
	if confirm.Visible() {
		t.Errorf("Confirm should not be visible yet")
	}
	state.SetInput(MakeURI("test.pcv"))
	updates.Update()
	if !state.IsDecrypting() {
		t.Errorf("State should be decrypting")
	}
	if confirm.Visible() {
		t.Errorf("Confirm should not be visible for decrypting")
	}
	state.SetInput(MakeURI("test"))
	updates.Update()
	if !state.IsEncrypting() {
		t.Errorf("State should be encrypting")
	}
	if !confirm.Visible() {
		t.Errorf("Confirm should be visible for encrypting")
	}

	// Type a password
	test.Type(confirm, "test-confirm")
	updates.Update()
	if confirm.Text != "test-confirm" {
		t.Errorf("Confirm should be maintained")
	}
	if state.ConfirmPassword != "test-confirm" {
		t.Errorf("State should be updated with confirm password")
	}
}

func TestWorkBtn(t *testing.T) {
	state := State{}
	updates := UpdateMethods{}
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
	workBtn := MakeWorkBtn(&logger, &state, window, encrypt, decrypt, &updates)

	// Work button should start hidden
	updates.Update()
	if workBtn.Visible() {
		t.Errorf("Work button should not be visible")
	}
	// Tapping should do nothing
	test.Tap(workBtn)
	if encryptCalled || decryptCalled {
		t.Errorf("Encrypt or decrypt should not be called")
	}

	// Set state to encrypting
	state.SetInput(MakeURI("test"))
	updates.Update()
	if !workBtn.Visible() {
		t.Errorf("Work button should be visible")
	}
	if workBtn.Text != "Encrypt" {
		t.Errorf("Work button should say 'Encrypt'")
	}

	// Test mismatched passwords
	state.Password = "test-password"
	state.ConfirmPassword = "test-confirm"
	test.Tap(workBtn)
	if encryptCalled || decryptCalled {
		t.Errorf("Encrypt or decrypt should not be called")
	}

	// Match passwords
	state.ConfirmPassword = "test-password"
	test.Tap(workBtn)
	if !encryptCalled || decryptCalled {
		t.Errorf("Only encrypt should be called")
	}

	// Set state to decrypting
	state.SetInput(MakeURI("test.pcv"))
	updates.Update()
	if !workBtn.Visible() {
		t.Errorf("Work button should be visible")
	}
	if workBtn.Text != "Decrypt" {
		t.Errorf("Work button should say 'Decrypt'")
	}

	// Test decrypting
	encryptCalled = false
	decryptCalled = false
	test.Tap(workBtn)
	if encryptCalled || !decryptCalled {
		t.Errorf("Only decrypt should be called")
	}
}
