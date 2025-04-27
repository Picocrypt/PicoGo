package ui

import (
	"log"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/storage"
)

func testApp() fyne.App {
	return app.New()
}

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
	testApp := app.New()
	window := testApp.NewWindow("Test Window")
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
	testApp := app.New()
	window := testApp.NewWindow("Test Window")
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
	_ = testApp()
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
	_ = testApp()
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
	state.Comments = "test-comments"
	updates.Update()
	if comments.Text != "test-comments" {
		t.Errorf("Comments should be maintained")
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
	_ = testApp()
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
