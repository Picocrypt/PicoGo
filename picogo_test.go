package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/picocrypt/picogo/internal/ui"
)

func TestVersion(t *testing.T) {
	r, err := os.Open("VERSION")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	version, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(version, []byte(ui.PicoGoVersion)) {
		t.Fatal(version, "does not match", ui.PicoGoVersion)
	}
}
	
