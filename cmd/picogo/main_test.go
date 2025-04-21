package main

import (
	"os"
	"testing"
)

func argsMatch(a, b args) bool {
	if a.reedSolomon != b.reedSolomon {
		return false
	}
	if a.paranoid != b.paranoid {
		return false
	}
	if a.deniability != b.deniability {
		return false
	}
	if len(a.keyfiles) != len(b.keyfiles) {
		return false
	}
	for i := range a.keyfiles {
		if a.keyfiles[i] != b.keyfiles[i] {
			return false
		}
	}
	if a.keep != b.keep {
		return false
	}
	if a.ordered != b.ordered {
		return false
	}
	if a.password != b.password {
		return false
	}
	if a.comments != b.comments {
		return false
	}
	if a.overwrite != b.overwrite {
		return false
	}
	if a.encryptOnly != b.encryptOnly {
		return false
	}
	if a.decryptOnly != b.decryptOnly {
		return false
	}
	if len(a.inFiles) != len(b.inFiles) {
		return false
	}
	for i := range a.inFiles {
		if a.inFiles[i] != b.inFiles[i] {
			return false
		}
	}
	return true
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want args
	}{
		{
			name: "basic case",
			args: []string{"-passfrom", "pass:password", "file1.txt"},
			want: args{inFiles: []string{"file1.txt"}, password: "password"},
		},
		{
			name: "all args",
			args: []string{"-rs", "-paranoid", "-deniability", "-keyfiles", "keyfile1,keyfile2", "-keep", "-ordered", "-passfrom", "pass:password", "-comments", "test comments", "-overwrite", "-encrypt-only", "-decrypt-only", "file1.txt"},
			want: args{
				reedSolomon: true,
				paranoid:    true,
				deniability: true,
				keyfiles:    []string{"keyfile1", "keyfile2"},
				keep:        true,
				ordered:     true,
				password:    "password",
				comments:    "test comments",
				overwrite:   true,
				encryptOnly: true,
				decryptOnly: true,
				inFiles:     []string{"file1.txt"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = append([]string{"picogo"}, tt.args...)
			got, err := parseArgs()
			if err != nil {
				t.Errorf("parseArgs() error = %v", err)
				return
			}
			if !argsMatch(got, tt.want) {
				t.Errorf("parseArgs() = %v, want %v", got, tt.want)
			}
		})
	}

}
