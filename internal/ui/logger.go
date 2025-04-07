package ui

import (
	"strconv"
	"strings"
	"time"
)

func redactedFile(f *fileDesc) string {
	if f == nil {
		return "null"
	}
	redactedUri := "parsing-error-" + strconv.Itoa(f.id)
	splitIdx := strings.Index(f.uri, ":")
	if splitIdx != -1 {
		redactedUri = f.uri[:splitIdx+1] + "redacted-" + strconv.Itoa(f.id)
	}
	return "{\"Uri\":\"" + redactedUri + "\"}"
}

func redactedString(s string) string {
	if len(s) > 0 {
		return "non-empty-string"
	}
	return ""
}

func stateJson(state State) string {
	keyfiles := []string{}
	for _, k := range state.Keyfiles {
		keyfiles = append(keyfiles, redactedFile(&k))
	}
	keyfilesJson := "[" + strings.Join(keyfiles, ",") + "]"
	fields := []string{
		"\"Input\":" + redactedFile(state.Input()),
		"\"SaveAs\":" + redactedFile(state.Input()),
		"\"Comments\":" + redactedString(state.Comments),
		"\"ReedSolomon\":" + strconv.FormatBool(state.ReedSolomon),
		"\"Deniability\":" + strconv.FormatBool(state.Deniability),
		"\"Paranoid\":" + strconv.FormatBool(state.Paranoid),
		"\"OrderedKeyfiles\":\"redacted\"",
		"\"Keyfiles\":" + keyfilesJson,
		"\"Password\":" + redactedString(state.Password),
		"\"ConfirmPassword\":" + redactedString(state.ConfirmPassword),
	}
	return "{" + strings.Join(fields, ",") + "}"
}

type logLine struct {
	time   string
	action string
	state  string
	err    string
}

type Logger struct {
	lines []logLine
}

func (l *Logger) Log(action string, state State, err error) {
	line := logLine{
		time:   time.Now().Format("15:04:05.1234"),
		action: action,
		state:  stateJson(state),
		err:    err.Error(),
	}
	l.lines = append(l.lines, line)
}

func (l *Logger) CsvString() string {
	logLines := []string{"Time,Action,State,Error," + PicoGoVersion}
	for _, line := range l.lines {
		fields := []string{
			"\"" + line.time + "\"",
			"\"" + line.action + "\"",
			"\"" + line.state + "\"",
			"\"" + line.err + "\"",
		}
		logLines = append(logLines, strings.Join(fields, ","))
	}
	return strings.Join(logLines, "\n")
}
