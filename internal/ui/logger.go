package ui

import (
	"strconv"
	"strings"
	"sync"
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
		"\"SaveAs\":" + redactedFile(state.SaveAs),
		"\"Comments\":\"" + redactedString(state.Comments) + "\"",
		"\"ReedSolomon\":" + strconv.FormatBool(state.ReedSolomon.Checked),
		"\"Deniability\":" + strconv.FormatBool(state.Deniability.Checked),
		"\"Paranoid\":" + strconv.FormatBool(state.Paranoid.Checked),
		"\"Keyfiles\":" + keyfilesJson,
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
	mutex sync.Mutex
}

func (l *Logger) Log(action string, state State, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	line := logLine{
		time:   time.Now().Format("15:04:05.000"),
		action: action,
		state:  stateJson(state),
		err:    errMsg,
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
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
