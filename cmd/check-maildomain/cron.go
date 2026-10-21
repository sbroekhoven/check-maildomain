package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sbroekhoven/check-maildomain/v2/internal/rules"
)

// cronEntry is the single JSON line that -cron prints for a run
type cronEntry struct {
	Time       string `json:"time"` // start of the run, RFC 3339 UTC
	Tool       string `json:"tool"`
	Version    string `json:"version"`
	Domain     string `json:"domain"`
	Status     string `json:"status"` // "ok", "fail" or "error", see statusFor
	Exit       int    `json:"exit"`
	Pass       int    `json:"pass"`
	Warn       int    `json:"warn"`
	Fail       int    `json:"fail"`
	Info       int    `json:"info"`
	Err        int    `json:"err"` // failed lookups plus output files that could not be written
	DurationMS int64  `json:"duration_ms"`
	JSON       string `json:"json,omitempty"`  // path of the stored JSON results
	HTML       string `json:"html,omitempty"`  // path of the stored HTML report
	Error      string `json:"error,omitempty"` // why the status is "error"

	start  time.Time
	errors []string
}

func newCronEntry(start time.Time) *cronEntry {
	return &cronEntry{Time: start.UTC().Format(time.RFC3339), Tool: toolName, Version: version, start: start}
}

// addError records a problem; count is how many failed lookups or files it stands for (0 for
// usage errors)
func (e *cronEntry) addError(msg string, count int) {
	e.errors = append(e.errors, msg)
	e.Err += count
}

// addCounts copies the result counts of a report
func (e *cronEntry) addCounts(report *rules.Report) {
	for _, r := range report.RuleResults {
		switch r.Status {
		case rules.StatusPass:
			e.Pass++
		case rules.StatusWarn:
			e.Warn++
		case rules.StatusFail:
			e.Fail++
		case rules.StatusInfo:
			e.Info++
		}
	}
}

// statusFor maps an exit code to the status in the log line
func statusFor(exit int) string {
	switch exit {
	case exitOK:
		return "ok"
	case exitFail:
		return "fail"
	default:
		return "error"
	}
}

// write finishes the entry for the exit code and prints it as one JSON line
func (e *cronEntry) write(w io.Writer, exit int) {
	e.Exit = exit
	e.Status = statusFor(exit)
	e.Error = strings.Join(e.errors, "; ")
	e.DurationMS = time.Since(e.start).Milliseconds()

	line, err := json.Marshal(e)
	if err != nil {
		// Can't happen for this struct, but never leave the log without a line
		line = []byte(fmt.Sprintf(`{"time":%q,"tool":%q,"status":"error","exit":%d,"error":%q}`, e.Time, e.Tool, exit, err.Error()))
	}
	fmt.Fprintf(w, "%s\n", line)
}
