package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// offline makes runs fail fast: nothing listens on 127.0.0.1:1. MTA-STS policies are only fetched
// when the (failing) DNS lookup finds a record, so no other connections are made.
var offline = []string{"-nameserver", "127.0.0.1:1", "-timeout", "200ms"}

// runCron runs the tool and returns the exit code, stdout and stderr
func runCron(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := run(args, &stdout, &stderr)
	return exit, stdout.String(), stderr.String()
}

// logLine parses stdout as exactly one JSON line
func logLine(t *testing.T, stdout string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("want exactly one log line, got %d:\n%s", len(lines), stdout)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, lines[0])
	}
	return entry
}

func TestCronNeedsOutput(t *testing.T) {
	exit, stdout, stderr := runCron(t, "-cron", "example.com")
	entry := logLine(t, stdout)
	if exit != exitError || entry["status"] != "error" || entry["exit"] != float64(exitError) {
		t.Errorf("exit %d, entry %v", exit, entry)
	}
	if !strings.Contains(entry["error"].(string), "-json or -html") || entry["domain"] != "example.com" {
		t.Errorf("entry %v", entry)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty, got %q", stderr)
	}
}

func TestCronUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"invalid domain": {"-cron", "-json", dir + "/", "not a domain"},
		"no domain":      {"-cron", "-json", dir + "/"},
	} {
		exit, stdout, stderr := runCron(t, args...)
		entry := logLine(t, stdout)
		if exit != exitError || entry["status"] != "error" || entry["error"] == nil || entry["err"] != float64(0) || stderr != "" {
			t.Errorf("%s: exit %d, entry %v, stderr %q", name, exit, entry, stderr)
		}
	}
}

func TestCronFailedLookups(t *testing.T) {
	dir := t.TempDir()
	args := append([]string{"-cron", "-json", dir + "/json/", "-html", dir + "/html/"}, offline...)
	exit, stdout, stderr := runCron(t, append(args, "Example.COM")...)
	entry := logLine(t, stdout)

	if exit != exitError || entry["status"] != "error" || entry["err"].(float64) < 1 {
		t.Errorf("exit %d, entry %v", exit, entry)
	}
	if !strings.Contains(entry["error"].(string), "lookups failed") || entry["domain"] != "example.com" {
		t.Errorf("entry %v", entry)
	}
	for _, key := range []string{"time", "tool", "version", "pass", "warn", "fail", "info", "duration_ms"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("log line has no %q field", key)
		}
	}
	// The results are still stored, at the paths in the log line
	for _, key := range []string{"json", "html"} {
		path, _ := entry[key].(string)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s file %q: %v", key, path, err)
		}
	}
	if stderr != "" {
		t.Errorf("stderr should be empty, got %q", stderr)
	}
}

func TestCronWriteError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0644); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-cron", "-json", filepath.Join(file, "x.json")}, offline...)
	exit, stdout, _ := runCron(t, append(args, "example.com")...)
	entry := logLine(t, stdout)

	if exit != exitError || !strings.Contains(entry["error"].(string), "writing JSON") || entry["err"].(float64) < 2 {
		t.Errorf("exit %d, entry %v (want the write error and the failed lookup counted)", exit, entry)
	}
	if _, ok := entry["json"]; ok {
		t.Error("a file that was not written should not be in the log line")
	}
}

func TestNormalModeUnchanged(t *testing.T) {
	dir := t.TempDir()
	args := append([]string{"-json", dir + "/"}, offline...)
	exit, stdout, stderr := runCron(t, append(args, "example.com")...)
	if exit != exitError || !strings.Contains(stdout, "example.com  ·  ") {
		t.Errorf("exit %d, console output:\n%s", exit, stdout)
	}
	if !strings.Contains(stderr, "JSON saved to: ") || !strings.Contains(stderr, "Lookups failed for") {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestUnknownFlag(t *testing.T) {
	exit, stdout, _ := runCron(t, "-cron", "-bogus", "example.com")
	if exit != exitError || stdout != "" {
		t.Errorf("exit %d, stdout %q", exit, stdout)
	}
}

func TestStatusFor(t *testing.T) {
	for exit, want := range map[int]string{exitOK: "ok", exitFail: "fail", exitError: "error", 3: "error"} {
		if got := statusFor(exit); got != want {
			t.Errorf("statusFor(%d) = %q, want %q", exit, got, want)
		}
	}
}
