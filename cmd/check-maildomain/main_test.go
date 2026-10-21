package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com", false},
		{" Example.COM. ", "example.com", false},
		{"bücher.example", "xn--bcher-kva.example", false},
		{"localhost", "", true},
		{"", "", true},
		{"exa mple.com", "", true},
	}
	for _, tt := range tests {
		got, err := normalizeDomain(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("normalizeDomain(%q) = %q, %v; want %q, error %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestOutputPath(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 15, 0, 0, time.UTC)
	dir := t.TempDir()

	tests := []struct {
		target string
		want   string
	}{
		{"report.json", "report.json"},
		{"out/report.html", "out/report.html"},
		{"runs/", filepath.Join("runs", "20261021001500-example.com-check-maildomain.json")},
		{dir, filepath.Join(dir, "20261021001500-example.com-check-maildomain.json")},
	}
	for _, tt := range tests {
		if got := outputPath(tt.target, "example.com", ".json", now); got != tt.want {
			t.Errorf("outputPath(%q) = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) func(io.Writer) error {
		return func(w io.Writer) error {
			_, err := io.WriteString(w, content)
			return err
		}
	}

	t.Run("creates parent folders", func(t *testing.T) {
		path := filepath.Join(dir, "a", "b", "c.json")
		if _, err := writeFile(path, "example.com", ".json", write("{}")); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
		if got, _ := os.ReadFile(path); string(got) != "{}" {
			t.Errorf("file content = %q", got)
		}
	})

	t.Run("write error", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := writeFile(filepath.Join(dir, "x.json"), "example.com", ".json", func(io.Writer) error { return boom })
		if !errors.Is(err, boom) {
			t.Errorf("writeFile error = %v, want %v", err, boom)
		}
	})

	t.Run("unwritable path", func(t *testing.T) {
		file := filepath.Join(dir, "file")
		if err := os.WriteFile(file, nil, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := writeFile(filepath.Join(file, "sub", "x.json"), "example.com", ".json", write("{}")); err == nil {
			t.Error("writeFile under a regular file should fail")
		}
	})
}
