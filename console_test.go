package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/rules"
	"github.com/sbroekhoven/check-maildomain/internal/spf"
)

func TestWrap(t *testing.T) {
	tests := []struct {
		text  string
		width int
		want  []string
	}{
		{"", 10, []string{""}},
		{"short", 10, []string{"short"}},
		{"one two three four", 9, []string{"one two", "three", "four"}},
		{"averyveryverylongword fits", 5, []string{"averyveryverylongword", "fits"}},
		{"ünïcödé wörds", 7, []string{"ünïcödé", "wörds"}},
	}
	for _, tt := range tests {
		if got := wrap(tt.text, tt.width); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("wrap(%q, %d) = %q, want %q", tt.text, tt.width, got, tt.want)
		}
	}
}

func TestDisplayServer(t *testing.T) {
	for in, want := range map[string]string{
		"8.8.8.8:53":                "8.8.8.8",
		"8.8.8.8:5353":              "8.8.8.8:5353",
		"[2001:4860:4860::8888]:53": "2001:4860:4860::8888",
	} {
		if got := displayServer(in); got != want {
			t.Errorf("displayServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConsolePrint(t *testing.T) {
	info := collector.NewDomainInfo("example.com")
	info.QueryTime = time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	info.SPFRecord = spf.Parse("v=spf1 mx ?all")
	e := rules.NewEnhancedDomainInfo(info)
	rules.ApplyAllRules(e)

	render := func(verbose bool) string {
		var out strings.Builder
		c := &console{w: &out, verbose: verbose, width: 100}
		c.print(e, "8.8.8.8:53")
		return out.String()
	}

	out := render(false)
	for _, want := range []string{
		"example.com  ·  2026-01-02 03:04  ·  via 8.8.8.8\n",
		"SPF      !  v=spf1 mx ?all\n",                                           // area line shows the worst status and the record
		"         !  Ends with ?all (neutral)\n            SPF record uses ?all", // problems get details
		"         ✓  Record published\n         ✓  Single record\n\n",            // passes stay on one line
		"DMARC    ✗  No DMARC record\n            No DMARC record was found",     // single check is merged into the area line
		"MX       !  No MX records\n",
		" passed · ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("output contains ANSI codes while colour is off")
	}

	if verbose := render(true); !strings.Contains(verbose, "✓  Single record\n            Exactly one SPF record is published.") {
		t.Errorf("verbose output does not show pass details:\n%s", verbose)
	}
}
