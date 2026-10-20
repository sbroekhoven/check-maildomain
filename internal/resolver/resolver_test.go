package resolver

import "testing"

func TestNormalizeNameserver(t *testing.T) {
	for in, want := range map[string]string{
		"8.8.8.8":                     "8.8.8.8:53",
		"8.8.8.8:5353":                "8.8.8.8:5353",
		" 1.1.1.1 ":                   "1.1.1.1:53",
		"2001:4860:4860::8888":        "[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8888]":      "[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8888]:5353": "[2001:4860:4860::8888]:5353",
		"dns.example.net":             "dns.example.net:53",
	} {
		if got := NormalizeNameserver(in); got != want {
			t.Errorf("NormalizeNameserver(%q) = %q, want %q", in, got, want)
		}
	}
}
