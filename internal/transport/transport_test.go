package transport

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	good := "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.backup.example.net\r\nmax_age: 604800\r\n"
	got := ParsePolicy(good)
	want := Policy{Version: "STSv1", Mode: "enforce", MX: []string{"mail.example.com", "*.backup.example.net"}, MaxAge: 604800}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParsePolicy() = %+v, want %+v", got, want)
	}

	for body, problems := range map[string]int{
		"version: STSv1\nmode: none\nmax_age: 86400\n":                      0, // mx not needed with mode none
		"version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 86400\n":    1,
		"version: STSv1\nmode: strict\nmx: a.example\nmax_age: 86400\n":     1,
		"version: STSv1\nmode: enforce\nmax_age: 86400\n":                   1, // no mx
		"version: STSv1\nmode: enforce\nmx: a.example\n":                    1, // no max_age
		"version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 99999999\n": 1,
		"version: STSv1\nmode: enforce\nmode: testing\nmx: a\nmax_age: 1\n": 1,
		"<html>not a policy</html>":                                         5,
	} {
		if got := ParsePolicy(body); len(got.Problems) != problems {
			t.Errorf("ParsePolicy(%q) problems = %q, want %d", body, got.Problems, problems)
		}
	}
}

func TestMatchesMX(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"mail.example.com", "mail.example.com", true},
		{"mail.example.com", "MAIL.example.com.", true},
		{"*.example.net", "mx1.example.net", true},
		{"*.example.net", "a.b.example.net", false},
		{"*.example.net", "example.net", false},
		{"mail.example.com", "mail2.example.com", false},
	}
	for _, tt := range tests {
		if got := MatchesMX(tt.pattern, tt.host); got != tt.want {
			t.Errorf("MatchesMX(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestParseSTSRecord(t *testing.T) {
	for record, want := range map[string]int{
		"v=STSv1; id=20240101T000000":            0,
		"v=STSv1; id=2024-01-01":                 1, // invalid characters
		"v=STSv1":                                1, // no id
		"id=abc; v=STSv1":                        1, // v not first
		"v=STSv1; id=" + strings.Repeat("a", 33): 1,
	} {
		if _, problems := parseSTSRecord(record); len(problems) != want {
			t.Errorf("parseSTSRecord(%q) = %q, want %d problems", record, problems, want)
		}
	}
}

func TestParseTLSRPT(t *testing.T) {
	rua, problems := ParseTLSRPT("v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com/tls")
	if len(rua) != 2 || len(problems) != 0 {
		t.Errorf("valid record: rua %q, problems %q", rua, problems)
	}
	for record, want := range map[string]int{
		"v=TLSRPTv1":                 1,
		"v=TLSRPTv1; rua=ftp://x":    1,
		"rua=mailto:a@b; v=TLSRPTv1": 1,
	} {
		if _, problems := ParseTLSRPT(record); len(problems) != want {
			t.Errorf("ParseTLSRPT(%q) = %q, want %d problems", record, problems, want)
		}
	}
}

func TestFetchPolicy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "version: STSv1\n") })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/missing", http.NotFound)
	mux.HandleFunc("/huge", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", maxPolicySize+1)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := srv.Client()

	if body, err := fetchPolicy(srv.URL+"/ok", client); err != nil || body != "version: STSv1\n" {
		t.Errorf("ok: %q, %v", body, err)
	}
	for _, path := range []string{"/redirect", "/missing", "/huge"} {
		if _, err := fetchPolicy(srv.URL+path, client); err == nil {
			t.Errorf("%s: expected an error", path)
		}
	}
}
