package dmarc

import (
	"reflect"
	"testing"
)

func TestParseDMARCRecord(t *testing.T) {
	tests := []struct {
		raw   string
		valid bool
	}{
		{"v=DMARC1; p=reject; rua=mailto:d@example.com", true},
		{"v=DMARC1;p=none", true},
		{"v=DMARC1; P=Quarantine", true},
		{"v=DMARC1; rua=mailto:d@example.com", false}, // missing p
		{"v=DMARC1; p=block", false},                  // invalid p
		{"p=reject; v=DMARC1", false},                 // v not first
		{"v=dmarc1; p=reject", false},                 // version is case-sensitive
		{"v=DMARC1; p=reject; pct=150", false},
		{"v=DMARC1; p=reject; sp=all", false},
		{"v=DMARC1; p=reject; garbage", false},
	}

	for _, tt := range tests {
		r := Parse(tt.raw, "_dmarc.example.com")
		if r.Valid != tt.valid {
			t.Errorf("Parse(%q).Valid = %v, want %v (problems: %v)", tt.raw, r.Valid, tt.valid, r.Problems)
		}
	}
}

func TestGetPolicy(t *testing.T) {
	r := Parse("v=DMARC1; p=Reject; pct=50; rua=mailto:a@example.com, mailto:b@example.com; aspf=s", "_dmarc.example.com")
	got := r.GetPolicy()
	want := DMARCPolicy{
		Policy:             "reject",
		SubdomainPolicy:    "reject",
		Percentage:         50,
		ReportInterval:     86400,
		AggregateReportURI: []string{"mailto:a@example.com", "mailto:b@example.com"},
		ADKIM:              "r",
		ASPF:               "s",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetPolicy() = %+v, want %+v", got, want)
	}
}

func TestOrganizationalDomain(t *testing.T) {
	for domain, want := range map[string]string{
		"example.com":             "example.com",
		"mail.example.com":        "example.com",
		"a.b.example.co.uk":       "example.co.uk",
		"news.bbc.co.uk.":         "bbc.co.uk",
		"foo.example.com.au":      "example.com.au",
		"user.github.io":          "user.github.io",
		"deep.sub.user.github.io": "user.github.io",
	} {
		got, err := OrganizationalDomain(domain)
		if err != nil || got != want {
			t.Errorf("OrganizationalDomain(%q) = %q, %v; want %q", domain, got, err, want)
		}
	}
}
