package dmarc

import (
	"errors"
	"reflect"
	"testing"

	"github.com/sbroekhoven/check-maildomain/internal/resolver"
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

func TestReportDomain(t *testing.T) {
	for uri, want := range map[string]string{
		"mailto:d@example.com":             "example.com",
		"mailto:d@Reports.Example.NET!10m": "reports.example.net",
		"https://example.com/report":       "",
		"mailto:no-at-sign":                "",
	} {
		if got, _ := reportDomain(uri); got != want {
			t.Errorf("reportDomain(%q) = %q, want %q", uri, got, want)
		}
	}
}

func TestVerifyExternalReports(t *testing.T) {
	zone := map[string][]string{
		"example.com._report._dmarc.vendor.net": {"v=DMARC1"},
	}
	lookup := func(name string) ([]string, error) {
		if name == "example.com._report._dmarc.broken.net" {
			return nil, errors.New("i/o timeout")
		}
		if txts, ok := zone[name]; ok {
			return txts, nil
		}
		return nil, &resolver.RcodeError{Name: name, Rcode: 3}
	}

	record := Parse("v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@mail.example.com,mailto:c@vendor.net; ruf=mailto:x@other.org,mailto:y@broken.net,https://x.example", "_dmarc.example.com")
	got := verifyExternalReports(record, lookup)
	want := []ExternalReport{
		{URI: "mailto:c@vendor.net", Domain: "vendor.net", Authorized: true},
		{URI: "mailto:x@other.org", Domain: "other.org"},
		{URI: "mailto:y@broken.net", Domain: "broken.net", Unchecked: true, Error: "i/o timeout"},
		{URI: "https://x.example", Error: "only mailto: report addresses are supported by receivers"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verifyExternalReports() =\n%+v\nwant\n%+v", got, want)
	}
}
