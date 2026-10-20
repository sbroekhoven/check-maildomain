package spf

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

func TestParseTerm(t *testing.T) {
	tests := []struct {
		raw  string
		want Term
	}{
		{"-all", Term{Qualifier: '-', Name: "all"}},
		{"?all", Term{Qualifier: '?', Name: "all"}},
		{"all", Term{Qualifier: '+', Name: "all"}},
		{"include:_spf.google.com", Term{Qualifier: '+', Name: "include", Value: "_spf.google.com"}},
		{"~PTR:example.com", Term{Qualifier: '~', Name: "ptr", Value: "example.com"}},
		{"ip4:192.0.2.0/24", Term{Qualifier: '+', Name: "ip4", Value: "192.0.2.0/24"}},
		{"a/24", Term{Qualifier: '+', Name: "a"}},
		{"redirect=_spf.example.com", Term{Name: "redirect", Value: "_spf.example.com", Modifier: true}},
	}

	for _, tt := range tests {
		if got := ParseTerm(tt.raw); got != tt.want {
			t.Errorf("ParseTerm(%q) = %+v, want %+v", tt.raw, got, tt.want)
		}
	}
}

func TestIsSPF(t *testing.T) {
	for txt, want := range map[string]bool{
		"v=spf1 -all":       true,
		"V=SPF1 mx -all":    true,
		"v=spf1":            true,
		"v=spf10 -all":      false,
		"google-site-verif": false,
	} {
		if got := IsSPF(txt); got != want {
			t.Errorf("IsSPF(%q) = %v, want %v", txt, got, want)
		}
	}
}

func TestAllTermAndRedirect(t *testing.T) {
	r := Parse("v=spf1 mx ?all")
	if all := r.AllTerm(); all == nil || all.Qualifier != '?' {
		t.Errorf("AllTerm() = %+v, want ?all", all)
	}

	r = Parse("v=spf1 redirect=_spf.example.com")
	if r.AllTerm() != nil {
		t.Error("AllTerm() should be nil without all mechanism")
	}
	if got := r.Redirect(); got != "_spf.example.com" {
		t.Errorf("Redirect() = %q", got)
	}
}

func TestCountLookups(t *testing.T) {
	zone := map[string][]string{
		"a.example":     {"v=spf1 include:b.example include:c.example mx -all"},
		"b.example":     {"v=spf1 a mx ip4:192.0.2.1 -all"},
		"c.example":     {"v=spf1 exists:%{i}.x.example include:b.example -all"},
		"loop.example":  {"v=spf1 include:loop.example -all"},
		"redir.example": {"v=spf1 redirect=b.example"},
		"both.example":  {"v=spf1 mx redirect=b.example -all"},
		"twice.example": {"v=spf1 -all", "v=spf1 ~all"},
		"nospf.example": {"some other txt"},
	}
	lookup := func(domain string) ([]string, error) {
		if txts, ok := zone[domain]; ok {
			return txts, nil
		}
		if domain == "empty.example" {
			return nil, nil // NOERROR without records
		}
		return nil, &resolver.RcodeError{Name: domain, Rcode: dns.RcodeNameError}
	}

	tests := []struct {
		domain     string
		record     string
		want       int
		wantErrors int
		wantVoid   int
	}{
		// include b (1) + a,mx (2) + include c (1) + exists (1) + include b again (1) + a,mx (2) + mx (1)
		{"a.example", zone["a.example"][0], 9, 0, 0},
		{"loop.example", zone["loop.example"][0], 1, 1, 0},
		{"redir.example", zone["redir.example"][0], 3, 0, 0},
		// redirect is ignored when all is present
		{"both.example", zone["both.example"][0], 1, 0, 0},
		// missing.example is NXDOMAIN, so it is a void lookup
		{"x.example", "v=spf1 include:twice.example include:nospf.example include:missing.example -all", 3, 3, 1},
		{"x.example", "v=spf1 include:empty.example include:missing.example include:missing2.example -all", 3, 3, 3},
		{"x.example", "v=spf1 ip4:192.0.2.1 -all", 0, 0, 0},
	}

	for _, tt := range tests {
		stats := CountLookups(tt.domain, Parse(tt.record), lookup)
		if stats.Lookups != tt.want || len(stats.Problems) != tt.wantErrors || stats.VoidLookups != tt.wantVoid {
			t.Errorf("CountLookups(%q) = %+v; want %d lookups, %d void, %d problems", tt.record, stats, tt.want, tt.wantVoid, tt.wantErrors)
		}
	}
}

func TestCountLookupsStopsOnHugeRecords(t *testing.T) {
	lookup := func(domain string) ([]string, error) {
		return []string{"v=spf1 a a a a a a a a a a include:" + domain + "x -all"}, nil
	}
	got := CountLookups("x", Parse("v=spf1 include:x1 -all"), lookup).Lookups
	if got <= MaxDNSLookups || got > 4*MaxDNSLookups {
		t.Errorf("CountLookups = %d, want a bounded count above %d", got, MaxDNSLookups)
	}
}

func TestSyntaxErrors(t *testing.T) {
	tests := []struct {
		record string
		errors int
	}{
		{"v=spf1 mx a ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.com ~all", 0},
		{"v=spf1 a/24 mx:mail.example.com/24 exists:%{i}.x.example exp=explain.example -all", 0},
		{"v=spf1 foo:bar -all", 1},          // unknown mechanism
		{"v=spf1 ip4:192.0.2.0/33 -all", 1}, // prefix too long
		{"v=spf1 ip4:2001:db8::1 -all", 1},  // wrong family
		{"v=spf1 ip6:192.0.2.1 -all", 1},    // wrong family
		{"v=spf1 include -all", 1},          // include needs a domain
		{"v=spf1 -all:example.com", 1},      // all takes no arguments
		{"v=spf1 redirect=a.example redirect=b.example", 1},
		{"v=spf1 custom=value -all", 0}, // unknown modifiers are allowed
	}
	for _, tt := range tests {
		if got := Parse(tt.record).SyntaxErrors(); len(got) != tt.errors {
			t.Errorf("SyntaxErrors(%q) = %q, want %d errors", tt.record, got, tt.errors)
		}
	}
}

func TestIPRanges(t *testing.T) {
	got := Parse("v=spf1 ip4:192.0.2.1 +ip4:10.0.0.0/8 -ip4:0.0.0.0/0 ip6:2001:db8::/32 ip4:bad/99 -all").IPRanges()
	want := []IPRange{
		{"ip4:192.0.2.1", true, 32},
		{"+ip4:10.0.0.0/8", true, 8},
		{"ip6:2001:db8::/32", false, 32},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IPRanges() = %+v, want %+v", got, want)
	}
}
