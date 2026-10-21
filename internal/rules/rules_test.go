package rules

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/sbroekhoven/check-maildomain/v2/internal/bimi"
	"github.com/sbroekhoven/check-maildomain/v2/internal/collector"
	"github.com/sbroekhoven/check-maildomain/v2/internal/dkim"
	"github.com/sbroekhoven/check-maildomain/v2/internal/dmarc"
	"github.com/sbroekhoven/check-maildomain/v2/internal/dnssec"
	"github.com/sbroekhoven/check-maildomain/v2/internal/mx"
	"github.com/sbroekhoven/check-maildomain/v2/internal/spf"
	"github.com/sbroekhoven/check-maildomain/v2/internal/transport"
)

// newInfo returns empty collected data for example.com, modified by setup
func newInfo(setup func(*collector.DomainInfo)) *collector.DomainInfo {
	d := collector.NewDomainInfo("example.com")
	d.QueryTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if setup != nil {
		setup(d)
	}
	return d
}

// ruleByID returns the registered rule with the given ID
func ruleByID(t *testing.T, id int) Rule {
	t.Helper()
	for _, r := range Rules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule with ID %d", id)
	return Rule{}
}

// evalRule runs one rule against the data and returns its outcome, or nil if it does not apply
func evalRule(t *testing.T, id int, d *collector.DomainInfo) *Outcome {
	t.Helper()
	return ruleByID(t, id).Check(d)
}

// statusOf returns the status of rule id, or "" if the rule does not apply
func statusOf(t *testing.T, id int, d *collector.DomainInfo) Status {
	t.Helper()
	if o := evalRule(t, id, d); o != nil {
		return o.Status
	}
	return ""
}

type ruleCase struct {
	name  string
	setup func(*collector.DomainInfo)
	want  Status
}

func runRuleCases(t *testing.T, ruleID int, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusOf(t, ruleID, newInfo(tc.setup)); got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

func withSPF(raw string) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) { d.SPFRecord = spf.Parse(raw) }
}

func TestSPFRules(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		runRuleCases(t, 6, []ruleCase{
			{"missing", nil, StatusFail},
			{"present", withSPF("v=spf1 -all"), StatusPass},
		})
	})

	t.Run("ptr", func(t *testing.T) {
		runRuleCases(t, 1, []ruleCase{
			{"no record", nil, ""},
			{"ptr", withSPF("v=spf1 ptr -all"), StatusWarn},
			{"qualified ptr", withSPF("v=spf1 ?ptr:example.com -all"), StatusWarn},
			{"no ptr", withSPF("v=spf1 mx -all"), StatusPass},
		})
	})

	t.Run("all", func(t *testing.T) {
		runRuleCases(t, 3, []ruleCase{
			{"-all", withSPF("v=spf1 mx -all"), StatusPass},
			{"~all", withSPF("v=spf1 mx ~all"), StatusPass},
			{"?all", withSPF("v=spf1 mx ?all"), StatusWarn},
			{"+all", withSPF("v=spf1 mx +all"), StatusFail},
			{"bare all", withSPF("v=spf1 mx all"), StatusFail},
			{"missing", withSPF("v=spf1 mx"), StatusFail},
			{"redirect", withSPF("v=spf1 redirect=_spf.example.net"), StatusInfo},
		})
	})

	t.Run("lookup limit", func(t *testing.T) {
		withCount := func(n int, problems ...string) func(*collector.DomainInfo) {
			return func(d *collector.DomainInfo) {
				d.SPFRecord = spf.Parse("v=spf1 -all")
				d.SPFRecord.LookupCount = n
				d.SPFRecord.LookupErrors = problems
			}
		}
		runRuleCases(t, 2, []ruleCase{
			{"within limit", withCount(10), StatusPass},
			{"over limit", withCount(11), StatusFail},
			{"problems", withCount(3, "include:x has no SPF record"), StatusWarn},
		})
	})

	t.Run("multiple records", func(t *testing.T) {
		runRuleCases(t, 16, []ruleCase{
			{"one", withSPF("v=spf1 -all"), StatusPass},
			{"two", func(d *collector.DomainInfo) {
				d.SPFRecord = spf.Parse("v=spf1 -all")
				d.SPFRecord.RecordCount = 2
			}, StatusFail},
		})
	})
}

func withDMARC(raw string) func(*collector.DomainInfo) {
	return withDMARCAt(raw, "_dmarc.example.com")
}

func withDMARCAt(raw, location string) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) {
		d.DMARCRecord = dmarc.Parse(raw, location)
		d.DMARCPolicy = d.DMARCRecord.GetPolicy()
	}
}

func TestDMARCRules(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		runRuleCases(t, 5, []ruleCase{
			{"missing", nil, StatusFail},
			{"present", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"org domain", withDMARCAt("v=DMARC1; p=reject", "_dmarc.example.org"), StatusPass},
		})
	})

	t.Run("policy", func(t *testing.T) {
		runRuleCases(t, 4, []ruleCase{
			{"missing", nil, ""},
			{"reject", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"quarantine uppercase", withDMARC("v=DMARC1; p=QUARANTINE"), StatusWarn},
			{"none", withDMARC("v=DMARC1; p=none"), StatusFail},
			{"no p", withDMARC("v=DMARC1; rua=mailto:x@example.com"), StatusFail},
		})
	})

	t.Run("valid", func(t *testing.T) {
		runRuleCases(t, 17, []ruleCase{
			{"valid", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"invalid", withDMARC("v=DMARC1; p=block"), StatusFail},
		})
	})

	t.Run("pct", func(t *testing.T) {
		runRuleCases(t, 18, []ruleCase{
			{"default", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"partial", withDMARC("v=DMARC1; p=reject; pct=20"), StatusWarn},
			{"none policy", withDMARC("v=DMARC1; p=none; pct=20"), ""},
		})
	})

	t.Run("reporting", func(t *testing.T) {
		runRuleCases(t, 19, []ruleCase{
			{"rua", withDMARC("v=DMARC1; p=reject; rua=mailto:d@example.com"), StatusPass},
			{"no rua", withDMARC("v=DMARC1; p=reject"), StatusWarn},
		})
	})

	t.Run("subdomain policy", func(t *testing.T) {
		runRuleCases(t, 20, []ruleCase{
			{"inherited", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"sp none", withDMARC("v=DMARC1; p=reject; sp=none"), StatusWarn},
		})
	})
}

func TestDKIMRules(t *testing.T) {
	withDKIM := func(hasDomainKey bool, selectors ...string) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.DKIMInfo = &dkim.DKIMInfo{
				Domain:       d.Domain,
				HasDomainKey: hasDomainKey,
				HasSelectors: len(selectors) > 0,
				Selectors:    selectors,
				ResponseCode: map[bool]string{true: "NOERROR", false: "NXDOMAIN"}[hasDomainKey],
			}
		}
	}
	runRuleCases(t, 7, []ruleCase{
		{"unknown", nil, StatusInfo},
		{"selector found", withDKIM(true, "google"), StatusPass},
		{"domainkey without known selector", withDKIM(true), StatusWarn},
		{"nxdomain", withDKIM(false), StatusFail},
	})
}

func TestDNSSECRules(t *testing.T) {
	withDNSSEC := func(dnskey, ds bool, expiry time.Time) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.DNSSECInfo = &dnssec.DNSSECInfo{HasDNSKEY: dnskey, HasDS: ds, Enabled: dnskey && ds, SignatureExpiry: expiry}
		}
	}
	queryTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("enabled", func(t *testing.T) {
		runRuleCases(t, 8, []ruleCase{
			{"unknown", nil, StatusInfo},
			{"signed and delegated", withDNSSEC(true, true, time.Time{}), StatusPass},
			{"no DS", withDNSSEC(true, false, time.Time{}), StatusWarn},
			{"DS without DNSKEY", withDNSSEC(false, true, time.Time{}), StatusFail},
			{"unsigned", withDNSSEC(false, false, time.Time{}), StatusWarn},
		})
	})

	t.Run("signature expiry", func(t *testing.T) {
		runRuleCases(t, 21, []ruleCase{
			{"unsigned", withDNSSEC(false, false, time.Time{}), ""},
			{"valid", withDNSSEC(true, true, queryTime.Add(30*24*time.Hour)), StatusPass},
			{"expiring", withDNSSEC(true, true, queryTime.Add(48*time.Hour)), StatusWarn},
			{"expired", withDNSSEC(true, true, queryTime.Add(-time.Hour)), StatusFail},
		})
	})
}

func host(name string, records ...string) mx.MXRecord {
	r := mx.MXRecord{Host: name, Priority: 10, Records: []mx.Record{}}
	for _, v := range records {
		typ := "CNAME"
		if ip := net.ParseIP(v); ip != nil {
			typ = "A"
			if ip.To4() == nil {
				typ = "AAAA"
			}
		}
		r.Records = append(r.Records, mx.Record{Type: typ, Value: v})
	}
	return r
}

func withMX(records ...mx.MXRecord) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) { d.MXRecords = records }
}

func TestMXRules(t *testing.T) {
	nullMX := withMX(mx.MXRecord{Host: mx.NullMXHost})
	good := withMX(host("mx1.example.com", "192.0.2.1", "2001:db8::1"), host("mx2.example.com", "192.0.2.2", "2001:db8::2"))

	t.Run("exists", func(t *testing.T) {
		runRuleCases(t, 9, []ruleCase{
			{"none", nil, StatusWarn},
			{"null MX", nullMX, StatusInfo},
			{"present", good, StatusPass},
		})
	})

	t.Run("has IPs", func(t *testing.T) {
		runRuleCases(t, 10, []ruleCase{
			{"null MX", nullMX, ""},
			{"resolved", good, StatusPass},
			{"unresolved", withMX(host("mx.example.com")), StatusWarn},
			{"dangling CNAME", withMX(host("mx.example.com", "gone.example.net")), StatusWarn},
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		runRuleCases(t, 11, []ruleCase{
			{"dual stack", good, StatusPass},
			{"IPv4 only", withMX(host("mx.example.com", "192.0.2.1")), StatusWarn},
		})
	})

	t.Run("redundancy", func(t *testing.T) {
		runRuleCases(t, 12, []ruleCase{
			{"null MX", nullMX, ""},
			{"single", withMX(host("mx.example.com", "192.0.2.1")), StatusWarn},
			{"two", good, StatusPass},
		})
	})

	t.Run("too many", func(t *testing.T) {
		var many []mx.MXRecord
		for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
			many = append(many, host(n+".example.com", "192.0.2.1"))
		}
		runRuleCases(t, 13, []ruleCase{
			{"two", good, StatusPass},
			{"six", withMX(many...), StatusWarn},
		})
	})

	t.Run("localhost", func(t *testing.T) {
		runRuleCases(t, 14, []ruleCase{
			{"public", good, StatusPass},
			{"localhost name", withMX(host("localhost")), StatusFail},
			{"loopback range", withMX(host("mx.example.com", "127.0.0.2")), StatusFail},
			{"IPv6 loopback", withMX(host("mx.example.com", "::1")), StatusFail},
		})
	})

	t.Run("private IPs", func(t *testing.T) {
		runRuleCases(t, 15, []ruleCase{
			{"public", good, StatusPass},
			{"RFC 1918", withMX(host("mx.example.com", "10.1.2.3")), StatusFail},
			{"172.16/12 edge", withMX(host("mx.example.com", "172.31.255.255")), StatusFail},
			{"outside 172.16/12", withMX(host("mx.example.com", "172.32.0.1")), StatusPass},
			{"ULA", withMX(host("mx.example.com", "fd00::1")), StatusFail},
			{"link-local", withMX(host("mx.example.com", "169.254.1.1")), StatusFail},
		})
	})

	t.Run("CNAME", func(t *testing.T) {
		runRuleCases(t, 22, []ruleCase{
			{"no CNAME", good, StatusPass},
			{"CNAME", withMX(host("mx.example.com", "mail.example.net", "192.0.2.1")), StatusWarn},
		})
	})
}

func TestEvaluate(t *testing.T) {
	report := Evaluate(newInfo(withSPF("v=spf1 -all")))
	for i := 1; i < len(report.RuleResults); i++ {
		if report.RuleResults[i-1].RuleID >= report.RuleResults[i].RuleID {
			t.Fatalf("results not sorted by rule ID: %d before %d", report.RuleResults[i-1].RuleID, report.RuleResults[i].RuleID)
		}
	}
	for _, r := range report.RuleResults {
		if rule := ruleByID(t, r.RuleID); r.Area != rule.Area {
			t.Errorf("rule %d result has area %q, want %q", r.RuleID, r.Area, rule.Area)
		}
	}
	if !report.HasStatus(StatusFail) || report.Worst() != StatusFail {
		t.Error("expected failures for a domain without DMARC")
	}
}

func TestRegistry(t *testing.T) {
	areas := map[Area]bool{}
	for _, a := range Areas {
		areas[a] = true
	}

	prev := 0
	for _, r := range Rules() {
		if r.ID <= prev {
			t.Errorf("rule %d: IDs must be unique and ascending (previous %d)", r.ID, prev)
		}
		prev = r.ID
		if !areas[r.Area] || r.Name == "" || r.Check == nil {
			t.Errorf("rule %d is incomplete: %+v", r.ID, r)
		}
	}
}

// TestRegistryMatchesReadme keeps the rule table in README.md in sync with the registry
func TestRegistryMatchesReadme(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[int]Area{}
	for _, m := range regexp.MustCompile(`(?m)^\| (\d+) \| (\w+) \|`).FindAllStringSubmatch(string(readme), -1) {
		id, _ := strconv.Atoi(m[1])
		documented[id] = Area(m[2])
	}

	for _, r := range Rules() {
		if area, ok := documented[r.ID]; !ok || area != r.Area {
			t.Errorf("rule %d (%s, %s) is missing or has the wrong area in the README rule table", r.ID, r.Area, r.Name)
		}
		delete(documented, r.ID)
	}
	for id := range documented {
		t.Errorf("README documents rule %d, which does not exist", id)
	}
}

func TestStatusSeverity(t *testing.T) {
	order := []Status{StatusPass, StatusInfo, StatusWarn, StatusFail}
	for i := 1; i < len(order); i++ {
		if Worst(order[i-1], order[i]) != order[i] || Worst(order[i], order[i-1]) != order[i] {
			t.Errorf("Worst(%s, %s) should be %s", order[i-1], order[i], order[i])
		}
	}
}

func TestFailedLookupsAreUnchecked(t *testing.T) {
	failed := func(check collector.Check) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.Errors[check] = "DNS query failed: i/o timeout"
			d.Failed[check] = true
		}
	}
	notFound := func(check collector.Check) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.Errors[check] = "no record found"
		}
	}

	tests := []struct {
		ruleID int
		area   Area
		absent Status // status when the record simply does not exist
	}{
		{6, AreaSPF, StatusFail},
		{5, AreaDMARC, StatusFail},
		{9, AreaMX, StatusWarn},
		{7, AreaDKIM, StatusInfo},
		{8, AreaDNSSEC, StatusInfo},
	}
	for _, tt := range tests {
		t.Run(string(tt.area), func(t *testing.T) {
			o := evalRule(t, tt.ruleID, newInfo(failed(tt.area.Checks()[0])))
			if o == nil || o.Status != StatusInfo || o.Description != "Could not be checked" {
				t.Errorf("failed lookup: outcome = %+v, want info 'Could not be checked'", o)
			}
			if got := statusOf(t, tt.ruleID, newInfo(notFound(tt.area.Checks()[0]))); got != tt.absent {
				t.Errorf("record not found: status = %q, want %q", got, tt.absent)
			}
		})
	}
}

func withDKIMKeys(keys ...dkim.Key) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) {
		d.DKIMInfo = &dkim.DKIMInfo{Domain: d.Domain, HasDomainKey: true, HasSelectors: len(keys) > 0, Keys: keys}
		for _, k := range keys {
			d.DKIMInfo.Selectors = append(d.DKIMInfo.Selectors, k.Selector)
		}
	}
}

func TestDKIMKeyRules(t *testing.T) {
	rsa := func(bits int) dkim.Key { return dkim.Key{Selector: "s1", Type: "rsa", Bits: bits} }

	t.Run("strength", func(t *testing.T) {
		runRuleCases(t, 23, []ruleCase{
			{"no keys", withDKIMKeys(), ""},
			{"2048", withDKIMKeys(rsa(2048)), StatusPass},
			{"ed25519", withDKIMKeys(dkim.Key{Selector: "ed", Type: "ed25519", Bits: 256}), StatusPass},
			{"1024", withDKIMKeys(rsa(1024)), StatusWarn},
			{"512", withDKIMKeys(rsa(2048), rsa(512)), StatusFail},
			{"unparseable", withDKIMKeys(dkim.Key{Selector: "x", Type: "rsa", Error: "bad"}), StatusWarn},
			{"only revoked", withDKIMKeys(dkim.Key{Selector: "old", Type: "rsa", Revoked: true}), ""},
		})
	})

	t.Run("flags", func(t *testing.T) {
		testMode := rsa(2048)
		testMode.TestMode = true
		sha1 := rsa(2048)
		sha1.HashAlgorithms = []string{"sha1"}
		both := rsa(2048)
		both.HashAlgorithms = []string{"sha1", "sha256"}
		revoked := dkim.Key{Selector: "old", Revoked: true}
		runRuleCases(t, 24, []ruleCase{
			{"clean", withDKIMKeys(rsa(2048)), StatusPass},
			{"test mode", withDKIMKeys(testMode), StatusWarn},
			{"sha1 only", withDKIMKeys(sha1), StatusWarn},
			{"sha1 and sha256", withDKIMKeys(both), StatusPass},
			{"one revoked", withDKIMKeys(rsa(2048), revoked), StatusPass},
			{"all revoked", withDKIMKeys(revoked), StatusInfo},
		})
	})
}

func TestNewSPFRules(t *testing.T) {
	t.Run("syntax", func(t *testing.T) {
		runRuleCases(t, 25, []ruleCase{
			{"valid", withSPF("v=spf1 mx ip4:192.0.2.0/24 -all"), StatusPass},
			{"invalid", withSPF("v=spf1 ip4:192.0.2.0/40 -all"), StatusFail},
		})
	})

	t.Run("void lookups", func(t *testing.T) {
		withVoid := func(n int) func(*collector.DomainInfo) {
			return func(d *collector.DomainInfo) {
				d.SPFRecord = spf.Parse("v=spf1 -all")
				d.SPFRecord.VoidLookups = n
			}
		}
		runRuleCases(t, 26, []ruleCase{
			{"none", withVoid(0), StatusPass},
			{"two", withVoid(2), StatusWarn},
			{"three", withVoid(3), StatusFail},
		})
	})

	t.Run("ip ranges", func(t *testing.T) {
		runRuleCases(t, 27, []ruleCase{
			{"narrow", withSPF("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/48 -all"), StatusPass},
			{"ipv4 /12", withSPF("v=spf1 ip4:10.0.0.0/12 -all"), StatusWarn},
			{"ipv6 /24", withSPF("v=spf1 ip6:2001:db8::/24 -all"), StatusWarn},
			{"ipv4 /4", withSPF("v=spf1 ip4:0.0.0.0/4 -all"), StatusFail},
			{"excluded range ignored", withSPF("v=spf1 -ip4:0.0.0.0/1 mx -all"), StatusPass},
		})
	})
}

func TestNoMailDomain(t *testing.T) {
	setup := func(mxs []mx.MXRecord, spfRaw, dmarcRaw string) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.MXRecords = mxs
			if spfRaw != "" {
				d.SPFRecord = spf.Parse(spfRaw)
			}
			if dmarcRaw != "" {
				withDMARC(dmarcRaw)(d)
			}
		}
	}
	nullMX := []mx.MXRecord{{Host: mx.NullMXHost}}
	runRuleCases(t, 28, []ruleCase{
		{"receives mail", setup([]mx.MXRecord{host("mx.example.com", "192.0.2.1")}, "", ""), ""},
		{"null MX locked down", setup(nullMX, "v=spf1 -all", "v=DMARC1; p=reject"), StatusPass},
		{"null MX unprotected", setup(nullMX, "", ""), StatusWarn},
		{"null MX, DMARC none", setup(nullMX, "v=spf1 -all", "v=DMARC1; p=none"), StatusWarn},
		{"no MX unprotected", setup(nil, "", ""), StatusInfo},
		{"no MX but sends", setup(nil, "v=spf1 include:_spf.example.net -all", ""), StatusInfo},
		{"MX lookup failed", func(d *collector.DomainInfo) {
			d.Errors[collector.CheckMX], d.Failed[collector.CheckMX] = "timeout", true
		}, ""},
	})
}

func TestDMARCReportAuthorization(t *testing.T) {
	withExternal := func(raw string, reports ...dmarc.ExternalReport) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			withDMARC(raw)(d)
			d.DMARCRecord.ExternalReports = reports
		}
	}
	runRuleCases(t, 29, []ruleCase{
		{"no report addresses", withExternal("v=DMARC1; p=reject"), ""},
		{"own domain", withExternal("v=DMARC1; p=reject; rua=mailto:d@example.com"), StatusPass},
		{"authorized", withExternal("v=DMARC1; p=reject; rua=mailto:d@vendor.net",
			dmarc.ExternalReport{URI: "mailto:d@vendor.net", Domain: "vendor.net", Authorized: true}), StatusPass},
		{"not authorized", withExternal("v=DMARC1; p=reject; rua=mailto:d@vendor.net",
			dmarc.ExternalReport{URI: "mailto:d@vendor.net", Domain: "vendor.net"}), StatusWarn},
		{"unsupported", withExternal("v=DMARC1; p=reject; rua=https://x",
			dmarc.ExternalReport{URI: "https://x", Error: "only mailto"}), StatusWarn},
		{"unchecked", withExternal("v=DMARC1; p=reject; rua=mailto:d@vendor.net",
			dmarc.ExternalReport{URI: "mailto:d@vendor.net", Domain: "vendor.net", Unchecked: true}), StatusInfo},
	})
}

func TestMXReverseDNS(t *testing.T) {
	withPTR := func(ptr string, confirmed bool, ptrErr string) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			r := host("mx.example.com", "192.0.2.1")
			r.Records[0].PTR, r.Records[0].PTRConfirmed, r.Records[0].PTRError = ptr, confirmed, ptrErr
			d.MXRecords = []mx.MXRecord{r}
		}
	}
	runRuleCases(t, 30, []ruleCase{
		{"no MX", nil, ""},
		{"confirmed", withPTR("mx.example.com", true, ""), StatusPass},
		{"missing", withPTR("", false, ""), StatusWarn},
		{"not confirmed", withPTR("other.example.net", false, ""), StatusWarn},
		{"lookup failed", withPTR("", false, "timeout"), StatusInfo},
	})
}

func withMTASTS(mode string, mxPatterns ...string) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) {
		d.MXRecords = []mx.MXRecord{host("mx1.example.com", "192.0.2.1")}
		d.MTASTS = &transport.MTASTS{Record: "v=STSv1; id=1", ID: "1", RecordCount: 1}
		if mode != "" {
			d.MTASTS.Policy = &transport.Policy{Version: "STSv1", Mode: mode, MX: mxPatterns, MaxAge: 604800}
		}
	}
}

func TestMTASTSRules(t *testing.T) {
	t.Run("record", func(t *testing.T) {
		runRuleCases(t, 32, []ruleCase{
			{"no mail", nil, ""},
			{"missing", withMX(host("mx1.example.com", "192.0.2.1")), StatusWarn},
			{"present", withMTASTS("enforce", "mx1.example.com"), StatusPass},
			{"invalid", func(d *collector.DomainInfo) {
				withMTASTS("enforce")(d)
				d.MTASTS.RecordProblems = []string{"the id= tag is missing"}
			}, StatusFail},
			{"lookup failed", func(d *collector.DomainInfo) {
				d.Errors[collector.CheckMTASTS], d.Failed[collector.CheckMTASTS] = "timeout", true
			}, StatusInfo},
		})
	})

	t.Run("policy", func(t *testing.T) {
		runRuleCases(t, 33, []ruleCase{
			{"no record", nil, ""},
			{"enforce", withMTASTS("enforce", "mx1.example.com"), StatusPass},
			{"testing", withMTASTS("testing", "mx1.example.com"), StatusWarn},
			{"none", withMTASTS("none"), StatusWarn},
			{"unreachable", func(d *collector.DomainInfo) {
				withMTASTS("")(d)
				d.MTASTS.PolicyError = "HTTP 404"
			}, StatusFail},
			{"invalid", func(d *collector.DomainInfo) {
				withMTASTS("enforce", "mx1.example.com")(d)
				d.MTASTS.Policy.Problems = []string{"version must be STSv1"}
			}, StatusFail},
			{"short max_age", func(d *collector.DomainInfo) {
				withMTASTS("enforce", "mx1.example.com")(d)
				d.MTASTS.Policy.MaxAge = 300
			}, StatusWarn},
		})
	})

	t.Run("mx coverage", func(t *testing.T) {
		runRuleCases(t, 34, []ruleCase{
			{"covered", withMTASTS("enforce", "mx1.example.com"), StatusPass},
			{"wildcard", withMTASTS("enforce", "*.example.com"), StatusPass},
			{"missing in enforce", withMTASTS("enforce", "mx9.example.com"), StatusFail},
			{"missing in testing", withMTASTS("testing", "mx9.example.com"), StatusWarn},
			{"mode none", withMTASTS("none"), ""},
		})
	})
}

func TestTLSRPT(t *testing.T) {
	withMXOnly := withMX(host("mx1.example.com", "192.0.2.1"))
	runRuleCases(t, 35, []ruleCase{
		{"no mail", nil, ""},
		{"missing, no MTA-STS", withMXOnly, StatusInfo},
		{"missing with MTA-STS", withMTASTS("enforce", "mx1.example.com"), StatusWarn},
		{"present", func(d *collector.DomainInfo) {
			withMXOnly(d)
			d.TLSRPT = &transport.TLSRPT{Record: "v=TLSRPTv1; rua=mailto:tls@example.com", RUA: []string{"mailto:tls@example.com"}}
		}, StatusPass},
		{"invalid", func(d *collector.DomainInfo) {
			withMXOnly(d)
			d.TLSRPT = &transport.TLSRPT{Record: "v=TLSRPTv1", Problems: []string{"rua missing"}}
		}, StatusFail},
	})
}

func TestDANE(t *testing.T) {
	withDANE := func(hosts ...transport.DANEHost) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) { d.DANE = hosts }
	}
	tlsa := func(usage uint8) []transport.TLSA {
		return []transport.TLSA{{Usage: usage, Selector: 1, MatchingType: 1, Data: "ab"}}
	}
	runRuleCases(t, 36, []ruleCase{
		{"not looked up", nil, ""},
		{"not used", withDANE(transport.DANEHost{Host: "mx1", TLSA: []transport.TLSA{}}), StatusInfo},
		{"all hosts", withDANE(transport.DANEHost{Host: "mx1", TLSA: tlsa(3), Authenticated: true}), StatusPass},
		{"partial", withDANE(transport.DANEHost{Host: "mx1", TLSA: tlsa(3), Authenticated: true}, transport.DANEHost{Host: "mx2", TLSA: []transport.TLSA{}}), StatusWarn},
		{"not validated", withDANE(transport.DANEHost{Host: "mx1", TLSA: tlsa(3)}), StatusFail},
		{"pkix usage", withDANE(transport.DANEHost{Host: "mx1", TLSA: tlsa(1), Authenticated: true}), StatusWarn},
		{"lookup failed", withDANE(transport.DANEHost{Host: "mx1", Error: "timeout"}), StatusInfo},
	})
}

func TestBIMIRules(t *testing.T) {
	withBIMI := func(raw, dmarcRaw string) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.BIMI = bimi.Parse(raw, "default._bimi.example.com")
			if dmarcRaw != "" {
				withDMARC(dmarcRaw)(d)
			}
		}
	}
	full := "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"

	t.Run("record", func(t *testing.T) {
		runRuleCases(t, 38, []ruleCase{
			{"missing", nil, StatusInfo},
			{"full", withBIMI(full, ""), StatusPass},
			{"no certificate", withBIMI("v=BIMI1; l=https://example.com/logo.svg", ""), StatusWarn},
			{"declined", withBIMI("v=BIMI1; l=; a=", ""), StatusInfo},
			{"invalid", withBIMI("v=BIMI1; l=http://example.com/logo.svg", ""), StatusFail},
		})
	})

	t.Run("dmarc requirements", func(t *testing.T) {
		runRuleCases(t, 39, []ruleCase{
			{"no BIMI", nil, ""},
			{"reject", withBIMI(full, "v=DMARC1; p=reject"), StatusPass},
			{"quarantine", withBIMI(full, "v=DMARC1; p=quarantine"), StatusPass},
			{"no DMARC", withBIMI(full, ""), StatusFail},
			{"p=none", withBIMI(full, "v=DMARC1; p=none"), StatusFail},
			{"pct 50", withBIMI(full, "v=DMARC1; p=reject; pct=50"), StatusFail},
			{"sp=none", withBIMI(full, "v=DMARC1; p=reject; sp=none"), StatusFail},
		})
	})
}
