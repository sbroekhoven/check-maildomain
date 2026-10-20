package rules

import (
	"net"
	"testing"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/dkim"
	"github.com/sbroekhoven/check-maildomain/internal/dmarc"
	"github.com/sbroekhoven/check-maildomain/internal/dnssec"
	"github.com/sbroekhoven/check-maildomain/internal/mx"
	"github.com/sbroekhoven/check-maildomain/internal/spf"
)

// newInfo returns an empty EnhancedDomainInfo for example.com, modified by setup
func newInfo(setup func(*collector.DomainInfo)) *EnhancedDomainInfo {
	d := collector.NewDomainInfo("example.com")
	d.QueryTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if setup != nil {
		setup(d)
	}
	return NewEnhancedDomainInfo(d)
}

// statusOf runs check and returns the status of ruleID, or "" if the rule produced no result
func statusOf(t *testing.T, check func(*EnhancedDomainInfo), info *EnhancedDomainInfo, ruleID int) Status {
	t.Helper()
	check(info)
	var status Status
	for _, r := range info.RuleResults {
		if r.RuleID != ruleID {
			t.Errorf("unexpected rule %d in results", r.RuleID)
		}
		status = r.Status
	}
	if len(info.RuleResults) > 1 {
		t.Errorf("rule %d produced %d results", ruleID, len(info.RuleResults))
	}
	return status
}

type ruleCase struct {
	name  string
	setup func(*collector.DomainInfo)
	want  Status
}

func runRuleCases(t *testing.T, check func(*EnhancedDomainInfo), ruleID int, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusOf(t, check, newInfo(tc.setup), ruleID); got != tc.want {
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
		runRuleCases(t, CheckSPFExists, 6, []ruleCase{
			{"missing", nil, StatusFail},
			{"present", withSPF("v=spf1 -all"), StatusPass},
		})
	})

	t.Run("ptr", func(t *testing.T) {
		runRuleCases(t, CheckSPFPtrUsage, 1, []ruleCase{
			{"no record", nil, ""},
			{"ptr", withSPF("v=spf1 ptr -all"), StatusWarn},
			{"qualified ptr", withSPF("v=spf1 ?ptr:example.com -all"), StatusWarn},
			{"no ptr", withSPF("v=spf1 mx -all"), StatusPass},
		})
	})

	t.Run("all", func(t *testing.T) {
		runRuleCases(t, CheckSPFAllMechanism, 3, []ruleCase{
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
		runRuleCases(t, CheckSPFLookupLimit, 2, []ruleCase{
			{"within limit", withCount(10), StatusPass},
			{"over limit", withCount(11), StatusFail},
			{"problems", withCount(3, "include:x has no SPF record"), StatusWarn},
		})
	})

	t.Run("multiple records", func(t *testing.T) {
		runRuleCases(t, CheckSPFMultipleRecords, 16, []ruleCase{
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
		runRuleCases(t, CheckDMARCExists, 5, []ruleCase{
			{"missing", nil, StatusFail},
			{"present", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"org domain", withDMARCAt("v=DMARC1; p=reject", "_dmarc.example.org"), StatusPass},
		})
	})

	t.Run("policy", func(t *testing.T) {
		runRuleCases(t, CheckDMARCPolicy, 4, []ruleCase{
			{"missing", nil, ""},
			{"reject", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"quarantine uppercase", withDMARC("v=DMARC1; p=QUARANTINE"), StatusWarn},
			{"none", withDMARC("v=DMARC1; p=none"), StatusFail},
			{"no p", withDMARC("v=DMARC1; rua=mailto:x@example.com"), StatusFail},
		})
	})

	t.Run("valid", func(t *testing.T) {
		runRuleCases(t, CheckDMARCValid, 17, []ruleCase{
			{"valid", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"invalid", withDMARC("v=DMARC1; p=block"), StatusFail},
		})
	})

	t.Run("pct", func(t *testing.T) {
		runRuleCases(t, CheckDMARCPercentage, 18, []ruleCase{
			{"default", withDMARC("v=DMARC1; p=reject"), StatusPass},
			{"partial", withDMARC("v=DMARC1; p=reject; pct=20"), StatusWarn},
			{"none policy", withDMARC("v=DMARC1; p=none; pct=20"), ""},
		})
	})

	t.Run("reporting", func(t *testing.T) {
		runRuleCases(t, CheckDMARCReporting, 19, []ruleCase{
			{"rua", withDMARC("v=DMARC1; p=reject; rua=mailto:d@example.com"), StatusPass},
			{"no rua", withDMARC("v=DMARC1; p=reject"), StatusWarn},
		})
	})

	t.Run("subdomain policy", func(t *testing.T) {
		runRuleCases(t, CheckDMARCSubdomainPolicy, 20, []ruleCase{
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
	runRuleCases(t, CheckDKIMExists, 7, []ruleCase{
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
		runRuleCases(t, CheckDNSSECEnabled, 8, []ruleCase{
			{"unknown", nil, StatusInfo},
			{"signed and delegated", withDNSSEC(true, true, time.Time{}), StatusPass},
			{"no DS", withDNSSEC(true, false, time.Time{}), StatusWarn},
			{"DS without DNSKEY", withDNSSEC(false, true, time.Time{}), StatusFail},
			{"unsigned", withDNSSEC(false, false, time.Time{}), StatusWarn},
		})
	})

	t.Run("signature expiry", func(t *testing.T) {
		runRuleCases(t, CheckDNSSECSignatureExpiry, 21, []ruleCase{
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
		runRuleCases(t, CheckMXExists, 9, []ruleCase{
			{"none", nil, StatusWarn},
			{"null MX", nullMX, StatusInfo},
			{"present", good, StatusPass},
		})
	})

	t.Run("has IPs", func(t *testing.T) {
		runRuleCases(t, CheckMXHasIPs, 10, []ruleCase{
			{"null MX", nullMX, ""},
			{"resolved", good, StatusPass},
			{"unresolved", withMX(host("mx.example.com")), StatusWarn},
			{"dangling CNAME", withMX(host("mx.example.com", "gone.example.net")), StatusWarn},
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		runRuleCases(t, CheckMXHasIPv6, 11, []ruleCase{
			{"dual stack", good, StatusPass},
			{"IPv4 only", withMX(host("mx.example.com", "192.0.2.1")), StatusWarn},
		})
	})

	t.Run("redundancy", func(t *testing.T) {
		runRuleCases(t, CheckMXRedundancy, 12, []ruleCase{
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
		runRuleCases(t, CheckMXTooMany, 13, []ruleCase{
			{"two", good, StatusPass},
			{"six", withMX(many...), StatusWarn},
		})
	})

	t.Run("localhost", func(t *testing.T) {
		runRuleCases(t, CheckMXLocalhost, 14, []ruleCase{
			{"public", good, StatusPass},
			{"localhost name", withMX(host("localhost")), StatusFail},
			{"loopback range", withMX(host("mx.example.com", "127.0.0.2")), StatusFail},
			{"IPv6 loopback", withMX(host("mx.example.com", "::1")), StatusFail},
		})
	})

	t.Run("private IPs", func(t *testing.T) {
		runRuleCases(t, CheckMXPrivateIPs, 15, []ruleCase{
			{"public", good, StatusPass},
			{"RFC 1918", withMX(host("mx.example.com", "10.1.2.3")), StatusFail},
			{"172.16/12 edge", withMX(host("mx.example.com", "172.31.255.255")), StatusFail},
			{"outside 172.16/12", withMX(host("mx.example.com", "172.32.0.1")), StatusPass},
			{"ULA", withMX(host("mx.example.com", "fd00::1")), StatusFail},
			{"link-local", withMX(host("mx.example.com", "169.254.1.1")), StatusFail},
		})
	})

	t.Run("CNAME", func(t *testing.T) {
		runRuleCases(t, CheckMXCNAME, 22, []ruleCase{
			{"no CNAME", good, StatusPass},
			{"CNAME", withMX(host("mx.example.com", "mail.example.net", "192.0.2.1")), StatusWarn},
		})
	})
}

func TestApplyAllRulesOrdered(t *testing.T) {
	info := newInfo(withSPF("v=spf1 -all"))
	ApplyAllRules(info)
	for i := 1; i < len(info.RuleResults); i++ {
		if info.RuleResults[i-1].RuleID > info.RuleResults[i].RuleID {
			t.Fatalf("results not sorted by rule ID: %d before %d", info.RuleResults[i-1].RuleID, info.RuleResults[i].RuleID)
		}
	}
	if !info.HasStatus(StatusFail) {
		t.Error("expected failures for a domain without DMARC")
	}
}

func TestFailedLookupsAreUnchecked(t *testing.T) {
	failed := func(check string) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.Errors[check] = "DNS query failed: i/o timeout"
			d.Failed[check] = true
		}
	}
	notFound := func(check string) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) {
			d.Errors[check] = "no record found"
		}
	}

	tests := []struct {
		check  func(*EnhancedDomainInfo)
		ruleID int
		key    string
		absent Status // status when the record simply does not exist
	}{
		{CheckSPFExists, 6, "spf", StatusFail},
		{CheckDMARCExists, 5, "dmarc", StatusFail},
		{CheckMXExists, 9, "mx", StatusWarn},
		{CheckDKIMExists, 7, "dkim", StatusInfo},
		{CheckDNSSECEnabled, 8, "dnssec", StatusInfo},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			info := newInfo(failed(tt.key))
			if got := statusOf(t, tt.check, info, tt.ruleID); got != StatusInfo {
				t.Errorf("failed lookup: status = %q, want info", got)
			}
			if got := info.RuleResults[0].Description; got != "Could not be checked" {
				t.Errorf("failed lookup: description = %q", got)
			}
			if got := statusOf(t, tt.check, newInfo(notFound(tt.key)), tt.ruleID); got != tt.absent {
				t.Errorf("record not found: status = %q, want %q", got, tt.absent)
			}
		})
	}
}
