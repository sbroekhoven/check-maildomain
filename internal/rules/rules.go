package rules

import (
	"fmt"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
)

// Status is the outcome of a rule check
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

// Severity orders statuses from harmless (0) to worst
func (s Status) Severity() int {
	switch s {
	case StatusPass:
		return 0
	case StatusInfo:
		return 1
	case StatusWarn:
		return 2
	default:
		return 3
	}
}

// Worst returns the more severe of two statuses
func Worst(a, b Status) Status {
	if b.Severity() > a.Severity() {
		return b
	}
	return a
}

// Area is the part of the mail setup a rule checks
type Area string

const (
	AreaSPF    Area = "SPF"
	AreaDMARC  Area = "DMARC"
	AreaDKIM   Area = "DKIM"
	AreaDNSSEC Area = "DNSSEC"
	AreaMX     Area = "MX"
	AreaTLS    Area = "TLS"
	AreaBIMI   Area = "BIMI"
)

// Areas lists all areas in display order
var Areas = []Area{AreaSPF, AreaDMARC, AreaDKIM, AreaDNSSEC, AreaMX, AreaTLS, AreaBIMI}

// Checks returns the collector lookups that provide the data for this area
func (a Area) Checks() []collector.Check {
	switch a {
	case AreaSPF:
		return []collector.Check{collector.CheckSPF}
	case AreaDMARC:
		return []collector.Check{collector.CheckDMARC}
	case AreaDKIM:
		return []collector.Check{collector.CheckDKIM}
	case AreaDNSSEC:
		return []collector.Check{collector.CheckDNSSEC}
	case AreaMX:
		return []collector.Check{collector.CheckMX}
	case AreaTLS:
		return []collector.Check{collector.CheckMTASTS, collector.CheckTLSRPT, collector.CheckDANE}
	case AreaBIMI:
		return []collector.Check{collector.CheckBIMI}
	}
	return nil
}

// Rule is a single check on the collected DNS data
type Rule struct {
	ID    int                                    // stable, public identifier
	Area  Area                                   // part of the mail setup it checks
	Name  string                                 // what it checks, e.g. "SPF DNS lookup limit"
	Check func(d *collector.DomainInfo) *Outcome // nil when the rule does not apply
}

// Outcome is what a rule found
type Outcome struct {
	Status      Status
	Description string // short outcome, e.g. "Ends with ~all"
	Message     string // explanation and advice
}

func pass(description, message string) *Outcome {
	return &Outcome{StatusPass, description, message}
}

func warn(description, message string) *Outcome {
	return &Outcome{StatusWarn, description, message}
}

func fail(description, message string) *Outcome {
	return &Outcome{StatusFail, description, message}
}

func inform(description, message string) *Outcome {
	return &Outcome{StatusInfo, description, message}
}

// unchecked returns an info outcome when the lookup for check failed, so a rule can't tell
// whether the record is missing; nil otherwise. what names the lookup in the message, e.g. "SPF".
func unchecked(d *collector.DomainInfo, check collector.Check, what string) *Outcome {
	err, failed := d.LookupFailure(check)
	if !failed {
		return nil
	}
	return inform("Could not be checked", fmt.Sprintf("The %s lookup failed, so this could not be checked: %s", what, err))
}

// registry holds all rules, ordered by ID. IDs are public (JSON, README) and must never be reused;
// retired IDs: 31 (MX blocklists) and 37 (SMTP STARTTLS probe).
var registry = []Rule{
	{1, AreaSPF, "SPF ptr mechanism", checkSPFPtrUsage},
	{2, AreaSPF, "SPF DNS lookup limit", checkSPFLookupLimit},
	{3, AreaSPF, "SPF all mechanism", checkSPFAllMechanism},
	{4, AreaDMARC, "DMARC policy", checkDMARCPolicy},
	{5, AreaDMARC, "DMARC record exists", checkDMARCExists},
	{6, AreaSPF, "SPF record exists", checkSPFExists},
	{7, AreaDKIM, "DKIM keys published", checkDKIMExists},
	{8, AreaDNSSEC, "DNSSEC enabled", checkDNSSECEnabled},
	{9, AreaMX, "MX records exist", checkMXExists},
	{10, AreaMX, "MX hosts resolve", checkMXHasIPs},
	{11, AreaMX, "MX hosts have IPv6", checkMXHasIPv6},
	{12, AreaMX, "MX redundancy", checkMXRedundancy},
	{13, AreaMX, "MX record count", checkMXTooMany},
	{14, AreaMX, "MX not localhost", checkMXLocalhost},
	{15, AreaMX, "MX no private IPs", checkMXPrivateIPs},
	{16, AreaSPF, "Single SPF record", checkSPFMultipleRecords},
	{17, AreaDMARC, "DMARC syntax", checkDMARCValid},
	{18, AreaDMARC, "DMARC percentage", checkDMARCPercentage},
	{19, AreaDMARC, "DMARC aggregate reporting", checkDMARCReporting},
	{20, AreaDMARC, "DMARC subdomain policy", checkDMARCSubdomainPolicy},
	{21, AreaDNSSEC, "DNSSEC signature expiry", checkDNSSECSignatureExpiry},
	{22, AreaMX, "MX hosts not CNAMEs", checkMXCNAME},
	{23, AreaDKIM, "DKIM key strength", checkDKIMKeyStrength},
	{24, AreaDKIM, "DKIM key flags", checkDKIMKeyFlags},
	{25, AreaSPF, "SPF syntax", checkSPFSyntax},
	{26, AreaSPF, "SPF void lookups", checkSPFVoidLookups},
	{27, AreaSPF, "SPF IP ranges", checkSPFIPRanges},
	{28, AreaMX, "No-mail domain protection", checkNoMailDomain},
	{29, AreaDMARC, "DMARC report authorization", checkDMARCReportAuthorization},
	{30, AreaMX, "MX reverse DNS", checkMXReverseDNS},
	{32, AreaTLS, "MTA-STS record", checkMTASTSRecord},
	{33, AreaTLS, "MTA-STS policy", checkMTASTSPolicy},
	{34, AreaTLS, "MTA-STS covers all MX hosts", checkMTASTSMX},
	{35, AreaTLS, "TLS reporting (TLS-RPT)", checkTLSRPT},
	{36, AreaTLS, "DANE for MX hosts", checkDANE},
	{38, AreaBIMI, "BIMI record", checkBIMIRecord},
	{39, AreaBIMI, "BIMI DMARC requirements", checkBIMIDMARC},
}

// Rules returns all rules, ordered by ID
func Rules() []Rule {
	return append([]Rule(nil), registry...)
}

// RuleResult represents the outcome of a rule check
type RuleResult struct {
	RuleID      int    `json:"rule_id"`
	Area        Area   `json:"area"`
	Description string `json:"description"`
	Status      Status `json:"status"`
	Message     string `json:"message"`
}

// Report is the collected DNS data together with the rule results
type Report struct {
	*collector.DomainInfo
	RuleResults []RuleResult `json:"rule_results,omitempty"`
}

// Evaluate runs all rules against the collected data; results are ordered by rule ID
func Evaluate(d *collector.DomainInfo) *Report {
	report := &Report{DomainInfo: d, RuleResults: []RuleResult{}}
	for _, rule := range registry {
		if o := rule.Check(d); o != nil {
			report.RuleResults = append(report.RuleResults, RuleResult{
				RuleID:      rule.ID,
				Area:        rule.Area,
				Description: o.Description,
				Status:      o.Status,
				Message:     o.Message,
			})
		}
	}
	return report
}

// HasStatus reports whether any rule ended with the given status
func (r *Report) HasStatus(status Status) bool {
	for _, res := range r.RuleResults {
		if res.Status == status {
			return true
		}
	}
	return false
}

// Worst returns the most severe status of all results
func (r *Report) Worst() Status {
	worst := StatusPass
	for _, res := range r.RuleResults {
		worst = Worst(worst, res.Status)
	}
	return worst
}
