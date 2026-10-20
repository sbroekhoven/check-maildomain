package dmarc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/resolver"
	"golang.org/x/net/publicsuffix"
)

// DMARCRecord represents a parsed DMARC record
type DMARCRecord struct {
	Raw      string            `json:"raw"`      // The complete raw TXT record
	Version  string            `json:"version"`  // Should be "DMARC1"
	Tags     map[string]string `json:"tags"`     // All DMARC tags and their values
	Valid    bool              `json:"valid"`    // Whether the record is valid
	Problems []string          `json:"problems"` // Why the record is not valid
	Location string            `json:"location"` // Where the record was found
}

// DMARCPolicy represents the parsed policy values
type DMARCPolicy struct {
	Policy                 string   `json:"policy"`                   // p tag value (none, quarantine, reject)
	SubdomainPolicy        string   `json:"subdomain_policy"`         // sp tag value
	Percentage             int      `json:"percentage"`               // pct tag value
	ReportFormat           string   `json:"report_format"`            // rf tag value
	ReportInterval         int      `json:"report_interval"`          // ri tag value
	FailureReportingOption string   `json:"failure_reporting_option"` // fo tag value
	AggregateReportURI     []string `json:"aggregate_report_uri"`     // rua tag values
	ForensicReportURI      []string `json:"forensic_report_uri"`      // ruf tag values
	ADKIM                  string   `json:"adkim"`                    // adkim tag value (r=relaxed, s=strict)
	ASPF                   string   `json:"aspf"`                     // aspf tag value (r=relaxed, s=strict)
}

// LookupDMARC looks up the DMARC record for the domain. If the domain has no record of its own,
// the record of the organizational domain (RFC 7489 6.6.3) is used instead.
func LookupDMARC(domain string, res *resolver.Resolver) (*DMARCRecord, error) {
	record, err := lookupDMARCAt(domain, res)
	if record != nil || (err != nil && !resolver.IsNotFound(err)) {
		return record, err
	}

	orgDomain, perr := OrganizationalDomain(domain)
	if perr != nil || strings.EqualFold(orgDomain, domain) {
		return nil, err
	}
	return lookupDMARCAt(orgDomain, res)
}

func lookupDMARCAt(domain string, res *resolver.Resolver) (*DMARCRecord, error) {
	dmarcDomain := "_dmarc." + domain

	txts, err := res.TXT(dmarcDomain)
	if err != nil {
		return nil, err
	}

	// Look for DMARC record in TXT records
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			return Parse(txt, dmarcDomain), nil
		}
	}

	return nil, &resolver.NotFoundError{What: "DMARC", Name: dmarcDomain}
}

// OrganizationalDomain returns the registrable domain (e.g. example.co.uk for mail.example.co.uk)
func OrganizationalDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(domain, "."))
}

// Parse parses a DMARC record string into a structured format
func Parse(rawRecord, location string) *DMARCRecord {
	record := &DMARCRecord{
		Raw:      rawRecord,
		Tags:     make(map[string]string),
		Location: location,
		Problems: []string{},
	}

	// Split the record into tag-value pairs
	parts := strings.Split(rawRecord, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split tag=value
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			record.Problems = append(record.Problems, fmt.Sprintf("malformed tag %q", part))
			continue
		}

		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		if key == "v" {
			record.Version = value
			if value != "DMARC1" {
				record.Problems = append(record.Problems, fmt.Sprintf("version must be DMARC1, got %q", value))
			}
			if i != 0 {
				record.Problems = append(record.Problems, "v=DMARC1 must be the first tag")
			}
		}

		record.Tags[key] = value
	}

	// Ensure required tags are present and valid
	switch p, ok := record.Tags["p"]; {
	case !ok:
		record.Problems = append(record.Problems, "required p tag is missing")
	case !validPolicy(p):
		record.Problems = append(record.Problems, fmt.Sprintf("invalid p value %q", p))
	}
	if sp, ok := record.Tags["sp"]; ok && !validPolicy(sp) {
		record.Problems = append(record.Problems, fmt.Sprintf("invalid sp value %q", sp))
	}
	if pct, ok := record.Tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err != nil || n < 0 || n > 100 {
			record.Problems = append(record.Problems, fmt.Sprintf("invalid pct value %q", pct))
		}
	}

	record.Valid = len(record.Problems) == 0
	return record
}

func validPolicy(p string) bool {
	switch strings.ToLower(p) {
	case "none", "quarantine", "reject":
		return true
	}
	return false
}

// GetPolicy extracts the structured policy information from the DMARC record
func (r *DMARCRecord) GetPolicy() DMARCPolicy {
	policy := DMARCPolicy{
		Policy:         strings.ToLower(r.Tags["p"]),
		Percentage:     100,   // Default
		ReportInterval: 86400, // Default (24 hours in seconds)
		ADKIM:          "r",   // Default is relaxed
		ASPF:           "r",   // Default is relaxed
	}

	// Extract subdomain policy (default to main policy if not specified)
	if sp, ok := r.Tags["sp"]; ok {
		policy.SubdomainPolicy = strings.ToLower(sp)
	} else {
		policy.SubdomainPolicy = policy.Policy
	}

	// Extract percentage if present
	if pct, ok := r.Tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err == nil {
			policy.Percentage = n
		}
	}

	// Extract report format
	if rf, ok := r.Tags["rf"]; ok {
		policy.ReportFormat = rf
	}

	// Extract report interval
	if ri, ok := r.Tags["ri"]; ok {
		if n, err := strconv.Atoi(ri); err == nil {
			policy.ReportInterval = n
		}
	}

	// Extract failure reporting option
	if fo, ok := r.Tags["fo"]; ok {
		policy.FailureReportingOption = fo
	}

	// Extract report URIs
	if rua, ok := r.Tags["rua"]; ok {
		policy.AggregateReportURI = parseDMARCUris(rua)
	}

	if ruf, ok := r.Tags["ruf"]; ok {
		policy.ForensicReportURI = parseDMARCUris(ruf)
	}

	// Extract alignment modes
	if adkim, ok := r.Tags["adkim"]; ok {
		policy.ADKIM = adkim
	}

	if aspf, ok := r.Tags["aspf"]; ok {
		policy.ASPF = aspf
	}

	return policy
}

// parseDMARCUris splits a comma-separated list of URIs
func parseDMARCUris(uriList string) []string {
	uris := strings.Split(uriList, ",")
	var result []string
	for _, uri := range uris {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			result = append(result, uri)
		}
	}
	return result
}
