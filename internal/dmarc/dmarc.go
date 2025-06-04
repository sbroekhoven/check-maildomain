package dmarc

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DMARCRecord represents a parsed DMARC record
type DMARCRecord struct {
	Raw      string            // The complete raw TXT record
	Version  string            // Should be "DMARC1"
	Tags     map[string]string // All DMARC tags and their values
	Valid    bool              // Whether the record is valid
	Location string            // Where the record was found
}

// DMARCPolicy represents the parsed policy values
type DMARCPolicy struct {
	Policy                 string   // p tag value (none, quarantine, reject)
	SubdomainPolicy        string   // sp tag value
	Percentage             int      // pct tag value
	ReportFormat           string   // rf tag value
	ReportInterval         int      // ri tag value
	FailureReportingOption string   // fo tag value
	AggregateReportURI     []string // rua tag values
	ForensicReportURI      []string // ruf tag values
	ADKIM                  string   // adkim tag value (r=relaxed, s=strict)
	ASPF                   string   // aspf tag value (r=relaxed, s=strict)
}

// LookupDMARC looks up DMARC record for the specified domain using the given nameserver
func LookupDMARC(domain string, nameserver string) (*DMARCRecord, error) {
	if !strings.HasSuffix(nameserver, ":53") {
		nameserver = nameserver + ":53"
	}

	dmarcDomain := "_dmarc." + domain

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dmarcDomain), dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, nameserver)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query returned non-success code: %v", dns.RcodeToString[r.Rcode])
	}

	// Look for DMARC record in TXT records
	for _, a := range r.Answer {
		if txt, ok := a.(*dns.TXT); ok {
			// Join TXT chunks into single string
			txtValue := strings.Join(txt.Txt, "")

			// Check if this is a DMARC record
			if strings.HasPrefix(strings.ToLower(txtValue), "v=dmarc1") {
				return parseDMARCRecord(txtValue, dmarcDomain), nil
			}
		}
	}

	return nil, fmt.Errorf("no DMARC record found for domain: %s", dmarcDomain)
}

// LookupDMARCWithFallback tries to use the specified nameserver, but falls back to the system resolver if that fails
func LookupDMARCWithFallback(domain string, nameserver string) (*DMARCRecord, error) {
	record, err := LookupDMARC(domain, nameserver)
	if err == nil {
		return record, nil
	}

	// Fallback to standard library
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		// Try the organizational domain if subdomain lookup fails
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			orgDomain := strings.Join(parts[len(parts)-2:], ".")
			return LookupDMARCWithFallback(orgDomain, nameserver)
		}
		return nil, fmt.Errorf("DMARC TXT lookup failed: %v", err)
	}

	// Look for DMARC record in TXT records
	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			return parseDMARCRecord(txt, dmarcDomain), nil
		}
	}

	return nil, fmt.Errorf("no DMARC record found for domain: %s", dmarcDomain)
}

// parseDMARCRecord parses a DMARC record string into a structured format
func parseDMARCRecord(rawRecord, location string) *DMARCRecord {
	record := &DMARCRecord{
		Raw:      rawRecord,
		Tags:     make(map[string]string),
		Location: location,
		Valid:    true,
	}

	// Split the record into tag-value pairs
	parts := strings.Split(rawRecord, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split tag=value
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			record.Valid = false
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		if key == "v" {
			record.Version = value
			if value != "DMARC1" {
				record.Valid = false
			}
		}

		record.Tags[key] = value
	}

	// Ensure required tags are present
	if _, ok := record.Tags["p"]; !ok {
		record.Valid = false
	}

	return record
}

// GetPolicy extracts the structured policy information from the DMARC record
func (r *DMARCRecord) GetPolicy() DMARCPolicy {
	policy := DMARCPolicy{
		Policy:         r.Tags["p"],
		Percentage:     100,   // Default
		ReportInterval: 86400, // Default (24 hours in seconds)
		ADKIM:          "r",   // Default is relaxed
		ASPF:           "r",   // Default is relaxed
	}

	// Extract subdomain policy (default to main policy if not specified)
	if sp, ok := r.Tags["sp"]; ok {
		policy.SubdomainPolicy = sp
	} else {
		policy.SubdomainPolicy = policy.Policy
	}

	// Extract percentage if present
	if pct, ok := r.Tags["pct"]; ok {
		fmt.Sscanf(pct, "%d", &policy.Percentage)
	}

	// Extract report format
	if rf, ok := r.Tags["rf"]; ok {
		policy.ReportFormat = rf
	}

	// Extract report interval
	if ri, ok := r.Tags["ri"]; ok {
		fmt.Sscanf(ri, "%d", &policy.ReportInterval)
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
