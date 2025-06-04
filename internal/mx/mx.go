package mx

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// MXRecord represents an MX record with its priority
// Record represents a DNS record with its type and value
type Record struct {
	Type  string // "A", "AAAA", or "CNAME"
	Value string // IP address or CNAME target
}

// MXRecord represents an MX record with its priority
type MXRecord struct {
	Host     string
	Priority uint16
	Records  []Record
}

// LookupMX looks up MX records for the specified domain using the given nameserver
// Returns a sorted slice of MXRecord (sorted by priority, lowest first)
// LookupMX looks up MX records for the specified domain using the given nameserver
//
// MX records are sorted by priority (lowest first)
func LookupMX(domain string, nameserver string) ([]MXRecord, error) {
	if !strings.HasSuffix(nameserver, ":53") {
		nameserver = nameserver + ":53"
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, nameserver)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query returned non-success code: %v", dns.RcodeToString[r.Rcode])
	}

	var records []MXRecord
	for _, a := range r.Answer {
		if mx, ok := a.(*dns.MX); ok {
			host := strings.TrimSuffix(mx.Mx, ".")
			record := MXRecord{
				Host:     host,
				Priority: mx.Preference,
				Records:  []Record{},
			}

			// Resolve the MX host's records
			resolvedRecords, err := resolveMXHost(host, nameserver)
			if err == nil {
				record.Records = resolvedRecords
			}

			records = append(records, record)
		}
	}

	// Sort by priority (lowest first)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})

	return records, nil
}

// resolveMXHost resolves the DNS records for an MX host
func resolveMXHost(host string, nameserver string) ([]Record, error) {
	c := new(dns.Client)
	var records []Record

	// Check for CNAME records
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeCNAME)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, nameserver)
	if err == nil && r.Rcode == dns.RcodeSuccess {
		for _, a := range r.Answer {
			if record, ok := a.(*dns.CNAME); ok {
				records = append(records, Record{
					Type:  "CNAME",
					Value: strings.TrimSuffix(record.Target, "."),
				})
			}
		}
	}

	// Get IPv4 addresses
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	r, _, err = c.Exchange(m, nameserver)
	if err != nil {
		return nil, fmt.Errorf("DNS A record query failed: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS A record query returned non-success code: %v", dns.RcodeToString[r.Rcode])
	}

	for _, a := range r.Answer {
		if record, ok := a.(*dns.A); ok {
			records = append(records, Record{
				Type:  "A",
				Value: record.A.String(),
			})
		}
	}

	// Also try to get IPv6 addresses
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	m.RecursionDesired = true

	r, _, err = c.Exchange(m, nameserver)
	if err == nil && r.Rcode == dns.RcodeSuccess {
		for _, a := range r.Answer {
			if record, ok := a.(*dns.AAAA); ok {
				records = append(records, Record{
					Type:  "AAAA",
					Value: record.AAAA.String(),
				})
			}
		}
	}

	return records, nil
}

// LookupMXWithFallback tries to use the specified nameserver, but falls back to the system resolver if that fails
func LookupMXWithFallback(domain string, nameserver string) ([]MXRecord, error) {
	records, err := LookupMX(domain, nameserver)
	if err == nil && len(records) > 0 {
		return records, nil
	}

	// Fallback to standard library
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("MX lookup failed: %v", err)
	}

	var results []MXRecord
	for _, mx := range mxRecords {
		results = append(results, MXRecord{
			Host:     strings.TrimSuffix(mx.Host, "."),
			Priority: mx.Pref,
		})
	}

	// Sort by priority
	sort.Slice(results, func(i, j int) bool {
		return results[i].Priority < results[j].Priority
	})

	return results, nil
}
