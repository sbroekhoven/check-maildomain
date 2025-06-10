package spf

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SPFRecord represents an SPF record with its parsed value
type SPFRecord struct {
	Raw     string   // The complete raw TXT record
	Version string   // Should be "spf1"
	Terms   []string // The individual mechanisms and modifiers
}

// LookupSPF looks up SPF records for the specified domain using the given nameserver
func LookupSPF(domain string, nameserver string) (*SPFRecord, error) {
	if !strings.HasSuffix(nameserver, ":53") {
		nameserver = nameserver + ":53"
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)

	in, _, err := c.Exchange(m, nameserver)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %v", err)
	}

	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query returned non-success code: %v", dns.RcodeToString[in.Rcode])
	}

	// Look for SPF record in TXT records
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.TXT); ok {

			// Join TXT chunks into single string
			txtValue := strings.Join(a.Txt, "")

			// Check if this is an SPF record
			if strings.HasPrefix(strings.ToLower(txtValue), "v=spf1") {
				// Parse the SPF record
				terms := strings.Fields(txtValue)
				return &SPFRecord{
					Raw:     txtValue,
					Version: strings.TrimPrefix(terms[0], "v="),
					Terms:   terms[1:],
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no SPF record found for domain: %s", domain)
}

// LookupSPFWithFallback tries to use the specified nameserver, but falls back to the system resolver if that fails
func LookupSPFWithFallback(domain string, nameserver string) (*SPFRecord, error) {
	record, err := LookupSPF(domain, nameserver)
	if err == nil {
		return record, nil
	}
	println(err.Error())

	// Fallback to standard library
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		println(err.Error())
		return nil, fmt.Errorf("TXT lookup failed: %v", err)
	}

	// Look for SPF record in TXT records
	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			terms := strings.Fields(txt)
			return &SPFRecord{
				Raw:     txt,
				Version: strings.TrimPrefix(terms[0], "v="),
				Terms:   terms[1:],
			}, nil
		}
	}

	return nil, fmt.Errorf("no SPF record found for domain: %s", domain)
}

// HasInclude checks if the SPF record includes the specified domain
func (r *SPFRecord) HasInclude(domain string) bool {
	includePrefix := "include:" + domain
	for _, term := range r.Terms {
		if term == includePrefix || strings.HasPrefix(term, includePrefix+"/") {
			return true
		}
	}
	return false
}

// HasIP checks if the SPF record includes the specified IP
func (r *SPFRecord) HasIP(ip string) bool {
	ipPrefix := "ip4:" + ip
	for _, term := range r.Terms {
		if term == ipPrefix || strings.HasPrefix(term, ipPrefix+"/") {
			return true
		}
	}
	return false
}
