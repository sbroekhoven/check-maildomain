package dkim

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DKIMInfo contains information about DKIM configuration for a domain
type DKIMInfo struct {
	Domain       string   // Domain that was checked
	HasDomainKey bool     // Whether _domainkey record exists
	HasSelectors bool     // Whether any selectors were found
	Selectors    []string // List of discovered selectors
	ResponseCode string   // DNS response code (NOERROR, NXDOMAIN, etc.)
	Error        string   // Any error encountered during the check
}

// CommonSelectors is a list of commonly used DKIM selector names to check
var CommonSelectors = []string{
	"default", "dkim", "mail", "email", "k1", "selector1", "selector2",
	"google", "zoho", "mx", "key", "mta", "pm", "dkim-smtp", "s1", "s2",
}

// CheckDKIM checks if a domain has DKIM configured by looking for _domainkey record
func CheckDKIM(domain string, nameserver string) (*DKIMInfo, error) {
	if !strings.HasSuffix(nameserver, ":53") {
		nameserver = nameserver + ":53"
	}

	info := &DKIMInfo{
		Domain:       domain,
		HasDomainKey: false,
		HasSelectors: false,
		Selectors:    []string{},
	}

	c := dns.Client{}
	m := dns.Msg{}

	// Check if _domainkey record exists
	domainKeyName := "_domainkey." + domain
	m.SetQuestion(dns.Fqdn(domainKeyName), dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := c.Exchange(&m, nameserver)
	if err != nil {
		info.Error = fmt.Sprintf("DNS query failed: %v", err)
		return info, err
	}

	// Store the response code
	info.ResponseCode = dns.RcodeToString[r.Rcode]

	// If response code is NOERROR, _domainkey record likely exists
	if r.Rcode == dns.RcodeSuccess {
		info.HasDomainKey = true
	}

	// Try to find some common selectors
	for _, selector := range CommonSelectors {
		selectorName := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		m := dns.Msg{}
		m.SetQuestion(dns.Fqdn(selectorName), dns.TypeTXT)
		m.RecursionDesired = true

		r, _, err := c.Exchange(&m, nameserver)
		if err != nil {
			continue
		}

		// If we get a successful response and have answers, this selector exists
		if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			info.HasSelectors = true
			info.Selectors = append(info.Selectors, selector)
		}
	}

	return info, nil
}

// CheckDKIMWithFallback tries to use the specified nameserver, but falls back to 8.8.4.4 if that fails
func CheckDKIMWithFallback(domain string, nameserver string) (*DKIMInfo, error) {
	info, err := CheckDKIM(domain, nameserver)
	if err == nil {
		return info, nil
	}

	// Fallback to Google DNS
	return CheckDKIM(domain, "8.8.4.4:53")
}
