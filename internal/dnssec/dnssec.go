package dnssec

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSSECInfo contains basic DNSSEC information for a domain
type DNSSECInfo struct {
	Domain           string    // The domain name that was checked
	Enabled          bool      // Whether DNSSEC is enabled
	HasDNSKEY        bool      // Whether DNSKEY records were found
	HasDS            bool      // Whether DS records were found
	KeyCount         int       // Number of DNSKEY records found
	Algorithm        []int     // DNSSEC algorithms in use
	KeyTags          []uint16  // Key tags of the keys
	LastSignatureExp time.Time // Expiration time of the most recent signature
	Error            string    // Any error encountered during the check
}

// CheckDNSSEC retrieves DNSSEC information for a domain using the specified nameserver
func CheckDNSSEC(domain string, nameserver string) (*DNSSECInfo, error) {
	if !strings.HasSuffix(nameserver, ":53") {
		nameserver = nameserver + ":53"
	}

	info := &DNSSECInfo{
		Domain:    domain,
		Enabled:   false,
		Algorithm: []int{},
		KeyTags:   []uint16{},
	}

	// Check for DNSKEY records
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true

	r, _, err := c.Exchange(&m, nameserver)
	if err != nil {
		info.Error = fmt.Sprintf("DNS query failed: %v", err)
		return info, err
	}

	// Process DNSKEY records
	for _, ans := range r.Answer {
		if dnskey, ok := ans.(*dns.DNSKEY); ok {
			info.HasDNSKEY = true
			info.Enabled = true
			info.KeyCount++
			info.Algorithm = append(info.Algorithm, int(dnskey.Algorithm))
			info.KeyTags = append(info.KeyTags, dnskey.KeyTag())
		}

		// Check for signature expiration
		if rrsig, ok := ans.(*dns.RRSIG); ok {
			expiration := time.Unix(int64(rrsig.Expiration), 0)
			if expiration.After(info.LastSignatureExp) {
				info.LastSignatureExp = expiration
			}
		}
	}

	// Check for DS records in the parent zone
	m = dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true

	r, _, err = c.Exchange(&m, nameserver)
	if err != nil {
		info.Error = fmt.Sprintf("DS record query failed: %v", err)
		return info, err
	}

	if len(r.Answer) > 0 {
		info.HasDS = true
		info.Enabled = true
	}

	return info, nil
}

// CheckDNSSECWithFallback tries to use the specified nameserver, but falls back to 8.8.4.4 if that fails
func CheckDNSSECWithFallback(domain string, nameserver string) (*DNSSECInfo, error) {
	info, err := CheckDNSSEC(domain, nameserver)
	if err == nil {
		return info, nil
	}

	// Fallback to Google DNS
	return CheckDNSSEC(domain, "8.8.4.4:53")
}
