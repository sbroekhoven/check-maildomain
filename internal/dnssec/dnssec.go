package dnssec

import (
	"time"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-maildomain/v2/internal/resolver"
)

// DNSSECInfo contains basic DNSSEC information for a domain
type DNSSECInfo struct {
	Domain          string    `json:"domain"`           // The domain name that was checked
	Enabled         bool      `json:"enabled"`          // Whether the zone is signed and delegated securely (DNSKEY + DS)
	HasDNSKEY       bool      `json:"has_dnskey"`       // Whether DNSKEY records were found
	HasDS           bool      `json:"has_ds"`           // Whether DS records were found in the parent zone
	KeyCount        int       `json:"key_count"`        // Number of DNSKEY records found
	Algorithm       []int     `json:"algorithm"`        // DNSSEC algorithms in use
	KeyTags         []uint16  `json:"key_tags"`         // Key tags of the keys
	SignatureExpiry time.Time `json:"signature_expiry"` // Earliest expiration of the DNSKEY RRset signatures
}

// CheckDNSSEC retrieves DNSSEC information for a domain
func CheckDNSSEC(domain string, res *resolver.Resolver) (*DNSSECInfo, error) {
	info := &DNSSECInfo{
		Domain:    domain,
		Algorithm: []int{},
		KeyTags:   []uint16{},
	}

	// Check for DNSKEY records
	r, err := res.Query(domain, dns.TypeDNSKEY, true)
	if err != nil {
		return nil, err
	}

	for _, ans := range r.Answer {
		switch rr := ans.(type) {
		case *dns.DNSKEY:
			info.HasDNSKEY = true
			info.KeyCount++
			info.Algorithm = append(info.Algorithm, int(rr.Algorithm))
			info.KeyTags = append(info.KeyTags, rr.KeyTag())
		case *dns.RRSIG:
			expiration := time.Unix(int64(rr.Expiration), 0)
			if info.SignatureExpiry.IsZero() || expiration.Before(info.SignatureExpiry) {
				info.SignatureExpiry = expiration
			}
		}
	}

	// Check for DS records in the parent zone
	r, err = res.Query(domain, dns.TypeDS, true)
	if err != nil {
		return nil, err
	}

	for _, ans := range r.Answer {
		if _, ok := ans.(*dns.DS); ok {
			info.HasDS = true
			break
		}
	}

	info.Enabled = info.HasDNSKEY && info.HasDS
	return info, nil
}
