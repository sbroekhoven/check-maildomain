package transport

import (
	"sync"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// DANEHost holds the TLSA records published for an MX host (RFC 7672)
type DANEHost struct {
	Host          string `json:"host"`
	TLSA          []TLSA `json:"tlsa"`
	Authenticated bool   `json:"authenticated"`   // the resolver validated the answer with DNSSEC (AD bit)
	Error         string `json:"error,omitempty"` // the lookup failed
}

// TLSA is one TLSA record
type TLSA struct {
	Usage        uint8  `json:"usage"`         // 2 = DANE-TA, 3 = DANE-EE; 0 and 1 (PKIX) are not used for SMTP
	Selector     uint8  `json:"selector"`      // 0 = full certificate, 1 = public key
	MatchingType uint8  `json:"matching_type"` // 0 = exact, 1 = SHA-256, 2 = SHA-512
	Data         string `json:"data"`
}

// LookupDANE looks up the TLSA records at _25._tcp.<host> for each MX host
func LookupDANE(hosts []string, res *resolver.Resolver) []DANEHost {
	results := make([]DANEHost, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = lookupTLSA(host, res)
		}()
	}
	wg.Wait()
	return results
}

func lookupTLSA(host string, res *resolver.Resolver) DANEHost {
	result := DANEHost{Host: host, TLSA: []TLSA{}}
	r, err := res.Query("_25._tcp."+host, dns.TypeTLSA, true)
	switch {
	case resolver.IsNotFound(err):
		return result
	case err != nil:
		result.Error = err.Error()
		return result
	}

	result.Authenticated = r.AuthenticatedData
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			result.TLSA = append(result.TLSA, TLSA{
				Usage:        t.Usage,
				Selector:     t.Selector,
				MatchingType: t.MatchingType,
				Data:         t.Certificate,
			})
		}
	}
	return result
}
