package dkim

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// DKIMInfo contains information about DKIM configuration for a domain
type DKIMInfo struct {
	Domain       string   `json:"domain"`        // Domain that was checked
	HasDomainKey bool     `json:"has_domainkey"` // Whether the _domainkey name exists
	HasSelectors bool     `json:"has_selectors"` // Whether any selectors were found
	Selectors    []string `json:"selectors"`     // List of discovered selectors
	ResponseCode string   `json:"response_code"` // DNS response code for _domainkey (NOERROR, NXDOMAIN, etc.)
}

// CommonSelectors is a list of commonly used DKIM selector names to check
var CommonSelectors = []string{
	"default", "dkim", "mail", "email", "k1", "selector1", "selector2",
	"google", "zoho", "mx", "key", "mta", "pm", "dkim-smtp", "s1", "s2",
}

// CheckDKIM checks if a domain has DKIM configured by probing the _domainkey name and a set of
// selectors: the common ones plus any extra selectors given by the caller
func CheckDKIM(domain string, res *resolver.Resolver, extraSelectors []string) (*DKIMInfo, error) {
	info := &DKIMInfo{
		Domain:    domain,
		Selectors: []string{},
	}

	// Check if _domainkey name exists; NXDOMAIN means nothing exists below it (RFC 8020)
	r, err := res.Query("_domainkey."+domain, dns.TypeTXT, false)
	if r == nil {
		return nil, err
	}
	info.ResponseCode = dns.RcodeToString[r.Rcode]
	info.HasDomainKey = r.Rcode == dns.RcodeSuccess

	selectors := uniqueSelectors(extraSelectors, CommonSelectors)
	found := make([]bool, len(selectors))

	// Probe all selectors concurrently
	var wg sync.WaitGroup
	for i, selector := range selectors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			txts, err := res.TXT(selector + "._domainkey." + domain)
			if err != nil {
				return
			}
			for _, txt := range txts {
				if IsDKIMKey(txt) {
					found[i] = true
					return
				}
			}
		}()
	}
	wg.Wait()

	for i, selector := range selectors {
		if found[i] {
			info.HasSelectors = true
			info.Selectors = append(info.Selectors, selector)
		}
	}

	return info, nil
}

// IsDKIMKey reports whether a TXT value looks like a DKIM key record (RFC 6376 3.6.1)
func IsDKIMKey(txt string) bool {
	hasKey := false
	for i, part := range strings.Split(txt, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		switch {
		case key == "v" && (i != 0 || value != "DKIM1"):
			return false
		case key == "p":
			hasKey = true
		}
	}
	return hasKey
}

func uniqueSelectors(lists ...[]string) []string {
	seen := map[string]bool{}
	var result []string
	for _, list := range lists {
		for _, s := range list {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" && !seen[s] {
				seen[s] = true
				result = append(result, s)
			}
		}
	}
	return result
}
