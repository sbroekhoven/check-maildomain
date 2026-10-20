package dkim

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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
	Keys         []Key    `json:"keys"`          // The keys published under the discovered selectors
	ResponseCode string   `json:"response_code"` // DNS response code for _domainkey (NOERROR, NXDOMAIN, etc.)
}

// Key is a parsed DKIM key record (RFC 6376 3.6.1)
type Key struct {
	Selector       string   `json:"selector"`
	Raw            string   `json:"raw"`
	Type           string   `json:"type"`                      // k= tag: "rsa" (default) or "ed25519"
	Bits           int      `json:"bits,omitempty"`            // key size, 0 when the key could not be parsed
	Revoked        bool     `json:"revoked"`                   // empty p= tag: the key was withdrawn
	TestMode       bool     `json:"test_mode"`                 // t=y: receivers must not treat failures differently
	HashAlgorithms []string `json:"hash_algorithms,omitempty"` // h= tag: allowed hash algorithms, empty means all
	Error          string   `json:"error,omitempty"`           // why the public key could not be parsed
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
		Keys:      []Key{},
	}

	// Check if _domainkey name exists; NXDOMAIN means nothing exists below it (RFC 8020)
	r, err := res.Query("_domainkey."+domain, dns.TypeTXT, false)
	if r == nil {
		return nil, err
	}
	info.ResponseCode = dns.RcodeToString[r.Rcode]
	info.HasDomainKey = r.Rcode == dns.RcodeSuccess

	selectors := uniqueSelectors(extraSelectors, CommonSelectors)
	found := make([]*Key, len(selectors))

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
					key := ParseKey(selector, txt)
					found[i] = &key
					return
				}
			}
		}()
	}
	wg.Wait()

	for i, selector := range selectors {
		if found[i] != nil {
			info.HasSelectors = true
			info.Selectors = append(info.Selectors, selector)
			info.Keys = append(info.Keys, *found[i])
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

// tags splits a tag=value list (RFC 6376 3.2) into a map with lowercase tag names
func tags(txt string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			result[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

// ParseKey parses a DKIM key record and determines the key type and size
func ParseKey(selector, txt string) Key {
	t := tags(txt)
	key := Key{Selector: selector, Raw: txt, Type: "rsa"}
	if k, ok := t["k"]; ok && k != "" {
		key.Type = strings.ToLower(k)
	}
	for _, flag := range strings.Split(t["t"], ":") {
		if strings.TrimSpace(flag) == "y" {
			key.TestMode = true
		}
	}
	for _, h := range strings.Split(t["h"], ":") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			key.HashAlgorithms = append(key.HashAlgorithms, h)
		}
	}

	// Whitespace is allowed inside the base64 value
	p := strings.Join(strings.Fields(t["p"]), "")
	if p == "" {
		key.Revoked = true
		return key
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		key.Error = "public key is not valid base64"
		return key
	}

	switch key.Type {
	case "ed25519":
		// RFC 8463: the raw 32-byte key, not wrapped in SubjectPublicKeyInfo
		if len(der) != ed25519.PublicKeySize {
			key.Error = "Ed25519 public key has the wrong length"
			return key
		}
		key.Bits = 256
	case "rsa":
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			// Some publishers use a bare PKCS#1 key instead of SubjectPublicKeyInfo
			rsaPub, err2 := x509.ParsePKCS1PublicKey(der)
			if err2 != nil {
				key.Error = "RSA public key could not be parsed"
				return key
			}
			pub = rsaPub
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			key.Error = "k=rsa but the public key is not an RSA key"
			return key
		}
		key.Bits = rsaPub.N.BitLen()
	default:
		key.Error = "unknown key type " + key.Type
	}
	return key
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
