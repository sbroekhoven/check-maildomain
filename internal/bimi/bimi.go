// Package bimi looks up the BIMI (Brand Indicators for Message Identification) record of a domain
package bimi

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/dmarc"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// Record is a parsed BIMI record ("v=BIMI1; l=<logo URL>; a=<certificate URL>")
type Record struct {
	Raw       string   `json:"raw"`
	Location  string   `json:"location"`  // where the record was found
	Logo      string   `json:"logo"`      // l=: HTTPS URL of the SVG logo
	Authority string   `json:"authority"` // a=: HTTPS URL of the Verified Mark Certificate (VMC/CMC)
	Declined  bool     `json:"declined"`  // l= and a= are empty: the domain explicitly publishes no logo
	Problems  []string `json:"problems,omitempty"`
}

// Lookup reads default._bimi.<domain>, falling back to the organizational domain
func Lookup(domain string, res *resolver.Resolver) (*Record, error) {
	record, err := lookupAt(domain, res)
	if record == nil && (err == nil || resolver.IsNotFound(err)) {
		if org, perr := dmarc.OrganizationalDomain(domain); perr == nil && !strings.EqualFold(org, domain) {
			record, err = lookupAt(org, res)
		}
	}
	return record, err
}

func lookupAt(domain string, res *resolver.Resolver) (*Record, error) {
	name := "default._bimi." + domain
	txts, err := res.TXT(name)
	if err != nil {
		return nil, err
	}
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=bimi1") {
			return Parse(txt, name), nil
		}
	}
	return nil, &resolver.NotFoundError{What: "BIMI", Name: name}
}

// Parse parses a BIMI record
func Parse(raw, location string) *Record {
	r := &Record{Raw: raw, Location: location}
	tags := map[string]string{}
	for i, part := range strings.Split(raw, ";") {
		key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if i == 0 && (key != "v" || value != "BIMI1") {
			r.Problems = append(r.Problems, "the record must start with v=BIMI1")
		}
		tags[key] = value
	}

	r.Logo, r.Authority = tags["l"], tags["a"]
	if r.Logo == "" && r.Authority == "" {
		r.Declined = true
		return r
	}
	if r.Logo == "" {
		r.Problems = append(r.Problems, "the l= tag with the logo URL is missing")
	} else if !strings.HasPrefix(strings.ToLower(r.Logo), "https://") {
		r.Problems = append(r.Problems, fmt.Sprintf("logo URL %q must use https://", r.Logo))
	}
	if r.Authority != "" && !strings.HasPrefix(strings.ToLower(r.Authority), "https://") {
		r.Problems = append(r.Problems, fmt.Sprintf("certificate URL %q must use https://", r.Authority))
	}
	return r
}
