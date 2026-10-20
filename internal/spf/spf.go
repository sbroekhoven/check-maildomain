package spf

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// MaxDNSLookups is the RFC 7208 limit on DNS-querying terms during SPF evaluation
const MaxDNSLookups = 10

// SPFRecord represents an SPF record with its parsed value
type SPFRecord struct {
	Raw          string   `json:"raw"`                     // The complete raw TXT record
	Version      string   `json:"version"`                 // Should be "spf1"
	Terms        []string `json:"terms"`                   // The individual mechanisms and modifiers
	RecordCount  int      `json:"record_count"`            // Number of v=spf1 records published (must be 1)
	LookupCount  int      `json:"lookup_count"`            // DNS lookups needed to evaluate, including nested includes
	LookupErrors []string `json:"lookup_errors,omitempty"` // Problems found while following include/redirect
}

// Term is a single parsed SPF mechanism or modifier
type Term struct {
	Qualifier byte   // '+', '-', '~' or '?' for mechanisms, 0 for modifiers
	Name      string // Mechanism or modifier name, lowercased (e.g. "include", "all", "redirect")
	Value     string // Everything after ':' or '=' (domain-spec, IP, ...)
	Modifier  bool   // true for name=value modifiers
}

// ParseTerm parses a single SPF term such as "~all", "include:_spf.google.com" or "redirect=example.com"
func ParseTerm(raw string) Term {
	t := Term{Qualifier: '+'}
	if raw != "" && strings.ContainsRune("+-~?", rune(raw[0])) {
		t.Qualifier = raw[0]
		raw = raw[1:]
	}

	if i := strings.IndexAny(raw, ":=/"); i >= 0 {
		t.Name = strings.ToLower(raw[:i])
		if raw[i] == '=' {
			t.Modifier = true
			t.Qualifier = 0
		}
		if raw[i] != '/' {
			t.Value = raw[i+1:]
		}
	} else {
		t.Name = strings.ToLower(raw)
	}
	return t
}

// Parse parses a raw "v=spf1 ..." TXT value
func Parse(raw string) *SPFRecord {
	fields := strings.Fields(raw)
	record := &SPFRecord{Raw: raw, Terms: []string{}, RecordCount: 1}
	if len(fields) > 0 {
		record.Version = strings.TrimPrefix(strings.ToLower(fields[0]), "v=")
		record.Terms = fields[1:]
	}
	return record
}

// IsSPF reports whether a TXT value is an SPF record
func IsSPF(txt string) bool {
	lower := strings.ToLower(txt)
	return lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ")
}

// findSPF returns the first SPF record among TXT values and how many SPF records there are
func findSPF(txts []string) (*SPFRecord, int) {
	var record *SPFRecord
	count := 0
	for _, txt := range txts {
		if IsSPF(txt) {
			count++
			if record == nil {
				record = Parse(txt)
			}
		}
	}
	return record, count
}

// TXTLookup returns the TXT records for a domain
type TXTLookup func(domain string) ([]string, error)

// LookupSPF looks up and parses the SPF record of a domain and counts the DNS lookups it needs
func LookupSPF(domain string, res *resolver.Resolver) (*SPFRecord, error) {
	txts, err := res.TXT(domain)
	if err != nil {
		return nil, err
	}

	record, count := findSPF(txts)
	if record == nil {
		return nil, &resolver.NotFoundError{What: "SPF", Name: domain}
	}
	record.RecordCount = count
	record.LookupCount, record.LookupErrors = CountLookups(domain, record, res.TXT)
	return record, nil
}

// CountLookups counts the DNS-querying terms (include, a, mx, ptr, exists, redirect) needed to
// evaluate an SPF record, following include and redirect targets recursively (RFC 7208 4.6.4).
// It also returns problems found along the way, such as include loops or unresolvable targets.
func CountLookups(domain string, record *SPFRecord, lookup TXTLookup) (int, []string) {
	c := &lookupCounter{
		lookup: lookup,
		path:   map[string]bool{strings.ToLower(domain): true},
	}
	c.walk(record)
	return c.count, c.problems
}

type lookupCounter struct {
	lookup   TXTLookup
	path     map[string]bool // domains on the current include chain, to detect loops
	count    int
	problems []string
}

// done reports whether the limit is exceeded far enough that resolving further adds nothing
func (c *lookupCounter) done() bool {
	return c.count > 2*MaxDNSLookups
}

func (c *lookupCounter) walk(record *SPFRecord) {
	hasAll := record.AllTerm() != nil
	for _, term := range record.Mechanisms() {
		if c.done() {
			return
		}
		switch term.Name {
		case "a", "mx", "ptr", "exists":
			if !term.Modifier {
				c.count++
			}
		case "include", "redirect":
			// include is a mechanism, redirect a modifier; redirect is ignored when "all" is present
			if (term.Name == "redirect") != term.Modifier || term.Name == "redirect" && hasAll {
				continue
			}
			c.count++
			c.follow(term)
		}
	}
}

func (c *lookupCounter) follow(term Term) {
	target := strings.ToLower(strings.TrimSuffix(term.Value, "."))
	switch {
	case target == "":
		c.problems = append(c.problems, fmt.Sprintf("%s without a domain", term.Name))
		return
	case strings.Contains(target, "%"):
		// Macro targets can only be resolved at evaluation time
		return
	case c.path[target]:
		c.problems = append(c.problems, fmt.Sprintf("%s loop detected at %s", term.Name, target))
		return
	}

	txts, err := c.lookup(target)
	if err != nil {
		c.problems = append(c.problems, fmt.Sprintf("%s:%s could not be resolved: %v", term.Name, target, err))
		return
	}
	nested, n := findSPF(txts)
	if nested == nil {
		c.problems = append(c.problems, fmt.Sprintf("%s:%s has no SPF record", term.Name, target))
		return
	}
	if n > 1 {
		c.problems = append(c.problems, fmt.Sprintf("%s:%s publishes %d SPF records", term.Name, target, n))
	}

	c.path[target] = true
	c.walk(nested)
	delete(c.path, target)
}

// Mechanisms returns the parsed terms of the record
func (r *SPFRecord) Mechanisms() []Term {
	terms := make([]Term, 0, len(r.Terms))
	for _, raw := range r.Terms {
		terms = append(terms, ParseTerm(raw))
	}
	return terms
}

// AllTerm returns the "all" mechanism of the record, or nil if there is none
func (r *SPFRecord) AllTerm() *Term {
	for _, term := range r.Mechanisms() {
		if term.Name == "all" && !term.Modifier {
			return &term
		}
	}
	return nil
}

// Redirect returns the redirect= target of the record, or "" if there is none
func (r *SPFRecord) Redirect() string {
	for _, term := range r.Mechanisms() {
		if term.Name == "redirect" && term.Modifier {
			return term.Value
		}
	}
	return ""
}

// HasInclude checks if the SPF record includes the specified domain
func (r *SPFRecord) HasInclude(domain string) bool {
	for _, term := range r.Mechanisms() {
		if term.Name == "include" && !term.Modifier && strings.EqualFold(term.Value, domain) {
			return true
		}
	}
	return false
}

// HasIP checks if the SPF record includes the specified IP
func (r *SPFRecord) HasIP(ip string) bool {
	for _, term := range r.Mechanisms() {
		if term.Name == "ip4" || term.Name == "ip6" {
			if term.Value == ip || strings.HasPrefix(term.Value, ip+"/") {
				return true
			}
		}
	}
	return false
}
