package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// MaxDNSLookups is the RFC 7208 limit on DNS-querying terms during SPF evaluation
const MaxDNSLookups = 10

// MaxVoidLookups is the RFC 7208 limit on lookups that return no records (NXDOMAIN or no answers)
const MaxVoidLookups = 2

// SPFRecord represents an SPF record with its parsed value
type SPFRecord struct {
	Raw          string   `json:"raw"`                     // The complete raw TXT record
	Version      string   `json:"version"`                 // Should be "spf1"
	Terms        []string `json:"terms"`                   // The individual mechanisms and modifiers
	RecordCount  int      `json:"record_count"`            // Number of v=spf1 records published (must be 1)
	LookupCount  int      `json:"lookup_count"`            // DNS lookups needed to evaluate, including nested includes
	VoidLookups  int      `json:"void_lookups"`            // include/redirect targets that returned no records
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
	stats := CountLookups(domain, record, res.TXT)
	record.LookupCount, record.VoidLookups, record.LookupErrors = stats.Lookups, stats.VoidLookups, stats.Problems
	return record, nil
}

// LookupStats is the result of CountLookups
type LookupStats struct {
	Lookups     int      // DNS-querying terms, including those in nested includes
	VoidLookups int      // include/redirect targets that returned no records
	Problems    []string // include loops, unresolvable targets, targets without SPF, ...
}

// CountLookups counts the DNS-querying terms (include, a, mx, ptr, exists, redirect) needed to
// evaluate an SPF record, following include and redirect targets recursively (RFC 7208 4.6.4).
// Void lookups are only counted for include and redirect targets, since those are the only
// terms resolved here; a, mx and exists targets are resolved by receivers at evaluation time.
func CountLookups(domain string, record *SPFRecord, lookup TXTLookup) LookupStats {
	c := &lookupCounter{
		lookup: lookup,
		path:   map[string]bool{strings.ToLower(domain): true},
	}
	c.walk(record)
	return c.LookupStats
}

type lookupCounter struct {
	LookupStats
	lookup TXTLookup
	path   map[string]bool // domains on the current include chain, to detect loops
}

// done reports whether the limit is exceeded far enough that resolving further adds nothing
func (c *lookupCounter) done() bool {
	return c.Lookups > 2*MaxDNSLookups
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
				c.Lookups++
			}
		case "include", "redirect":
			// include is a mechanism, redirect a modifier; redirect is ignored when "all" is present
			if (term.Name == "redirect") != term.Modifier || term.Name == "redirect" && hasAll {
				continue
			}
			c.Lookups++
			c.follow(term)
		}
	}
}

func (c *lookupCounter) follow(term Term) {
	target := strings.ToLower(strings.TrimSuffix(term.Value, "."))
	switch {
	case target == "":
		c.Problems = append(c.Problems, fmt.Sprintf("%s without a domain", term.Name))
		return
	case strings.Contains(target, "%"):
		// Macro targets can only be resolved at evaluation time
		return
	case c.path[target]:
		c.Problems = append(c.Problems, fmt.Sprintf("%s loop detected at %s", term.Name, target))
		return
	}

	txts, err := c.lookup(target)
	if resolver.IsNotFound(err) || err == nil && len(txts) == 0 {
		c.VoidLookups++
		c.Problems = append(c.Problems, fmt.Sprintf("%s:%s does not exist or has no records", term.Name, target))
		return
	}
	if err != nil {
		c.Problems = append(c.Problems, fmt.Sprintf("%s:%s could not be resolved: %v", term.Name, target, err))
		return
	}
	nested, n := findSPF(txts)
	if nested == nil {
		c.Problems = append(c.Problems, fmt.Sprintf("%s:%s has no SPF record", term.Name, target))
		return
	}
	if n > 1 {
		c.Problems = append(c.Problems, fmt.Sprintf("%s:%s publishes %d SPF records", term.Name, target, n))
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

// knownMechanisms are the SPF mechanisms of RFC 7208 5, with whether they need a value
var knownMechanisms = map[string]bool{
	"all": false, "include": true, "a": false, "mx": false, "ptr": false,
	"ip4": true, "ip6": true, "exists": true,
}

// SyntaxErrors returns the problems that make receivers reject the record with a permerror
func (r *SPFRecord) SyntaxErrors() []string {
	var errs []string
	modifiers := map[string]int{}
	for _, raw := range r.Terms {
		term := ParseTerm(raw)
		if term.Modifier {
			if term.Name == "" {
				errs = append(errs, fmt.Sprintf("%q is not a valid term", raw))
			}
			modifiers[term.Name]++
			continue
		}

		needsValue, known := knownMechanisms[term.Name]
		switch {
		case !known:
			errs = append(errs, fmt.Sprintf("unknown mechanism %q", raw))
		case term.Name == "all" && (term.Value != "" || strings.Contains(raw, "/")):
			errs = append(errs, fmt.Sprintf("%q: all takes no arguments", raw))
		case needsValue && term.Value == "":
			errs = append(errs, fmt.Sprintf("%q: %s needs a value", raw, term.Name))
		case term.Name == "ip4" && !validCIDR(term.Value, 32, true):
			errs = append(errs, fmt.Sprintf("%q: not a valid IPv4 address or range", raw))
		case term.Name == "ip6" && !validCIDR(term.Value, 128, false):
			errs = append(errs, fmt.Sprintf("%q: not a valid IPv6 address or range", raw))
		}
	}
	for _, name := range []string{"redirect", "exp"} {
		if modifiers[name] > 1 {
			errs = append(errs, fmt.Sprintf("%s= appears %d times; it may appear only once", name, modifiers[name]))
		}
	}
	return errs
}

// validCIDR reports whether value is an IP address of the right family, optionally with /prefix
func validCIDR(value string, maxBits int, v4 bool) bool {
	addr, prefix, hasPrefix := strings.Cut(value, "/")
	ip := net.ParseIP(addr)
	if ip == nil || (ip.To4() != nil) != v4 {
		return false
	}
	if !hasPrefix {
		return true
	}
	n, err := strconv.Atoi(prefix)
	return err == nil && n >= 0 && n <= maxBits
}

// IPRange is an ip4/ip6 mechanism with its prefix length
type IPRange struct {
	Term   string
	IPv4   bool
	Prefix int
}

// IPRanges returns the valid ip4/ip6 mechanisms that authorize senders (the + qualifier)
func (r *SPFRecord) IPRanges() []IPRange {
	var ranges []IPRange
	for _, raw := range r.Terms {
		term := ParseTerm(raw)
		if term.Modifier || term.Qualifier != '+' || term.Name != "ip4" && term.Name != "ip6" {
			continue
		}
		v4 := term.Name == "ip4"
		maxBits := 128
		if v4 {
			maxBits = 32
		}
		if !validCIDR(term.Value, maxBits, v4) {
			continue
		}
		prefix := maxBits
		if _, p, ok := strings.Cut(term.Value, "/"); ok {
			prefix, _ = strconv.Atoi(p)
		}
		ranges = append(ranges, IPRange{Term: raw, IPv4: v4, Prefix: prefix})
	}
	return ranges
}
