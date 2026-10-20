package mx

import (
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// Record represents a DNS record with its type and value
type Record struct {
	Type  string `json:"type"`  // "A", "AAAA", or "CNAME"
	Value string `json:"value"` // IP address or CNAME target

	// Reverse DNS, for A and AAAA records only
	PTR          string `json:"ptr,omitempty"`           // host name the address points back to
	PTRConfirmed bool   `json:"ptr_confirmed,omitempty"` // the PTR name resolves back to this address (FCrDNS)
	PTRError     string `json:"ptr_error,omitempty"`     // the reverse lookup failed (not: no PTR record)
}

// MXRecord represents an MX record with its priority
type MXRecord struct {
	Host     string   `json:"host"`
	Priority uint16   `json:"priority"`
	Records  []Record `json:"records"`
}

// NullMXHost is the host of a null MX record (RFC 7505)
const NullMXHost = "."

// IsNullMX reports whether the records are a null MX ("MX 0 ."), meaning the domain accepts no mail
func IsNullMX(records []MXRecord) bool {
	return len(records) == 1 && records[0].Host == NullMXHost
}

// LookupMX looks up MX records for the specified domain and resolves each MX host
//
// MX records are sorted by priority (lowest first), then by host name
func LookupMX(domain string, res *resolver.Resolver) ([]MXRecord, error) {
	r, err := res.Query(domain, dns.TypeMX, false)
	if err != nil {
		return nil, err
	}

	var records []MXRecord
	for _, a := range r.Answer {
		if mx, ok := a.(*dns.MX); ok {
			record := MXRecord{
				Host:     strings.TrimSuffix(mx.Mx, "."),
				Priority: mx.Preference,
				Records:  []Record{},
			}
			if mx.Mx == "." {
				record.Host = NullMXHost
			}
			records = append(records, record)
		}
	}

	// Resolve all MX hosts concurrently
	var wg sync.WaitGroup
	for i := range records {
		if records[i].Host == NullMXHost {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			records[i].Records = resolveMXHost(records[i].Host, res)
		}()
	}
	wg.Wait()

	sort.Slice(records, func(i, j int) bool {
		if records[i].Priority != records[j].Priority {
			return records[i].Priority < records[j].Priority
		}
		return records[i].Host < records[j].Host
	})

	return records, nil
}

// resolveMXHost resolves the CNAME, A and AAAA records of an MX host
func resolveMXHost(host string, res *resolver.Resolver) []Record {
	var records []Record
	seenCNAME := map[string]bool{}

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r, err := res.Query(host, qtype, false)
		if err != nil {
			continue
		}

		// A recursive answer contains the CNAME chain followed by the addresses
		for _, a := range r.Answer {
			switch rr := a.(type) {
			case *dns.CNAME:
				target := strings.TrimSuffix(rr.Target, ".")
				if !seenCNAME[target] {
					seenCNAME[target] = true
					records = append(records, Record{Type: "CNAME", Value: target})
				}
			case *dns.A:
				records = append(records, Record{Type: "A", Value: rr.A.String()})
			case *dns.AAAA:
				records = append(records, Record{Type: "AAAA", Value: rr.AAAA.String()})
			}
		}
	}

	for i := range records {
		if records[i].Type == "A" || records[i].Type == "AAAA" {
			reverseLookup(&records[i], res)
		}
	}
	return records
}

// reverseLookup fills in the PTR of an address record and checks that the PTR name resolves back
// to the same address (forward-confirmed reverse DNS)
func reverseLookup(record *Record, res *resolver.Resolver) {
	ip := net.ParseIP(record.Value)
	arpa, err := dns.ReverseAddr(record.Value)
	if ip == nil || err != nil {
		return
	}

	r, err := res.Query(arpa, dns.TypePTR, false)
	if err != nil {
		if !resolver.IsNotFound(err) {
			record.PTRError = err.Error()
		}
		return
	}
	for _, a := range r.Answer {
		if ptr, ok := a.(*dns.PTR); ok {
			record.PTR = strings.TrimSuffix(ptr.Ptr, ".")
			break
		}
	}
	if record.PTR == "" {
		return
	}

	qtype := dns.TypeAAAA
	if record.Type == "A" {
		qtype = dns.TypeA
	}
	fwd, err := res.Query(record.PTR, qtype, false)
	if err != nil {
		return
	}
	for _, a := range fwd.Answer {
		switch rr := a.(type) {
		case *dns.A:
			record.PTRConfirmed = record.PTRConfirmed || rr.A.Equal(ip)
		case *dns.AAAA:
			record.PTRConfirmed = record.PTRConfirmed || rr.AAAA.Equal(ip)
		}
	}
}
