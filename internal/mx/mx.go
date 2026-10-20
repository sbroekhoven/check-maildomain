package mx

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// Record represents a DNS record with its type and value
type Record struct {
	Type  string `json:"type"`  // "A", "AAAA", or "CNAME"
	Value string `json:"value"` // IP address or CNAME target
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
			} else {
				record.Records = resolveMXHost(record.Host, res)
			}

			records = append(records, record)
		}
	}

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

	return records
}
