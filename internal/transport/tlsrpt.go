package transport

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// TLSRPT is the SMTP TLS reporting configuration of a domain (RFC 8460)
type TLSRPT struct {
	Record      string   `json:"record"`
	RecordCount int      `json:"record_count"`
	RUA         []string `json:"rua"` // where reports are sent: mailto: or https: URIs
	Problems    []string `json:"problems,omitempty"`
}

// LookupTLSRPT reads the _smtp._tls TXT record of a domain
func LookupTLSRPT(domain string, res *resolver.Resolver) (*TLSRPT, error) {
	name := "_smtp._tls." + domain
	txts, err := res.TXT(name)
	if err != nil {
		return nil, err
	}

	info := &TLSRPT{RUA: []string{}}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=TLSRPTv1") {
			info.RecordCount++
			if info.RecordCount == 1 {
				info.Record = txt
			}
		}
	}
	if info.RecordCount == 0 {
		return nil, &resolver.NotFoundError{What: "TLS-RPT", Name: name}
	}

	info.RUA, info.Problems = ParseTLSRPT(info.Record)
	if info.RecordCount > 1 {
		info.Problems = append(info.Problems, fmt.Sprintf("%d v=TLSRPTv1 records published; there must be exactly one", info.RecordCount))
	}
	return info, nil
}

// ParseTLSRPT returns the report URIs of a "v=TLSRPTv1; rua=..." record and any problems with it
func ParseTLSRPT(record string) ([]string, []string) {
	rua := []string{}
	var problems []string
	for i, part := range strings.Split(record, ";") {
		key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if i == 0 && (key != "v" || value != "TLSRPTv1") {
			problems = append(problems, "the record must start with v=TLSRPTv1")
		}
		if key == "rua" {
			for _, uri := range strings.Split(value, ",") {
				if uri = strings.TrimSpace(uri); uri != "" {
					rua = append(rua, uri)
					if !strings.HasPrefix(uri, "mailto:") && !strings.HasPrefix(uri, "https:") {
						problems = append(problems, fmt.Sprintf("report URI %q must be mailto: or https:", uri))
					}
				}
			}
		}
	}
	if len(rua) == 0 {
		problems = append(problems, "the rua= tag with at least one report address is missing")
	}
	return rua, problems
}
