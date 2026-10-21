// Package output renders check results as grouped terminal output or as a self-contained HTML report.
package output

import (
	"fmt"
	"net"
	"strings"

	"github.com/sbroekhoven/check-maildomain/v2/internal/mx"
	"github.com/sbroekhoven/check-maildomain/v2/internal/rules"
)

// areaResults returns the results of one area and the worst status among them
func areaResults(results []rules.RuleResult, area rules.Area) ([]rules.RuleResult, rules.Status) {
	var matching []rules.RuleResult
	worst := rules.StatusPass
	for _, r := range results {
		if r.Area == area {
			matching = append(matching, r)
			worst = rules.Worst(worst, r.Status)
		}
	}
	return matching, worst
}

// areaFailure returns the first failed lookup error among the lookups of an area
func areaFailure(e *rules.Report, area rules.Area) (string, bool) {
	for _, check := range area.Checks() {
		if err, failed := e.LookupFailure(check); failed {
			return err, true
		}
	}
	return "", false
}

// displayServer drops the default port from a host:port nameserver address
func displayServer(server string) string {
	if host, port, err := net.SplitHostPort(server); err == nil && port == "53" {
		return host
	}
	return server
}

// areaSummary is the one-line description of what was found for an area
func areaSummary(e *rules.Report, area rules.Area) string {
	lookupError := func(fallback string) string {
		if err, failed := areaFailure(e, area); failed {
			return err
		}
		return fallback
	}

	switch area {
	case rules.AreaSPF:
		if e.SPFRecord == nil {
			return lookupError("No SPF record found")
		}
		return e.SPFRecord.Raw

	case rules.AreaDMARC:
		if e.DMARCRecord == nil {
			return lookupError("No DMARC record found")
		}
		policy := e.DMARCPolicy.Policy
		if policy == "" {
			policy = "(missing)"
		}
		return fmt.Sprintf("p=%s  (%s)", policy, e.DMARCRecord.Location)

	case rules.AreaDKIM:
		switch {
		case e.DKIMInfo == nil:
			return lookupError("DKIM status unknown")
		case e.DKIMInfo.HasSelectors:
			return "Selectors: " + strings.Join(e.DKIMInfo.Selectors, ", ")
		default:
			return "No keys found under the checked selectors"
		}

	case rules.AreaDNSSEC:
		switch d := e.DNSSECInfo; {
		case d == nil:
			return lookupError("DNSSEC status unknown")
		case d.HasDNSKEY && d.HasDS:
			return "Signed, DS published at parent"
		case d.HasDNSKEY:
			return "Signed, but no DS at parent"
		case d.HasDS:
			return "DS at parent, but zone is not signed"
		default:
			return "Not signed"
		}

	case rules.AreaMX:
		switch {
		case mx.IsNullMX(e.MXRecords):
			return "Null MX: domain accepts no mail"
		case len(e.MXRecords) == 0:
			return lookupError("No MX records found")
		}
		hosts := make([]string, 0, len(e.MXRecords))
		for _, r := range e.MXRecords {
			hosts = append(hosts, fmt.Sprintf("%s (%d)", r.Host, r.Priority))
		}
		return strings.Join(hosts, ", ")

	case rules.AreaTLS:
		var parts []string
		switch {
		case e.MTASTS != nil && e.MTASTS.Policy != nil:
			parts = append(parts, "MTA-STS "+e.MTASTS.Policy.Mode)
		case e.MTASTS != nil:
			parts = append(parts, "MTA-STS record without policy")
		default:
			parts = append(parts, "no MTA-STS")
		}
		if e.TLSRPT != nil {
			parts = append(parts, "TLS-RPT")
		} else {
			parts = append(parts, "no TLS-RPT")
		}
		dane, failed := 0, 0
		for _, h := range e.DANE {
			switch {
			case h.Error != "":
				failed++
			case len(h.TLSA) > 0:
				dane++
			}
		}
		if len(e.DANE) > 0 {
			summary := fmt.Sprintf("DANE on %d of %d MX hosts", dane, len(e.DANE))
			if failed > 0 {
				summary += fmt.Sprintf(" (lookup failed for %d)", failed)
			}
			parts = append(parts, summary)
		}
		return strings.Join(parts, " · ")

	case rules.AreaBIMI:
		switch {
		case e.BIMI == nil:
			return lookupError("No BIMI record")
		case e.BIMI.Declined:
			return "Logo declined"
		default:
			return e.BIMI.Logo
		}
	}
	return ""
}

// plural returns "1 thing" or "n things"
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
