// Package output renders check results as grouped terminal output or as a self-contained HTML report.
package output

import (
	"fmt"
	"net"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/mx"
	"github.com/sbroekhoven/check-maildomain/internal/rules"
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
		if err, failed := e.LookupFailure(area.Check()); failed {
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
