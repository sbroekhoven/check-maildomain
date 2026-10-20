package output

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-maildomain/internal/mx"
	"github.com/sbroekhoven/check-maildomain/internal/rules"
	"github.com/sbroekhoven/check-maildomain/internal/spf"
)

//go:embed templates/report.html.tmpl
var templateFS embed.FS

var reportTemplate = template.Must(template.New("report.html.tmpl").
	Funcs(template.FuncMap{"icon": statusIcon}).
	ParseFS(templateFS, "templates/report.html.tmpl"))

// reportData is the view model of the HTML report
type reportData struct {
	Domain     string
	Checked    string
	Nameserver string
	Version    string
	Worst      rules.Status
	Verdict    string
	Counts     []countChip
	Areas      []reportArea
}

type countChip struct {
	Status rules.Status
	Label  string
}

// reportArea is one card of the report
type reportArea struct {
	Area    rules.Area
	ID      string
	Worst   rules.Status
	Summary string
	Facts   []fact
	Tables  []dataTable
	Error   string
	Results []rules.RuleResult
}

// fact is one label/value pair under "Found"
type fact struct {
	Label string
	Value string
	Mono  bool
}

type dataTable struct {
	Title string
	Head  []string
	Rows  [][]string
}

// WriteHTML renders the results as a self-contained HTML page. version is shown in the footer.
func WriteHTML(w io.Writer, e *rules.Report, nameserver, version string) error {
	return reportTemplate.Execute(w, buildReport(e, nameserver, version))
}

func buildReport(e *rules.Report, nameserver, version string) reportData {
	data := reportData{
		Domain:     e.Domain,
		Checked:    e.QueryTime.Format("2 January 2006, 15:04 MST"),
		Nameserver: displayServer(nameserver),
		Version:    version,
	}

	data.Worst = e.Worst()
	counts := map[rules.Status]int{}
	for _, r := range e.RuleResults {
		counts[r.Status]++
	}
	data.Counts = []countChip{
		{rules.StatusPass, fmt.Sprintf("%d passed", counts[rules.StatusPass])},
		{rules.StatusWarn, plural(counts[rules.StatusWarn], "warning")},
		{rules.StatusFail, fmt.Sprintf("%d failed", counts[rules.StatusFail])},
	}
	if n := counts[rules.StatusInfo]; n > 0 {
		data.Counts = append(data.Counts, countChip{rules.StatusInfo, fmt.Sprintf("%d info", n)})
	}

	switch data.Worst {
	case rules.StatusFail:
		data.Verdict = "Problems found"
	case rules.StatusWarn:
		data.Verdict = "Passed with warnings"
	default:
		data.Verdict = "All checks passed"
	}

	for _, area := range rules.Areas {
		results, worst := areaResults(e.RuleResults, area)
		if len(results) == 0 {
			continue // no check applies, e.g. TLS for a domain that receives no mail
		}
		ra := reportArea{
			Area:    area,
			ID:      strings.ToLower(string(area)),
			Worst:   worst,
			Summary: areaSummary(e, area),
			Results: results,
		}
		addFound(&ra, e)

		// Show failed lookups as a note, unless the summary already shows the error
		if err, failed := areaFailure(e, area); failed && err != ra.Summary {
			ra.Error = err
		}
		data.Areas = append(data.Areas, ra)
	}

	return data
}

// addFound fills in the "Found" section of an area with the collected DNS data
func addFound(ra *reportArea, e *rules.Report) {
	add := func(label, value string, mono bool) {
		ra.Facts = append(ra.Facts, fact{label, value, mono})
	}
	yesNo := func(b bool) string {
		if b {
			return "Yes"
		}
		return "No"
	}

	switch ra.Area {
	case rules.AreaSPF:
		r := e.SPFRecord
		if r == nil {
			return
		}
		ra.Summary = "SPF record published"
		add("Record", r.Raw, true)
		add("DNS lookups", fmt.Sprintf("%d of %d", r.LookupCount, spf.MaxDNSLookups), false)
		add("Void lookups", fmt.Sprintf("%d of %d", r.VoidLookups, spf.MaxVoidLookups), false)
		if r.RecordCount > 1 {
			add("Records published", strconv.Itoa(r.RecordCount), false)
		}
		for _, p := range r.LookupErrors {
			add("Problem", p, false)
		}

	case rules.AreaDMARC:
		r := e.DMARCRecord
		if r == nil {
			return
		}
		add("Record", r.Raw, true)
		add("Found at", r.Location, true)
		tags := dataTable{Head: []string{"Tag", "Value", "Meaning"}}
		for _, tag := range orderedTags(r.Tags) {
			tags.Rows = append(tags.Rows, []string{tag, r.Tags[tag], dmarcTagNames[tag]})
		}
		ra.Tables = append(ra.Tables, tags)
		for _, ext := range r.ExternalReports {
			status := "authorized"
			switch {
			case ext.Domain == "":
				status = ext.Error
			case ext.Unchecked:
				status = "could not be checked"
			case !ext.Authorized:
				status = "not authorized"
			}
			add("External report address", ext.URI+" ("+status+")", false)
		}

	case rules.AreaDKIM:
		d := e.DKIMInfo
		if d == nil {
			return
		}
		selectors := "None found"
		if d.HasSelectors {
			selectors = strings.Join(d.Selectors, ", ")
		}
		add("Selectors", selectors, d.HasSelectors)
		add("_domainkey", d.ResponseCode, true)
		if len(d.Keys) > 0 {
			keys := dataTable{Head: []string{"Selector", "Key", "Flags"}}
			for _, k := range d.Keys {
				key := fmt.Sprintf("%s %d bits", strings.ToUpper(k.Type), k.Bits)
				switch {
				case k.Revoked:
					key = "revoked"
				case k.Error != "":
					key = k.Error
				}
				var flags []string
				if k.TestMode {
					flags = append(flags, "test mode (t=y)")
				}
				if len(k.HashAlgorithms) > 0 {
					flags = append(flags, "h="+strings.Join(k.HashAlgorithms, ":"))
				}
				keys.Rows = append(keys.Rows, []string{k.Selector, key, strings.Join(flags, ", ")})
			}
			ra.Tables = append(ra.Tables, keys)
		}

	case rules.AreaDNSSEC:
		d := e.DNSSECInfo
		if d == nil {
			return
		}
		add("DNSKEY records", fmt.Sprintf("%s (%d)", yesNo(d.HasDNSKEY), d.KeyCount), false)
		add("DS at parent", yesNo(d.HasDS), false)
		if len(d.Algorithm) > 0 {
			add("Algorithms", algorithmNames(d.Algorithm), false)
		}
		if len(d.KeyTags) > 0 {
			tags := make([]string, len(d.KeyTags))
			for i, t := range d.KeyTags {
				tags[i] = strconv.Itoa(int(t))
			}
			add("Key tags", strings.Join(tags, ", "), true)
		}
		if !d.SignatureExpiry.IsZero() {
			add("Signatures valid until", d.SignatureExpiry.UTC().Format("2 January 2006, 15:04 MST"), false)
		}

	case rules.AreaMX:
		if len(e.MXRecords) == 0 || mx.IsNullMX(e.MXRecords) {
			return
		}
		ra.Summary = plural(len(e.MXRecords), "mail server")
		hosts := dataTable{Head: []string{"Priority", "Host", "Records", "Reverse DNS"}}
		for _, r := range e.MXRecords {
			var records, ptrs []string
			for _, rec := range r.Records {
				records = append(records, rec.Type+" "+rec.Value)
				if rec.Type == "A" || rec.Type == "AAAA" {
					ptrs = append(ptrs, describePTR(rec))
				}
			}
			if len(records) == 0 {
				records = []string{"(does not resolve)"}
			}
			hosts.Rows = append(hosts.Rows, []string{strconv.Itoa(int(r.Priority)), r.Host, strings.Join(records, "\n"), strings.Join(ptrs, "\n")})
		}
		ra.Tables = append(ra.Tables, hosts)

	case rules.AreaTLS:
		if m := e.MTASTS; m != nil {
			add("MTA-STS record", m.Record, true)
			add("Policy URL", m.PolicyURL, true)
			if m.PolicyError != "" {
				add("Policy error", m.PolicyError, false)
			}
			if p := m.Policy; p != nil {
				add("Mode", p.Mode, false)
				add("Allowed MX", strings.Join(p.MX, ", "), true)
				add("Max age", fmt.Sprintf("%d seconds", p.MaxAge), false)
			}
		}
		if t := e.TLSRPT; t != nil {
			add("TLS-RPT record", t.Record, true)
		}
		if len(e.DANE) > 0 {
			dane := dataTable{Title: "DANE (TLSA records)", Head: []string{"MX host", "TLSA", "DNSSEC"}}
			for _, h := range e.DANE {
				var tlsa []string
				for _, t := range h.TLSA {
					tlsa = append(tlsa, fmt.Sprintf("%d %d %d %s", t.Usage, t.Selector, t.MatchingType, shorten(t.Data, 16)))
				}
				if len(tlsa) == 0 {
					tlsa = []string{"none"}
				}
				validated := "-"
				if len(h.TLSA) > 0 {
					validated = yesNo(h.Authenticated)
				}
				if h.Error != "" {
					tlsa, validated = []string{h.Error}, "-"
				}
				dane.Rows = append(dane.Rows, []string{h.Host, strings.Join(tlsa, "\n"), validated})
			}
			ra.Tables = append(ra.Tables, dane)
		}

	case rules.AreaBIMI:
		if b := e.BIMI; b != nil {
			add("Record", b.Raw, true)
			add("Found at", b.Location, true)
			if b.Logo != "" {
				add("Logo", b.Logo, true)
			}
			if b.Authority != "" {
				add("Certificate", b.Authority, true)
			}
		}
	}
}

// describePTR summarizes the reverse DNS of an address record
func describePTR(rec mx.Record) string {
	switch {
	case rec.PTRError != "":
		return "lookup failed"
	case rec.PTR == "":
		return "no PTR"
	case rec.PTRConfirmed:
		return rec.PTR + " ✓"
	default:
		return rec.PTR + " (does not resolve back)"
	}
}

// shorten cuts long hex data for display
func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// dmarcTagNames explains the DMARC tags (RFC 7489 6.3)
var dmarcTagNames = map[string]string{
	"v":     "Version",
	"p":     "Policy",
	"sp":    "Subdomain policy",
	"pct":   "Percentage of mail the policy applies to",
	"rua":   "Aggregate report addresses",
	"ruf":   "Failure report addresses",
	"adkim": "DKIM alignment (r = relaxed, s = strict)",
	"aspf":  "SPF alignment (r = relaxed, s = strict)",
	"fo":    "Failure reporting options",
	"rf":    "Failure report format",
	"ri":    "Report interval (seconds)",
}

// orderedTags returns the tags in their usual order, followed by any unknown tags alphabetically
func orderedTags(tags map[string]string) []string {
	known := []string{"v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"}
	var ordered, unknown []string
	for _, t := range known {
		if _, ok := tags[t]; ok {
			ordered = append(ordered, t)
		}
	}
	for t := range tags {
		if _, ok := dmarcTagNames[t]; !ok {
			unknown = append(unknown, t)
		}
	}
	sort.Strings(unknown)
	return append(ordered, unknown...)
}

// algorithmNames returns readable, de-duplicated DNSSEC algorithm names
func algorithmNames(algorithms []int) string {
	seen := map[int]bool{}
	var names []string
	for _, a := range algorithms {
		if seen[a] {
			continue
		}
		seen[a] = true
		name, ok := dns.AlgorithmToString[uint8(a)]
		if !ok {
			name = "unknown"
		}
		names = append(names, fmt.Sprintf("%s (%d)", name, a))
	}
	return strings.Join(names, ", ")
}

// statusIcon returns the symbol shown in a status badge
func statusIcon(status rules.Status) string {
	switch status {
	case rules.StatusPass:
		return "✓"
	case rules.StatusWarn:
		return "!"
	case rules.StatusFail:
		return "✗"
	default:
		return "i"
	}
}
