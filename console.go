package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/mx"
	"github.com/sbroekhoven/check-maildomain/internal/rules"
)

const (
	labelWidth = 9               // width of the area column ("DNSSEC   ")
	textIndent = labelWidth + 3  // where text starts, after the status symbol
	minWidth   = textIndent + 40 // narrowest line width we wrap to
	defWidth   = 100             // line width when $COLUMNS is not set
)

// console renders results as grouped, optionally coloured terminal output
type console struct {
	w       io.Writer
	color   bool // emit ANSI colours
	verbose bool // show the message of passing rules too
	width   int  // wrap text at this many columns
}

func newConsole(f *os.File, verbose bool) *console {
	width := defWidth
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		width = max(n, minWidth)
	}
	return &console{w: f, color: useColor(f), verbose: verbose, width: width}
}

// useColor reports whether f is a terminal that should get colours (see https://no-color.org)
func useColor(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ANSI styles
const (
	styleBold   = "1"
	styleDim    = "2"
	styleRed    = "31"
	styleGreen  = "32"
	styleYellow = "33"
	styleBlue   = "34"
)

func (c *console) paint(style, s string) string {
	if !c.color || s == "" {
		return s
	}
	return "\033[" + style + "m" + s + "\033[0m"
}

// symbol returns the single-width, coloured marker for a status
func (c *console) symbol(status rules.Status) string {
	switch status {
	case rules.StatusPass:
		return c.paint(styleGreen, "✓")
	case rules.StatusWarn:
		return c.paint(styleYellow, "!")
	case rules.StatusFail:
		return c.paint(styleRed, "✗")
	default:
		return c.paint(styleBlue, "i")
	}
}

// severity orders statuses from harmless to worst
func severity(status rules.Status) int {
	switch status {
	case rules.StatusPass:
		return 0
	case rules.StatusInfo:
		return 1
	case rules.StatusWarn:
		return 2
	default:
		return 3
	}
}

// print writes the full report: a header, one block per area and a summary line
func (c *console) print(e *rules.EnhancedDomainInfo, nameserver string) {
	fmt.Fprintf(c.w, "%s  %s\n\n",
		c.paint(styleBold, e.Domain),
		c.paint(styleDim, fmt.Sprintf("·  %s  ·  via %s", e.QueryTime.Format("2006-01-02 15:04"), displayServer(nameserver))))

	for _, area := range rules.Areas {
		c.printArea(e, area)
	}

	c.printSummary(e.RuleResults)
}

func (c *console) printArea(e *rules.EnhancedDomainInfo, area rules.Area) {
	var results []rules.RuleResult
	worst := rules.StatusPass
	for _, r := range e.RuleResults {
		if r.Area == area {
			results = append(results, r)
			if severity(r.Status) > severity(worst) {
				worst = r.Status
			}
		}
	}

	label := c.paint(styleBold, fmt.Sprintf("%-*s", labelWidth, area))

	// A single check says it all: show it on the area line itself
	if len(results) == 1 {
		c.line(label, c.symbol(worst), results[0].Description, c.detail(results[0]))
		fmt.Fprintln(c.w)
		return
	}

	c.line(label, c.symbol(worst), areaSummary(e, area), "")
	for _, r := range results {
		c.line(strings.Repeat(" ", labelWidth), c.symbol(r.Status), r.Description, c.detail(r))
	}
	fmt.Fprintln(c.w)
}

// detail returns the message to show under a result: always for problems, for passes only in verbose mode
func (c *console) detail(r rules.RuleResult) string {
	if r.Status != rules.StatusPass || c.verbose {
		return r.Message
	}
	return ""
}

// displayServer drops the default port from a host:port nameserver address
func displayServer(server string) string {
	if host, port, err := net.SplitHostPort(server); err == nil && port == "53" {
		return host
	}
	return server
}

// line prints "<label><symbol>  <text>", with text and the optional detail wrapped under the text column
func (c *console) line(label, symbol, text, detail string) {
	pad := strings.Repeat(" ", textIndent)
	lines := wrap(text, c.width-textIndent)
	fmt.Fprintf(c.w, "%s%s  %s\n", label, symbol, strings.Join(lines, "\n"+pad))
	if detail != "" {
		for _, l := range wrap(detail, c.width-textIndent) {
			fmt.Fprintf(c.w, "%s%s\n", pad, c.paint(styleDim, l))
		}
	}
}

func (c *console) printSummary(results []rules.RuleResult) {
	counts := map[rules.Status]int{}
	for _, r := range results {
		counts[r.Status]++
	}

	parts := []string{
		c.paint(styleGreen, fmt.Sprintf("%d passed", counts[rules.StatusPass])),
		c.paint(styleYellow, plural(counts[rules.StatusWarn], "warning")),
		c.paint(styleRed, fmt.Sprintf("%d failed", counts[rules.StatusFail])),
	}
	if n := counts[rules.StatusInfo]; n > 0 {
		parts = append(parts, c.paint(styleBlue, fmt.Sprintf("%d info", n)))
	}
	fmt.Fprintln(c.w, strings.Join(parts, " · "))
}

// areaSummary is the one-line description of what was found for an area
func areaSummary(e *rules.EnhancedDomainInfo, area rules.Area) string {
	lookupError := func(key, fallback string) string {
		if err, ok := e.Errors[key]; ok {
			return err
		}
		return fallback
	}

	switch area {
	case rules.AreaSPF:
		if e.SPFRecord == nil {
			return lookupError("spf", "No SPF record found")
		}
		return e.SPFRecord.Raw

	case rules.AreaDMARC:
		if e.DMARCRecord == nil {
			return lookupError("dmarc", "No DMARC record found")
		}
		policy := e.DMARCPolicy.Policy
		if policy == "" {
			policy = "(missing)"
		}
		return fmt.Sprintf("p=%s  (%s)", policy, e.DMARCRecord.Location)

	case rules.AreaDKIM:
		switch {
		case e.DKIMInfo == nil:
			return lookupError("dkim", "DKIM status unknown")
		case e.DKIMInfo.HasSelectors:
			return "Selectors: " + strings.Join(e.DKIMInfo.Selectors, ", ")
		default:
			return "No keys found under the checked selectors"
		}

	case rules.AreaDNSSEC:
		switch d := e.DNSSECInfo; {
		case d == nil:
			return lookupError("dnssec", "DNSSEC status unknown")
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
			return lookupError("mx", "No MX records found")
		}
		hosts := make([]string, 0, len(e.MXRecords))
		for _, r := range e.MXRecords {
			hosts = append(hosts, fmt.Sprintf("%s (%d)", r.Host, r.Priority))
		}
		return strings.Join(hosts, ", ")
	}
	return ""
}

// wrap breaks text into lines of at most width runes, splitting on spaces
func wrap(text string, width int) []string {
	var lines []string
	var current strings.Builder
	for _, word := range strings.Fields(text) {
		if current.Len() > 0 && runeLen(current.String())+1+runeLen(word) > width {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(word)
	}
	if current.Len() > 0 || len(lines) == 0 {
		lines = append(lines, current.String())
	}
	return lines
}

func runeLen(s string) int {
	return len([]rune(s))
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
