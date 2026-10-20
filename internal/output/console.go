package output

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/rules"
)

const (
	labelWidth = 9               // width of the area column ("DNSSEC   ")
	textIndent = labelWidth + 3  // where text starts, after the status symbol
	minWidth   = textIndent + 40 // narrowest line width we wrap to
	defWidth   = 100             // line width when $COLUMNS is not set
)

// Console renders results as grouped, optionally coloured terminal output
type Console struct {
	w       io.Writer
	color   bool // emit ANSI colours
	verbose bool // show the message of passing rules too
	width   int  // wrap text at this many columns
}

// NewConsole creates a Console writing to f. Colours are used only when f is a terminal.
// verbose also shows the explanation of passing checks.
func NewConsole(f *os.File, verbose bool) *Console {
	width := defWidth
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		width = max(n, minWidth)
	}
	return &Console{w: f, color: useColor(f), verbose: verbose, width: width}
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

func (c *Console) paint(style, s string) string {
	if !c.color || s == "" {
		return s
	}
	return "\033[" + style + "m" + s + "\033[0m"
}

// symbol returns the single-width, coloured marker for a status
func (c *Console) symbol(status rules.Status) string {
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

// Print writes the full report: a header, one block per area and a summary line
func (c *Console) Print(e *rules.Report, nameserver string) {
	fmt.Fprintf(c.w, "%s  %s\n\n",
		c.paint(styleBold, e.Domain),
		c.paint(styleDim, fmt.Sprintf("·  %s  ·  via %s", e.QueryTime.Format("2006-01-02 15:04"), displayServer(nameserver))))

	for _, area := range rules.Areas {
		c.printArea(e, area)
	}

	c.printSummary(e.RuleResults)
}

func (c *Console) printArea(e *rules.Report, area rules.Area) {
	results, worst := areaResults(e.RuleResults, area)

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
func (c *Console) detail(r rules.RuleResult) string {
	if r.Status != rules.StatusPass || c.verbose {
		return r.Message
	}
	return ""
}

// line prints "<label><symbol>  <text>", with text and the optional detail wrapped under the text column
func (c *Console) line(label, symbol, text, detail string) {
	pad := strings.Repeat(" ", textIndent)
	lines := wrap(text, c.width-textIndent)
	fmt.Fprintf(c.w, "%s%s  %s\n", label, symbol, strings.Join(lines, "\n"+pad))
	if detail != "" {
		for _, l := range wrap(detail, c.width-textIndent) {
			fmt.Fprintf(c.w, "%s%s\n", pad, c.paint(styleDim, l))
		}
	}
}

func (c *Console) printSummary(results []rules.RuleResult) {
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
