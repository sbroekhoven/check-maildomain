package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sbroekhoven/check-maildomain/v2/internal/collector"
	"github.com/sbroekhoven/check-maildomain/v2/internal/output"
	"github.com/sbroekhoven/check-maildomain/v2/internal/resolver"
	"github.com/sbroekhoven/check-maildomain/v2/internal/rules"
	"golang.org/x/net/idna"
)

// Set by goreleaser through -ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// toolName is shown in the version string and the -cron log line
const toolName = "check-maildomain"

// Exit codes
const (
	exitOK    = 0
	exitError = 1 // usage or runtime error, an output file could not be written, or a DNS lookup failed
	exitFail  = 2 // at least one rule failed
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	start := time.Now()

	// Define flags
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	domainFlag := fs.String("domain", "", "domain to check (can also be given as the first argument)")
	nameserver := fs.String("nameserver", "8.8.8.8", "nameserver to use, optionally with port (e.g. 1.1.1.1, [2606:4700:4700::1111]:53)")
	fallback := fs.String("fallback", "", "fallback nameserver used when the primary one does not respond")
	timeout := fs.Duration("timeout", 3*time.Second, "timeout per DNS query")
	jsonFile := fs.String("json", "", "also write the results as JSON to this file (or into this folder/)")
	htmlFile := fs.String("html", "", "also write an HTML report to this file (or into this folder/)")
	cron := fs.Bool("cron", false, "print only one JSON log line for the run, for cron jobs; needs -json or -html to store the results")
	verbose := fs.Bool("v", false, "show details of passing checks too")
	listRules := fs.Bool("rules", false, "list all checks and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	var selectors []string
	fs.Func("selector", "extra DKIM selector to check (repeatable)", func(s string) error {
		selectors = append(selectors, strings.Split(s, ",")...)
		return nil
	})

	// Parse the flags; a malformed command line exits 1, so 2 keeps meaning "a check failed"
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}

	if *showVersion {
		fmt.Fprintf(stdout, "%s %s (commit %s, built %s)\n", toolName, version, commit, date)
		return exitOK
	}
	if *listRules {
		printRules(stdout)
		return exitOK
	}

	// With -cron, all messages go into one log line instead of to the terminal
	var entry *cronEntry
	if *cron {
		entry = newCronEntry(start)
	}
	finish := func(exit int) int {
		if entry != nil {
			entry.write(stdout, exit)
		}
		return exit
	}
	problem := func(count int, format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if entry != nil {
			entry.addError(msg, count)
			return
		}
		fmt.Fprintln(stderr, strings.ToUpper(msg[:1])+msg[1:])
	}

	rawDomain := *domainFlag
	if rawDomain == "" && fs.NArg() > 0 {
		rawDomain = fs.Arg(0)
	}
	if entry != nil {
		entry.Domain = rawDomain
	}
	if rawDomain == "" {
		if entry != nil {
			problem(0, "no domain given")
			return finish(exitError)
		}
		fmt.Fprintf(stderr, "usage: %s [flags] <domain>\n", toolName)
		fs.PrintDefaults()
		return exitError
	}

	domain, err := normalizeDomain(rawDomain)
	if err != nil {
		problem(0, "invalid domain %q: %v", rawDomain, err)
		return finish(exitError)
	}
	if entry != nil {
		entry.Domain = domain
		if *jsonFile == "" && *htmlFile == "" {
			problem(0, "-cron needs -json or -html to store the results")
			return finish(exitError)
		}
	}

	// Collect all DNS information and apply rules
	res := resolver.New(*nameserver, *fallback, *timeout)
	info := collector.CollectDNSInfo(domain, res, collector.Options{DKIMSelectors: selectors})
	report := rules.Evaluate(info)

	// Output results: the console (or the log line with -cron), plus the requested files
	if entry != nil {
		entry.addCounts(report)
	} else {
		output.NewConsole(stdout, *verbose).Print(report, res.Server)
	}

	incomplete := false
	save := func(label, target, ext string, write func(io.Writer) error) string {
		path, err := writeFile(target, domain, ext, write)
		if err != nil {
			problem(1, "writing %s: %v", label, err)
			incomplete = true
			return ""
		}
		if entry == nil {
			fmt.Fprintf(stderr, "%s saved to: %s\n", label, path)
		}
		return path
	}
	var jsonPath, htmlPath string
	if *jsonFile != "" {
		jsonPath = save("JSON", *jsonFile, ".json", func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		})
	}
	if *htmlFile != "" {
		htmlPath = save("HTML report", *htmlFile, ".html", func(w io.Writer) error {
			return output.WriteHTML(w, report, res.Server, version)
		})
	}
	if entry != nil {
		entry.JSON, entry.HTML = jsonPath, htmlPath
	}

	// Incomplete results take precedence: a failed rule may be caused by the failed lookup
	if info.HasFailedLookups() {
		checks := make([]string, 0, len(info.Failed))
		for check := range info.Failed {
			checks = append(checks, string(check))
		}
		sort.Strings(checks)
		problem(len(checks), "lookups failed for %s; results are incomplete", strings.Join(checks, ", "))
		incomplete = true
	}
	switch {
	case incomplete:
		return finish(exitError)
	case report.HasStatus(rules.StatusFail):
		return finish(exitFail)
	default:
		return finish(exitOK)
	}
}

// printRules lists all checks, grouped by area
func printRules(w io.Writer) {
	for _, area := range rules.Areas {
		for _, rule := range rules.Rules() {
			if rule.Area == area {
				fmt.Fprintf(w, "%3d  %-7s %s\n", rule.ID, rule.Area, rule.Name)
			}
		}
	}
}

// normalizeDomain lowercases the domain, strips a trailing dot and converts IDNs to punycode
func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", err
	}
	if !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("not a fully qualified domain name")
	}
	return ascii, nil
}

// outputPath returns the file to write for target. A target that is an existing directory or ends
// in a path separator gets a timestamped file name inside it, e.g.
// 20261021001500-example.com-check-maildomain.json; the tool name keeps check-domain and check-maildomain
// results apart when both write to the same folder.
func outputPath(target, domain, ext string, now time.Time) string {
	isDir := strings.HasSuffix(target, "/") || strings.HasSuffix(target, string(os.PathSeparator))
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		isDir = true
	}
	if !isDir {
		return target
	}
	return filepath.Join(target, now.Format("20060102150405")+"-"+domain+"-"+toolName+ext)
}

// writeFile writes an output file for target (see outputPath), creating missing parent folders,
// and returns the path it was saved to
func writeFile(target, domain, ext string, write func(io.Writer) error) (string, error) {
	path := outputPath(target, domain, ext, time.Now())
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	if err := write(f); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return path, nil
}
