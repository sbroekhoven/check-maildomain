package main

import (
	"encoding/json"
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

// Exit codes
const (
	exitOK    = 0
	exitError = 1 // usage or runtime error, an output file could not be written, or a DNS lookup failed
	exitFail  = 2 // at least one rule failed
)

func main() {
	os.Exit(run())
}

func run() int {
	// Define flags
	domainFlag := flag.String("domain", "", "domain to check (can also be given as the first argument)")
	nameserver := flag.String("nameserver", "8.8.8.8", "nameserver to use, optionally with port (e.g. 1.1.1.1, [2606:4700:4700::1111]:53)")
	fallback := flag.String("fallback", "", "fallback nameserver used when the primary one does not respond")
	timeout := flag.Duration("timeout", 3*time.Second, "timeout per DNS query")
	jsonFile := flag.String("json", "", "also write the results as JSON to this file (or into this folder/)")
	htmlFile := flag.String("html", "", "also write an HTML report to this file (or into this folder/)")
	verbose := flag.Bool("v", false, "show details of passing checks too")
	listRules := flag.Bool("rules", false, "list all checks and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	var selectors []string
	flag.Func("selector", "extra DKIM selector to check (repeatable)", func(s string) error {
		selectors = append(selectors, strings.Split(s, ",")...)
		return nil
	})

	// Parse the flags
	flag.Parse()

	if *showVersion {
		fmt.Printf("check-maildomain %s (commit %s, built %s)\n", version, commit, date)
		return exitOK
	}
	if *listRules {
		printRules()
		return exitOK
	}

	rawDomain := *domainFlag
	if rawDomain == "" && flag.NArg() > 0 {
		rawDomain = flag.Arg(0)
	}
	if rawDomain == "" {
		fmt.Fprintln(os.Stderr, "usage: check-maildomain [flags] <domain>")
		flag.PrintDefaults()
		return exitError
	}

	domain, err := normalizeDomain(rawDomain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid domain %q: %v\n", rawDomain, err)
		return exitError
	}

	// Collect all DNS information and apply rules
	res := resolver.New(*nameserver, *fallback, *timeout)
	info := collector.CollectDNSInfo(domain, res, collector.Options{DKIMSelectors: selectors})
	report := rules.Evaluate(info)

	// Output results: always the console, plus the requested files
	output.NewConsole(os.Stdout, *verbose).Print(report, res.Server)

	writeFailed := false
	if *jsonFile != "" {
		err := writeFile(*jsonFile, domain, ".json", "JSON", func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			writeFailed = true
		}
	}
	if *htmlFile != "" {
		err := writeFile(*htmlFile, domain, ".html", "HTML report", func(w io.Writer) error {
			return output.WriteHTML(w, report, res.Server, version)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
			writeFailed = true
		}
	}
	if writeFailed {
		return exitError
	}

	// Incomplete results take precedence: a failed rule may be caused by the failed lookup
	if info.HasFailedLookups() {
		checks := make([]string, 0, len(info.Failed))
		for check := range info.Failed {
			checks = append(checks, string(check))
		}
		sort.Strings(checks)
		fmt.Fprintf(os.Stderr, "Warning: DNS lookups failed for %s; results are incomplete\n", strings.Join(checks, ", "))
		return exitError
	}
	if report.HasStatus(rules.StatusFail) {
		return exitFail
	}
	return exitOK
}

// printRules lists all checks, grouped by area
func printRules() {
	for _, area := range rules.Areas {
		for _, rule := range rules.Rules() {
			if rule.Area == area {
				fmt.Printf("%3d  %-7s %s\n", rule.ID, rule.Area, rule.Name)
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
// in a path separator gets a timestamped file name inside it, e.g. 20261021001500-example.com.json.
func outputPath(target, domain, ext string, now time.Time) string {
	isDir := strings.HasSuffix(target, "/") || strings.HasSuffix(target, string(os.PathSeparator))
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		isDir = true
	}
	if !isDir {
		return target
	}
	return filepath.Join(target, now.Format("20060102150405")+"-"+domain+ext)
}

// writeFile writes an output file for target (see outputPath), creating missing parent folders,
// and reports the saved path on stderr
func writeFile(target, domain, ext, label string, write func(io.Writer) error) error {
	path := outputPath(target, domain, ext, time.Now())
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "%s saved to: %s\n", label, path)
	return nil
}
