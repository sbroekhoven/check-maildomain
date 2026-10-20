package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
	"github.com/sbroekhoven/check-maildomain/internal/rules"
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
	exitError = 1 // usage or runtime error, or a DNS lookup failed so the results are incomplete
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
	jsonOutput := flag.Bool("json", false, "output as JSON")
	outputFolder := flag.String("output", "", "folder to save JSON output files (implies -json)")
	htmlFile := flag.String("html", "", "write an HTML report to this file (- for stdout)")
	verbose := flag.Bool("v", false, "show details of passing checks too")
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
	enhanced := rules.NewEnhancedDomainInfo(info)
	rules.ApplyAllRules(enhanced)

	// Output results
	if *htmlFile != "" {
		if err := saveHTML(*htmlFile, enhanced, res.Server); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
			return exitError
		}
	}

	if *htmlFile == "-" {
		// The HTML report already went to stdout
	} else if *jsonOutput || *outputFolder != "" {
		jsonData, err := json.MarshalIndent(enhanced, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling to JSON: %v\n", err)
			return exitError
		}

		// If output folder is specified, save to file
		if *outputFolder != "" {
			filename, err := saveJSON(*outputFolder, domain, jsonData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error saving JSON: %v\n", err)
				return exitError
			}
			fmt.Fprintf(os.Stderr, "Results saved to: %s\n", filename)
		}

		fmt.Println(string(jsonData))
	} else {
		newConsole(os.Stdout, *verbose).print(enhanced, res.Server)
	}

	// Incomplete results take precedence: a failed rule may be caused by the failed lookup
	if info.HasFailedLookups() {
		checks := make([]string, 0, len(info.Failed))
		for check := range info.Failed {
			checks = append(checks, check)
		}
		sort.Strings(checks)
		fmt.Fprintf(os.Stderr, "Warning: DNS lookups failed for %s; results are incomplete\n", strings.Join(checks, ", "))
		return exitError
	}
	if enhanced.HasStatus(rules.StatusFail) {
		return exitFail
	}
	return exitOK
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

// saveHTML writes the HTML report to filename, or to stdout when filename is "-"
func saveHTML(filename string, e *rules.EnhancedDomainInfo, nameserver string) error {
	if filename == "-" {
		return writeHTML(os.Stdout, e, nameserver)
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	if err := writeHTML(f, e, nameserver); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Report saved to: %s\n", filename)
	return nil
}

func saveJSON(folder, domain string, data []byte) (string, error) {
	// Create output folder if it doesn't exist
	if err := os.MkdirAll(folder, 0755); err != nil {
		return "", err
	}

	// Generate filename with timestamp and domain
	timestamp := time.Now().Format("20060102150405") // YYYYMMDDHHmmss
	filename := filepath.Join(folder, fmt.Sprintf("%s-%s.json", timestamp, domain))
	return filename, os.WriteFile(filename, data, 0644)
}
