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
	exitError = 1 // usage or runtime error
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
	if *jsonOutput || *outputFolder != "" {
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
		printEnhancedDomainInfo(enhanced)
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

func printEnhancedDomainInfo(enhanced *rules.EnhancedDomainInfo) {
	info := enhanced.DomainInfo

	fmt.Println("Domain Info:")
	fmt.Printf("Domain: %s\n", info.Domain)
	fmt.Printf("Checked at: %v\n", info.QueryTime.Format(time.RFC3339))

	fmt.Println("\nMX Records:")
	if len(info.MXRecords) > 0 {
		for _, mx := range info.MXRecords {
			fmt.Printf("Host: %s, Priority: %d\n", mx.Host, mx.Priority)
		}
	} else {
		fmt.Println("No MX records found")
	}

	fmt.Println("\nSPF Record:")
	if info.SPFRecord != nil {
		fmt.Println(info.SPFRecord.Raw)
	} else {
		fmt.Println("No SPF record found")
	}

	fmt.Println("\nDMARC Record:")
	if info.DMARCRecord != nil {
		fmt.Printf("%s (at %s)\n", info.DMARCRecord.Raw, info.DMARCRecord.Location)
	} else {
		fmt.Println("No DMARC record found")
	}

	fmt.Println("\nDKIM Selectors:")
	if info.DKIMInfo != nil && info.DKIMInfo.HasSelectors {
		fmt.Println(strings.Join(info.DKIMInfo.Selectors, ", "))
	} else {
		fmt.Println("None found")
	}

	fmt.Println("\nDNSSEC Info:")
	if info.DNSSECInfo != nil {
		fmt.Printf("DNSSEC Enabled: %v\n", info.DNSSECInfo.Enabled)
	} else {
		fmt.Println("DNSSEC Info: Not available")
	}

	if info.HasErrors() {
		fmt.Println("\nLookup Errors:")
		checks := make([]string, 0, len(info.Errors))
		for check := range info.Errors {
			checks = append(checks, check)
		}
		sort.Strings(checks)
		for _, check := range checks {
			fmt.Printf("%s: %s\n", check, info.Errors[check])
		}
	}

	fmt.Println("\nRule Check Results:")
	for _, result := range enhanced.RuleResults {
		icon := getRuleStatusIcon(result.Status)
		fmt.Printf("%s [%d] %s: %s\n", icon, result.RuleID, result.Description, result.Message)
	}
}

func getRuleStatusIcon(status rules.Status) string {
	switch status {
	case rules.StatusPass:
		return "✅"
	case rules.StatusWarn:
		return "⚠️"
	case rules.StatusFail:
		return "❌"
	case rules.StatusInfo:
		return "ℹ️"
	default:
		return "❓"
	}
}
