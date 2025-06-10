package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"check-maildomain/internal/dns"
	"check-maildomain/internal/rules"
)

func main() {
	// Define flags
	domain := flag.String("domain", "suspiciousbytes.com", "what domain to use")
	nameserver := flag.String("nameserver", "8.8.8.8", "what nameserver to use")
	jsonOutput := flag.Bool("json", false, "output as JSON")
	outputFolder := flag.String("output", "", "folder to save JSON output files")

	// Parse the flags
	flag.Parse()

	// Collect all DNS information
	info, err := dns.CollectDNSInfo(*domain, *nameserver)
	if err != nil {
		log.Fatalf("Error collecting DNS info: %v", err)
	}

	// Create enhanced domain info and apply rules
	enhanced := rules.NewEnhancedDomainInfo(info)
	rules.ApplyAllRules(enhanced)

	// Output results
	if *jsonOutput {
		// Output as JSON
		jsonData, err := json.MarshalIndent(enhanced, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling to JSON: %v", err)
		}

		// If output folder is specified, save to file
		if *outputFolder != "" {
			// Create output folder if it doesn't exist
			if err := os.MkdirAll(*outputFolder, 0755); err != nil {
				log.Fatalf("Error creating output folder: %v", err)
			}

			// Generate filename with timestamp and domain
			timestamp := time.Now().Format("20060102150405") // YYYYMMDDHHmmss
			filename := filepath.Join(*outputFolder, fmt.Sprintf("%s-%s.json", timestamp, *domain))

			// Write JSON to file
			if err := os.WriteFile(filename, jsonData, 0644); err != nil {
				log.Fatalf("Error writing JSON to file: %v", err)
			}

			fmt.Printf("Results saved to: %s\n", filename)
		}

		fmt.Println(string(jsonData))
	} else {
		// Output as console friendly
		printEnhancedDomainInfo(enhanced)
	}
}

func printEnhancedDomainInfo(enhanced *rules.EnhancedDomainInfo) {
	fmt.Println("Domain Info:")
	fmt.Printf("Domain: %s\n", enhanced.DomainInfo.Domain)
	fmt.Printf("Checked at: %v\n", enhanced.DomainInfo.QueryTime)

	fmt.Println("\nDNSSEC Info:")
	if enhanced.DomainInfo.DNSSECInfo != nil {
		fmt.Printf("DNSSEC Enabled: %v\n", enhanced.DomainInfo.DNSSECInfo.Enabled)
	} else {
		fmt.Println("DNSSEC Info: Not available")
	}

	fmt.Println("\nMX Records:")
	if len(enhanced.DomainInfo.MXRecords) > 0 {
		for _, mx := range enhanced.DomainInfo.MXRecords {
			fmt.Printf("Host: %s, Priority: %d\n", mx.Host, mx.Priority)
		}
	} else {
		fmt.Println("No MX records found")
	}

	fmt.Println("\nRule Check Results:")
	for _, result := range enhanced.RuleResults {
		icon := getRuleStatusIcon(result.Status)
		fmt.Printf("%s - %s: %s\n", icon, result.Description, result.Message)
	}
}

func getRuleStatusIcon(status string) string {
	switch status {
	case "pass":
		return "✅"
	case "warn":
		return "⚠️"
	case "fail":
		return "❌"
	case "info":
		return "ℹ️"
	default:
		return "❓"
	}
}
