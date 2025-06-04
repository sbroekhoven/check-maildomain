package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"check-maildomain/internal/dns"
	"check-maildomain/internal/rules"
)

func main() {
	// Define flags
	domain := flag.String("domain", "suspiciousbytes.com", "what domain to use")
	nameserver := flag.String("nameserver", "8.8.8.8", "what nameserver to use")
	jsonOutput := flag.Bool("json", true, "output as JSON")

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
		fmt.Println(string(jsonData))
	}
}
