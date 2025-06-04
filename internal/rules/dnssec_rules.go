package rules

// CheckDNSSECEnabled verifies if DNSSEC is enabled for the domain
func CheckDNSSECEnabled(info *EnhancedDomainInfo) {
	if info.DNSSECInfo == nil {
		// No DNSSEC info available
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      8,
			Description: "DNSSEC enabled",
			Status:      "info",
			Message:     "DNSSEC status could not be determined. DNSSEC adds an additional layer of security to DNS lookups.",
		})
		return
	}

	if info.DNSSECInfo.Enabled {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      8,
			Description: "DNSSEC enabled",
			Status:      "pass",
			Message:     "DNSSEC is enabled for this domain, providing additional security for DNS lookups.",
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      8,
			Description: "DNSSEC enabled",
			Status:      "warn",
			Message:     "DNSSEC is not enabled for this domain. Consider enabling DNSSEC to protect against DNS spoofing attacks.",
		})
	}
}
