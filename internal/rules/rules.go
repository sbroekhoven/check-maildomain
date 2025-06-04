package rules

import (
	"check-maildomain/internal/dns"
)

// RuleResult represents the outcome of a rule check
type RuleResult struct {
	RuleID      int    `json:"rule_id"`
	Description string `json:"description"`
	Status      string `json:"status"` // "warning", "error", "info", "pass"
	Message     string `json:"message"`
}

// EnhancedDomainInfo wraps DomainInfo with additional rule check results
type EnhancedDomainInfo struct {
	*dns.DomainInfo
	RuleResults []RuleResult `json:"rule_results,omitempty"`
}

// NewEnhancedDomainInfo creates a new EnhancedDomainInfo from a DomainInfo
func NewEnhancedDomainInfo(info *dns.DomainInfo) *EnhancedDomainInfo {
	return &EnhancedDomainInfo{
		DomainInfo:  info,
		RuleResults: []RuleResult{},
	}
}

// ApplyAllRules runs all available rules against the domain info
func ApplyAllRules(info *EnhancedDomainInfo) {
	// Apply SPF rules
	CheckSPFPtrUsage(info)
	CheckSPFIncludeLimit(info)
	CheckSPFAllMechanism(info)
	CheckSPFExists(info)

	// Apply DMARC rules
	CheckDMARCPolicy(info)
	CheckDMARCExists(info)

	// Apply DKIM rules
	CheckDKIMExists(info)

	// Apply DNSSEC rules
	CheckDNSSECEnabled(info)

	// Apply MX rules
	CheckMXExists(info)
	CheckMXHasIPs(info)
	CheckMXHasIPv6(info)
	CheckMXRedundancy(info)
	CheckMXTooMany(info)
	CheckMXLocalhost(info)
	CheckMXPrivateIPs(info)

	// etc.
}
