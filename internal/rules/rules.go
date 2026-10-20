package rules

import (
	"fmt"
	"sort"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
)

// Status is the outcome of a rule check
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

// Area is the part of the mail setup a rule checks
type Area string

const (
	AreaSPF    Area = "SPF"
	AreaDMARC  Area = "DMARC"
	AreaDKIM   Area = "DKIM"
	AreaDNSSEC Area = "DNSSEC"
	AreaMX     Area = "MX"
)

// Areas lists all areas in display order
var Areas = []Area{AreaSPF, AreaDMARC, AreaDKIM, AreaDNSSEC, AreaMX}

// RuleResult represents the outcome of a rule check
type RuleResult struct {
	RuleID      int    `json:"rule_id"`
	Area        Area   `json:"area"`
	Description string `json:"description"`
	Status      Status `json:"status"`
	Message     string `json:"message"`
}

// EnhancedDomainInfo wraps DomainInfo with additional rule check results
type EnhancedDomainInfo struct {
	*collector.DomainInfo
	RuleResults []RuleResult `json:"rule_results,omitempty"`
}

// NewEnhancedDomainInfo creates a new EnhancedDomainInfo from a DomainInfo
func NewEnhancedDomainInfo(info *collector.DomainInfo) *EnhancedDomainInfo {
	return &EnhancedDomainInfo{
		DomainInfo:  info,
		RuleResults: []RuleResult{},
	}
}

// add appends a rule result
func (info *EnhancedDomainInfo) add(id int, area Area, description string, status Status, message string) {
	info.RuleResults = append(info.RuleResults, RuleResult{
		RuleID:      id,
		Area:        area,
		Description: description,
		Status:      status,
		Message:     message,
	})
}

// addIfLookupFailed records an info result and returns true when the lookup for check failed,
// so the rule can't tell whether the record is missing
func (info *EnhancedDomainInfo) addIfLookupFailed(id int, area Area, check string) bool {
	err, failed := info.LookupFailure(check)
	if failed {
		info.add(id, area, "Could not be checked", StatusInfo,
			fmt.Sprintf("The %s lookup failed, so this could not be checked: %s", area, err))
	}
	return failed
}

// HasStatus reports whether any rule ended with the given status
func (info *EnhancedDomainInfo) HasStatus(status Status) bool {
	for _, r := range info.RuleResults {
		if r.Status == status {
			return true
		}
	}
	return false
}

// ApplyAllRules runs all available rules against the domain info; results are ordered by rule ID
func ApplyAllRules(info *EnhancedDomainInfo) {
	// Apply SPF rules
	CheckSPFExists(info)
	CheckSPFMultipleRecords(info)
	CheckSPFPtrUsage(info)
	CheckSPFLookupLimit(info)
	CheckSPFAllMechanism(info)

	// Apply DMARC rules
	CheckDMARCExists(info)
	CheckDMARCValid(info)
	CheckDMARCPolicy(info)
	CheckDMARCPercentage(info)
	CheckDMARCReporting(info)
	CheckDMARCSubdomainPolicy(info)

	// Apply DKIM rules
	CheckDKIMExists(info)

	// Apply DNSSEC rules
	CheckDNSSECEnabled(info)
	CheckDNSSECSignatureExpiry(info)

	// Apply MX rules
	CheckMXExists(info)
	CheckMXHasIPs(info)
	CheckMXHasIPv6(info)
	CheckMXRedundancy(info)
	CheckMXTooMany(info)
	CheckMXLocalhost(info)
	CheckMXPrivateIPs(info)
	CheckMXCNAME(info)

	sort.SliceStable(info.RuleResults, func(i, j int) bool {
		return info.RuleResults[i].RuleID < info.RuleResults[j].RuleID
	})
}
