package rules

import (
	"fmt"
	"strings"
)

// CheckSPFPtrUsage checks if SPF record uses the deprecated ptr: mechanism
func CheckSPFPtrUsage(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		// No SPF record to check
		return
	}

	for _, term := range info.SPFRecord.Terms {
		if strings.HasPrefix(term, "ptr") || term == "ptr" {
			info.RuleResults = append(info.RuleResults, RuleResult{
				RuleID:      1,
				Description: "SPF record uses deprecated ptr: mechanism",
				Status:      "warning",
				Message:     "The ptr: mechanism in SPF records is deprecated due to performance issues and should be avoided",
			})
			return
		}
	}

	// If we got here, the rule passed
	info.RuleResults = append(info.RuleResults, RuleResult{
		RuleID:      1,
		Description: "SPF record doesn't use deprecated ptr: mechanism",
		Status:      "pass",
		Message:     "No ptr: mechanism found in SPF record",
	})
}

// CheckSPFIncludeLimit checks if SPF record has more than 10 include mechanisms
func CheckSPFIncludeLimit(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		// No SPF record to check
		return
	}

	includeCount := 0
	for _, term := range info.SPFRecord.Terms {
		if strings.HasPrefix(term, "include:") {
			includeCount++
		}
	}

	if includeCount > 10 {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      2,
			Description: "SPF record has too many include mechanisms",
			Status:      "fail",
			Message:     "SPF record contains more than 10 include mechanisms. Consider using SPF flattening to reduce lookup complexity.",
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      2,
			Description: "SPF record include count is acceptable",
			Status:      "pass",
			Message:     fmt.Sprintf("SPF record contains %d include mechanisms (limit is 10)", includeCount),
		})
	}
}

// CheckSPFAllMechanism verifies that SPF record ends with -all or ~all, not +all
func CheckSPFAllMechanism(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		// No SPF record to check
		return
	}

	// Check for the "all" mechanism in the SPF record
	hasProperAll := false
	hasPositiveAll := false

	for _, term := range info.SPFRecord.Terms {
		term = strings.TrimSpace(term)
		if term == "-all" || term == "~all" {
			hasProperAll = true
			break
		} else if term == "+all" || term == "all" {
			hasPositiveAll = true
			break
		}
	}

	if hasPositiveAll {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      3,
			Description: "SPF record uses +all",
			Status:      "fail",
			Message:     "SPF record uses +all which allows any server to send mail for your domain. Use -all or ~all instead.",
		})
	} else if hasProperAll {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      3,
			Description: "SPF record uses proper all qualifier",
			Status:      "pass",
			Message:     "SPF record properly uses -all or ~all to restrict unauthorized senders.",
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      3,
			Description: "SPF record missing all mechanism",
			Status:      "fail",
			Message:     "SPF record doesn't have an 'all' mechanism. Add -all or ~all at the end of your SPF record.",
		})
	}
}

// CheckSPFExists verifies that an SPF record exists for the domain
func CheckSPFExists(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		// No SPF record found
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      6,
			Description: "SPF record existence",
			Status:      "fail",
			Message:     "No SPF record was found for this domain. SPF is important for preventing email spoofing. Add an SPF record to specify which servers are authorized to send email for your domain.",
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      6,
			Description: "SPF record existence",
			Status:      "pass",
			Message:     "SPF record exists for this domain.",
		})
	}
}
