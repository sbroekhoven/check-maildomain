package rules

import (
	"fmt"
	"strings"
)

// CheckDKIMExists attempts to verify if DKIM records might exist for the domain
func CheckDKIMExists(info *EnhancedDomainInfo) {
	if info.DKIMInfo == nil {
		// No DKIM info available
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      7,
			Description: "DKIM record existence",
			Status:      "info",
			Message:     "DKIM status could not be determined. DKIM uses selectors that vary by email provider. Ensure DKIM is configured with your email service provider.",
		})
		return
	}

	if info.DKIMInfo.HasDomainKey && info.DKIMInfo.ResponseCode == "NOERROR" {
		// _domainkey record exists
		if info.DKIMInfo.HasSelectors {
			// Found actual DKIM selectors
			info.RuleResults = append(info.RuleResults, RuleResult{
				RuleID:      7,
				Description: "DKIM record existence",
				Status:      "pass",
				Message:     fmt.Sprintf("DKIM records found for this domain with selectors: %s", strings.Join(info.DKIMInfo.Selectors, ", ")),
			})
		} else {
			// _domainkey exists but no selectors found
			info.RuleResults = append(info.RuleResults, RuleResult{
				RuleID:      7,
				Description: "DKIM record existence",
				Status:      "warn",
				Message:     "Domain has _domainkey record but no common selectors were found. Ensure DKIM is properly configured with your email provider.",
			})
		}
	} else {
		// No _domainkey record found
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      7,
			Description: "DKIM record existence",
			Status:      "fail",
			Message:     "No DKIM _domainkey record was found. DKIM helps prevent email spoofing. Configure DKIM with your email service provider.",
		})
	}
}
