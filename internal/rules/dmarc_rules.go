package rules

// CheckDMARCPolicy verifies that DMARC policy is set to reject or quarantine
func CheckDMARCPolicy(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		return
	}

	// The policy is already parsed and available in info.DMARCPolicy
	policyValue := info.DMARCPolicy.Policy

	switch policyValue {
	case "reject":
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      4,
			Description: "DMARC policy set to reject",
			Status:      "pass",
			Message:     "DMARC policy is set to 'reject', which provides the strongest protection against email spoofing.",
		})
	case "quarantine":
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      4,
			Description: "DMARC policy set to quarantine",
			Status:      "warn",
			Message:     "DMARC policy is set to 'quarantine'. Consider upgrading to 'reject' for stronger protection once you've verified legitimate emails are passing authentication.",
		})
	case "none":
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      4,
			Description: "DMARC policy set to none",
			Status:      "fail",
			Message:     "DMARC policy is set to 'none', which only monitors but doesn't protect against spoofing. Consider upgrading to 'quarantine' or ideally 'reject'.",
		})
	default:
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      4,
			Description: "DMARC policy not found or invalid",
			Status:      "fail",
			Message:     "No valid DMARC policy (p tag) was found. Ensure your DMARC record includes a valid p=reject, p=quarantine, or p=none tag.",
		})
	}
}

// CheckDMARCExists verifies that a DMARC record exists for the domain
func CheckDMARCExists(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		// No DMARC record found
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      5,
			Description: "DMARC record existence",
			Status:      "fail",
			Message:     "No DMARC record was found for this domain. DMARC is essential for preventing email spoofing. Add a DMARC record with p=reject or at least p=quarantine.",
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      5,
			Description: "DMARC record existence",
			Status:      "pass",
			Message:     "DMARC record exists for this domain.",
		})
	}
}
