package rules

import (
	"fmt"
	"strings"
)

// CheckDMARCPolicy verifies that DMARC policy is set to reject or quarantine
func CheckDMARCPolicy(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		return
	}

	switch info.DMARCPolicy.Policy {
	case "reject":
		info.add(4, AreaDMARC, "Policy: reject", StatusPass,
			"DMARC policy is set to 'reject', which provides the strongest protection against email spoofing.")
	case "quarantine":
		info.add(4, AreaDMARC, "Policy: quarantine", StatusWarn,
			"DMARC policy is set to 'quarantine'. Consider upgrading to 'reject' for stronger protection once you've verified legitimate emails are passing authentication.")
	case "none":
		info.add(4, AreaDMARC, "Policy: none (monitoring only)", StatusFail,
			"DMARC policy is set to 'none', which only monitors but doesn't protect against spoofing. Consider upgrading to 'quarantine' or ideally 'reject'.")
	default:
		info.add(4, AreaDMARC, "No valid policy", StatusFail,
			"No valid DMARC policy (p tag) was found. Ensure your DMARC record includes a valid p=reject, p=quarantine, or p=none tag.")
	}
}

// CheckDMARCExists verifies that a DMARC record exists for the domain
func CheckDMARCExists(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		info.add(5, AreaDMARC, "No DMARC record", StatusFail,
			"No DMARC record was found for this domain. DMARC is essential for preventing email spoofing. Add a DMARC record with p=reject or at least p=quarantine.")
		return
	}

	description, message := "Record published", "DMARC record exists for this domain."
	if info.DMARCRecord.Location != "_dmarc."+info.Domain {
		description = "Inherited from organizational domain"
		message = fmt.Sprintf("No DMARC record at _dmarc.%s; the organizational domain record at %s applies.", info.Domain, info.DMARCRecord.Location)
	}
	info.add(5, AreaDMARC, description, StatusPass, message)
}

// CheckDMARCValid verifies the DMARC record syntax
func CheckDMARCValid(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		return
	}

	if info.DMARCRecord.Valid {
		info.add(17, AreaDMARC, "Valid syntax", StatusPass, "DMARC record syntax is valid.")
	} else {
		info.add(17, AreaDMARC, "Invalid syntax", StatusFail,
			"DMARC record is invalid: "+strings.Join(info.DMARCRecord.Problems, "; ")+".")
	}
}

// CheckDMARCPercentage warns when the DMARC policy only applies to part of the mail
func CheckDMARCPercentage(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil || info.DMARCPolicy.Policy == "none" {
		return
	}

	if pct := info.DMARCPolicy.Percentage; pct < 100 {
		info.add(18, AreaDMARC, fmt.Sprintf("Applies to %d%% of mail", pct), StatusWarn,
			fmt.Sprintf("DMARC policy only applies to %d%% of failing mail (pct=%d). Raise pct to 100 once you are confident in your setup.", pct, pct))
	} else {
		info.add(18, AreaDMARC, "Applies to 100% of mail", StatusPass, "DMARC policy applies to all failing mail.")
	}
}

// CheckDMARCReporting verifies that aggregate reports are requested
func CheckDMARCReporting(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		return
	}

	if len(info.DMARCPolicy.AggregateReportURI) == 0 {
		info.add(19, AreaDMARC, "No aggregate reports (rua)", StatusWarn,
			"DMARC record has no rua tag, so you receive no aggregate reports about who sends mail as your domain. Add rua=mailto:...")
	} else {
		info.add(19, AreaDMARC, "Aggregate reports enabled", StatusPass,
			"Aggregate reports are sent to: "+strings.Join(info.DMARCPolicy.AggregateReportURI, ", "))
	}
}

// CheckDMARCSubdomainPolicy warns when subdomains are explicitly left unprotected
func CheckDMARCSubdomainPolicy(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil || info.DMARCPolicy.Policy == "none" {
		return
	}

	if info.DMARCPolicy.SubdomainPolicy == "none" {
		info.add(20, AreaDMARC, "Subdomains unprotected (sp=none)", StatusWarn,
			"DMARC subdomain policy is sp=none, so spoofed mail from subdomains is not blocked. Consider sp=quarantine or sp=reject.")
	} else {
		info.add(20, AreaDMARC, "Subdomain policy: "+info.DMARCPolicy.SubdomainPolicy, StatusPass,
			fmt.Sprintf("Subdomains are covered by policy '%s'.", info.DMARCPolicy.SubdomainPolicy))
	}
}
