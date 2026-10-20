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
		info.add(4, "DMARC policy set to reject", StatusPass,
			"DMARC policy is set to 'reject', which provides the strongest protection against email spoofing.")
	case "quarantine":
		info.add(4, "DMARC policy set to quarantine", StatusWarn,
			"DMARC policy is set to 'quarantine'. Consider upgrading to 'reject' for stronger protection once you've verified legitimate emails are passing authentication.")
	case "none":
		info.add(4, "DMARC policy set to none", StatusFail,
			"DMARC policy is set to 'none', which only monitors but doesn't protect against spoofing. Consider upgrading to 'quarantine' or ideally 'reject'.")
	default:
		info.add(4, "DMARC policy not found or invalid", StatusFail,
			"No valid DMARC policy (p tag) was found. Ensure your DMARC record includes a valid p=reject, p=quarantine, or p=none tag.")
	}
}

// CheckDMARCExists verifies that a DMARC record exists for the domain
func CheckDMARCExists(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		info.add(5, "DMARC record existence", StatusFail,
			"No DMARC record was found for this domain. DMARC is essential for preventing email spoofing. Add a DMARC record with p=reject or at least p=quarantine.")
		return
	}

	message := "DMARC record exists for this domain."
	if info.DMARCRecord.Location != "_dmarc."+info.Domain {
		message = fmt.Sprintf("No DMARC record at _dmarc.%s; the organizational domain record at %s applies.", info.Domain, info.DMARCRecord.Location)
	}
	info.add(5, "DMARC record existence", StatusPass, message)
}

// CheckDMARCValid verifies the DMARC record syntax
func CheckDMARCValid(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		return
	}

	if info.DMARCRecord.Valid {
		info.add(17, "DMARC record syntax", StatusPass, "DMARC record syntax is valid.")
	} else {
		info.add(17, "DMARC record syntax", StatusFail,
			"DMARC record is invalid: "+strings.Join(info.DMARCRecord.Problems, "; ")+".")
	}
}

// CheckDMARCPercentage warns when the DMARC policy only applies to part of the mail
func CheckDMARCPercentage(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil || info.DMARCPolicy.Policy == "none" {
		return
	}

	if pct := info.DMARCPolicy.Percentage; pct < 100 {
		info.add(18, "DMARC policy percentage", StatusWarn,
			fmt.Sprintf("DMARC policy only applies to %d%% of failing mail (pct=%d). Raise pct to 100 once you are confident in your setup.", pct, pct))
	} else {
		info.add(18, "DMARC policy percentage", StatusPass, "DMARC policy applies to all failing mail.")
	}
}

// CheckDMARCReporting verifies that aggregate reports are requested
func CheckDMARCReporting(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil {
		return
	}

	if len(info.DMARCPolicy.AggregateReportURI) == 0 {
		info.add(19, "DMARC aggregate reporting", StatusWarn,
			"DMARC record has no rua tag, so you receive no aggregate reports about who sends mail as your domain. Add rua=mailto:...")
	} else {
		info.add(19, "DMARC aggregate reporting", StatusPass,
			"Aggregate reports are sent to: "+strings.Join(info.DMARCPolicy.AggregateReportURI, ", "))
	}
}

// CheckDMARCSubdomainPolicy warns when subdomains are explicitly left unprotected
func CheckDMARCSubdomainPolicy(info *EnhancedDomainInfo) {
	if info.DMARCRecord == nil || info.DMARCPolicy.Policy == "none" {
		return
	}

	if info.DMARCPolicy.SubdomainPolicy == "none" {
		info.add(20, "DMARC subdomain policy", StatusWarn,
			"DMARC subdomain policy is sp=none, so spoofed mail from subdomains is not blocked. Consider sp=quarantine or sp=reject.")
	} else {
		info.add(20, "DMARC subdomain policy", StatusPass,
			fmt.Sprintf("Subdomains are covered by policy '%s'.", info.DMARCPolicy.SubdomainPolicy))
	}
}
