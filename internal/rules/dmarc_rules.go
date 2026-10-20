package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
)

// checkDMARCPolicy verifies that DMARC policy is set to reject or quarantine
func checkDMARCPolicy(d *collector.DomainInfo) *Outcome {
	if d.DMARCRecord == nil {
		return nil
	}

	switch d.DMARCPolicy.Policy {
	case "reject":
		return pass("Policy: reject",
			"DMARC policy is set to 'reject', which provides the strongest protection against email spoofing.")
	case "quarantine":
		return warn("Policy: quarantine",
			"DMARC policy is set to 'quarantine'. Consider upgrading to 'reject' for stronger protection once you've verified legitimate emails are passing authentication.")
	case "none":
		return fail("Policy: none (monitoring only)",
			"DMARC policy is set to 'none', which only monitors but doesn't protect against spoofing. Consider upgrading to 'quarantine' or ideally 'reject'.")
	default:
		return fail("No valid policy",
			"No valid DMARC policy (p tag) was found. Ensure your DMARC record includes a valid p=reject, p=quarantine, or p=none tag.")
	}
}

// checkDMARCExists verifies that a DMARC record exists for the domain
func checkDMARCExists(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckDMARC, "DMARC"); o != nil {
		return o
	}
	if d.DMARCRecord == nil {
		return fail("No DMARC record",
			"No DMARC record was found for this domain. DMARC is essential for preventing email spoofing. Add a DMARC record with p=reject or at least p=quarantine.")
	}

	description, message := "Record published", "DMARC record exists for this domain."
	if d.DMARCRecord.Location != "_dmarc."+d.Domain {
		description = "Inherited from organizational domain"
		message = fmt.Sprintf("No DMARC record at _dmarc.%s; the organizational domain record at %s applies.", d.Domain, d.DMARCRecord.Location)
	}
	return pass(description, message)
}

// checkDMARCValid verifies the DMARC record syntax
func checkDMARCValid(d *collector.DomainInfo) *Outcome {
	if d.DMARCRecord == nil {
		return nil
	}

	if d.DMARCRecord.Valid {
		return pass("Valid syntax", "DMARC record syntax is valid.")
	} else {
		return fail("Invalid syntax",
			"DMARC record is invalid: "+strings.Join(d.DMARCRecord.Problems, "; ")+".")
	}
}

// checkDMARCPercentage warns when the DMARC policy only applies to part of the mail
func checkDMARCPercentage(d *collector.DomainInfo) *Outcome {
	if d.DMARCRecord == nil || d.DMARCPolicy.Policy == "none" {
		return nil
	}

	if pct := d.DMARCPolicy.Percentage; pct < 100 {
		return warn(fmt.Sprintf("Applies to %d%% of mail", pct),
			fmt.Sprintf("DMARC policy only applies to %d%% of failing mail (pct=%d). Raise pct to 100 once you are confident in your setup.", pct, pct))
	} else {
		return pass("Applies to 100% of mail", "DMARC policy applies to all failing mail.")
	}
}

// checkDMARCReporting verifies that aggregate reports are requested
func checkDMARCReporting(d *collector.DomainInfo) *Outcome {
	if d.DMARCRecord == nil {
		return nil
	}

	if len(d.DMARCPolicy.AggregateReportURI) == 0 {
		return warn("No aggregate reports (rua)",
			"DMARC record has no rua tag, so you receive no aggregate reports about who sends mail as your domain. Add rua=mailto:...")
	} else {
		return pass("Aggregate reports enabled",
			"Aggregate reports are sent to: "+strings.Join(d.DMARCPolicy.AggregateReportURI, ", "))
	}
}

// checkDMARCSubdomainPolicy warns when subdomains are explicitly left unprotected
func checkDMARCSubdomainPolicy(d *collector.DomainInfo) *Outcome {
	if d.DMARCRecord == nil || d.DMARCPolicy.Policy == "none" {
		return nil
	}

	if d.DMARCPolicy.SubdomainPolicy == "none" {
		return warn("Subdomains unprotected (sp=none)",
			"DMARC subdomain policy is sp=none, so spoofed mail from subdomains is not blocked. Consider sp=quarantine or sp=reject.")
	} else {
		return pass("Subdomain policy: "+d.DMARCPolicy.SubdomainPolicy,
			fmt.Sprintf("Subdomains are covered by policy '%s'.", d.DMARCPolicy.SubdomainPolicy))
	}
}

// checkDMARCReportAuthorization verifies that report addresses in other domains accepted the
// reports (RFC 7489 7.1); without that, receivers don't send them
func checkDMARCReportAuthorization(d *collector.DomainInfo) *Outcome {
	if d.DMARCRecord == nil || len(d.DMARCPolicy.AggregateReportURI)+len(d.DMARCPolicy.ForensicReportURI) == 0 {
		return nil
	}

	var unauthorized, unsupported, unchecked []string
	for _, r := range d.DMARCRecord.ExternalReports {
		switch {
		case r.Domain == "":
			unsupported = append(unsupported, r.URI)
		case r.Unchecked:
			unchecked = append(unchecked, r.URI)
		case !r.Authorized:
			unauthorized = append(unauthorized, fmt.Sprintf("%s (needs %s._report._dmarc.%s)", r.URI, strings.TrimPrefix(d.DMARCRecord.Location, "_dmarc."), r.Domain))
		}
	}

	switch {
	case len(unauthorized) > 0:
		return warn("Report address not authorized",
			"These report addresses are in another domain that has not agreed to receive your reports, so receivers will not send them: "+strings.Join(unauthorized, "; ")+". Ask the report provider to publish the record, or check the address.")
	case len(unsupported) > 0:
		return warn("Unsupported report address",
			"Receivers only send reports to mailto: addresses: "+strings.Join(unsupported, ", ")+".")
	case len(unchecked) > 0:
		return inform("Could not be checked",
			"The authorization of these report addresses could not be looked up: "+strings.Join(unchecked, ", ")+".")
	case len(d.DMARCRecord.ExternalReports) > 0:
		return pass("External report addresses authorized", "Report addresses in other domains have published their authorization.")
	default:
		return pass("Report addresses in own domain", "All report addresses are in your own organizational domain.")
	}
}
