package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/spf"
)

// CheckSPFPtrUsage checks if SPF record uses the deprecated ptr mechanism (RFC 7208 5.5)
func CheckSPFPtrUsage(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		// No SPF record to check
		return
	}

	for _, term := range info.SPFRecord.Mechanisms() {
		if term.Name == "ptr" && !term.Modifier {
			info.add(1, AreaSPF, "Uses deprecated ptr mechanism", StatusWarn,
				"The ptr mechanism in SPF records is deprecated due to performance issues and should be avoided.")
			return
		}
	}

	info.add(1, AreaSPF, "No deprecated ptr mechanism", StatusPass,
		"No ptr mechanism found in SPF record.")
}

// CheckSPFLookupLimit checks that evaluating the SPF record needs at most 10 DNS lookups (RFC 7208 4.6.4)
func CheckSPFLookupLimit(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		// No SPF record to check
		return
	}

	count := info.SPFRecord.LookupCount
	var notes string
	if len(info.SPFRecord.LookupErrors) > 0 {
		notes = " Problems found: " + strings.Join(info.SPFRecord.LookupErrors, "; ") + "."
	}

	if count > spf.MaxDNSLookups {
		info.add(2, AreaSPF, fmt.Sprintf("%d DNS lookups, over the limit of %d", count, spf.MaxDNSLookups), StatusFail,
			fmt.Sprintf("SPF record needs %d DNS lookups (including nested includes), more than the limit of %d. Receivers will return a permerror; reduce includes or flatten the record.%s",
				count, spf.MaxDNSLookups, notes))
	} else if notes != "" {
		info.add(2, AreaSPF, fmt.Sprintf("%d of %d DNS lookups, with problems", count, spf.MaxDNSLookups), StatusWarn,
			fmt.Sprintf("SPF record needs %d DNS lookups (limit is %d).%s", count, spf.MaxDNSLookups, notes))
	} else {
		info.add(2, AreaSPF, fmt.Sprintf("%d of %d DNS lookups", count, spf.MaxDNSLookups), StatusPass,
			fmt.Sprintf("SPF record needs %d DNS lookups (limit is %d).", count, spf.MaxDNSLookups))
	}
}

// CheckSPFAllMechanism verifies that SPF record ends with -all or ~all, not +all or ?all
func CheckSPFAllMechanism(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		// No SPF record to check
		return
	}

	all := info.SPFRecord.AllTerm()
	switch {
	case all == nil && info.SPFRecord.Redirect() != "":
		info.add(3, AreaSPF, "Delegated via redirect", StatusInfo,
			fmt.Sprintf("SPF record has no 'all' mechanism but redirects to %s, whose policy applies.", info.SPFRecord.Redirect()))
	case all == nil:
		info.add(3, AreaSPF, "No 'all' mechanism", StatusFail,
			"SPF record doesn't have an 'all' mechanism. Add -all or ~all at the end of your SPF record.")
	case all.Qualifier == '+':
		info.add(3, AreaSPF, "Ends with +all", StatusFail,
			"SPF record uses +all which allows any server to send mail for your domain. Use -all or ~all instead.")
	case all.Qualifier == '?':
		info.add(3, AreaSPF, "Ends with ?all (neutral)", StatusWarn,
			"SPF record uses ?all (neutral), which gives no protection against unauthorized senders. Use -all or ~all instead.")
	default:
		info.add(3, AreaSPF, fmt.Sprintf("Ends with %call", all.Qualifier), StatusPass,
			fmt.Sprintf("SPF record properly uses %call to restrict unauthorized senders.", all.Qualifier))
	}
}

// CheckSPFExists verifies that an SPF record exists for the domain
func CheckSPFExists(info *EnhancedDomainInfo) {
	if info.addIfLookupFailed(6, AreaSPF, "spf") {
		return
	}
	if info.SPFRecord == nil {
		info.add(6, AreaSPF, "No SPF record", StatusFail,
			"No SPF record was found for this domain. SPF is important for preventing email spoofing. Add an SPF record to specify which servers are authorized to send email for your domain.")
	} else {
		info.add(6, AreaSPF, "Record published", StatusPass, "SPF record exists for this domain.")
	}
}

// CheckSPFMultipleRecords verifies that only one SPF record is published (RFC 7208 4.5)
func CheckSPFMultipleRecords(info *EnhancedDomainInfo) {
	if info.SPFRecord == nil {
		return
	}

	if info.SPFRecord.RecordCount > 1 {
		info.add(16, AreaSPF, "Multiple SPF records", StatusFail,
			fmt.Sprintf("Found %d SPF records. Publishing more than one v=spf1 record causes a permerror; merge them into a single record.", info.SPFRecord.RecordCount))
	} else {
		info.add(16, AreaSPF, "Single record", StatusPass, "Exactly one SPF record is published.")
	}
}
