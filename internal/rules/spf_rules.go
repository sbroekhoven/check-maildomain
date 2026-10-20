package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/spf"
)

// checkSPFPtrUsage checks if SPF record uses the deprecated ptr mechanism (RFC 7208 5.5)
func checkSPFPtrUsage(d *collector.DomainInfo) *Outcome {
	if d.SPFRecord == nil {
		// No SPF record to check
		return nil
	}

	for _, term := range d.SPFRecord.Mechanisms() {
		if term.Name == "ptr" && !term.Modifier {
			return warn("Uses deprecated ptr mechanism",
				"The ptr mechanism in SPF records is deprecated due to performance issues and should be avoided.")
		}
	}

	return pass("No deprecated ptr mechanism",
		"No ptr mechanism found in SPF record.")
}

// checkSPFLookupLimit checks that evaluating the SPF record needs at most 10 DNS lookups (RFC 7208 4.6.4)
func checkSPFLookupLimit(d *collector.DomainInfo) *Outcome {
	if d.SPFRecord == nil {
		// No SPF record to check
		return nil
	}

	count := d.SPFRecord.LookupCount
	var notes string
	if len(d.SPFRecord.LookupErrors) > 0 {
		notes = " Problems found: " + strings.Join(d.SPFRecord.LookupErrors, "; ") + "."
	}

	if count > spf.MaxDNSLookups {
		return fail(fmt.Sprintf("%d DNS lookups, over the limit of %d", count, spf.MaxDNSLookups),
			fmt.Sprintf("SPF record needs %d DNS lookups (including nested includes), more than the limit of %d. Receivers will return a permerror; reduce includes or flatten the record.%s",
				count, spf.MaxDNSLookups, notes))
	} else if notes != "" {
		return warn(fmt.Sprintf("%d of %d DNS lookups, with problems", count, spf.MaxDNSLookups),
			fmt.Sprintf("SPF record needs %d DNS lookups (limit is %d).%s", count, spf.MaxDNSLookups, notes))
	} else {
		return pass(fmt.Sprintf("%d of %d DNS lookups", count, spf.MaxDNSLookups),
			fmt.Sprintf("SPF record needs %d DNS lookups (limit is %d).", count, spf.MaxDNSLookups))
	}
}

// checkSPFAllMechanism verifies that SPF record ends with -all or ~all, not +all or ?all
func checkSPFAllMechanism(d *collector.DomainInfo) *Outcome {
	if d.SPFRecord == nil {
		// No SPF record to check
		return nil
	}

	all := d.SPFRecord.AllTerm()
	switch {
	case all == nil && d.SPFRecord.Redirect() != "":
		return inform("Delegated via redirect",
			fmt.Sprintf("SPF record has no 'all' mechanism but redirects to %s, whose policy applies.", d.SPFRecord.Redirect()))
	case all == nil:
		return fail("No 'all' mechanism",
			"SPF record doesn't have an 'all' mechanism. Add -all or ~all at the end of your SPF record.")
	case all.Qualifier == '+':
		return fail("Ends with +all",
			"SPF record uses +all which allows any server to send mail for your domain. Use -all or ~all instead.")
	case all.Qualifier == '?':
		return warn("Ends with ?all (neutral)",
			"SPF record uses ?all (neutral), which gives no protection against unauthorized senders. Use -all or ~all instead.")
	default:
		return pass(fmt.Sprintf("Ends with %call", all.Qualifier),
			fmt.Sprintf("SPF record properly uses %call to restrict unauthorized senders.", all.Qualifier))
	}
}

// checkSPFExists verifies that an SPF record exists for the domain
func checkSPFExists(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, AreaSPF); o != nil {
		return o
	}
	if d.SPFRecord == nil {
		return fail("No SPF record",
			"No SPF record was found for this domain. SPF is important for preventing email spoofing. Add an SPF record to specify which servers are authorized to send email for your domain.")
	} else {
		return pass("Record published", "SPF record exists for this domain.")
	}
}

// checkSPFMultipleRecords verifies that only one SPF record is published (RFC 7208 4.5)
func checkSPFMultipleRecords(d *collector.DomainInfo) *Outcome {
	if d.SPFRecord == nil {
		return nil
	}

	if d.SPFRecord.RecordCount > 1 {
		return fail("Multiple SPF records",
			fmt.Sprintf("Found %d SPF records. Publishing more than one v=spf1 record causes a permerror; merge them into a single record.", d.SPFRecord.RecordCount))
	} else {
		return pass("Single record", "Exactly one SPF record is published.")
	}
}
