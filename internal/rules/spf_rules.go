package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/v2/internal/collector"
	"github.com/sbroekhoven/check-maildomain/v2/internal/spf"
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
	if o := unchecked(d, collector.CheckSPF, "SPF"); o != nil {
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

// checkSPFSyntax verifies that the record only uses valid mechanisms and modifiers (RFC 7208 4.6)
func checkSPFSyntax(d *collector.DomainInfo) *Outcome {
	if d.SPFRecord == nil {
		return nil
	}

	if errs := d.SPFRecord.SyntaxErrors(); len(errs) > 0 {
		return fail("Syntax errors",
			"Receivers reject the whole SPF record (permerror) because of: "+strings.Join(errs, "; ")+".")
	}
	return pass("Valid syntax", "All SPF mechanisms and modifiers are valid.")
}

// checkSPFVoidLookups verifies that at most 2 lookups return no records (RFC 7208 4.6.4)
func checkSPFVoidLookups(d *collector.DomainInfo) *Outcome {
	if d.SPFRecord == nil {
		return nil
	}

	n := d.SPFRecord.VoidLookups
	switch {
	case n > spf.MaxVoidLookups:
		return fail(fmt.Sprintf("%d void lookups, over the limit of %d", n, spf.MaxVoidLookups),
			fmt.Sprintf("%d include/redirect targets do not exist or have no records. More than %d makes receivers reject the SPF record (permerror). Remove the stale includes.", n, spf.MaxVoidLookups))
	case n > 0:
		return warn(plural(n, "void lookup"),
			fmt.Sprintf("%s does not exist or has no records (limit is %d). This usually is a stale include; remove it.", plural(n, "include/redirect target"), spf.MaxVoidLookups))
	default:
		return pass("No void lookups", "All include/redirect targets exist.")
	}
}

// checkSPFIPRanges warns about ip4/ip6 ranges so large they authorize a big part of the internet
func checkSPFIPRanges(d *collector.DomainInfo) *Outcome {
	if d.SPFRecord == nil {
		return nil
	}

	var huge, large []string
	for _, r := range d.SPFRecord.IPRanges() {
		switch {
		case r.IPv4 && r.Prefix < 8, !r.IPv4 && r.Prefix < 16:
			huge = append(huge, r.Term)
		case r.IPv4 && r.Prefix < 16, !r.IPv4 && r.Prefix < 32:
			large = append(large, r.Term)
		}
	}

	switch {
	case len(huge) > 0:
		return fail("Extremely broad IP ranges",
			fmt.Sprintf("These ranges authorize a large part of the internet to send as your domain, which is almost as bad as +all: %s. List only the servers that actually send your mail.", strings.Join(huge, ", ")))
	case len(large) > 0:
		return warn("Broad IP ranges",
			fmt.Sprintf("These ranges authorize tens of thousands of addresses or more: %s. Check that you really own and send from all of them.", strings.Join(large, ", ")))
	default:
		return pass("No overly broad IP ranges", "All ip4/ip6 ranges are narrow enough.")
	}
}
