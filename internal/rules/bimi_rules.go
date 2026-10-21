package rules

import (
	"strings"

	"github.com/sbroekhoven/check-maildomain/v2/internal/collector"
)

// checkBIMIRecord verifies the default._bimi TXT record that points to the brand logo
func checkBIMIRecord(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckBIMI, "BIMI"); o != nil {
		return o
	}
	b := d.BIMI
	switch {
	case b == nil:
		return inform("Not configured", "BIMI shows your logo next to your mail in supporting mail clients. It requires DMARC enforcement.")
	case b.Declined:
		return inform("Logo explicitly declined", "The BIMI record has empty l= and a= tags, which says the domain publishes no logo.")
	case len(b.Problems) > 0:
		return fail("Invalid BIMI record", "Mail clients ignore the BIMI record because of: "+strings.Join(b.Problems, "; ")+".")
	case b.Authority == "":
		return warn("No certificate (a=)",
			"The logo is published without a Verified Mark Certificate. Gmail and Apple Mail only show BIMI logos with a VMC or CMC; Yahoo shows it without one.")
	default:
		return pass("Logo and certificate published", "BIMI logo: "+b.Logo+"; certificate: "+b.Authority)
	}
}

// checkBIMIDMARC verifies the DMARC requirements for BIMI: an enforced policy on all mail
func checkBIMIDMARC(d *collector.DomainInfo) *Outcome {
	if d.BIMI == nil || d.BIMI.Declined {
		return nil
	}

	var missing []string
	p := d.DMARCPolicy
	switch {
	case d.DMARCRecord == nil:
		missing = append(missing, "a DMARC record")
	case p.Policy != "quarantine" && p.Policy != "reject":
		missing = append(missing, "DMARC p=quarantine or p=reject (now p="+p.Policy+")")
	}
	if d.DMARCRecord != nil && p.Percentage < 100 {
		missing = append(missing, "DMARC pct=100")
	}
	if d.DMARCRecord != nil && p.SubdomainPolicy == "none" {
		missing = append(missing, "a subdomain policy other than sp=none")
	}

	if len(missing) > 0 {
		return fail("DMARC not strict enough for BIMI", "Mail clients will not show the logo. BIMI requires "+strings.Join(missing, ", ")+".")
	}
	return pass("DMARC meets BIMI requirements", "DMARC is enforced on all mail, as BIMI requires.")
}
