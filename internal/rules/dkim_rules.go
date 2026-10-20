package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
)

// checkDKIMExists attempts to verify if DKIM records might exist for the domain
func checkDKIMExists(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, AreaDKIM); o != nil {
		return o
	}
	switch {
	case d.DKIMInfo == nil:
		return inform("Status unknown",
			"DKIM status could not be determined. DKIM uses selectors that vary by email provider. Ensure DKIM is configured with your email service provider.")
	case d.DKIMInfo.HasSelectors:
		return pass("Keys found: "+strings.Join(d.DKIMInfo.Selectors, ", "),
			fmt.Sprintf("DKIM keys found for this domain with selectors: %s", strings.Join(d.DKIMInfo.Selectors, ", ")))
	case d.DKIMInfo.HasDomainKey:
		return warn("No key under common selectors",
			"The _domainkey name exists but no DKIM key was found under the common selectors. Selectors are provider-specific; check yours with -selector.")
	default:
		return fail("No DKIM keys published",
			fmt.Sprintf("_domainkey.%s does not exist (%s), so no DKIM keys are published. DKIM helps prevent email spoofing. Configure DKIM with your email service provider.",
				d.Domain, d.DKIMInfo.ResponseCode))
	}
}
