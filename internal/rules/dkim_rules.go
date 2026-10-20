package rules

import (
	"fmt"
	"strings"
)

// CheckDKIMExists attempts to verify if DKIM records might exist for the domain
func CheckDKIMExists(info *EnhancedDomainInfo) {
	if info.addIfLookupFailed(7, AreaDKIM, "dkim") {
		return
	}
	switch {
	case info.DKIMInfo == nil:
		info.add(7, AreaDKIM, "Status unknown", StatusInfo,
			"DKIM status could not be determined. DKIM uses selectors that vary by email provider. Ensure DKIM is configured with your email service provider.")
	case info.DKIMInfo.HasSelectors:
		info.add(7, AreaDKIM, "Keys found: "+strings.Join(info.DKIMInfo.Selectors, ", "), StatusPass,
			fmt.Sprintf("DKIM keys found for this domain with selectors: %s", strings.Join(info.DKIMInfo.Selectors, ", ")))
	case info.DKIMInfo.HasDomainKey:
		info.add(7, AreaDKIM, "No key under common selectors", StatusWarn,
			"The _domainkey name exists but no DKIM key was found under the common selectors. Selectors are provider-specific; check yours with -selector.")
	default:
		info.add(7, AreaDKIM, "No DKIM keys published", StatusFail,
			fmt.Sprintf("_domainkey.%s does not exist (%s), so no DKIM keys are published. DKIM helps prevent email spoofing. Configure DKIM with your email service provider.",
				info.Domain, info.DKIMInfo.ResponseCode))
	}
}
