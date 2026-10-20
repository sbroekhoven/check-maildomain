package rules

import (
	"fmt"
	"time"
)

// signatureExpiryWarning is how long before expiry a DNSKEY signature triggers a warning
const signatureExpiryWarning = 7 * 24 * time.Hour

// CheckDNSSECEnabled verifies if DNSSEC is enabled for the domain
func CheckDNSSECEnabled(info *EnhancedDomainInfo) {
	if info.addIfLookupFailed(8, AreaDNSSEC, "dnssec") {
		return
	}
	d := info.DNSSECInfo
	switch {
	case d == nil:
		info.add(8, AreaDNSSEC, "Status unknown", StatusInfo,
			"DNSSEC status could not be determined. DNSSEC adds an additional layer of security to DNS lookups.")
	case d.HasDNSKEY && d.HasDS:
		info.add(8, AreaDNSSEC, "Signed, DS published at parent", StatusPass,
			"DNSSEC is enabled for this domain (DNSKEY and DS present), providing additional security for DNS lookups.")
	case d.HasDNSKEY:
		info.add(8, AreaDNSSEC, "Signed, but no DS at parent", StatusWarn,
			"The zone is signed (DNSKEY present) but the parent has no DS record, so the chain of trust is incomplete. Publish the DS record at your registrar.")
	case d.HasDS:
		info.add(8, AreaDNSSEC, "DS at parent, but zone not signed", StatusFail,
			"A DS record exists at the parent but the zone publishes no DNSKEY. Validating resolvers will fail to resolve this domain.")
	default:
		info.add(8, AreaDNSSEC, "Not enabled", StatusWarn,
			"DNSSEC is not enabled for this domain. Consider enabling DNSSEC to protect against DNS spoofing attacks.")
	}
}

// CheckDNSSECSignatureExpiry verifies that the DNSKEY signatures are not (nearly) expired
func CheckDNSSECSignatureExpiry(info *EnhancedDomainInfo) {
	if info.DNSSECInfo == nil || !info.DNSSECInfo.HasDNSKEY || info.DNSSECInfo.SignatureExpiry.IsZero() {
		return
	}

	expiry := info.DNSSECInfo.SignatureExpiry
	remaining := expiry.Sub(info.QueryTime)
	switch {
	case remaining <= 0:
		info.add(21, AreaDNSSEC, "Signatures expired", StatusFail,
			fmt.Sprintf("DNSKEY signatures expired at %s. Validating resolvers will fail to resolve this domain.", expiry.UTC().Format(time.RFC3339)))
	case remaining < signatureExpiryWarning:
		info.add(21, AreaDNSSEC, "Signatures expire in "+remaining.Round(time.Hour).String(), StatusWarn,
			fmt.Sprintf("DNSKEY signatures expire at %s (in %s). Check that re-signing works.", expiry.UTC().Format(time.RFC3339), remaining.Round(time.Hour)))
	default:
		info.add(21, AreaDNSSEC, "Signatures valid until "+expiry.UTC().Format("2006-01-02"), StatusPass,
			fmt.Sprintf("DNSKEY signatures are valid until %s.", expiry.UTC().Format(time.RFC3339)))
	}
}
