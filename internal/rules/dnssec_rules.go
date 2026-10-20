package rules

import (
	"fmt"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
)

// signatureExpiryWarning is how long before expiry a DNSKEY signature triggers a warning
const signatureExpiryWarning = 7 * 24 * time.Hour

// checkDNSSECEnabled verifies if DNSSEC is enabled for the domain
func checkDNSSECEnabled(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckDNSSEC, "DNSSEC"); o != nil {
		return o
	}
	sec := d.DNSSECInfo
	switch {
	case sec == nil:
		return inform("Status unknown",
			"DNSSEC status could not be determined. DNSSEC adds an additional layer of security to DNS lookups.")
	case sec.HasDNSKEY && sec.HasDS:
		return pass("Signed, DS published at parent",
			"DNSSEC is enabled for this domain (DNSKEY and DS present), providing additional security for DNS lookups.")
	case sec.HasDNSKEY:
		return warn("Signed, but no DS at parent",
			"The zone is signed (DNSKEY present) but the parent has no DS record, so the chain of trust is incomplete. Publish the DS record at your registrar.")
	case sec.HasDS:
		return fail("DS at parent, but zone not signed",
			"A DS record exists at the parent but the zone publishes no DNSKEY. Validating resolvers will fail to resolve this domain.")
	default:
		return warn("Not enabled",
			"DNSSEC is not enabled for this domain. Consider enabling DNSSEC to protect against DNS spoofing attacks.")
	}
}

// checkDNSSECSignatureExpiry verifies that the DNSKEY signatures are not (nearly) expired
func checkDNSSECSignatureExpiry(d *collector.DomainInfo) *Outcome {
	if d.DNSSECInfo == nil || !d.DNSSECInfo.HasDNSKEY || d.DNSSECInfo.SignatureExpiry.IsZero() {
		return nil
	}

	expiry := d.DNSSECInfo.SignatureExpiry
	remaining := expiry.Sub(d.QueryTime)
	switch {
	case remaining <= 0:
		return fail("Signatures expired",
			fmt.Sprintf("DNSKEY signatures expired at %s. Validating resolvers will fail to resolve this domain.", expiry.UTC().Format(time.RFC3339)))
	case remaining < signatureExpiryWarning:
		return warn("Signatures expire in "+remaining.Round(time.Hour).String(),
			fmt.Sprintf("DNSKEY signatures expire at %s (in %s). Check that re-signing works.", expiry.UTC().Format(time.RFC3339), remaining.Round(time.Hour)))
	default:
		return pass("Signatures valid until "+expiry.UTC().Format("2006-01-02"),
			fmt.Sprintf("DNSKEY signatures are valid until %s.", expiry.UTC().Format(time.RFC3339)))
	}
}
