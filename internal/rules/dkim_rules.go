package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/dkim"
)

// checkDKIMExists attempts to verify if DKIM records might exist for the domain
func checkDKIMExists(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckDKIM, "DKIM"); o != nil {
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

// usableKeys returns the published DKIM keys that are not revoked
func usableKeys(d *collector.DomainInfo) []dkim.Key {
	if d.DKIMInfo == nil {
		return nil
	}
	var keys []dkim.Key
	for _, k := range d.DKIMInfo.Keys {
		if !k.Revoked {
			keys = append(keys, k)
		}
	}
	return keys
}

// checkDKIMKeyStrength verifies that DKIM keys are strong enough (RFC 8301: at least 1024 bits, 2048 recommended)
func checkDKIMKeyStrength(d *collector.DomainInfo) *Outcome {
	keys := usableKeys(d)
	if len(keys) == 0 {
		return nil
	}

	var weak, short, broken, details []string
	for _, k := range keys {
		switch {
		case k.Error != "":
			broken = append(broken, fmt.Sprintf("%s (%s)", k.Selector, k.Error))
			continue
		case k.Type == "rsa" && k.Bits < 1024:
			weak = append(weak, fmt.Sprintf("%s (%d bits)", k.Selector, k.Bits))
		case k.Type == "rsa" && k.Bits < 2048:
			short = append(short, fmt.Sprintf("%s (%d bits)", k.Selector, k.Bits))
		}
		details = append(details, fmt.Sprintf("%s: %s %d bits", k.Selector, strings.ToUpper(k.Type), k.Bits))
	}

	switch {
	case len(weak) > 0:
		return fail("Weak DKIM key",
			fmt.Sprintf("RSA keys shorter than 1024 bits can be cracked and are ignored by receivers (RFC 8301): %s. Rotate to a 2048-bit key.", strings.Join(weak, ", ")))
	case len(broken) > 0:
		return warn("Unreadable DKIM key",
			fmt.Sprintf("These keys could not be parsed, so signatures made with them will fail: %s.", strings.Join(broken, ", ")))
	case len(short) > 0:
		return warn("1024-bit DKIM key",
			fmt.Sprintf("1024-bit RSA keys are the minimum and are considered weak today: %s. Rotate to a 2048-bit key.", strings.Join(short, ", ")))
	default:
		return pass("Strong keys", "DKIM keys are strong enough: "+strings.Join(details, "; ")+".")
	}
}

// checkDKIMKeyFlags warns about keys in test mode, revoked keys and SHA-1-only keys
func checkDKIMKeyFlags(d *collector.DomainInfo) *Outcome {
	if d.DKIMInfo == nil || len(d.DKIMInfo.Keys) == 0 {
		return nil
	}

	var testMode, sha1Only, revoked []string
	for _, k := range d.DKIMInfo.Keys {
		if k.Revoked {
			revoked = append(revoked, k.Selector)
			continue
		}
		if k.TestMode {
			testMode = append(testMode, k.Selector)
		}
		if len(k.HashAlgorithms) == 1 && k.HashAlgorithms[0] == "sha1" {
			sha1Only = append(sha1Only, k.Selector)
		}
	}

	switch {
	case len(sha1Only) > 0:
		return warn("SHA-1 only",
			fmt.Sprintf("These keys only allow SHA-1 signatures (h=sha1), which receivers no longer accept (RFC 8301): %s. Remove the h= tag or use h=sha256.", strings.Join(sha1Only, ", ")))
	case len(testMode) > 0:
		return warn("Key in test mode",
			fmt.Sprintf("These keys have t=y, so receivers treat DKIM failures as a test: %s. Remove t=y once DKIM works.", strings.Join(testMode, ", ")))
	case len(revoked) > 0 && len(revoked) == len(d.DKIMInfo.Keys):
		return inform("All keys revoked",
			fmt.Sprintf("All found keys are revoked (empty p=): %s. That is fine if this domain no longer signs mail.", strings.Join(revoked, ", ")))
	case len(revoked) > 0:
		return pass("No problematic flags",
			fmt.Sprintf("No test mode or SHA-1-only keys. Revoked keys (empty p=), which is fine after a key rotation: %s.", strings.Join(revoked, ", ")))
	default:
		return pass("No problematic flags", "No keys in test mode, revoked, or limited to SHA-1.")
	}
}
