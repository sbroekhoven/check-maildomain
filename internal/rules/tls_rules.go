package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/transport"
)

// minPolicyAge is the max_age below which an MTA-STS policy protects too briefly (1 day)
const minPolicyAge = 86400

// checkMTASTSRecord verifies the _mta-sts TXT record (RFC 8461 3.1)
func checkMTASTSRecord(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckMTASTS, "MTA-STS"); o != nil {
		return o
	}
	if d.MTASTS == nil {
		if len(mailHosts(d)) == 0 {
			return nil // the domain receives no mail
		}
		return warn("Not configured",
			"MTA-STS is not configured, so other mail servers fall back to unencrypted delivery when TLS fails or is stripped by an attacker. Publish a _mta-sts TXT record and a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt.")
	}

	if len(d.MTASTS.RecordProblems) > 0 {
		return fail("Invalid MTA-STS record",
			"Senders ignore the MTA-STS record because of: "+strings.Join(d.MTASTS.RecordProblems, "; ")+".")
	}
	return pass("Record published", fmt.Sprintf("MTA-STS record found with id %s.", d.MTASTS.ID))
}

// checkMTASTSPolicy verifies that the policy can be fetched, is valid and is enforced
func checkMTASTSPolicy(d *collector.DomainInfo) *Outcome {
	m := d.MTASTS
	if m == nil {
		return nil
	}
	if m.PolicyError != "" {
		return fail("Policy not reachable",
			"The MTA-STS record exists but the policy could not be fetched, so senders ignore MTA-STS: "+m.PolicyError+".")
	}

	p := m.Policy
	if len(p.Problems) > 0 {
		return fail("Invalid policy", "Senders ignore the MTA-STS policy because of: "+strings.Join(p.Problems, "; ")+".")
	}

	var short string
	if p.MaxAge < minPolicyAge {
		short = fmt.Sprintf(" max_age is only %d seconds; use at least a week (604800) so the policy stays cached.", p.MaxAge)
	}
	switch {
	case p.Mode == "none":
		return warn("Policy disabled (mode: none)", "The MTA-STS policy is switched off with mode: none."+short)
	case p.Mode == "testing":
		return warn("Policy in testing mode",
			"With mode: testing, senders only report TLS problems (via TLS-RPT) and still deliver without TLS. Switch to mode: enforce once reports are clean."+short)
	case short != "":
		return warn("Policy cached too briefly", "The MTA-STS policy is enforced, but"+short)
	default:
		return pass("Policy enforced", fmt.Sprintf("The MTA-STS policy is enforced and cached for %s.", time.Duration(p.MaxAge)*time.Second))
	}
}

// checkMTASTSMX verifies that every MX host is allowed by the MTA-STS policy; in enforce mode,
// senders refuse to deliver to MX hosts that don't match
func checkMTASTSMX(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if d.MTASTS == nil || d.MTASTS.Policy == nil || d.MTASTS.Policy.Mode == "none" || len(d.MTASTS.Policy.MX) == 0 || len(hosts) == 0 {
		return nil
	}

	var unmatched []string
	for _, h := range hosts {
		matched := false
		for _, pattern := range d.MTASTS.Policy.MX {
			if transport.MatchesMX(pattern, h.Host) {
				matched = true
				break
			}
		}
		if !matched {
			unmatched = append(unmatched, h.Host)
		}
	}

	if len(unmatched) == 0 {
		return pass("All MX hosts covered", "Every MX host matches an mx: line of the MTA-STS policy.")
	}
	message := fmt.Sprintf("These MX hosts are not listed in the MTA-STS policy (mx: %s): %s.", strings.Join(d.MTASTS.Policy.MX, ", "), strings.Join(unmatched, ", "))
	if d.MTASTS.Policy.Mode == "enforce" {
		return fail("MX hosts missing from policy", message+" Senders that enforce MTA-STS will refuse to deliver to them.")
	}
	return warn("MX hosts missing from policy", message+" This will break delivery once the policy is enforced.")
}

// checkTLSRPT verifies the _smtp._tls TXT record that asks senders for TLS failure reports (RFC 8460)
func checkTLSRPT(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckTLSRPT, "TLS-RPT"); o != nil {
		return o
	}
	if d.TLSRPT == nil {
		if len(mailHosts(d)) == 0 {
			return nil
		}
		usesTLSPolicy := d.MTASTS != nil || daneHosts(d) > 0
		if usesTLSPolicy {
			return warn("Not configured",
				"MTA-STS or DANE is used without TLS-RPT, so you get no reports when senders fail to deliver because of TLS problems. Publish _smtp._tls TXT \"v=TLSRPTv1; rua=mailto:...\".")
		}
		return inform("Not configured", "TLS-RPT lets senders report TLS delivery problems to you. It is most useful together with MTA-STS or DANE.")
	}

	if len(d.TLSRPT.Problems) > 0 {
		return fail("Invalid TLS-RPT record", "Senders ignore the TLS-RPT record because of: "+strings.Join(d.TLSRPT.Problems, "; ")+".")
	}
	return pass("Reports enabled", "TLS reports are sent to: "+strings.Join(d.TLSRPT.RUA, ", "))
}

// daneHosts returns how many MX hosts publish TLSA records
func daneHosts(d *collector.DomainInfo) int {
	n := 0
	for _, h := range d.DANE {
		if len(h.TLSA) > 0 {
			n++
		}
	}
	return n
}

// checkDANE verifies TLSA records for the MX hosts (RFC 7672); they only count when DNSSEC-signed
func checkDANE(d *collector.DomainInfo) *Outcome {
	if len(d.DANE) == 0 {
		return nil
	}

	var without, unsigned, pkix, failed []string
	for _, h := range d.DANE {
		switch {
		case h.Error != "":
			failed = append(failed, fmt.Sprintf("%s (%s)", h.Host, h.Error))
		case len(h.TLSA) == 0:
			without = append(without, h.Host)
		case !h.Authenticated:
			unsigned = append(unsigned, h.Host)
		default:
			for _, t := range h.TLSA {
				if t.Usage < 2 {
					pkix = append(pkix, h.Host)
					break
				}
			}
		}
	}

	with := daneHosts(d)
	switch {
	case with == 0 && len(failed) == 0:
		return inform("Not used",
			"No MX host publishes TLSA records. DANE lets senders verify your mail server's certificate through DNSSEC; it requires DNSSEC on the MX host's zone.")
	case len(unsigned) > 0:
		return fail("TLSA records not DNSSEC-validated",
			"These MX hosts publish TLSA records that the resolver could not validate with DNSSEC, so senders ignore them or, if validation fails, may refuse delivery: "+strings.Join(unsigned, ", ")+".")
	case len(pkix) > 0:
		return warn("PKIX usage in TLSA",
			"These MX hosts use TLSA usage 0 or 1 (PKIX), which SMTP senders treat as unusable (RFC 7672 3.1.3). Use usage 3 (DANE-EE) or 2 (DANE-TA): "+strings.Join(pkix, ", ")+".")
	case len(without) > 0:
		return warn("Not all MX hosts use DANE",
			"These MX hosts publish no TLSA records, so mail to them is not protected by DANE: "+strings.Join(without, ", ")+".")
	case len(failed) > 0:
		return inform("Could not be checked", "The TLSA lookup failed for: "+strings.Join(failed, "; ")+".")
	default:
		return pass("DANE on all MX hosts", fmt.Sprintf("All %s publish DNSSEC-validated TLSA records.", plural(with, "MX host")))
	}
}
