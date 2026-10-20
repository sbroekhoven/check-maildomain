package rules

import (
	"fmt"
	"net"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/mx"
)

// mailHosts returns the MX records to run host checks on; none for a missing or null MX
func mailHosts(d *collector.DomainInfo) []mx.MXRecord {
	if mx.IsNullMX(d.MXRecords) {
		return nil
	}
	return d.MXRecords
}

// addresses returns the parsed A/AAAA addresses of an MX host
func addresses(record mx.MXRecord) []net.IP {
	var ips []net.IP
	for _, r := range record.Records {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		if ip := net.ParseIP(r.Value); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// checkMXExists verifies that MX records exist for the domain
func checkMXExists(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckMX, "MX"); o != nil {
		return o
	}
	switch {
	case mx.IsNullMX(d.MXRecords):
		return inform("Null MX: accepts no mail",
			"Domain publishes a null MX (RFC 7505): it explicitly accepts no email.")
	case len(d.MXRecords) == 0:
		return warn("No MX records",
			"No MX records found. If this domain is used for email, add MX records to specify mail servers. If it never receives mail, publish a null MX (\"MX 0 .\").")
	default:
		return pass(plural(len(d.MXRecords), "MX record"),
			fmt.Sprintf("Found %d MX records for this domain.", len(d.MXRecords)))
	}
}

// checkMXHasIPs verifies that each MX record has at least one IP address
func checkMXHasIPs(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if len(hosts) == 0 {
		return nil
	}

	badMXHosts := []string{}
	for _, record := range hosts {
		if len(addresses(record)) == 0 {
			badMXHosts = append(badMXHosts, record.Host)
		}
	}

	if len(badMXHosts) > 0 {
		return warn("Hosts without IP addresses",
			fmt.Sprintf("The following MX hosts could not be resolved to IP addresses: %s", strings.Join(badMXHosts, ", ")))
	} else {
		return pass("All hosts resolve", "All MX records resolve to valid IP addresses.")
	}
}

// checkMXHasIPv6 verifies that each MX record has at least one IPv6 address
func checkMXHasIPv6(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if len(hosts) == 0 {
		return nil
	}

	badMXHosts := []string{}
	for _, record := range hosts {
		hasIPv6 := false
		for _, ip := range addresses(record) {
			if ip.To4() == nil {
				hasIPv6 = true
				break
			}
		}
		if !hasIPv6 {
			badMXHosts = append(badMXHosts, record.Host)
		}
	}

	if len(badMXHosts) > 0 {
		return warn("Hosts without IPv6",
			fmt.Sprintf("The following MX hosts could not be resolved to IPv6 addresses: %s", strings.Join(badMXHosts, ", ")))
	} else {
		return pass("All hosts have IPv6", "All MX records resolve to IPv6 addresses.")
	}
}

// checkMXRedundancy verifies that more than one MX record exists for redundancy
func checkMXRedundancy(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	switch len(hosts) {
	case 0:
		return nil
	case 1:
		return warn("Single MX host, no backup",
			"Only one MX record found. For better email reliability, consider adding at least one backup MX server.")
	default:
		return pass("Redundant MX hosts",
			fmt.Sprintf("Found %d MX records, which provides redundancy for email delivery.", len(hosts)))
	}
}

// checkMXTooMany verifies that there aren't too many MX records which could indicate misconfiguration
func checkMXTooMany(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if len(hosts) == 0 {
		return nil
	}

	// Define the threshold for too many MX records
	const maxRecommendedMX = 5

	if len(hosts) > maxRecommendedMX {
		return warn("More than 5 MX records",
			fmt.Sprintf("Found %d MX records, which is more than the recommended maximum of %d. Too many MX records may indicate a misconfiguration.",
				len(hosts), maxRecommendedMX))
	} else {
		return pass("At most 5 MX records",
			fmt.Sprintf("Found %d MX records, which is within the recommended range (1-%d).", len(hosts), maxRecommendedMX))
	}
}

// checkMXLocalhost verifies that MX records don't point to localhost
func checkMXLocalhost(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if len(hosts) == 0 {
		return nil
	}

	var badMXs []string
	for _, record := range hosts {
		isLocalhost := strings.EqualFold(record.Host, "localhost")
		for _, ip := range addresses(record) {
			if ip.IsLoopback() || ip.IsUnspecified() {
				isLocalhost = true
			}
		}
		if isLocalhost {
			badMXs = append(badMXs, record.Host)
		}
	}

	if len(badMXs) > 0 {
		return fail("Points to localhost",
			fmt.Sprintf("Found %d MX records pointing to localhost or loopback addresses: %s. This is a misconfiguration that will prevent email delivery.",
				len(badMXs), strings.Join(badMXs, ", ")))
	} else {
		return pass("No localhost targets", "No MX records pointing to localhost found.")
	}
}

// checkMXPrivateIPs verifies that MX records don't resolve to private IP addresses
func checkMXPrivateIPs(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if len(hosts) == 0 {
		return nil
	}

	var details []string
	for _, record := range hosts {
		var privateIPs []string
		for _, ip := range addresses(record) {
			if isPrivateIP(ip) {
				privateIPs = append(privateIPs, ip.String())
			}
		}
		if len(privateIPs) > 0 {
			details = append(details, fmt.Sprintf("%s resolves to private IPs: %s", record.Host, strings.Join(privateIPs, ", ")))
		}
	}

	if len(details) > 0 {
		return fail("Private IP addresses",
			fmt.Sprintf("Found %d MX records resolving to private IP addresses. %s", len(details), strings.Join(details, "; ")))
	} else {
		return pass("No private IP addresses", "No MX records resolving to private IP addresses found.")
	}
}

// checkMXCNAME verifies that MX hosts are not aliases (RFC 2181 10.3, RFC 5321 5.1)
func checkMXCNAME(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if len(hosts) == 0 {
		return nil
	}

	var aliases []string
	for _, record := range hosts {
		for _, r := range record.Records {
			if r.Type == "CNAME" {
				aliases = append(aliases, fmt.Sprintf("%s -> %s", record.Host, r.Value))
				break
			}
		}
	}

	if len(aliases) > 0 {
		return warn("Hosts are CNAMEs",
			fmt.Sprintf("MX records must point to a host name with A/AAAA records, not to a CNAME: %s", strings.Join(aliases, ", ")))
	} else {
		return pass("No CNAME targets", "No MX records point to a CNAME.")
	}
}

// isPrivateIP checks if an IP address is in a private, loopback or link-local range
func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// plural returns "1 thing" or "n things"
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// checkNoMailDomain verifies that a domain that receives no mail is also protected against being
// spoofed: SPF "v=spf1 -all" and DMARC p=reject (M3AAWG parked domain best practice)
func checkNoMailDomain(d *collector.DomainInfo) *Outcome {
	if _, failed := d.LookupFailure(collector.CheckMX); failed {
		return nil // rule 9 already reports the failed lookup
	}
	nullMX := mx.IsNullMX(d.MXRecords)
	if !nullMX && len(d.MXRecords) > 0 {
		return nil // the domain receives mail
	}

	spfLocked := d.SPFRecord != nil && len(d.SPFRecord.Terms) == 1 && d.SPFRecord.AllTerm() != nil && d.SPFRecord.AllTerm().Qualifier == '-'
	dmarcReject := d.DMARCRecord != nil && d.DMARCPolicy.Policy == "reject"
	receives := "has no MX records"
	if nullMX {
		receives = "publishes a null MX"
	}

	switch {
	case spfLocked && dmarcReject:
		return pass("Locked down against spoofing",
			fmt.Sprintf("The domain %s and publishes SPF \"v=spf1 -all\" and DMARC p=reject, so nobody can send mail as this domain.", receives))
	case d.SPFRecord != nil && !spfLocked:
		return inform("Receives no mail but sends",
			fmt.Sprintf("The domain %s but its SPF record authorizes senders. If it does not send mail either, use \"v=spf1 -all\" and DMARC p=reject.", receives))
	default:
		status := inform
		if nullMX {
			status = warn // a null MX says the domain is not used for mail at all
		}
		var missing []string
		if !spfLocked {
			missing = append(missing, "SPF \"v=spf1 -all\"")
		}
		if !dmarcReject {
			missing = append(missing, "DMARC p=reject")
		}
		return status("Not protected against spoofing",
			fmt.Sprintf("The domain %s. If it does not send mail, publish %s so nobody can send mail as this domain.", receives, strings.Join(missing, " and ")))
	}
}

// checkMXReverseDNS verifies that every MX address has a PTR record that resolves back to it
// (forward-confirmed reverse DNS); many receivers distrust servers without it
func checkMXReverseDNS(d *collector.DomainInfo) *Outcome {
	hosts := mailHosts(d)
	if len(hosts) == 0 {
		return nil
	}

	var missing, unconfirmed, failed []string
	checked := 0
	for _, host := range hosts {
		for _, r := range host.Records {
			if r.Type != "A" && r.Type != "AAAA" {
				continue
			}
			checked++
			switch {
			case r.PTRError != "":
				failed = append(failed, r.Value)
			case r.PTR == "":
				missing = append(missing, fmt.Sprintf("%s (%s)", r.Value, host.Host))
			case !r.PTRConfirmed:
				unconfirmed = append(unconfirmed, fmt.Sprintf("%s -> %s", r.Value, r.PTR))
			}
		}
	}

	switch {
	case checked == 0:
		return nil // rule 10 reports hosts without addresses
	case len(missing) > 0:
		return warn("Addresses without reverse DNS",
			"These MX addresses have no PTR record, which many receivers treat as a spam signal: "+strings.Join(missing, ", ")+". Ask your hosting provider to set one.")
	case len(unconfirmed) > 0:
		return warn("Reverse DNS does not match",
			"The PTR name of these addresses does not resolve back to the same address: "+strings.Join(unconfirmed, ", ")+".")
	case len(failed) > 0:
		return inform("Could not be checked", "The reverse lookup failed for: "+strings.Join(failed, ", ")+".")
	default:
		return pass("Reverse DNS confirmed", fmt.Sprintf("All %s have a PTR record that resolves back to them.", plural(checked, "MX address")))
	}
}
