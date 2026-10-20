package rules

import (
	"fmt"
	"net"
	"strings"

	"github.com/sbroekhoven/check-maildomain/internal/mx"
)

// mailHosts returns the MX records to run host checks on; none for a missing or null MX
func mailHosts(info *EnhancedDomainInfo) []mx.MXRecord {
	if mx.IsNullMX(info.MXRecords) {
		return nil
	}
	return info.MXRecords
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

// CheckMXExists verifies that MX records exist for the domain
func CheckMXExists(info *EnhancedDomainInfo) {
	if info.addIfLookupFailed(9, AreaMX, "mx") {
		return
	}
	switch {
	case mx.IsNullMX(info.MXRecords):
		info.add(9, AreaMX, "Null MX: accepts no mail", StatusInfo,
			"Domain publishes a null MX (RFC 7505): it explicitly accepts no email.")
	case len(info.MXRecords) == 0:
		info.add(9, AreaMX, "No MX records", StatusWarn,
			"No MX records found. If this domain is used for email, add MX records to specify mail servers. If it never receives mail, publish a null MX (\"MX 0 .\").")
	default:
		info.add(9, AreaMX, plural(len(info.MXRecords), "MX record"), StatusPass,
			fmt.Sprintf("Found %d MX records for this domain.", len(info.MXRecords)))
	}
}

// CheckMXHasIPs verifies that each MX record has at least one IP address
func CheckMXHasIPs(info *EnhancedDomainInfo) {
	hosts := mailHosts(info)
	if len(hosts) == 0 {
		return
	}

	badMXHosts := []string{}
	for _, record := range hosts {
		if len(addresses(record)) == 0 {
			badMXHosts = append(badMXHosts, record.Host)
		}
	}

	if len(badMXHosts) > 0 {
		info.add(10, AreaMX, "Hosts without IP addresses", StatusWarn,
			fmt.Sprintf("The following MX hosts could not be resolved to IP addresses: %s", strings.Join(badMXHosts, ", ")))
	} else {
		info.add(10, AreaMX, "All hosts resolve", StatusPass, "All MX records resolve to valid IP addresses.")
	}
}

// CheckMXHasIPv6 verifies that each MX record has at least one IPv6 address
func CheckMXHasIPv6(info *EnhancedDomainInfo) {
	hosts := mailHosts(info)
	if len(hosts) == 0 {
		return
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
		info.add(11, AreaMX, "Hosts without IPv6", StatusWarn,
			fmt.Sprintf("The following MX hosts could not be resolved to IPv6 addresses: %s", strings.Join(badMXHosts, ", ")))
	} else {
		info.add(11, AreaMX, "All hosts have IPv6", StatusPass, "All MX records resolve to IPv6 addresses.")
	}
}

// CheckMXRedundancy verifies that more than one MX record exists for redundancy
func CheckMXRedundancy(info *EnhancedDomainInfo) {
	hosts := mailHosts(info)
	switch len(hosts) {
	case 0:
		return
	case 1:
		info.add(12, AreaMX, "Single MX host, no backup", StatusWarn,
			"Only one MX record found. For better email reliability, consider adding at least one backup MX server.")
	default:
		info.add(12, AreaMX, "Redundant MX hosts", StatusPass,
			fmt.Sprintf("Found %d MX records, which provides redundancy for email delivery.", len(hosts)))
	}
}

// CheckMXTooMany verifies that there aren't too many MX records which could indicate misconfiguration
func CheckMXTooMany(info *EnhancedDomainInfo) {
	hosts := mailHosts(info)
	if len(hosts) == 0 {
		return
	}

	// Define the threshold for too many MX records
	const maxRecommendedMX = 5

	if len(hosts) > maxRecommendedMX {
		info.add(13, AreaMX, "More than 5 MX records", StatusWarn,
			fmt.Sprintf("Found %d MX records, which is more than the recommended maximum of %d. Too many MX records may indicate a misconfiguration.",
				len(hosts), maxRecommendedMX))
	} else {
		info.add(13, AreaMX, "At most 5 MX records", StatusPass,
			fmt.Sprintf("Found %d MX records, which is within the recommended range (1-%d).", len(hosts), maxRecommendedMX))
	}
}

// CheckMXLocalhost verifies that MX records don't point to localhost
func CheckMXLocalhost(info *EnhancedDomainInfo) {
	hosts := mailHosts(info)
	if len(hosts) == 0 {
		return
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
		info.add(14, AreaMX, "Points to localhost", StatusFail,
			fmt.Sprintf("Found %d MX records pointing to localhost or loopback addresses: %s. This is a misconfiguration that will prevent email delivery.",
				len(badMXs), strings.Join(badMXs, ", ")))
	} else {
		info.add(14, AreaMX, "No localhost targets", StatusPass, "No MX records pointing to localhost found.")
	}
}

// CheckMXPrivateIPs verifies that MX records don't resolve to private IP addresses
func CheckMXPrivateIPs(info *EnhancedDomainInfo) {
	hosts := mailHosts(info)
	if len(hosts) == 0 {
		return
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
		info.add(15, AreaMX, "Private IP addresses", StatusFail,
			fmt.Sprintf("Found %d MX records resolving to private IP addresses. %s", len(details), strings.Join(details, "; ")))
	} else {
		info.add(15, AreaMX, "No private IP addresses", StatusPass, "No MX records resolving to private IP addresses found.")
	}
}

// CheckMXCNAME verifies that MX hosts are not aliases (RFC 2181 10.3, RFC 5321 5.1)
func CheckMXCNAME(info *EnhancedDomainInfo) {
	hosts := mailHosts(info)
	if len(hosts) == 0 {
		return
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
		info.add(22, AreaMX, "Hosts are CNAMEs", StatusWarn,
			fmt.Sprintf("MX records must point to a host name with A/AAAA records, not to a CNAME: %s", strings.Join(aliases, ", ")))
	} else {
		info.add(22, AreaMX, "No CNAME targets", StatusPass, "No MX records point to a CNAME.")
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
