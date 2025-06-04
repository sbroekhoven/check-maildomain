package rules

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// CheckMXExists verifies that MX records exist for the domain
func CheckMXExists(info *EnhancedDomainInfo) {
	if len(info.MXRecords) == 0 {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      9,
			Description: "MX record existence",
			Status:      "warn",
			Message:     "No MX records found. If this domain is used for email, add MX records to specify mail servers.",
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      9,
			Description: "MX record existence",
			Status:      "pass",
			Message:     fmt.Sprintf("Found %d MX records for this domain.", len(info.MXRecords)),
		})
	}
}

// CheckMXHasIPs verifies that each MX record has at least one IP address
func CheckMXHasIPs(info *EnhancedDomainInfo) {
	if len(info.MXRecords) == 0 {
		// No MX records to check
		return
	}

	badMXHosts := []string{}
	for _, record := range info.MXRecords {
		if len(record.Records) == 0 {
			badMXHosts = append(badMXHosts, record.Host)
		}
	}

	if len(badMXHosts) > 0 {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      10,
			Description: "MX records have IP addresses",
			Status:      "warn",
			Message:     fmt.Sprintf("The following MX hosts could not be resolved to IP addresses: %s", strings.Join(badMXHosts, ", ")),
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      10,
			Description: "MX records have IP addresses",
			Status:      "pass",
			Message:     "All MX records resolve to valid IP addresses.",
		})
	}
}

// CheckMXHasIPv6 verifies that each MX record has at least one IPv6 address
func CheckMXHasIPv6(info *EnhancedDomainInfo) {
	if len(info.MXRecords) == 0 {
		// No MX records to check
		return
	}

	badMXHosts := []string{}
	for _, record := range info.MXRecords {
		hasIPv6 := false
		for _, r := range record.Records {
			// Check if this is an IPv6 address (AAAA record)
			if r.Type == "AAAA" {
				hasIPv6 = true
				break
			}
		}

		if !hasIPv6 {
			badMXHosts = append(badMXHosts, record.Host)
		}
	}

	if len(badMXHosts) > 0 {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      11,
			Description: "MX records have IPv6 addresses",
			Status:      "warn",
			Message:     fmt.Sprintf("The following MX hosts could not be resolved to IPv6 addresses: %s", strings.Join(badMXHosts, ", ")),
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      11,
			Description: "MX records have IPv6 addresses",
			Status:      "pass",
			Message:     "All MX records resolve to IPv6 addresses.",
		})
	}
}

// CheckMXRedundancy verifies that more than one MX record exists for redundancy
func CheckMXRedundancy(info *EnhancedDomainInfo) {
	if len(info.MXRecords) == 0 {
		// No MX records to check
		return
	}

	if len(info.MXRecords) == 1 {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      12,
			Description: "MX record redundancy",
			Status:      "warn",
			Message:     "Only one MX record found. For better email reliability, consider adding at least one backup MX server.",
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      12,
			Description: "MX record redundancy",
			Status:      "pass",
			Message:     fmt.Sprintf("Found %d MX records, which provides redundancy for email delivery.", len(info.MXRecords)),
		})
	}
}

// CheckMXTooMany verifies that there aren't too many MX records which could indicate misconfiguration
func CheckMXTooMany(info *EnhancedDomainInfo) {
	if len(info.MXRecords) == 0 {
		// No MX records to check
		return
	}

	// Define the threshold for too many MX records
	const maxRecommendedMX = 5

	if len(info.MXRecords) > maxRecommendedMX {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      13,
			Description: "MX record count",
			Status:      "warn",
			Message: fmt.Sprintf("Found %d MX records, which is more than the recommended maximum of %d. Too many MX records may indicate a misconfiguration.",
				len(info.MXRecords), maxRecommendedMX),
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      13,
			Description: "MX record count",
			Status:      "pass",
			Message: fmt.Sprintf("Found %d MX records, which is within the recommended range (1-%d).",
				len(info.MXRecords), maxRecommendedMX),
		})
	}
}

// CheckMXLocalhost verifies that MX records don't point to localhost
func CheckMXLocalhost(info *EnhancedDomainInfo) {
	if len(info.MXRecords) == 0 {
		// No MX records to check
		return
	}

	localhostPatterns := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
	}

	var badMXs []string
	for _, mx := range info.MXRecords {
		// Check the host name itself
		target := strings.ToLower(mx.Host)
		isLocalhost := false

		for _, pattern := range localhostPatterns {
			if target == pattern {
				isLocalhost = true
				break
			}
		}

		// Also check resolved IPs
		if !isLocalhost {
			for _, record := range mx.Records {
				if record.Type == "A" || record.Type == "AAAA" {
					for _, pattern := range localhostPatterns {
						if record.Value == pattern {
							isLocalhost = true
							break
						}
					}
				}
				if isLocalhost {
					break
				}
			}
		}

		if isLocalhost {
			badMXs = append(badMXs, mx.Host)
		}
	}

	if len(badMXs) > 0 {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      14,
			Description: "MX localhost check",
			Status:      "fail",
			Message: fmt.Sprintf("Found %d MX records pointing to localhost or loopback addresses: %s. This is a misconfiguration that will prevent email delivery.",
				len(badMXs), strings.Join(badMXs, ", ")),
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      14,
			Description: "MX localhost check",
			Status:      "pass",
			Message:     "No MX records pointing to localhost found.",
		})
	}
}

// CheckMXPrivateIPs verifies that MX records don't resolve to private IP addresses
func CheckMXPrivateIPs(info *EnhancedDomainInfo) {
	if len(info.MXRecords) == 0 {
		// No MX records to check
		return
	}

	// Map to store MX hosts with private IPs
	mxWithPrivateIPs := make(map[string][]string)

	for _, mx := range info.MXRecords {
		// Skip if we couldn't resolve the MX host
		if len(mx.Records) == 0 {
			continue
		}

		// Check each IP address for the MX record
		var privateIPs []string
		for _, record := range mx.Records {
			// Only check A and AAAA records
			if record.Type != "A" && record.Type != "AAAA" {
				continue
			}

			// Parse the IP address
			parsedIP := net.ParseIP(record.Value)
			if parsedIP == nil {
				continue
			}

			// Check if it's a private IP
			if isPrivateIP(parsedIP) {
				privateIPs = append(privateIPs, record.Value)
			}
		}

		// If we found private IPs, add them to our map
		if len(privateIPs) > 0 {
			mxWithPrivateIPs[mx.Host] = privateIPs
		}
	}

	if len(mxWithPrivateIPs) > 0 {
		// Format the message with details about which MX records have private IPs
		var details []string
		for host, ips := range mxWithPrivateIPs {
			details = append(details, fmt.Sprintf("%s resolves to private IPs: %s", host, strings.Join(ips, ", ")))
		}

		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      15,
			Description: "MX private IP check",
			Status:      "fail",
			Message: fmt.Sprintf("Found %d MX records resolving to private IP addresses. %s",
				len(mxWithPrivateIPs), strings.Join(details, "; ")),
		})
	} else {
		info.RuleResults = append(info.RuleResults, RuleResult{
			RuleID:      15,
			Description: "MX private IP check",
			Status:      "pass",
			Message:     "No MX records resolving to private IP addresses found.",
		})
	}
}

// isPrivateIP checks if an IP address is in a private range
func isPrivateIP(ip net.IP) bool {
	// Define private IP ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},                        // 10.0.0.0/8
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},                      // 172.16.0.0/12
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},                    // 192.168.0.0/16
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},                      // 127.0.0.0/8
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")},                    // 169.254.0.0/16
		{net.ParseIP("fc00::"), net.ParseIP("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}, // fc00::/7 (ULA)
		{net.ParseIP("fe80::"), net.ParseIP("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}, // fe80::/10 (link-local)
	}

	// Check if IP is IPv4 or IPv6
	if ip.To4() != nil {
		// IPv4 address
		ip = ip.To4()
	}

	// Check each range
	for _, r := range privateRanges {
		// Skip IPv6 ranges for IPv4 addresses and vice versa
		if (ip.To4() == nil) != (r.start.To4() == nil) {
			continue
		}

		if bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0 {
			return true
		}
	}

	return false
}
