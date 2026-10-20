# Email Domain Security Checker

A command-line tool that analyzes email domain configurations for security and deliverability best practices.

## Overview

This tool checks a domain's DNS records related to email security, including:

- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)
- DMARC (Domain-based Message Authentication, Reporting & Conformance)
- DNSSEC (Domain Name System Security Extensions)
- MX (Mail Exchange) records

It evaluates these configurations against a set of rules and reports each finding as pass, warn, fail or info.

## Features

- Analyzes SPF syntax, the `all` qualifier, and the RFC 7208 limit of 10 DNS lookups (following nested includes)
- Checks DMARC syntax, policy strength, `pct`, reporting and subdomain policy, with organizational-domain fallback
- Detects DKIM keys under common selectors and selectors you supply
- Validates the DNSSEC chain (DNSKEY + DS) and signature expiry
- Examines MX records for redundancy, null MX, CNAME targets, IPv6, and private or loopback addresses
- Console or JSON output; exit code reflects failures, so it can run in CI

## Installation

```bash
go install github.com/sbroekhoven/check-maildomain@latest
```

Or download a binary from the [releases page](https://github.com/sbroekhoven/check-maildomain/releases), or build from source:

```bash
git clone https://github.com/sbroekhoven/check-maildomain.git
cd check-maildomain
go build -o check-maildomain
```

## Usage

```bash
# Check a domain
check-maildomain example.com

# Use a specific nameserver (IPv4, IPv6, optional port)
check-maildomain -nameserver 1.1.1.1 example.com
check-maildomain -nameserver "[2606:4700:4700::1111]:53" example.com

# Also check your own DKIM selectors
check-maildomain -selector s2024 -selector mailjet example.com

# JSON output, optionally also saved to a folder
check-maildomain -json example.com | jq .
check-maildomain -output results example.com
```

## Example Output

```
google.com  ·  2026-10-21 00:13  ·  via 8.8.8.8

SPF      ✓  v=spf1 include:_spf.google.com ~all
         ✓  No deprecated ptr mechanism
         ✓  1 of 10 DNS lookups
         ✓  Ends with ~all
         ✓  Record published
         ✓  Single record

DKIM     !  No key under common selectors
            The _domainkey name exists but no DKIM key was found under the common selectors.
            Selectors are provider-specific; check yours with -selector.

MX       !  smtp.google.com (10)
         ✓  1 MX record
         !  Single MX host, no backup
            Only one MX record found. For better email reliability, consider adding at least one
            backup MX server.
         ...

18 passed · 3 warnings · 0 failed
```

Results are grouped per area: `✓` pass, `!` warning, `✗` fail, `i` info. Details are shown for anything that is not a pass (use `-v` to see them all). Colours are used when writing to a terminal and are turned off when the output is piped or `NO_COLOR` is set. Long lines wrap to `$COLUMNS` (default 100).

## HTML Report

```bash
check-maildomain -html report.html example.com
```

Writes a single, self-contained HTML file (inline CSS, no external assets) that you can email, attach to a ticket or archive. It shows an overall verdict, then one card per area with the records that were found (SPF record and lookup count, DMARC tags, DKIM selectors, DNSSEC keys, an MX table with addresses) and all checks. Problems are expanded; passing checks can be clicked open. The report follows the system light/dark theme, works on phones, and prints cleanly. The console output is still printed, unless you use `-html -` to write the report to stdout.

## Command-line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-domain` | | Domain to check (alternatively the first argument) |
| `-nameserver` | `8.8.8.8` | Nameserver for lookups, optionally with port |
| `-fallback` | | Nameserver to use when the primary does not respond |
| `-timeout` | `3s` | Timeout per DNS query |
| `-selector` | | Extra DKIM selector to check (repeatable, or comma-separated) |
| `-v` | `false` | Also show the details of passing checks |
| `-json` | `false` | Output results as JSON |
| `-html` | | Write an HTML report to this file (`-` for stdout) |
| `-output` | | Folder to save JSON results to (implies `-json`) |
| `-version` | | Print version and exit |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No rule failed |
| 1 | Usage or runtime error, or a DNS lookup failed so the results are incomplete |
| 2 | At least one rule failed |

When a lookup fails (for example a timeout), the affected checks are reported as "Could not be checked" (info) instead of as a missing record, the failed lookups are listed in `failed_lookups` in the JSON output, and a warning is printed to stderr. A record that simply does not exist is not a failed lookup and is reported by the normal checks.

## Rule Checks

| ID | Area | Check |
|----|------|-------|
| 1 | SPF | No deprecated `ptr` mechanism |
| 2 | SPF | At most 10 DNS lookups, including nested includes and redirects |
| 3 | SPF | Ends with `-all` or `~all` (not `+all` / `?all`) |
| 4 | DMARC | Policy strength (reject / quarantine / none) |
| 5 | DMARC | Record exists (own or organizational domain) |
| 6 | SPF | Record exists |
| 7 | DKIM | Keys found under common or supplied selectors |
| 8 | DNSSEC | Zone signed and DS published at parent |
| 9 | MX | Records exist (null MX reported as info) |
| 10 | MX | Hosts resolve to IP addresses |
| 11 | MX | Hosts have IPv6 addresses |
| 12 | MX | More than one MX for redundancy |
| 13 | MX | Not more than 5 MX records |
| 14 | MX | No localhost / loopback targets |
| 15 | MX | No private or link-local addresses |
| 16 | SPF | Only one SPF record published |
| 17 | DMARC | Record syntax is valid |
| 18 | DMARC | Policy applies to 100% of mail (`pct`) |
| 19 | DMARC | Aggregate reporting (`rua`) configured |
| 20 | DMARC | Subdomain policy is not `none` |
| 21 | DNSSEC | DNSKEY signatures not (nearly) expired |
| 22 | MX | MX hosts are not CNAMEs |

## Development

```bash
go vet ./...
go test ./...
```

## License

MIT, see [LICENSE](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
