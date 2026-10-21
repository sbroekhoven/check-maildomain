# Email Domain Security Checker

A command-line tool that analyzes email domain configurations for security and deliverability best practices. For the domain's general DNS setup (delegation, nameservers, SOA, DNSSEC, registration), see its sibling [check-domain](https://github.com/sbroekhoven/check-domain).

## Overview

This tool checks a domain's DNS records related to email security, including:

- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)
- DMARC (Domain-based Message Authentication, Reporting & Conformance)
- DNSSEC (Domain Name System Security Extensions)
- MX (Mail Exchange) records and their reverse DNS
- Transport security: MTA-STS, TLS-RPT and DANE
- BIMI (Brand Indicators for Message Identification)

It evaluates these configurations against a set of rules and reports each finding as pass, warn, fail or info.

## Features

- Analyzes SPF syntax, the `all` qualifier, overly broad IP ranges, and the RFC 7208 limits of 10 DNS lookups and 2 void lookups (following nested includes)
- Checks DMARC syntax, policy strength, `pct`, reporting, subdomain policy and authorization of external report addresses, with organizational-domain fallback
- Detects DKIM keys under common selectors and selectors you supply, and checks key size, test mode and SHA-1-only keys
- Validates the DNSSEC chain (DNSKEY + DS) and signature expiry
- Examines MX records for redundancy, null MX, CNAME targets, IPv6, private or loopback addresses and forward-confirmed reverse DNS
- Checks that a domain that receives no mail is locked down against spoofing (SPF `-all` + DMARC `p=reject`)
- Fetches and validates the MTA-STS policy and checks that it covers all MX hosts; checks TLS-RPT and DANE (TLSA) records
- Checks the BIMI record and the DMARC enforcement BIMI requires
- Console output, plus optional JSON and HTML report files; exit code reflects failures, so it can run in CI

## Installation

```bash
go install github.com/sbroekhoven/check-maildomain/v2/cmd/check-maildomain@latest
```

Or download a binary from the [releases page](https://github.com/sbroekhoven/check-maildomain/releases), or build from source:

```bash
git clone https://github.com/sbroekhoven/check-maildomain.git
cd check-maildomain
go build -o check-maildomain ./cmd/check-maildomain
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

# Also save the results as JSON (missing folders are created)
check-maildomain -json results/example.json example.com

# JSON and HTML report at the same time
check-maildomain -json reports/example.json -html reports/example.html example.com

# A folder (trailing /) gets a timestamped file name, e.g. results/20261021001500-example.com-check-maildomain.json
check-maildomain -json results/ example.com
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

## Running from Cron

With `-cron` the tool prints nothing but one JSON line per run, so a cron job can check a list of domains and keep a simple log. The full results go to the `-json` and/or `-html` files; `-cron` refuses to run without at least one of them.

```bash
# /etc/cron.d/check-maildomain: every day at 06:00, append one line per domain to checks.log
0 6 * * * user cd /srv/checks && for d in example.com example.org example.net; do check-maildomain -cron -json results/ -html reports/ "$d"; done >> checks.log 2>&1
```

Each run adds a line like this (one line in the log; wrapped here for reading):

```json
{"time":"2026-10-21T06:00:01Z","tool":"check-maildomain","version":"2.0.0","domain":"example.com",
 "status":"fail","exit":2,"pass":30,"warn":3,"fail":1,"info":3,"err":0,"duration_ms":620,
 "json":"results/20261021060001-example.com-check-maildomain.json","html":"reports/20261021060001-example.com-check-maildomain.html"}
```

| Field | Meaning |
|-------|---------|
| `time` | Start of the run (UTC) |
| `tool`, `version` | The tool and its version |
| `domain` | The domain that was checked |
| `status` | `ok`, `fail` (a check failed) or `error` (the run could not complete), matching `exit` |
| `exit` | Exit code: 0, 2 or 1 (see [Exit Codes](#exit-codes)) |
| `pass`, `warn`, `fail`, `info` | Number of checks per result |
| `err` | Number of failed lookups plus output files that could not be written |
| `duration_ms` | How long the run took |
| `json`, `html` | Where the results were stored (left out if not written) |
| `error` | Why the status is `error` (left out otherwise) |

A run that can't start (no or an invalid domain, no `-json`/`-html`) still logs one line with `"status":"error"`. Only a malformed command line, such as an unknown flag, prints a usage message instead. The log format is the same as [check-domain](https://github.com/sbroekhoven/check-domain)'s, so both tools can write to one log.

Useful queries with [jq](https://jqlang.github.io/jq/):

```bash
# Every run that did not end OK
jq -c 'select(.status != "ok")' checks.log

# The latest result per domain
jq -s -c 'group_by(.domain) | map(max_by(.time) | {domain, status, pass, warn, fail})[]' checks.log
```

## HTML Report

```bash
check-maildomain -html report.html example.com
```

Writes a single, self-contained HTML file (inline CSS, no external assets) that you can email, attach to a ticket or archive. It shows an overall verdict, then one card per area with the records that were found (SPF record and lookup count, DMARC tags, DKIM selectors, DNSSEC keys, an MX table with addresses) and all checks. Problems are expanded; passing checks can be clicked open. The report follows the system light/dark theme, works on phones, and prints cleanly. The console output is printed as well, and `-json` can be combined with it.

## Command-line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-domain` | | Domain to check (alternatively the first argument) |
| `-nameserver` | `8.8.8.8` | Nameserver for lookups, optionally with port |
| `-fallback` | | Nameserver to use when the primary does not respond |
| `-timeout` | `3s` | Timeout per DNS query |
| `-selector` | | Extra DKIM selector to check (repeatable, or comma-separated) |
| `-cron` | `false` | Print only one JSON log line per run, for cron jobs (needs `-json` or `-html`) |
| `-v` | `false` | Also show the details of passing checks |
| `-json` | | Also write the results as JSON to this file, or into this folder (`dir/`) |
| `-html` | | Also write an HTML report to this file, or into this folder (`dir/`) |

The console output is always printed to stdout. `-json` and `-html` write files in addition to it and can be used together; the paths they were saved to are printed on stderr.
| `-rules` | | List all checks (ID, area, name) and exit |
| `-version` | | Print version and exit |

## Network Access

Besides DNS queries to the chosen nameserver, the tool makes one other kind of connection: when a domain publishes an MTA-STS record, its policy is fetched from `https://mta-sts.<domain>/.well-known/mta-sts.txt` (no redirects, at most 64 KiB). It never connects to the mail servers themselves.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No rule failed |
| 1 | Usage or runtime error, an output file could not be written, or a DNS lookup failed so the results are incomplete |
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
| 23 | DKIM | Key strength: RSA at least 1024 bits, 2048 recommended |
| 24 | DKIM | No keys in test mode (`t=y`) or limited to SHA-1 |
| 25 | SPF | Valid syntax (known mechanisms, valid IP ranges, single `redirect=`) |
| 26 | SPF | At most 2 void lookups (includes that don't exist) |
| 27 | SPF | No overly broad `ip4`/`ip6` ranges |
| 28 | MX | A domain that receives no mail publishes SPF `-all` and DMARC `p=reject` |
| 29 | DMARC | External report addresses are authorized (RFC 7489 7.1) |
| 30 | MX | MX addresses have forward-confirmed reverse DNS |
| 32 | TLS | MTA-STS record published and valid |
| 33 | TLS | MTA-STS policy reachable, valid and enforced |
| 34 | TLS | MTA-STS policy covers all MX hosts |
| 35 | TLS | TLS-RPT reporting configured |
| 36 | TLS | DANE TLSA records on the MX hosts, DNSSEC-validated |
| 38 | BIMI | BIMI record valid, with a certificate |
| 39 | BIMI | DMARC enforced as BIMI requires |

IDs 31 and 37 belonged to checks that were removed (MX blocklists and the SMTP STARTTLS probe); IDs are never reused.

## Project Layout

```
cmd/check-maildomain/   command-line entry point: flags, output selection, exit codes
internal/resolver/      DNS queries (UDP with TCP retry, optional fallback nameserver)
internal/spf/ dmarc/ dkim/ dnssec/ mx/
                        lookups and parsing per mail mechanism
internal/collector/     runs all lookups concurrently into one DomainInfo
internal/rules/         the checks, producing pass/warn/fail/info results
internal/output/        terminal output and the HTML report (template in templates/)
```

## Development

```bash
go vet ./...
go test ./...
```

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
