# Email Domain Security Checker

A command-line tool that analyzes email domain configurations for security and deliverability best practices.

## Overview

This tool checks a domain's DNS records related to email security, including:

- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)
- DMARC (Domain-based Message Authentication, Reporting & Conformance)
- DNSSEC (Domain Name System Security Extensions)
- MX (Mail Exchange) records

It evaluates these configurations against a comprehensive set of rules and provides detailed results about potential issues and recommendations.

## Features

- Analyzes SPF record configuration and syntax
- Checks DMARC policy strength
- Verifies DKIM record existence
- Validates DNSSEC configuration
- Examines MX record configuration for redundancy and proper setup
- Detects common misconfigurations like private IPs or localhost in MX records
- Provides detailed output in JSON format

## Installation

```bash
# Clone the repository
git clone https://github.com/sbroekhoven/check-maildomain.git
cd check-maildomain

# Build the application
go build -o check-maildomain
```

## Usage

```bash
# Basic usage with default values
./check-maildomain

# Specify a domain to check
./check-maildomain -domain example.com

# Use a specific DNS nameserver
./check-maildomain -domain example.com -nameserver 1.1.1.1

# Disable JSON output
./check-maildomain -domain example.com -json=false
```

## Command-line Options

- `-domain`: Domain to check (default: "suspiciousbytes.com")
- `-nameserver`: DNS nameserver to use for lookups (default: "8.8.8.8")
- `-json`: Output results in JSON format (default: true)

Other output will be added later. Think about console readable, or HTML file.

## Output

The tool outputs a JSON structure containing:
- Domain information
- DNS records found
- Rule check results with status (pass/warn/fail/info)
- Detailed messages explaining each finding

## Rule Checks

The tool performs the following checks:

### SPF Checks
- SPF record existence
- Proper use of the `all` qualifier
- Detection of deprecated `ptr:` mechanism
- Limit on `include:` mechanisms

### DMARC Checks
- DMARC record existence
- DMARC policy strength (reject/quarantine/none)

### DKIM Checks
- DKIM record existence
- Detection of common DKIM selectors

### MX Checks
- MX record existence
- MX record redundancy
- IPv6 support
- Private IP detection
- Localhost detection

### DNSSEC Checks
- DNSSEC enablement status

## License

Good question?

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.