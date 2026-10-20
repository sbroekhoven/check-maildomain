package resolver

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RcodeError is returned when a DNS query completes but the server answers with a non-success code
type RcodeError struct {
	Name  string
	Rcode int
}

func (e *RcodeError) Error() string {
	return fmt.Sprintf("DNS query for %s returned %s", e.Name, dns.RcodeToString[e.Rcode])
}

// IsNXDomain reports whether err is an NXDOMAIN answer
func IsNXDomain(err error) bool {
	var rerr *RcodeError
	return errors.As(err, &rerr) && rerr.Rcode == dns.RcodeNameError
}

// Resolver sends DNS queries to a single nameserver, with an optional fallback nameserver
type Resolver struct {
	Server   string // host:port of the primary nameserver
	Fallback string // host:port of the fallback nameserver, empty to disable
	Timeout  time.Duration
}

// New creates a Resolver. Nameservers may be given as "1.1.1.1", "1.1.1.1:5353",
// "2001:4860:4860::8888" or "[2001:4860:4860::8888]:53". An empty fallback disables fallback.
func New(nameserver, fallback string, timeout time.Duration) *Resolver {
	r := &Resolver{
		Server:  NormalizeNameserver(nameserver),
		Timeout: timeout,
	}
	if fallback != "" {
		r.Fallback = NormalizeNameserver(fallback)
	}
	return r
}

// NormalizeNameserver turns a nameserver address into host:port form, defaulting to port 53
func NormalizeNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	if host, port, err := net.SplitHostPort(ns); err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(strings.Trim(ns, "[]"), "53")
}

// Query sends a recursive query for name/qtype. Truncated UDP answers are retried over TCP.
// Network failures on the primary nameserver are retried on the fallback nameserver, if configured.
// A non-success response code is returned as *RcodeError together with the response.
func (r *Resolver) Query(name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	if dnssec {
		m.SetEdns0(4096, true)
	}

	resp, err := r.exchange(m, r.Server)
	if err != nil && r.Fallback != "" {
		resp, err = r.exchange(m, r.Fallback)
	}
	if err != nil {
		return nil, fmt.Errorf("DNS query for %s failed: %w", name, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return resp, &RcodeError{Name: name, Rcode: resp.Rcode}
	}
	return resp, nil
}

func (r *Resolver) exchange(m *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: r.Timeout}
	resp, _, err := c.Exchange(m, server)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.Exchange(m, server)
	}
	return resp, err
}

// TXT returns the TXT strings for name, with the chunks of each record joined together
func (r *Resolver) TXT(name string) ([]string, error) {
	resp, err := r.Query(name, dns.TypeTXT, false)
	if err != nil {
		return nil, err
	}

	var txts []string
	for _, a := range resp.Answer {
		if txt, ok := a.(*dns.TXT); ok {
			txts = append(txts, strings.Join(txt.Txt, ""))
		}
	}
	return txts, nil
}
