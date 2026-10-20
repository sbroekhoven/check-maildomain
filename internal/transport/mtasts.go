// Package transport looks up how mail to a domain is protected in transit: MTA-STS, TLS-RPT
// and DANE
package transport

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/resolver"
)

// maxPolicySize is the largest MTA-STS policy we read (RFC 8461 3.3 suggests 64 KiB)
const maxPolicySize = 64 * 1024

// MaxPolicyAge is the largest max_age an MTA-STS policy may have (RFC 8461 3.2: about one year)
const MaxPolicyAge = 31557600

// MTASTS is the MTA-STS configuration of a domain (RFC 8461)
type MTASTS struct {
	Record         string   `json:"record"`
	ID             string   `json:"id"`
	RecordCount    int      `json:"record_count"`
	RecordProblems []string `json:"record_problems,omitempty"`
	PolicyURL      string   `json:"policy_url"`
	Policy         *Policy  `json:"policy,omitempty"`
	PolicyError    string   `json:"policy_error,omitempty"` // the policy could not be fetched
}

// Policy is a parsed MTA-STS policy file
type Policy struct {
	Version  string   `json:"version"`
	Mode     string   `json:"mode"` // enforce, testing or none
	MX       []string `json:"mx"`   // allowed MX host patterns, e.g. "*.mail.example.net"
	MaxAge   int      `json:"max_age"`
	Problems []string `json:"problems,omitempty"`
}

var stsIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// LookupMTASTS reads the _mta-sts TXT record and, when there is one, fetches the policy over HTTPS
func LookupMTASTS(domain string, res *resolver.Resolver, client *http.Client) (*MTASTS, error) {
	txts, err := res.TXT("_mta-sts." + domain)
	if err != nil {
		return nil, err
	}

	info := &MTASTS{PolicyURL: "https://mta-sts." + domain + "/.well-known/mta-sts.txt"}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=STSv1") {
			info.RecordCount++
			if info.RecordCount == 1 {
				info.Record = txt
			}
		}
	}
	if info.RecordCount == 0 {
		return nil, &resolver.NotFoundError{What: "MTA-STS", Name: "_mta-sts." + domain}
	}
	info.ID, info.RecordProblems = parseSTSRecord(info.Record)
	if info.RecordCount > 1 {
		info.RecordProblems = append(info.RecordProblems, fmt.Sprintf("%d v=STSv1 records published; there must be exactly one", info.RecordCount))
	}

	body, err := fetchPolicy(info.PolicyURL, client)
	if err != nil {
		info.PolicyError = err.Error()
		return info, nil
	}
	policy := ParsePolicy(body)
	info.Policy = &policy
	return info, nil
}

// parseSTSRecord returns the id of a "v=STSv1; id=..." record and any problems with it
func parseSTSRecord(record string) (string, []string) {
	var id string
	var problems []string
	for i, part := range strings.Split(record, ";") {
		key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if i == 0 && (key != "v" || value != "STSv1") {
			problems = append(problems, "the record must start with v=STSv1")
		}
		if key == "id" {
			id = value
		}
	}
	switch {
	case id == "":
		problems = append(problems, "the id= tag is missing")
	case !stsIDPattern.MatchString(id):
		problems = append(problems, fmt.Sprintf("id %q must be 1 to 32 letters or digits", id))
	}
	return id, problems
}

// fetchPolicy downloads the policy file; redirects are not allowed (RFC 8461 3.3)
func fetchPolicy(url string, client *http.Client) (string, error) {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return "", fmt.Errorf("%s redirects to %s; MTA-STS policies must be served without redirects", url, resp.Header.Get("Location"))
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxPolicySize {
		return "", fmt.Errorf("%s is larger than %d bytes", url, maxPolicySize)
	}
	return string(body), nil
}

// ParsePolicy parses an MTA-STS policy file ("key: value" lines, RFC 8461 3.2)
func ParsePolicy(body string) Policy {
	p := Policy{MX: []string{}}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			p.Problems = append(p.Problems, fmt.Sprintf("invalid line %q", line))
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key != "mx" && seen[key] {
			p.Problems = append(p.Problems, fmt.Sprintf("%s appears more than once", key))
		}
		seen[key] = true

		switch key {
		case "version":
			p.Version = value
		case "mode":
			p.Mode = value
		case "mx":
			p.MX = append(p.MX, strings.ToLower(value))
		case "max_age":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > MaxPolicyAge {
				p.Problems = append(p.Problems, fmt.Sprintf("max_age %q must be a number of seconds up to %d", value, MaxPolicyAge))
			}
			p.MaxAge = n
		}
	}

	if p.Version != "STSv1" {
		p.Problems = append(p.Problems, fmt.Sprintf("version must be STSv1, got %q", p.Version))
	}
	switch p.Mode {
	case "enforce", "testing", "none":
	default:
		p.Problems = append(p.Problems, fmt.Sprintf("mode must be enforce, testing or none, got %q", p.Mode))
	}
	if !seen["max_age"] {
		p.Problems = append(p.Problems, "max_age is missing")
	}
	if len(p.MX) == 0 && p.Mode != "none" {
		p.Problems = append(p.Problems, "no mx: lines; every MX host must be listed")
	}
	return p
}

// MatchesMX reports whether an MX host matches a policy pattern. A leading "*." matches exactly
// one label: "*.example.net" matches "mx1.example.net" but not "a.b.example.net" (RFC 8461 4.1).
func MatchesMX(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		label, rest, found := strings.Cut(host, ".")
		return found && label != "" && rest == suffix
	}
	return pattern == host
}

// NewHTTPClient returns the client used to fetch MTA-STS policies
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}
