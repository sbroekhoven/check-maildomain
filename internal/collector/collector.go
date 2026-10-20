package collector

import (
	"sync"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/dkim"
	"github.com/sbroekhoven/check-maildomain/internal/dmarc"
	"github.com/sbroekhoven/check-maildomain/internal/dnssec"
	"github.com/sbroekhoven/check-maildomain/internal/mx"
	"github.com/sbroekhoven/check-maildomain/internal/resolver"
	"github.com/sbroekhoven/check-maildomain/internal/spf"
)

// Check identifies one lookup of the collection; it is the key of Errors and Failed
type Check string

const (
	CheckSPF    Check = "spf"
	CheckDMARC  Check = "dmarc"
	CheckDKIM   Check = "dkim"
	CheckDNSSEC Check = "dnssec"
	CheckMX     Check = "mx"
)

// DomainInfo represents collected DNS information about a domain
type DomainInfo struct {
	Domain      string             `json:"domain"`
	QueryTime   time.Time          `json:"query_time"`
	MXRecords   []mx.MXRecord      `json:"mx_records"`
	SPFRecord   *spf.SPFRecord     `json:"spf_record"`
	DMARCRecord *dmarc.DMARCRecord `json:"dmarc_record"`
	DMARCPolicy dmarc.DMARCPolicy  `json:"dmarc_policy"`
	DNSSECInfo  *dnssec.DNSSECInfo `json:"dnssec_info"`
	DKIMInfo    *dkim.DKIMInfo     `json:"dkim_info"`
	Errors      map[Check]string   `json:"errors,omitempty"`         // Lookup errors per check, including "record not found"
	Failed      map[Check]bool     `json:"failed_lookups,omitempty"` // Checks whose lookup failed, so their result is unknown

	mu sync.Mutex
}

// Options tunes what is collected
type Options struct {
	DKIMSelectors []string // Extra DKIM selectors to check besides dkim.CommonSelectors
}

// NewDomainInfo creates a new DomainInfo structure
func NewDomainInfo(domain string) *DomainInfo {
	return &DomainInfo{
		Domain:    domain,
		QueryTime: time.Now(),
		Errors:    make(map[Check]string),
		Failed:    make(map[Check]bool),
	}
}

// CollectDNSInfo gathers all DNS information for the domain. The lookups run concurrently;
// failures are recorded per check in Errors rather than aborting the collection.
func CollectDNSInfo(domain string, res *resolver.Resolver, opts Options) *DomainInfo {
	info := NewDomainInfo(domain)

	var wg sync.WaitGroup
	run := func(name Check, lookup func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := lookup(); err != nil {
				info.mu.Lock()
				info.Errors[name] = err.Error()
				if !resolver.IsNotFound(err) {
					info.Failed[name] = true
				}
				info.mu.Unlock()
			}
		}()
	}

	run(CheckMX, func() (err error) {
		info.MXRecords, err = mx.LookupMX(domain, res)
		return err
	})
	run(CheckSPF, func() (err error) {
		info.SPFRecord, err = spf.LookupSPF(domain, res)
		return err
	})
	run(CheckDMARC, func() (err error) {
		info.DMARCRecord, err = dmarc.LookupDMARC(domain, res)
		if info.DMARCRecord != nil {
			info.DMARCPolicy = info.DMARCRecord.GetPolicy()
		}
		return err
	})
	run(CheckDNSSEC, func() (err error) {
		info.DNSSECInfo, err = dnssec.CheckDNSSEC(domain, res)
		return err
	})
	run(CheckDKIM, func() (err error) {
		info.DKIMInfo, err = dkim.CheckDKIM(domain, res, opts.DKIMSelectors)
		return err
	})

	wg.Wait()
	return info
}

// HasErrors returns true if any errors were encountered during collection
func (di *DomainInfo) HasErrors() bool {
	return len(di.Errors) > 0
}

// HasFailedLookups returns true if any lookup failed, so the results are incomplete
func (di *DomainInfo) HasFailedLookups() bool {
	return len(di.Failed) > 0
}

// LookupFailure returns the error of a failed lookup for a check, if it failed
func (di *DomainInfo) LookupFailure(check Check) (string, bool) {
	if !di.Failed[check] {
		return "", false
	}
	return di.Errors[check], true
}
