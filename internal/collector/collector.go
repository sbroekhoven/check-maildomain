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
	Errors      map[string]string  `json:"errors,omitempty"`

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
		Errors:    make(map[string]string),
	}
}

// CollectDNSInfo gathers all DNS information for the domain. The lookups run concurrently;
// failures are recorded per check in Errors rather than aborting the collection.
func CollectDNSInfo(domain string, res *resolver.Resolver, opts Options) *DomainInfo {
	info := NewDomainInfo(domain)

	var wg sync.WaitGroup
	run := func(name string, lookup func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := lookup(); err != nil {
				info.mu.Lock()
				info.Errors[name] = err.Error()
				info.mu.Unlock()
			}
		}()
	}

	run("mx", func() (err error) {
		info.MXRecords, err = mx.LookupMX(domain, res)
		return err
	})
	run("spf", func() (err error) {
		info.SPFRecord, err = spf.LookupSPF(domain, res)
		return err
	})
	run("dmarc", func() (err error) {
		info.DMARCRecord, err = dmarc.LookupDMARC(domain, res)
		if info.DMARCRecord != nil {
			info.DMARCPolicy = info.DMARCRecord.GetPolicy()
		}
		return err
	})
	run("dnssec", func() (err error) {
		info.DNSSECInfo, err = dnssec.CheckDNSSEC(domain, res)
		return err
	})
	run("dkim", func() (err error) {
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
