package dns

import (
	"time"

	"check-maildomain/internal/dkim"
	"check-maildomain/internal/dmarc"
	"check-maildomain/internal/dnssec"
	"check-maildomain/internal/mx"
	"check-maildomain/internal/spf"
)

// DomainInfo represents collected DNS information about a domain
type DomainInfo struct {
	Domain      string
	QueryTime   time.Time
	MXRecords   []mx.MXRecord
	SPFRecord   *spf.SPFRecord
	DMARCRecord *dmarc.DMARCRecord
	DMARCPolicy dmarc.DMARCPolicy
	DNSSECInfo  *dnssec.DNSSECInfo
	DKIMInfo    *dkim.DKIMInfo
	Errors      map[string]error
}

// NewDomainInfo creates a new DomainInfo structure
func NewDomainInfo(domain string) *DomainInfo {
	return &DomainInfo{
		Domain:    domain,
		QueryTime: time.Now(),
		Errors:    make(map[string]error),
	}
}

// CollectDNSInfo gathers all DNS information for the domain
func CollectDNSInfo(domain string, nameserver string) (*DomainInfo, error) {
	info := NewDomainInfo(domain)

	// Collect MX records
	mxRecords, err := mx.LookupMXWithFallback(domain, nameserver)
	if err != nil {
		info.Errors["mx"] = err
	} else {
		info.MXRecords = mxRecords
	}

	// Collect SPF record
	spfRecord, err := spf.LookupSPFWithFallback(domain, nameserver)
	if err != nil {
		info.Errors["spf"] = err
	} else {
		info.SPFRecord = spfRecord
	}

	// Collect DMARC record
	dmarcRecord, err := dmarc.LookupDMARCWithFallback(domain, nameserver)
	if err != nil {
		info.Errors["dmarc"] = err
	} else {
		info.DMARCRecord = dmarcRecord
		info.DMARCPolicy = dmarcRecord.GetPolicy()
	}

	dnssecInfo, err := dnssec.CheckDNSSECWithFallback(domain, nameserver)
	if err != nil {
		info.Errors["dnssec"] = err
	} else {
		info.DNSSECInfo = dnssecInfo
	}

	dkimInfo, err := dkim.CheckDKIMWithFallback(domain, nameserver)
	if err != nil {
		info.Errors["dkim"] = err
	} else {
		info.DKIMInfo = dkimInfo
	}

	return info, nil
}

// HasErrors returns true if any errors were encountered during collection
func (di *DomainInfo) HasErrors() bool {
	return len(di.Errors) > 0
}
