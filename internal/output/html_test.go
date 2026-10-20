package output

import (
	"strings"
	"testing"
	"time"

	"github.com/sbroekhoven/check-maildomain/internal/collector"
	"github.com/sbroekhoven/check-maildomain/internal/dmarc"
	"github.com/sbroekhoven/check-maildomain/internal/mx"
	"github.com/sbroekhoven/check-maildomain/internal/rules"
	"github.com/sbroekhoven/check-maildomain/internal/spf"
)

func testReport(t *testing.T, setup func(*collector.DomainInfo)) string {
	t.Helper()
	info := collector.NewDomainInfo("example.com")
	info.QueryTime = time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	setup(info)
	e := rules.Evaluate(info)

	var out strings.Builder
	if err := WriteHTML(&out, e, "8.8.8.8:53", "test"); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	return out.String()
}

func TestWriteHTML(t *testing.T) {
	out := testReport(t, func(d *collector.DomainInfo) {
		d.SPFRecord = spf.Parse("v=spf1 mx -all")
		d.DMARCRecord = dmarc.Parse("v=DMARC1; p=reject; rua=mailto:d@example.com", "_dmarc.example.com")
		d.DMARCPolicy = d.DMARCRecord.GetPolicy()
		d.MXRecords = []mx.MXRecord{
			{Host: "mx1.example.com", Priority: 10, Records: []mx.Record{{Type: "A", Value: "192.0.2.1"}, {Type: "AAAA", Value: "2001:db8::1"}}},
			{Host: "mx2.example.com", Priority: 20, Records: []mx.Record{}},
		}
		d.Errors["dkim"] = "DNS query for _domainkey.example.com failed: i/o timeout"
		d.Failed["dkim"] = true
		d.Errors["dnssec"] = "DNS query for example.com returned NXDOMAIN" // not found, not a failure
	})

	for _, want := range []string{
		"<!doctype html>",
		"<title>Mail domain report: example.com</title>",
		"Checked 2 January 2026, 03:04 UTC · via 8.8.8.8",
		`<section class="card pass" id="spf">`,
		`<section class="card pass" id="dmarc">`,
		`id="dkim"`, `id="dnssec"`, `id="mx"`,
		"<td>mx1.example.com</td>",
		"A 192.0.2.1\nAAAA 2001:db8::1",
		"(does not resolve)",
		"<td>rua</td>",
		// Without data, a lookup error is shown as the area's lead line
		`<p class="lead">DNS query for _domainkey.example.com failed: i/o timeout</p>`,
		"passed</span>",
		"Could not be checked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not contain %q", want)
		}
	}

	if strings.Contains(out, "returned NXDOMAIN") {
		t.Error("a record that does not exist is shown as a lookup error")
	}

	// Self-contained: the only external reference is the footer link
	if n := strings.Count(out, "http"); n != 1 {
		t.Errorf("report contains %d http references, want only the footer link", n)
	}
}

func TestWriteHTMLEscapesDNSData(t *testing.T) {
	out := testReport(t, func(d *collector.DomainInfo) {
		d.SPFRecord = spf.Parse(`v=spf1 include:<script>alert(1)</script> -all`)
	})

	if strings.Contains(out, "<script>alert") {
		t.Error("DNS data is not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped DNS data is missing from the report")
	}
}

func TestOrderedTags(t *testing.T) {
	got := orderedTags(map[string]string{"rua": "", "zz": "", "p": "", "v": "", "aa": ""})
	want := "v p rua aa zz"
	if strings.Join(got, " ") != want {
		t.Errorf("orderedTags() = %v, want %s", got, want)
	}
}
