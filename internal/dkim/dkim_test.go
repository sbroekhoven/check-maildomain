package dkim

import (
	"reflect"
	"testing"
)

func TestIsDKIMKey(t *testing.T) {
	for txt, want := range map[string]bool{
		"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ": true,
		"k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ":          true,
		"v=DKIM1; p=":                  true, // revoked key is still a key record
		"v=spf1 -all":                  false,
		"k=rsa; v=DKIM1; p=abc":        false, // v must be first
		"v=DKIM2; p=abc":               false,
		"google-site-verification=abc": false,
	} {
		if got := IsDKIMKey(txt); got != want {
			t.Errorf("IsDKIMKey(%q) = %v, want %v", txt, got, want)
		}
	}
}

func TestUniqueSelectors(t *testing.T) {
	got := uniqueSelectors([]string{"Custom", " google ", ""}, []string{"default", "google"})
	want := []string{"custom", "google", "default"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("uniqueSelectors() = %v, want %v", got, want)
	}
}
