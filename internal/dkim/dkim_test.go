package dkim

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
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

// rsaKeyRecord returns a DKIM record with an RSA public key of the given size
func rsaKeyRecord(t *testing.T, bits int, extra string) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; " + extra + "p=" + base64.StdEncoding.EncodeToString(der)
}

func TestParseKey(t *testing.T) {
	ed := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	tests := []struct {
		name string
		txt  string
		want Key
	}{
		{"rsa 2048", rsaKeyRecord(t, 2048, ""), Key{Type: "rsa", Bits: 2048}},
		{"rsa 1024 test mode", rsaKeyRecord(t, 1024, "t=y:s; "), Key{Type: "rsa", Bits: 1024, TestMode: true}},
		{"rsa 512 sha1", rsaKeyRecord(t, 512, "h=sha1; "), Key{Type: "rsa", Bits: 512, HashAlgorithms: []string{"sha1"}}},
		{"ed25519", "v=DKIM1; k=ed25519; p=" + ed, Key{Type: "ed25519", Bits: 256}},
		{"revoked", "v=DKIM1; p=", Key{Type: "rsa", Revoked: true}},
		{"garbage", "v=DKIM1; p=not-base64!", Key{Type: "rsa", Error: "public key is not valid base64"}},
		{"not a key", "v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte("hello")), Key{Type: "rsa", Error: "RSA public key could not be parsed"}},
	}
	for _, tt := range tests {
		got := ParseKey("s1", tt.txt)
		tt.want.Selector, tt.want.Raw = "s1", tt.txt
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: ParseKey = %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestParseKeyAllowsWhitespaceInKey(t *testing.T) {
	txt := rsaKeyRecord(t, 2048, "")
	spaced := txt[:len(txt)-40] + " " + txt[len(txt)-40:]
	if k := ParseKey("s1", spaced); k.Bits != 2048 {
		t.Errorf("Bits = %d (%s), want 2048", k.Bits, k.Error)
	}
}
