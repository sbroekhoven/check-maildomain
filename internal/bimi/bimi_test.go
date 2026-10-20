package bimi

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		raw      string
		declined bool
		problems int
	}{
		{"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem", false, 0},
		{"v=BIMI1; l=https://example.com/logo.svg;", false, 0},
		{"v=BIMI1; l=; a=;", true, 0},
		{"v=BIMI1;", true, 0},
		{"v=BIMI1; l=http://example.com/logo.svg", false, 1},
		{"v=BIMI1; a=https://example.com/vmc.pem", false, 1},
		{"l=https://example.com/logo.svg; v=BIMI1", false, 1},
	}
	for _, tt := range tests {
		r := Parse(tt.raw, "default._bimi.example.com")
		if r.Declined != tt.declined || len(r.Problems) != tt.problems {
			t.Errorf("Parse(%q) = declined %v, problems %q; want declined %v, %d problems", tt.raw, r.Declined, r.Problems, tt.declined, tt.problems)
		}
	}
}
