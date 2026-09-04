package gpst

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestGenerateTOTPRFC6238Vectors(t *testing.T) {
	// Secret from RFC 6238 Appendix B: ASCII "12345678901234567890"
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tc := range cases {
		got, err := generateTOTPAt(secret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("generateTOTPAt(%d) error: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("generateTOTPAt(%d) = %q, want %q", tc.unix, got, tc.want)
		}
	}
}

func TestGenerateTOTPNormalizesSecret(t *testing.T) {
	raw := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	// Insert spaces / dashes and lowercase to ensure normalization.
	messy := ""
	for i, r := range raw {
		if i > 0 && i%4 == 0 {
			messy += "-"
		}
		messy += string(r)
	}
	// Strip padding to also verify auto-padding.
	for len(messy) > 0 && messy[len(messy)-1] == '=' {
		messy = messy[:len(messy)-1]
	}
	got, err := generateTOTPAt(messy, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "287082" {
		t.Errorf("normalized secret = %q, want %q", got, "287082")
	}
}
