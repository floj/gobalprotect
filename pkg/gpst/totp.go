package gpst

import (
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// GenerateTOTP returns the current 6-digit TOTP code for the given
// base32-encoded secret using SHA1, a 30-second time step and 6 digits
// (RFC 6238 defaults, matching Google Authenticator).
//
// Spaces and dashes in the secret are stripped so values copied from
// otpauth URIs or QR-code text still work.
func GenerateTOTP(secret string) (string, error) {
	return generateTOTPAt(secret, time.Now())
}

func generateTOTPAt(secret string, now time.Time) (string, error) {
	s := strings.NewReplacer(" ", "", "-", "").Replace(secret)
	if s == "" {
		return "", fmt.Errorf("empty TOTP secret")
	}
	code, err := totp.GenerateCode(s, now)
	if err != nil {
		return "", fmt.Errorf("generating TOTP: %w", err)
	}
	return code, nil
}
