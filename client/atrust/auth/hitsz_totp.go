package auth

// HITSZ's \"security token OTP\" MFA method (reAuthType 10) uses the
// conventional RFC 6238 profile: a Base32 seed, HMAC-SHA1, six digits, and a
// 30-second period. Keep this in the auth package so the seed is only ever
// held in memory and never added to aTrust's persisted client state.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	hitszTOTPPeriod = 30
	hitszTOTPDigits = 6
)

func currentHITSZTOTP(secret string) (string, error) {
	return generateHITSZTOTP(secret, time.Now())
}

func generateHITSZTOTP(secret string, at time.Time) (string, error) {
	key, err := decodeHITSZTOTPSecret(secret)
	if err != nil {
		return "", err
	}

	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/hitszTOTPPeriod))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", hitszTOTPDigits, value%1_000_000), nil
}

func decodeHITSZTOTPSecret(raw string) ([]byte, error) {
	secret := strings.TrimSpace(raw)
	if secret == "" {
		return nil, errors.New("HITSZ OTP secret is empty")
	}

	if strings.HasPrefix(strings.ToLower(secret), "otpauth:") {
		u, err := url.Parse(secret)
		if err != nil || !strings.EqualFold(u.Scheme, "otpauth") || !strings.EqualFold(u.Host, "totp") {
			return nil, errors.New("invalid HITSZ OTP secret URI")
		}
		query := u.Query()
		if algorithm := strings.TrimSpace(query.Get("algorithm")); algorithm != "" && !strings.EqualFold(algorithm, "SHA1") {
			return nil, errors.New("HITSZ OTP only supports SHA1")
		}
		if digits := strings.TrimSpace(query.Get("digits")); digits != "" && digits != "6" {
			return nil, errors.New("HITSZ OTP only supports six digits")
		}
		if period := strings.TrimSpace(query.Get("period")); period != "" && period != "30" {
			return nil, errors.New("HITSZ OTP only supports a 30-second period")
		}
		secret = query.Get("secret")
	}

	// Authenticator exports commonly omit Base32 padding and may group the
	// seed with spaces or hyphens. Normalize those harmless variants without
	// including the source value in any error message.
	secret = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "", "\r", "", "\n", "").Replace(secret))
	secret = strings.TrimRight(secret, "=")
	if secret == "" {
		return nil, errors.New("HITSZ OTP secret is empty")
	}
	if remainder := len(secret) % 8; remainder != 0 {
		secret += strings.Repeat("=", 8-remainder)
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil || len(key) == 0 {
		return nil, errors.New("invalid HITSZ OTP secret")
	}
	return key, nil
}
