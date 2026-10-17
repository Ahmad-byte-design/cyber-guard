// Package urlintel validates, normalizes and fingerprints submitted URLs.
//
// Design rules from the architecture document:
//
//   - Only http and https are accepted.
//   - Embedded credentials are rejected outright.
//   - Overlong input is rejected rather than truncated.
//   - Paths and query strings are never case-folded: URLs are case-sensitive
//     outside the scheme and host, and parameters can change behaviour.
//   - Fingerprints are HMAC-SHA-256 over a documented canonical form. The raw
//     URL is never persisted; the key stays backend-side.
//
// A fingerprint is a keyed lookup handle, not anonymisation: hostname and
// surrounding metadata remain sensitive.
package urlintel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// MaxURLLength bounds accepted input so a hostile client cannot push an
// unbounded string through parsing, hashing and logging.
const MaxURLLength = 2048

// ValidationError describes why a submitted URL was rejected. It is safe to
// return to the client: messages never echo the URL itself.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

var (
	errEmpty      = &ValidationError{"url", "must not be empty"}
	errTooLong    = &ValidationError{"url", fmt.Sprintf("must be at most %d characters", MaxURLLength)}
	errControl    = &ValidationError{"url", "must not contain control characters"}
	errUnparsable = &ValidationError{"url", "is not a valid URL"}
	errScheme     = &ValidationError{"url", "scheme must be http or https"}
	errHost       = &ValidationError{"url", "must include a hostname"}
	errCreds      = &ValidationError{"url", "must not contain embedded credentials"}
	errPort       = &ValidationError{"url", "port must be numeric"}
)

// IsValidation reports whether err is a client-input problem.
func IsValidation(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// Validate parses raw and returns it only if it is a URL CyberGuard is willing
// to analyze. Surrounding whitespace is tolerated because browser toolbars and
// paste operations routinely add it.
func Validate(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)

	if trimmed == "" {
		return nil, errEmpty
	}
	if len(trimmed) > MaxURLLength {
		return nil, errTooLong
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return nil, errControl
		}
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, errUnparsable
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, errScheme
	}

	if u.Host == "" || u.Hostname() == "" {
		return nil, errHost
	}
	if u.User != nil {
		return nil, errCreds
	}
	if port := u.Port(); port != "" && !isNumeric(port) {
		return nil, errPort
	}

	// Host must contain at least one label character; reject bare separators.
	if strings.Trim(u.Hostname(), ".-") == "" {
		return nil, errHost
	}

	return u, nil
}

// Canonical returns the string that gets hashed into a fingerprint. The scheme
// and host are case-folded and an empty path becomes "/", because
// "https://a.test" and "https://a.test/" address the same resource. Path and
// query are preserved byte-for-byte.
func Canonical(u *url.URL) string {
	c := *u
	c.Scheme = strings.ToLower(c.Scheme)
	c.Host = strings.ToLower(c.Host)
	if c.Path == "" {
		c.Path = "/"
	}
	c.Fragment = ""   // a fragment is never sent to a server; drop it so
	return c.String() // "http://a.test/p#x" and "http://a.test/p" match.
}

// Fingerprint returns the hex-encoded HMAC-SHA-256 of canonical under key.
// An empty key is rejected: an unkeyed hash would let an attacker confirm
// guesses about URLs already assessed.
func Fingerprint(key []byte, canonical string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("urlintel: fingerprint key must not be empty")
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(canonical)); err != nil {
		return "", fmt.Errorf("urlintel: fingerprint: %w", err)
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Prepare is the common entry point: validate, canonicalize and fingerprint in
// one step. The canonical form is returned transiently and should not be
// logged or stored.
func Prepare(key []byte, raw string) (canonical, fingerprint string, err error) {
	u, err := Validate(raw)
	if err != nil {
		return "", "", err
	}
	canonical = Canonical(u)
	if fingerprint, err = Fingerprint(key, canonical); err != nil {
		return "", "", err
	}
	return canonical, fingerprint, nil
}

// isNumeric reports whether s is a non-empty run of ASCII digits.
//
// A port must be numeric; url.Parse is permissive about some forms, so the
// check is explicit rather than relying on parsing alone.
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
