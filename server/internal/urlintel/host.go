package urlintel

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Host intelligence: hostname normalisation and registrable-domain extraction.
//
// The two are deliberately separate functions rather than one.
//
// Normalisation answers "what is this host, spelled canonically?" — lowercase,
// punycoded, without a trailing dot. It is a pure string operation.
//
// Registrable-domain extraction answers "which organisation does this host
// belong to?" — a question about the public suffix list, not about spelling.
// It requires the normalised form as input, because the Public Suffix List
// matches on the canonical (ASCII, lower-case) spelling and rejects a trailing
// dot outright.
//
// Combining them hides the dependency: callers would not know that a stray
// full stop silently turns a valid domain into an unresolvable one.
//
// # Why the Public Suffix List
//
// The previous hand-rolled implementation was wrong in ways that mattered, and
// all were verified rather than assumed:
//
//	"co.uk"        -> "co.uk"         a public suffix returned as a domain
//	"8.8.8.8"      -> "8.8"           an IP address mangled into a domain
//	"192.168.1.1"  -> "1.1"           likewise
//	"localhost"    -> "localhost"     a bare label treated as a domain
//	"com"          -> "com"           a bare TLD treated as a domain
//
// Each would let host-level reputation aggregation group unrelated hosts, or a
// domain-scoped rule block far more than intended. Every one of those inputs is
// now rejected rather than guessed at.
//
// The full list is maintained at publicsuffix.org and changes over time. A
// snapshot would go stale exactly where it matters most.

// maxHostnameLen is the maximum length of a DNS name, in bytes, per RFC 1035.
const maxHostnameLen = 253

// maxLabelLen is the maximum length of a single DNS label.
const maxLabelLen = 63

// ErrNotRegistrable means a host has no registrable domain: it is an IP
// literal, a bare label such as "localhost", or itself a public suffix such as
// "co.uk".
//
// It is distinct from a validation error. The host may be perfectly valid; it
// simply does not belong to a registrable domain, and inventing one would be
// the misclassification this package exists to prevent.
var ErrNotRegistrable = errors.New("urlintel: host has no registrable domain")

// HostInfo describes a hostname and, where one exists, the registrable domain
// it belongs to.
type HostInfo struct {
	// Hostname is the normalised hostname: lower-case, punycoded, no trailing
	// dot. This is the original host, preserved separately from the
	// registrable domain so a host-scoped verdict is never confused with a
	// domain-scoped one.
	Hostname string

	// RegistrableDomain is the "eTLD+1" per the Public Suffix List. Empty
	// when the host has none.
	RegistrableDomain string

	// IsIP reports whether the host is an IP literal. An IP has no
	// registrable domain and no public suffix, so this must be checked
	// explicitly rather than inferred from an empty RegistrableDomain.
	IsIP bool

	// IsLocal reports whether the host is a bare local name such as
	// "localhost", which likewise has no registrable domain.
	IsLocal bool
}

// NormalizeHostname returns the canonical spelling of a hostname:
// lower-case, punycoded, and without a trailing dot.
//
// It performs no suffix logic whatsoever. A host that is itself a public
// suffix normalises successfully and is rejected only by RegistrableDomain,
// which is what keeps the two concerns separate.
//
// Internationalised names are converted with the idna.Lookup profile, the one
// recommended for domain lookups. Without this a Unicode homograph such as
// "аpple.com" (Cyrillic а) would survive into host aggregation and become a
// second, indistinguishable entry for a domain an operator already blocked.
func NormalizeHostname(host string) (string, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", &ValidationError{Field: "hostname", Reason: "must not be empty"}
	}

	// An IPv6 literal arrives bracketed from net/url; strip the brackets
	// before parsing, and restore nothing — the normalised form is bare.
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}

	// An IP literal has no DNS spelling. Normalising it would be wrong, and
	// it is handled explicitly by ParseHost.
	if net.ParseIP(h) != nil {
		return h, nil
	}

	// One trailing dot is the DNS root and carries no meaning here.
	h = strings.TrimSuffix(h, ".")

	if h == "" {
		return "", &ValidationError{Field: "hostname", Reason: "must not be empty"}
	}
	if len(h) > maxHostnameLen {
		return "", &ValidationError{
			Field:  "hostname",
			Reason: fmt.Sprintf("must be at most %d characters", maxHostnameLen),
		}
	}

	// Lower-case before IDNA so the profile sees the ASCII form it expects.
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(h))
	if err != nil {
		return "", &ValidationError{Field: "hostname", Reason: "is not a valid internationalised domain name"}
	}

	if err := validateLabels(ascii); err != nil {
		return "", err
	}
	return ascii, nil
}

// validateLabels enforces DNS label syntax.
//
// It deliberately does not require two or more labels. A single-label host is
// syntactically valid — "localhost" is the obvious one — and rejecting it here
// would conflate normalisation with suffix resolution, which is exactly the
// separation this package exists to preserve. A bare label simply has no
// registrable domain, which RegistrableDomain reports.
func validateLabels(h string) error {
	labels := strings.Split(h, ".")
	for _, label := range labels {
		switch {
		case label == "":
			return &ValidationError{Field: "hostname", Reason: "must not contain empty labels"}
		case len(label) > maxLabelLen:
			return &ValidationError{
				Field:  "hostname",
				Reason: fmt.Sprintf("labels must be at most %d characters", maxLabelLen),
			}
		case strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-"):
			return &ValidationError{Field: "hostname", Reason: "labels must not start or end with a hyphen"}
		}

		for _, r := range label {
			isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if !isLetter && !isDigit && r != '-' {
				return &ValidationError{Field: "hostname", Reason: "must contain only letters, digits and hyphens"}
			}
		}
	}
	return nil
}

// RegistrableDomain returns the registrable domain ("eTLD+1") of a host, using
// the Public Suffix List.
//
// It returns ErrNotRegistrable for an IP literal, a bare label such as
// "localhost", a host that is itself a public suffix such as "co.uk", and any
// host the list cannot resolve. It never falls back to a heuristic, because a
// wrong registrable domain silently merges unrelated hosts into one reputation
// or widens a rule's blast radius.
//
// The input is normalised first, so a trailing dot or upper case does not cause
// a spurious "no registrable domain".
func RegistrableDomain(host string) (string, error) {
	normalised, err := NormalizeHostname(host)
	if err != nil {
		return "", err
	}

	// publicsuffix rejects IP literals and single labels on its own, but
	// checking here produces a clearer error and avoids relying on that.
	if net.ParseIP(normalised) != nil {
		return "", fmt.Errorf("%w: %q is an IP address", ErrNotRegistrable, normalised)
	}

	effective, err := publicsuffix.EffectiveTLDPlusOne(normalised)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrNotRegistrable, normalised)
	}

	// Belt and braces. EffectiveTLDPlusOne should never return a value that is
	// itself a public suffix, but that is the one misclassification that must
	// be impossible: if it happened, every site under that suffix would share
	// a single reputation and a single domain-scoped rule.
	if suffix, _ := publicsuffix.PublicSuffix(effective); suffix == effective {
		return "", fmt.Errorf("%w: %q is a public suffix", ErrNotRegistrable, effective)
	}

	return effective, nil
}

// ParseHost normalises a host and derives its registrable domain.
//
// It returns a HostInfo even when no registrable domain exists — an IP or
// "localhost" is a legitimate host whose RegistrableDomain is simply empty —
// so a caller can distinguish "not a domain" from "invalid host".
//
// Errors are returned only for hosts that are malformed.
func ParseHost(host string) (HostInfo, error) {
	normalised, err := NormalizeHostname(host)
	if err != nil {
		return HostInfo{}, err
	}

	info := HostInfo{Hostname: normalised}

	if net.ParseIP(normalised) != nil {
		info.IsIP = true
		return info, nil
	}
	if !strings.Contains(normalised, ".") {
		// A single label — "localhost" and friends. Valid, but belonging to
		// no registrable domain.
		info.IsLocal = true
		return info, nil
	}

	// A failure here is expected for public suffixes and unknown suffixes.
	// It is not an error: the host is valid, it just has no registrable domain.
	if domain, err := RegistrableDomain(normalised); err == nil {
		info.RegistrableDomain = domain
	}
	return info, nil
}
