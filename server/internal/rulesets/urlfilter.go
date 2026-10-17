package rulesets

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Building Chrome `urlFilter` patterns safely.
//
// # The grammar, and why nothing here escapes anything
//
// Chrome documents `urlFilter` as:
//
//	(optional Left/Domain name anchor) + pattern + (optional Right anchor)
//
// with exactly four constructs: `*` wildcard, `|` anchor, `||` domain anchor,
// and `^` separator. There is **no documented escape mechanism**.
//
// An earlier version of this engine escaped `*`, `|`, `,`, `:`, `/`, `?`, `=`,
// `#` and `@` with backslashes. Three of those are wrong — `/`, `?`, `=` and
// `#` are ordinary literal characters in a URL and are not operators — and none
// of it was verifiable, because the backslash form is not in the specification
// this engine is written against. A pattern built on undocumented behaviour is
// a pattern nobody can prove correct.
//
// So this file escapes nothing. Instead every literal that goes into a filter is
// checked first, and a candidate that cannot be expressed safely is **rejected**.
// A missing rule is a recoverable annoyance; a rule that quietly matches a
// different host is not.
//
// # Hostname boundaries
//
// `||example.com^` is the correct, narrow host pattern:
//
//   - `||` anchors to the start of a (sub-)domain, so the literal must begin at
//     a label boundary. `evil-example.com` has no label boundary before
//     `example`, so it does not match.
//   - `^` matches any character that is not a letter, digit, `_`, `-`, `.` or
//     `%`, and also the end of the URL. The `.` exclusion is what stops
//     `example.com` from matching `example.company`.
//
// TestHostnameFilterBoundary records these properties.

const (
	filterDomainAnchor = "||"
	filterSeparator    = "^"
)

// urlFilterOperators are the characters that carry meaning in the documented
// urlFilter grammar, and therefore may never appear literally in a pattern.
//
// `*` is the wildcard, `|` is the anchor, `^` is the separator, and `:` and `,`
// are separators in the adblock-derived syntax Chrome's matcher descends from.
// Chrome's current reference does not list `:` or `,`, so they are rejected on
// the conservative reading: if a character might be an operator, a pattern that
// contains it is not provably literal.
const urlFilterOperators = "*|^,:"

// ErrUnsafeFilterLiteral means a value cannot be put into a urlFilter without
// risking a pattern that matches more than intended.
var ErrUnsafeFilterLiteral = fmt.Errorf("%w: value contains a urlFilter operator or non-ASCII text",
	ErrInvalidRule)

// checkRegexText verifies a value is safe to build a urlFilter-independent RE2
// pattern from.
//
// It is deliberately looser than checkFilterLiteral. The urlFilter grammar has
// no escape, so an operator in a literal makes the pattern unprovable; RE2 does
// have escaping, and regexQuote applies it. What is still required is that the
// value be ASCII — Chrome matches a regexFilter against a URL whose host is
// punycoded and whose other non-ASCII characters are percent-encoded, so a
// non-ASCII literal could never match and would look correct while matching
// nothing.
func checkRegexText(what, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidRule, what)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidRule, what)
	}

	for _, r := range value {
		if r > 0x7f {
			return fmt.Errorf("%w: %s contains a non-ASCII character; Chrome matches a regex "+
				"against a percent-encoded URL", ErrInvalidRule, what)
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidRule, what)
		}
	}
	return nil
}

// checkFilterLiteral verifies a value is safe to embed literally.
//
// It rejects non-ASCII as well as the operators. Chrome percent-encodes paths on
// the wire, so a non-ASCII path never appears literally in the URL a filter is
// matched against, and emitting one would produce a pattern that matches nothing
// while looking correct.
func checkFilterLiteral(what, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidRule, what)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidRule, what)
	}

	for _, r := range value {
		if r > 0x7f {
			return fmt.Errorf("%w: %s contains a non-ASCII character", ErrUnsafeFilterLiteral, what)
		}
		if strings.ContainsRune(urlFilterOperators, r) {
			return fmt.Errorf("%w: %s contains the operator %q", ErrUnsafeFilterLiteral, what, r)
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidRule, what)
		}
	}
	return nil
}

// DomainFilter builds a `urlFilter` matching one host and its subdomains.
//
// The result is `||host^`. It is safe for any hostname that survived
// NormalizeHostname: lower-case, punycoded ASCII, containing only letters,
// digits, hyphens and dots.
func DomainFilter(host string) (string, error) {
	if err := checkFilterLiteral("hostname", host); err != nil {
		return "", err
	}
	// An IPv6 literal carries colons and, in URL form, brackets. Neither is
	// expressible here. Rejecting is correct: silently emitting a filter that
	// matches an address prefix would block a different host.
	if strings.ContainsAny(host, ":[]") {
		return "", fmt.Errorf("%w: hostname %q is an IPv6 literal and has no urlFilter form", ErrInvalidRule, host)
	}

	return filterDomainAnchor + host + filterSeparator, nil
}

// PrefixFilter builds a `urlFilter` matching one path prefix on one host.
//
// The result is `||host^/prefix`, which is a prefix match on the URL string, so
// it also matches longer paths under the same prefix. That is what the
// prefix scope means, and it is why the prefix scope needs more corroboration
// than the exact scope.
//
// The path must already be percent-encoded — it comes from url.URL.EscapedPath,
// never from a raw decoded string — and must contain no urlFilter operator.
func PrefixFilter(host, path string) (string, error) {
	p := normalisePath(path)
	if err := checkFilterLiteral("path prefix", p); err != nil {
		return "", err
	}

	domain, err := DomainFilter(host)
	if err != nil {
		return "", err
	}
	return domain + p, nil
}

// ExactURLRegex builds the anchored RE2 pattern for the exact-URL scope.
//
// `urlFilter` cannot express "this URL and nothing else": `||host^/p` is a
// prefix match, so it would also cover `/p/admin`. An anchored regex can.
//
// The pattern is built from the scheme, the host, the port and the percent-
// encoded path. It deliberately omits the query string, because the assessment
// does not store one — queries carry session tokens, and persisting or
// publishing those would undo the point of the fingerprint. Two URLs differing
// only in query therefore share a rule; that is recorded in ADR 0018 and is the
// price of not retaining the query.
//
// Chrome requires a regexFilter to be ASCII-only and to match against a URL
// whose host is punycoded and whose other non-ASCII characters are percent-
// encoded. Everything written here already satisfies that, which is checked
// rather than assumed.
func ExactURLRegex(scheme, host, port, path string) (string, error) {
	if scheme == "" {
		return "", fmt.Errorf("%w: exact URL rule needs a scheme", ErrInvalidRule)
	}
	if err := checkRegexText("hostname", host); err != nil {
		return "", err
	}
	if port != "" {
		if err := checkRegexText("port", port); err != nil {
			return "", err
		}
		// A port must be digits. Anything else would make the pattern match a
		// different authority.
		if _, err := strconv.Atoi(port); err != nil {
			return "", fmt.Errorf("%w: port %q is not numeric", ErrInvalidRule, port)
		}
	}

	p := normalisePath(path)
	if err := checkRegexText("path", p); err != nil {
		return "", err
	}

	authority := host
	// An IPv6 literal is bracketed in a URL authority. The brackets are part of
	// the URL text, so they are emitted and escaped like any other character.
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority += ":" + port
	}

	pattern := "^" + regexQuote(scheme) + "://" + regexQuote(authority) + regexQuote(p) + "$"

	if len(pattern) > MaxRegexRuleBytes {
		return "", fmt.Errorf("%w: regex rule is %d characters, over Chrome's %d limit",
			ErrInvalidRule, len(pattern), MaxRegexRuleBytes)
	}
	return pattern, nil
}

// regexQuote escapes a string for literal use in an RE2 pattern.
//
// It is regexp.QuoteMeta spelled out rather than imported so that the rule this
// engine depends on — "every metacharacter is escaped" — is visible and
// testable at the point it matters.
func regexQuote(s string) string {
	const meta = `\.+*?()|[]{}^$`

	var b strings.Builder
	b.Grow(len(s) + 8)

	for _, r := range s {
		if strings.ContainsRune(meta, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// normalisePath makes a path comparable and filter-safe.
//
// An empty path becomes "/" so that a bare host produces a usable pattern.
func normalisePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// pathSegments counts the non-empty segments of a path.
func pathSegments(p string) int {
	p = normalisePath(p)
	if p == "/" {
		return 0
	}

	n := 0
	for _, seg := range strings.Split(p, "/") {
		if seg != "" {
			n++
		}
	}
	return n
}
