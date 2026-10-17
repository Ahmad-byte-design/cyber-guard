package urlintel

import (
	"errors"
	"strings"
	"testing"
)

// The cases below were chosen because each one either broke the hand-rolled
// implementation that preceded the Public Suffix List, or is a class of host a
// security product must get right.

func TestNormalizeHostname(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, in, want string }{
		{"already canonical", "example.com", "example.com"},
		{"upper case", "WWW.Example.COM", "www.example.com"},
		{"mixed case", "Shop.Example.co.uk", "shop.example.co.uk"},
		{"trailing dot", "example.com.", "example.com"},
		{"trailing dot with subdomains", "a.b.example.com.", "a.b.example.com"},
		{"surrounding whitespace", "  example.com  ", "example.com"},
		{"ipv4 literal", "192.168.1.1", "192.168.1.1"},
		{"ipv6 literal unbracketed", "2001:db8::1", "2001:db8::1"},
		{"ipv6 bracketed", "[2001:db8::1]", "2001:db8::1"},
		{"punycode passthrough", "xn--80ak6aa92e.com", "xn--80ak6aa92e.com"},
		{"unicode is punycoded", "bücher.example", "xn--bcher-kva.example"},
		{"hyphen inside label", "my-site.example.com", "my-site.example.com"},

		// Single-label hosts are syntactically valid. They have no
		// registrable domain, but rejecting them here would conflate
		// normalisation with suffix resolution.
		{"bare local name", "localhost", "localhost"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeHostname(tc.in)
			if err != nil {
				t.Fatalf("NormalizeHostname(%q) = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Malformed hosts must be rejected rather than normalised into something that
// looks valid.
func TestNormalizeHostnameRejectsMalformed(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, in string }{
		{"empty", ""},
		{"whitespace only", "   "},
		{"empty label", "example..com"},
		{"leading dot", ".example.com"},
		{"label too long", strings.Repeat("a", 64) + ".com"},
		{"hostname too long", strings.Repeat("a.", 130) + "com"},
		{"label starting with hyphen", "-example.com"},
		{"label ending with hyphen", "example-.com"},
		{"underscore", "ex_ample.com"},
		{"space inside", "exa mple.com"},
		{"only a dot", "."},
		{"double trailing dot", "example.com.."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeHostname(tc.in)
			if err == nil {
				t.Fatalf("NormalizeHostname(%q) = %q, want an error", tc.in, got)
			}
			if !IsValidation(err) {
				t.Errorf("error %v is not a *ValidationError", err)
			}
		})
	}
}

// ---------------------------------------------------------- registrable domain

func TestRegistrableDomain(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, in, want string }{
		// Ordinary domains: the registrable domain is the host itself.
		{"simple domain", "example.com", "example.com"},
		{"subdomain", "login.example.com", "example.com"},
		{"deep subdomain", "a.b.c.example.com", "example.com"},

		// Multi-label public suffixes. The registrable domain keeps the
		// suffix plus one label.
		{"co.uk", "shop.example.co.uk", "example.co.uk"},
		{"com.au", "shop.example.com.au", "example.com.au"},
		{"co.jp", "a.b.example.co.jp", "example.co.jp"},
		{"deep with multi-label suffix", "deep.sub.example.co.uk", "example.co.uk"},

		// Private suffixes from the PSL are handled like public ones: the
		// suffix itself is not a registrable domain.
		{"private suffix", "user.github.io", "user.github.io"},
		{"private suffix subdomain", "a.user.github.io", "user.github.io"},

		// gov.uk is a public suffix, so the label under it is registrable.
		{"under gov.uk", "www.gov.uk", "www.gov.uk"},

		// service.gov.uk is itself listed in the PSL as a private suffix, so
		// it has no registrable domain at all. Verified against the list
		// rather than assumed — a hand-written rule would have returned it.
		{"private suffix under gov.uk", "x.service.gov.uk", "x.service.gov.uk"},

		// Internationalised.
		{"punycode", "xn--80ak6aa92e.com", "xn--80ak6aa92e.com"},

		// Input is normalised first, so spelling must not change the answer.
		{"upper case", "WWW.EXAMPLE.COM", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := RegistrableDomain(tc.in)
			if err != nil {
				t.Fatalf("RegistrableDomain(%q) = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("RegistrableDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Every input here was misclassified by the hand-rolled implementation this
// replaced. Each must now be refused rather than guessed at.
func TestRegistrableDomainRefusesToGuess(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, in string }{
		{"public suffix itself", "co.uk"},
		{"another public suffix", "com"},
		{"gov.uk is a suffix", "gov.uk"},
		{"service.gov.uk is itself a private suffix", "service.gov.uk"},
		{"bare local name", "localhost"},
		{"ipv4", "8.8.8.8"},
		{"private ipv4", "192.168.1.1"},
		{"ipv6", "2001:db8::1"},
		{"empty", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := RegistrableDomain(tc.in)
			if err == nil {
				t.Fatalf("RegistrableDomain(%q) = %q, want an error", tc.in, got)
			}
			if !errors.Is(err, ErrNotRegistrable) && !IsValidation(err) {
				t.Errorf("error = %v, want ErrNotRegistrable or a validation error", err)
			}
		})
	}
}

// The single most important property: a public suffix is never returned as a
// registrable domain. If it were, every UK site would share one reputation and
// one domain-scoped rule.
func TestPublicSuffixIsNeverARegistrableDomain(t *testing.T) {
	t.Parallel()

	for _, suffix := range []string{
		"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
		"co.jp", "co.nz", "co.za", "com.br", "com.mx", "com.cn", "github.io",
	} {
		got, err := RegistrableDomain(suffix)
		if err == nil {
			t.Errorf("public suffix %q returned a registrable domain %q", suffix, got)
		}
	}
}

// An IP address must never produce a registrable domain, because "1.1" is not
// an organisation.
func TestIPAddressesProduceNoRegistrableDomain(t *testing.T) {
	t.Parallel()

	for _, ip := range []string{"8.8.8.8", "192.168.1.1", "10.0.0.1", "255.255.255.255", "2001:db8::1"} {
		got, err := RegistrableDomain(ip)
		if err == nil {
			t.Errorf("IP %q produced registrable domain %q", ip, got)
		}
	}
}

// ----------------------------------------------------------------- ParseHost

func TestParseHost(t *testing.T) {
	t.Parallel()

	t.Run("ordinary domain", func(t *testing.T) {
		t.Parallel()
		info, err := ParseHost("Shop.Example.co.uk.")
		if err != nil {
			t.Fatalf("ParseHost: %v", err)
		}
		// The original hostname is preserved separately from the domain.
		if info.Hostname != "shop.example.co.uk" {
			t.Errorf("Hostname = %q, want the normalised original", info.Hostname)
		}
		if info.RegistrableDomain != "example.co.uk" {
			t.Errorf("RegistrableDomain = %q", info.RegistrableDomain)
		}
		if info.IsIP || info.IsLocal {
			t.Error("a public domain reported IsIP or IsLocal")
		}
	})

	t.Run("ip address", func(t *testing.T) {
		t.Parallel()
		info, err := ParseHost("192.168.1.1")
		if err != nil {
			t.Fatalf("ParseHost: %v", err)
		}
		if !info.IsIP {
			t.Error("IsIP = false for an IP literal")
		}
		if info.RegistrableDomain != "" {
			t.Errorf("RegistrableDomain = %q, want empty for an IP", info.RegistrableDomain)
		}
		if info.Hostname != "192.168.1.1" {
			t.Errorf("Hostname = %q, want the original preserved", info.Hostname)
		}
	})

	t.Run("localhost", func(t *testing.T) {
		t.Parallel()
		info, err := ParseHost("localhost")
		if err != nil {
			t.Fatalf("ParseHost: %v", err)
		}
		if !info.IsLocal {
			t.Error("IsLocal = false for localhost")
		}
		if info.RegistrableDomain != "" {
			t.Errorf("RegistrableDomain = %q, want empty for localhost", info.RegistrableDomain)
		}
	})

	t.Run("public suffix has no registrable domain", func(t *testing.T) {
		t.Parallel()
		// A valid host, so no error — but it belongs to no registrable domain.
		info, err := ParseHost("co.uk")
		if err != nil {
			t.Fatalf("ParseHost: %v", err)
		}
		if info.RegistrableDomain != "" {
			t.Errorf("RegistrableDomain = %q for a public suffix, want empty", info.RegistrableDomain)
		}
		if info.Hostname != "co.uk" {
			t.Errorf("Hostname = %q, want the original preserved", info.Hostname)
		}
	})

	t.Run("malformed host errors", func(t *testing.T) {
		t.Parallel()
		if _, err := ParseHost("example..com"); err == nil {
			t.Error("a malformed host was accepted")
		}
	})
}

// The hostname and the registrable domain are different things and must not be
// conflated: host-scoped and domain-scoped verdicts are different data types.
func TestHostnameAndRegistrableDomainAreDistinct(t *testing.T) {
	t.Parallel()

	info, err := ParseHost("login.bank.example.co.uk")
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	if info.Hostname != "login.bank.example.co.uk" {
		t.Errorf("Hostname = %q, want the full original host", info.Hostname)
	}
	if info.RegistrableDomain != "example.co.uk" {
		t.Errorf("RegistrableDomain = %q", info.RegistrableDomain)
	}
	if info.Hostname == info.RegistrableDomain {
		t.Error("hostname and registrable domain collapsed to the same value")
	}
}

// Normalisation must be idempotent: normalising a normalised host changes
// nothing, or repeated processing could drift.
func TestNormalizeIsIdempotent(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"EXAMPLE.COM", "shop.example.co.uk.", "xn--80ak6aa92e.com", "192.168.1.1",
	} {
		once, err := NormalizeHostname(host)
		if err != nil {
			t.Fatalf("NormalizeHostname(%q): %v", host, err)
		}
		twice, err := NormalizeHostname(once)
		if err != nil {
			t.Fatalf("NormalizeHostname(%q): %v", once, err)
		}
		if once != twice {
			t.Errorf("%q normalised to %q then %q", host, once, twice)
		}
	}
}
