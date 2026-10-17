package scans

import (
	"errors"
	"net/url"
	"testing"

	"cyberguard/server/internal/urlintel"
)

// The target check decides whether a URL may cross the network boundary to an
// external sandbox. Every case here is one where sending the URL would either
// disclose an internal host or probe a network that is not the public one.

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := urlintel.Validate(raw)
	if err != nil {
		t.Fatalf("Validate(%q): %v", raw, err)
	}
	return u
}

// Loopback, private, link-local and reserved addresses are refused.
func TestCheckTargetRefusesNonPublicAddresses(t *testing.T) {
	t.Parallel()

	refused := []struct{ name, target string }{
		{"ipv4 loopback", "http://127.0.0.1/"},
		{"ipv4 loopback high", "http://127.99.1.1/"},
		{"ipv6 loopback", "http://[::1]/"},
		{"private 10/8", "http://10.1.2.3/"},
		{"private 172.16/12", "http://172.16.5.4/"},
		{"private 192.168/16", "http://192.168.0.1/admin"},
		{"ipv6 unique local", "http://[fd00::1]/"},
		{"link local v4", "http://169.254.169.254/latest/meta-data/"},
		{"link local v6", "http://[fe80::1]/"},
		{"unspecified", "http://0.0.0.0/"},
		{"unspecified v6", "http://[::]/"},
		{"cgnat", "http://100.64.0.1/"},
		{"multicast", "http://224.0.0.1/"},
		{"broadcast", "http://255.255.255.255/"},
		{"reserved 240/4", "http://240.0.0.1/"},
		{"test-net-1", "http://192.0.2.1/"},
		{"benchmarking", "http://198.18.0.1/"},
		// An IPv4 address smuggled inside an IPv6 literal must not slip past
		// the IPv4 rules.
		{"ipv4-mapped loopback", "http://[::ffff:127.0.0.1]/"},
		{"ipv4-mapped private", "http://[::ffff:192.168.1.1]/"},
	}

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := CheckTarget(mustParse(t, tc.target)); !errors.Is(err, ErrDisallowedTarget) {
				t.Errorf("CheckTarget(%q) = %v, want ErrDisallowedTarget", tc.target, err)
			}
		})
	}
}

// Internal hostnames are refused even though they are not IP literals.
func TestCheckTargetRefusesInternalNames(t *testing.T) {
	t.Parallel()

	refused := []string{
		"http://localhost/",
		"http://localhost:8080/admin",
		"http://app.localhost/",
		"http://printer.local/",
		"http://nas.local/status",
		"http://fileserver.internal/share",
		"http://wiki.intranet/",
		"http://gateway.lan/",
		"http://host.corp/",
		"http://box.private/",
		// The suffix must end the name: a public domain that merely contains
		// an internal-looking label, such as attacker.com hosting a host
		// called "internal", is not an internal target.
		"http://build.intranet/",
		"http://router.home.arpa/",
		// A bare label is either loopback by another name or an intranet host.
		"http://intranet/",
		"http://metadata/",
		"http://database/",
		// Infrastructure TLD.
		"http://router.arpa/",
	}

	for _, target := range refused {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			if err := CheckTarget(mustParse(t, target)); !errors.Is(err, ErrDisallowedTarget) {
				t.Errorf("CheckTarget(%q) = %v, want ErrDisallowedTarget", target, err)
			}
		})
	}
}

// Public hosts are allowed.
func TestCheckTargetAllowsPublicHosts(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"http://example.com/",
		"https://example.com/path?q=1",
		"https://shop.example.co.uk/",
		"https://sub.domain.example.org:8443/x",
		"https://xn--80ak6aa92e.com/",
		// An internal-looking label inside a public domain is not internal.
		"http://build.intranet.example.com/",
		"http://internal.attacker.com/",
		// Public addresses.
		"http://1.1.1.1/",
		"http://8.8.8.8/",
		"http://93.184.216.34/",
		"https://[2606:2800:220:1:248:1893:25c8:1946]/",
	}

	for _, target := range allowed {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			if err := CheckTarget(mustParse(t, target)); err != nil {
				t.Errorf("CheckTarget(%q) = %v, want nil", target, err)
			}
		})
	}
}

// Reserved documentation names are permitted, and deliberately so.
//
// A name like example.test cannot resolve on the public internet, so submitting
// one discloses nothing and probes nothing. It is also the example domain
// throughout this project's API contract, so refusing it would make every
// documented example fail. The omission is a decision, not an oversight.
func TestCheckTargetAllowsDocumentationNames(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"https://example.test/login",
		"http://example.example/path",
		"http://anything.invalid/",
	} {
		if err := CheckTarget(mustParse(t, target)); err != nil {
			t.Errorf("CheckTarget(%q) = %v, want nil: documentation names are not internal targets", target, err)
		}
	}
}

// Spelling must not be a bypass: case, a trailing dot and punycode are all
// normalised before the check, so none of them slips an internal name through.
func TestCheckTargetNormalisesBeforeDeciding(t *testing.T) {
	t.Parallel()

	// Case and a trailing dot are cosmetic, but the check must see past them.
	if err := CheckTarget(mustParse(t, "http://LOCALHOST/")); !errors.Is(err, ErrDisallowedTarget) {
		t.Error("an upper-case localhost was allowed")
	}
	if err := CheckTarget(mustParse(t, "http://printer.local./")); !errors.Is(err, ErrDisallowedTarget) {
		t.Error("a trailing dot bypassed the internal-suffix check")
	}

	// A Unicode host is punycoded before the check, so a confusable spelling of
	// an internal name cannot slip past.
	puny, err := urlintel.NormalizeHostname("рrinter.local")
	if err == nil {
		if CheckTarget(&url.URL{Scheme: "http", Host: puny}) == nil {
			t.Errorf("a punycoded internal name %q was allowed", puny)
		}
	}
}

// A nil URL and a URL with no host are refused rather than panicking.
func TestCheckTargetHandlesDegenerateInput(t *testing.T) {
	t.Parallel()

	if err := CheckTarget(nil); !errors.Is(err, ErrDisallowedTarget) {
		t.Errorf("CheckTarget(nil) = %v, want ErrDisallowedTarget", err)
	}
	if err := CheckTarget(&url.URL{Scheme: "http"}); !errors.Is(err, ErrDisallowedTarget) {
		t.Errorf("a URL with no host = %v, want ErrDisallowedTarget", err)
	}
	if err := CheckTarget(&url.URL{Scheme: "http", Host: "   "}); !errors.Is(err, ErrDisallowedTarget) {
		t.Errorf("a URL with a blank host = %v, want ErrDisallowedTarget", err)
	}
}

// The ports an internal service listens on must not become a bypass, whether or
// not they are standard.
func TestPortsDoNotAffectTheDecision(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"http://127.0.0.1:80/",
		"http://127.0.0.1:22/",
		"http://127.0.0.1:6379/",
		"http://127.0.0.1:27017/",
		"https://192.168.1.1:443/admin",
	} {
		if err := CheckTarget(mustParse(t, target)); !errors.Is(err, ErrDisallowedTarget) {
			t.Errorf("CheckTarget(%q) = %v, want ErrDisallowedTarget", target, err)
		}
	}
}
