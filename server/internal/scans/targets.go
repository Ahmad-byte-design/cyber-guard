package scans

import (
	"net/netip"
	"net/url"
	"strings"

	"cyberguard/server/internal/urlintel"
)

// Deciding whether a submitted URL may be handed to an external sandbox.
//
// # What this is, and what it is not
//
// CyberGuard never fetches the submitted URL itself — the sandbox does. So
// this is not an SSRF filter protecting *this* process's network, and it is
// deliberately not dressed up as one. Blocking addresses here would not stop a
// request from reaching a loopback interface, because CyberGuard issues no
// request at all.
//
// What it does stop is real and worth stating plainly:
//
//   - Leaking a private URL to a third party. An internal sharepoint host or a
//     router admin page is submitted to an external service the moment the
//     sandbox detonates it. The internal hostname and its existence are
//     disclosed to the provider, and the sandbox can report back what it found.
//   - Using the sandbox as a probe into the *provider's* network and, by
//     extension, into any network reachable from it.
//   - Wasting quota on URLs that cannot produce a meaningful verdict.
//
// # What is deliberately permitted
//
// Documentation names such as `example.test` are allowed through. They are
// reserved and non-resolvable, so they disclose nothing and probe nothing;
// refusing them would only break this project's own documented examples.
//
// # Why this is not a DNS-resolution check
//
// Resolving the hostname here and checking the answer would be worse, not
// better. It introduces a TOCTOU window — the sandbox resolves the name again
// at detonation time and gets a different, internal address — it costs a DNS
// round trip on the submission hot path, and it makes the check depend on a
// third-party resolver being both available and trustworthy. A hostname-based
// rule fails honestly for attacker-controlled names, which is acceptable when
// the target is the provider's sandbox rather than our own network.

// internalSuffixes are hostname suffixes that resolve inside a private network
// by convention.
//
// The list is deliberately short and conventional rather than exhaustive. An
// attempt to enumerate every internal TLD would be unbounded, and the ones
// that matter are the ones RFC 6761, RFC 8375 and common enterprise DNS
// actually reserve.
var internalSuffixes = []string{
	".localhost", // RFC 6761
	".local",     // mDNS
	".internal",  // widely used for private zones
	".intranet",
	".lan",
	".corp",
	".private",
	".home.arpa", // RFC 8375
	".arpa",      // infrastructure, never a registrable target
	".onion",
	".localdomain",
}

// exactInternalHosts are names that are internal regardless of suffix.
var exactInternalHosts = map[string]bool{
	"localhost":     true,
	"metadata":      true,
	"broadcasthost": true,
}

// CheckTarget reports whether a URL may be submitted to an external provider.
//
// It takes an already-parsed, already-canonical URL rather than a string, so
// the host that gets checked is the same one the fingerprint was computed from
// and the same one the worker will send. Parsing twice would be a chance for
// the two views of the URL to disagree.
func CheckTarget(u *url.URL) error {
	if u == nil {
		return ErrDisallowedTarget
	}

	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return ErrDisallowedTarget
	}

	// urlintel normalisation lower-cases, punycodes and strips the trailing
	// dot, so a check here cannot be bypassed by spelling.
	normalised, err := urlintel.NormalizeHostname(host)
	if err != nil || normalised == "" {
		return ErrDisallowedTarget
	}

	if addr, err := netip.ParseAddr(normalised); err == nil {
		return checkIP(addr)
	}

	if exactInternalHosts[normalised] {
		return ErrDisallowedTarget
	}
	// A single label is either loopback by another name or an intranet host.
	// Neither is a legitimate analysis target.
	if !strings.Contains(normalised, ".") {
		return ErrDisallowedTarget
	}
	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(normalised, suffix) {
			return ErrDisallowedTarget
		}
	}

	// Reserved documentation names — `.test`, `.example`, `.invalid` — are
	// deliberately NOT rejected. The instinct is to refuse anything
	// non-resolvable, but that would reject for a reason unrelated to what
	// this check is for: a documentation name cannot resolve on the public
	// internet, so submitting one leaks nothing and probes no private network,
	// which are the only two risks here. They are also the example domain
	// throughout this project's own API contract, and a rule that made every
	// documented curl example return 422 would be aimed at the wrong thing.
	return nil
}

// checkIP rejects addresses that are not publicly routable.
//
// Every branch is a documented special-purpose range. Listing them explicitly
// rather than testing "is it public?" against a maintained table means the
// behaviour is auditable and cannot change when a dependency updates.
func checkIP(addr netip.Addr) error {
	// Unmap first: an IPv4 address smuggled in as ::ffff:127.0.0.1 is still
	// loopback, and checking it as IPv6 would miss it.
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback(), // 127.0.0.0/8, ::1
		addr.IsPrivate(),            // 10/8, 172.16/12, 192.168/16, fc00::/7
		addr.IsLinkLocalUnicast(),   // 169.254/16, fe80::/10
		addr.IsLinkLocalMulticast(), // 224.0.0.0/24, ff02::/16
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsUnspecified(): // 0.0.0.0, ::
		return ErrDisallowedTarget
	}

	// Ranges with no address assigned, which are never valid analysis targets.
	if addr.Is4() {
		v4 := addr.As4()
		switch {
		case v4[0] == 0: // 0.0.0.0/8 "this network"
			return ErrDisallowedTarget
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // 100.64.0.0/10 CGNAT
			return ErrDisallowedTarget
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24 IETF protocol
			return ErrDisallowedTarget
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // 192.0.2.0/24 TEST-NET-1
			return ErrDisallowedTarget
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15 benchmarking
			return ErrDisallowedTarget
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // 198.51.100.0/24 TEST-NET-2
			return ErrDisallowedTarget
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // 203.0.113.0/24 TEST-NET-3
			return ErrDisallowedTarget
		case v4[0] >= 240: // 240.0.0.0/4 reserved, includes 255.255.255.255
			return ErrDisallowedTarget
		}
		return nil
	}

	v6 := addr.As16()
	if v6[0] == 0x01 && v6[1] == 0x00 && v6[2] == 0x00 && v6[3] == 0x00 {
		// 100::/64 discard-only
		return ErrDisallowedTarget
	}
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8 {
		// 2001:db8::/32 documentation
		return ErrDisallowedTarget
	}
	if v6[0]&0xfe == 0x01 && v6[1] == 0x00 {
		// Anything beginning 0100::/64 is reserved by RFC 4380 / 7343.
		return ErrDisallowedTarget
	}
	return nil
}
