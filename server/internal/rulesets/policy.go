package rulesets

import (
	"fmt"

	"cyberguard/server/internal/verdicts"
)

// The eligibility policy from docs/security-and-privacy.md §6, expressed as code.
//
// # What the documentation specifies, and what it does not
//
// The document is unusually clear on the important parts. It states that:
//
//   - No verdict becomes a rule automatically.
//   - `inconclusive` and `unknown` are **never** eligible. "Unknown is not
//     safe, and unknown is not dangerous."
//   - `suspicious` and `no_threat_detected` are never eligible.
//   - `malicious` requires corroboration, "e.g. ≥2 independent fingerprints on
//     the host, or a confidence floor".
//   - Scope is a ladder — exact URL → URL prefix → registrable domain — "each
//     requiring stronger evidence than the last".
//   - An invalid rule fails the whole snapshot.
//
// Two things it does **not** specify, and this file is explicit about both:
//
//  1. **The thresholds.** The corroboration rule is given as an example ("e.g."),
//     not a decision, and the ladder's relative spacing is given as a direction,
//     not numbers. The numbers below are a choice, documented in
//     [ADR 0018](decisions/0018-ruleset-thresholds-and-scope.md) and
//     configurable. They are conservative — high enough that a rule is very
//     unlikely to be a false positive — and they are the first thing to revisit
//     once real data exists.
//
//  2. **The confidence floor.** There is no confidence field anywhere in the
//     data model, so the alternative the document offers cannot be implemented
//     without inventing provider semantics. It is therefore not implemented.
//     Claiming a confidence value the provider never reported is precisely the
//     kind of fabrication this project refuses elsewhere.

// Scope is how broad a generated rule is.
//
// The ordering is the ladder: a rule with a broader Scope needs more evidence.
type Scope string

const (
	// ScopeExactURL blocks one exact URL.
	ScopeExactURL Scope = "exact_url"
	// ScopeURLPrefix blocks one URL prefix on one host.
	ScopeURLPrefix Scope = "url_prefix"
	// ScopeRegistrableDomain blocks a registrable domain and its subdomains.
	ScopeRegistrableDomain Scope = "registrable_domain"
)

// Valid reports whether s is a defined scope.
func (s Scope) Valid() bool {
	switch s {
	case ScopeExactURL, ScopeURLPrefix, ScopeRegistrableDomain:
		return true
	default:
		return false
	}
}

// ParseScope converts a configured value into a Scope.
func ParseScope(v string) (Scope, error) {
	s := Scope(v)
	if !s.Valid() {
		return "", fmt.Errorf("rulesets: unknown scope %q", v)
	}
	return s, nil
}

// Severity orders scopes from narrowest to broadest. A lower value is narrower.
func (s Scope) Severity() int {
	switch s {
	case ScopeExactURL:
		return 0
	case ScopeURLPrefix:
		return 1
	case ScopeRegistrableDomain:
		return 2
	default:
		return 3
	}
}

// String returns the wire value.
func (s Scope) String() string { return string(s) }

// Policy is the configured eligibility policy.
//
// Every threshold is a field rather than a constant so an operator can tune it
// without a code change. That matters more than usual here: these numbers encode
// a judgement about false positives, and the right judgement depends on data
// that does not exist yet.
type Policy struct {
	// MaxScope is the broadest scope this deployment will ever emit. It is the
	// primary safety valve: setting it to ScopeExactURL makes it impossible to
	// publish a rule that affects more than one exact URL, whatever the
	// thresholds say.
	MaxScope Scope

	// MinCorroboration is how many independent malicious findings on a host
	// are required before any rule is emitted for a URL on that host.
	//
	// "Independent" means distinct URL fingerprints. Two scans of the same URL
	// are one finding, not two, however many times they run.
	MinCorroboration int

	// MinCorroborationPrefix is the same, for a URL-prefix rule.
	MinCorroborationPrefix int

	// MinCorroborationDomain is how many independent malicious findings across
	// a registrable domain are required for a domain-wide rule.
	MinCorroborationDomain int

	// MaxRules caps a snapshot. Chrome enforces a per-ruleset limit and a
	// total rule-count limit; a cap keeps the response inside both, and stops
	// one noisy campaign from producing a snapshot no client can hold.
	//
	// When the cap is hit, rules are dropped from the *narrowest* evidence
	// first? No — from the *broadest* first. A host-wide rule and a single-URL
	// rule protect the same host; keeping the narrower one when space runs out
	// is both safer and more informative.
	MaxRules int

	// MinPathSegments is how many path segments a prefix must have before a
	// prefix rule is emitted. One segment such as `/login` is a specific page;
	// zero segments is the host itself, which is domain scope wearing a
	// different name.
	MinPathSegments int
}

// DefaultPolicy is the policy used when nothing is configured.
//
// The thresholds follow the documentation's own example for the narrowest rung
// (2) and step up from there. See the package comment for why these are a
// decision rather than a specification.
func DefaultPolicy() Policy {
	return Policy{
		MaxScope: ScopeExactURL,
		// The document's example figure, applied to the narrowest scope where
		// it was written.
		MinCorroboration:       2,
		MinCorroborationPrefix: 3,
		MinCorroborationDomain: 5,
		MaxRules:               5000,
		MinPathSegments:        1,
	}
}

// Validate checks the policy is internally coherent.
//
// A policy whose thresholds decrease with breadth would make the ladder
// meaningless: a broader rule would need *less* evidence than a narrower one,
// which is precisely the over-blocking the policy exists to prevent.
func (p Policy) Validate() error {
	if !p.MaxScope.Valid() {
		return fmt.Errorf("rulesets: MaxScope %q is not a defined scope", p.MaxScope)
	}
	if p.MinCorroboration < 1 {
		return fmt.Errorf("rulesets: MinCorroboration must be at least 1, got %d", p.MinCorroboration)
	}
	if p.MinCorroborationPrefix < p.MinCorroboration {
		return fmt.Errorf("rulesets: MinCorroborationPrefix (%d) must be at least MinCorroboration (%d); "+
			"a broader scope must not need less evidence", p.MinCorroborationPrefix, p.MinCorroboration)
	}
	if p.MinCorroborationDomain < p.MinCorroborationPrefix {
		return fmt.Errorf("rulesets: MinCorroborationDomain (%d) must be at least MinCorroborationPrefix (%d); "+
			"a broader scope must not need less evidence", p.MinCorroborationDomain, p.MinCorroborationPrefix)
	}
	if p.MaxRules < 1 {
		return fmt.Errorf("rulesets: MaxRules must be at least 1, got %d", p.MaxRules)
	}
	if p.MinPathSegments < 0 {
		return fmt.Errorf("rulesets: MinPathSegments must not be negative, got %d", p.MinPathSegments)
	}
	return nil
}

// corroborationRequired is how many findings a scope needs.
func (p Policy) corroborationRequired(s Scope) int {
	switch s {
	case ScopeURLPrefix:
		return p.MinCorroborationPrefix
	case ScopeRegistrableDomain:
		return p.MinCorroborationDomain
	default:
		return p.MinCorroboration
	}
}

// EligibleVerdict reports whether a verdict can ever produce a rule, ignoring
// corroboration.
//
// It is exported so an ineligible finding is filtered before it reaches a
// corroboration query, rather than after.
//
// The table is the documentation's, unchanged. `malicious` is the only verdict
// that is ever eligible, and even then only with corroboration.
//
// The two "never" rows are worth stating in code rather than only in prose,
// because they are the ones a future change is most likely to break: a failed,
// timed-out or unrecognised analysis must not become a browser block.
func EligibleVerdict(v verdicts.Verdict) bool {
	switch v {
	case verdicts.Malicious:
		return true
	case verdicts.Suspicious, verdicts.NoThreatDetected, verdicts.Inconclusive, verdicts.Unknown:
		return false
	default:
		// An undefined verdict is treated as ineligible. Nothing unknown
		// should ever reach a blocking rule.
		return false
	}
}

// EligibleScopes returns the scopes a host's evidence supports, narrowest
// first.
//
// It is the ladder: each rung is returned only when the evidence clears that
// rung's threshold, so a broader rule is never easier to earn than a narrower
// one. See pickScope for why reaching a higher rung broadens the rule rather
// than being a bonus.
func (p Policy) EligibleScopes(ev Corroboration, hasPath bool) []Scope {
	var out []Scope

	// Each rung is judged against its own count. Collapsing the three into a
	// single number would make the thresholds indistinguishable: domain-wide
	// evidence would then license a single-URL rule on a host nobody else has
	// ever flagged.
	if ev.HostFingerprints >= p.MinCorroboration {
		out = append(out, ScopeExactURL)
	}
	if hasPath && ev.PrefixFingerprints >= p.MinCorroborationPrefix {
		out = append(out, ScopeURLPrefix)
	}
	if ev.DomainFingerprints >= p.MinCorroborationDomain {
		out = append(out, ScopeRegistrableDomain)
	}

	// Clip to the configured ceiling.
	kept := out[:0]
	for _, s := range out {
		if s.Severity() <= p.MaxScope.Severity() {
			kept = append(kept, s)
		}
	}
	return kept
}
