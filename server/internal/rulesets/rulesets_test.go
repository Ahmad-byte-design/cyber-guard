package rulesets

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cyberguard/server/internal/verdicts"
)

// The eligibility policy is the highest-consequence decision in this package: it
// decides what becomes a user-visible block. These tests are the guard on it.

// fixedEvidence answers corroboration from a table keyed by fingerprint.
type fixedEvidence struct {
	counts map[string]Corroboration
	err    error
}

func (f fixedEvidence) Corroboration(_ context.Context, refs []Reference, _ time.Time) (map[string]Corroboration, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]Corroboration, len(refs))
	for _, r := range refs {
		if c, ok := f.counts[r.Fingerprint]; ok {
			out[r.Fingerprint] = c
		}
	}
	return out, nil
}

var testNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func candidate(fingerprint, host, path string, verdict verdicts.Verdict, expires time.Time) Candidate {
	return Candidate{
		Fingerprint:       fingerprint,
		Hostname:          host,
		RegistrableDomain: domainOf(host),
		Verdict:           verdict,
		Scheme:            "https",
		PathPrefix:        path,
		AnalyzedAt:        testNow.Add(-time.Hour),
		ExpiresAt:         expires,
	}
}

func domainOf(host string) string {
	if i := strings.Index(host, "."); i > 0 && strings.Count(host, ".") >= 1 {
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2] + "." + parts[len(parts)-1]
		}
	}
	return host
}

func newGen(t *testing.T, p Policy, ev EvidenceSource) *Generator {
	t.Helper()
	g, err := NewGenerator(p, ev)
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	return g
}

// ------------------------------------------------------------ eligibility

// Only `malicious` may ever become a rule. Every other verdict is ineligible
// by construction, which is what makes "unknown is not safe" mechanical rather
// than a matter of reviewer attention.
func TestOnlyMaliciousIsEligible(t *testing.T) {
	t.Parallel()

	eligible := map[verdicts.Verdict]bool{
		verdicts.Malicious:        true,
		verdicts.Suspicious:       false,
		verdicts.NoThreatDetected: false,
		verdicts.Inconclusive:     false,
		verdicts.Unknown:          false,
	}

	for verdict, want := range eligible {
		if got := EligibleVerdict(verdict); got != want {
			t.Errorf("EligibleVerdict(%q) = %v, want %v", verdict, got, want)
		}
	}
}

// An undefined verdict must never be treated as eligible. That is the failure
// mode a future change is most likely to introduce.
func TestUndefinedVerdictIsIneligible(t *testing.T) {
	t.Parallel()

	if EligibleVerdict(verdicts.Verdict("looks_fine_to_me")) {
		t.Error("an unrecognised verdict was treated as rule-eligible")
	}
	if EligibleVerdict(verdicts.Verdict("")) {
		t.Error("an empty verdict was treated as rule-eligible")
	}
}

// End to end: no verdict other than malicious ever produces a rule, however
// much evidence exists.
func TestNonMaliciousFindingsNeverProduceRules(t *testing.T) {
	t.Parallel()

	for _, verdict := range []verdicts.Verdict{
		verdicts.Suspicious, verdicts.NoThreatDetected, verdicts.Inconclusive, verdicts.Unknown,
	} {
		t.Run(verdict.String(), func(t *testing.T) {
			t.Parallel()

			g := newGen(t, DefaultPolicy(), fixedEvidence{counts: map[string]Corroboration{
				"fp1": {HostFingerprints: 99, PrefixFingerprints: 99, DomainFingerprints: 99},
			}})

			snap, err := g.Generate(t.Context(), []Candidate{
				candidate("fp1", "evil.test", "/login", verdict, testNow.Add(time.Hour)),
			}, testNow)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(snap.Rules) != 0 {
				t.Errorf("%s produced %d rules; it must produce none", verdict, len(snap.Rules))
			}
		})
	}
}

// ---------------------------------------------------------- corroboration

// A single malicious finding is not enough: the policy requires corroboration,
// because provider false positives block real sites.
func TestSingleFindingProducesNoRule(t *testing.T) {
	t.Parallel()

	g := newGen(t, DefaultPolicy(), fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 1},
	}})

	snap, err := g.Generate(t.Context(), []Candidate{
		candidate("fp1", "evil.test", "/login", verdicts.Malicious, testNow.Add(time.Hour)),
	}, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(snap.Rules) != 0 {
		t.Errorf("one uncorroborated finding produced %d rules; it must produce none", len(snap.Rules))
	}
}

// Two independent findings on the host are enough for the narrowest scope.
func TestCorroboratedFindingProducesAnExactURLRule(t *testing.T) {
	t.Parallel()

	g := newGen(t, DefaultPolicy(), fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 2, PrefixFingerprints: 2, DomainFingerprints: 2},
	}})

	snap, err := g.Generate(t.Context(), []Candidate{
		candidate("fp1", "evil.test", "/login", verdicts.Malicious, testNow.Add(time.Hour)),
	}, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(snap.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(snap.Rules))
	}

	rule := snap.Rules[0]
	if rule.Provenance.Scope != ScopeExactURL {
		t.Errorf("scope = %q, want the narrowest (exact_url)", rule.Provenance.Scope)
	}
	if rule.Condition.URLFilter != "" {
		t.Errorf("an exact-URL rule must not use urlFilter, got %q", rule.Condition.URLFilter)
	}
	if rule.Condition.Filter == nil {
		t.Fatal("an exact-URL rule must carry a filter")
	}
	// Anchored, so it can never match a longer URL.
	if !strings.HasPrefix(rule.Condition.Filter.RegexFilter, "^") ||
		!strings.HasSuffix(rule.Condition.Filter.RegexFilter, "$") {
		t.Errorf("regexFilter %q is not anchored", rule.Condition.Filter.RegexFilter)
	}
	// The host is present but regex-escaped, so a literal substring check on the
	// unescaped form would be wrong here.
	if !strings.Contains(rule.Condition.Filter.RegexFilter, `evil\.test`) {
		t.Errorf("regexFilter %q does not mention the host", rule.Condition.Filter.RegexFilter)
	}
}

// The ladder: broader scopes need strictly more evidence, and reaching a higher
// rung is what widens the rule.
//
// Escalation is deliberate — see pickScope. The default MaxScope of exact_url
// is what keeps that escalation from being observable in a default deployment.
func TestScopeLadderRequiresMoreEvidenceAsItBroadens(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		corrob    Corroboration
		wantScope Scope
		wantRules int
	}{
		{"below exact threshold", Corroboration{HostFingerprints: 1}, "", 0},
		{"exact only", Corroboration{HostFingerprints: 2, PrefixFingerprints: 2, DomainFingerprints: 2}, ScopeExactURL, 1},
		{"strong domain evidence escalates", Corroboration{HostFingerprints: 2, PrefixFingerprints: 2, DomainFingerprints: 99}, ScopeRegistrableDomain, 1},
		{"prefix reached", Corroboration{HostFingerprints: 3, PrefixFingerprints: 3, DomainFingerprints: 3}, ScopeURLPrefix, 1},
		{"domain reached", Corroboration{HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9}, ScopeRegistrableDomain, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy := DefaultPolicy()
			policy.MaxScope = ScopeRegistrableDomain
			g := newGen(t, policy, fixedEvidence{counts: map[string]Corroboration{"fp1": tc.corrob}})
			snap, err := g.Generate(t.Context(), []Candidate{
				candidate("fp1", "evil.test", "/login/page", verdicts.Malicious, testNow.Add(time.Hour)),
			}, testNow)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(snap.Rules) != tc.wantRules {
				t.Fatalf("got %d rules, want %d", len(snap.Rules), tc.wantRules)
			}
			if tc.wantRules == 0 {
				return
			}
			if got := snap.Rules[0].Provenance.Scope; got != tc.wantScope {
				t.Errorf("scope = %q, want %q", got, tc.wantScope)
			}
		})
	}
}

// A domain-wide rule must never be emitted at the exact-URL ceiling, however
// much evidence exists. This is the primary safety valve.
func TestMaxScopeCeilingIsRespected(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy()
	policy.MaxScope = ScopeExactURL

	g := newGen(t, policy, fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 50, PrefixFingerprints: 50, DomainFingerprints: 50},
	}})

	snap, err := g.Generate(t.Context(), []Candidate{
		candidate("fp1", "evil.test", "/login", verdicts.Malicious, testNow.Add(time.Hour)),
	}, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(snap.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(snap.Rules))
	}
	if got := snap.Rules[0].Provenance.Scope; got != ScopeExactURL {
		t.Errorf("scope = %q; the ceiling did not hold", got)
	}
}

// A registrable-domain rule must use the `||domain^` anchor, and must never
// fall back to the hostname or to a bare public suffix.
func TestDomainScopeUsesTheRegistrableDomain(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy()
	policy.MaxScope = ScopeRegistrableDomain
	policy.MinCorroboration, policy.MinCorroborationPrefix, policy.MinCorroborationDomain = 1, 1, 1

	g := newGen(t, policy, fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
	}})

	snap, err := g.Generate(t.Context(), []Candidate{
		{
			Fingerprint: "fp1", Hostname: "login.shop.evil.co.uk",
			RegistrableDomain: "evil.co.uk",
			Verdict:           verdicts.Malicious, Scheme: "https", PathPrefix: "/login",
			AnalyzedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(time.Hour),
		},
	}, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(snap.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(snap.Rules))
	}

	filter := snap.Rules[0].Condition.URLFilter
	if !strings.Contains(filter, "evil.co.uk") {
		t.Errorf("filter %q does not use the registrable domain", filter)
	}
	if strings.Contains(filter, "login.shop") {
		t.Errorf("filter %q pinned a subdomain as the domain", filter)
	}
	// "co.uk" alone would be catastrophic: it is a public suffix.
	if strings.HasPrefix(filter, "||co.uk^") {
		t.Errorf("filter %q treats a public suffix as a registrable domain", filter)
	}
}

// ---------------------------------------------------------------- expiry

// An expired finding must not produce a rule, however malicious it was.
func TestExpiredFindingProducesNoRule(t *testing.T) {
	t.Parallel()

	g := newGen(t, DefaultPolicy(), fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 10, PrefixFingerprints: 10, DomainFingerprints: 10},
	}})

	for _, tc := range []struct {
		name    string
		expires time.Time
	}{
		{"expired an hour ago", testNow.Add(-time.Hour)},
		{"expires exactly now", testNow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap, err := g.Generate(t.Context(), []Candidate{
				candidate("fp1", "evil.test", "/login", verdicts.Malicious, tc.expires),
			}, testNow)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(snap.Rules) != 0 {
				t.Errorf("an expired finding produced %d rules", len(snap.Rules))
			}
		})
	}
}

// ----------------------------------------------------------- determinism

// The same evidence must always produce byte-identical output.
//
// This is a correctness requirement, not tidiness: the digest decides whether
// the version is bumped, and an unstable order would bump it on every rebuild,
// making every client re-download continuously.
func TestOutputIsDeterministic(t *testing.T) {
	t.Parallel()

	ev := fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
		"fp2": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
		"fp3": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
	}}
	in := []Candidate{
		candidate("fp3", "zeta.test", "/c", verdicts.Malicious, testNow.Add(time.Hour)),
		candidate("fp1", "alpha.test", "/b", verdicts.Malicious, testNow.Add(time.Hour)),
		candidate("fp2", "alpha.test", "/a", verdicts.Malicious, testNow.Add(time.Hour)),
	}

	g := newGen(t, DefaultPolicy(), ev)
	first, err := g.Generate(t.Context(), in, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for range 20 {
		again, err := newGen(t, DefaultPolicy(), ev).Generate(t.Context(), in, testNow)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if again.Digest != first.Digest {
			t.Fatalf("digest changed between runs: %s then %s", first.Digest, again.Digest)
		}
		for i := range first.Rules {
			if again.Rules[i].ID != first.Rules[i].ID {
				t.Fatalf("rule %d changed id: %d then %d", i, first.Rules[i].ID, again.Rules[i].ID)
			}
		}
	}
}

// Input order must not change the output.
func TestInputOrderDoesNotAffectOutput(t *testing.T) {
	t.Parallel()

	ev := fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
		"fp2": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
	}}

	forward := []Candidate{
		candidate("fp1", "alpha.test", "/a", verdicts.Malicious, testNow.Add(time.Hour)),
		candidate("fp2", "beta.test", "/b", verdicts.Malicious, testNow.Add(time.Hour)),
	}
	reverse := []Candidate{forward[1], forward[0]}

	a, err := newGen(t, DefaultPolicy(), ev).Generate(t.Context(), forward, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := newGen(t, DefaultPolicy(), ev).Generate(t.Context(), reverse, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a.Digest != b.Digest {
		t.Errorf("input order changed the digest: %s vs %s", a.Digest, b.Digest)
	}
}

// The digest must not change when only corroboration counts change, because
// corroboration is not published. Otherwise a rising count on one host would
// republish the identical ruleset and make every client re-download for nothing.
func TestDigestIgnoresUnpublishedProvenance(t *testing.T) {
	t.Parallel()

	in := []Candidate{
		candidate("fp1", "alpha.test", "/a", verdicts.Malicious, testNow.Add(time.Hour)),
	}

	low, err := newGen(t, DefaultPolicy(), fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 2},
	}}).Generate(t.Context(), in, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	high, err := newGen(t, DefaultPolicy(), fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 40},
	}}).Generate(t.Context(), in, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if low.Digest != high.Digest {
		t.Error("the digest changed with corroboration counts, which are not published")
	}
}

// Removing a finding must change the digest, so a revoked rule is published as
// a removal rather than lingering silently.
func TestRemovingAFindingChangesTheDigest(t *testing.T) {
	t.Parallel()

	ev := fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
		"fp2": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
	}}

	withBoth, err := newGen(t, DefaultPolicy(), ev).Generate(t.Context(), []Candidate{
		candidate("fp1", "alpha.test", "/a", verdicts.Malicious, testNow.Add(time.Hour)),
		candidate("fp2", "beta.test", "/b", verdicts.Malicious, testNow.Add(time.Hour)),
	}, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	withOne, err := newGen(t, DefaultPolicy(), ev).Generate(t.Context(), []Candidate{
		candidate("fp1", "alpha.test", "/a", verdicts.Malicious, testNow.Add(time.Hour)),
	}, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if withBoth.Digest == withOne.Digest {
		t.Error("removing a rule did not change the digest; the removal would never publish")
	}
}

// --------------------------------------------------------------- ids, cap

// Chrome requires contiguous identifiers from 1.
func TestRuleIDsAreContiguousFromOne(t *testing.T) {
	t.Parallel()

	ev := fixedEvidence{counts: map[string]Corroboration{}}
	var in []Candidate
	for i := range 7 {
		fp := string(rune('a' + i))
		ev.counts[fp] = Corroboration{HostFingerprints: 5, PrefixFingerprints: 5, DomainFingerprints: 5}
		in = append(in, candidate(fp, "host"+string(rune('a'+i))+".test", "/p", verdicts.Malicious, testNow.Add(time.Hour)))
	}

	snap, err := newGen(t, DefaultPolicy(), ev).Generate(t.Context(), in, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for i, r := range snap.Rules {
		if r.ID != i+1 {
			t.Errorf("rule at position %d has id %d, want %d", i, r.ID, i+1)
		}
	}
}

// The cap must drop the broadest rules first, because a narrower rule protects
// the same host while blocking less.
func TestCapDropsBroadestRulesFirst(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy()
	policy.MaxScope = ScopeRegistrableDomain
	policy.MinCorroboration, policy.MinCorroborationPrefix, policy.MinCorroborationDomain = 1, 1, 1
	policy.MaxRules = 2

	ev := fixedEvidence{counts: map[string]Corroboration{}}
	var in []Candidate

	// Two candidates get only enough host evidence for an exact-URL rule, and
	// no prefix or domain evidence at all.
	ev.counts["narrow1"] = Corroboration{HostFingerprints: 1}
	ev.counts["narrow2"] = Corroboration{HostFingerprints: 1}
	in = append(in,
		candidate("narrow1", "a.test", "/a", verdicts.Malicious, testNow.Add(time.Hour)),
		candidate("narrow2", "b.test", "/b", verdicts.Malicious, testNow.Add(time.Hour)))

	// One candidate earns a broad, domain-wide rule.
	ev.counts["broad"] = Corroboration{HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9}
	in = append(in,
		candidate("broad", "c.test", "/c", verdicts.Malicious, testNow.Add(time.Hour)))

	snap, err := newGen(t, policy, ev).Generate(t.Context(), in, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(snap.Rules) != 2 {
		t.Fatalf("got %d rules, want the cap of 2", len(snap.Rules))
	}
	for _, r := range snap.Rules {
		if r.Provenance.Scope == ScopeRegistrableDomain {
			t.Error("the broadest rule survived the cap; the narrow ones should have been kept")
		}
	}
	if snap.SuppressedCount != 1 {
		t.Errorf("SuppressedCount = %d, want 1", snap.SuppressedCount)
	}
}

// ------------------------------------------------------------- validation

// Every generated rule must survive the Chrome schema subset.
func TestGeneratedRulesAlwaysValidate(t *testing.T) {
	t.Parallel()

	ev := fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9},
	}}

	for _, scope := range []Scope{ScopeExactURL, ScopeURLPrefix, ScopeRegistrableDomain} {
		policy := DefaultPolicy()
		policy.MaxScope = scope
		policy.MinCorroboration, policy.MinCorroborationPrefix, policy.MinCorroborationDomain = 1, 1, 1

		snap, err := newGen(t, policy, ev).Generate(t.Context(), []Candidate{
			candidate("fp1", "evil.test", "/login/page", verdicts.Malicious, testNow.Add(time.Hour)),
		}, testNow)
		if err != nil {
			t.Fatalf("Generate at scope %s: %v", scope, err)
		}
		if err := ValidateAll(snap.Rules); err != nil {
			t.Errorf("ValidateAll at scope %s: %v", scope, err)
		}
	}
}

// An evidence failure must abort the whole build rather than publish a partial
// ruleset.
func TestEvidenceFailureAbortsTheBuild(t *testing.T) {
	t.Parallel()

	g := newGen(t, DefaultPolicy(), fixedEvidence{err: errors.New("mongodb: timeout")})

	snap, err := g.Generate(t.Context(), []Candidate{
		candidate("fp1", "evil.test", "/login", verdicts.Malicious, testNow.Add(time.Hour)),
	}, testNow)
	if err == nil {
		t.Fatal("Generate succeeded despite an evidence failure")
	}
	if len(snap.Rules) != 0 {
		t.Errorf("a failed build returned %d rules", len(snap.Rules))
	}
}

// An empty finding set is a valid, empty snapshot — not an error.
func TestNoFindingsYieldsAnEmptySnapshot(t *testing.T) {
	t.Parallel()

	snap, err := newGen(t, DefaultPolicy(), fixedEvidence{}).Generate(t.Context(), nil, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(snap.Rules) != 0 {
		t.Errorf("got %d rules from no findings", len(snap.Rules))
	}
	if snap.Rules == nil {
		t.Error("rules is nil; the response contract requires an array")
	}
	if snap.Digest == "" {
		t.Error("an empty snapshot has no digest, so change detection cannot work")
	}
}

// --------------------------------------------------------------- policy

// A policy whose thresholds weaken as scopes broaden would make the ladder
// meaningless, so it is rejected at construction.
func TestPolicyValidationRejectsAWeakenedLadder(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.MinCorroborationPrefix = 1
	p.MinCorroboration = 5
	if err := p.Validate(); err == nil {
		t.Error("Validate accepted a broader scope needing less evidence")
	}

	p2 := DefaultPolicy()
	p2.MinCorroborationDomain = 1
	if err := p2.Validate(); err == nil {
		t.Error("Validate accepted a domain scope needing less evidence than a prefix")
	}
}

func TestPolicyValidationRejectsNonsense(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*Policy){
		"unknown scope":      func(p *Policy) { p.MaxScope = "everything" },
		"zero corroboration": func(p *Policy) { p.MinCorroboration = 0 },
		"zero max rules":     func(p *Policy) { p.MaxRules = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			p := DefaultPolicy()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Error("Validate accepted an incoherent policy")
			}
		})
	}
}

func TestParseScopeRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	if _, err := ParseScope("everything"); err == nil {
		t.Error("ParseScope accepted an unknown scope")
	}
	if s, err := ParseScope("registrable_domain"); err != nil || s != ScopeRegistrableDomain {
		t.Errorf("ParseScope = (%v, %v)", s, err)
	}
}

// ------------------------------------------------------------- escaping

// A path containing a urlFilter operator must never widen a rule.
//
// There is no documented escape for these characters, so an older version of
// this engine emitted a backslash and hoped. The rule now rejects the candidate
// instead, which is the only behaviour that can be proved correct.
func TestUnsafeFilterLiteralsAreRejectedNotEscaped(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy()
	policy.MaxScope = ScopeURLPrefix
	policy.MinCorroboration, policy.MinCorroborationPrefix = 1, 1

	g := newGen(t, policy, fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 5, PrefixFingerprints: 5},
	}})

	// Each of these is an operator in the documented urlFilter grammar, or a
	// character that cannot appear literally in a matched URL.
	for _, path := range []string{
		"/a|*other.test^", // would OR in an unrelated host
		"/a*b",            // wildcard
		"/a,b",
		"/a:b",
		"/a^b",
		"/\u00fcber", // non-ASCII: never appears literally in a URL
	} {
		t.Run(path, func(t *testing.T) {
			_, err := g.Generate(t.Context(), []Candidate{
				{
					Fingerprint: "fp1", Hostname: "evil.test", RegistrableDomain: "evil.test",
					Verdict: verdicts.Malicious, Scheme: "https",
					PathPrefix: path,
					AnalyzedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(time.Hour),
				},
			}, testNow)

			if err == nil {
				t.Fatal("Generate accepted a path containing a filter operator; " +
					"it must be rejected rather than escaped into an unverifiable pattern")
			}
			if !errors.Is(err, ErrInvalidRule) {
				t.Errorf("error = %v, want ErrInvalidRule", err)
			}
		})
	}
}

// The same path is expressible at exact-URL scope, where RE2 escaping is well
// defined. A candidate is rejected only where it cannot be represented safely.
func TestFilterOperatorPathIsFineAtExactURLScope(t *testing.T) {
	t.Parallel()

	g := newGen(t, DefaultPolicy(), fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 5, PrefixFingerprints: 5, DomainFingerprints: 5},
	}})

	snap, err := g.Generate(t.Context(), []Candidate{
		{
			Fingerprint: "fp1", Hostname: "evil.test", RegistrableDomain: "evil.test",
			Verdict: verdicts.Malicious, Scheme: "https",
			PathPrefix: "/a*b",
			AnalyzedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(time.Hour),
		},
	}, testNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(snap.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(snap.Rules))
	}

	// The star must be escaped so it cannot act as a wildcard.
	re := snap.Rules[0].Condition.Filter.RegexFilter
	if !strings.Contains(re, `\*`) {
		t.Errorf("regexFilter %q does not escape the star; it would match any character", re)
	}
}

// A registrable domain derived from a host must never be a public suffix.
func TestDeriveDomainRejectsABareLabel(t *testing.T) {
	t.Parallel()

	if _, err := DeriveDomain("localhost"); err == nil {
		t.Error("DeriveDomain produced a domain for localhost")
	}
	if _, err := DeriveDomain("example.com"); err != nil {
		t.Errorf("DeriveDomain(example.com) = %v", err)
	}
}
