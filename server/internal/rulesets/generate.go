package rulesets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"cyberguard/server/internal/urlintel"
	"cyberguard/server/internal/verdicts"
)

// Turning eligible findings into a deterministic, validated snapshot.

// Reference identifies the subject of a corroboration query without carrying
// the verdict or the timestamps.
//
// Splitting it from Candidate exists so a storage implementation receives only
// what it needs to count with, and cannot accidentally be handed a verdict it
// might then trust instead of querying for.
type Reference struct {
	Fingerprint       string
	Hostname          string
	RegistrableDomain string
	PathPrefix        string
}

// Candidate is one assessment that might become a rule.
//
// It is a projection of an assessment, not the document itself, so the ruleset
// package depends on the fields it needs rather than on the persistence layer.
type Candidate struct {
	// Fingerprint is the HMAC of the full canonical URL. It is provenance only;
	// it is never emitted in a rule.
	Fingerprint string

	// Hostname is the normalised host, lower-case and punycoded.
	Hostname string

	// RegistrableDomain is the PSL eTLD+1 for Hostname.
	//
	// It is resolved once, here, and never recomputed from a string that a rule
	// will be built from. Recomputing it downstream is how a public suffix ends
	// up treated as a domain.
	RegistrableDomain string

	// Verdict is the normalised CyberGuard verdict.
	Verdict verdicts.Verdict

	// Scheme is "http" or "https".
	Scheme string

	// Port is the URL's explicit port, empty when the URL used the default for
	// its scheme.
	//
	// It is carried because dropping it silently broadens a rule: an assessment
	// of `https://host.test:8443/login` would otherwise produce a rule covering
	// `https://host.test/login`, which nobody assessed. Recorded in ADR 0019.
	Port string

	// PathPrefix is the URL path, with no query string and no fragment.
	//
	// The query is excluded deliberately. It routinely carries session tokens
	// and identifiers, so persisting it would reintroduce exactly the sensitive
	// material the fingerprint exists to avoid.
	PathPrefix string

	// AnalyzedAt and ExpiresAt bound the finding's usefulness.
	AnalyzedAt time.Time
	ExpiresAt  time.Time
}

// Corroboration is how much independent evidence supports a candidate.
//
// "Independent" is the operative word: it counts distinct URL fingerprints, so
// the same URL scanned repeatedly is one finding, not several. Without that,
// an attacker could inflate their own corroboration simply by asking for the
// same scan many times.
type Corroboration struct {
	// HostFingerprints counts distinct malicious findings on the hostname.
	HostFingerprints int
	// PrefixFingerprints counts distinct malicious findings sharing the
	// candidate's path prefix on that host.
	PrefixFingerprints int
	// DomainFingerprints counts distinct malicious findings across the
	// registrable domain.
	DomainFingerprints int
}

// EvidenceSource supplies corroboration counts.
//
// It is an interface so the generator can be tested exhaustively without a
// database, and so the query lives in the persistence package where the index
// knowledge is.
type EvidenceSource interface {
	Corroboration(ctx context.Context, refs []Reference, now time.Time) (map[string]Corroboration, error)
}

// Snapshot is a versioned ruleset ready to publish.
type Snapshot struct {
	// Version is assigned by the store at publication. It is not set here,
	// because the store owns the monotonic counter.
	Version int64 `json:"version" bson:"_id"`

	// GeneratedAt is when this snapshot was built.
	GeneratedAt time.Time `json:"generated_at" bson:"generated_at"`

	// Rules are the DNR rules, in publication order, with contiguous IDs.
	Rules []Rule `json:"rules" bson:"rules"`

	// Digest identifies the *effective* rule set.
	//
	// It covers the rules only, not the generation timestamp, so a rebuild that
	// produces identical rules is recognised as unchanged. Without that,
	// every scan would bump the version and every extension would re-download.
	Digest string `json:"-" bson:"digest"`

	// SuppressedCount is how many eligible candidates did not fit within
	// MaxRules, or were dropped as duplicates of a broader rule.
	SuppressedCount int `json:"-" bson:"suppressed_count"`
}

// Generator builds snapshots from findings.
type Generator struct {
	policy   Policy
	evidence EvidenceSource
}

// NewGenerator builds a Generator.
func NewGenerator(policy Policy, evidence EvidenceSource) (*Generator, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Generator{policy: policy, evidence: evidence}, nil
}

// Policy returns the generator's policy, for logging and diagnostics.
func (g *Generator) Policy() Policy { return g.policy }

// Generate builds a snapshot from candidate findings.
//
// Any invalid rule fails the whole build. A partial ruleset is worse than none:
// the extension would silently under-block while the operator believed coverage
// was complete.
func (g *Generator) Generate(ctx context.Context, candidates []Candidate, now time.Time) (Snapshot, error) {
	snap := Snapshot{
		GeneratedAt: now.UTC(),
		Rules:       []Rule{},
	}

	if len(candidates) == 0 {
		snap.Digest = digestOf(nil)
		return snap, nil
	}

	corroboration := map[string]Corroboration{}
	if g.evidence != nil {
		refs := make([]Reference, 0, len(candidates))
		for _, c := range candidates {
			refs = append(refs, Reference{
				Fingerprint:       c.Fingerprint,
				Hostname:          c.Hostname,
				RegistrableDomain: c.RegistrableDomain,
				PathPrefix:        c.PathPrefix,
			})
		}

		var err error
		if corroboration, err = g.evidence.Corroboration(ctx, refs, now); err != nil {
			return Snapshot{}, fmt.Errorf("rulesets: corroboration: %w", err)
		}
	}

	// Filter first, so an ineligible or expired finding never reaches the rule
	// builder. Expiry is checked here and nowhere else, so it cannot be missed.
	eligible := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if !EligibleVerdict(c.Verdict) {
			continue
		}
		if !c.ExpiresAt.After(now) {
			continue
		}
		if c.Hostname == "" {
			continue
		}
		eligible = append(eligible, c)
	}

	rules := make([]Rule, 0, len(eligible))
	suppressed := 0

	// Sort before building, so the output is a pure function of the input set.
	sortCandidates(eligible)

	for _, c := range eligible {
		ev := corroboration[c.Fingerprint]
		scopes := g.policy.EligibleScopes(ev, pathAvailable(c, g.policy))

		scope, ok := pickScope(scopes, c)
		if !ok {
			suppressed++
			continue
		}

		rule, err := g.buildRule(c, scope)
		if err != nil {
			return Snapshot{}, err
		}
		rules = append(rules, rule)
	}

	// Enforce Chrome's regex limit before the total limit. It is the tighter
	// constraint and the one whose failure mode is silent, so it must be
	// applied to the same rule set the total cap then considers.
	rules, regexDropped := capRegexRules(rules, g.policy.MaxRegexRules)
	suppressed += regexDropped

	// Enforce the total cap, dropping the broadest rules first. A host-wide rule
	// and a single-URL rule protect the same host, so when space runs out the
	// narrower one is both safer and more informative.
	rules, dropped := capRules(rules, g.policy.MaxRules)
	suppressed += dropped

	// Assign identifiers by position.
	//
	// Chrome requires unique positive integers; contiguity is a convention this
	// engine keeps because it makes a snapshot readable and diffable. Position-
	// derived identifiers are stable across rebuilds *because* the ordering is
	// deterministic, which sortCandidates guarantees — the same evidence always
	// produces the same order, so the same rule keeps the same ID across
	// versions.
	//
	// What IDs are not is stable under removal: dropping the first rule shifts
	// every later ID by one. That is acceptable because a client replaces the
	// whole ruleset rather than reconciling rule-by-rule, and an ID that stayed
	// put while its meaning changed would be worse. See ADR 0019.
	for i := range rules {
		rules[i].ID = i + 1
		rules[i].Priority = g.policy.Priority
	}

	if err := ValidateAll(rules); err != nil {
		return Snapshot{}, err
	}

	snap.Rules = rules
	snap.SuppressedCount = suppressed
	snap.Digest = digestOf(rules)
	return snap, nil
}

// pathAvailable reports whether a prefix rule is possible for a candidate.
func pathAvailable(c Candidate, p Policy) bool {
	return pathSegments(c.PathPrefix) >= p.MinPathSegments
}

// pickScope chooses which scope a candidate earns.
//
// # Why evidence escalates breadth rather than narrowing it
//
// The policy states that a rule must be "the narrowest defensible one" and that
// each rung "requires stronger evidence than the last". Those two sentences only
// fit together if stronger evidence makes a broader rule *defensible*.
//
// Always taking the narrowest supported scope would make the ladder's extra
// thresholds dead configuration: no amount of evidence would ever produce a
// prefix or domain rule, so nobody could ever widen protection without a code
// change.
//
// There is also a concrete reason to escalate. A host with nine distinct
// malicious findings will be asked about more URLs; an exact-URL rule per
// finding covers the nine already seen and none of the rest. A broader rule
// covers what has not been scanned yet, which is the whole point of collecting
// the evidence.
//
// The safety valve is MaxScope. With the default of exact_url, escalation is
// invisible: the deployment can never emit anything but a single-URL rule, and
// every threshold above the first is inert by construction. Widening requires
// an operator to change one setting, which is a deliberate, reviewed act.
func pickScope(scopes []Scope, c Candidate) (Scope, bool) {
	// Walk narrow to broad and keep the last usable one.
	best := Scope("")
	found := false

	for _, s := range scopes {
		switch s {
		case ScopeExactURL:
			if c.Scheme != "" && c.PathPrefix != "" {
				best, found = s, true
			}
		case ScopeURLPrefix:
			if c.PathPrefix != "" {
				best, found = s, true
			}
		case ScopeRegistrableDomain:
			if c.RegistrableDomain != "" {
				best, found = s, true
			}
		}
	}
	return best, found
}

// buildRule constructs one rule at the given scope.
//
// A candidate that cannot be expressed safely at this scope is rejected rather
// than widened. That is the whole point: a rule that quietly matches more than
// the assessment licensed is worse than no rule, because it blocks something
// nobody assessed and the failure is invisible.
func (g *Generator) buildRule(c Candidate, scope Scope) (Rule, error) {
	resourceTypes, err := ResourceTypesForAction(g.policy.Action, g.policy.ResourceProfile)
	if err != nil {
		return Rule{}, err
	}

	rule := Rule{
		Priority: g.policy.Priority,
		Action:   g.action(),
		Condition: Condition{
			ResourceTypes: resourceTypes,
		},
		Provenance: Provenance{
			Fingerprint:       c.Fingerprint,
			RegistrableDomain: c.RegistrableDomain,
			Scope:             scope,
			Corroboration:     g.policy.corroborationRequired(scope),
			Action:            g.policy.Action,
		},
	}

	switch scope {
	case ScopeExactURL:
		// urlFilter cannot express "this URL and nothing else": `||host^/p` is
		// a prefix match and would also cover `/p/admin`. An anchored regex can,
		// and RE2 escaping is well defined, so this is the one scope where a
		// path containing a filter operator is still safely expressible.
		pattern, err := ExactURLRegex(c.Scheme, c.Hostname, c.Port, c.PathPrefix)
		if err != nil {
			return Rule{}, err
		}
		rule.Condition.Filter = &Filter{Type: FilterTypeRegex, RegexFilter: pattern}

	case ScopeURLPrefix:
		filter, err := PrefixFilter(c.Hostname, c.PathPrefix)
		if err != nil {
			return Rule{}, err
		}
		rule.Condition.URLFilter = filter

	case ScopeRegistrableDomain:
		filter, err := DomainFilter(c.RegistrableDomain)
		if err != nil {
			return Rule{}, err
		}
		rule.Condition.URLFilter = filter

	default:
		return Rule{}, fmt.Errorf("rulesets: cannot build a rule for scope %q", scope)
	}

	return rule, nil
}

// action returns the configured action, including the redirect target.
func (g *Generator) action() Action {
	if g.policy.Action != ActionRedirect {
		return Action{Type: ActionBlock}
	}
	return Action{
		Type:     ActionRedirect,
		Redirect: &Redirect{ExtensionPath: g.policy.RedirectPath},
	}
}

// capRegexRules drops regex-scoped rules beyond Chrome's per-ruleset limit.
//
// # Why this cannot be left to the total rule cap
//
// Chrome caps regular-expression rules at 1000 per ruleset type, separately
// from and far below the total rule limit. A snapshot of 5000 exact-URL rules —
// all of them regex — is within this engine's size cap and completely
// uninstallable, and Chrome's symptom is that the ruleset is ignored rather
// than rejected, so a client would quietly carry no protection at all.
//
// Regex rules are therefore dropped narrowest-first. A registrable-domain rule
// covers everything an exact-URL rule would, so keeping the broad rule when
// space runs out protects more, not less.
func capRegexRules(rules []Rule, limit int) ([]Rule, int) {
	var regexCount int
	for _, r := range rules {
		if r.Condition.Filter != nil {
			regexCount++
		}
	}
	if limit <= 0 || regexCount <= limit {
		return rules, 0
	}

	ordered := append([]Rule(nil), rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i].Provenance.Scope.Severity(), ordered[j].Provenance.Scope.Severity()
		if a != b {
			return a < b // narrower scope first, so it is dropped first
		}
		return ordered[i].Provenance.Fingerprint < ordered[j].Provenance.Fingerprint
	})

	dropRegex := regexCount - limit
	dropped := 0
	kept := make([]Rule, 0, len(rules))

	for _, r := range ordered {
		if dropped < dropRegex && r.Condition.Filter != nil {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	return kept, dropped
}

// capRules enforces MaxRules, dropping the broadest scopes first.
//
// When space runs out, the narrower rule is the one worth keeping: a host-wide
// rule and a single-URL rule protect the same host, so dropping the broad one
// is both safer and more informative.
//
// Survivors keep their original relative order, so IDs stay stable and the
// digest changes only in the way the caller asked for.
func capRules(rules []Rule, max int) ([]Rule, int) {
	if len(rules) <= max {
		return rules, 0
	}

	type ranked struct {
		rule   Rule
		scope  int
		origin int
	}

	ordered := make([]ranked, 0, len(rules))
	for i, r := range rules {
		ordered = append(ordered, ranked{rule: r, scope: r.Provenance.Scope.Severity(), origin: i})
	}

	// Broadest first, then newest-first within a scope, so ties are broken
	// deterministically rather than by input order.
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].scope != ordered[j].scope {
			return ordered[i].scope > ordered[j].scope
		}
		return ordered[i].origin > ordered[j].origin
	})

	// `ordered` is broadest-first, so the broadest `dropped` entries go and
	// the remaining len-max survive.
	dropped := len(rules) - max
	kept := make([]ranked, 0, max)
	kept = append(kept, ordered[dropped:]...)

	// Back into publication order, so identifiers stay stable.
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].origin < kept[j].origin })

	out := make([]Rule, 0, len(kept))
	for _, k := range kept {
		out = append(out, k.rule)
	}
	return out, dropped
}

// sortCandidates orders candidates deterministically.
//
// Determinism is a correctness requirement, not tidiness: the digest is
// computed over the emitted rules, and an unstable order would produce a
// different digest for the same evidence and bump the version on every
// rebuild.
func sortCandidates(c []Candidate) {
	sort.SliceStable(c, func(i, j int) bool {
		a, b := c[i], c[j]

		// Narrower scopes first is handled later; here we order by scope
		// capacity implicitly via hostname, then path, then fingerprint.
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		if a.PathPrefix != b.PathPrefix {
			return a.PathPrefix < b.PathPrefix
		}
		return a.Fingerprint < b.Fingerprint
	})
}

// digestOf computes the fingerprint of a rule set.
//
// It covers only the published content: a rebuild that produces the same rules
// must produce the same digest, or every scan would look like a change.
func digestOf(rules []Rule) string {
	// Provenance is excluded deliberately. It carries corroboration counts,
	// which can change while the effective rules do not — and a client cannot
	// do anything with them.
	type published struct {
		ID        int       `json:"id"`
		Priority  int       `json:"priority"`
		Action    Action    `json:"action"`
		Condition Condition `json:"condition"`
	}

	out := make([]published, 0, len(rules))
	for _, r := range rules {
		out = append(out, published{ID: r.ID, Priority: r.Priority, Action: r.Action, Condition: r.Condition})
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		// The types are plain data with no channels or cycles, so this cannot
		// happen; returning an empty digest would silently disable change
		// detection, so it panics loudly instead.
		panic(fmt.Sprintf("rulesets: marshalling rules for digest: %v", err))
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// DeriveDomain returns the registrable domain for a hostname.
//
// It exists so a caller cannot accidentally use the hostname as a domain. The
// check that a registrable domain is never itself a public suffix is the whole
// reason ADR 0012 was written, and re-deriving it at each call site is how that
// class of bug comes back.
func DeriveDomain(hostname string) (string, error) {
	host, err := urlintel.ParseHost(hostname)
	if err != nil {
		return "", err
	}
	if host.RegistrableDomain == "" {
		return "", fmt.Errorf("rulesets: %q has no registrable domain", hostname)
	}
	return host.RegistrableDomain, nil
}
