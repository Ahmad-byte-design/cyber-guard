package rulesets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
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

	// Enforce the cap, dropping the broadest rules first. A host-wide rule and
	// a single-URL rule protect the same host, so when space runs out the
	// narrower one is both safer and more informative.
	rules, dropped := capRules(rules, g.policy.MaxRules)
	suppressed += dropped

	// Assign identifiers by position. Chrome requires contiguous identifiers
	// from 1, and position-derived IDs stay stable for a client diffing two
	// versions as long as the ordering is deterministic — which the sort above
	// guarantees.
	for i := range rules {
		rules[i].ID = i + 1
		rules[i].Priority = 1
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
func (g *Generator) buildRule(c Candidate, scope Scope) (Rule, error) {
	rule := Rule{
		Priority: 1,
		Action:   Action{Type: Block},
		Condition: Condition{
			// Every navigable and sub-resource type: a phishing payload is very
			// often delivered by a script or an iframe rather than the main
			// frame, and a main-frame-only rule would miss it.
			ResourceTypes: append([]string(nil), resourceTypes...),
		},
		Provenance: Provenance{
			Fingerprint:       c.Fingerprint,
			RegistrableDomain: c.RegistrableDomain,
			Scope:             scope,
			Corroboration:     g.policy.corroborationRequired(scope),
		},
	}

	switch scope {
	case ScopeExactURL:
		// urlFilter cannot express "exactly this URL and nothing else", so the
		// exact scope uses an anchored regex.
		//
		// The URL carries no query string. That is a deliberate narrowing of
		// both storage and blast radius: queries carry session tokens, so
		// persisting or publishing one would reintroduce exactly the sensitive
		// material the fingerprint exists to avoid. The trade is that two URLs
		// differing only in query share a rule, which blocks slightly more than
		// true exactness — recorded in ADR 0018.
		target := c.Scheme + "://" + c.Hostname + normalisePath(c.PathPrefix)
		rule.Condition.Filter = &Filter{
			Type:        FilterTypeRegex,
			RegexFilter: "^" + regexp.QuoteMeta(target) + "$",
		}

	case ScopeURLPrefix:
		rule.Condition.URLFilter = "||" + escapeHost(c.Hostname) + "^" + escapePathPrefix(normalisePath(c.PathPrefix))

	case ScopeRegistrableDomain:
		// The broadest rung. `||host^` matches the domain and its subdomains,
		// which is exactly why it needs the most evidence.
		rule.Condition.URLFilter = "||" + escapeHost(c.RegistrableDomain) + "^"

	default:
		return Rule{}, fmt.Errorf("rulesets: cannot build a rule for scope %q", scope)
	}

	return rule, nil
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

// normalisePath makes a path comparable and filter-safe.
//
// An empty path is "/" so that a bare host does not produce "https://host".
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
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
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

// escapePathPrefix escapes a path for the urlFilter prefix form.
func escapePathPrefix(p string) string {
	return escapeURLFilter(normalisePath(p))
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
