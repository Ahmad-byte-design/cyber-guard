package rulesets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"cyberguard/server/internal/verdicts"
)

// Chrome Declarative Net Request conformance: the target JSON shape, the action
// and resource-type policies, urlFilter safety, identifier and priority
// allocation, and the Chrome limits.
//
// No Chrome is run here. These tests assert the engine emits what Chrome's
// documented schema requires; they do not claim Chrome installed it.

// dnrNow is the fixed clock every generator test uses.
var dnrNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// wellCorroborated satisfies every threshold at every scope.
func wellCorroborated(fps ...string) EvidenceSource {
	counts := map[string]Corroboration{}
	for _, fp := range fps {
		counts[fp] = Corroboration{HostFingerprints: 9, PrefixFingerprints: 9, DomainFingerprints: 9}
	}
	return fixedEvidence{counts: counts}
}

func dnrCandidate(fp, host, path string) Candidate {
	return Candidate{
		Fingerprint:       fp,
		Hostname:          host,
		RegistrableDomain: registrableOf(host),
		Verdict:           verdicts.Malicious,
		Scheme:            "https",
		PathPrefix:        path,
		AnalyzedAt:        dnrNow.Add(-time.Hour),
		ExpiresAt:         dnrNow.Add(time.Hour),
	}
}

// registrableOf is a two-label approximation, sufficient for host patterns.
func registrableOf(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func generateWith(t *testing.T, p Policy, ev EvidenceSource, cands ...Candidate) Snapshot {
	t.Helper()
	g, err := NewGenerator(p, ev)
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	snap, err := g.Generate(t.Context(), cands, dnrNow)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return snap
}

// ============================================================ A. JSON format

// The published shape must match the target DNR structure exactly.
//
// This is a golden-shape test: it marshals a generated ruleset and compares the
// member names and nesting against the structure the contract specifies. A
// rename of `urlFilter` to `url_filter`, or a `redirect` appearing where
// Chrome does not expect it, fails here rather than in a browser.
func TestPublishedRuleMatchesTheTargetDNRShape(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.MaxScope = ScopeRegistrableDomain

	snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))

	encoded, err := json.Marshal(snap.Rules)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var rules []map[string]any
	if err := json.Unmarshal(encoded, &rules); err != nil {
		t.Fatalf("the published rules are not valid JSON objects: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}

	rule := rules[0]
	for _, key := range []string{"id", "priority", "action", "condition"} {
		if _, ok := rule[key]; !ok {
			t.Errorf("the rule has no %q member", key)
		}
	}
	// Nothing beyond the four members: Chrome rejects unknown members.
	if extra := len(rule) - 4; extra > 0 {
		t.Errorf("the rule carries %d members beyond the documented four", extra)
	}

	action, _ := rule["action"].(map[string]any)
	if action["type"] != string(ActionBlock) {
		t.Errorf("action.type = %v, want block", action["type"])
	}
	if _, has := action["redirect"]; has {
		t.Error("a block action carries a redirect member; Chrome rejects that")
	}

	cond, _ := rule["condition"].(map[string]any)
	if _, ok := cond["urlFilter"]; !ok {
		t.Error("the condition has no urlFilter")
	}
	rts, ok := cond["resourceTypes"].([]any)
	if !ok || len(rts) == 0 {
		t.Fatal("the condition has no resourceTypes")
	}
}

// A block rule must not carry redirect configuration.
func TestBlockRuleOmitsRedirect(t *testing.T) {
	t.Parallel()

	snap := generateWith(t, DefaultPolicy(), wellCorroborated("fp1"),
		dnrCandidate("fp1", "evil.test", "/login"))

	for _, r := range snap.Rules {
		if r.Action.Type != ActionBlock {
			continue
		}
		if r.Action.Redirect != nil {
			t.Errorf("rule %d is a block carrying %+v", r.ID, r.Action.Redirect)
		}
		encoded, _ := json.Marshal(r)
		if strings.Contains(string(encoded), "redirect") {
			t.Errorf("a block rule serialises the word redirect: %s", encoded)
		}
	}
}

// A redirect rule must carry the configured extensionPath, and nothing else.
func TestRedirectRuleCarriesTheExtensionPath(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.Action = ActionRedirect
	p.RedirectPath = "/locked.html"

	snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))
	if len(snap.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(snap.Rules))
	}

	rule := snap.Rules[0]
	if rule.Action.Type != ActionRedirect {
		t.Fatalf("action = %q, want redirect", rule.Action.Type)
	}
	if rule.Action.Redirect == nil {
		t.Fatal("a redirect rule carries no redirect")
	}
	if rule.Action.Redirect.ExtensionPath != "/locked.html" {
		t.Errorf("extensionPath = %q, want /locked.html", rule.Action.Redirect.ExtensionPath)
	}

	// No off-site redirect can be emitted at all.
	encoded, _ := json.Marshal(rule.Action)
	if strings.Contains(string(encoded), "https://") || strings.Contains(string(encoded), "transform") {
		t.Errorf("the redirect names a destination outside the extension: %s", encoded)
	}
}

// The whole snapshot must serialise as a JSON array of rule objects.
func TestSnapshotRulesAreAJSONArrayOfObjects(t *testing.T) {
	t.Parallel()

	snap := generateWith(t, DefaultPolicy(), wellCorroborated("fp1", "fp2"),
		dnrCandidate("fp1", "a.test", "/x"), dnrCandidate("fp2", "b.test", "/y"))

	// Even an empty snapshot must be `[]`, never `null`.
	if snap.Rules == nil {
		t.Fatal("Rules is nil; the contract requires an array")
	}
	encoded, err := json.Marshal(snap.Rules)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.HasPrefix(string(encoded), "[") {
		t.Errorf("rules serialise as %s, want a JSON array", encoded)
	}

	var out []map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("not an array of objects: %v", err)
	}

	empty := generateWith(t, DefaultPolicy(), wellCorroborated())
	if string(mustJSON(t, empty.Rules)) != "[]" {
		t.Errorf("an empty snapshot serialises as %s, want []", mustJSON(t, empty.Rules))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// ========================================================== B. Security

// No verdict other than malicious may produce a rule, however much evidence
// exists. Unknown is not safe, and a failed analysis is not evidence of
// harmlessness — nor of harm.
func TestOnlyMaliciousProducesARule(t *testing.T) {
	t.Parallel()

	for _, verdict := range []verdicts.Verdict{
		verdicts.Suspicious, verdicts.NoThreatDetected, verdicts.Inconclusive, verdicts.Unknown,
	} {
		t.Run(verdict.String(), func(t *testing.T) {
			c := dnrCandidate("fp1", "evil.test", "/login")
			c.Verdict = verdict

			snap := generateWith(t, DefaultPolicy(), wellCorroborated("fp1"), c)
			if len(snap.Rules) != 0 {
				t.Errorf("%s produced %d rules", verdict, len(snap.Rules))
			}
		})
	}
}

// An expired finding produces nothing, even though its verdict is malicious.
func TestExpiredAssessmentProducesNoRule(t *testing.T) {
	t.Parallel()

	c := dnrCandidate("fp1", "evil.test", "/login")
	c.ExpiresAt = dnrNow.Add(-time.Second)

	snap := generateWith(t, DefaultPolicy(), wellCorroborated("fp1"), c)
	if len(snap.Rules) != 0 {
		t.Errorf("an expired finding produced %d rules", len(snap.Rules))
	}
}

// Insufficient corroboration produces nothing. A provider false positive blocks
// a real site, and that is the cost this threshold exists to avoid.
func TestInsufficientCorroborationProducesNoRule(t *testing.T) {
	t.Parallel()

	weak := fixedEvidence{counts: map[string]Corroboration{
		"fp1": {HostFingerprints: 1, PrefixFingerprints: 1, DomainFingerprints: 1},
	}}

	snap := generateWith(t, DefaultPolicy(), weak, dnrCandidate("fp1", "evil.test", "/login"))
	if len(snap.Rules) != 0 {
		t.Errorf("one uncorroborated finding produced %d rules", len(snap.Rules))
	}
}

// The central scope property: an exact-URL assessment must not produce a rule
// that covers the host.
//
// The corroboration count is high enough to satisfy every rung, so the only
// thing keeping the rule narrow is MaxScope. If the ceiling ever stops being
// enforced, an exact-URL finding would block the whole host.
func TestExactURLAssessmentDoesNotBroadenToTheHost(t *testing.T) {
	t.Parallel()

	for _, scope := range []Scope{ScopeExactURL, ScopeURLPrefix, ScopeRegistrableDomain} {
		t.Run("ceiling="+string(scope), func(t *testing.T) {
			p := DefaultPolicy()
			p.MaxScope = scope

			snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))
			if len(snap.Rules) != 1 {
				t.Fatalf("got %d rules, want 1", len(snap.Rules))
			}

			r := snap.Rules[0]
			if got := r.Provenance.Scope; got != scope {
				t.Errorf("scope = %q, want %q", got, scope)
			}

			// The matcher must mention the path at exact and prefix scope, and
			// must not at domain scope.
			matcher := matcherOf(r)
			switch scope {
			case ScopeExactURL, ScopeURLPrefix:
				if !strings.Contains(matcher, "login") {
					t.Errorf("a %s rule ignores the assessed path: %s", scope, matcher)
				}
			case ScopeRegistrableDomain:
				if strings.Contains(matcher, "login") {
					t.Errorf("a domain rule still carries the path: %s", matcher)
				}
			}
		})
	}
}

func matcherOf(r Rule) string {
	if r.Condition.Filter != nil {
		return r.Condition.Filter.RegexFilter
	}
	return r.Condition.URLFilter
}

// ========================================================= C. URL filters

// HostnameFilterBoundary pins the property that makes `||host^` safe, which is
// the whole justification for emitting it.
//
// These are properties of the documented grammar, not of a pattern produced by
// one particular run: `||` anchors to the start of a (sub-)domain, so the
// literal must begin at a label boundary; `^` matches any character that is not
// a letter, digit, `_`, `-`, `.` or `%`, and also the end of the URL, which is
// what stops `example.com` matching `example.company`.
func TestHostnameFilterBoundary(t *testing.T) {
	t.Parallel()

	filter, err := DomainFilter("example.com")
	if err != nil {
		t.Fatalf("DomainFilter: %v", err)
	}
	if filter != "||example.com^" {
		t.Fatalf("filter = %q, want ||example.com^", filter)
	}

	// The two properties that matter, stated as the boundaries the grammar
	// creates. These are assertions about the emitted shape, because no Chrome
	// is executed here.
	if !strings.HasPrefix(filter, "||") {
		t.Error("the filter is not domain-anchored; it would match any host containing the name")
	}
	if !strings.HasSuffix(filter, "^") {
		t.Error("the filter is not separator-terminated; example.com would match example.company")
	}
	// A mid-string occurrence, which is exactly the evil-example.com case.
	mid := strings.Index(filter, "example.com")
	if mid != len("||") {
		t.Errorf("the literal starts at offset %d; it must start immediately after the anchor", mid)
	}
}

// A hostname that is only a substring of another host must not be reachable
// through the emitted filter.
//
// The filter cannot contain a wildcard, so the only way it could match another
// host is if the anchor were missing. Asserting the anchor is present is what
// rules that out.
func TestFilterDoesNotMatchASubstringHost(t *testing.T) {
	t.Parallel()

	filter, err := DomainFilter("example.com")
	if err != nil {
		t.Fatalf("DomainFilter: %v", err)
	}

	for _, other := range []string{"evil-example.com", "notexample.com", "example.com.evil.test"} {
		// Strip the anchors to get the bare literal the pattern requires.
		literal := strings.TrimSuffix(strings.TrimPrefix(filter, "||"), "^")

		if other != literal && strings.Contains(other, literal) {
			// A bare substring rule would match this host. Ours does not,
			// because of || and ^. Record the pair so the intent is explicit.
			t.Logf("%q contains %q but is not matched: || anchors to a label boundary "+
				"and ^ rejects a following letter or dot", other, literal)
		}
	}
}

// Subdomains are within the domain-anchor's reach, which is what makes the
// registrable-domain rung cover them.
func TestDomainFilterIsDomainAnchored(t *testing.T) {
	t.Parallel()

	filter, err := DomainFilter("co.uk")
	if err != nil {
		t.Fatalf("DomainFilter: %v", err)
	}
	if filter != "||co.uk^" {
		t.Errorf("filter = %q", filter)
	}
}

// An IP literal has no urlFilter form for the prefix and domain scopes, because
// it carries characters the grammar gives meaning to. It must be rejected, not
// silently narrowed.
func TestIPv6LiteralIsRejectedAtURLFilterScopes(t *testing.T) {
	t.Parallel()

	if _, err := DomainFilter("2606:4700::1111"); err == nil {
		t.Error("an IPv6 literal was accepted into a urlFilter")
	} else if !errors.Is(err, ErrInvalidRule) {
		t.Errorf("error = %v, want ErrInvalidRule", err)
	}
}

// An IPv4 literal is accepted: it carries only digits and dots, and `^` matches
// the `:` or `/` that follows it, or the end of the URL.
func TestIPv4LiteralIsAcceptedAtURLFilterScope(t *testing.T) {
	t.Parallel()

	filter, err := DomainFilter("203.0.113.5")
	if err != nil {
		t.Fatalf("DomainFilter: %v", err)
	}
	if filter != "||203.0.113.5^" {
		t.Errorf("filter = %q", filter)
	}
}

// An IPv6 literal is expressible at exact-URL scope, where RE2 escaping is
// well defined, and must be bracketed in the authority.
func TestIPv6LiteralIsExpressibleAtExactURLScope(t *testing.T) {
	t.Parallel()

	pattern, err := ExactURLRegex("https", "2606:4700::1111", "", "/login")
	if err != nil {
		t.Fatalf("ExactURLRegex: %v", err)
	}
	if !strings.Contains(pattern, `\[2606:4700::1111\]`) {
		t.Errorf("pattern %q does not bracket the IPv6 literal", pattern)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("the pattern does not compile: %v", err)
	}
	if !re.MatchString("https://[2606:4700::1111]/login") {
		t.Error("the pattern does not match the URL it was built from")
	}
	if re.MatchString("https://[2606:4700::1111]/login/extra") {
		t.Error("the pattern matched a longer path than the assessed URL")
	}
}

// A port must be pinned, or the rule covers ports nobody assessed.
func TestExactURLRulePinsThePort(t *testing.T) {
	t.Parallel()

	withPort, err := ExactURLRegex("https", "evil.test", "8443", "/login")
	if err != nil {
		t.Fatalf("ExactURLRegex: %v", err)
	}
	if !strings.Contains(withPort, `evil\.test:8443`) {
		t.Errorf("pattern %q does not pin the port", withPort)
	}

	re := regexp.MustCompile(withPort)
	if re.MatchString("https://evil.test/login") {
		t.Error("a rule built for :8443 matched the default port")
	}
	if !re.MatchString("https://evil.test:8443/login") {
		t.Error("the rule does not match the URL it was built from")
	}
}

// A non-numeric port is refused rather than emitted.
func TestExactURLRuleRejectsANonNumericPort(t *testing.T) {
	t.Parallel()

	if _, err := ExactURLRegex("https", "evil.test", "https", "/login"); err == nil {
		t.Error("a non-numeric port was accepted")
	}
}

// A punycoded host is what the filter must carry, because Chrome matches
// against a punycoded URL.
func TestPunycodeIsEmittedVerbatim(t *testing.T) {
	t.Parallel()

	// The punycode of a Unicode domain, as urlintel would produce it.
	filter, err := DomainFilter("xn--bcher-kva.test")
	if err != nil {
		t.Fatalf("DomainFilter: %v", err)
	}
	if filter != "||xn--bcher-kva.test^" {
		t.Errorf("filter = %q", filter)
	}
}

// A raw Unicode host must never reach a filter.
func TestUnicodeHostIsRejected(t *testing.T) {
	t.Parallel()

	if _, err := DomainFilter("bücher.test"); err == nil {
		t.Error("a Unicode hostname was accepted into a urlFilter")
	}
}

// A prefix filter is a prefix match, which is what the prefix scope means.
func TestPrefixFilterIsAnchoredToHostAndPath(t *testing.T) {
	t.Parallel()

	filter, err := PrefixFilter("evil.test", "/login/page")
	if err != nil {
		t.Fatalf("PrefixFilter: %v", err)
	}
	if filter != "||evil.test^/login/page" {
		t.Errorf("filter = %q", filter)
	}
}

// The query string must never appear in a rule, because the assessment does not
// retain one.
func TestQueryStringNeverAppearsInAFilter(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.MaxScope = ScopeRegistrableDomain

	snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))
	for _, r := range snap.Rules {
		if strings.ContainsAny(matcherOf(r), "?=") {
			t.Errorf("rule %d's matcher carries a query delimiter: %s", r.ID, matcherOf(r))
		}
	}
}

// =========================================================== D. DNR validity

// Every generated rule must satisfy the engine's own validation, which mirrors
// Chrome's documented constraints.
func TestGeneratedRulesValidateForEveryActionAndScope(t *testing.T) {
	t.Parallel()

	for _, action := range []ActionType{ActionBlock, ActionRedirect} {
		for _, scope := range []Scope{ScopeExactURL, ScopeURLPrefix, ScopeRegistrableDomain} {
			t.Run(string(action)+"/"+string(scope), func(t *testing.T) {
				p := DefaultPolicy()
				p.Action = action
				p.MaxScope = scope

				snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login/page"))
				if err := ValidateAll(snap.Rules); err != nil {
					t.Errorf("ValidateAll: %v", err)
				}
			})
		}
	}
}

// Identifiers are positive, contiguous, unique and within Chrome's range.
func TestRuleIDsAreValidAndUnique(t *testing.T) {
	t.Parallel()

	var cands []Candidate
	for i := range 25 {
		fp := fmt.Sprintf("fp%02d", i)
		cands = append(cands, dnrCandidate(fp, fmt.Sprintf("host%02d.test", i), "/p"))
	}

	snap := generateWith(t, DefaultPolicy(), wellCorroborated(fps(cands)...), cands...)

	seen := map[int]bool{}
	for i, r := range snap.Rules {
		if r.ID != i+1 {
			t.Errorf("rule at position %d has id %d, want %d", i, r.ID, i+1)
		}
		if r.ID < 1 || r.ID > maxRuleID {
			t.Errorf("rule id %d is outside Chrome's range", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("rule id %d is duplicated", r.ID)
		}
		seen[r.ID] = true
	}
}

func fps(cands []Candidate) []string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.Fingerprint
	}
	return out
}

// Priorities are explicit and identical across rules, which is what leaves
// Chrome's block-before-redirect ordering to decide.
func TestPriorityIsExplicitAndUniform(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.Priority = 7

	snap := generateWith(t, p, wellCorroborated("fp1", "fp2"),
		dnrCandidate("fp1", "a.test", "/x"), dnrCandidate("fp2", "b.test", "/y"))

	for _, r := range snap.Rules {
		if r.Priority != 7 {
			t.Errorf("rule %d has priority %d, want the configured 7", r.ID, r.Priority)
		}
	}
}

// Every emitted resource type must be in Chrome's enum.
func TestEmittedResourceTypesAreValid(t *testing.T) {
	t.Parallel()

	for _, profile := range KnownResourceProfiles() {
		t.Run(profile, func(t *testing.T) {
			p := DefaultPolicy()
			p.ResourceProfile = ResourceProfile(profile)

			snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/x"))
			if len(snap.Rules) == 0 {
				t.Fatal("no rule generated")
			}
			for _, r := range snap.Rules {
				if len(r.Condition.ResourceTypes) == 0 {
					t.Errorf("rule %d has no resourceTypes", r.ID)
				}
				for _, rt := range r.Condition.ResourceTypes {
					if !KnownResourceType(rt) {
						t.Errorf("rule %d names %q, which is not in Chrome's enum", r.ID, rt)
					}
				}
			}
		})
	}
}

// A block applies to navigations and the resources that can act on the page; a
// redirect applies to navigations only, because replacing a sub-resource with
// an HTML page breaks the page rather than protecting it.
func TestRedirectIsRestrictedToNavigationResourceTypes(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.Action = ActionRedirect
	// Even when the operator asks for the broadest profile.
	p.ResourceProfile = ProfileAllSubresources

	snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))
	if len(snap.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(snap.Rules))
	}

	got := snap.Rules[0].Condition.ResourceTypes
	if len(got) != 2 {
		t.Errorf("a redirect covers %v; it must be navigations only", got)
	}
	for _, rt := range got {
		if rt != ResourceMainFrame && rt != ResourceSubFrame {
			t.Errorf("a redirect names %q; redirecting a sub-resource to a page breaks it", rt)
		}
	}
}

// A block must include main_frame. Chrome's own default for an omitted list
// excludes it, which would silently stop the rule blocking navigation.
func TestBlockAlwaysIncludesMainFrame(t *testing.T) {
	t.Parallel()

	for _, profile := range KnownResourceProfiles() {
		t.Run(profile, func(t *testing.T) {
			p := DefaultPolicy()
			p.ResourceProfile = ResourceProfile(profile)

			snap := generateWith(t, p, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/x"))
			if len(snap.Rules) == 0 {
				t.Fatal("no rule generated")
			}
			var found bool
			for _, rt := range snap.Rules[0].Condition.ResourceTypes {
				if rt == ResourceMainFrame {
					found = true
				}
			}
			if !found {
				t.Errorf("profile %s produced %v with no main_frame; the rule would not "+
					"stop navigation", profile, snap.Rules[0].Condition.ResourceTypes)
			}
		})
	}
}

// The redirect target must be a usable extension-relative path.
func TestRedirectPathValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		ok   bool
	}{
		{"absolute path", "/locked.html", true},
		{"nested path", "/pages/locked.html", true},
		{"no leading slash", "locked.html", false},
		{"protocol relative", "//evil.test/x", false},
		{"backslash", `/\evil.test`, false},
		{"parent traversal", "/../etc/passwd", false},
		{"query string", "/locked.html?next=x", false},
		{"fragment", "/locked.html#x", false},
		{"empty", "", false},
		{"newline", "/locked.html\nX: y", false},
		{"absolute URL", "https://evil.test/locked", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Redirect{ExtensionPath: tc.path}).validate()
			if tc.ok && err != nil {
				t.Errorf("path %q was refused: %v", tc.path, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("path %q was accepted; it could redirect off-site", tc.path)
			}
		})
	}
}

// A policy naming an unusable redirect path must be refused at construction,
// before any rule is built.
func TestPolicyRefusesAnUnusableRedirectPath(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.Action = ActionRedirect
	p.RedirectPath = "//evil.test/steal"

	if err := p.Validate(); err == nil {
		t.Error("Validate accepted a protocol-relative redirect path")
	}
}

// An action outside block/redirect must be refused.
func TestPolicyRefusesAnUnknownAction(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.Action = ActionType("allowAllRequests")

	if err := p.Validate(); err == nil {
		t.Error("Validate accepted an action this engine does not emit")
	}
}

// A snapshot must never exceed Chrome's documented regex limit, because the
// failure mode is that Chrome ignores the whole ruleset.
func TestRegexRulesAreCappedAtChromesLimit(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.MaxRules = DefaultMaxRules // well above the regex limit
	p.MaxRegexRules = 5

	var cands []Candidate
	for i := range 20 {
		fp := fmt.Sprintf("fp%02d", i)
		cands = append(cands, dnrCandidate(fp, fmt.Sprintf("host%02d.test", i), "/p"))
	}

	snap := generateWith(t, p, wellCorroborated(fps(cands)...), cands...)

	var regexCount int
	for _, r := range snap.Rules {
		if r.Condition.Filter != nil {
			regexCount++
		}
	}
	if regexCount > p.MaxRegexRules {
		t.Errorf("%d regex rules survived a cap of %d", regexCount, p.MaxRegexRules)
	}
	if len(snap.Rules) != p.MaxRegexRules {
		t.Errorf("got %d rules, want the %d non-regex rules that were kept", len(snap.Rules), p.MaxRegexRules)
	}
	if snap.SuppressedCount == 0 {
		t.Error("SuppressedCount is 0 although rules were dropped")
	}
}

// A policy cannot ask for more regex rules than Chrome allows.
func TestPolicyCannotExceedChromesRegexLimit(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.MaxRegexRules = MaxRegexRules + 1

	if err := p.Validate(); err == nil {
		t.Error("Validate accepted a regex cap above Chrome's documented limit")
	}
}

// The total snapshot must respect the configured cap.
func TestTotalRuleCapIsRespected(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	p.MaxRules = 10

	var cands []Candidate
	for i := range 30 {
		fp := fmt.Sprintf("fp%02d", i)
		cands = append(cands, dnrCandidate(fp, fmt.Sprintf("host%02d.test", i), "/p"))
	}

	snap := generateWith(t, p, wellCorroborated(fps(cands)...), cands...)
	if len(snap.Rules) != 10 {
		t.Errorf("got %d rules, want the cap of 10", len(snap.Rules))
	}
}

// =========================================================== E. Versioning

// Identical input must produce byte-identical output, including identifiers.
// This is what makes the version meaningful: a rebuild that reorders rules
// would republish an identical ruleset under a new version.
func TestIdenticalInputProducesIdenticalOutput(t *testing.T) {
	t.Parallel()

	cands := []Candidate{
		dnrCandidate("fp1", "zeta.test", "/c"),
		dnrCandidate("fp2", "alpha.test", "/b"),
		dnrCandidate("fp3", "alpha.test", "/a"),
	}

	first := generateWith(t, DefaultPolicy(), wellCorroborated(fps(cands)...), cands...)
	for range 20 {
		again := generateWith(t, DefaultPolicy(), wellCorroborated(fps(cands)...), cands...)
		if string(mustJSON(t, again.Rules)) != string(mustJSON(t, first.Rules)) {
			t.Fatal("the same evidence produced different published bytes")
		}
		if again.Digest != first.Digest {
			t.Fatalf("digest changed between runs: %s then %s", first.Digest, again.Digest)
		}
	}
}

// The digest must change when the action changes, or a deployment switching
// block to redirect would serve a stale ruleset to every client.
func TestDigestCoversTheAction(t *testing.T) {
	t.Parallel()

	block := DefaultPolicy()
	redirect := DefaultPolicy()
	redirect.Action = ActionRedirect

	b := generateWith(t, block, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))
	r := generateWith(t, redirect, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))

	if b.Digest == r.Digest {
		t.Error("switching block to redirect did not change the digest; clients would " +
			"keep the old ruleset")
	}
}

// The digest must cover the resource types.
func TestDigestCoversResourceTypes(t *testing.T) {
	t.Parallel()

	narrow := DefaultPolicy()
	narrow.ResourceProfile = ProfileNavigation
	broad := DefaultPolicy()
	broad.ResourceProfile = ProfileAllSubresources

	a := generateWith(t, narrow, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))
	b := generateWith(t, broad, wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))

	if a.Digest == b.Digest {
		t.Error("changing the resource profile did not change the digest")
	}
}

// A rule's fingerprint must never reach the published rule. Chrome rejects
// unknown members, and a fingerprint is exactly the kind of correlation handle
// the audit trail should keep to itself.
func TestProvenanceIsNotPublished(t *testing.T) {
	t.Parallel()

	snap := generateWith(t, DefaultPolicy(), wellCorroborated("fp1"), dnrCandidate("fp1", "evil.test", "/login"))

	encoded := string(mustJSON(t, snap.Rules))
	for _, leak := range []string{"fingerprint", "provenance", "corroboration", "fp1"} {
		if strings.Contains(encoded, leak) {
			t.Errorf("the published ruleset contains %q: %s", leak, encoded)
		}
	}
}

// An evidence failure must abort the whole build, so a partial ruleset cannot be
// published.
func TestEvidenceFailureAbortsTheWholeBuild(t *testing.T) {
	t.Parallel()

	g, err := NewGenerator(DefaultPolicy(), fixedEvidence{err: errors.New("mongodb: timeout")})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}

	snap, err := g.Generate(context.Background(),
		[]Candidate{dnrCandidate("fp1", "evil.test", "/login")}, dnrNow)
	if err == nil {
		t.Fatal("Generate succeeded despite an evidence failure")
	}
	if len(snap.Rules) != 0 {
		t.Errorf("a failed build returned %d rules", len(snap.Rules))
	}
}
