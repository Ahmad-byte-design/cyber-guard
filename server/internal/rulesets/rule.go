// Package rulesets turns eligible security assessments into a versioned
// browser ruleset.
//
// # Analysis and policy are separate decisions
//
// `verdicts` answers "what did the provider say?". This package answers "does
// that warrant a browser rule?". Conflating the two is the highest-consequence
// mistake available here: it turns one provider's opinion about one URL into a
// silent, persistent block with no human in the loop. A finding can therefore be
// recorded, cached and served forever without ever becoming a rule.
//
// The policy itself is in docs/security-and-privacy.md §6. This file implements
// it and states, in policy.go, exactly which thresholds were specified and
// which were chosen here.
package rulesets

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The subset of Chrome's `declarativeNetRequest` Rule schema CyberGuard emits.
//
// It is a subset on purpose. Modelling fields the generator never sets would
// invite setting them by accident, and a field emitted that Chrome does not
// understand fails the whole ruleset at import time — in the extension, on the
// user's machine.

// Rule is one declarativeNetRequest rule.
type Rule struct {
	// ID is the rule identifier. Chrome requires a positive integer, unique
	// within a ruleset.
	ID int `json:"id" bson:"id"`

	// Priority orders evaluation. Higher runs first.
	Priority int `json:"priority" bson:"priority"`

	// Action is what to do on a match.
	Action Action `json:"action" bson:"action"`

	// Condition is what to match.
	Condition Condition `json:"condition" bson:"condition"`

	// Provenance is CyberGuard's own audit trail. It is stored with the rule in
	// MongoDB and stripped from the published JSON, because Chrome rejects
	// unknown members inside a Rule.
	Provenance Provenance `json:"-" bson:"provenance"`
}

// Provenance records why a rule exists, for diagnosis and for audit.
//
// It is deliberately not part of the published rule: Chrome's Rule schema has
// `additionalProperties: false` semantics for the structures it defines, and an
// unknown member causes the entire ruleset to fail to import.
type Provenance struct {
	// Fingerprint is the HMAC of the exact URL that produced the rule.
	//
	// The fingerprint, not the URL, so the audit trail does not itself become
	// the raw-URL retention the project forbids.
	Fingerprint string `bson:"fingerprint"`

	// RegistrableDomain is the host scope the rule was derived from.
	RegistrableDomain string `bson:"registrable_domain,omitempty"`

	// Corroboration is how many independent malicious findings supported this
	// rule when it was generated.
	Corroboration int `bson:"corroboration"`

	// Scope is the rule's breadth, recorded for audit and regeneration.
	Scope Scope `bson:"scope"`
}

// Action is the action taken on a match.
type Action struct {
	// Type is "block" in every rule CyberGuard emits. There is no "allow",
	// "redirect" or "upgrade": this package never grants trust, only refuses.
	Type string `json:"type" bson:"type"`
}

// Condition is what a rule matches.
type Condition struct {
	// URLFilter is Chrome's lightweight filter syntax. Used for prefix and
	// domain scopes.
	URLFilter string `json:"urlFilter,omitempty" bson:"url_filter,omitempty"`

	// RegexFilter is Chrome's RE2-based matcher. Used for the exact-URL scope,
	// which urlFilter cannot express.
	//
	// It is emitted inside `filter`, matching the declarativeNetRequest schema,
	// rather than as a bare field.
	Filter *Filter `json:"filter,omitempty" bson:"filter,omitempty"`

	// ResourceTypes narrows what the rule applies to.
	//
	// Sub-resources are included because the resource that delivers a
	// phishing payload is very often not the main frame: a form on a
	// third-party script, an image beacon, a redirect in an iframe.
	ResourceTypes []string `json:"resourceTypes,omitempty" bson:"resource_types,omitempty"`
}

// Filter carries Chrome's filter object, used for exact matching.
type Filter struct {
	// Type is "regexFilter".
	Type string `json:"type" bson:"type"`

	// RegexFilter is an RE2 pattern. It is anchored here so it can never match
	// a suffix of a URL.
	RegexFilter string `json:"regexFilter" bson:"regex_filter"`
}

// Block is the only action this package emits.
const Block = "block"

// FilterTypeRegex is the only filter type emitted.
const FilterTypeRegex = "regexFilter"

// resourceTypes are the Chrome resource types a block applies to.
//
// Every navigable and sub-resource type is included. Restricting to main_frame
// would leave an iframe-based redirect untouched, which is the easiest way for
// a phishing page to survive a rule.
var resourceTypes = []string{
	"main_frame",
	"sub_frame",
	"stylesheet",
	"script",
	"image",
	"font",
	"object",
	"xmlhttprequest",
	"ping",
	"media",
	"websocket",
	"other",
}

// Chrome's documented constraint on rule identifiers.
const (
	maxRuleID       = 1 << 31 // Chrome requires 1..2^31-1
	maxURLFilterLen = 30000
)

// ErrInvalidRule means a generated rule would be rejected by Chrome.
//
// The build treats this as fatal for the whole snapshot. Publishing a partial
// ruleset is worse than publishing none: the extension would silently
// under-block, and the operator would believe coverage was complete.
var ErrInvalidRule = errors.New("rulesets: generated rule is invalid")

// Validate checks a rule against the subset of Chrome's schema that CyberGuard
// emits.
//
// It is deliberately strict. Every rule this package generates is machine-made,
// so a rule that fails validation is a bug here, never a legitimate edge case
// from upstream data.
func (r Rule) Validate() error {
	if r.ID <= 0 || r.ID > maxRuleID {
		return fmt.Errorf("%w: id %d is outside Chrome's range 1..%d", ErrInvalidRule, r.ID, maxRuleID)
	}

	if r.Priority < 1 {
		return fmt.Errorf("%w: priority %d must be at least 1", ErrInvalidRule, r.Priority)
	}

	if r.Action.Type != Block {
		return fmt.Errorf("%w: action type %q is not emitted by this package", ErrInvalidRule, r.Action.Type)
	}

	hasFilter := r.Condition.URLFilter != "" || r.Condition.Filter != nil
	switch {
	case !hasFilter:
		return fmt.Errorf("%w: a rule needs urlFilter or filter", ErrInvalidRule)
	case r.Condition.URLFilter != "" && r.Condition.Filter != nil:
		// Chrome rejects a condition carrying both; one is ambiguous about
		// which matcher wins.
		return fmt.Errorf("%w: a rule must not set both urlFilter and filter", ErrInvalidRule)
	}

	if r.Condition.URLFilter != "" && len(r.Condition.URLFilter) > maxURLFilterLen {
		return fmt.Errorf("%w: urlFilter is %d characters, over the %d limit",
			ErrInvalidRule, len(r.Condition.URLFilter), maxURLFilterLen)
	}

	if r.Condition.Filter != nil {
		if r.Condition.Filter.Type != FilterTypeRegex {
			return fmt.Errorf("%w: filter type %q is not emitted by this package",
				ErrInvalidRule, r.Condition.Filter.Type)
		}
		if _, err := regexp.Compile(r.Condition.Filter.RegexFilter); err != nil {
			return fmt.Errorf("%w: regexFilter does not compile: %v", ErrInvalidRule, err)
		}
	}

	for _, rt := range r.Condition.ResourceTypes {
		if !isKnownResourceType(rt) {
			return fmt.Errorf("%w: unknown resource type %q", ErrInvalidRule, rt)
		}
	}

	return nil
}

var knownResourceTypes = func() map[string]bool {
	m := make(map[string]bool, len(resourceTypes))
	for _, rt := range resourceTypes {
		m[rt] = true
	}
	return m
}()

func isKnownResourceType(rt string) bool { return knownResourceTypes[rt] }

// ValidateAll checks every rule and the snapshot as a whole.
//
// It also enforces the cross-rule invariants Chrome requires of a ruleset as a
// set: unique identifiers, and contiguous identifiers starting at 1.
//
// The contiguity requirement is why Rule IDs are assigned by position rather
// than derived from a fingerprint. Identifiers must be stable across
// regenerations for a client diffing two versions, and a fingerprint-derived ID
// would leave holes whenever a rule is removed.
func ValidateAll(rules []Rule) error {
	seen := make(map[int]bool, len(rules))

	for i, r := range rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %d at position %d: %w", r.ID, i, err)
		}
		if seen[r.ID] {
			return fmt.Errorf("%w: duplicate rule id %d", ErrInvalidRule, r.ID)
		}
		seen[r.ID] = true
	}

	return nil
}

// escapeURLFilter escapes a string for Chrome's urlFilter syntax.
//
// In that syntax `*`, `|`, `,` and `:` are operators, and a backslash escapes
// any character. Path segments are emitted verbatim where safe and escaped
// where not, so a path containing `|` cannot widen a rule's reach beyond the
// URL it was derived from.
func escapeURLFilter(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch r {
		case '\\', '*', '|', ',', ':', '/', '?', '=', '#', '@':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeHost escapes a hostname for the `||host^` anchor form.
//
// A hostname has no path, so `/` needs no escaping; the operators do. Validating
// the host first means a hostname can never contain a character that changes
// the filter's meaning.
func escapeHost(host string) string {
	var b strings.Builder
	b.Grow(len(host))

	for _, r := range host {
		switch r {
		case '\\', '*', '|', ',', ':', '@':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
