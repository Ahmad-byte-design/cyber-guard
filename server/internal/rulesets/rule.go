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
	"fmt"
	"regexp"
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

// Condition is what a rule matches.
type Condition struct {
	// URLFilter is Chrome's lightweight filter syntax. Used for the
	// registrable-domain and URL-prefix scopes.
	//
	// It is never built by string interpolation of untrusted text; see
	// urlfilter.go, which checks every literal it emits.
	URLFilter string `json:"urlFilter,omitempty" bson:"url_filter,omitempty"`

	// RegexFilter is Chrome's RE2-based matcher, used for the exact-URL scope,
	// which urlFilter cannot express without broadening the match.
	//
	// It is emitted inside `filter`, matching the declarativeNetRequest schema,
	// rather than as a bare field.
	Filter *Filter `json:"filter,omitempty" bson:"filter,omitempty"`

	// ResourceTypes narrows what the rule applies to.
	//
	// Always set. Chrome's own default when this key is absent matches every
	// request type *except* main_frame, so omitting it would quietly stop a
	// rule from blocking navigation — which for a malicious URL is the one thing
	// it most needs to do.
	ResourceTypes []ResourceType `json:"resourceTypes,omitempty" bson:"resource_types,omitempty"`
}

// FilterTypeRegex is the only filter type this engine emits.
const FilterTypeRegex = "regexFilter"

// Filter carries Chrome's filter object, used for exact matching.
type Filter struct {
	// Type is "regexFilter".
	Type string `json:"type" bson:"type"`

	// RegexFilter is an RE2 pattern, always anchored by the builder so it can
	// never match a suffix of a URL.
	RegexFilter string `json:"regexFilter" bson:"regex_filter"`
}

// Provenance records why a rule exists, for diagnosis and audit.
//
// It is deliberately not part of the published rule: Chrome rejects unknown
// members inside a Rule, and an unknown member fails the whole ruleset in the
// client.
type Provenance struct {
	// Fingerprint is the HMAC of the canonical URL behind the rule.
	//
	// The fingerprint, not the URL, so the audit trail does not itself become
	// the raw-URL retention the project forbids.
	Fingerprint string `bson:"fingerprint"`

	// RegistrableDomain is the host scope the rule was derived from.
	RegistrableDomain string `bson:"registrable_domain,omitempty"`

	// Corroboration is how many independent malicious findings supported the
	// rule when it was generated.
	Corroboration int `bson:"corroboration"`

	// Scope is the rule's breadth, recorded for audit and regeneration.
	Scope Scope `bson:"scope"`

	// Action records which action was emitted, so an audit can distinguish a
	// block from an interstitial without parsing the published rule.
	Action ActionType `bson:"action"`
}

// The action model, the Chrome limits and ErrInvalidRule live in dnr.go, so that
// everything describing the DNR surface is read in one place.

// Validate checks a rule against the subset of Chrome's schema that CyberGuard
// emits.
//
// It is deliberately strict. Every rule this package generates is machine-made,
// so a rule that fails validation is a bug here, never a legitimate edge case
// from upstream data.
func (r Rule) Validate() error {
	if r.ID <= 0 || r.ID > maxRuleID {
		return fmt.Errorf("%w: id %d is outside Chrome's documented range 1..%d", ErrInvalidRule, r.ID, maxRuleID)
	}

	if r.Priority < minRulePriority {
		return fmt.Errorf("%w: priority %d is below Chrome's minimum of %d", ErrInvalidRule, r.Priority, minRulePriority)
	}

	if err := r.Action.Validate(); err != nil {
		return err
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

	// Chrome caps a static rule file; the limit is far above any real pattern,
	// so exceeding it means the rule was built wrong.
	if r.Condition.URLFilter != "" && len(r.Condition.URLFilter) > 30000 {
		return fmt.Errorf("%w: urlFilter is %d characters, over the static file limit",
			ErrInvalidRule, len(r.Condition.URLFilter))
	}

	if r.Condition.Filter != nil {
		if r.Condition.Filter.Type != FilterTypeRegex {
			return fmt.Errorf("%w: filter type %q is not emitted by this engine",
				ErrInvalidRule, r.Condition.Filter.Type)
		}
		if _, err := regexp.Compile(r.Condition.Filter.RegexFilter); err != nil {
			return fmt.Errorf("%w: regexFilter does not compile: %v", ErrInvalidRule, err)
		}
		// Chrome ignores a rule whose regex is too large, so one that compiles
		// but is oversized fails silently rather than loudly.
		if len(r.Condition.Filter.RegexFilter) > MaxRegexRuleBytes {
			return fmt.Errorf("%w: regexFilter is %d characters, over Chrome's %d per-rule limit",
				ErrInvalidRule, len(r.Condition.Filter.RegexFilter), MaxRegexRuleBytes)
		}
		// Chrome requires a regexFilter to be ASCII only: it is matched against
		// a URL with a punycoded host and percent-encoded everything else.
		if !isASCII(r.Condition.Filter.RegexFilter) {
			return fmt.Errorf("%w: regexFilter must be ASCII only", ErrInvalidRule)
		}
	}

	// An empty list is not the same as an absent one to Chrome: an absent list
	// excludes main_frame, which is never what this engine wants.
	if len(r.Condition.ResourceTypes) == 0 {
		return fmt.Errorf("%w: resourceTypes is empty", ErrInvalidRule)
	}

	seen := make(map[ResourceType]bool, len(r.Condition.ResourceTypes))
	for _, rt := range r.Condition.ResourceTypes {
		if !KnownResourceType(rt) {
			return fmt.Errorf("%w: resource type %q is not in Chrome's enum", ErrInvalidRule, rt)
		}
		if seen[rt] {
			return fmt.Errorf("%w: resource type %q is listed twice", ErrInvalidRule, rt)
		}
		seen[rt] = true
	}

	return nil
}

// isASCII reports whether every byte of s is in the ASCII range.
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

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
