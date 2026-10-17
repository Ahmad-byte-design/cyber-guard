// Package rulesetapi adapts the ruleset domain to HTTP and MongoDB.
//
// It exists so `internal/rulesets` stays free of transport and persistence
// concerns: the policy and the rule builder have no opinion about MongoDB
// indexes or JSON responses, which is what keeps them testable in isolation and
// keeps a change to either from reaching into the other.
package rulesetapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/rulesets"
)

// Store is the persistence the ruleset service needs.
//
// It is declared here, at the consumer, so `internal/rulesets` stays free of
// persistence concerns and the unit tests need no database.
type Store interface {
	CurrentRuleset(ctx context.Context) (mongostore.Ruleset, error)
	RulesetAtVersion(ctx context.Context, version int64) (mongostore.Ruleset, error)
	PublishRuleset(ctx context.Context, rs mongostore.Ruleset) (mongostore.Ruleset, bool, error)
	ListRulesetVersions(ctx context.Context, limit int64) ([]int64, error)

	// EligibleAssessments returns fresh assessments that could become rules.
	EligibleAssessments(ctx context.Context, now time.Time, limit int64) ([]mongostore.Assessment, error)
}

// Service builds and serves rulesets.
type Service struct {
	store     Store
	generator *rulesets.Generator
	now       func() time.Time
}

// New builds a Service.
func New(store Store, generator *rulesets.Generator, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, generator: generator, now: now}
}

// Snapshot is what the HTTP layer serves.
type Snapshot struct {
	Version     int64     `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Rules       []Rule    `json:"rules"`

	// Unchanged is true when the client already has this version.
	Unchanged bool `json:"unchanged,omitempty"`

	// RolledBack is true when the client claims a newer version than the
	// server has, meaning it installed a ruleset from a different deployment.
	RolledBack bool `json:"-"`
}

// Rule is the published rule shape.
type Rule struct {
	ID        int       `json:"id"`
	Priority  int       `json:"priority"`
	Action    Action    `json:"action"`
	Condition Condition `json:"condition"`
}

// Action is the published action shape.
type Action struct {
	Type string `json:"type"`
}

// Condition is the published condition shape.
type Condition struct {
	URLFilter     string   `json:"urlFilter,omitempty"`
	Filter        *Filter  `json:"filter,omitempty"`
	ResourceTypes []string `json:"resourceTypes,omitempty"`
}

// Filter is the published filter shape.
type Filter struct {
	Type        string `json:"type"`
	RegexFilter string `json:"regexFilter"`
}

// Fetch returns the current ruleset for publication.
//
// The version is read, not recomputed: this endpoint never publishes. Generation
// is the worker's job, so a read-heavy endpoint cannot turn into a write-heavy
// one, and a burst of clients cannot each trigger a rebuild.
func (s *Service) Fetch(ctx context.Context) (Snapshot, error) {
	current, err := s.store.CurrentRuleset(ctx)
	switch {
	case errors.Is(err, mongostore.ErrRulesetNotFound):
		// Version 0 with no rules is the documented, truthful representation of
		// "nothing has been published". It is not an error.
		return Snapshot{
			Version:     0,
			GeneratedAt: s.now().UTC(),
			Rules:       []Rule{},
		}, nil
	case err != nil:
		return Snapshot{}, fmt.Errorf("rulesetapi: fetch: %w", err)
	}

	return snapshotFrom(current), nil
}

// Build regenerates the snapshot and publishes it if the effective rule set
// changed.
//
// It is called by the worker after a scan completes, not by a client request.
// An unchanged rule set returns created=false and does not increment the
// version, which is what stops every scan from making every extension
// re-download.
func (s *Service) Build(ctx context.Context) (Snapshot, bool, error) {
	now := s.now().UTC()

	assessments, err := s.store.EligibleAssessments(ctx, now, eligibleScanLimit)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("rulesetapi: eligible assessments: %w", err)
	}

	candidates := toCandidates(assessments)

	snap, err := s.generator.Generate(ctx, candidates, now)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("rulesetapi: generate: %w", err)
	}

	published, created, err := s.store.PublishRuleset(ctx, mongostore.Ruleset{
		GeneratedAt:     snap.GeneratedAt,
		Rules:           toStoredRules(snap.Rules),
		Digest:          snap.Digest,
		SuppressedCount: snap.SuppressedCount,
	})
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("rulesetapi: publish: %w", err)
	}

	if !created {
		// Unchanged: report the snapshot already in force, not the one that
		// was about to be published.
		return snapshotFrom(published), false, nil
	}
	return snapshotFrom(published), true, nil
}

// eligibleScanLimit bounds how many findings one rebuild considers.
//
// A rebuild that considered every assessment ever written would grow without
// bound and would eventually exceed the response a client can hold. Findings
// are ordered by recency, so the cap keeps the most relevant ones and the
// SuppressedCount records that more existed.
const eligibleScanLimit = 50000

// snapshotFrom converts a stored snapshot into the published shape.
func snapshotFrom(rs mongostore.Ruleset) Snapshot {
	out := Snapshot{
		Version:     rs.Version,
		GeneratedAt: rs.GeneratedAt.UTC(),
		Rules:       make([]Rule, 0, len(rs.Rules)),
	}
	for _, r := range rs.Rules {
		rule := Rule{
			ID:       r.ID,
			Priority: r.Priority,
			Action:   Action{Type: r.Action.Type},
			Condition: Condition{
				URLFilter: r.Condition.URLFilter,
			},
		}
		if r.Condition.Filter != nil {
			rule.Condition.Filter = &Filter{
				Type:        r.Condition.Filter.Type,
				RegexFilter: r.Condition.Filter.RegexFilter,
			}
		}
		rule.Condition.ResourceTypes = append([]string(nil), r.Condition.ResourceTypes...)
		out.Rules = append(out.Rules, rule)
	}
	return out
}

// toCandidates projects assessments onto ruleset candidates.
//
// An assessment whose verdict is not rule-eligible is dropped here rather than
// later, so an ineligible finding never reaches the corroboration queries — and
// so a benign or failed assessment never contributes to another finding's
// evidence.
func toCandidates(assessments []mongostore.Assessment) []rulesets.Candidate {
	var out []rulesets.Candidate

	for _, a := range assessments {
		if a.Hostname == "" {
			continue
		}
		c := rulesets.Candidate{
			Fingerprint:       a.URLFingerprint,
			Hostname:          a.Hostname,
			RegistrableDomain: a.RegistrableDomain,
			Verdict:           a.Verdict,
			Scheme:            a.Scheme,
			PathPrefix:        a.PathPrefix,
			AnalyzedAt:        a.AnalyzedAt,
			ExpiresAt:         a.ExpiresAt,
		}
		if !rulesets.EligibleVerdict(c.Verdict) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// toStoredRules converts generated rules into their stored shape.
func toStoredRules(rules []rulesets.Rule) []mongostore.Rule {
	out := make([]mongostore.Rule, 0, len(rules))
	for _, r := range rules {
		stored := mongostore.Rule{
			ID:       r.ID,
			Priority: r.Priority,
			Action:   mongostore.RuleAction{Type: r.Action.Type},
			Condition: mongostore.RuleCondition{
				URLFilter:     r.Condition.URLFilter,
				ResourceTypes: append([]string(nil), r.Condition.ResourceTypes...),
			},
			Provenance: mongostore.RuleProvenance{
				Fingerprint:       r.Provenance.Fingerprint,
				RegistrableDomain: r.Provenance.RegistrableDomain,
				Corroboration:     r.Provenance.Corroboration,
				Scope:             r.Provenance.Scope.String(),
			},
		}
		if r.Condition.Filter != nil {
			stored.Condition.Filter = &mongostore.RuleFilter{
				Type:        r.Condition.Filter.Type,
				RegexFilter: r.Condition.Filter.RegexFilter,
			}
		}
		out = append(out, stored)
	}
	return out
}
