package mongostore

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"cyberguard/server/internal/rulesets"
	"cyberguard/server/internal/verdicts"
)

// Ruleset snapshots and their monotonic version.
//
// # The version is the primary key, and that is the whole concurrency story
//
// `rulesets._id` is the version number. Publishing is therefore an insert with a
// candidate version of "current + 1", and the database rejects it with a
// duplicate-key error if another writer got there first. Monotonicity under
// concurrency is enforced by the database rather than by a read-then-write in
// Go, which is the only approach that actually holds under load.
//
// # Why there is no `ruleset_meta` counter
//
// docs/data-model.md lists a `ruleset_meta` collection holding a monotonic
// version counter. Deriving the version from the highest snapshot instead makes
// that counter unnecessary *and* removes the failure mode it introduces: a
// counter and a snapshot can disagree, and a counter that advanced past a
// failed snapshot leaves a permanent gap in the version sequence, so a client
// that saw version 12 could never install version 13.
//
// This is a deliberate deviation from the data model. See ADR 0018.

// CollectionRulesets holds immutable, versioned ruleset snapshots.
const CollectionRulesets = "rulesets"

// Rule is one declarativeNetRequest rule as stored.
//
// It mirrors the published shape, with provenance kept separately because
// Chrome rejects unknown members inside a Rule.
type Rule struct {
	ID         int            `bson:"id"          json:"id"`
	Priority   int            `bson:"priority"    json:"priority"`
	Action     RuleAction     `bson:"action"   json:"action"`
	Condition  RuleCondition  `bson:"condition" json:"condition"`
	Provenance RuleProvenance `bson:"provenance" json:"-"`
}

// RuleAction is what a rule does on a match.
type RuleAction struct {
	Type     string    `bson:"type"              json:"type"`
	Redirect *Redirect `bson:"redirect,omitempty" json:"redirect,omitempty"`
}

// Redirect is the persisted redirect target of a redirect rule.
//
// Only extension_path is modelled. Chrome also permits `url` and `transform`;
// neither is emitted by this engine, and modelling them would make it possible
// to persist a redirect that leaves the extension.
type Redirect struct {
	ExtensionPath string `bson:"extension_path" json:"extensionPath"`
}

// RuleCondition is what a rule matches.
type RuleCondition struct {
	URLFilter     string      `bson:"url_filter,omitempty"     json:"urlFilter,omitempty"`
	Filter        *RuleFilter `bson:"filter,omitempty"         json:"filter,omitempty"`
	ResourceTypes []string    `bson:"resource_types,omitempty" json:"resourceTypes,omitempty"`
}

// RuleFilter carries Chrome's filter object, used for exact matching.
type RuleFilter struct {
	Type        string `bson:"type"         json:"type"`
	RegexFilter string `bson:"regex_filter" json:"regexFilter"`
}

// RuleProvenance is CyberGuard's audit trail for a rule.
//
// It is stored with the rule but never published. The URL fingerprint is
// recorded instead of the URL, so the audit trail does not become the raw-URL
// retention the project forbids.
type RuleProvenance struct {
	Fingerprint       string `bson:"fingerprint"`
	RegistrableDomain string `bson:"registrable_domain,omitempty"`
	Corroboration     int    `bson:"corroboration"`
	Scope             string `bson:"scope"`
	Action            string `bson:"action"`
}

// Ruleset is one immutable published snapshot.
type Ruleset struct {
	// Version is the document _id. Zero means "nothing published yet", which is
	// why version 0 is never stored: the empty state is represented by the
	// absence of any document, and a client sees version 0 with no rules.
	Version int64 `bson:"_id" json:"version"`

	GeneratedAt time.Time `bson:"generated_at" json:"generated_at"`
	Rules       []Rule    `bson:"rules"       json:"rules"`

	// Digest covers the effective rule set, so a rebuild producing identical
	// rules is recognised as unchanged and does not bump the version.
	Digest string `bson:"digest" json:"-"`

	SuppressedCount int `bson:"suppressed_count" json:"-"`
}

// ErrRulesetNotFound is returned when nothing has been published yet.
var ErrRulesetNotFound = errors.New("mongostore: no ruleset has been published")

// CurrentRuleset returns the newest published snapshot.
//
// It is a single indexed lookup: the version is the primary key, so "newest" is
// a descending scan of one index and stops at the first document.
func (s *Store) CurrentRuleset(ctx context.Context) (Ruleset, error) {
	if s == nil || s.db == nil {
		return Ruleset{}, ErrClosed
	}

	var rs Ruleset
	err := s.db.Collection(CollectionRulesets).
		FindOne(ctx, bson.M{}, options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})).
		Decode(&rs)

	switch {
	case err == nil:
		return rs, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Ruleset{}, ErrRulesetNotFound
	default:
		return Ruleset{}, fmt.Errorf("mongostore: current ruleset: %w", err)
	}
}

// RulesetAtVersion returns a specific snapshot.
func (s *Store) RulesetAtVersion(ctx context.Context, version int64) (Ruleset, error) {
	if s == nil || s.db == nil {
		return Ruleset{}, ErrClosed
	}

	var rs Ruleset
	err := s.db.Collection(CollectionRulesets).FindOne(ctx, bson.M{"_id": version}).Decode(&rs)

	switch {
	case err == nil:
		return rs, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Ruleset{}, ErrRulesetNotFound
	default:
		return Ruleset{}, fmt.Errorf("mongostore: ruleset %d: %w", version, err)
	}
}

// PublishRuleset stores a snapshot, assigning it the next version.
//
// It returns the stored snapshot and whether it was created. `created` is false
// when the effective rule set has not changed, in which case the version is not
// incremented and no document is written.
//
// The version is assigned by the database rejecting a duplicate, not by a
// read-then-write, so two concurrent publishers cannot both believe they won.
// A loser simply retries and either finds nothing changed, or competes again.
//
// The retry budget is deliberately small. A caller that loses repeatedly is
// contending with heavy concurrent publication, and returning an error is
// better than spinning.
func (s *Store) PublishRuleset(ctx context.Context, rs Ruleset) (Ruleset, bool, error) {
	if s == nil || s.db == nil {
		return Ruleset{}, false, ErrClosed
	}

	const maxAttempts = 12

	for attempt := range maxAttempts {
		current, err := s.CurrentRuleset(ctx)
		switch {
		case errors.Is(err, ErrRulesetNotFound):
			// Nothing published yet. Version 0 is the documented "empty"
			// representation, so the first real snapshot is version 1.
			current = Ruleset{Version: 0}
		case err != nil:
			return Ruleset{}, false, err
		}

		if current.Digest != "" && current.Digest == rs.Digest {
			// The effective rule set is unchanged. Not bumping the version is
			// what stops every scan from making every extension re-download.
			return current, false, nil
		}

		next := current.Version + 1
		candidate := rs
		candidate.Version = next
		if candidate.Rules == nil {
			// An empty rules array is not the same as a missing one: the
			// response contract requires the field.
			candidate.Rules = []Rule{}
		}

		_, err = s.db.Collection(CollectionRulesets).InsertOne(ctx, candidate)
		switch {
		case err == nil:
			return candidate, true, nil
		case mongo.IsDuplicateKeyError(err):
			// Another writer took this version. The snapshot we hold is still
			// valid; only its version was stale, so re-read and try again.
			//
			// The backoff is what makes this converge. Retrying immediately
			// would be a thundering herd: every loser re-reads the same
			// version, tries the same next one, and collides again. Jitter
			// spreads them out, and growing it means the longer the race
			// persists the less traffic it carries.
			if !sleepCtx(ctx, publishBackoff(attempt)) {
				return Ruleset{}, false, context.Cause(ctx)
			}
			continue
		default:
			return Ruleset{}, false, fmt.Errorf("mongostore: publish ruleset: %w", err)
		}
	}

	return Ruleset{}, false, fmt.Errorf("mongostore: publish ruleset: lost the version race %d times", maxAttempts)
}

// ListRulesetVersions returns the published versions, newest first.
func (s *Store) ListRulesetVersions(ctx context.Context, limit int64) ([]int64, error) {
	if s == nil || s.db == nil {
		return nil, ErrClosed
	}
	if limit <= 0 {
		limit = 20
	}

	cur, err := s.db.Collection(CollectionRulesets).
		Find(ctx, bson.M{}, options.Find().
			SetSort(bson.D{{Key: "_id", Value: -1}}).
			SetProjection(bson.M{"_id": 1}).
			SetLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("mongostore: list ruleset versions: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	var docs []struct {
		ID int64 `bson:"_id"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("mongostore: decode ruleset versions: %w", err)
	}

	out := make([]int64, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.ID)
	}
	return out, nil
}

// DeleteRulesetsBefore removes snapshots older than a version.
//
// Snapshots are immutable and unbounded by design — a client may be several
// versions behind — so pruning is an explicit operator action rather than a TTL
// that would delete history a slow client still needs.
func (s *Store) DeleteRulesetsBefore(ctx context.Context, version int64) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrClosed
	}
	res, err := s.db.Collection(CollectionRulesets).
		DeleteMany(ctx, bson.M{"_id": bson.M{"$lt": version}})
	if err != nil {
		return 0, fmt.Errorf("mongostore: prune rulesets: %w", err)
	}
	return res.DeletedCount, nil
}

// EnsureRulesetIndexes creates the indexes the ruleset queries need.
//
// It is separate from EnsureIndexes because rulesets are a new concern: an
// operator migrating an existing deployment should be able to see what this adds
// before it runs.
func (s *Store) EnsureRulesetIndexes(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}

	_, err := s.db.Collection(CollectionRulesets).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			// The primary key is the version, so descending order needs no
			// separate index. The only extra index is on generation time, for
			// an operator asking "when was this last rebuilt?".
			Keys:    bson.D{{Key: "generated_at", Value: -1}},
			Options: options.Index().SetName("by_generated_at"),
		},
	})
	if err != nil {
		return fmt.Errorf("mongostore: ruleset indexes: %w", err)
	}
	return nil
}

// ---------------------------------------------------- ruleset evidence

// RulesetEvidence answers corroboration queries for the ruleset generator.
//
// It lives here rather than in internal/rulesets because the queries depend on
// the assessments indexes, and that knowledge belongs to the persistence layer.
// It satisfies rulesets.EvidenceSource.
type RulesetEvidence struct {
	store *Store
}

// NewRulesetEvidence builds an evidence source over a Store.
func (s *Store) NewRulesetEvidence() *RulesetEvidence {
	return &RulesetEvidence{store: s}
}

// Corroboration counts independent malicious findings for each reference.
//
// Every query filters on `expires_at > now` and `verdict: malicious`, so an
// expired or failed finding can never contribute to a rule. Counting distinct
// fingerprints — via $addToSet rather than $sum — is what makes "independent"
// true: two scans of one URL are one finding, and counting them separately
// would let a client inflate its own corroboration by asking for the same scan
// repeatedly.
func (e *RulesetEvidence) Corroboration(
	ctx context.Context,
	refs []rulesets.Reference,
	now time.Time,
) (map[string]rulesets.Corroboration, error) {
	out := make(map[string]rulesets.Corroboration, len(refs))
	if e == nil || e.store == nil || e.store.db == nil {
		return out, ErrClosed
	}
	if len(refs) == 0 {
		return out, nil
	}

	hostnames, domains, prefixesByHost := collect(refs)

	hostCounts, err := e.countBy(ctx, "hostname", hostnames, now)
	if err != nil {
		return nil, err
	}
	domainCounts, err := e.countBy(ctx, "registrable_domain", domains, now)
	if err != nil {
		return nil, err
	}
	prefixCounts, err := e.countPrefixes(ctx, prefixesByHost, now)
	if err != nil {
		return nil, err
	}

	for _, r := range refs {
		out[r.Fingerprint] = rulesets.Corroboration{
			HostFingerprints:   hostCounts[r.Hostname],
			PrefixFingerprints: prefixCounts[r.Hostname+"\x00"+r.PathPrefix],
			DomainFingerprints: domainCounts[r.RegistrableDomain],
		}
	}
	return out, nil
}

// collect de-duplicates the query inputs, so a hundred candidates on one host
// produce one $in clause rather than a hundred.
func collect(refs []rulesets.Reference) (hosts, domains []string, prefixesByHost map[string][]string) {
	seenHost := map[string]bool{}
	seenDomain := map[string]bool{}
	seenPrefix := map[string]map[string]bool{}
	prefixesByHost = make(map[string][]string)

	for _, r := range refs {
		if r.Hostname != "" && !seenHost[r.Hostname] {
			seenHost[r.Hostname] = true
			hosts = append(hosts, r.Hostname)
		}
		if r.RegistrableDomain != "" && !seenDomain[r.RegistrableDomain] {
			seenDomain[r.RegistrableDomain] = true
			domains = append(domains, r.RegistrableDomain)
		}
		if r.PathPrefix == "" || r.Hostname == "" {
			continue
		}
		if seenPrefix[r.Hostname] == nil {
			seenPrefix[r.Hostname] = map[string]bool{}
		}
		if !seenPrefix[r.Hostname][r.PathPrefix] {
			seenPrefix[r.Hostname][r.PathPrefix] = true
			prefixesByHost[r.Hostname] = append(prefixesByHost[r.Hostname], r.PathPrefix)
		}
	}
	return hosts, domains, prefixesByHost
}

// corroborationMatch is the filter every corroboration query shares.
func corroborationMatch(field string, values []string, now time.Time) bson.M {
	return bson.M{
		field:        bson.M{"$in": values},
		"verdict":    string(verdicts.Malicious),
		"expires_at": bson.M{"$gt": now},
	}
}

// countBy counts distinct fingerprints per distinct value of a field.
func (e *RulesetEvidence) countBy(ctx context.Context, field string, values []string, now time.Time) (map[string]int, error) {
	out := make(map[string]int, len(values))
	if len(values) == 0 {
		return out, nil
	}

	rows, err := e.aggregateDistinctCounts(ctx,
		mongo.Pipeline{
			{{Key: "$match", Value: corroborationMatch(field, values, now)}},
			{{Key: "$group", Value: bson.M{"_id": "$" + field, "fingerprints": bson.M{"$addToSet": "$_id"}}}},
			{{Key: "$project", Value: bson.M{"_id": 0, "key": "$_id", "count": bson.M{"$size": "$fingerprints"}}}},
		})
	if err != nil {
		return nil, fmt.Errorf("mongostore: corroboration by %s: %w", field, err)
	}

	for _, r := range rows {
		out[r.Key] = r.Count
	}
	return out, nil
}

// countPrefixes counts distinct fingerprints per (hostname, path prefix).
//
// It issues one query per distinct host rather than one per candidate: a
// hundred candidates on one host must not become a hundred round trips.
func (e *RulesetEvidence) countPrefixes(ctx context.Context, prefixesByHost map[string][]string, now time.Time) (map[string]int, error) {
	out := map[string]int{}

	for host, prefixes := range prefixesByHost {
		if len(prefixes) == 0 {
			continue
		}

		match := corroborationMatch("hostname", []string{host}, now)
		match["path_prefix"] = bson.M{"$in": prefixes}

		rows, err := e.aggregateDistinctCounts(ctx,
			mongo.Pipeline{
				{{Key: "$match", Value: match}},
				{{Key: "$group", Value: bson.M{"_id": "$path_prefix", "fingerprints": bson.M{"$addToSet": "$_id"}}}},
				{{Key: "$project", Value: bson.M{"_id": 0, "key": "$_id", "count": bson.M{"$size": "$fingerprints"}}}},
			})
		if err != nil {
			return nil, fmt.Errorf("mongostore: corroboration by prefix on %s: %w", host, err)
		}

		for _, r := range rows {
			out[host+"\x00"+r.Key] = r.Count
		}
	}
	return out, nil
}

// countRow is one grouped count.
type countRow struct {
	Key   string `bson:"key"`
	Count int    `bson:"count"`
}

func (e *RulesetEvidence) aggregateDistinctCounts(ctx context.Context, pipeline mongo.Pipeline) ([]countRow, error) {
	cur, err := e.store.db.Collection(CollectionAssessments).Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(ctx) }()

	var rows []countRow
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// EligibleAssessments returns fresh assessments that could become rules.
//
// Only `malicious` findings qualify, because the ruleset policy makes every
// other verdict ineligible by construction. Expiry is filtered here rather than
// relied upon from the TTL reaper, which runs about once a minute: a rule must
// not depend on when the reaper last ran.
func (s *Store) EligibleAssessments(ctx context.Context, now time.Time, limit int64) ([]Assessment, error) {
	if s == nil || s.db == nil {
		return nil, ErrClosed
	}
	if limit <= 0 {
		limit = 50000
	}

	cur, err := s.db.Collection(CollectionAssessments).Find(ctx, bson.M{
		"verdict":    string(verdicts.Malicious),
		"expires_at": bson.M{"$gt": now},
	}, options.Find().
		SetSort(bson.D{{Key: "analyzed_at", Value: -1}}).
		SetLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("mongostore: eligible assessments: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	var out []Assessment
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("mongostore: decode eligible assessments: %w", err)
	}
	return out, nil
}

// publishBackoff returns the wait before retrying a lost version race.
//
// It starts small, because most races are decided in one round trip, and grows
// so a contended publish stops carrying as many retries as it does early on.
// A random component keeps two writers from re-colliding in lockstep.
func publishBackoff(attempt int) time.Duration {
	base := 2 * time.Millisecond
	for range attempt {
		base *= 2
		if base >= 50*time.Millisecond {
			break
		}
	}
	jitter := time.Duration(rand.IntN(int(base/2) + 1)) //nolint:gosec // not security-relevant
	return base + jitter
}

// sleepCtx waits for d, returning false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
