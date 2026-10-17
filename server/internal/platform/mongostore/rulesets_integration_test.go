//go:build integration

package mongostore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/rulesets"
	"cyberguard/server/internal/verdicts"
)

// Ruleset publication against a real MongoDB.
//
//	docker compose up -d mongodb
//	docker compose run --rm go go test -tags integration ./internal/platform/mongostore/...
//
// The version is the primary key, so the interesting property is whether the
// database — not a read-then-write in Go — is what keeps versions monotonic and
// contiguous. That cannot be proven against an in-memory double.

func newRulesetStore(t *testing.T) *mongostore.Store {
	t.Helper()
	store := testDB(t)
	if err := store.EnsureRulesetIndexes(t.Context()); err != nil {
		t.Fatalf("EnsureRulesetIndexes: %v", err)
	}
	return store
}

func rulesetFixture(digest string, rules int) mongostore.Ruleset {
	rs := mongostore.Ruleset{
		GeneratedAt: time.Now().UTC(),
		Digest:      digest,
		Rules:       []mongostore.Rule{},
	}
	for i := range rules {
		rs.Rules = append(rs.Rules, mongostore.Rule{
			ID:       i + 1,
			Priority: 1,
			Action:   mongostore.RuleAction{Type: "block"},
			Condition: mongostore.RuleCondition{
				URLFilter:     `||evil.test^`,
				ResourceTypes: []string{"main_frame", "sub_frame"},
			},
			Provenance: mongostore.RuleProvenance{
				Fingerprint: "fingerprint-for-audit-not-publish",
				Scope:       "exact_url",
				Action:      "block",
			},
		})
	}
	return rs
}

// Nothing published reads as version 0, not as an error.
func TestCurrentRulesetReportsNothingPublished(t *testing.T) {
	store := newRulesetStore(t)

	if _, err := store.CurrentRuleset(t.Context()); !errors.Is(err, mongostore.ErrRulesetNotFound) {
		t.Fatalf("CurrentRuleset on an empty collection = %v, want ErrRulesetNotFound", err)
	}
}

// The first publication is version 1. Version 0 is reserved for "nothing
// published", so it is never stored.
func TestFirstPublicationIsVersionOne(t *testing.T) {
	store := newRulesetStore(t)

	rs, created, err := store.PublishRuleset(t.Context(), rulesetFixture("digest-a", 2))
	if err != nil {
		t.Fatalf("PublishRuleset: %v", err)
	}
	if !created {
		t.Error("created = false on the first publication")
	}
	if rs.Version != 1 {
		t.Errorf("version = %d, want 1", rs.Version)
	}
}

// An unchanged effective rule set must not bump the version.
//
// This is the single most important property for a polling client: if it held
// no value, every scan would make every client re-download.
func TestUnchangedRuleSetDoesNotBumpTheVersion(t *testing.T) {
	store := newRulesetStore(t)

	first, _, err := store.PublishRuleset(t.Context(), rulesetFixture("same-digest", 1))
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	for range 5 {
		again, created, err := store.PublishRuleset(t.Context(), rulesetFixture("same-digest", 1))
		if err != nil {
			t.Fatalf("republish: %v", err)
		}
		if created {
			t.Fatal("an identical rule set was republished")
		}
		if again.Version != first.Version {
			t.Fatalf("version moved from %d to %d with no change", first.Version, again.Version)
		}
	}

	versions, err := store.ListRulesetVersions(t.Context(), 50)
	if err != nil {
		t.Fatalf("ListRulesetVersions: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("%d snapshots exist, want exactly 1", len(versions))
	}
}

// A changed rule set is a new version, and the old one is retained: a client
// may still be on it.
func TestChangedRuleSetBumpsTheVersion(t *testing.T) {
	store := newRulesetStore(t)

	first, _, err := store.PublishRuleset(t.Context(), rulesetFixture("digest-a", 1))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, created, err := store.PublishRuleset(t.Context(), rulesetFixture("digest-b", 2))
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if !created {
		t.Error("created = false for a changed rule set")
	}
	if second.Version != first.Version+1 {
		t.Errorf("version = %d, want %d", second.Version, first.Version+1)
	}

	// The older snapshot is still readable, because a client may hold it.
	old, err := store.RulesetAtVersion(t.Context(), first.Version)
	if err != nil {
		t.Fatalf("RulesetAtVersion(%d): %v", first.Version, err)
	}
	if len(old.Rules) != 1 {
		t.Errorf("the retained snapshot has %d rules, want 1", len(old.Rules))
	}
}

// Removing a rule must publish as a new version rather than silently sticking.
func TestRemovingARuleIsPublishedAsANewVersion(t *testing.T) {
	store := newRulesetStore(t)

	_, _, err := store.PublishRuleset(t.Context(), rulesetFixture("with-rule", 3))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	reduced, created, err := store.PublishRuleset(t.Context(), rulesetFixture("without-rule", 1))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !created {
		t.Error("removing a rule did not publish a new version")
	}
	if len(reduced.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(reduced.Rules))
	}
}

// Concurrency: the version must stay monotonic and contiguous with no gaps and
// no duplicates.
//
// The database rejects a duplicate _id, so a writer that lost the race retries
// rather than believing it won. This is the property a read-then-write in Go
// could not deliver.
func TestConcurrentPublicationIsMonotonicAndContiguous(t *testing.T) {
	store := newRulesetStore(t)

	const writers = 16

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created []int64
		errs    []error
	)

	start := make(chan struct{})

	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			// A distinct digest per writer, so each one is a genuine change and
			// no writer is short-circuited as "unchanged".
			rs, wasCreated, err := store.PublishRuleset(t.Context(),
				rulesetFixture("digest-"+string(rune('a'+i)), i+1))

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if wasCreated {
				created = append(created, rs.Version)
			}
		}()
	}

	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Fatalf("concurrent PublishRuleset: %v", err)
	}

	if len(created) != writers {
		t.Fatalf("%d publications succeeded, want %d", len(created), writers)
	}

	versions, err := store.ListRulesetVersions(t.Context(), 100)
	if err != nil {
		t.Fatalf("ListRulesetVersions: %v", err)
	}

	seen := map[int64]bool{}
	for _, v := range versions {
		if seen[v] {
			t.Errorf("version %d appears twice", v)
		}
		seen[v] = true
	}

	// Newest first, and every version from 1 to N must exist.
	for i, v := range versions {
		want := int64(writers - i)
		if v != want {
			t.Errorf("version at position %d = %d, want %d: the sequence has a gap", i, v, want)
		}
	}
}

// Concurrent identical publications must collapse: the rule set did not
// change, so only one version may exist.
func TestConcurrentIdenticalPublicationsCollapseToOneVersion(t *testing.T) {
	store := newRulesetStore(t)

	const writers = 16

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		made int
		errs []error
	)

	start := make(chan struct{})
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			_, created, err := store.PublishRuleset(t.Context(), rulesetFixture("identical", 1))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if created {
				made++
			}
		}()
	}

	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Fatalf("PublishRuleset: %v", err)
	}
	if made != 1 {
		t.Errorf("%d writers published, want exactly 1", made)
	}

	versions, err := store.ListRulesetVersions(t.Context(), 50)
	if err != nil {
		t.Fatalf("ListRulesetVersions: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("%d snapshots exist, want 1", len(versions))
	}
}

// Pruning removes old snapshots without touching the current one.
func TestPruningKeepsTheCurrentVersion(t *testing.T) {
	store := newRulesetStore(t)

	for i := range 4 {
		if _, _, err := store.PublishRuleset(t.Context(), rulesetFixture("digest-"+string(rune('a'+i)), i+1)); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	current, err := store.CurrentRuleset(t.Context())
	if err != nil {
		t.Fatalf("CurrentRuleset: %v", err)
	}

	deleted, err := store.DeleteRulesetsBefore(t.Context(), current.Version)
	if err != nil {
		t.Fatalf("DeleteRulesetsBefore: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted %d snapshots, want 3", deleted)
	}

	after, err := store.CurrentRuleset(t.Context())
	if err != nil {
		t.Fatalf("the current version was pruned away: %v", err)
	}
	if after.Version != current.Version {
		t.Errorf("current version = %d, want %d", after.Version, current.Version)
	}
}

// ------------------------------------------------------- corroboration

// Corroboration must count distinct fingerprints on fresh malicious findings
// only. This is the query that decides whether a rule is published at all, so
// every clause of it is load-bearing.
func TestCorroborationCountsOnlyFreshMaliciousFindings(t *testing.T) {
	store := testDB(t)
	now := time.Now().UTC()

	seed := func(fingerprint, host, domain, path string, verdict verdicts.Verdict, expires time.Time) {
		t.Helper()
		_, err := store.PutAssessment(context.Background(), mongostore.Assessment{
			URLFingerprint:    fingerprint,
			ScanID:            "scan-" + fingerprint,
			Hostname:          host,
			RegistrableDomain: domain,
			Scheme:            "https",
			PathPrefix:        path,
			Verdict:           verdict,
			AnalyzedAt:        now.Add(-time.Hour),
			ExpiresAt:         expires,
		})
		if err != nil {
			t.Fatalf("seed %s: %v", fingerprint, err)
		}
	}

	// Three distinct malicious fingerprints on one host and prefix.
	seed("fp1", "evil.test", "evil.test", "/login", verdicts.Malicious, now.Add(time.Hour))
	seed("fp2", "evil.test", "evil.test", "/login", verdicts.Malicious, now.Add(time.Hour))
	seed("fp3", "evil.test", "evil.test", "/login", verdicts.Malicious, now.Add(time.Hour))

	// Findings that must NOT be counted.
	seed("expired", "expired.test", "expired.test", "/x", verdicts.Malicious, now.Add(-time.Hour))
	seed("benign", "benign.test", "benign.test", "/x", verdicts.NoThreatDetected, now.Add(time.Hour))
	seed("unknown", "unknown.test", "unknown.test", "/x", verdicts.Unknown, now.Add(time.Hour))

	evidence := store.NewRulesetEvidence()
	counts, err := evidence.Corroboration(context.Background(), []rulesets.Reference{
		{Fingerprint: "fp1", Hostname: "evil.test", RegistrableDomain: "evil.test", PathPrefix: "/login"},
		{Fingerprint: "expired", Hostname: "expired.test", RegistrableDomain: "expired.test", PathPrefix: "/x"},
		{Fingerprint: "benign", Hostname: "benign.test", RegistrableDomain: "benign.test", PathPrefix: "/x"},
		{Fingerprint: "unknown", Hostname: "unknown.test", RegistrableDomain: "unknown.test", PathPrefix: "/x"},
	}, now)
	if err != nil {
		t.Fatalf("Corroboration: %v", err)
	}

	if got := counts["fp1"].HostFingerprints; got != 3 {
		t.Errorf("host count = %d, want 3", got)
	}
	if got := counts["fp1"].PrefixFingerprints; got != 3 {
		t.Errorf("prefix count = %d, want 3", got)
	}
	if got := counts["fp1"].DomainFingerprints; got != 3 {
		t.Errorf("domain count = %d, want 3", got)
	}

	for _, fp := range []string{"expired", "benign", "unknown"} {
		if c := counts[fp]; c.HostFingerprints != 0 || c.DomainFingerprints != 0 {
			t.Errorf("%s counted %+v; an expired or ineligible finding must count for nothing", fp, c)
		}
	}
}

// Only malicious assessments are returned as eligible, so an ineligible finding
// can never even reach the corroboration stage.
func TestEligibleAssessmentsReturnsOnlyFreshMalicious(t *testing.T) {
	store := testDB(t)
	now := time.Now().UTC()

	for _, a := range []mongostore.Assessment{
		{URLFingerprint: "ok", ScanID: "s1", Hostname: "ok.test", Verdict: verdicts.Malicious,
			AnalyzedAt: now, ExpiresAt: now.Add(time.Hour)},
		{URLFingerprint: "expired", ScanID: "s2", Hostname: "expired.test", Verdict: verdicts.Malicious,
			AnalyzedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)},
		{URLFingerprint: "benign", ScanID: "s3", Hostname: "benign.test", Verdict: verdicts.NoThreatDetected,
			AnalyzedAt: now, ExpiresAt: now.Add(time.Hour)},
	} {
		if _, err := store.PutAssessment(context.Background(), a); err != nil {
			t.Fatalf("seed %s: %v", a.URLFingerprint, err)
		}
	}

	got, err := store.EligibleAssessments(context.Background(), now, 100)
	if err != nil {
		t.Fatalf("EligibleAssessments: %v", err)
	}
	if len(got) != 1 || got[0].URLFingerprint != "ok" {
		t.Errorf("got %d eligible assessments (%v), want only the fresh malicious one",
			len(got), got)
	}
}

// The scan record must not retain the URL detail once the verdict is known.
//
// The audit trail is long-lived, so the path fragment is copied onto the
// assessment and cleared here — otherwise every URL ever scanned would leave a
// path behind in a record that is never deleted.
func TestRecordScanTargetStoresThenClears(t *testing.T) {
	store := testDB(t)

	if _, _, err := store.CreateScan(context.Background(), mongostore.Scan{
		ScanID: "scan-1", URLFingerprint: "fp", Status: mongostore.ScanQueued,
	}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	if err := store.RecordScanTarget(context.Background(), "scan-1", "https", "", "/login", false); err != nil {
		t.Fatalf("RecordScanTarget: %v", err)
	}

	scan, err := store.GetScan(context.Background(), "scan-1")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if scan.Scheme != "https" || scan.PathPrefix != "/login" {
		t.Fatalf("the target detail was not stored: %+v", scan)
	}

	if err := store.RecordScanTarget(context.Background(), "scan-1", "", "", "", true); err != nil {
		t.Fatalf("clear: %v", err)
	}

	scan, err = store.GetScan(context.Background(), "scan-1")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if scan.Scheme != "" || scan.Port != "" || scan.PathPrefix != "" {
		t.Errorf("the target detail survived the clear: %+v", scan)
	}
}

// A redirect must survive a round trip through MongoDB.
//
// The redirect member is what tells a client to send the user to an interstitial
// rather than block the request, so a ruleset that loses it silently reverts to
// blocking. That is a behaviour change the client cannot see coming.
func TestRedirectActionRoundTrips(t *testing.T) {
	store := newRulesetStore(t)

	rs := mongostore.Ruleset{
		GeneratedAt: time.Now().UTC(),
		Digest:      "redirect-digest",
		Rules: []mongostore.Rule{{
			ID:       1,
			Priority: 1,
			Action: mongostore.RuleAction{
				Type:     "redirect",
				Redirect: &mongostore.Redirect{ExtensionPath: "/locked.html"},
			},
			Condition: mongostore.RuleCondition{
				URLFilter:     "||evil.test^",
				ResourceTypes: []string{"main_frame", "sub_frame"},
			},
		}},
	}

	if _, _, err := store.PublishRuleset(context.Background(), rs); err != nil {
		t.Fatalf("PublishRuleset: %v", err)
	}

	got, err := store.CurrentRuleset(context.Background())
	if err != nil {
		t.Fatalf("CurrentRuleset: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].Action.Type != "redirect" {
		t.Errorf("action.type = %q, want redirect", got.Rules[0].Action.Type)
	}
	if got.Rules[0].Action.Redirect == nil {
		t.Fatal("the redirect member was lost in storage")
	}
	if got.Rules[0].Action.Redirect.ExtensionPath != "/locked.html" {
		t.Errorf("extensionPath = %q, want /locked.html", got.Rules[0].Action.Redirect.ExtensionPath)
	}
}

// A block action must not acquire a redirect member in storage, so a client can
// rely on the member's absence.
func TestBlockActionNeverCarriesARedirectInStorage(t *testing.T) {
	store := newRulesetStore(t)

	rs, _, err := store.PublishRuleset(context.Background(), mongostore.Ruleset{
		GeneratedAt: time.Now().UTC(),
		Digest:      "block-digest",
		Rules: []mongostore.Rule{{
			ID:       1,
			Priority: 1,
			Action:   mongostore.RuleAction{Type: "block"},
			Condition: mongostore.RuleCondition{
				URLFilter: "||evil.test^", ResourceTypes: []string{"main_frame"},
			},
		}},
	})
	if err != nil {
		t.Fatalf("PublishRuleset: %v", err)
	}
	if rs.Rules[0].Action.Redirect != nil {
		t.Error("a block rule was stored with a redirect member")
	}
}

// Switching from block to redirect must produce a new version.
//
// If the digest ignored the action, a deployment that changed the action would
// keep serving the old ruleset, and every client would carry block rules while
// the operator believed the interstitial was live.
func TestChangingTheActionPublishesANewVersion(t *testing.T) {
	store := newRulesetStore(t)

	_, _, err := store.PublishRuleset(context.Background(), mongostore.Ruleset{
		GeneratedAt: time.Now().UTC(), Digest: "digest-block",
		Rules: []mongostore.Rule{{
			ID: 1, Priority: 1, Action: mongostore.RuleAction{Type: "block"},
			Condition: mongostore.RuleCondition{URLFilter: "||evil.test^", ResourceTypes: []string{"main_frame"}},
		}},
	})
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}

	second, created, err := store.PublishRuleset(context.Background(), mongostore.Ruleset{
		GeneratedAt: time.Now().UTC(), Digest: "digest-redirect",
		Rules: []mongostore.Rule{{
			ID: 1, Priority: 1,
			Action: mongostore.RuleAction{
				Type: "redirect", Redirect: &mongostore.Redirect{ExtensionPath: "/locked.html"},
			},
			Condition: mongostore.RuleCondition{URLFilter: "||evil.test^", ResourceTypes: []string{"main_frame"}},
		}},
	})
	if err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if !created {
		t.Error("changing the action did not publish a new version")
	}
	if second.Version != 2 {
		t.Errorf("version = %d, want 2", second.Version)
	}
}
