package mongostore

import (
	"testing"
	"time"

	"cyberguard/server/internal/verdicts"
)

// The structural privacy checks live in transienturl_test.go alongside the
// reflection helper they share. This file covers the remaining pure model
// behaviour.

func TestScanStatusValidity(t *testing.T) {
	t.Parallel()

	for _, s := range []ScanStatus{
		ScanQueued, ScanRunning, ScanCompleted, ScanFailed, ScanTimedOut, ScanExpired,
	} {
		if !s.Valid() {
			t.Errorf("%q reported invalid", s)
		}
	}
	for _, s := range []ScanStatus{"", "pending", "done", "QUEUED", "in_progress"} {
		if s.Valid() {
			t.Errorf("%q reported valid", s)
		}
	}
}

// activeStatuses drives the partial unique index that prevents duplicate
// provider submissions, so it must contain exactly the in-flight statuses.
func TestActiveStatusSet(t *testing.T) {
	t.Parallel()

	if len(activeStatuses) != 2 {
		t.Fatalf("activeStatuses = %v, want exactly queued and running", activeStatuses)
	}
	for _, s := range activeStatuses {
		if !s.IsActive() {
			t.Errorf("%q is in activeStatuses but IsActive() is false", s)
		}
	}
	for _, s := range []ScanStatus{ScanCompleted, ScanFailed, ScanTimedOut, ScanExpired, "unknown"} {
		if s.IsActive() {
			t.Errorf("%q reports IsActive() but is terminal", s)
		}
	}
}

func TestAssessmentFreshness(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		until time.Time
		want  bool
	}{
		{"expires in an hour", now.Add(time.Hour), true},
		{"expires exactly now is stale", now, false},
		{"expired an hour ago", now.Add(-time.Hour), false},
	}

	for _, tc := range cases {
		a := Assessment{ExpiresAt: tc.until}
		if got := a.IsFresh(now); got != tc.want {
			t.Errorf("%s: IsFresh = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The assessment stores verdicts.Verdict, not a bare string, so reintroducing
// "benign" would not compile.
func TestAssessmentCarriesTheRealVerdictVocabulary(t *testing.T) {
	t.Parallel()

	for _, v := range verdicts.All() {
		a := Assessment{Verdict: v}
		if !a.Verdict.Valid() {
			t.Errorf("verdict %q is not valid", v)
		}
	}
	if (Assessment{Verdict: "benign"}).Verdict.Valid() {
		t.Error("benign is accepted; ADR 0011 replaced it with no_threat_detected")
	}
}
