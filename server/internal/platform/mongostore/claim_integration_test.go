//go:build integration

// Lease semantics against a real MongoDB.
//
// These cannot be proven against an in-memory double. The property that matters
// most is that a claim is atomic — that is a property of the server's
// FindOneAndUpdate, not of any client-side logic, and a double would simply
// assume it.
//
// Run with:
//
//	docker compose run --rm go go test -tags integration ./internal/platform/mongostore/...
package mongostore_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"cyberguard/server/internal/platform/mongostore"
)

// activeScan writes a queued scan that is immediately claimable.
func activeScan(t *testing.T, store *mongostore.Store, id string) mongostore.Scan {
	t.Helper()
	now := time.Now().UTC()
	scan, created, err := store.CreateScan(t.Context(), mongostore.Scan{
		ScanID:         id,
		URLFingerprint: "fp-" + id,
		Hostname:       "example.test",
		Status:         mongostore.ScanQueued,
		Attempts:       0,
		MaxAttempts:    3,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	if err != nil || !created {
		t.Fatalf("CreateScan(%s): created=%v err=%v", id, created, err)
	}
	return scan
}

// A claim must exclude every other claimant. This is the whole guarantee: two
// consumers cannot both be handed the same scan, which is what stops a
// submission path from running twice.
func TestClaimIsExclusive(t *testing.T) {
	store := testDB(t)
	id := "claim-exclusive"
	activeScan(t, store, id)

	const claimants = 12
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []string
	)
	for range claimants {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scan, err := store.ClaimNextScan(t.Context(), time.Now().UTC(), time.Minute, "consumer")
			if err != nil {
				return
			}
			mu.Lock()
			winners = append(winners, scan.ScanID)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(winners) != 1 {
		t.Errorf("%d consumers claimed the single scan %v, want exactly 1", len(winners), winners)
	}
}

// A live lease hides the scan. This is what makes the claim safe against a
// second consumer while the first is still polling the provider.
func TestALiveLeaseHidesTheScan(t *testing.T) {
	store := testDB(t)
	id := "claim-live-lease"
	activeScan(t, store, id)

	now := time.Now().UTC()
	if _, err := store.ClaimNextScan(t.Context(), now, time.Minute, "consumer-a"); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// Inside the lease.
	if _, err := store.ClaimNextScan(t.Context(), now.Add(30*time.Second), time.Minute, "consumer-b"); !errors.Is(err, mongostore.ErrNoClaimableScan) {
		t.Errorf("claim inside the lease = %v, want ErrNoClaimableScan", err)
	}

	// Past the lease, with no sweeper in between.
	scan, err := store.ClaimNextScan(t.Context(), now.Add(61*time.Second), time.Minute, "consumer-b")
	if err != nil {
		t.Fatalf("claim after the lease lapsed: %v", err)
	}
	if scan.ScanID != id {
		t.Errorf("ScanID = %q, want %q", scan.ScanID, id)
	}
	if scan.LeaseOwner != "consumer-b" {
		t.Errorf("LeaseOwner = %q, want consumer-b", scan.LeaseOwner)
	}
}

// Releasing returns work at once rather than after the lease would have expired.
func TestReleaseMakesTheScanClaimableImmediately(t *testing.T) {
	store := testDB(t)
	id := "claim-release"
	activeScan(t, store, id)

	now := time.Now().UTC()
	if _, err := store.ClaimNextScan(t.Context(), now, time.Hour, "consumer"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := store.ReleaseScanLease(t.Context(), id); err != nil {
		t.Fatalf("ReleaseScanLease: %v", err)
	}

	// One second later — nowhere near the one-hour lease.
	scan, err := store.ClaimNextScan(t.Context(), now.Add(time.Second), time.Minute, "consumer")
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	if scan.ScanID != id {
		t.Errorf("ScanID = %q, want %q", scan.ScanID, id)
	}
}

// A deferred retry must not be claimable early. Claiming it early would spend
// provider quota as fast as the loop can run.
func TestScheduledRetryIsNotClaimableUntilDue(t *testing.T) {
	store := testDB(t)
	id := "claim-deferred"
	activeScan(t, store, id)

	now := time.Now().UTC()
	if _, err := store.ClaimNextScan(t.Context(), now, time.Minute, "consumer"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := store.ScheduleScanRetry(t.Context(), id, now.Add(time.Minute)); err != nil {
		t.Fatalf("ScheduleScanRetry: %v", err)
	}

	if _, err := store.ClaimNextScan(t.Context(), now.Add(30*time.Second), time.Minute, "c"); !errors.Is(err, mongostore.ErrNoClaimableScan) {
		t.Errorf("claim before the retry was due = %v, want ErrNoClaimableScan", err)
	}
	scan, err := store.ClaimNextScan(t.Context(), now.Add(61*time.Second), time.Minute, "c")
	if err != nil {
		t.Fatalf("claim after the retry came due: %v", err)
	}
	if scan.ScanID != id {
		t.Errorf("ScanID = %q, want %q", scan.ScanID, id)
	}
}

// A finished scan is not work, however old its lease. Claiming one would replay
// a completed analysis.
func TestFinishedScansAreNeverClaimable(t *testing.T) {
	store := testDB(t)
	id := "claim-finished"
	activeScan(t, store, id)

	if _, err := store.UpdateScanStatus(t.Context(), id, mongostore.ScanCompleted, ""); err != nil {
		t.Fatalf("UpdateScanStatus: %v", err)
	}

	now := time.Now().UTC()
	if _, err := store.ClaimNextScan(t.Context(), now, time.Minute, "consumer"); !errors.Is(err, mongostore.ErrNoClaimableScan) {
		t.Errorf("claim of a completed scan = %v, want ErrNoClaimableScan", err)
	}
}

// A scan written before the lease fields existed has no available_at and must
// still be picked up. Treating a missing field as "never due" would strand every
// historical scan permanently.
func TestScansWithoutLeaseFieldsAreStillClaimable(t *testing.T) {
	store := testDB(t)
	id := "claim-legacy"
	activeScan(t, store, id)

	if err := store.ReleaseScanLease(t.Context(), id); err != nil {
		t.Fatalf("ReleaseScanLease: %v", err)
	}

	scan, err := store.ClaimNextScan(t.Context(), time.Now().UTC(), time.Minute, "consumer")
	if err != nil {
		t.Fatalf("claim of a pre-lease scan: %v", err)
	}
	if scan.ScanID != id {
		t.Errorf("ScanID = %q, want %q", scan.ScanID, id)
	}
}

// A zero lease duration is a programming error, not a request to lease forever.
func TestClaimRejectsANonPositiveLease(t *testing.T) {
	store := testDB(t)

	if _, err := store.ClaimNextScan(t.Context(), time.Now().UTC(), 0, "consumer"); err == nil {
		t.Error("ClaimNextScan accepted a zero lease duration")
	}
}
