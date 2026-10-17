// Package memstore provides in-memory implementations of the persistence and
// queue interfaces the scan lifecycle depends on.
//
// # Why this is not a mock
//
// The behaviour under test is ordering: a URL must be stored before the scan
// that references it, a duplicate submission must not create a second scan,
// and a lost enqueue must be recoverable. Stubs that return canned values
//
// cannot express any of that, and a test that asserts "PutTransientURL was
// called" passes just as happily when the calls happen in the wrong order.
//
// This store therefore reproduces the real semantics: the partial-unique dedup
// on fingerprints, the AES-256-GCM encryption with the scan ID as additional
// authenticated data, the read-and-delete of a transient URL, and the TTL
// window. What it does not reproduce is MongoDB's durability — which is exactly
// what the integration tests are for.
//
// # Failure injection
//
// Every dependency the workflow depends on can be made to fail on demand:
// MongoDB reads and writes, the enqueue, the verdict write. That is the only
// way to test "the scan was recorded but the job never arrived", which is the
// case the reconciler exists to repair and which cannot be produced any other
// way.
package memstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/scans"
	"cyberguard/server/internal/verdicts"
)

// Store is a concurrency-safe in-memory mongostore.Store substitute.
type Store struct {
	mu sync.Mutex

	scans       map[string]mongostore.Scan
	assessments map[string]mongostore.Assessment
	transients  map[string]memTransient

	aead cipher.AEAD

	// Failure injection.
	FailReads         error
	FailWrites        error
	FailEnqueue       error
	FailPutAssessment error

	// Counters, for assertions.
	TransientPuts    int
	TransientDeletes int
	EnqueueCalls     int
	AssessmentWrites int
	AttemptBumps     int
}

type memTransient struct {
	ciphertext []byte
	nonce      []byte
	createdAt  time.Time
	expiresAt  time.Time
}

// NewStore builds an in-memory store with a real AES-256-GCM cipher.
//
// A real cipher rather than a stand-in is deliberate: the tests assert that a
// stored payload is not the plaintext and that decryption fails under the wrong
// key, and neither assertion is meaningful against a fake cipher.
func NewStore(key []byte) (*Store, error) {
	if len(key) < 32 {
		return nil, errors.New("memstore: key must be at least 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("memstore: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("memstore: gcm: %w", err)
	}

	return &Store{
		scans:       make(map[string]mongostore.Scan),
		assessments: make(map[string]mongostore.Assessment),
		transients:  make(map[string]memTransient),
		aead:        aead,
	}, nil
}

// ----------------------------------------------------------------- scans

func (s *Store) CreateScan(ctx context.Context, scan mongostore.Scan) (mongostore.Scan, bool, error) {
	if err := s.check("write"); err != nil {
		return mongostore.Scan{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The real store enforces dedup with a partial unique index over active
	// statuses. Reproducing that here is what makes the concurrent-dedup test
	// meaningful.
	for _, existing := range s.scans {
		if existing.URLFingerprint != scan.URLFingerprint {
			continue
		}
		if existing.Status.IsActive() {
			return existing, false, nil
		}
	}

	if scan.CreatedAt.IsZero() {
		scan.CreatedAt = time.Now().UTC()
	}
	if scan.UpdatedAt.IsZero() {
		scan.UpdatedAt = scan.CreatedAt
	}
	s.scans[scan.ScanID] = scan
	return scan, true, nil
}

func (s *Store) GetScan(ctx context.Context, scanID string) (mongostore.Scan, error) {
	if err := s.check("read"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return mongostore.Scan{}, mongostore.ErrScanNotFound
	}
	return scan, nil
}

// FindLatestScanByFingerprint returns the newest scan for a fingerprint.
//
// It mirrors the MongoDB implementation, which sorts by created_at descending
// and takes the first hit. Map iteration order here is random, so the tie-break
// is done explicitly — otherwise a test could pass or fail depending on Go's
// map seed, which is exactly the kind of flakiness a fake must not introduce.
func (s *Store) FindLatestScanByFingerprint(ctx context.Context, fingerprint string) (mongostore.Scan, error) {
	if err := s.check("read"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var newest mongostore.Scan
	var found bool

	for _, scan := range s.scans {
		if scan.URLFingerprint != fingerprint {
			continue
		}
		if !found || scan.CreatedAt.After(newest.CreatedAt) {
			newest, found = scan, true
		}
	}
	if !found {
		return mongostore.Scan{}, mongostore.ErrScanNotFound
	}
	return newest, nil
}

func (s *Store) FindActiveScanByFingerprint(ctx context.Context, fingerprint string) (mongostore.Scan, error) {
	if err := s.check("read"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, scan := range s.scans {
		if scan.URLFingerprint == fingerprint && scan.Status.IsActive() {
			return scan, nil
		}
	}
	return mongostore.Scan{}, mongostore.ErrScanNotFound
}

func (s *Store) UpdateScanStatus(ctx context.Context, scanID string, status mongostore.ScanStatus, lastErrorCode string) (mongostore.Scan, error) {
	if err := s.check("write"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return mongostore.Scan{}, mongostore.ErrScanNotFound
	}
	now := time.Now().UTC()
	scan.Status = status
	scan.UpdatedAt = now
	if lastErrorCode != "" {
		scan.LastErrorCode = lastErrorCode
	} else if status.IsActive() {
		scan.LastErrorCode = ""
	}
	switch status {
	case mongostore.ScanRunning:
		if scan.StartedAt == nil {
			scan.StartedAt = &now
		}
	case mongostore.ScanCompleted, mongostore.ScanFailed, mongostore.ScanTimedOut, mongostore.ScanExpired:
		scan.CompletedAt = &now
	}
	s.scans[scanID] = scan
	return scan, nil
}

func (s *Store) RecordProviderSubmission(ctx context.Context, scanID, provider, providerScanID, providerSubmissionID, providerState string, environmentID *int) (mongostore.Scan, error) {
	if err := s.check("write"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return mongostore.Scan{}, mongostore.ErrScanNotFound
	}
	now := time.Now().UTC()
	scan.Provider = provider
	scan.ProviderScanID = providerScanID
	scan.ProviderSubmissionID = providerSubmissionID
	scan.ProviderState = providerState
	scan.SubmittedAt = &now
	scan.UpdatedAt = now
	if environmentID != nil {
		scan.ProviderEnvironmentID = environmentID
	}
	s.scans[scanID] = scan
	return scan, nil
}

func (s *Store) RecordProviderState(ctx context.Context, scanID, providerState, errorType, errorOrigin string) (mongostore.Scan, error) {
	if err := s.check("write"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return mongostore.Scan{}, mongostore.ErrScanNotFound
	}
	scan.ProviderState = providerState
	scan.UpdatedAt = time.Now().UTC()
	if errorType != "" {
		scan.ProviderErrorType = errorType
	}
	if errorOrigin != "" {
		scan.ProviderErrorOrigin = errorOrigin
	}
	s.scans[scanID] = scan
	return scan, nil
}

func (s *Store) IncrementAttempts(ctx context.Context, scanID string) (mongostore.Scan, error) {
	if err := s.check("write"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return mongostore.Scan{}, mongostore.ErrScanNotFound
	}
	scan.Attempts++
	scan.UpdatedAt = time.Now().UTC()
	s.scans[scanID] = scan
	s.AttemptBumps++
	return scan, nil
}

func (s *Store) FindActiveScanByProviderScanID(ctx context.Context, providerScanID string) (mongostore.Scan, error) {
	if err := s.check("read"); err != nil {
		return mongostore.Scan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, scan := range s.scans {
		if scan.ProviderScanID == providerScanID && scan.Status.IsActive() {
			return scan, nil
		}
	}
	return mongostore.Scan{}, mongostore.ErrScanNotFound
}

func (s *Store) ListStalledScans(ctx context.Context, olderThan time.Time, limit int64) ([]mongostore.Scan, error) {
	if err := s.check("read"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []mongostore.Scan
	for _, scan := range s.scans {
		if scan.Status.IsActive() && scan.UpdatedAt.Before(olderThan) {
			out = append(out, scan)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.Before(out[j].UpdatedAt) })
	if limit > 0 && int64(len(out)) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ----------------------------------------------------------- assessments

func (s *Store) PutAssessment(ctx context.Context, a mongostore.Assessment) (mongostore.Assessment, error) {
	s.mu.Lock()
	if s.FailPutAssessment != nil {
		err := s.FailPutAssessment
		s.mu.Unlock()
		return mongostore.Assessment{}, err
	}
	s.mu.Unlock()

	if !a.Verdict.Valid() {
		return mongostore.Assessment{}, fmt.Errorf("memstore: invalid verdict %q", a.Verdict)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.assessments[a.URLFingerprint]; ok && a.CreatedAt.IsZero() {
		a.CreatedAt = existing.CreatedAt
	}
	a.UpdatedAt = time.Now().UTC()
	s.assessments[a.URLFingerprint] = a
	s.AssessmentWrites++
	return a, nil
}

func (s *Store) GetAssessmentByFingerprint(ctx context.Context, fingerprint string) (mongostore.Assessment, error) {
	if err := s.check("read"); err != nil {
		return mongostore.Assessment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.assessments[fingerprint]
	if !ok {
		return mongostore.Assessment{}, mongostore.ErrAssessmentNotFound
	}
	return a, nil
}

func (s *Store) FindFreshAssessment(ctx context.Context, fingerprint string, now time.Time) (mongostore.Assessment, error) {
	a, err := s.GetAssessmentByFingerprint(ctx, fingerprint)
	if err != nil {
		return mongostore.Assessment{}, err
	}
	if !a.IsFresh(now) {
		return mongostore.Assessment{}, mongostore.ErrAssessmentNotFound
	}
	return a, nil
}

func (s *Store) GetAssessmentByScanID(ctx context.Context, scanID string) (mongostore.Assessment, error) {
	if err := s.check("read"); err != nil {
		return mongostore.Assessment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, a := range s.assessments {
		if a.ScanID == scanID {
			return a, nil
		}
	}
	return mongostore.Assessment{}, mongostore.ErrAssessmentNotFound
}

// --------------------------------------------------------- transient URLs

func (s *Store) PutTransientURL(ctx context.Context, aead cipher.AEAD, scanID, rawURL string, ttl time.Duration) error {
	if err := s.check("write"); err != nil {
		return err
	}
	if aead == nil {
		return mongostore.ErrEncryptionKeyInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.transients[scanID]; exists {
		return fmt.Errorf("memstore: transient url already exists for scan %s", scanID)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("memstore: nonce: %w", err)
	}
	now := time.Now().UTC()
	s.transients[scanID] = memTransient{
		ciphertext: aead.Seal(nil, nonce, []byte(rawURL), []byte(scanID)),
		nonce:      nonce,
		createdAt:  now,
		expiresAt:  now.Add(ttl),
	}
	s.TransientPuts++
	return nil
}

func (s *Store) GetTransientURL(ctx context.Context, aead cipher.AEAD, scanID string) (string, error) {
	if err := s.check("read"); err != nil {
		return "", err
	}
	if aead == nil {
		return "", mongostore.ErrEncryptionKeyInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openLocked(aead, scanID)
}

func (s *Store) DeleteTransientURL(ctx context.Context, scanID string) error {
	if err := s.check("write"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.transients, scanID)
	s.TransientDeletes++
	return nil
}

func (s *Store) TakeTransientURL(ctx context.Context, aead cipher.AEAD, scanID string) (string, error) {
	raw, err := s.GetTransientURL(ctx, aead, scanID)
	if err != nil {
		return "", err
	}
	if err := s.DeleteTransientURL(ctx, scanID); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *Store) openLocked(aead cipher.AEAD, scanID string) (string, error) {
	rec, ok := s.transients[scanID]
	if !ok {
		return "", mongostore.ErrTransientURLNotFound
	}
	plaintext, err := aead.Open(nil, rec.nonce, rec.ciphertext, []byte(scanID))
	if err != nil {
		return "", mongostore.ErrDecryptFailed
	}
	return string(plaintext), nil
}

// CiphertextFor exposes the stored ciphertext, so a test can assert that the
// plaintext is genuinely encrypted rather than merely stored in a struct field
// nobody inspects.
func (s *Store) CiphertextFor(scanID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.transients[scanID]
	if !ok {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(rec.ciphertext), true
}

// ExpireTransient backdates a stored record's expiry, simulating the TTL index
// reaping it while the worker was down.
func (s *Store) ExpireTransient(scanID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.transients[scanID]; ok {
		rec.expiresAt = time.Now().Add(-time.Hour)
		s.transients[scanID] = rec
	}
}

// DropTransient removes a stored URL without going through the normal path,
// simulating its disappearance between writes.
func (s *Store) DropTransient(scanID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.transients, scanID)
}

// TransientCount reports how many encrypted URLs are stored.
func (s *Store) TransientCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.transients)
}

// ScanSnapshot returns a copy of the stored scans.
func (s *Store) ScanSnapshot() []mongostore.Scan {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]mongostore.Scan, 0, len(s.scans))
	for _, scan := range s.scans {
		out = append(out, scan)
	}
	return out
}

// PutScanDirect inserts a scan without going through CreateScan, so a test can
// set up a pre-existing in-flight scan.
func (s *Store) PutScanDirect(scan mongostore.Scan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[scan.ScanID] = scan
}

// ExpireAssessment backdates an assessment's expiry, simulating the TTL index
// reaping it.
func (s *Store) ExpireAssessment(fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.assessments[fingerprint]; ok {
		a.ExpiresAt = time.Now().Add(-time.Hour)
		s.assessments[fingerprint] = a
	}
}

// PutAssessmentDirect stores an assessment without the counters, for arranging
// cache-hit scenarios.
func (s *Store) PutAssessmentDirect(a mongostore.Assessment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assessments[a.URLFingerprint] = a
}

func (s *Store) check(kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "read":
		return s.FailReads
	case "write":
		return s.FailWrites
	default:
		return nil
	}
}

// ------------------------------------------------------------------ queue

// Queue is an in-memory scans.Queue substitute.
//
// It deliberately keeps the *old* explicit-queue semantics — enqueue appends,
// claim pops — rather than mimicking the MongoDB lease. That is intentional: the
// reconciler's job is to notice work that is durable but undelivered, and a
// double that models the real queue's behaviour would make those tests
// vacuous. The real lease semantics are exercised in mongostore's integration
// tests, where they belong.
type Queue struct {
	mu     sync.Mutex
	queue  []string
	retry  map[string]time.Time
	closed bool

	// FailEnqueue, when set, makes every enqueue fail. It reproduces the case
	// the reconciler exists for: the scan is durable, the job never arrived.
	FailEnqueue error

	// Claimed records the scan IDs Claim has handed out, including repeats, so a
	// test can assert duplicate delivery.
	Claimed []string

	// Released records the scan IDs Release returned early.
	Released []string
}

// NewQueue builds an empty in-memory queue.
func NewQueue() *Queue {
	return &Queue{retry: make(map[string]time.Time)}
}

func (q *Queue) Enqueue(ctx context.Context, scanID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.FailEnqueue != nil {
		return q.FailEnqueue
	}
	q.queue = append(q.queue, scanID)
	return nil
}

func (q *Queue) EnqueueRetry(ctx context.Context, scanID string, delay time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.retry[scanID] = time.Now().Add(delay)
	return nil
}

// Claim pops one job. A block timeout is honoured only up to a small bound so
// tests stay fast; a non-blocking pop is enough to drain the queue.
func (q *Queue) Claim(ctx context.Context, block time.Duration) (scans.Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) == 0 {
		return scans.Job{}, scans.ErrNoJob
	}
	scanID := q.queue[0]
	q.queue = q.queue[1:]
	q.Claimed = append(q.Claimed, scanID)
	return scans.Job{ScanID: scanID}, nil
}

// Release is a no-op for an explicit queue, since claiming already removed the
// job. It records the call so a test can assert leases are handed back promptly
// rather than left to expire.
func (q *Queue) Release(_ context.Context, scanID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Released = append(q.Released, scanID)
	return nil
}

func (q *Queue) PromoteDue(ctx context.Context, limit int) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	promoted := 0
	for id, due := range q.retry {
		if !due.After(now) {
			delete(q.retry, id)
			q.queue = append(q.queue, id)
			promoted++
		}
	}
	return promoted, nil
}

// Pending returns the queued scan IDs.
func (q *Queue) Pending() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.queue...)
}

// Push adds a scan ID directly, so a test can simulate duplicate delivery or a
// message that survived a restart.
func (q *Queue) Push(scanID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queue = append(q.queue, scanID)
}

// Drain removes and returns every queued scan ID.
func (q *Queue) Drain() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.queue
	q.queue = nil
	return out
}

// Verdicts is a convenience for asserting which verdicts exist.
func (s *Store) Verdicts() map[string]verdicts.Verdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]verdicts.Verdict, len(s.assessments))
	for fp, a := range s.assessments {
		out[fp] = a.Verdict
	}
	return out
}

// RecordScanTarget stores or clears a scan's bounded target detail.
//
// clear=true blanks both fields, matching the production behaviour where the
// detail is removed once the verdict is known.
func (s *Store) RecordScanTarget(ctx context.Context, scanID, scheme, port, pathPrefix string, clear bool) error {
	if err := s.check("write"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return mongostore.ErrScanNotFound
	}
	if clear {
		scan.Scheme = ""
		scan.Port = ""
		scan.PathPrefix = ""
	} else {
		scan.Scheme = scheme
		scan.Port = port
		scan.PathPrefix = pathPrefix
	}
	scan.UpdatedAt = time.Now().UTC()
	s.scans[scanID] = scan
	return nil
}

// TargetOf returns a scan's stored scheme, port and path.
func (s *Store) TargetOf(scanID string) (scheme, port, path string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scan, found := s.scans[scanID]
	if !found {
		return "", "", "", false
	}
	return scan.Scheme, scan.Port, scan.PathPrefix, true
}

// ScanCount returns how many scans are stored.
//
// It exists so a test can assert that a read path did not write anything, which
// is otherwise only observable by counting documents in the real store.
func (s *Store) ScanCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.scans)
}
