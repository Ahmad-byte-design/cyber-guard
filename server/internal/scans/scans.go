// Package scans owns the scan lifecycle: accepting a URL, deduplicating it,
// dispatching it, running it against a provider, and normalising the result.
//
// # Why this package exists
//
// Phases 1-3 built the pieces — persistence, the provider adapter, the queue
// connectivity — but nothing connected them, and the ordering between them is
// where the correctness lives. Four stores and two processes are involved; the
// sequence below is what makes a crash at any point recoverable rather than
// silent.
//
// # The dispatch order, and why it is this order
//
//	validate → canonicalise → fingerprint → cache lookup
//	  → PutTransientURL   (encrypted input, keyed by a scan ID not yet in use)
//	  → CreateScan        (deduplicated by a partial unique index)
//	  → Enqueue           (scan ID only)
//
// Putting the encrypted URL *before* the scan record looks backwards and is the
// single most important ordering decision here. The reverse order creates a
// scan that is durably recorded, awaiting a worker, with no input that worker
// can ever read — permanently stuck, requiring an operator to clean it up. In
// this order, a crash between the two writes leaves an encrypted URL with no
// scan: garbage that the TTL index removes, no stuck scan, and a client that
// received no scan ID and will therefore simply try again.
//
// # Why the reconciler exists
//
// MongoDB writes and Redis pushes are not one transaction. A scan can be
// durably recorded while the enqueue fails, or succeed and then be lost to a
// Redis restart. Nothing in Redis can repair this, because Redis does not know
// the scan exists.
//
// MongoDB can. Reconciler therefore treats MongoDB as the ledger and Redis as
// delivery: any scan still in `queued` or `running` whose `updated_at` is older
// than the stall threshold is re-enqueued. A lost queue message degrades to a
// delay of one stall threshold plus one tick. It cannot become a lost scan.
//
// The alternative — a transactional outbox — would make the enqueue atomic
// with the scan write, but only inside a MongoDB replica set. The default
// deployment is a standalone server with no transactions at all, so the
// reconciler is not a simplification here; it is the only design available.
//
// # At-least-once, and why that is safe
//
// Every stage tolerates being repeated. A job for a finished scan is a no-op. A
// job for a scan with a stored provider job ID resumes polling rather than
// submitting again. A verdict write is an upsert keyed by fingerprint. The one
// thing that is never repeated is a provider submission — see submit().
package scans

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/platform/redisqueue"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/hybridanalysis"
	"cyberguard/server/internal/urlintel"
	"cyberguard/server/internal/verdicts"
)

// defaultProviderName is recorded when the service was built without a
// provider.
//
// A scan can only exist without a provider if one was configured and then
// became unavailable, and the field exists so a client can tell "no provider"
// from "a provider said nothing".
const defaultProviderName = "none"

// Store is the persistence the scan lifecycle needs.
//
// It is declared here, at the consumer, rather than used as a concrete
// *mongostore.Store. That keeps the unit tests free of a live database while the
// integration tests exercise the real thing against the same interface.
type Store interface {
	CreateScan(ctx context.Context, scan mongostore.Scan) (mongostore.Scan, bool, error)
	GetScan(ctx context.Context, scanID string) (mongostore.Scan, error)
	FindActiveScanByFingerprint(ctx context.Context, fingerprint string) (mongostore.Scan, error)
	UpdateScanStatus(ctx context.Context, scanID string, status mongostore.ScanStatus, lastErrorCode string) (mongostore.Scan, error)
	RecordProviderSubmission(ctx context.Context, scanID, provider, providerScanID, providerSubmissionID, providerState string, environmentID *int) (mongostore.Scan, error)
	RecordProviderState(ctx context.Context, scanID, providerState, errorType, errorOrigin string) (mongostore.Scan, error)
	RecordScanTarget(ctx context.Context, scanID, scheme, pathPrefix string, clear bool) error
	IncrementAttempts(ctx context.Context, scanID string) (mongostore.Scan, error)
	FindActiveScanByProviderScanID(ctx context.Context, providerScanID string) (mongostore.Scan, error)
	ListStalledScans(ctx context.Context, olderThan time.Time, limit int64) ([]mongostore.Scan, error)

	PutAssessment(ctx context.Context, a mongostore.Assessment) (mongostore.Assessment, error)
	GetAssessmentByFingerprint(ctx context.Context, fingerprint string) (mongostore.Assessment, error)
	FindFreshAssessment(ctx context.Context, fingerprint string, now time.Time) (mongostore.Assessment, error)
	GetAssessmentByScanID(ctx context.Context, scanID string) (mongostore.Assessment, error)

	PutTransientURL(ctx context.Context, aead cipher.AEAD, scanID, rawURL string, ttl time.Duration) error
	GetTransientURL(ctx context.Context, aead cipher.AEAD, scanID string) (string, error)
	DeleteTransientURL(ctx context.Context, scanID string) error
	TakeTransientURL(ctx context.Context, aead cipher.AEAD, scanID string) (string, error)
}

// Queue is the delivery mechanism.
//
// The signature deliberately names a scan ID. There is no parameter through
// which a raw URL could travel, which is how ADR 0013's "scan IDs only" rule is
// enforced structurally rather than by convention.
type Queue interface {
	Enqueue(ctx context.Context, scanID string) error
	EnqueueRetry(ctx context.Context, scanID string, delay time.Duration) error
	Claim(ctx context.Context, block time.Duration) (redisqueue.Job, error)
	PromoteDue(ctx context.Context, limit int) (int, error)
}

// Sentinel errors the HTTP layer maps to status codes.
//
// Each is a distinct value because each needs a distinct client-facing answer,
// and collapsing them would force the handler to guess.
// ErrNotReady means a required dependency or secret is missing. The HTTP layer
// reports it as 503.
var ErrNotReady = errors.New("scans: service is not ready")

// ErrDisallowedTarget means a URL points somewhere that must not be submitted
// to an external analysis provider — a loopback address, a private network, a
// reserved name. See targets.go.
//
// It is a validation outcome, not a system error: the HTTP layer reports it as
// a 422 exactly as it would any other validation failure.
var ErrDisallowedTarget = errors.New("scans: URL targets a disallowed host")

// ErrRateLimited means this URL fingerprint has spent its submission budget.
//
// It is returned by the Guard hook, which the HTTP layer installs. The scan
// lifecycle does not own the configured limits — they are an API-layer policy
// concern — so it takes the decision as a callback rather than the numbers.
var ErrRateLimited = errors.New("scans: submission rate limit exceeded")

// LimitError carries the client's wait time alongside the refusal.
//
// RetryAfter travels with the error rather than being recomputed by the HTTP
// layer, so the value the client is told to wait matches what the limiter
// actually measured, instead of a second and slightly different calculation.
type LimitError struct {
	Limit      int
	Remaining  int
	Reset      time.Time
	RetryAfter time.Duration
}

func (e *LimitError) Error() string { return ErrRateLimited.Error() }

func (e *LimitError) Unwrap() error { return ErrRateLimited }

// Options configures a Service.
type Options struct {
	Store  Store
	Queue  Queue
	Logger *slog.Logger
	Now    func() time.Time

	// FingerprintKey is the HMAC key. Required.
	FingerprintKey []byte
	// Cipher encrypts the transient URL. Required; a nil cipher makes every
	// submission fail rather than storing the URL in the clear.
	Cipher cipher.AEAD

	// Provider may be nil, which disables remote analysis. Cached reads and
	// status polling keep working.
	Provider providers.AnalysisProvider

	// Guard is consulted immediately before a new scan would be created.
	//
	// It is placed there rather than in HTTP middleware for one reason: the
	// budget exists to protect the provider quota, so it must be charged only
	// when a submission is actually going to happen. Counting every request
	// would charge cache hits — which cost no quota — and would make a
	// repeatedly-visited benign URL look like an attack.
	//
	// Returning an error aborts the submission before anything is written, so
	// a refused submission leaves no scan and no encrypted URL behind.
	Guard func(ctx context.Context, fingerprint string) error

	// AssessmentTTL is how long a verdict may be served as fresh.
	AssessmentTTL time.Duration
	// TransientURLTTL bounds the encrypted URL if explicit deletion fails.
	TransientURLTTL time.Duration
	// MaxAttempts bounds retries of a scan before it is failed outright.
	MaxAttempts int

	// Polling.
	ProviderTimeout time.Duration
	PollInterval    time.Duration
	PollDeadline    time.Duration

	// Reconciler.
	ReconcileInterval time.Duration
	StallThreshold    time.Duration

	// Concurrency is the number of jobs processed at once.
	Concurrency int
	// ClaimBlock is how long a consumer waits for work before re-checking
	// shutdown. It must be short enough that Ctrl-C feels immediate.
	ClaimBlock time.Duration
}

// Service is the scan lifecycle.
type Service struct {
	store    Store
	queue    Queue
	provider providers.AnalysisProvider
	guard    func(context.Context, string) error
	cipher   cipher.AEAD
	logger   *slog.Logger
	now      func() time.Time

	fingerprintKey []byte
	// providerName is what gets written to scan and assessment documents.
	//
	// It comes from the provider rather than a constant here, because the
	// system can run against more than one. A document claiming a real
	// provider when a mock produced the verdict would send an operator
	// auditing a result to the wrong place.
	providerName string

	assessmentTTL   time.Duration
	transientTTL    time.Duration
	maxAttempts     int
	providerTimeout time.Duration
	pollInterval    time.Duration
	pollDeadline    time.Duration
	reconcileEvery  time.Duration
	stallThreshold  time.Duration
	concurrency     int
	claimBlock      time.Duration
}

// New builds a Service, applying defaults for every unset field.
//
// A nil logger, clock or queue is replaced with something usable so a caller
// cannot accidentally construct a Service that panics on first use.
//
// A missing cipher or fingerprint key is deliberately *not* a construction
// error. Both are configuration faults an operator must be able to see, and the
// way to see them is the readiness endpoint — a process that refused to start
// would never answer /health/ready, and an orchestrator would restart-loop the
// container instead of reporting a specific, actionable sub-check.
//
// So the Service builds anyway, and Submit refuses every request with
// ErrNotReady before writing a byte. Nothing is ever stored unencrypted, and
// the failure is visible rather than silent.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("scans: Store is required")
	}
	if opts.Queue == nil {
		return nil, errors.New("scans: Queue is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	providerName := defaultProviderName
	if opts.Provider != nil {
		if name := strings.TrimSpace(opts.Provider.Name()); name != "" {
			providerName = name
		}
	}

	return &Service{
		store:           opts.Store,
		queue:           opts.Queue,
		provider:        opts.Provider,
		guard:           opts.Guard,
		cipher:          opts.Cipher,
		logger:          opts.Logger,
		now:             opts.Now,
		fingerprintKey:  opts.FingerprintKey,
		providerName:    providerName,
		assessmentTTL:   orDuration(opts.AssessmentTTL, 24*time.Hour),
		transientTTL:    orDuration(opts.TransientURLTTL, 10*time.Minute),
		maxAttempts:     orInt(opts.MaxAttempts, 3),
		providerTimeout: orDuration(opts.ProviderTimeout, 30*time.Second),
		pollInterval:    orDuration(opts.PollInterval, 5*time.Second),
		pollDeadline:    orDuration(opts.PollDeadline, 5*time.Minute),
		reconcileEvery:  orDuration(opts.ReconcileInterval, 30*time.Second),
		stallThreshold:  orDuration(opts.StallThreshold, 2*time.Minute),
		concurrency:     orInt(opts.Concurrency, 4),
		claimBlock:      orDuration(opts.ClaimBlock, time.Second),
	}, nil
}

func orDuration(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func orInt(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// Submit is the whole read/write path behind POST /api/v1/check-url.
//
// The returned Outcome tells the caller which of the three documented outcomes
// occurred: a fresh cached verdict, an existing scan already in progress, or a
// newly accepted scan.
func (s *Service) Submit(ctx context.Context, rawURL string) (Outcome, error) {
	// Checked before validation so an unconfigured service never even parses
	// a URL, and certainly never writes one.
	if err := s.usable(); err != nil {
		return Outcome{}, err
	}

	parsed, err := urlintel.Validate(rawURL)
	if err != nil {
		return Outcome{}, err
	}
	canonical := urlintel.Canonical(parsed)

	// The fingerprint key is checked here rather than trusted, because this is
	// the boundary where an unkeyed hash would become possible.
	fingerprint, err := urlintel.Fingerprint(s.fingerprintKey, canonical)
	if err != nil {
		return Outcome{}, err
	}

	// Refuse before anything is stored. A rejected URL must leave no trace: no
	// fingerprint, no scan, no queue entry.
	if err := CheckTarget(parsed); err != nil {
		return Outcome{}, err
	}

	host, err := urlintel.ParseHost(parsed.Hostname())
	if err != nil {
		return Outcome{}, err
	}

	// A fresh verdict ends the request without touching the queue or the
	// provider. This is the path that makes repeated browsing free.
	if assessment, err := s.store.FindFreshAssessment(ctx, fingerprint, s.now().UTC()); err == nil {
		return Outcome{Cached: true, Assessment: &assessment}, nil
	} else if !errors.Is(err, mongostore.ErrAssessmentNotFound) {
		return Outcome{}, fmt.Errorf("scans: cache lookup: %w", err)
	}

	// Charged here: after the cache miss, before anything is written. The
	// budget therefore tracks submissions rather than requests.
	if s.guard != nil {
		if err := s.guard(ctx, fingerprint); err != nil {
			return Outcome{}, err
		}
	}

	scanID, err := newScanID()
	if err != nil {
		return Outcome{}, fmt.Errorf("scans: generate scan id: %w", err)
	}

	// The encrypted URL is written first, against a scan ID that does not exist
	// yet. See the package comment: the reverse order strands a scan with no
	// readable input.
	if err := s.store.PutTransientURL(ctx, s.cipher, scanID, canonical, s.transientTTL); err != nil {
		return Outcome{}, fmt.Errorf("scans: store transient url: %w", err)
	}

	scan, created, err := s.store.CreateScan(ctx, mongostore.Scan{
		ScanID:            scanID,
		URLFingerprint:    fingerprint,
		Hostname:          host.Hostname,
		RegistrableDomain: host.RegistrableDomain,
		Status:            mongostore.ScanQueued,
		MaxAttempts:       s.maxAttempts,
	})
	if err != nil {
		// The scan does not exist, so the encrypted URL is unreferenced. Drop it
		// now rather than waiting for the TTL.
		s.dropTransient(ctx, scanID)
		return Outcome{}, fmt.Errorf("scans: create scan: %w", err)
	}

	if !created {
		// A concurrent request already has this URL in flight. Our copy of the
		// URL is keyed to a scan ID nobody will ever read.
		s.dropTransient(ctx, scanID)
		s.logger.DebugContext(ctx, "reusing in-flight scan",
			slog.String("scan_id", scan.ScanID),
			slog.Int("attempts", scan.Attempts),
		)
		return Outcome{Scan: scan}, nil
	}

	// An enqueue failure is logged and swallowed, deliberately.
	//
	// The scan is already durable and the reconciler will re-enqueue it, so the
	// work is delayed rather than lost. Returning an error here would tell the
	// client the submission was rejected when it was in fact accepted, and the
	// retry would create a second scan the dedup index would then reject.
	enqueued := true
	if err := s.queue.Enqueue(ctx, scan.ScanID); err != nil {
		enqueued = false
		s.logger.ErrorContext(ctx, "enqueue failed; the scan is durable and the reconciler will recover it",
			slog.String("scan_id", scan.ScanID),
			slog.String("reason", err.Error()),
		)
	}

	// The scan id is the correlation handle, and it is the only field logged.
	// Host-level intelligence is deliberately left out: it is the most
	// identifying thing available, and an operator holding a scan id can look
	// it up in the database anyway.
	s.logger.InfoContext(ctx, "scan accepted",
		slog.String("scan_id", scan.ScanID),
		slog.Bool("enqueued", enqueued),
	)
	return Outcome{Scan: scan, Created: true, Enqueued: enqueued}, nil
}

// usable reports whether the service has the cryptographic configuration it
// needs to accept work.
//
// It is checked at the top of Submit rather than only at the point of use so a
// misconfigured instance fails every request identically, instead of storing an
// encrypted URL and then failing when it goes to write the scan.
func (s *Service) usable() error {
	if len(s.fingerprintKey) == 0 {
		return ErrNotReady
	}
	if s.cipher == nil {
		return ErrNotReady
	}
	return nil
}

// Outcome is the result of Submit.
type Outcome struct {
	// Assessment is set only when Cached is true.
	Assessment *mongostore.Assessment
	// Scan is set when a scan exists, whether new or pre-existing.
	Scan mongostore.Scan
	// Cached reports a fresh verdict was served without any scan work.
	Cached bool
	// Created reports this request created the scan.
	Created bool
	// Enqueued reports the job reached Redis. False with Created true means the
	// reconciler will deliver it instead.
	Enqueued bool
}

// Retrying reports whether a previous attempt on this scan failed and another is
// scheduled. The API surfaces it so a client can distinguish first-time work
// from a recovered scan.
func (o Outcome) Retrying() bool {
	return !o.Cached && o.Scan.Attempts > 0
}

// Result is the outcome of a status lookup.
type Result struct {
	Scan       mongostore.Scan
	Assessment *mongostore.Assessment
}

// ErrScanNotFound is returned when no scan matches the identifier.
var ErrScanNotFound = mongostore.ErrScanNotFound

// Lookup returns the current state of a scan.
//
// A completed scan is returned together with its assessment. A scan in any
// other state carries no verdict at all — not an empty one, not a default one —
// so a client cannot mistake "not finished" for "nothing found".
func (s *Service) Lookup(ctx context.Context, scanID string) (Result, error) {
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		return Result{}, ErrNotReady
	}

	scan, err := s.store.GetScan(ctx, scanID)
	if err != nil {
		return Result{}, err
	}

	result := Result{Scan: scan}
	if scan.Status != mongostore.ScanCompleted {
		return result, nil
	}

	assessment, err := s.store.GetAssessmentByScanID(ctx, scanID)
	switch {
	case err == nil:
		// An expired verdict is not reported as the current one.
		//
		// The scan stays "completed" — that is a true statement about what
		// happened — but presenting a week-old verdict as the answer now would
		// let the extension act on stale security information. Omitting it
		// makes the client re-submit through check-url, which re-runs the
		// freshness check properly.
		if !assessment.IsFresh(s.now().UTC()) {
			s.logger.DebugContext(ctx, "assessment has expired; reporting the scan without a verdict",
				slog.String("scan_id", scanID),
				slog.Time("expired_at", assessment.ExpiresAt))
			return result, nil
		}
		result.Assessment = &assessment
	case errors.Is(err, mongostore.ErrAssessmentNotFound):
		// A completed scan whose assessment has been reaped. Reporting the scan
		// without a verdict is truthful: there is no fresh verdict to serve.
	default:
		return Result{}, fmt.Errorf("scans: assessment lookup: %w", err)
	}
	return result, nil
}

// dropTransient removes an encrypted URL, logging rather than propagating a
// failure.
//
// Every caller is already on an error path, so a second failure here would mask
// the first and tell the operator nothing useful. The TTL index remains the
// backstop.
func (s *Service) dropTransient(ctx context.Context, scanID string) {
	if err := s.store.DeleteTransientURL(ctx, scanID); err != nil {
		s.logger.WarnContext(ctx, "could not delete unreferenced transient url; the TTL index will remove it",
			slog.String("scan_id", scanID),
			slog.String("reason", err.Error()),
		)
	}
}

// newScanID mints an opaque, unguessable scan identifier.
//
// Unguessability matters: the status endpoint is unauthenticated, so a
// sequential ID would let one client enumerate and read another's scans.
//
// The format matches the OpenAPI example and stays inside the documented
// 64-character limit.
func newScanID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return "scan_" + hex.EncodeToString(b[:]), nil
}

// buildEvidence renders bounded, provider-free evidence for a client.
//
// The summary is composed from CyberGuard's own vocabulary. Provider response
// prose never reaches it, because this value is returned verbatim to the
// browser extension by GET /api/v1/get-url.
func buildEvidence(a providers.Analysis, verdict verdicts.Verdict) []mongostore.Evidence {
	state := strings.ToUpper(strings.TrimSpace(a.ProviderState))
	if state == "" {
		state = "UNREPORTED"
	}

	summary := fmt.Sprintf("analysis finished with verdict %s; provider state %s",
		verdict, state)

	return []mongostore.Evidence{{
		Type:    "provider_verdict",
		Summary: summary,
	}}
}

// providerVerdict resolves the verdict for an analysis.
//
// It exists so there is exactly one place that decides which analyses are
// allowed to produce a cached verdict. hybridanalysis.NormaliseVerdict already
// refuses to map a failed or unfinished analysis to anything but unknown; this
// wrapper additionally refuses to *cache* anything but a genuinely completed,
// non-failed analysis, because caching a transient provider outage as "unknown"
// would suppress re-checking for the whole freshness window.
//
// The no_threat_detected verdict can therefore only ever reach the cache
// through a recognised classification on a completed, successful analysis.
func providerVerdict(a providers.Analysis) (verdicts.Verdict, bool) {
	if a.Failed() || !a.Finished {
		return verdicts.Unknown, false
	}
	return hybridanalysis.NormaliseVerdict(a), true
}
