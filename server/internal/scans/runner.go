package scans

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/verdicts"
)

// Scan execution: claiming scans, submitting to the provider, polling,
// persisting verdicts, and recovering work after a crash.
//
// These run in the API process. They were a separate binary driven by a Redis
// queue; see ADR 0019 for why that is no longer the case. Nothing else in the
// package needed to change, which is the strongest evidence that the split was
// a deployment choice rather than a design requirement.

// Safe, low-cardinality error codes recorded on the scan.
//
// They reach the browser extension verbatim in the status response, so none of
// them may contain provider prose, a URL, or a driver message. The provider's
// own error_type and error_origin are stored separately on the scan record for
// diagnosis and are never serialised.
const (
	codeProviderAuthFailed    = "provider_auth_failed"
	codeProviderRateLimited   = "provider_rate_limited"
	codeProviderQuotaExceeded = "provider_quota_exceeded"
	codeProviderBadResponse   = "provider_bad_response"
	codeProviderTimeout       = "provider_timeout"
	codeProviderUnavailable   = "provider_unavailable"
	codeProviderNotConfigured = "provider_not_configured"
	codeSubmissionAmbiguous   = "submission_outcome_unknown"
	codeSubmissionNotRecorded = "submission_not_recorded"
	codeInputUnavailable      = "input_unavailable"
	codeProviderStateFailed   = "provider_analysis_failed"
	codeProviderPollTimeout   = "provider_poll_timeout"
	codeAttemptsExhausted     = "attempts_exhausted"
	codeDependencyUnavailable = "dependency_unavailable"
)

// Run consumes the queue until ctx is cancelled, then waits for in-flight jobs.
//
// It blocks, so the caller runs it in its own goroutine and shuts down by
// cancelling the context. Cancellation stops new claims immediately; a job
// already executing is abandoned and recovered by the reconciler rather than
// being waited on indefinitely, because a provider call can outlive any
// shutdown budget.
//
// Shutdown latency is ClaimBlock, not the poll deadline: consumers block in
// BRPOP for at most one claim interval before re-reading ctx.
func (s *Service) Run(ctx context.Context) error {
	logger := s.logger.With(slog.Int("consumers", s.concurrency))
	logger.Info("scan worker started",
		slog.Duration("poll_interval", s.pollInterval),
		slog.Duration("poll_deadline", s.pollDeadline),
		slog.Duration("reconcile_interval", s.reconcileEvery),
		slog.Duration("stall_threshold", s.stallThreshold),
	)

	if s.provider == nil {
		logger.Warn("no analysis provider configured; jobs will fail rather than be analysed")
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runSupervisor(ctx)
	}()

	for i := range s.concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runConsumer(ctx, i)
		}()
	}

	wg.Wait()
	logger.Info("scan worker stopped")
	return nil
}

// runConsumer claims and processes jobs until ctx is cancelled.
//
// The claim error handling matters. A queue outage is expected and transient,
// so the consumer backs off rather than spinning on a failing connection, and
// a malformed message is dropped rather than retried, because re-reading an
// undecodable message can never succeed.
func (s *Service) runConsumer(ctx context.Context, id int) {
	logger := s.logger.With(slog.Int("consumer", id))
	backoff := newBackoff()

	for ctx.Err() == nil {
		job, err := s.queue.Claim(ctx, s.claimBlock)

		switch {
		case errors.Is(err, ErrNoJob):
			continue
		case err != nil:
			logger.Warn("claim failed; backing off", slog.String("reason", err.Error()))
			if !sleepCtx(ctx, backoff.next()) {
				return
			}
			continue
		}

		backoff.reset()
		s.Process(ctx, job.ScanID)

		// Hand the lease back rather than waiting for it to lapse.
		//
		// A scan that ended in a terminal status is no longer claimable, so the
		// release is a no-op for it. For one that did not — a poll deadline, a
		// dropped dependency, a shutdown mid-job — releasing now means a retry
		// starts immediately instead of idling for a whole lease. The worst case
		// if this call fails is one lease of extra latency, which is why the
		// failure is logged rather than escalated.
		if err := s.queue.Release(ctx, job.ScanID); err != nil && ctx.Err() == nil {
			logger.Debug("releasing a lease failed; it will lapse on its own",
				slog.String("scan_id", job.ScanID),
				slog.String("reason", err.Error()))
		}
	}

	logger.Debug("consumer exiting")
}

// runSupervisor promotes due retries and re-enqueues stalled scans.
//
// These two run on one goroutine because both are interval work over the whole
// queue; giving each its own goroutine would multiply MongoDB queries
// for no gain.
func (s *Service) runSupervisor(ctx context.Context) {
	logger := s.logger
	ticker := time.NewTicker(s.reconcileEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Debug("supervisor exiting")
			return
		case <-ticker.C:
		}

		if n, err := s.queue.PromoteDue(ctx, 200); err != nil {
			if ctx.Err() == nil {
				logger.Warn("promoting due retries failed", slog.String("reason", err.Error()))
			}
		} else if n > 0 {
			logger.Info("promoted due retries", slog.Int("count", n))
		}

		if ctx.Err() != nil {
			return
		}
		s.Reconcile(ctx)
	}
}

// Reconcile re-enqueues scans that are active but no longer progressing.
//
// This is the recovery mechanism for a consumer that stopped making progress:
// MongoDB holds an active scan whose updated_at has gone stale. Re-enqueueing is
// always safe because processing a scan twice is a no-op.
//
// It covers a narrower set of failures than it used to. There is no longer a
// window between "scan recorded" and "job delivered" to be lost in, because the
// scan document *is* the job — so the reconciler's job is now purely to recover
// work whose consumer died, alongside the lease expiry in mongostore.
//
// A scan that has exhausted its attempts is failed outright rather than
// re-enqueued. Without that, a permanently failing URL would be retried
// forever, spending quota and a worker slot on each pass.
func (s *Service) Reconcile(ctx context.Context) {
	cutoff := s.now().UTC().Add(-s.stallThreshold)

	scans, err := s.store.ListStalledScans(ctx, cutoff, 100)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Warn("listing stalled scans failed", slog.String("reason", err.Error()))
		}
		return
	}
	if len(scans) == 0 {
		return
	}

	recovered := 0
	for _, scan := range scans {
		if ctx.Err() != nil {
			return
		}

		if scan.Attempts >= scan.MaxAttempts && scan.MaxAttempts > 0 {
			s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeAttemptsExhausted,
				"scan exhausted its retry budget", nil)
			continue
		}

		if err := s.queue.Enqueue(ctx, scan.ScanID); err != nil {
			s.logger.Warn("re-enqueue of a stalled scan failed",
				slog.String("scan_id", scan.ScanID),
				slog.String("reason", err.Error()))
			continue
		}
		recovered++

		// Count the recovery as an attempt. Without this a scan that always
		// stalls would be re-enqueued on every tick forever.
		if _, err := s.store.IncrementAttempts(ctx, scan.ScanID); err != nil && ctx.Err() == nil {
			s.logger.Warn("recording a recovery attempt failed",
				slog.String("scan_id", scan.ScanID),
				slog.String("reason", err.Error()))
		}
	}

	if recovered > 0 {
		s.logger.Warn("recovered stalled scans", slog.Int("count", recovered))
	}
}

// Process executes one scan by ID.
//
// It is the unit of work behind every queued message, and is exported so a test
// — or a future one-shot "analyse this now" path — can drive a single scan
// deterministically without starting the consumer loop.
//
// Every branch is idempotent. A duplicate delivery — which the reconciler will
// cause whenever a scan was recovered while its original message was still
// queued — must cost nothing and change nothing.
func (s *Service) Process(ctx context.Context, scanID string) {
	scan, err := s.store.GetScan(ctx, scanID)
	switch {
	case errors.Is(err, mongostore.ErrScanNotFound):
		// The record is gone: expired, or purged by an operator. There is
		// nothing to analyse and nothing to report.
		s.logger.Debug("dropping job with no scan record", slog.String("scan_id", scanID))
		return
	case err != nil:
		if ctx.Err() == nil {
			s.logger.Error("loading a scan failed",
				slog.String("scan_id", scanID),
				slog.String("reason", err.Error()))
		}
		return
	}

	if !scan.Status.IsActive() {
		s.logger.Debug("dropping duplicate job for a finished scan",
			slog.String("scan_id", scanID),
			slog.String("status", string(scan.Status)),
		)
		return
	}

	providerScanID := scan.ProviderScanID
	if providerScanID == "" {
		var err error
		providerScanID, err = s.submit(ctx, &scan)
		if err != nil {
			s.handleSubmitFailure(ctx, scan, err)
			return
		}
	} else {
		s.logger.Info("resuming an in-flight submission rather than resubmitting",
			slog.String("scan_id", scan.ScanID),
			slog.String("provider_scan_id", providerScanID),
		)
	}

	s.poll(ctx, scan, providerScanID)
}

// submit sends the URL to the provider and records the identifiers.
//
// # Why the transient URL is read and deleted in one call
//
// TakeTransientURL removes the record as part of the read. A separate delete
// would leave a window where a worker crash after a successful submission left
// a plaintext URL alive until the TTL, and a worker crash after a *failed*
// submission left it alive with no job to use it. Reading under delete makes
// "we hold the URL" and "the URL is still stored" the same instant.
//
// # Why a submission is never retried
//
// The Hybrid Analysis specification declares no idempotency or deduplication
// token for POST /submit/url. A request that timed out or dropped the response
// may already have been accepted upstream, so the outcome is genuinely unknown.
//
// Retrying it would risk a second sandbox job and a second unit of quota for
// one user request. Worse, it could not be detected: both submissions would
// succeed and the scan would silently have two children. So an ambiguous
// submission fails the scan and is reported as submission_outcome_unknown.
//
// The exception is a rate-limit rejection. HTTP 429 is a definitive refusal —
// the server states it did not accept the submission — so retrying it is
// provably safe. That distinction is the difference between an honest unknown
// and a known fact, and it is why ErrRateLimited is treated separately here.
func (s *Service) submit(ctx context.Context, scan *mongostore.Scan) (string, error) {
	if s.provider == nil {
		return "", &submitError{code: codeProviderNotConfigured, err: providers.ErrNotConfigured, retryable: false}
	}

	rawURL, err := s.store.TakeTransientURL(ctx, s.cipher, scan.ScanID)
	switch {
	case errors.Is(err, mongostore.ErrTransientURLNotFound):
		// The input is gone and cannot be recovered. This is the one failure
		// that must never produce a verdict: the URL was never analysed.
		return "", &submitError{code: codeInputUnavailable, err: err, retryable: false}
	case errors.Is(err, mongostore.ErrDecryptFailed):
		// Tampered record or rotated key. Substituting a different URL would
		// analyse something the user did not ask about.
		return "", &submitError{code: codeInputUnavailable, err: err, retryable: false}
	case errors.Is(err, mongostore.ErrEncryptionKeyInvalid):
		return "", &submitError{code: codeInputUnavailable, err: err, retryable: false}
	case err != nil:
		// A store outage. Transient, so the reconciler retries the whole job.
		return "", &submitError{code: codeDependencyUnavailable, err: err, retryable: true}
	}

	// Capture the bounded target detail while the plaintext is still in hand.
	// By the time the analysis completes the URL is gone, so this is the only
	// moment the path is available.
	//
	// Only the scheme and path are taken; the query string is dropped here and
	// never reaches the database.
	scheme, port, path, _ := splitTarget(rawURL)

	submitCtx, cancel := context.WithTimeout(ctx, s.providerTimeout)
	submission, err := s.provider.SubmitURL(submitCtx, rawURL)
	cancel()

	// Drop the plaintext reference as early as possible. The provider has it,
	// or the attempt is over; either way it is no longer needed here.
	rawURL = ""

	if err != nil {
		return "", classifySubmitError(err)
	}

	if scheme != "" {
		if err := s.store.RecordScanTarget(ctx, scan.ScanID, scheme, port, path, false); err != nil {
			s.logger.Warn("recording the scan target detail failed",
				slog.String("scan_id", scan.ScanID),
				slog.String("reason", err.Error()))
		}
		// Mirror it onto the in-memory copy.
		//
		// complete() runs later with this same struct and builds the assessment
		// from it. Without the mirror the persisted value is correct but the
		// in-memory one is still the pre-submission scan, so the assessment
		// silently gets an empty path and no rule is ever generated.
		scan.Scheme = scheme
		scan.Port = port
		scan.PathPrefix = path
	}

	if strings.TrimSpace(submission.ProviderScanID) == "" {
		// The provider accepted but gave no handle to poll. Reporting success
		// would leave a scan no worker can ever complete.
		return "", &submitError{
			code:      codeSubmissionNotRecorded,
			err:       fmt.Errorf("provider returned no job id: %w", providers.ErrBadResponse),
			retryable: false,
		}
	}

	// Persist the handle immediately, before anything else. It is what makes a
	// restart resumable: a worker that finds it polls instead of submitting,
	// so a crash here costs nothing beyond a delay.
	if _, err := s.store.RecordProviderSubmission(ctx, scan.ScanID, s.providerName,
		submission.ProviderScanID, submission.ProviderSubmissionID,
		string(submission.State), submission.EnvironmentID); err != nil {
		return "", &submitError{code: codeSubmissionNotRecorded, err: err, retryable: true}
	}

	// Mirror the provider identifiers onto the in-memory copy, for the same
	// reason the target detail is mirrored above.
	//
	// process() continues with this struct and passes it to poll(), which
	// eventually calls complete(), which builds the assessment from it. MongoDB
	// now holds the job id but this copy is still the pre-submission scan, so on
	// a first-attempt submission the assessment would record an empty
	// provider_scan_id — the audit trail would point at a scan with no handle,
	// and a later diagnosis could not re-derive which provider job produced the
	// verdict. Only a resumed scan would have carried it, which is why this was
	// invisible: the recovery path masked the common path.
	scan.ProviderScanID = submission.ProviderScanID
	scan.ProviderSubmissionID = submission.ProviderSubmissionID

	if _, err := s.store.UpdateScanStatus(ctx, scan.ScanID, mongostore.ScanRunning, ""); err != nil && ctx.Err() == nil {
		s.logger.Warn("marking a scan running failed",
			slog.String("scan_id", scan.ScanID),
			slog.String("reason", err.Error()))
	}

	return submission.ProviderScanID, nil
}

// handleSubmitFailure decides whether a failed submission is retried or is the
// scan's end.
//
// Retrying is only correct where the submission was provably not accepted. For
// an ambiguous failure the scan ends, because resubmitting could double-charge
// quota and create a second sandbox job nobody would ever find.
func (s *Service) handleSubmitFailure(ctx context.Context, scan mongostore.Scan, err error) {
	var se *submitError
	if !errors.As(err, &se) {
		se = &submitError{code: codeProviderUnavailable, err: err, retryable: true}
	}

	// A rate-limit rejection is provably not an acceptance, so the submission
	// is safe to make again — but the plaintext is gone, so the job must be
	// re-accepted by the API rather than resubmitted by the worker.
	if se.retryable && errors.Is(se.err, providers.ErrRateLimited) {
		s.logger.Warn("submission refused by a rate limit; ending the scan so the client can re-request",
			slog.String("scan_id", scan.ScanID),
			slog.String("code", se.code))
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, se.code,
			"the provider refused the submission under a rate limit", se)
		return
	}

	if !se.retryable {
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, se.code,
			"the URL could not be submitted for analysis", se)
		return
	}

	if se.code == codeDependencyUnavailable || errors.Is(se.err, context.Canceled) {
		// Leave the scan active: the reconciler will re-enqueue it once the
		// store recovers. Failing it here would discard a request the client
		// was told was accepted.
		s.logger.Warn("submission deferred; the scan stays active for the reconciler",
			slog.String("scan_id", scan.ScanID),
			slog.String("reason", se.err.Error()))
		return
	}

	// Ambiguous or unrecoverable: end it. Reporting "unknown" through a cached
	// assessment would be wrong, and reporting nothing while leaving it active
	// would retry a submission that may already have been accepted.
	s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, se.code,
		"the URL could not be submitted for analysis", se)
}

// poll waits for the provider to finish, then persists the verdict.
//
// Polling stops at the first of three conditions: a terminal report, the poll
// deadline, or context cancellation. A deadline produces timed_out with no
// assessment, because a scan that ran out of time has no result.
func (s *Service) poll(ctx context.Context, scan mongostore.Scan, providerScanID string) {
	deadline := s.now().Add(s.pollDeadline)
	interval := s.pollInterval

	for {
		analysis, err := s.fetch(ctx, providerScanID)
		if err != nil {
			s.handlePollFailure(ctx, scan, err)
			return
		}

		// Record the provider's own state even on a terminal report: it is the
		// only diagnostic an operator has when a verdict looks wrong.
		if _, err := s.store.RecordProviderState(ctx, scan.ScanID,
			analysis.ProviderState, analysis.ErrorType, analysis.ErrorOrigin); err != nil && ctx.Err() == nil {
			s.logger.Warn("recording provider state failed",
				slog.String("scan_id", scan.ScanID),
				slog.String("reason", err.Error()))
		}

		if analysis.Finished {
			s.complete(ctx, scan, analysis)
			return
		}

		if !s.now().Before(deadline) {
			s.logger.Warn("poll deadline reached",
				slog.String("scan_id", scan.ScanID),
				slog.String("provider_scan_id", providerScanID),
				slog.String("provider_state", analysis.ProviderState))
			s.failScan(ctx, scan.ScanID, mongostore.ScanTimedOut, codeProviderPollTimeout,
				"the analysis did not finish within the poll deadline", nil)
			return
		}

		if !sleepCtx(ctx, interval) {
			s.logger.Info("poll interrupted by shutdown; the scan stays active for recovery",
				slog.String("scan_id", scan.ScanID))
			return
		}

		// Back off gently so a long analysis does not hammer the provider for
		// the whole deadline.
		if interval < 30*time.Second {
			interval *= 2
		}
	}
}

// fetch retrieves one provider report under the provider timeout.
func (s *Service) fetch(ctx context.Context, providerScanID string) (providers.Analysis, error) {
	if s.provider == nil {
		return providers.Analysis{}, &submitError{code: codeProviderNotConfigured, err: providers.ErrNotConfigured}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, s.providerTimeout)
	defer cancel()

	analysis, err := s.provider.GetAnalysis(fetchCtx, providerScanID)
	if err != nil {
		return providers.Analysis{}, err
	}
	return analysis, nil
}

// handlePollFailure decides what an unreadable report means.
//
// A transient read failure leaves the scan active: the submission definitely
// happened, the job ID is stored, and the reconciler will resume polling. That
// is the single most valuable recovery in the system, and it is available only
// because the job ID was persisted immediately after submission.
//
// A permanent failure ends the scan without a verdict.
func (s *Service) handlePollFailure(ctx context.Context, scan mongostore.Scan, err error) {
	if ctx.Err() != nil {
		s.logger.Info("poll stopped by shutdown; the scan stays active for recovery",
			slog.String("scan_id", scan.ScanID))
		return
	}

	switch {
	case errors.Is(err, providers.ErrAuthFailed):
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeProviderAuthFailed,
			"the analysis provider rejected our credentials", err)
	case errors.Is(err, providers.ErrRateLimited):
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeProviderRateLimited,
			"the analysis provider is rate limiting us", err)
	case errors.Is(err, providers.ErrNotConfigured):
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeProviderNotConfigured,
			"no analysis provider is configured", err)
	case errors.Is(err, providers.ErrBadResponse):
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeProviderBadResponse,
			"the analysis provider returned an unusable response", err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, providers.ErrUnavailable):
		s.logger.Warn("could not read the provider report; the scan stays active for recovery",
			slog.String("scan_id", scan.ScanID),
			slog.String("reason", err.Error()))
	default:
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeProviderUnavailable,
			"the analysis result could not be retrieved", err)
	}
}

// complete turns a terminal provider report into a persisted verdict.
//
// The branches are ordered by how much they matter, and the first two are the
// reason this function is not a three-liner: a failed analysis and an analysis
// that did not finish both end in a scan status and no verdict at all. Neither
// may produce a cached assessment, because a cached "unknown" would suppress
// re-checking for a whole freshness window and the real answer would never be
// obtained.
func (s *Service) complete(ctx context.Context, scan mongostore.Scan, analysis providers.Analysis) {
	verdict, cacheable := providerVerdict(analysis)

	if analysis.Failed() {
		s.logger.Warn("provider reported a failed analysis",
			slog.String("scan_id", scan.ScanID),
			slog.String("provider_state", analysis.ProviderState),
			slog.String("provider_error_type", analysis.ErrorType),
			slog.String("provider_error_origin", analysis.ErrorOrigin),
		)
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeProviderStateFailed,
			"the analysis did not complete successfully", nil)
		return
	}

	if !cacheable {
		// Unreachable while providerVerdict gates on Finished, but a verdict
		// must never be written for an unfinished analysis even if that gate
		// is later weakened.
		s.failScan(ctx, scan.ScanID, mongostore.ScanFailed, codeProviderStateFailed,
			"the analysis did not complete", nil)
		return
	}

	now := s.now().UTC()

	// Scheme and path are carried onto the assessment only for a malicious
	// verdict — the one verdict the ruleset policy can ever act on. Every other
	// verdict stores neither, so URL detail exists only where it could plausibly
	// become a published rule.
	//
	// The query string is never carried. It routinely holds session tokens and
	// identifiers, and persisting those would undo the point of the fingerprint.
	// See ADR 0018 for the trade-off this represents.
	scheme, port, path := "", "", ""
	if verdict == verdicts.Malicious {
		scheme, port, path = scan.Scheme, scan.Port, scan.PathPrefix
	}

	assessment, err := s.store.PutAssessment(ctx, mongostore.Assessment{
		URLFingerprint:    scan.URLFingerprint,
		ScanID:            scan.ScanID,
		Hostname:          scan.Hostname,
		RegistrableDomain: scan.RegistrableDomain,
		Scheme:            scheme,
		Port:              port,
		PathPrefix:        path,
		Verdict:           verdict,
		Provider:          s.providerName,
		ProviderScanID:    scan.ProviderScanID,
		Evidence:          buildEvidence(analysis, verdict),
		AnalyzedAt:        analysis.ReportedAt.UTC(),
		ExpiresAt:         now.Add(s.assessmentTTL),
	})
	if err != nil {
		// The scan stays active: the submission happened, the job ID is
		// stored, and a retry writes the same assessment again because
		// PutAssessment is an upsert keyed by fingerprint.
		s.logger.Error("persisting the assessment failed; the scan stays active for recovery",
			slog.String("scan_id", scan.ScanID),
			slog.String("reason", err.Error()))
		return
	}

	// The scan record is the long-lived audit trail. Once the assessment
	// carries whatever rule detail the verdict justified, the scan no longer
	// needs it, so it is cleared rather than kept indefinitely.
	if err := s.store.RecordScanTarget(ctx, scan.ScanID, "", "", "", true); err != nil && ctx.Err() == nil {
		s.logger.Warn("clearing the scan target detail failed",
			slog.String("scan_id", scan.ScanID),
			slog.String("reason", err.Error()))
	}

	if _, err := s.store.UpdateScanStatus(ctx, scan.ScanID, mongostore.ScanCompleted, ""); err != nil {
		// The verdict is already durable, so a client that polls gets the
		// assessment even though the scan still reads "running". Logging beats
		// failing: there is nothing left to do that would change the outcome.
		s.logger.Error("marking the scan completed failed",
			slog.String("scan_id", scan.ScanID),
			slog.String("reason", err.Error()))
		return
	}

	s.logger.Info("scan completed",
		slog.String("scan_id", scan.ScanID),
		slog.String("verdict", verdict.String()),
		slog.String("provider_state", analysis.ProviderState),
		slog.String("fingerprint", assessment.URLFingerprint[:16]),
	)
}

// failScan records a terminal failure with a safe error code.
//
// cause is logged but never returned to a client, and errCode is always one of
// the constants above — never a provider message, a driver error, or anything
// derived from the submitted URL.
func (s *Service) failScan(
	ctx context.Context,
	scanID string,
	status mongostore.ScanStatus,
	errCode string,
	detail string,
	cause error,
) {
	attrs := []any{
		slog.String("scan_id", scanID),
		slog.String("status", string(status)),
		slog.String("code", errCode),
	}
	if cause != nil {
		attrs = append(attrs, slog.String("reason", cause.Error()))
	}
	s.logger.WarnContext(ctx, "scan failed", attrs...)

	if ctx.Err() != nil {
		// Shutdown: leave the scan active so the reconciler resumes it, and
		// leave its encrypted URL alone — the resumed scan still needs it.
		return
	}

	// A terminal scan will never be submitted, so its encrypted URL is dead
	// weight. Delete it here rather than at the point of failure, because
	// several failure paths end before the URL has ever been read: a missing
	// provider, a budget already spent, a queue that never delivered. Waiting
	// for the TTL would leave the last copy of a user's URL sitting in the
	// database for minutes after the system stopped needing it.
	s.store.DeleteTransientURL(ctx, scanID)

	if _, err := s.store.UpdateScanStatus(ctx, scanID, status, errCode); err != nil {
		s.logger.Error("recording the scan failure failed",
			slog.String("scan_id", scanID),
			slog.String("reason", err.Error()))
	}
}

// submitError carries the decision of whether a failed submission may be
// retried alongside the safe code to report.
type submitError struct {
	code string
	err  error
	// retryable means the submission was provably NOT accepted upstream, so
	// making it again is safe.
	retryable bool
}

func (e *submitError) Error() string {
	if e.err == nil {
		return "scans: " + e.code
	}
	return "scans: " + e.code + ": " + e.err.Error()
}

func (e *submitError) Unwrap() error { return e.err }

// classifySubmitError maps a provider error onto a decision and a safe code.
//
// Only ErrRateLimited is retryable, and the reasoning is in submit(): a 429 is
// an explicit refusal, whereas a timeout or a 5xx is genuinely unknown.
func classifySubmitError(err error) error {
	switch {
	case errors.Is(err, providers.ErrAuthFailed):
		return &submitError{code: codeProviderAuthFailed, err: err, retryable: false}
	case errors.Is(err, providers.ErrRateLimited):
		return &submitError{code: codeProviderRateLimited, err: err, retryable: true}
	case errors.Is(err, providers.ErrNotConfigured):
		return &submitError{code: codeProviderNotConfigured, err: err, retryable: false}
	case errors.Is(err, providers.ErrBadResponse):
		return &submitError{code: codeProviderBadResponse, err: err, retryable: false}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// The request may have been accepted before the timeout. Resubmitting
		// could double-charge quota, so this is explicitly not retryable.
		return &submitError{code: codeSubmissionAmbiguous, err: err, retryable: false}
	case errors.Is(err, providers.ErrUnavailable):
		return &submitError{code: codeSubmissionAmbiguous, err: err, retryable: false}
	default:
		return &submitError{code: codeProviderUnavailable, err: err, retryable: false}
	}
}

// backoff produces an exponential delay, used when a dependency is failing.
type backoff struct {
	base time.Duration
	max  time.Duration
	n    int
}

func newBackoff() *backoff {
	return &backoff{base: time.Second, max: time.Minute}
}

func (b *backoff) next() time.Duration {
	d := b.base << b.n
	if d > b.max || d <= 0 {
		d = b.max
	}
	b.n++
	if b.n > 6 {
		b.n = 6
	}
	return d
}

func (b *backoff) reset() { b.n = 0 }

// sleepCtx waits for d, reporting false if ctx was cancelled first.
//
// Every wait in the runner goes through it. A bare time.Sleep would keep a
// shutdown blocked for up to a full poll interval, and would make a context
// cancellation invisible to the polling loop.
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

// splitTarget extracts the scheme, port and path from a canonical URL, dropping
// the query string and fragment.
//
// The port is kept because dropping it silently broadens a rule: an assessment
// of https://host.test:8443/login must not produce a rule covering
// https://host.test/login, which nobody assessed.
//
// The query is discarded rather than stored because it routinely carries
// session tokens and identifiers. Persisting those would undo the point of the
// fingerprint, which exists so the URL itself never has to be kept.
//
// A URL with no path yields "/", so a rule built from it still has a stable,
// filterable shape.
func splitTarget(canonical string) (scheme, port, path string, ok bool) {
	parsed, err := url.Parse(canonical)
	if err != nil {
		return "", "", "", false
	}
	if parsed.Scheme == "" {
		return "", "", "", false
	}
	p := parsed.EscapedPath()
	if p == "" {
		p = "/"
	}
	return parsed.Scheme, parsed.Port(), p, true
}
