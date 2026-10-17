package app

import (
	"context"
	"crypto/cipher"
	"fmt"
	"log/slog"
	"os"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/platform/mongoqueue"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/scans"
)

// Construction of the scan lifecycle.
//
// The API builds it from configuration and also runs it in-process; there is no
// second binary to disagree with.

// NewScanService builds the scan lifecycle from configuration.
//
// provider may be nil, which disables remote analysis. That is a supported
// configuration, not an error: cached verdicts still resolve and stalled scans
// are still reconciled, the pipeline simply cannot analyse anything new.
//
// A missing or short encryption key is fatal. The alternative — carrying on
// without one — would mean storing raw URLs in the clear, and silently
// degrading privacy in order to keep serving is precisely the failure this
// design exists to prevent. Failing at startup makes it an operator decision
// rather than a quiet downgrade.
func NewScanService(
	cfg config.Config,
	store *mongostore.Store,
	provider providers.AnalysisProvider,
	logger *slog.Logger,
	guard func(ctx context.Context, fingerprint string) error,
) (*scans.Service, error) {
	if store == nil {
		return nil, fmt.Errorf("app: a MongoDB store is required")
	}
	// A missing or short encryption key is a configuration fault, not a
	// startup fault. The process starts so the readiness endpoint can report
	// exactly which secret is absent; scans.New then refuses every submission
	// with ErrNotReady, so nothing is ever stored unencrypted.
	var aead cipher.AEAD
	if cfg.HasEncryptionKey() {
		built, err := mongostore.NewTransientURLCipher(cfg.URLEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("app: transient url cipher: %w", err)
		}
		aead = built
	} else {
		logger.Error("URL_ENCRYPTION_KEY is unset or shorter than 32 bytes; " +
			"URL submissions are refused and readiness will report the failure")
	}

	queue, err := newQueue(cfg, store, logger)
	if err != nil {
		return nil, err
	}

	service, err := scans.New(scans.Options{
		Store:             store,
		Queue:             queue,
		Provider:          provider,
		Guard:             guard,
		Cipher:            aead,
		Logger:            logger,
		FingerprintKey:    []byte(cfg.URLFingerprintHMACKey),
		AssessmentTTL:     cfg.AssessmentTTL,
		TransientURLTTL:   cfg.TransientURLTTL,
		MaxAttempts:       cfg.ScanMaxAttempts,
		ProviderTimeout:   cfg.HybridAnalysisTimeout,
		PollInterval:      cfg.WorkerPollInterval,
		PollDeadline:      cfg.WorkerPollDeadline,
		ReconcileInterval: cfg.WorkerReconcileInterval,
		StallThreshold:    cfg.WorkerStallThreshold,
		Concurrency:       cfg.WorkerConcurrency,
		ClaimBlock:        cfg.WorkerClaimBlock,
	})
	if err != nil {
		return nil, fmt.Errorf("app: build scan service: %w", err)
	}
	return service, nil
}

// newQueue builds the MongoDB-backed work queue.
//
// The lease duration is the load-bearing number here. A lease shorter than the
// longest possible unit of work lets a second consumer start on a scan whose
// provider analysis is still running — which, on the submission path, is the
// difference between polling an existing job and submitting the URL a second
// time. It is therefore derived from the poll deadline plus headroom, and
// validated here rather than configured, so there is no setting an operator can
// get wrong into a double submission.
func newQueue(cfg config.Config, store *mongostore.Store, logger *slog.Logger) (*mongoqueue.Queue, error) {
	lease := cfg.WorkerPollDeadline + cfg.WorkerPollInterval + cfg.ClaimLeaseHeadroom
	if lease <= cfg.WorkerPollDeadline {
		return nil, fmt.Errorf("app: claim lease %s must exceed the poll deadline %s", lease, cfg.WorkerPollDeadline)
	}

	queue, err := mongoqueue.New(mongoqueue.Options{
		Store:         store,
		Owner:         claimOwner(),
		LeaseDuration: lease,
		PollGap:       cfg.WorkerClaimPollGap,
	})
	if err != nil {
		return nil, fmt.Errorf("app: build work queue: %w", err)
	}
	logger.Info("work queue ready",
		slog.String("backend", "mongodb"),
		slog.Duration("lease", lease),
		slog.Duration("poll_gap", cfg.WorkerClaimPollGap),
	)
	return queue, nil
}

// claimOwner identifies this process in the lease record.
//
// It is diagnostic only — leases are released by expiry or explicitly, never by
// matching owner — but it must be distinguishable between replicas, so a stuck
// lease can be traced to the process holding it. The hostname is used because it
// is the one identifier that is unique per machine and free; nothing secret
// goes into a field that lands in the database.
func claimOwner() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s/%d", host, os.Getpid())
}
