package app

import (
	"context"
	"crypto/cipher"
	"fmt"
	"log/slog"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/platform/redisqueue"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/scans"
)

// Construction of the scan lifecycle, shared by the api and worker binaries.
//
// Both processes build the same object from the same configuration. Letting
// each main assemble its own copy is the drift this package exists to prevent:
// one binary would pick up a different poll deadline or retry budget and the
// difference would only surface under load.

// NewScanService builds the scan lifecycle from configuration.
//
// provider may be nil, which disables remote analysis. That is a supported
// configuration, not an error: the API still serves cached verdicts and the
// worker still reconciles stalled scans, it simply cannot analyse anything new.
//
// A missing or short encryption key is fatal. The alternative — carrying on
// without one — would mean storing raw URLs in the clear, and silently
// degrading privacy in order to keep serving is precisely the failure this
// design exists to prevent. Failing at startup makes it an operator decision
// rather than a quiet downgrade.
func NewScanService(
	cfg config.Config,
	store *mongostore.Store,
	queue *redisqueue.Client,
	provider providers.AnalysisProvider,
	logger *slog.Logger,
	guard func(ctx context.Context, fingerprint string) error,
) (*scans.Service, error) {
	if store == nil {
		return nil, fmt.Errorf("app: a MongoDB store is required")
	}
	if queue == nil {
		return nil, fmt.Errorf("app: a Redis queue is required")
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
