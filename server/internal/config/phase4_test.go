package config

import (
	"strings"
	"testing"
	"time"
)

// Phase 4 added the worker tuning, the recovery thresholds and the abuse
// controls. The threshold relationships are the interesting part: they are the
// only place a misconfiguration can silently turn healthy work into infinite
// retries, so they are validated rather than documented and hoped for.

func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

// The defaults must be internally consistent, or a fresh deployment starts in
// a state the loader itself would reject.
func TestDefaultsAreSelfConsistent(t *testing.T) {
	withEnv(t, map[string]string{
		"URL_FINGERPRINT_HMAC_KEY": "",
		"URL_ENCRYPTION_KEY":       "",
		"HYBRID_ANALYSIS_API_KEY":  "",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with defaults: %v", err)
	}

	if cfg.WorkerStallThreshold <= cfg.WorkerReconcileInterval {
		t.Errorf("default stall threshold %s does not exceed the reconcile interval %s; "+
			"healthy scans would be re-enqueued forever",
			cfg.WorkerStallThreshold, cfg.WorkerReconcileInterval)
	}
	if cfg.WorkerStallThreshold <= cfg.HybridAnalysisTimeout {
		t.Errorf("default stall threshold %s does not exceed the provider timeout %s; "+
			"work about to succeed would be abandoned",
			cfg.WorkerStallThreshold, cfg.HybridAnalysisTimeout)
	}
	if cfg.WorkerPollDeadline <= cfg.WorkerPollInterval {
		t.Errorf("default poll deadline %s does not exceed the poll interval %s",
			cfg.WorkerPollDeadline, cfg.WorkerPollInterval)
	}
	if cfg.ScanMaxAttempts <= 0 {
		t.Errorf("default attempt budget is %d, want a positive value", cfg.ScanMaxAttempts)
	}
	if cfg.AssessmentTTL <= 0 {
		t.Errorf("default assessment TTL is %s, want a positive value", cfg.AssessmentTTL)
	}
	if cfg.FingerprintSubmitLimit <= 0 {
		t.Errorf("default fingerprint budget is %d, want a positive value", cfg.FingerprintSubmitLimit)
	}
	if cfg.RateLimitPollPerMinute < cfg.RateLimitPerMinute {
		t.Errorf("the polling limit %d is below the submission limit %d; a client "+
			"polling one pending scan would be blocked before it finished submitting it",
			cfg.RateLimitPollPerMinute, cfg.RateLimitPerMinute)
	}
}

func TestWorkerSettingsAreRead(t *testing.T) {
	withEnv(t, map[string]string{
		"WORKER_POLL_DEADLINE":      "7m",
		"WORKER_CONCURRENCY":        "12",
		"WORKER_RECONCILE_INTERVAL": "45s",
		"WORKER_STALL_THRESHOLD":    "9m",
		"WORKER_CLAIM_BLOCK":        "2s",
		"SCAN_MAX_ATTEMPTS":         "5",
		"ASSESSMENT_TTL":            "48h",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"poll deadline", cfg.WorkerPollDeadline, 7 * time.Minute},
		{"concurrency", cfg.WorkerConcurrency, 12},
		{"reconcile interval", cfg.WorkerReconcileInterval, 45 * time.Second},
		{"stall threshold", cfg.WorkerStallThreshold, 9 * time.Minute},
		{"claim block", cfg.WorkerClaimBlock, 2 * time.Second},
		{"max attempts", cfg.ScanMaxAttempts, 5},
		{"assessment ttl", cfg.AssessmentTTL, 48 * time.Hour},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestAbuseControlsAreRead(t *testing.T) {
	withEnv(t, map[string]string{
		"RATE_LIMIT_PER_MINUTE":      "120",
		"RATE_LIMIT_POLL_PER_MINUTE": "900",
		"FINGERPRINT_SUBMIT_LIMIT":   "4",
		"FINGERPRINT_SUBMIT_WINDOW":  "30m",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.RateLimitPerMinute != 120 {
		t.Errorf("rate limit = %d, want 120", cfg.RateLimitPerMinute)
	}
	if cfg.RateLimitPollPerMinute != 900 {
		t.Errorf("poll rate limit = %d, want 900", cfg.RateLimitPollPerMinute)
	}
	if cfg.FingerprintSubmitLimit != 4 {
		t.Errorf("fingerprint limit = %d, want 4", cfg.FingerprintSubmitLimit)
	}
	if cfg.FingerprintSubmitWindow != 30*time.Minute {
		t.Errorf("fingerprint window = %s, want 30m", cfg.FingerprintSubmitWindow)
	}
}

// A stall threshold shorter than the reconcile interval would re-enqueue a scan
// on every tick, forever, without the scan ever being the problem.
func TestStallThresholdMustExceedReconcileInterval(t *testing.T) {
	withEnv(t, map[string]string{
		"WORKER_RECONCILE_INTERVAL": "2m",
		"WORKER_STALL_THRESHOLD":    "1m",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted a stall threshold below the reconcile interval")
	}
	if !strings.Contains(err.Error(), "WORKER_STALL_THRESHOLD") {
		t.Errorf("error = %q, want it to name the offending setting", err)
	}
}

// A stall threshold shorter than the provider timeout would abandon work that
// was about to succeed.
func TestStallThresholdMustExceedProviderTimeout(t *testing.T) {
	withEnv(t, map[string]string{
		"HYBRID_ANALYSIS_TIMEOUT":   "2m",
		"WORKER_STALL_THRESHOLD":    "90s",
		"WORKER_RECONCILE_INTERVAL": "30s",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted a stall threshold below the provider timeout")
	}
	if !strings.Contains(err.Error(), "HYBRID_ANALYSIS_TIMEOUT") {
		t.Errorf("error = %q, want it to name the timeout it conflicts with", err)
	}
}

func TestNonPositiveCountersAreRejected(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"WORKER_CONCURRENCY", "0"},
		{"SCAN_MAX_ATTEMPTS", "-1"},
		{"ASSESSMENT_TTL", "0s"},
		{"WORKER_POLL_DEADLINE", "0s"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			withEnv(t, map[string]string{tc.key: tc.value})
			if _, err := Load(); err == nil {
				t.Errorf("Load accepted %s=%s", tc.key, tc.value)
			}
		})
	}
}

// A negative limit would reject every request; zero means "unset", and that is
// allowed so a deployment can deliberately run without a limit.
func TestNegativeLimitsAreRejectedButZeroIsNot(t *testing.T) {
	withEnv(t, map[string]string{"RATE_LIMIT_PER_MINUTE": "-1"})
	if _, err := Load(); err == nil {
		t.Error("Load accepted a negative rate limit")
	}

	withEnv(t, map[string]string{"RATE_LIMIT_PER_MINUTE": "0"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load rejected a zero rate limit: %v", err)
	}
	if cfg.RateLimitPerMinute != 0 {
		t.Errorf("rate limit = %d, want 0", cfg.RateLimitPerMinute)
	}
}

// HasEncryptionKey must check the length AES-256-GCM needs, not mere presence:
// a present-but-short key is unusable, and reporting it as configured would
// let readiness claim a capability the service does not have.
func TestHasEncryptionKeyChecksLength(t *testing.T) {
	// 64 hex characters is 32 bytes: the minimum AES-256-GCM accepts.
	withEnv(t, map[string]string{"URL_ENCRYPTION_KEY": strings.Repeat("ab", 32)})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HasEncryptionKey() {
		t.Error("a 32-byte key was reported as unusable")
	}

	// 32 hex characters is 16 bytes: present, but too short.
	withEnv(t, map[string]string{"URL_ENCRYPTION_KEY": strings.Repeat("ab", 16)})
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HasEncryptionKey() {
		t.Error("a 16-byte key was reported as usable")
	}
}

// ------------------------------------------------------- provider selection

func TestAnalysisProviderDefaultsToHybridAnalysis(t *testing.T) {
	withEnv(t, map[string]string{"ANALYSIS_PROVIDER": ""})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AnalysisProvider != ProviderHybridAnalysis {
		t.Errorf("default provider = %q, want %q", cfg.AnalysisProvider, ProviderHybridAnalysis)
	}
	if cfg.UsesMockProvider() {
		t.Error("UsesMockProvider = true for the default configuration")
	}
}

func TestAnalysisProviderAcceptsMock(t *testing.T) {
	withEnv(t, map[string]string{"ANALYSIS_PROVIDER": "mock"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.UsesMockProvider() {
		t.Error("UsesMockProvider = false with ANALYSIS_PROVIDER=mock")
	}
}

// An unrecognised provider name is rejected rather than guessed at.
func TestUnknownProviderIsRejected(t *testing.T) {
	withEnv(t, map[string]string{"ANALYSIS_PROVIDER": "virustotal"})
	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted an unknown provider")
	}
	if !strings.Contains(err.Error(), "ANALYSIS_PROVIDER") {
		t.Errorf("error = %q, want it to name the setting", err)
	}
}

// Mock mode needs no credentials. This is the whole point of it: a developer
// must be able to run the system with no provider account at all.
func TestMockModeNeedsNoCredentials(t *testing.T) {
	withEnv(t, map[string]string{"ANALYSIS_PROVIDER": "mock"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.ValidateProviderSelection(); err != nil {
		t.Errorf("mock mode was rejected: %v", err)
	}
}

// Selecting the real provider without a key must be fatal, and must NOT be
// quietly replaced by the mock. The error says how to get out.
func TestHybridAnalysisModeWithoutAKeyIsFatal(t *testing.T) {
	withEnv(t, map[string]string{
		"ANALYSIS_PROVIDER":       ProviderHybridAnalysis,
		"HYBRID_ANALYSIS_API_KEY": "",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	err = cfg.ValidateProviderSelection()
	if err == nil {
		t.Fatal("hybrid-analysis mode without a key was accepted")
	}
	if cfg.UsesMockProvider() {
		t.Error("configuration silently fell back to the mock provider")
	}
	for _, want := range []string{"HYBRID_ANALYSIS_API_KEY", "mock"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q so the operator knows the fix", err, want)
		}
	}
}

func TestHybridAnalysisModeWithAKeyIsValid(t *testing.T) {
	withEnv(t, map[string]string{
		"ANALYSIS_PROVIDER":       ProviderHybridAnalysis,
		"HYBRID_ANALYSIS_API_KEY": "not-a-real-key-but-well-formed",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.ValidateProviderSelection(); err != nil {
		t.Errorf("a configured hybrid-analysis selection was rejected: %v", err)
	}
}
