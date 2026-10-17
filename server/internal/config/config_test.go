package config

import (
	"strings"
	"testing"
	"time"
)

// clearEnv unsets every variable Load reads, so a test starts from known
// defaults regardless of what the developer's shell or .env file contains.
//
// t.Setenv forbids t.Parallel, so none of these tests are parallel.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HTTP_ADDR", "LOG_LEVEL", "LOG_FORMAT", "SHUTDOWN_TIMEOUT",
		"MONGODB_URI", "MONGODB_DATABASE", "MONGODB_CONNECT_TIMEOUT", "MONGODB_PING_TIMEOUT",
		"WORKER_CLAIM_POLL_GAP", "CLAIM_LEASE_HEADROOM",
		"HEALTH_CHECK_TIMEOUT", "WORKER_POLL_INTERVAL",
		"HYBRID_ANALYSIS_BASE_URL", "HYBRID_ANALYSIS_API_KEY", "URL_FINGERPRINT_HMAC_KEY",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadDefaultsAreUsable(t *testing.T) {
	clearEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Defaults must target the Compose network, not loopback: containers do
	// not reach siblings via 127.0.0.1.
	if cfg.MongoURI != "mongodb://mongodb:27017" {
		t.Errorf("MongoURI = %q, want the mongodb service name", cfg.MongoURI)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %s, want 15s", cfg.ShutdownTimeout)
	}
	if cfg.MongoConnectTimeout != 10*time.Second || cfg.MongoPingTimeout != 5*time.Second {
		t.Errorf("mongo timeouts = %s/%s, want 10s/5s", cfg.MongoConnectTimeout, cfg.MongoPingTimeout)
	}
	if cfg.HealthCheckTimeout != 2*time.Second {
		t.Errorf("HealthCheckTimeout = %s, want 2s", cfg.HealthCheckTimeout)
	}
	// Redis is gone, so the claim parameters are what a fresh deployment must
	// get right instead: a positive poll gap, and headroom on the lease.
	if cfg.WorkerClaimPollGap != 250*time.Millisecond {
		t.Errorf("WorkerClaimPollGap = %s, want 250ms", cfg.WorkerClaimPollGap)
	}
	if cfg.ClaimLeaseHeadroom != 30*time.Second {
		t.Errorf("ClaimLeaseHeadroom = %s, want 30s", cfg.ClaimLeaseHeadroom)
	}
}

func TestLoadReadsOverrides(t *testing.T) {
	clearEnv(t)
	t.Setenv("HTTP_ADDR", "127.0.0.1:9999")
	t.Setenv("MONGODB_DATABASE", "cyberguard_test")
	t.Setenv("WORKER_CLAIM_POLL_GAP", "750ms")
	t.Setenv("CLAIM_LEASE_HEADROOM", "90s")
	t.Setenv("SHUTDOWN_TIMEOUT", "45s")
	t.Setenv("URL_FINGERPRINT_HMAC_KEY", "  hexkey  ")
	t.Setenv("HYBRID_ANALYSIS_API_KEY", "notarealkey")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.HTTPAddr != "127.0.0.1:9999" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.MongoDatabase != "cyberguard_test" {
		t.Errorf("MongoDatabase = %q", cfg.MongoDatabase)
	}
	if cfg.WorkerClaimPollGap != 750*time.Millisecond {
		t.Errorf("WorkerClaimPollGap = %s, want 750ms", cfg.WorkerClaimPollGap)
	}
	if cfg.ClaimLeaseHeadroom != 90*time.Second {
		t.Errorf("ClaimLeaseHeadroom = %s, want 90s", cfg.ClaimLeaseHeadroom)
	}
	if cfg.ShutdownTimeout != 45*time.Second {
		t.Errorf("ShutdownTimeout = %s, want 45s", cfg.ShutdownTimeout)
	}
	// Surrounding whitespace is trimmed, so a value pasted from a secret store
	// does not silently become a different key.
	if cfg.URLFingerprintHMACKey != "hexkey" {
		t.Errorf("URLFingerprintHMACKey = %q, want trimmed", cfg.URLFingerprintHMACKey)
	}
	if !cfg.HasProviderCredentials() || !cfg.HasFingerprintKey() {
		t.Error("Has* helpers did not observe the supplied secrets")
	}
}

// A lease that does not outlive the work it protects would let a second
// consumer claim a scan whose provider analysis is still running — which on the
// submission path is a double submission and a double charge. The headroom is
// therefore rejected at load rather than at the point where it costs money.
func TestLoadRejectsAClaimLeaseThatCouldExpireMidScan(t *testing.T) {
	clearEnv(t)
	t.Setenv("CLAIM_LEASE_HEADROOM", "0s")

	_, err := Load()
	if err == nil {
		t.Fatal("a zero lease headroom was accepted")
	}
	if !strings.Contains(err.Error(), "CLAIM_LEASE_HEADROOM") {
		t.Errorf("error = %v, want it to name CLAIM_LEASE_HEADROOM", err)
	}
}

func TestLoadRejectsUnusableValues(t *testing.T) {
	cases := []struct{ name, key, value, wantErr string }{
		{"bad log format", "LOG_FORMAT", "xml", "LOG_FORMAT"},
		{"bad log level", "LOG_LEVEL", "verbose", "LOG_LEVEL"},
		{"negative shutdown", "SHUTDOWN_TIMEOUT", "-1s", "SHUTDOWN_TIMEOUT"},
		{"bad duration", "SHUTDOWN_TIMEOUT", "soon", "SHUTDOWN_TIMEOUT"},
		{"non-positive health timeout", "HEALTH_CHECK_TIMEOUT", "0s", "HEALTH_CHECK_TIMEOUT"},
		{"bad mongo connect timeout", "MONGODB_CONNECT_TIMEOUT", "later", "MONGODB_CONNECT_TIMEOUT"},
		{"bad mongo ping timeout", "MONGODB_PING_TIMEOUT", "1", "MONGODB_PING_TIMEOUT"},
		{"non-positive claim poll gap", "WORKER_CLAIM_POLL_GAP", "0s", "WORKER_CLAIM_POLL_GAP"},
		{"bad claim poll gap", "WORKER_CLAIM_POLL_GAP", "often", "WORKER_CLAIM_POLL_GAP"},
		{"negative lease headroom", "CLAIM_LEASE_HEADROOM", "-1s", "CLAIM_LEASE_HEADROOM"},
		{"bad health timeout", "HEALTH_CHECK_TIMEOUT", "nope", "HEALTH_CHECK_TIMEOUT"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(tc.key, tc.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load with %s=%q succeeded, want an error", tc.key, tc.value)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// A whitespace-only value means "unset", not "set to blank", so it falls back
// to the default. This is deliberate: it is how a variable that is present but
// empty behaves in a .env file or a CI runner.
//
// It is also why validate() cannot treat these as errors — an empty
// HTTP_ADDR never reaches validation, because env() has already substituted the
// default. The validate() checks remain as defence for a default that is later
// changed to empty.
func TestWhitespaceValuesFallBackToDefaults(t *testing.T) {
	clearEnv(t)
	for _, key := range []string{"HTTP_ADDR", "MONGODB_URI", "MONGODB_DATABASE",
		"WORKER_CLAIM_POLL_GAP", "CLAIM_LEASE_HEADROOM"} {
		t.Setenv(key, "   \t ")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with whitespace-only values: %v", err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.MongoDatabase != "cyberguard" {
		t.Errorf("whitespace did not fall back to defaults: %+v", cfg)
	}
	if cfg.WorkerClaimPollGap != 250*time.Millisecond || cfg.ClaimLeaseHeadroom != 30*time.Second {
		t.Errorf("whitespace did not fall back to defaults: %+v", cfg)
	}
}

// A missing secret is a readiness signal, never a startup failure: the service
// must boot and report its own state honestly.
func TestMissingSecretsDoNotFailLoad(t *testing.T) {
	clearEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with no secrets: %v", err)
	}
	if cfg.HasFingerprintKey() {
		t.Error("HasFingerprintKey reports true for an empty key")
	}
	if cfg.HasProviderCredentials() {
		t.Error("HasProviderCredentials reports true for an empty key")
	}
}

// A whitespace-only secret is not a secret.
func TestWhitespaceOnlySecretsAreTreatedAsAbsent(t *testing.T) {
	clearEnv(t)
	t.Setenv("URL_FINGERPRINT_HMAC_KEY", "   ")
	t.Setenv("HYBRID_ANALYSIS_API_KEY", "\t")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HasFingerprintKey() || cfg.HasProviderCredentials() {
		t.Error("whitespace-only secrets were treated as present")
	}
}
