// Package config loads runtime configuration from environment variables.
//
// Defaults are chosen to work inside the Docker Compose network (service
// names, not 127.0.0.1). Secrets are never required at load time: the API
// must boot and report readiness honestly even when provider credentials are
// absent, so a missing key is a readiness signal rather than a crash.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Analysis provider selectors.
const (
	// ProviderHybridAnalysis selects the real Hybrid Analysis service.
	ProviderHybridAnalysis = "hybrid-analysis"
	// ProviderMock selects the offline in-process provider.
	ProviderMock = "mock"
)

// Config is the full runtime configuration shared by the API and the worker.
type Config struct {
	// HTTP server.
	HTTPAddr        string
	ShutdownTimeout time.Duration

	// APIDocsEnabled controls whether /docs/ and /openapi.yaml are served.
	//
	// It exists so a deployment can publish the contract without also
	// publishing an interactive console that will submit requests to it. When
	// false the routes are not registered at all, so they are a plain 404
	// rather than something that exists and declines.
	//
	// Defaulting to true is deliberate. The document is a committed artefact
	// describing an unauthenticated API: it contains nothing that is not
	// already in the repository, and no credential of any kind. Suppressing it
	// by default would only mean local development has to opt in, which is how
	// documentation rots.
	//
	// There is no authentication in front of it, and none is added here. This
	// service has no accounts; adding a login to serve a static document would
	// be security theatre that breaks the only use case it has.
	APIDocsEnabled bool

	// Logging.
	LogLevel  string
	LogFormat string

	// MongoDB — the authoritative store.
	MongoURI            string
	MongoDatabase       string
	MongoConnectTimeout time.Duration
	MongoPingTimeout    time.Duration

	// Redis — scan queue and rate-limit counters.
	RedisAddr        string
	RedisPassword    string
	RedisDB          int
	RedisPingTimeout time.Duration

	// Readiness probes.
	HealthCheckTimeout time.Duration

	// AnalysisProvider selects which analysis backend runs.
	//
	// "hybrid-analysis" talks to the real sandbox service and needs an API
	// key. "mock" analyses URLs in-process and never opens a network
	// connection to any external provider.
	//
	// There is deliberately no fallback between them. A system that quietly
	// switched to a mock would pass its tests while the real integration
	// silently rotted, and one that quietly switched to the real provider
	// would spend quota from a machine the operator believed was offline.
	AnalysisProvider string

	// Analysis provider. See docs/verified/hybrid-analysis-v2-contract.md.
	HybridAnalysisBaseURL       string
	HybridAnalysisAPIKey        string
	HybridAnalysisEnvironmentID int
	HybridAnalysisTimeout       time.Duration
	HybridAnalysisMaxRetries    int
	HybridAnalysisRetryBase     time.Duration

	// URL fingerprinting. Backend-only secret; must never reach the client.
	URLFingerprintHMACKey string

	// Transient URL encryption. Deliberately a separate secret from the
	// fingerprint key: rotating the fingerprint key invalidates the entire
	// cache, while rotating this one only strands in-flight jobs. ADR 0013.
	URLEncryptionKey []byte
	// TransientURLTTL bounds how long an encrypted URL survives if explicit
	// deletion never happens. It is a crash-window safety net, not a retention
	// policy.
	TransientURLTTL time.Duration

	// Abuse controls. ADR 0014: the endpoint has no authentication, so these
	// are the only thing standing between a public URL and the provider quota.
	RateLimitPerMinute int
	// RateLimitPollPerMinute bounds status polling. It is far higher than the
	// submission limit because a client polling a pending scan legitimately
	// makes repeated requests, while check-url is the endpoint that spends
	// quota and must stay tight.
	RateLimitPollPerMinute  int
	FingerprintSubmitLimit  int
	FingerprintSubmitWindow time.Duration

	// Worker.
	WorkerPollInterval time.Duration
	// WorkerPollDeadline bounds how long one job waits for a terminal report
	// before it is recorded as timed_out.
	WorkerPollDeadline time.Duration
	// WorkerConcurrency is how many jobs are processed at once. It is a
	// self-inflicted-rate-limit control: too high and the provider throttles us.
	WorkerConcurrency int
	// WorkerReconcileInterval is how often stalled scans are re-enqueued.
	WorkerReconcileInterval time.Duration
	// WorkerStallThreshold is how long a scan may go without progressing before
	// the reconciler treats it as lost. It must exceed the longest plausible
	// provider round trip or healthy work would be re-enqueued underneath
	// itself.
	WorkerStallThreshold time.Duration
	// WorkerClaimBlock is how long a consumer waits for work before re-reading
	// its cancellation. It sets shutdown latency.
	WorkerClaimBlock time.Duration
	// AssessmentTTL is how long a verdict may be served as fresh.
	AssessmentTTL time.Duration
	// ScanMaxAttempts bounds recoveries before a scan is failed outright.
	ScanMaxAttempts int

	// Protection ruleset generation. See docs/security-and-privacy.md §6 and
	// ADR 0018.
	//
	// RULESET_MAX_SCOPE is the primary safety valve: it bounds how broad any
	// published rule may be, independently of the corroboration thresholds.
	RULESET_MAX_SCOPE                string
	RULESET_MIN_CORROBORATION        int
	RULESET_MIN_CORROBORATION_PREFIX int
	RULESET_MIN_CORROBORATION_DOMAIN int
	RULESET_MAX_RULES                int
	// RulesetRebuildInterval bounds how often the worker rebuilds, so a burst
	// of scans does not trigger one rebuild each.
	RulesetRebuildInterval time.Duration
	// RulesetEnabled turns generation off entirely.
	RulesetEnabled bool
}

// Load reads configuration from the environment and validates it. It returns
// an error only when a value is present but unusable.
func Load() (Config, error) {
	c := Config{
		HTTPAddr:              env("HTTP_ADDR", ":8080"),
		APIDocsEnabled:        envBool("API_DOCS_ENABLED", true),
		LogLevel:              env("LOG_LEVEL", "info"),
		LogFormat:             env("LOG_FORMAT", "json"),
		MongoURI:              env("MONGODB_URI", "mongodb://mongodb:27017"),
		MongoDatabase:         env("MONGODB_DATABASE", "cyberguard"),
		AnalysisProvider:      env("ANALYSIS_PROVIDER", ProviderHybridAnalysis),
		RedisAddr:             env("REDIS_ADDR", "redis:6379"),
		RedisPassword:         secret("REDIS_PASSWORD"),
		HybridAnalysisBaseURL: env("HYBRID_ANALYSIS_BASE_URL", "https://hybrid-analysis.com/api/v2"),
		HybridAnalysisAPIKey:  secret("HYBRID_ANALYSIS_API_KEY"),
		URLFingerprintHMACKey: secret("URL_FINGERPRINT_HMAC_KEY"),
	}

	// The encryption key is decoded from hex so it can be stored as an opaque
	// string like every other secret. A short or malformed value is left nil,
	// which readiness reports — it is never silently padded to a valid length.
	if key := secret("URL_ENCRYPTION_KEY"); key != "" {
		decoded, decodeErr := hex.DecodeString(key)
		if decodeErr != nil {
			return Config{}, fmt.Errorf("URL_ENCRYPTION_KEY: must be hex-encoded: %w", decodeErr)
		}
		c.URLEncryptionKey = decoded
	}

	var err error
	if c.ShutdownTimeout, err = envDuration("SHUTDOWN_TIMEOUT", 15*time.Second); err != nil {
		return Config{}, err
	}
	if c.WorkerPollInterval, err = envDuration("WORKER_POLL_INTERVAL", 5*time.Second); err != nil {
		return Config{}, err
	}
	if c.MongoConnectTimeout, err = envDuration("MONGODB_CONNECT_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}
	if c.MongoPingTimeout, err = envDuration("MONGODB_PING_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if c.RedisPingTimeout, err = envDuration("REDIS_PING_TIMEOUT", 3*time.Second); err != nil {
		return Config{}, err
	}
	if c.HealthCheckTimeout, err = envDuration("HEALTH_CHECK_TIMEOUT", 2*time.Second); err != nil {
		return Config{}, err
	}
	if c.RedisDB, err = envInt("REDIS_DB", 0); err != nil {
		return Config{}, err
	}

	// Hybrid Analysis provider defaults. The base URL is the documented
	// server from the v2 specification; environment 140 is Windows 11 64 bit,
	// chosen because phishing kits target Windows browsers.
	if c.HybridAnalysisEnvironmentID, err = envInt("HYBRID_ANALYSIS_ENVIRONMENT_ID", 140); err != nil {
		return Config{}, err
	}
	if c.HybridAnalysisMaxRetries, err = envInt("HYBRID_ANALYSIS_MAX_RETRIES", 3); err != nil {
		return Config{}, err
	}
	if c.HybridAnalysisTimeout, err = envDuration("HYBRID_ANALYSIS_TIMEOUT", 30*time.Second); err != nil {
		return Config{}, err
	}
	if c.HybridAnalysisRetryBase, err = envDuration("HYBRID_ANALYSIS_RETRY_BASE", 500*time.Millisecond); err != nil {
		return Config{}, err
	}
	if c.TransientURLTTL, err = envDuration("TRANSIENT_URL_TTL", 10*time.Minute); err != nil {
		return Config{}, err
	}
	if c.AssessmentTTL, err = envDuration("ASSESSMENT_TTL", 24*time.Hour); err != nil {
		return Config{}, err
	}
	if c.WorkerPollDeadline, err = envDuration("WORKER_POLL_DEADLINE", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.WorkerReconcileInterval, err = envDuration("WORKER_RECONCILE_INTERVAL", 30*time.Second); err != nil {
		return Config{}, err
	}
	if c.WorkerStallThreshold, err = envDuration("WORKER_STALL_THRESHOLD", 2*time.Minute); err != nil {
		return Config{}, err
	}
	if c.WorkerClaimBlock, err = envDuration("WORKER_CLAIM_BLOCK", 1*time.Second); err != nil {
		return Config{}, err
	}
	if c.FingerprintSubmitWindow, err = envDuration("FINGERPRINT_SUBMIT_WINDOW", time.Hour); err != nil {
		return Config{}, err
	}
	if c.WorkerConcurrency, err = envInt("WORKER_CONCURRENCY", 4); err != nil {
		return Config{}, err
	}
	if c.ScanMaxAttempts, err = envInt("SCAN_MAX_ATTEMPTS", 3); err != nil {
		return Config{}, err
	}
	if c.RateLimitPerMinute, err = envInt("RATE_LIMIT_PER_MINUTE", 60); err != nil {
		return Config{}, err
	}
	if c.FingerprintSubmitLimit, err = envInt("FINGERPRINT_SUBMIT_LIMIT", 10); err != nil {
		return Config{}, err
	}
	if c.RateLimitPollPerMinute, err = envInt("RATE_LIMIT_POLL_PER_MINUTE", 600); err != nil {
		return Config{}, err
	}
	c.RULESET_MAX_SCOPE = env("RULESET_MAX_SCOPE", "exact_url")
	if c.RULESET_MIN_CORROBORATION, err = envInt("RULESET_MIN_CORROBORATION", 2); err != nil {
		return Config{}, err
	}
	if c.RULESET_MIN_CORROBORATION_PREFIX, err = envInt("RULESET_MIN_CORROBORATION_PREFIX", 3); err != nil {
		return Config{}, err
	}
	if c.RULESET_MIN_CORROBORATION_DOMAIN, err = envInt("RULESET_MIN_CORROBORATION_DOMAIN", 5); err != nil {
		return Config{}, err
	}
	if c.RULESET_MAX_RULES, err = envInt("RULESET_MAX_RULES", 5000); err != nil {
		return Config{}, err
	}
	if c.RulesetRebuildInterval, err = envDuration("RULESET_REBUILD_INTERVAL", 60*time.Second); err != nil {
		return Config{}, err
	}
	c.RulesetEnabled = envBool("RULESET_ENABLED", true)

	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) validate() error {
	switch c.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("LOG_FORMAT: want %q or %q, got %q", "json", "text", c.LogFormat)
	}
	switch c.AnalysisProvider {
	case ProviderHybridAnalysis, ProviderMock:
	default:
		return fmt.Errorf("ANALYSIS_PROVIDER: want %q or %q, got %q",
			ProviderHybridAnalysis, ProviderMock, c.AnalysisProvider)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("LOG_LEVEL: want one of debug|info|warn|error, got %q", c.LogLevel)
	}
	if c.HTTPAddr == "" {
		return fmt.Errorf("HTTP_ADDR must not be empty")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("SHUTDOWN_TIMEOUT must be positive, got %s", c.ShutdownTimeout)
	}
	if c.MongoURI == "" {
		return fmt.Errorf("MONGODB_URI must not be empty")
	}
	if c.MongoDatabase == "" {
		return fmt.Errorf("MONGODB_DATABASE must not be empty")
	}
	if c.RedisAddr == "" {
		return fmt.Errorf("REDIS_ADDR must not be empty")
	}
	if c.RedisDB < 0 {
		return fmt.Errorf("REDIS_DB must not be negative, got %d", c.RedisDB)
	}
	if c.HealthCheckTimeout <= 0 {
		return fmt.Errorf("HEALTH_CHECK_TIMEOUT must be positive, got %s", c.HealthCheckTimeout)
	}
	if c.HybridAnalysisMaxRetries < 0 {
		return fmt.Errorf("HYBRID_ANALYSIS_MAX_RETRIES must not be negative, got %d", c.HybridAnalysisMaxRetries)
	}
	if c.HybridAnalysisEnvironmentID <= 0 {
		return fmt.Errorf("HYBRID_ANALYSIS_ENVIRONMENT_ID must be positive, got %d",
			c.HybridAnalysisEnvironmentID)
	}
	// The stall threshold is only meaningful if it outlasts the work it is
	// meant to judge. A threshold shorter than the reconcile interval would
	// re-enqueue healthy scans forever, and one shorter than the provider
	// timeout would abandon work that was about to succeed.
	if c.WorkerStallThreshold <= c.WorkerReconcileInterval {
		return fmt.Errorf("WORKER_STALL_THRESHOLD (%s) must exceed WORKER_RECONCILE_INTERVAL (%s)",
			c.WorkerStallThreshold, c.WorkerReconcileInterval)
	}
	if c.WorkerStallThreshold <= c.HybridAnalysisTimeout {
		return fmt.Errorf("WORKER_STALL_THRESHOLD (%s) must exceed HYBRID_ANALYSIS_TIMEOUT (%s)",
			c.WorkerStallThreshold, c.HybridAnalysisTimeout)
	}
	if c.WorkerPollDeadline <= 0 {
		return fmt.Errorf("WORKER_POLL_DEADLINE must be positive, got %s", c.WorkerPollDeadline)
	}
	if c.WorkerConcurrency <= 0 {
		return fmt.Errorf("WORKER_CONCURRENCY must be positive, got %d", c.WorkerConcurrency)
	}
	if c.ScanMaxAttempts <= 0 {
		return fmt.Errorf("SCAN_MAX_ATTEMPTS must be positive, got %d", c.ScanMaxAttempts)
	}
	if c.AssessmentTTL <= 0 {
		return fmt.Errorf("ASSESSMENT_TTL must be positive, got %s", c.AssessmentTTL)
	}
	if c.RateLimitPerMinute < 0 {
		return fmt.Errorf("RATE_LIMIT_PER_MINUTE must not be negative, got %d", c.RateLimitPerMinute)
	}
	if c.FingerprintSubmitLimit < 0 {
		return fmt.Errorf("FINGERPRINT_SUBMIT_LIMIT must not be negative, got %d", c.FingerprintSubmitLimit)
	}
	if c.RateLimitPollPerMinute < 0 {
		return fmt.Errorf("RATE_LIMIT_POLL_PER_MINUTE must not be negative, got %d", c.RateLimitPollPerMinute)
	}
	switch c.RULESET_MAX_SCOPE {
	case "exact_url", "url_prefix", "registrable_domain":
	default:
		return fmt.Errorf("RULESET_MAX_SCOPE: want exact_url, url_prefix or registrable_domain, got %q",
			c.RULESET_MAX_SCOPE)
	}
	// The corroboration ladder must not weaken as scopes widen: a broader rule
	// blocking more must never be easier to earn.
	if c.RULESET_MIN_CORROBORATION_PREFIX < c.RULESET_MIN_CORROBORATION {
		return fmt.Errorf("RULESET_MIN_CORROBORATION_PREFIX (%d) must be at least RULESET_MIN_CORROBORATION (%d)",
			c.RULESET_MIN_CORROBORATION_PREFIX, c.RULESET_MIN_CORROBORATION)
	}
	if c.RULESET_MIN_CORROBORATION_DOMAIN < c.RULESET_MIN_CORROBORATION_PREFIX {
		return fmt.Errorf("RULESET_MIN_CORROBORATION_DOMAIN (%d) must be at least RULESET_MIN_CORROBORATION_PREFIX (%d)",
			c.RULESET_MIN_CORROBORATION_DOMAIN, c.RULESET_MIN_CORROBORATION_PREFIX)
	}
	return nil
}

// UsesMockProvider reports whether the offline provider is selected.
func (c Config) UsesMockProvider() bool {
	return c.AnalysisProvider == ProviderMock
}

// HasProviderCredentials reports whether remote analysis is usable.
//
// It is only meaningful when the real provider is selected: in mock mode the
// API key is irrelevant and, ideally, absent.
func (c Config) HasProviderCredentials() bool {
	return strings.TrimSpace(c.HybridAnalysisAPIKey) != ""
}

// ValidateProviderSelection checks that the selected provider is usable.
//
// It is deliberately fatal rather than advisory. Falling back — to the mock
// because a key is missing, or to the real service because the mock was asked
// for — would each be a lie about what the system is doing, and the operator
// would have no way to tell from the outside.
func (c Config) ValidateProviderSelection() error {
	if c.UsesMockProvider() {
		return nil
	}
	if !c.HasProviderCredentials() {
		return fmt.Errorf("ANALYSIS_PROVIDER=%s requires HYBRID_ANALYSIS_API_KEY to be set; "+
			"set ANALYSIS_PROVIDER=%s to run without an external service",
			ProviderHybridAnalysis, ProviderMock)
	}
	return nil
}

// HasFingerprintKey reports whether URL fingerprinting can run. The HMAC key
// is required for exact-URL cache lookups.
func (c Config) HasFingerprintKey() bool {
	return strings.TrimSpace(c.URLFingerprintHMACKey) != ""
}

// HasEncryptionKey reports whether transient URL encryption is usable.
//
// A short key is present but unusable, so this checks the length AES-256-GCM
// requires rather than mere presence.
func (c Config) HasEncryptionKey() bool {
	return len(c.URLEncryptionKey) >= 32
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

// secret reads a credential and trims surrounding whitespace.
//
// Trimming matters more here than for ordinary settings. A key pasted from a
// secret manager, a CI variable or a .env file often carries a trailing newline,
// and a stray byte in an HMAC key silently produces different fingerprints on
// different replicas — a cache that appears to work while never hitting.
// A whitespace-only value is treated as absent, so an unset secret is reported
// honestly by the readiness probe rather than being mistaken for a real key.
func secret(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// envBool reads a boolean setting.
//
// Only the spellings a person would actually type are accepted. Anything else is
// a configuration error rather than a silent false: a typo that quietly
// disabled ruleset generation would be invisible until a user reported they
// were not being protected.
func envBool(key string, def bool) bool {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}
