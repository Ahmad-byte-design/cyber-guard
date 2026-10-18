// Package config loads runtime configuration from the environment.
//
// For local development a .env file in the working directory is loaded first,
// so the same binary runs unmodified inside Docker (pure environment) and on a
// host (environment + .env). Variables already present in the environment win;
// .env never overrides them.
package config

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// scanTypes is the documented enum of the provider's required `scan_type`
// field (official OpenAPI document, POST /quick-scan/url, retrieved
// 2026-10-17). No other value may be sent.
var scanTypes = map[string]bool{
	"all": true, "all_lookup": true, "all_scan": true,
	"lookup_ha": true, "lookup_cleandns": true, "lookup_bforeai": true,
	"scan_crowdstrike_ml": true, "scan_metadefender": true,
	"scan_urlscanio": true, "scan_scamadviser": true,
	"scan_criminalip": true, "scan_vipre": true,
}

// DefaultBaseURL is the server the official Hybrid Analysis v2 specification
// declares (servers[0].url). The www host answers 301 to this one, and a Go
// client does not replay a POST body across the method change a 301 implies,
// so the declared host is the default. Verified live on 2026-10-17.
const DefaultBaseURL = "https://hybrid-analysis.com/api/v2"

// Config is the runtime configuration.
type Config struct {
	// Port the HTTP server listens on.
	Port int

	// MongoDB.
	MongoURI      string
	MongoDatabase string

	// Hybrid Analysis provider.
	HABaseURL      string
	HAAPIKey       string
	HATimeout      time.Duration
	HAScanType     string
	HAPollInterval time.Duration

	// AssessmentTTL is how long a completed assessment stays reusable as a
	// cached result before check-url submits the URL again.
	AssessmentTTL time.Duration

	// CORSAllowedOrigins is the exact origin list the website may use.
	// Wildcards are rejected at load time, so production cannot accidentally
	// run with unrestricted CORS.
	CORSAllowedOrigins []string
}

// Load reads configuration from the environment.
//
// A missing API key is not a load error: GET /api/v1/get-all and the
// documentation endpoints still work, and POST /api/v1/check-url reports the
// provider as unconfigured instead of the process lying about what it can do.
func Load() (Config, error) {
	c := Config{
		Port:          8080,
		MongoURI:      "mongodb://localhost:27017",
		MongoDatabase: "cyberguard",
		HABaseURL:     DefaultBaseURL,
		HAAPIKey:      strings.TrimSpace(os.Getenv("HYBRID_ANALYSIS_API_KEY")),
		HATimeout:     30 * time.Second,
		HAScanType:    "all",
		// PollInterval bounds the wait between result retrievals inside one
		// check-url request; WaitBudget defaults to HATimeout.
		HAPollInterval: time.Second,
		AssessmentTTL:  24 * time.Hour,
	}

	var err error
	if raw := strings.TrimSpace(os.Getenv("APP_PORT")); raw != "" {
		if c.Port, err = strconv.Atoi(raw); err != nil {
			return Config{}, fmt.Errorf("APP_PORT: %w", err)
		}
	}
	// URI and database are required settings: present-but-blank is a
	// configuration error, not a silent fallback to the defaults, because a
	// blank value in an .env is almost always an editing accident.
	if raw, ok := os.LookupEnv("MONGODB_URI"); ok {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return Config{}, fmt.Errorf("MONGODB_URI must not be empty")
		}
		c.MongoURI = raw
	}
	if raw, ok := os.LookupEnv("MONGODB_DATABASE"); ok {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return Config{}, fmt.Errorf("MONGODB_DATABASE must not be empty")
		}
		c.MongoDatabase = raw
	}
	if raw := strings.TrimSpace(os.Getenv("HYBRID_ANALYSIS_BASE_URL")); raw != "" {
		c.HABaseURL = raw
	}
	if c.HATimeout, err = envDuration("HYBRID_ANALYSIS_TIMEOUT", c.HATimeout); err != nil {
		return Config{}, err
	}
	if c.HAPollInterval, err = envDuration("HYBRID_ANALYSIS_POLL_INTERVAL", c.HAPollInterval); err != nil {
		return Config{}, err
	}
	if raw := strings.TrimSpace(os.Getenv("HYBRID_ANALYSIS_SCAN_TYPE")); raw != "" {
		c.HAScanType = raw
	}
	if c.AssessmentTTL, err = envDuration("ASSESSMENT_TTL", c.AssessmentTTL); err != nil {
		return Config{}, err
	}
	if c.CORSAllowedOrigins, err = envOrigins("CORS_ALLOWED_ORIGINS",
		[]string{"http://localhost:3000", "http://localhost:5173"}); err != nil {
		return Config{}, err
	}

	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("APP_PORT must be a port between 1 and 65535, got %d", c.Port)
	}
	if c.MongoURI == "" {
		return fmt.Errorf("MONGODB_URI must not be empty")
	}
	if c.MongoDatabase == "" {
		return fmt.Errorf("MONGODB_DATABASE must not be empty")
	}
	if _, err := url.Parse(c.HABaseURL); err != nil {
		return fmt.Errorf("HYBRID_ANALYSIS_BASE_URL: %w", err)
	}
	if c.HATimeout <= 0 {
		return fmt.Errorf("HYBRID_ANALYSIS_TIMEOUT must be positive, got %s", c.HATimeout)
	}
	if c.HATimeout > 5*time.Minute {
		return fmt.Errorf("HYBRID_ANALYSIS_TIMEOUT must not exceed 5m, got %s", c.HATimeout)
	}
	if !scanTypes[c.HAScanType] {
		return fmt.Errorf("HYBRID_ANALYSIS_SCAN_TYPE %q is not one of the documented values: %s",
			c.HAScanType, strings.Join(sortedKeys(scanTypes), ", "))
	}
	// The poll interval must fit inside a single request: interval > timeout
	// would mean at most one retrieval and no waiting at all.
	if c.HAPollInterval <= 0 {
		return fmt.Errorf("HYBRID_ANALYSIS_POLL_INTERVAL must be positive, got %s", c.HAPollInterval)
	}
	if c.HAPollInterval > time.Minute {
		return fmt.Errorf("HYBRID_ANALYSIS_POLL_INTERVAL must not exceed 1m, got %s", c.HAPollInterval)
	}
	// Completed assessments stay cacheable for a bounded, positive lifetime;
	// beyond two weeks every check-url would re-contact the provider anyway,
	// which is what the value is supposed to prevent.
	if c.AssessmentTTL <= 0 {
		return fmt.Errorf("ASSESSMENT_TTL must be positive, got %s", c.AssessmentTTL)
	}
	if c.AssessmentTTL > 14*24*time.Hour {
		return fmt.Errorf("ASSESSMENT_TTL must not exceed 336h (14 days), got %s", c.AssessmentTTL)
	}
	if len(c.CORSAllowedOrigins) == 0 {
		return fmt.Errorf("CORS_ALLOWED_ORIGINS must name at least one origin")
	}
	return nil
}

// envOrigins parses a comma-separated origin list.
//
// "*" is rejected rather than honoured: the API holds no authentication, so an
// unrestricted origin list would let any page anywhere submit URLs that spend
// this deployment's provider quota.
func envOrigins(key string, def []string) ([]string, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def, nil
	}
	var origins []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(part), "/"))
		if part == "" {
			continue
		}
		if part == "*" {
			return nil, fmt.Errorf("%s: \"*\" is not allowed; list exact origins", key)
		}
		u, err := url.Parse(part)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" {
			return nil, fmt.Errorf("%s: %q is not a bare origin like https://example.com", key, part)
		}
		origins = append(origins, strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host))
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("%s must name at least one origin", key)
	}
	return origins, nil
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

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// LoadDotEnv reads a KEY=VALUE file and sets any variable that is not already
// present in the environment.
//
// Existing environment variables always win, which is what makes the same file
// harmless under Docker Compose or a real process manager. Lines that are not
// KEY=VALUE pairs are skipped: a stray comment inside a value is better than a
// service refusing to start over it.
func LoadDotEnv(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = unquote(strings.TrimSpace(key))
		value = unquote(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
}

// unquote strips one layer of matching surrounding quotes, the common style in
// committed .env files.
func unquote(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
