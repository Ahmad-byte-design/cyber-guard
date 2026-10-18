package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withEnv sets environment variables for the test and restores the previous
// values afterwards, so tests never leak state into each other.
func withEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		if v == "\x00unset" {
			prev, had := os.LookupEnv(k)
			if err := os.Unsetenv(k); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if had {
					_ = os.Setenv(k, prev)
				} else {
					_ = os.Unsetenv(k)
				}
			})
			continue
		}
		t.Setenv(k, v)
	}
}

func TestLoadDefaults(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_PORT":                      "\x00unset",
		"MONGODB_URI":                   "\x00unset",
		"MONGODB_DATABASE":              "\x00unset",
		"HYBRID_ANALYSIS_BASE_URL":      "\x00unset",
		"HYBRID_ANALYSIS_API_KEY":       "\x00unset",
		"HYBRID_ANALYSIS_TIMEOUT":       "\x00unset",
		"HYBRID_ANALYSIS_SCAN_TYPE":     "\x00unset",
		"HYBRID_ANALYSIS_POLL_INTERVAL": "\x00unset",
		"ASSESSMENT_TTL":                "\x00unset",
		"CORS_ALLOWED_ORIGINS":          "\x00unset",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.MongoURI != "mongodb://localhost:27017" {
		t.Errorf("MongoURI = %q", cfg.MongoURI)
	}
	if cfg.MongoDatabase != "cyberguard" {
		t.Errorf("MongoDatabase = %q", cfg.MongoDatabase)
	}
	if cfg.HABaseURL != DefaultBaseURL {
		t.Errorf("HABaseURL = %q, want the documented host", cfg.HABaseURL)
	}
	if cfg.HATimeout != 30*time.Second {
		t.Errorf("HATimeout = %s", cfg.HATimeout)
	}
	if cfg.HAScanType != "all" {
		t.Errorf("HAScanType = %q", cfg.HAScanType)
	}
	if cfg.HAPollInterval != time.Second {
		t.Errorf("HAPollInterval = %s, want 1s", cfg.HAPollInterval)
	}
	if cfg.AssessmentTTL != 24*time.Hour {
		t.Errorf("AssessmentTTL = %s, want 24h", cfg.AssessmentTTL)
	}
	want := []string{"http://localhost:3000", "http://localhost:5173"}
	if len(cfg.CORSAllowedOrigins) != len(want) {
		t.Fatalf("CORSAllowedOrigins = %v", cfg.CORSAllowedOrigins)
	}
	for i := range want {
		if cfg.CORSAllowedOrigins[i] != want[i] {
			t.Errorf("CORSAllowedOrigins[%d] = %q", i, cfg.CORSAllowedOrigins[i])
		}
	}
}

func TestLoadValues(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_PORT":                      "9090",
		"MONGODB_URI":                   "mongodb://db.internal:27017",
		"MONGODB_DATABASE":              "cyberguard_prod",
		"HYBRID_ANALYSIS_API_KEY":       " test-key-with-whitespace  ",
		"HYBRID_ANALYSIS_TIMEOUT":       "12s",
		"HYBRID_ANALYSIS_SCAN_TYPE":     "lookup_ha",
		"HYBRID_ANALYSIS_POLL_INTERVAL": "2s",
		"ASSESSMENT_TTL":                "72h",
		"CORS_ALLOWED_ORIGINS":          "https://cyberguard.example,https://app.example/",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d", cfg.Port)
	}
	if cfg.MongoURI != "mongodb://db.internal:27017" {
		t.Errorf("MongoURI = %q", cfg.MongoURI)
	}
	if cfg.MongoDatabase != "cyberguard_prod" {
		t.Errorf("MongoDatabase = %q", cfg.MongoDatabase)
	}
	// A key pasted with surrounding whitespace must be trimmed.
	if cfg.HAAPIKey != "test-key-with-whitespace" {
		t.Errorf("HAAPIKey = %q", cfg.HAAPIKey)
	}
	if cfg.HATimeout != 12*time.Second {
		t.Errorf("HATimeout = %s", cfg.HATimeout)
	}
	if cfg.HAScanType != "lookup_ha" {
		t.Errorf("HAScanType = %q", cfg.HAScanType)
	}
	if cfg.HAPollInterval != 2*time.Second {
		t.Errorf("HAPollInterval = %s, want 2s", cfg.HAPollInterval)
	}
	if cfg.AssessmentTTL != 72*time.Hour {
		t.Errorf("AssessmentTTL = %s, want 72h", cfg.AssessmentTTL)
	}
	origins := cfg.CORSAllowedOrigins
	if len(origins) != 2 || origins[0] != "https://cyberguard.example" || origins[1] != "https://app.example" {
		t.Errorf("CORSAllowedOrigins = %v; trailing slash and spaces must be normalised", origins)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
	}{
		{"port too high", map[string]string{"APP_PORT": "70000"}},
		{"port not numeric", map[string]string{"APP_PORT": "http"}},
		{"empty database", map[string]string{"MONGODB_DATABASE": " "}},
		{"bad timeout", map[string]string{"HYBRID_ANALYSIS_TIMEOUT": "soon"}},
		{"zero timeout", map[string]string{"HYBRID_ANALYSIS_TIMEOUT": "0s"}},
		{"huge timeout", map[string]string{"HYBRID_ANALYSIS_TIMEOUT": "6m"}},
		{"unknown scan type", map[string]string{"HYBRID_ANALYSIS_SCAN_TYPE": "deep_scan"}},
		{"zero poll interval", map[string]string{"HYBRID_ANALYSIS_POLL_INTERVAL": "0s"}},
		{"poll interval over one minute", map[string]string{"HYBRID_ANALYSIS_POLL_INTERVAL": "61s"}},
		{"bad poll interval", map[string]string{"HYBRID_ANALYSIS_POLL_INTERVAL": "soon"}},
		{"zero assessment ttl", map[string]string{"ASSESSMENT_TTL": "0s"}},
		{"negative assessment ttl", map[string]string{"ASSESSMENT_TTL": "-5m"}},
		{"ttl over two weeks", map[string]string{"ASSESSMENT_TTL": "337h"}},
		{"bad assessment ttl", map[string]string{"ASSESSMENT_TTL": "tomorrow"}},
		{"wildcard CORS", map[string]string{"CORS_ALLOWED_ORIGINS": "*"}},
		{"not an origin", map[string]string{"CORS_ALLOWED_ORIGINS": "https://example.com/app"}},
		{"all empty origins", map[string]string{"CORS_ALLOWED_ORIGINS": " , ,"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]string{"APP_PORT": "\x00unset", "MONGODB_URI": "\x00unset",
				"MONGODB_DATABASE": "\x00unset", "HYBRID_ANALYSIS_BASE_URL": "\x00unset",
				"HYBRID_ANALYSIS_TIMEOUT": "\x00unset", "HYBRID_ANALYSIS_SCAN_TYPE": "\x00unset",
				"CORS_ALLOWED_ORIGINS": "\x00unset"}
			for k, v := range tc.vars {
				vars[k] = v
			}
			withEnv(t, vars)

			if _, err := Load(); err == nil {
				t.Fatal("Load: want an error, got none")
			}
		})
	}
}

func TestLoadDotEnv(t *testing.T) {
	t.Run("missing file is not an error", func(t *testing.T) {
		if err := LoadDotEnv(filepath.Join(t.TempDir(), "nope.env")); err != nil {
			t.Fatalf("LoadDotEnv: %v", err)
		}
	})

	t.Run("sets values and never overrides the environment", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".env")
		content := "# comment\n" +
			"CG_TEST_FROM_FILE=from-file\n" +
			"\"CG_TEST_QUOTED\"='in quotes'\n" +
			"this line is not a pair\n" +
			"CG_TEST_EMPTY=\n" +
			"CG_TEST_ENV=from-file-but-ignored\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CG_TEST_ENV", "from-environment")
		t.Cleanup(func() {
			for _, k := range []string{"CG_TEST_FROM_FILE", "CG_TEST_QUOTED", "CG_TEST_EMPTY", "CG_TEST_ENV"} {
				_ = os.Unsetenv(k)
			}
		})

		if err := LoadDotEnv(path); err != nil {
			t.Fatalf("LoadDotEnv: %v", err)
		}
		if v := os.Getenv("CG_TEST_FROM_FILE"); v != "from-file" {
			t.Errorf("CG_TEST_FROM_FILE = %q", v)
		}
		if v := os.Getenv("CG_TEST_QUOTED"); v != "in quotes" {
			t.Errorf("CG_TEST_QUOTED = %q", v)
		}
		if v := os.Getenv("CG_TEST_ENV"); v != "from-environment" {
			t.Errorf("CG_TEST_ENV = %q; the environment must win over .env", v)
		}
	})
}
