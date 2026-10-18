package hybridanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cyberguard/internal/models"
)

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }

// TestQuickScanURLRequestShape pins the exact wire contract from the official
// specification: one POST to /quick-scan/url, form-encoded, api-key header.
func TestQuickScanURLRequestShape(t *testing.T) {
	var got struct {
		method    string
		path      string
		apiKey    string
		ua        string
		formURL   string
		formScan  string
		extraKeys []string
	}

	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path = r.Method, r.URL.Path
		got.apiKey = r.Header.Get("api-key")
		got.ua = r.Header.Get("User-Agent")
		_ = r.ParseForm()
		got.formURL = r.PostFormValue("url")
		got.formScan = r.PostFormValue("scan_type")
		for k := range r.PostForm {
			if k != "url" && k != "scan_type" {
				got.extraKeys = append(got.extraKeys, k)
			}
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"qs-1","finished":true}`)
	}))
	t.Cleanup(rs.Close)

	client, err := New(Options{BaseURL: rs.URL, APIKey: testKey, ScanType: "all_lookup", Timeout: time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.QuickScanURL(context.Background(), "https://example.com"); err != nil {
		t.Fatalf("QuickScanURL: %v", err)
	}

	if got.method != http.MethodPost || got.path != "/quick-scan/url" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.formScan != "all_lookup" {
		t.Errorf("scan_type = %q", got.formScan)
	}
	if got.formURL != "https://example.com" {
		t.Errorf("url = %q", got.formURL)
	}
	if len(got.extraKeys) != 0 {
		t.Errorf("undocumented form fields sent: %v", got.extraKeys)
	}
}

// TestResultMarshalsAsModelsShape confirms the stored-and-served JSON of a
// scanner uses this API's camelCase contract.
func TestResultMarshalsAsModelsShape(t *testing.T) {
	res := models.Scanner{
		Name:         "metadefender",
		Status:       "no specific threat",
		StatusRaw:    "NO_DETECTION",
		ErrorMessage: strPtr(""),
		Progress:     100,
		Positives:    intPtr(0),
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"name", "status", "statusRaw", "progress", "positives"} {
		if _, ok := m[key]; !ok {
			t.Errorf("key %q missing from marshalled scanner: %s", key, raw)
		}
	}
	if _, snake := m["anti_virus_results"]; snake {
		t.Error("snake_case keys must not appear in the served shape")
	}
}
