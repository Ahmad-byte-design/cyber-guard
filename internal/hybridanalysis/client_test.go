package hybridanalysis

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testKey is a placeholder used only against local httptest servers. No test
// in this package ever contacts the real provider.
const testKey = "local-test-key-not-a-real-credential"

// recordingServer is an httptest server that captures every request it
// receives, so tests can assert exactly what the client put on the wire.
type recordingServer struct {
	*httptest.Server
	requests   atomic.Int32
	status     int
	body       string
	header     func(http.Header)
	gotMethod  string
	gotPath    string
	gotForm    *urlForm
	gotHeaders http.Header
}

type urlForm struct {
	url      string
	scanType string
}

func newRecordingServer(t *testing.T, status int, body string, header func(http.Header), sleep time.Duration) *recordingServer {
	t.Helper()
	rs := &recordingServer{status: status, body: body, header: header}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.requests.Add(1)
		rs.gotMethod = r.Method
		rs.gotPath = r.URL.Path
		rs.gotHeaders = r.Header.Clone()
		_ = r.ParseForm()
		rs.gotForm = &urlForm{url: r.PostFormValue("url"), scanType: r.PostFormValue("scan_type")}

		if sleep > 0 {
			time.Sleep(sleep)
		}
		if rs.header != nil {
			rs.header(w.Header())
		}
		w.WriteHeader(rs.status)
		_, _ = w.Write([]byte(rs.body))
	}))
	t.Cleanup(rs.Close)
	return rs
}

func newTestClient(t *testing.T, baseURL string, timeout time.Duration, maxBody int64) (*Client, error) {
	t.Helper()
	return New(Options{
		BaseURL:      baseURL,
		APIKey:       testKey,
		ScanType:     "all",
		Timeout:      timeout,
		MaxBodyBytes: maxBody,
	})
}

// successfulBody mirrors the documented QuickScan schema of a 201 response,
// including the scanners_v2 object and the deprecated scanners array.
const successfulBody = `{
  "id": "qs-123",
  "sha256": "abc123",
  "finished": true,
  "scanners": [
    {
      "name": "metadefender",
      "status": "no specific threat",
      "statusRaw": "NO_DETECTION",
      "progress": 100,
      "total": 4,
      "positives": 0,
      "percent": 0
    }
  ],
  "scanners_v2": {
    "crowdstrike_ml": {"name": "crowdstrike_ml", "status": "no specific threat", "statusRaw": "NO_DETECTION", "progress": 100}
  },
  "whitelist": [],
  "reports": ["report-1", "report-2"]
}`

func TestQuickScanURLSuccess(t *testing.T) {
	rs := newRecordingServer(t, http.StatusCreated, successfulBody, nil, 0)
	client, err := newTestClient(t, rs.URL+"/", time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := client.QuickScanURL(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("QuickScanURL: %v", err)
	}

	// The wire contract.
	if rs.gotMethod != http.MethodPost {
		t.Errorf("method = %q", rs.gotMethod)
	}
	if rs.gotPath != "/quick-scan/url" {
		t.Errorf("path = %q; a trailing slash in the base URL must not change the route", rs.gotPath)
	}
	if got := rs.gotHeaders.Get("api-key"); got != testKey {
		t.Errorf("api-key header = %q", got)
	}
	if got := rs.gotHeaders.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q; the official contract requires it", got)
	}
	if got := rs.gotHeaders.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
	if rs.gotForm.url != "https://example.com" {
		t.Errorf("form url = %q", rs.gotForm.url)
	}
	if rs.gotForm.scanType != "all" {
		t.Errorf("form scan_type = %q", rs.gotForm.scanType)
	}

	// The parsed result.
	if res.ID != "qs-123" {
		t.Errorf("ID = %q", res.ID)
	}
	if res.SHA256 != "abc123" {
		t.Errorf("SHA256 = %q", res.SHA256)
	}
	if !res.Finished {
		t.Error("Finished = false, want true")
	}
	if res.ScanType != "all" {
		t.Errorf("ScanType = %q", res.ScanType)
	}
	if len(res.Reports) != 2 || res.Reports[0] != "report-1" {
		t.Errorf("Reports = %v", res.Reports)
	}
	if len(res.Scanners) != 1 || res.Scanners[0].Name != "metadefender" {
		t.Fatalf("Scanners = %+v", res.Scanners)
	}
	if res.Scanners[0].Total == nil || *res.Scanners[0].Total != 4 {
		t.Errorf("Scanners[0].Total = %v, want 4 (not a defaulted 0)", res.Scanners[0].Total)
	}
	if res.Scanners[0].Progress != 100 {
		t.Errorf("Scanners[0].Progress = %d", res.Scanners[0].Progress)
	}
	if res.ScannersV2 == nil {
		t.Fatal("ScannersV2 was not passed through")
	}
	if _, ok := res.ScannersV2["crowdstrike_ml"]; !ok {
		t.Errorf("ScannersV2 = %v; crowdstrike_ml key missing", res.ScannersV2)
	}
}

func TestQuickScanURLUnfinishedIsASubmission(t *testing.T) {
	body := `{"id": "qs-9", "finished": false}`
	rs := newRecordingServer(t, http.StatusCreated, body, nil, 0)
	client, err := newTestClient(t, rs.URL, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := client.QuickScanURL(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("QuickScanURL: %v", err)
	}
	if res.Finished {
		t.Error("Finished = true; the provider did not report completion")
	}
	if res.ID != "qs-9" {
		t.Errorf("ID = %q", res.ID)
	}
}

func TestQuickScanURLDropsUnparseableScannersV2(t *testing.T) {
	// scanners_v2 is a passthrough. A syntactically valid JSON body whose
	// scanners_v2 is not a JSON object is tolerated: the typed fields
	// (id, sha256, finished, scanners, reports) are what this service relies
	// on, and a broken passthrough object is dropped, not fatal.
	cases := map[string]string{
		"a string":    `{"id":"qs-v","finished":true,"scanners_v2":"nope"}`,
		"an array":    `{"id":"qs-v","finished":true,"scanners_v2":[1,2]}`,
		"null":        `{"id":"qs-v","finished":true,"scanners_v2":null}`,
		"not present": `{"id":"qs-v","finished":true}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rs := newRecordingServer(t, http.StatusCreated, body, nil, 0)
			client, err := newTestClient(t, rs.URL, time.Second, 0)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			res, err := client.QuickScanURL(context.Background(), "https://example.com")
			if err != nil {
				t.Fatalf("QuickScanURL: %v — a broken passthrough must not fail the submission", err)
			}
			if res.ScannersV2 != nil {
				t.Errorf("ScannersV2 = %v, want nil", res.ScannersV2)
			}
		})
	}
}

func TestQuickScanURLToleratesMissingOptionalFields(t *testing.T) { // Every optional field absent: the provider marks most of them nullable.
	body := `{"id": "qs-bare", "finished": true}`
	rs := newRecordingServer(t, http.StatusCreated, body, nil, 0)
	client, err := newTestClient(t, rs.URL, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := client.QuickScanURL(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("QuickScanURL: %v", err)
	}
	if res.SHA256 != "" || res.Scanners != nil || res.ScannersV2 != nil || res.Reports != nil {
		t.Errorf("optional fields not reported broke the parse: %+v", res)
	}
}

func TestQuickScanURLRejectsBadSuccessResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"malformed json", `{"id": `},
		{"no id", `{"finished": true}`},
		{"empty id", `{"id": "  ", "finished": true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRecordingServer(t, http.StatusCreated, tc.body, nil, 0)
			client, err := newTestClient(t, rs.URL, time.Second, 0)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := client.QuickScanURL(context.Background(), "https://example.com"); !errors.Is(err, ErrBadResponse) {
				t.Fatalf("err = %v, want ErrBadResponse", err)
			}
		})
	}
}

func TestQuickScanURLErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"unauthorized", http.StatusUnauthorized, ErrAuth},
		{"forbidden", http.StatusForbidden, ErrAuth},
		{"validation", http.StatusBadRequest, ErrValidation},
		{"lost", http.StatusGone, ErrBadResponse},
		{"server error", http.StatusInternalServerError, ErrUnavailable},
		{"bad gateway", http.StatusBadGateway, ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRecordingServer(t, tc.status, `{"message":"provider prose never reaches clients"}`, nil, 0)
			client, err := newTestClient(t, rs.URL, time.Second, 0)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = client.QuickScanURL(context.Background(), "https://example.com")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// Provider prose must never be echoed into the error chain.
			if strings.Contains(err.Error(), "provider prose") {
				t.Errorf("the provider message leaked into the error: %v", err)
			}
		})
	}
}

func TestQuickScanURLRateLimitedCarriesRetryAfter(t *testing.T) {
	rs := newRecordingServer(t, http.StatusTooManyRequests, `{"message":"slow down"}`,
		func(h http.Header) { h.Set("Retry-After", "7") }, 0)
	client, err := newTestClient(t, rs.URL, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = client.QuickScanURL(context.Background(), "https://example.com")
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want a RateLimitError", err)
	}
	if rl.RetryAfter != 7*time.Second {
		t.Errorf("RetryAfter = %s, want 7s", rl.RetryAfter)
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err does not wrap ErrRateLimited: %v", err)
	}
}

func TestQuickScanURLTimeoutIsNotRetried(t *testing.T) {
	// The server answers slowly; the client times out. Exactly one request
	// must arrive: the endpoint declares no idempotency token, so a retry
	// could submit the URL twice.
	rs := newRecordingServer(t, http.StatusCreated, successfulBody, nil, 500*time.Millisecond)
	client, err := newTestClient(t, rs.URL, 50*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = client.QuickScanURL(context.Background(), "https://example.com")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if got := rs.requests.Load(); got != 1 {
		t.Errorf("requests = %d, want exactly 1 (no retry after an ambiguous timeout)", got)
	}
}

func TestQuickScanURLDeadlineContext(t *testing.T) {
	rs := newRecordingServer(t, http.StatusCreated, successfulBody, nil, 500*time.Millisecond)
	client, err := newTestClient(t, rs.URL, time.Minute, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = client.QuickScanURL(ctx, "https://example.com")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func TestQuickScanURLOversizedBodyRejected(t *testing.T) {
	rs := newRecordingServer(t, http.StatusCreated, strings.Repeat("x", 4096), nil, 0)
	client, err := newTestClient(t, rs.URL, time.Second, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = client.QuickScanURL(context.Background(), "https://example.com")
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("err = %v, want ErrBadResponse", err)
	}
}

func TestQuickScanURLTransportError(t *testing.T) {
	// A server that immediately closes: the socket fails after Connect.
	rs := newRecordingServer(t, http.StatusCreated, successfulBody, nil, 0)
	url := rs.URL
	rs.Close() //nolint:errcheck — nothing was served, the URL is closed on purpose

	client, err := newTestClient(t, url, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.QuickScanURL(context.Background(), "https://example.com")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestClientRequiresAPIKey(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("New without a key: err = %v, want ErrNotConfigured", err)
	}
}

func TestConvertScannersPreservesOptionalValues(t *testing.T) {
	in := []wireScanner{{
		Name:         "metadefender",
		Status:       "suspicious",
		StatusRaw:    "DETECTION",
		ErrorMessage: strPtr("engine down"),
		Progress:     55,
		Total:        intPtr(5),
		Positives:    intPtr(2),
		Percent:      intPtr(40),
		AntiVirus:    []wireAVResult{{Name: "Vipre", Result: true, ThreatFound: "Heuristic"}},
	}}

	out := convertScanners(in)
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	s := out[0]
	if s.ErrorMessage == nil || *s.ErrorMessage != "engine down" {
		t.Errorf("ErrorMessage = %v", s.ErrorMessage)
	}
	if s.Total == nil || *s.Total != 5 {
		t.Errorf("Total = %v", s.Total)
	}
	if s.Positives == nil || *s.Positives != 2 {
		t.Errorf("Positives = %v", s.Positives)
	}
	if s.Percent == nil || *s.Percent != 40 {
		t.Errorf("Percent = %v", s.Percent)
	}
	if len(s.AntiVirusResults) != 1 || s.AntiVirusResults[0].ThreatFound != "Heuristic" {
		t.Errorf("AntiVirusResults = %+v", s.AntiVirusResults)
	}

	if convertScanners(nil) != nil {
		t.Error("convertScanners(nil) must stay nil so omitted data is omitted")
	}
}

// ---- no helper types beyond the above; the tests stay self-contained. ----

func TestGetQuickScanResultSuccess(t *testing.T) {
	// The official spec documents the success status of
	// GET /quick-scan/{id} as 201 despite the method being GET; both 201
	// and 200 are accepted. This endpoint is the documented mechanism for
	// obtaining final results after a `finished: false` submission.
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			rs := newRecordingServer(t, status, successfulBody, nil, 0)
			client, err := newTestClient(t, rs.URL, time.Second, 0)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			res, err := client.GetQuickScanResult(context.Background(), "qs-123")
			if err != nil {
				t.Fatalf("GetQuickScanResult: %v", err)
			}

			if rs.gotMethod != http.MethodGet {
				t.Errorf("method = %q, want GET", rs.gotMethod)
			}
			if rs.gotPath != "/quick-scan/qs-123" {
				t.Errorf("path = %q; the documented retrieval route", rs.gotPath)
			}
			if got := rs.gotHeaders.Get("api-key"); got != testKey {
				t.Errorf("api-key header = %q", got)
			}

			if res.ID != "qs-123" {
				t.Errorf("ID = %q", res.ID)
			}
			if !res.Finished {
				t.Error("Finished = false, want true")
			}
			// A retrieval carries no scan_type claim: the stored record
			// keeps its own.
			if res.ScanType != "" {
				t.Errorf("ScanType = %q, want empty", res.ScanType)
			}
			if res.ScannersV2 == nil {
				t.Error("ScannersV2 was not passed through")
			}
		})
	}
}

func TestGetQuickScanResultToleratesMissingID(t *testing.T) {
	// Retrieval already knows the identifier, so a response whose `id`
	// field is absent is parsed rather than discarded.
	rs := newRecordingServer(t, http.StatusCreated, `{"finished": true, "scanners": []}`, nil, 0)
	client, err := newTestClient(t, rs.URL, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := client.GetQuickScanResult(context.Background(), "qs-1")
	if err != nil {
		t.Fatalf("GetQuickScanResult: %v", err)
	}
	if res.ID != "" || !res.Finished {
		t.Errorf("result = %+v", res)
	}
}

func TestGetQuickScanResultRejectsBadSuccessResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"malformed json", `{"id": `},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRecordingServer(t, http.StatusOK, tc.body, nil, 0)
			client, err := newTestClient(t, rs.URL, time.Second, 0)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := client.GetQuickScanResult(context.Background(), "qs-1"); !errors.Is(err, ErrBadResponse) {
				t.Fatalf("err = %v, want ErrBadResponse", err)
			}
		})
	}
}

func TestGetQuickScanResultErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"unauthorized", http.StatusUnauthorized, ErrAuth},
		{"validation", http.StatusBadRequest, ErrValidation},
		{"not found", http.StatusNotFound, ErrValidation},
		{"server error", http.StatusInternalServerError, ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRecordingServer(t, tc.status, `{"message":"provider prose never reaches clients"}`, nil, 0)
			client, err := newTestClient(t, rs.URL, time.Second, 0)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = client.GetQuickScanResult(context.Background(), "qs-1")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "provider prose") {
				t.Errorf("the provider message leaked into the error: %v", err)
			}
		})
	}
}

func TestGetQuickScanResultRateLimitedCarriesRetryAfter(t *testing.T) {
	rs := newRecordingServer(t, http.StatusTooManyRequests, `{"message":"slow down"}`,
		func(h http.Header) { h.Set("Retry-After", "11") }, 0)
	client, err := newTestClient(t, rs.URL, time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = client.GetQuickScanResult(context.Background(), "qs-1")
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want a RateLimitError", err)
	}
	if rl.RetryAfter != 11*time.Second {
		t.Errorf("RetryAfter = %s, want 11s", rl.RetryAfter)
	}
}

func TestGetQuickScanResultRejectsEmptyID(t *testing.T) {
	client, err := newTestClient(t, "http://127.0.0.1:1", time.Second, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.GetQuickScanResult(context.Background(), "   "); !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestGetQuickScanResultOversizedBodyRejected(t *testing.T) {
	rs := newRecordingServer(t, http.StatusOK, strings.Repeat("x", 4096), nil, 0)
	client, err := newTestClient(t, rs.URL, time.Second, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = client.GetQuickScanResult(context.Background(), "qs-1")
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("err = %v, want ErrBadResponse", err)
	}
}
