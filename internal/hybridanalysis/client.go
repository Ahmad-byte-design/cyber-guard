// Package hybridanalysis is the CyberGuard adapter for the Hybrid Analysis
// API v2.
//
// Scope is deliberately two documented endpoints, both in the "Quick Scan"
// group:
//
//   - POST /quick-scan/url — submit a URL for scanning.
//   - GET /quick-scan/{id} — retrieve the scan's updated results. The official
//     specification states: "some scanners need time to process file, if in
//     response `finished` is set to false, then you need use this endpoint to
//     get final results". This is the minimum documented mechanism for turning
//     a pending submission into a real verdict.
//
// Nothing else is called — no quota probes, no search, no feeds.
//
// Contract provenance: every field, header and status below was read from the
// official OpenAPI 3.0.0 document (https://hybrid-analysis.com/bff/api-docs/v2,
// retrieved 2026-10-17). Where the document is silent — error status codes —
// conventional HTTP semantics are applied and stated as such.
//
// This package guarantees:
//
//   - The API key never appears in a log line, an error message, or any value
//     returned to a caller.
//   - A raw URL is never logged.
//   - A submission is never retried: the endpoint declares no idempotency
//     token, so an ambiguous failure may already have been accepted upstream.
//     Result retrieval is a read; it is safe to call again, and the service
//     layer uses its own poll loop instead of retries inside this package.
//   - Response bodies are size-bounded before decoding.
//   - Provider prose is logged at debug level only, never returned to clients.
package hybridanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cyberguard/internal/models"
)

// The two documented endpoints this service calls, relative to the base URL.
const (
	pathQuickScanURL = "/quick-scan/url"
	pathQuickScanID  = "/quick-scan/"
)

// Defaults applied when an Options field is zero.
const (
	defaultBaseURL  = "https://hybrid-analysis.com/api/v2"
	defaultTimeout  = 30 * time.Second
	defaultScanType = "all"
	// maxBodyBytes bounds a decoded provider body. A quick-scan response is
	// a few kilobytes; 2 MiB leaves room for verbose scanner payloads while
	// keeping an unbounded provider response from becoming an exhaustion
	// vector.
	defaultMaxBodyBytes = 2 << 20
)

// Provider error classes. Callers branch on these; none carries upstream text.
var (
	// ErrNotConfigured means no API key is available at all.
	ErrNotConfigured = errors.New("hybridanalysis: provider is not configured")
	// ErrAuth is a permanent credential rejection (401/403). Never retried.
	ErrAuth = errors.New("hybridanalysis: the provider rejected the configured API key")
	// ErrRateLimited is a 429 from the provider.
	ErrRateLimited = errors.New("hybridanalysis: the provider rate limited the request")
	// ErrTimeout is a request that exceeded its deadline.
	ErrTimeout = errors.New("hybridanalysis: the provider request timed out")
	// ErrUnavailable is a transient provider failure (network error, 5xx).
	ErrUnavailable = errors.New("hybridanalysis: the provider is unavailable")
	// ErrValidation is a 4xx other than auth or rate limit: the provider
	// considered the request itself unacceptable.
	ErrValidation = errors.New("hybridanalysis: the provider rejected the request")
	// ErrBadResponse is a malformed, oversized or incomplete provider response.
	ErrBadResponse = errors.New("hybridanalysis: unexpected provider response")
)

// RateLimitError carries the provider's Retry-After, when it sent one, so the
// API layer can pass the same hint to its own clients.
type RateLimitError struct {
	RetryAfter time.Duration
	Err        error
}

func (e *RateLimitError) Error() string { return e.Err.Error() }
func (e *RateLimitError) Unwrap() error { return e.Err }

// Client is a Hybrid Analysis API v2 client scoped to the quick scan.
//
// A Client is safe for concurrent use and reuses one http.Client.
type Client struct {
	baseURL      string
	apiKey       string
	scanType     string
	maxBodyBytes int64
	http         *http.Client
	logger       *slog.Logger
}

// Options configures a Client.
type Options struct {
	// BaseURL defaults to the host the official specification declares.
	BaseURL string
	// APIKey is the value of the documented `api-key` request header.
	APIKey string
	// ScanType is the required documented `scan_type` form field.
	ScanType string
	// Timeout bounds a single HTTP request, including the response body.
	Timeout time.Duration
	// MaxBodyBytes bounds a decoded response body.
	MaxBodyBytes int64
	// HTTPClient overrides the constructed client. Tests inject one; the
	// default transport is never exercised in tests.
	HTTPClient *http.Client
	// Logger receives operational events. It never receives the API key or a
	// submitted URL.
	Logger *slog.Logger
}

// New builds a Client. It refuses an empty API key: a client that cannot
// authenticate must not be constructed as if it could.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, ErrNotConfigured
	}
	if opts.BaseURL == "" {
		opts.BaseURL = defaultBaseURL
	}
	if opts.ScanType == "" {
		opts.ScanType = defaultScanType
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	// Trailing slashes are trimmed so path concatenation cannot produce a
	// double slash, which some gateways treat as a different route.
	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("hybridanalysis: invalid base URL: %w", err)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			// The overall deadline, so a hung provider connection cannot pin
			// a request handler indefinitely.
			Timeout: opts.Timeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          16,
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				ForceAttemptHTTP2:     true,
			},
		}
	}

	return &Client{
		baseURL:      baseURL,
		apiKey:       strings.TrimSpace(opts.APIKey),
		scanType:     opts.ScanType,
		maxBodyBytes: opts.MaxBodyBytes,
		http:         httpClient,
		logger:       opts.Logger,
	}, nil
}

// ScanType reports the documented scan_type this client submits with.
func (c *Client) ScanType() string { return c.scanType }

// Result is the parsed outcome of a quick scan submission or retrieval.
type Result struct {
	// ID is the provider-issued quick scan identifier.
	ID string
	// SHA256 is the provider-reported digest, when reported.
	SHA256 string
	// ScanType is the documented `scan_type` value the submission used.
	// Empty for retrieved results; the stored record keeps its own.
	ScanType string
	// Finished is the provider's own completion flag.
	Finished bool
	// Scanners is the provider's deprecated `scanners` array, when sent.
	Scanners []models.Scanner
	// ScannersV2 is the provider's `scanners_v2` object, decoded into a
	// generic map for passthrough storage. Nil when not sent.
	ScannersV2 map[string]any
	// Reports is the provider's report reference list, when sent.
	Reports []string
}

// QuickScanURL submits rawURL to POST /quick-scan/url and returns whatever
// the provider reported.
//
// Exactly one attempt is made. The endpoint declares no idempotency token, so
// a retry after an ambiguous failure — a timeout, a dropped connection — could
// submit the same URL twice; the caller decides what to do with the error
// instead of this package guessing.
//
// A `finished: true` response means every selected scanner completed and the
// per-scanner data is final. A `finished: false` response is a real,
// successful submission whose scans are still running — it is reported as
// pending, never as a completed result.
func (c *Client) QuickScanURL(ctx context.Context, rawURL string) (Result, error) {
	if strings.TrimSpace(rawURL) == "" {
		return Result{}, fmt.Errorf("hybridanalysis: submit: empty url: %w", ErrValidation)
	}

	form := url.Values{}
	form.Set("scan_type", c.scanType)
	form.Set("url", rawURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+pathQuickScanURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, fmt.Errorf("hybridanalysis: build request: %w", ErrBadResponse)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return c.do(ctx, req, "submit", c.scanType, true)
}

// GetQuickScanResult retrieves the current state of a quick scan through
// GET /quick-scan/{id} and returns whatever the provider reported.
//
// This is the documented endpoint for obtaining final results after a
// submission answered `finished: false`. Retrieval is read-only, so — unlike
// submission — calling it again cannot duplicate anything; the service layer
// decides whether repeated retrieval is worth an API request.
func (c *Client) GetQuickScanResult(ctx context.Context, quickScanID string) (Result, error) {
	quickScanID = strings.TrimSpace(quickScanID)
	if quickScanID == "" {
		return Result{}, fmt.Errorf("hybridanalysis: retrieve: empty id: %w", ErrValidation)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+pathQuickScanID+url.PathEscape(quickScanID), nil)
	if err != nil {
		return Result{}, fmt.Errorf("hybridanalysis: build request: %w", ErrBadResponse)
	}

	// The exact provider identifier was already verified when it was stored,
	// so an absent `id` field in the response body is tolerated here.
	return c.do(ctx, req, "retrieve", "", false)
}

// do sends one request and classifies the response.
//
// The documented authentication header is `api-key` on every call, per the
// specification's security scheme. The four response families below match both
// documented endpoints; anything the specification leaves as `default` falls
// into the final 4xx case.
//
// scanType is stamped onto a successful submission response ("all", say — the
// provider response itself carries no scan_type field) and empty for
// retrievals, whose records keep their own scan type.
// requireID reports whether a missing `id` field is a failure: a submission
// cannot proceed without one, while a retrieval already knows the identifier.
func (c *Client) do(ctx context.Context, req *http.Request, op, scanType string, requireID bool) (Result, error) {
	// The documented authentication header and content negotiation.
	req.Header.Set("api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// For submissions a timeout is ambiguous (the scan may have been
		// accepted); retrieval is a read, so its timeout is reported as a
		// timeout through the same class either way.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, fmt.Errorf("hybridanalysis: %s: %w: %w", op, ErrTimeout, ctxErr)
		}
		if isTimeout(err) {
			return Result{}, fmt.Errorf("hybridanalysis: %s: %w", op, ErrTimeout)
		}
		return Result{}, fmt.Errorf("hybridanalysis: %s: %w: %w", op, ErrUnavailable, err)
	}
	defer func() {
		// Drain a bounded remainder so the connection can be reused, then
		// close. Provider output is untrusted; it is never parsed here.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodyBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("hybridanalysis: %s: read body: %w: %w", op, ErrUnavailable, err)
	}
	if int64(len(body)) > c.maxBodyBytes {
		return Result{}, fmt.Errorf("hybridanalysis: %s: response exceeds %d bytes: %w",
			op, c.maxBodyBytes, ErrBadResponse)
	}

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		// The specification documents the success status of
		// GET /quick-scan/{id} as 201 despite the method being GET, so both
		// 200 and 201 are accepted.
		result, err := parseResult(body, scanType, requireID)
		if err != nil {
			return Result{}, err
		}
		c.logger.Debug("quick scan response",
			slog.String("operation", op),
			slog.String("provider_scan_id", result.ID),
			slog.Bool("finished", result.Finished),
		)
		return result, nil

	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// Permanent. Retrying an auth failure can lock the key.
		c.logger.Error("provider rejected credentials", slog.Int("status", resp.StatusCode))
		return Result{}, fmt.Errorf("hybridanalysis: %s: status %d: %w", op, resp.StatusCode, ErrAuth)

	case resp.StatusCode == http.StatusTooManyRequests:
		c.logger.Warn("provider rate limited the request", slog.Int("status", resp.StatusCode))
		rerr := fmt.Errorf("hybridanalysis: %s: status %d: %w", op, resp.StatusCode, ErrRateLimited)
		return Result{}, &RateLimitError{RetryAfter: retryAfter(resp.Header), Err: rerr}

	case resp.StatusCode >= 500:
		c.logger.Warn("provider unavailable", slog.Int("status", resp.StatusCode))
		return Result{}, fmt.Errorf("hybridanalysis: %s: status %d: %w", op, resp.StatusCode, ErrUnavailable)

	case resp.StatusCode == http.StatusGone:
		// Documented status with no documented meaning here; treated as a
		// bad response rather than guessed at.
		c.logger.Warn("provider returned 410", slog.Int("status", resp.StatusCode))
		return Result{}, fmt.Errorf("hybridanalysis: %s: status %d: %w", op, resp.StatusCode, ErrBadResponse)

	default:
		// Every other 4xx: the request itself was rejected (validation,
		// unsupported parameters, an unknown scan id, anything the spec
		// leaves as `default`).
		c.logger.Debug("provider rejected the request",
			slog.Int("status", resp.StatusCode),
			slog.String("provider_message", providerMessage(body)),
		)
		return Result{}, fmt.Errorf("hybridanalysis: %s: status %d: %w", op, resp.StatusCode, ErrValidation)
	}
}

// parseResult decodes a successful response body.
//
// Decoding is tolerant: the provider marks most fields nullable, so an absent
// field is "not reported", not a failure. The one field this service cannot
// proceed without on submission is `id` — without it there is no handle on the
// scan, and silently storing an unnamed scan would be a fabrication.
//
// scanType is the documented value the submission was sent with: the
// provider's quick-scan response carries no scan_type field, so the truth
// about what was requested can only come from the caller. It is empty for
// retrieved results.
func parseResult(body []byte, scanType string, requireID bool) (Result, error) {
	if len(body) == 0 {
		return Result{}, fmt.Errorf("hybridanalysis: empty response body: %w", ErrBadResponse)
	}

	var wire quickScan
	if err := json.Unmarshal(body, &wire); err != nil {
		return Result{}, fmt.Errorf("hybridanalysis: decode: %w: %w", ErrBadResponse, err)
	}

	id := strings.TrimSpace(wire.ID)
	if id == "" && requireID {
		return Result{}, fmt.Errorf("hybridanalysis: response has no id: %w", ErrBadResponse)
	}

	result := Result{
		ID:       id,
		SHA256:   strings.TrimSpace(deref(wire.SHA256)),
		ScanType: scanType,
		Finished: wire.Finished,
		Scanners: convertScanners(wire.Scanners),
		Reports:  wire.Reports,
	}
	if len(wire.ScannersV2) > 0 {
		var v2 map[string]any
		if err := json.Unmarshal(wire.ScannersV2, &v2); err == nil && v2 != nil {
			result.ScannersV2 = v2
		}
	}
	return result, nil
}

// isTimeout reports whether err is a deadline or timeout failure.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// retryAfter reads the Retry-After header in seconds; absent or invalid means
// zero and the caller falls back to no hint.
func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	sec, err := strconv.Atoi(v)
	if err != nil || sec <= 0 {
		return 0
	}
	return time.Duration(sec) * time.Second
}

// providerMessage extracts provider prose for debug logging only. It is never
// returned in an error: provider text is untrusted and unbounded, and error
// strings can reach client-visible responses.
func providerMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	msg := strings.TrimSpace(e.Message)
	const maxLen = 200
	if len(msg) > maxLen {
		return msg[:maxLen] + "…"
	}
	return msg
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
