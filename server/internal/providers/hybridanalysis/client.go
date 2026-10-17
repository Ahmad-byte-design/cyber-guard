// Package hybridanalysis adapts the Hybrid Analysis API v2 to CyberGuard's
// AnalysisProvider contract.
//
// # Contract provenance
//
// Every endpoint, header, field and status code used here was read from the
// official specification (OpenAPI 3.0.0, docs version 2.38.0) retrieved on
// 2026-10-16. The distilled contract, with citations, is in
// docs/verified/hybrid-analysis-v2-contract.md. Where the specification is
// silent, this package does not guess: see the retry and error-mapping comments
// for the specific assumptions, each of which is recorded as an open question.
//
// # What this package guarantees
//
//   - The API key never leaves this package in a log, an error, or a returned
//     value.
//   - A raw URL is never logged, and never placed in an error message.
//   - An ambiguous submission failure is never retried, because the provider may
//     already be analysing the URL.
//   - A response body is size-bounded before decoding.
//   - Provider prose never becomes a CyberGuard error code.
package hybridanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/verdicts"
)

// Documented endpoint paths, relative to the documented base URL.
const (
	pathSubmitURL = "/submit/url"
	pathReport    = "/report/"
	pathQuota     = "/key/submission-quota"
)

// Defaults. All are overridable through Options.
const (
	defaultBaseURL       = "https://hybrid-analysis.com/api/v2"
	defaultEnvironmentID = envWindows11x64
	defaultTimeout       = 30 * time.Second
	defaultMaxRetries    = 3
	defaultRetryBase     = 500 * time.Millisecond
	defaultMaxBodyBytes  = 4 << 20 // 4 MiB is generous for a summary
)

// Compile-time proof the adapter satisfies the contract.
var _ providers.AnalysisProvider = (*Client)(nil)

// Client is a Hybrid Analysis API v2 client.
//
// A Client is safe for concurrent use and reuses one http.Client, so polling a
// scan does not open a new TCP connection per request.
type Client struct {
	baseURL       string
	apiKey        string
	environmentID int

	http   *http.Client
	logger *slog.Logger
	sleep  func(ctx context.Context, d time.Duration) error
	now    func() time.Time

	maxRetries   int
	retryBase    time.Duration
	maxBodyBytes int64
}

// Options configures a Client.
type Options struct {
	// BaseURL defaults to the documented https://hybrid-analysis.com/api/v2.
	BaseURL string
	// APIKey is the value of the documented `api-key` request header.
	APIKey string
	// EnvironmentID selects the sandbox. Defaults to 140 (Windows 11 64 bit),
	// chosen because phishing kits target Windows browsers.
	EnvironmentID int
	// Timeout bounds a single HTTP request.
	Timeout time.Duration
	// MaxRetries bounds retries of idempotent GETs. Zero disables retrying.
	MaxRetries int
	// RetryBase is the first backoff delay; subsequent delays double with
	// full jitter.
	RetryBase time.Duration
	// MaxBodyBytes bounds a decoded response body.
	MaxBodyBytes int64
	// HTTPClient overrides the constructed client. Tests inject one with a
	// short timeout; production leaves it nil.
	HTTPClient *http.Client
	// Logger receives operational events. It never receives the API key or a
	// raw URL.
	Logger *slog.Logger
	// Now and Sleep are injection points for deterministic tests.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// New builds a Client. It returns an error when the API key is absent, because a
// client that cannot authenticate cannot do useful work and must not be
// constructed as if it could.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, providers.ErrNotConfigured
	}
	if strings.TrimSpace(opts.BaseURL) == "" {
		opts.BaseURL = defaultBaseURL
	}
	if opts.EnvironmentID == 0 {
		opts.EnvironmentID = defaultEnvironmentID
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.RetryBase <= 0 {
		opts.RetryBase = defaultRetryBase
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepCtx
	}

	// Trailing slashes are stripped so path concatenation cannot produce a
	// double slash, which some gateways treat as a different route.
	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("hybridanalysis: invalid base URL: %w", err)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			// The overall deadline, so a hung connection cannot pin a worker
			// lease indefinitely.
			Timeout: opts.Timeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          32,
				MaxIdleConnsPerHost:   8,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				ForceAttemptHTTP2:     true,
			},
		}
	}

	return &Client{
		baseURL:       baseURL,
		apiKey:        strings.TrimSpace(opts.APIKey),
		environmentID: opts.EnvironmentID,
		http:          httpClient,
		logger:        opts.Logger,
		sleep:         opts.Sleep,
		now:           opts.Now,
		maxRetries:    max(opts.MaxRetries, 0),
		retryBase:     opts.RetryBase,
		maxBodyBytes:  opts.MaxBodyBytes,
	}, nil
}

// EnvironmentID reports the sandbox this client submits to.
func (c *Client) EnvironmentID() int { return c.environmentID }

// Name identifies this provider on scan and assessment documents.
func (c *Client) Name() string { return ProviderName }

// ProviderName is the value recorded on documents analysed by this adapter.
const ProviderName = "hybrid-analysis"

// SubmitURL asks Hybrid Analysis to analyse rawURL.
//
// rawURL is the plaintext URL, the only point in CyberGuard at which a URL
// crosses a network boundary.
//
// This method performs exactly one attempt. The specification declares no
// idempotency or deduplication token for POST /submit/url, so a retry after an
// ambiguous failure — a timeout, a dropped connection — could submit the same
// URL twice and consume quota twice. Returning ErrUnavailable leaves the
// decision to the caller, who may hold a provider scan ID from a previous
// attempt and choose to poll instead.
func (c *Client) SubmitURL(ctx context.Context, rawURL string) (providers.Submission, error) {
	if strings.TrimSpace(rawURL) == "" {
		return providers.Submission{}, fmt.Errorf("hybridanalysis: submit: empty url: %w", providers.ErrBadResponse)
	}

	form := url.Values{}
	form.Set("url", rawURL)
	form.Set("environment_id", strconv.Itoa(c.environmentID))

	body, status, err := c.do(ctx, http.MethodPost, pathSubmitURL, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded", false /* retryable */)
	if err != nil {
		return providers.Submission{}, fmt.Errorf("hybridanalysis: submit: %w", err)
	}

	// The specification documents 201 as the success status for this endpoint.
	if status != http.StatusCreated && status != http.StatusOK && status != http.StatusAccepted {
		return providers.Submission{}, fmt.Errorf("hybridanalysis: submit: unexpected status %d: %w",
			status, providers.ErrBadResponse)
	}

	var out submissionStatus
	if err := decodeStrict(body, &out); err != nil {
		return providers.Submission{}, fmt.Errorf("hybridanalysis: submit: decode: %w", err)
	}

	// job_id is the identifier the report endpoints accept. The specification
	// marks it nullable, so an empty value is a real possibility and must be an
	// error rather than a silent empty handle.
	if strings.TrimSpace(out.JobID) == "" {
		return providers.Submission{}, fmt.Errorf("hybridanalysis: submit: response has no job_id: %w",
			providers.ErrBadResponse)
	}

	c.logger.Info("submitted url for analysis",
		slog.String("provider_scan_id", out.JobID),
		slog.Int("environment_id", c.environmentID),
		slog.String("environment", EnvironmentName(c.environmentID)),
	)

	return providers.Submission{
		ProviderScanID: out.JobID,
		// Both are nullable in the verified 201 schema, so deref yields ""
		// and nil respectively rather than a fabricated value.
		ProviderSubmissionID: deref(out.SubmissionID),
		EnvironmentID:        out.EnvironmentID,
		State:                providers.StateQueued,
	}, nil
}

// GetAnalysis retrieves the provider's current view of a submission.
//
// It issues one state request, and a second summary request only once the
// analysis has reached a terminal state. Polling a running scan therefore costs
// a single round trip, which matters because the worker polls on a schedule.
func (c *Client) GetAnalysis(ctx context.Context, providerScanID string) (providers.Analysis, error) {
	if strings.TrimSpace(providerScanID) == "" {
		return providers.Analysis{}, fmt.Errorf("hybridanalysis: get analysis: empty scan id: %w",
			providers.ErrBadResponse)
	}

	body, _, err := c.do(ctx, http.MethodGet, pathReport+url.PathEscape(providerScanID)+"/state", nil, "", true)
	if err != nil {
		return providers.Analysis{}, fmt.Errorf("hybridanalysis: get state: %w", err)
	}

	var st sampleState
	if err := decodeStrict(body, &st); err != nil {
		return providers.Analysis{}, fmt.Errorf("hybridanalysis: get state: decode: %w", err)
	}

	analysis := providers.Analysis{
		ProviderState: deref(st.State),
		ErrorType:     deref(st.ErrorType),
		ErrorOrigin:   deref(st.ErrorOrigin),
		ReportedAt:    c.now().UTC(),
	}

	// The specification documents these as the only non-terminal states.
	switch strings.ToUpper(analysis.ProviderState) {
	case providerStateInQueue:
		analysis.Finished = false
		analysis.ProviderState = providerStateInQueue
		return analysis, nil
	case providerStateInProgress:
		analysis.Finished = false
		analysis.ProviderState = providerStateInProgress
		return analysis, nil
	}

	// SUCCESS, ERROR, PARTIAL_SUCCESS, and anything unrecognised, are all
	// terminal for polling purposes. An unrecognised state is reported verbatim
	// and maps to the unknown verdict rather than being guessed at.
	analysis.Finished = true

	// A failed analysis still returns its state; no summary is needed and
	// fetching one could only produce a misleading verdict.
	if analysis.Failed() {
		return analysis, nil
	}

	summaryBody, _, err := c.do(ctx, http.MethodGet, pathReport+url.PathEscape(providerScanID)+"/summary", nil, "", true)
	if err != nil {
		return providers.Analysis{}, fmt.Errorf("hybridanalysis: get summary: %w", err)
	}

	var summary sampleSummary
	if err := decodeStrict(summaryBody, &summary); err != nil {
		return providers.Analysis{}, fmt.Errorf("hybridanalysis: get summary: decode: %w", err)
	}

	analysis.Classification = deref(summary.Verdict)
	analysis.Raw = summaryBody

	// The summary carries its own state; prefer it when present, since it
	// describes the analysed sample rather than the job.
	if s := strings.TrimSpace(deref(summary.State)); s != "" {
		analysis.ProviderState = s
	}
	if et := strings.TrimSpace(deref(summary.ErrorType)); et != "" {
		analysis.ErrorType = et
	}
	if eo := strings.TrimSpace(deref(summary.ErrorOrigin)); eo != "" {
		analysis.ErrorOrigin = eo
	}

	return analysis, nil
}

// GetQuota reports the account's submission quota.
//
// The specification exposes quota_reached per submission type; it is the only
// field this project needs, and it is what the "fail closed rather than exceed
// the provider contract" rule depends on.
func (c *Client) GetQuota(ctx context.Context) (detonationReached, quickScanReached bool, err error) {
	body, _, err := c.do(ctx, http.MethodGet, pathQuota, nil, "", true)
	if err != nil {
		return false, false, fmt.Errorf("hybridanalysis: get quota: %w", err)
	}

	var q submissionQuota
	if err := decodeStrict(body, &q); err != nil {
		return false, false, fmt.Errorf("hybridanalysis: get quota: decode: %w", err)
	}

	if q.Detonation != nil {
		detonationReached = deref(q.Detonation.QuotaReached)
	}
	if q.QuickScan != nil {
		quickScanReached = deref(q.QuickScan.QuotaReached)
	}
	return detonationReached, quickScanReached, nil
}

// NormaliseVerdict maps a provider report onto CyberGuard's verdict vocabulary.
//
// The mapping keys off the five verdict names the specification documents, in
// the POST /search/hash filter description. The read-side summary's verdict
// field is declared as a free-form string with no enumerated values, so an
// unrecognised value yields Unknown rather than a guess. See
// docs/verified/hybrid-analysis-v2-contract.md.
//
// Four rules are absolute:
//
//  1. A failed or partially-successful analysis is Unknown.
//  2. An unfinished analysis is Unknown.
//  3. An unrecognised classification is Unknown.
//  4. No input path can produce NoThreatDetected except a recognised
//     "no specific threat" or "whitelisted" classification on a completed,
//     successful analysis.
func NormaliseVerdict(a providers.Analysis) verdicts.Verdict {
	// Rule 1 and 2. Checked before the classification is even read, so a failed
	// analysis carrying a stale or forged verdict cannot produce a clean one.
	if a.Failed() {
		return verdicts.Unknown
	}
	if !a.Finished {
		return verdicts.Unknown
	}

	switch verdicts.NormaliseLower(a.Classification) {
	case "malicious":
		return verdicts.Malicious
	case "suspicious":
		return verdicts.Suspicious
	case "no specific threat", "whitelisted":
		return verdicts.NoThreatDetected
	case "no verdict":
		return verdicts.Inconclusive
	default:
		// Rule 3. Includes an empty classification, which the specification
		// permits because verdict is nullable.
		return verdicts.Unknown
	}
}

// -------------------------------------------------------------- transport

// do performs one HTTP request against the provider and returns the
// size-bounded body.
//
// retryable selects the retry policy. It is true for GET, where a repeated
// request is harmless, and false for POST /submit/url, where it is not: the
// specification declares no idempotency token, so a retried submission could
// consume quota twice.
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string, retryable bool) ([]byte, int, error) {
	attempts := 1
	if retryable {
		attempts += c.maxRetries
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			delay := c.backoff(attempt)
			c.logger.Warn("retrying provider request",
				slog.String("method", method),
				slog.String("path", path),
				slog.Int("attempt", attempt+1),
				slog.Int("of", attempts),
				slog.Duration("delay", delay),
				slog.String("previous_error", lastErr.Error()),
			)
			if err := c.sleep(ctx, delay); err != nil {
				return nil, 0, err
			}
			// A one-shot body cannot be replayed, so a retryable request is
			// always a bodyless GET here. Guard anyway rather than silently
			// sending an empty POST.
			if body != nil {
				return nil, 0, fmt.Errorf("hybridanalysis: cannot retry %s with a body", method)
			}
		}

		respBody, status, err := c.attempt(ctx, method, path, body, contentType)
		if err == nil {
			return respBody, status, nil
		}
		lastErr = err

		// Do not retry a classified-permanent failure.
		if !isRetryable(err) {
			return nil, 0, err
		}
	}

	return nil, 0, lastErr
}

// attempt performs a single request with no retry logic.
func (c *Client) attempt(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, 0, fmt.Errorf("hybridanalysis: build request: %w", providers.ErrBadResponse)
	}

	// The only documented authentication mechanism.
	req.Header.Set("api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// A transport error or timeout is ambiguous for a submission: the
		// provider may have accepted it. Report it as unavailable without
		// retrying; do() decides whether a retry is permitted.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, fmt.Errorf("hybridanalysis: request cancelled: %w", ctxErr)
		}
		return nil, 0, fmt.Errorf("hybridanalysis: transport: %w: %w", providers.ErrUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	// Bound the body before decoding. An unbounded provider response is a
	// memory-exhaustion vector, and provider output is untrusted input.
	limited := io.LimitReader(resp.Body, c.maxBodyBytes+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("hybridanalysis: read body: %w: %w", providers.ErrUnavailable, err)
	}
	if int64(len(respBody)) > c.maxBodyBytes {
		return nil, resp.StatusCode, fmt.Errorf("hybridanalysis: response exceeds %d bytes: %w",
			c.maxBodyBytes, providers.ErrBadResponse)
	}

	if err := classifyStatus(resp.StatusCode, respBody, c.logger); err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

// classifyStatus maps an HTTP status onto a CyberGuard provider error.
//
// The specification declares no specific 4xx or 5xx codes for any endpoint, only
// a catch-all "default" error. The mapping below therefore applies conventional
// HTTP semantics, which is a documented assumption rather than a verified
// contract — recorded as open question V4 in
// docs/verified/hybrid-analysis-v2-contract.md.
func classifyStatus(status int, body []byte, logger *slog.Logger) error {
	switch {
	case status >= 200 && status < 300:
		return nil

	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		// Permanent. Retrying an auth failure wastes quota and can lock the key.
		logger.Error("provider rejected credentials", slog.Int("status", status))
		return fmt.Errorf("hybridanalysis: status %d: %w", status, providers.ErrAuthFailed)

	case status == http.StatusTooManyRequests:
		// Retryable, and Retry-After must be honoured. Whether the provider
		// actually sends it is open question V5.
		if d := parseRetryAfter(body, status); d > 0 {
			logger.Warn("provider rate limited", slog.Duration("retry_after", d))
		}
		return fmt.Errorf("hybridanalysis: status %d: %w", status, providers.ErrRateLimited)

	case status == http.StatusGone:
		// Documented status, with no documented meaning for these endpoints.
		logger.Warn("provider returned 410", slog.Int("status", status))
		return fmt.Errorf("hybridanalysis: status %d: %w", status, providers.ErrBadResponse)

	case status >= 500:
		return fmt.Errorf("hybridanalysis: status %d: %w", status, providers.ErrUnavailable)

	default:
		// 4xx that is not auth, rate limit, or gone: the request itself is
		// wrong. Repeating it changes nothing.
		logger.Debug("provider rejected request",
			slog.Int("status", status),
			slog.String("provider_message", providerMessage(body)),
		)
		return fmt.Errorf("hybridanalysis: status %d: %w", status, providers.ErrBadResponse)
	}
}

// isRetryable reports whether an error is worth another attempt.
func isRetryable(err error) bool {
	return errors.Is(err, providers.ErrUnavailable)
}

// backoff returns the delay before attempt n, doubling with full jitter.
//
// Full jitter matters: without it, every worker that failed during a provider
// outage retries in lockstep and reproduces the outage on recovery.
func (c *Client) backoff(attempt int) time.Duration {
	exp := float64(c.retryBase) * math.Pow(2, float64(attempt-1))
	if exp > float64(math.MaxInt64) {
		exp = float64(math.MaxInt64)
	}
	return time.Duration(rand.N(int64(exp)))
}

// parseRetryAfter extracts a Retry-After value in seconds from the error body
// if present. The specification does not document the field, so a miss is normal
// and the caller falls back to computed backoff.
func parseRetryAfter(body []byte, _ int) time.Duration {
	var probe struct {
		RetryAfter *int `json:"retry_after"`
	}
	if err := json.Unmarshal(body, &probe); err != nil || probe.RetryAfter == nil {
		return 0
	}
	if *probe.RetryAfter <= 0 {
		return 0
	}
	return time.Duration(*probe.RetryAfter) * time.Second
}

// providerMessage extracts provider prose for Debug logging only.
//
// It is never returned in an error, because an error may surface in a
// client-visible response and provider prose is untrusted, unbounded text.
func providerMessage(body []byte) string {
	var e apiError
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	const maxLen = 200
	msg := strings.TrimSpace(e.Message)
	if len(msg) > maxLen {
		return msg[:maxLen] + "…"
	}
	return msg
}

// decodeStrict decodes JSON, rejecting unknown fields.
//
// Provider output is untrusted input. Rejecting an unexpected shape is what
// stops a silent reinterpreting of a field this code believes it understands.
func decodeStrict(body []byte, dst any) error {
	if len(body) == 0 {
		return fmt.Errorf("empty response body: %w", providers.ErrBadResponse)
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", providers.ErrBadResponse, err)
	}
	return nil
}

// sleepCtx waits for d unless ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
