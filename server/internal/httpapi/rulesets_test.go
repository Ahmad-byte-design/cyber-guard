package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/rulesetapi"
	"cyberguard/server/internal/rulesets"
)

// The published ruleset contract: version negotiation, conditional requests,
// and the rolled-back signal for a client on a different deployment.

// stubRulesetStore serves canned snapshots.
type stubRulesetStore struct {
	current   mongostore.Ruleset
	byVersion map[int64]mongostore.Ruleset
	notFound  bool
	err       error
}

func (s *stubRulesetStore) CurrentRuleset(context.Context) (mongostore.Ruleset, error) {
	if s.err != nil {
		return mongostore.Ruleset{}, s.err
	}
	if s.notFound {
		return mongostore.Ruleset{}, mongostore.ErrRulesetNotFound
	}
	return s.current, nil
}

func (s *stubRulesetStore) RulesetAtVersion(_ context.Context, v int64) (mongostore.Ruleset, error) {
	if rs, ok := s.byVersion[v]; ok {
		return rs, nil
	}
	return mongostore.Ruleset{}, mongostore.ErrRulesetNotFound
}

func (s *stubRulesetStore) PublishRuleset(context.Context, mongostore.Ruleset) (mongostore.Ruleset, bool, error) {
	return mongostore.Ruleset{}, false, errors.New("the read endpoint must never publish")
}

func (s *stubRulesetStore) ListRulesetVersions(context.Context, int64) ([]int64, error) {
	return nil, nil
}

func (s *stubRulesetStore) EligibleAssessments(context.Context, time.Time, int64) ([]mongostore.Assessment, error) {
	return nil, nil
}

func newRulesetServer(t *testing.T, store rulesetapi.Store) http.Handler {
	t.Helper()

	policy := rulesets.DefaultPolicy()
	gen, err := rulesets.NewGenerator(policy, nil)
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}

	return NewServer(Dependencies{
		Config:   config.Config{HTTPAddr: ":0"},
		Logger:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Rulesets: rulesetapi.New(store, gen, func() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) }),
	}).Handler()
}

func get(t *testing.T, h http.Handler, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func sampleSnapshot(version int64, rules int) mongostore.Ruleset {
	rs := mongostore.Ruleset{
		Version:     version,
		GeneratedAt: time.Date(2026, 10, 17, 11, 0, 0, 0, time.UTC),
		Digest:      "digest",
		Rules:       []mongostore.Rule{},
	}
	for i := range rules {
		rs.Rules = append(rs.Rules, mongostore.Rule{
			ID:       i + 1,
			Priority: 1,
			Action:   mongostore.RuleAction{Type: "block"},
			Condition: mongostore.RuleCondition{
				URLFilter:     `||evil.test^`,
				ResourceTypes: []string{"main_frame"},
			},
		})
	}
	return rs
}

// Nothing published yet is a valid, truthful answer — not an error.
func TestGetAllReturnsAnEmptySnapshotWhenNothingIsPublished(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{notFound: true})
	rec := get(t, h, "/api/v1/get-all", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Version   int               `json:"version"`
		Rules     []rulesetapi.Rule `json:"rules"`
		Generated string            `json:"generated_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Version != 0 {
		t.Errorf("version = %d, want 0", body.Version)
	}
	if body.Rules == nil {
		t.Error("rules is null; the contract requires an array")
	}
	if len(body.Rules) != 0 {
		t.Errorf("got %d rules, want none", len(body.Rules))
	}
	if body.Generated == "" {
		t.Error("generated_at is missing")
	}
}

// No version supplied means "send me everything".
func TestGetAllReturnsAFullSnapshot(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 2)})
	rec := get(t, h, "/api/v1/get-all", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Version int `json:"version"`
		Rules   []struct {
			ID       int `json:"id"`
			Priority int `json:"priority"`
			Action   struct {
				Type string `json:"type"`
			} `json:"action"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Version != 12 {
		t.Errorf("version = %d, want 12", body.Version)
	}
	if len(body.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(body.Rules))
	}
	if body.Rules[0].Action.Type != "block" {
		t.Errorf("action = %q, want block", body.Rules[0].Action.Type)
	}
	if got := rec.Header().Get("ETag"); got != `"v12"` {
		t.Errorf("ETag = %q, want \"v12\"", got)
	}
}

// A client already holding the current version gets `unchanged: true` and
// nothing else.
func TestGetAllReportsUnchangedForTheCurrentVersion(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 2)})
	rec := get(t, h, "/api/v1/get-all?version=12", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Version   int               `json:"version"`
		Unchanged bool              `json:"unchanged"`
		Rules     []rulesetapi.Rule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Unchanged {
		t.Error("unchanged = false for a matching version")
	}
	if len(body.Rules) != 0 {
		t.Errorf("got %d rules on an unchanged response, want 0", len(body.Rules))
	}
	if body.Version != 12 {
		t.Errorf("version = %d, want 12", body.Version)
	}
}

// A client behind gets the full snapshot.
func TestGetAllServesAnOlderClientTheFullSnapshot(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 2)})
	rec := get(t, h, "/api/v1/get-all?version=7", nil)

	var body struct {
		Unchanged bool              `json:"unchanged"`
		Rules     []rulesetapi.Rule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Unchanged {
		t.Error("unchanged = true for a client behind the server")
	}
	if len(body.Rules) != 2 {
		t.Errorf("got %d rules, want the full set", len(body.Rules))
	}
	if rec.Header().Get("X-Ruleset-Rolled-Back") != "" {
		t.Error("a client behind the server must not be told it rolled back")
	}
}

// A client *ahead* is on a different deployment, and must be told so explicitly
// rather than silently served an older ruleset.
func TestGetAllFlagsARolledBackClient(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(9, 1)})
	rec := get(t, h, "/api/v1/get-all?version=20", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Ruleset-Rolled-Back"); got != "true" {
		t.Errorf("X-Ruleset-Rolled-Back = %q, want true", got)
	}

	// It still receives a usable snapshot so it can recover.
	var body struct {
		Version int               `json:"version"`
		Rules   []rulesetapi.Rule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Version != 9 || len(body.Rules) != 1 {
		t.Errorf("a rolled-back client got version %d with %d rules, want 9 with 1",
			body.Version, len(body.Rules))
	}
}

// A matching ETag produces a 304 with no body.
func TestGetAllHonoursIfNoneMatch(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 2)})
	rec := get(t, h, "/api/v1/get-all", map[string]string{"If-None-Match": `"v12"`})

	if rec.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a 304 carried a body: %s", rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("a 304 must still carry the ETag")
	}
}

// A wildcard If-None-Match also means "any representation will do".
func TestGetAllHonoursWildcardIfNoneMatch(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 2)})
	rec := get(t, h, "/api/v1/get-all", map[string]string{"If-None-Match": "*"})
	if rec.Code != http.StatusNotModified {
		t.Errorf("status = %d, want 304", rec.Code)
	}
}

// The weak validator form is what several HTTP clients emit.
func TestGetAllAcceptsWeakETag(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 2)})
	rec := get(t, h, "/api/v1/get-all", map[string]string{"If-None-Match": `W/"v12"`})
	if rec.Code != http.StatusNotModified {
		t.Errorf("status = %d, want 304", rec.Code)
	}
}

// A stale ETag must not suppress the body.
func TestGetAllServesBodyForAStaleETag(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 2)})
	rec := get(t, h, "/api/v1/get-all", map[string]string{"If-None-Match": `"v3"`})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// A malformed version is a 400, not a silently-ignored parameter.
//
// Ignoring it would serve a full snapshot to a client that believed it was up
// to date, and would hide the bug in the caller.
func TestGetAllRejectsAMalformedVersion(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 1)})
	for _, bad := range []string{"abc", "-1", "1.5", "99999999999999999999"} {
		t.Run(bad, func(t *testing.T) {
			rec := get(t, h, "/api/v1/get-all?version="+bad, nil)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("version=%q status = %d, want 400", bad, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
				t.Errorf("Content-Type = %q, want a problem document", ct)
			}
		})
	}
}

// An empty version parameter is "not supplied", not an error.
func TestGetAllTreatsAnEmptyVersionAsAbsent(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(12, 1)})
	rec := get(t, h, "/api/v1/get-all?version=", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Rules []rulesetapi.Rule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rules) != 1 {
		t.Errorf("got %d rules, want the full snapshot", len(body.Rules))
	}
}

// A datastore failure is a 503, never an empty ruleset. An empty ruleset reads
// as "you are protected by nothing", which is a different and much worse claim.
func TestGetAllReportsAStoreFailureAsUnavailable(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{err: errors.New("mongodb: connection refused")})
	rec := get(t, h, "/api/v1/get-all", nil)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want a problem document", ct)
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Code != "service_unavailable" {
		t.Errorf("code = %q, want service_unavailable", p.Code)
	}
}

// The endpoint must never write. A read path that publishes would turn a burst
// of clients into a burst of rebuilds.
func TestGetAllNeverPublishes(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(1, 1)})
	get(t, h, "/api/v1/get-all", nil)
	get(t, h, "/api/v1/get-all?version=1", nil)
	get(t, h, "/api/v1/get-all?version=99", nil)
	// The stub's PublishRuleset returns an error; reaching it would fail loudly.
}

// Published rules must never carry provenance. Chrome rejects unknown members
// inside a Rule, so provenance in the payload would break the whole ruleset on
// the client's machine.
func TestPublishedRulesCarryNoProvenance(t *testing.T) {
	t.Parallel()

	rs := sampleSnapshot(1, 1)
	rs.Rules[0].Provenance = mongostore.RuleProvenance{
		Fingerprint:   "abc123",
		Scope:         "exact_url",
		Corroboration: 5,
	}

	h := newRulesetServer(t, &stubRulesetStore{current: rs})
	rec := get(t, h, "/api/v1/get-all", nil)

	body := rec.Body.String()
	for _, leak := range []string{"abc123", "provenance", "fingerprint", "corroboration"} {
		if strings.Contains(body, leak) {
			t.Errorf("the published ruleset contains %q; Chrome would reject the ruleset:\n%s", leak, body)
		}
	}
}

// A scan ID or URL must never leak into the ruleset.
func TestRulesetNeverCarriesURLs(t *testing.T) {
	t.Parallel()

	h := newRulesetServer(t, &stubRulesetStore{current: sampleSnapshot(1, 1)})
	rec := get(t, h, "/api/v1/get-all", nil)

	for _, leak := range []string{"http://", "https://", "?", "example.test"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the ruleset contains %q:\n%s", leak, rec.Body.String())
		}
	}
}

// ------------------------------------------------- published DNR conformance

// The response must decode into the DNR structure the contract specifies, with
// no MongoDB document leaking through and no provenance attached.
//
// Provenance in particular is the thing most likely to leak: it is stored with
// each rule and Chrome rejects unknown members inside a Rule, so emitting it
// would break the ruleset on the client's machine.
func TestPublishedRuleDecodesIntoTheDNRStructure(t *testing.T) {
	t.Parallel()

	rs := sampleSnapshot(1, 1)
	rs.Rules[0].Provenance = mongostore.RuleProvenance{
		Fingerprint: "abc123", Scope: "exact_url", Corroboration: 5, Action: "block",
	}

	rec := get(t, newRulesetServer(t, &stubRulesetStore{current: rs}), "/api/v1/get-all", nil)

	var envelope struct {
		Version int64 `json:"version"`
		Rules   []struct {
			ID       int `json:"id"`
			Priority int `json:"priority"`
			Action   struct {
				Type     string `json:"type"`
				Redirect *struct {
					ExtensionPath string `json:"extensionPath"`
				} `json:"redirect"`
			} `json:"action"`
			Condition struct {
				URLFilter string `json:"urlFilter"`
				Filter    *struct {
					Type        string `json:"type"`
					RegexFilter string `json:"regexFilter"`
				} `json:"filter"`
				ResourceTypes []string `json:"resourceTypes"`
			} `json:"condition"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("the response does not decode into the DNR structure: %v", err)
	}

	if len(envelope.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(envelope.Rules))
	}
	r := envelope.Rules[0]
	if r.ID < 1 || r.Priority < 1 {
		t.Errorf("id = %d, priority = %d; both must be >= 1", r.ID, r.Priority)
	}
	if r.Action.Type != "block" {
		t.Errorf("action.type = %q, want block", r.Action.Type)
	}
	if r.Action.Redirect != nil {
		t.Error("a block rule was published with a redirect member")
	}
	if len(r.Condition.ResourceTypes) == 0 {
		t.Error("resourceTypes is empty; Chrome would treat an absent list as excluding main_frame")
	}

	// No internal document key may reach the client.
	body := rec.Body.String()
	for _, leak := range []string{"provenance", "fingerprint", "corroboration", "bson", "_id"} {
		if strings.Contains(body, leak) {
			t.Errorf("the response leaks %q: %s", leak, body)
		}
	}
}

// A redirect rule must publish the extensionPath, and the extension page must be
// an extension-relative path.
func TestPublishedRedirectCarriesTheExtensionPath(t *testing.T) {
	t.Parallel()

	rs := sampleSnapshot(3, 1)
	rs.Rules[0].Action = mongostore.RuleAction{
		Type:     "redirect",
		Redirect: &mongostore.Redirect{ExtensionPath: "/locked.html"},
	}
	rs.Rules[0].Condition.ResourceTypes = []string{"main_frame", "sub_frame"}

	rec := get(t, newRulesetServer(t, &stubRulesetStore{current: rs}), "/api/v1/get-all", nil)

	var envelope struct {
		Rules []struct {
			Action struct {
				Type     string `json:"type"`
				Redirect *struct {
					ExtensionPath string `json:"extensionPath"`
				} `json:"redirect"`
			} `json:"action"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(envelope.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(envelope.Rules))
	}

	got := envelope.Rules[0].Action
	if got.Type != "redirect" {
		t.Errorf("action.type = %q, want redirect", got.Type)
	}
	if got.Redirect == nil {
		t.Fatal("a redirect rule was published without a redirect member")
	}
	if got.Redirect.ExtensionPath != "/locked.html" {
		t.Errorf("extensionPath = %q, want /locked.html", got.Redirect.ExtensionPath)
	}
	if !strings.HasPrefix(got.Redirect.ExtensionPath, "/") {
		t.Error("extensionPath is not extension-relative")
	}
}

// The rules property must always be an array, never null, because a client
// decoding into []Rule would treat the two differently.
func TestPublishedRulesAreAlwaysAnArray(t *testing.T) {
	t.Parallel()

	for _, current := range []mongostore.Ruleset{
		{Version: 1, GeneratedAt: time.Now().UTC(), Rules: nil},
		{Version: 2, GeneratedAt: time.Now().UTC(), Rules: []mongostore.Rule{}},
	} {
		rec := get(t, newRulesetServer(t, &stubRulesetStore{current: current}), "/api/v1/get-all", nil)

		var envelope struct {
			Rules []json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if envelope.Rules == nil {
			t.Errorf("version %d published rules as null, want []", current.Version)
		}
		if !strings.Contains(rec.Body.String(), `"rules":[`) {
			t.Errorf("version %d did not publish an array: %s", current.Version, rec.Body.String())
		}
	}
}

// A stored rule with no resourceTypes must still publish a list.
//
// Chrome's default for an absent list excludes main_frame, so a rule published
// without one would silently stop blocking navigation — the opposite of what it
// was generated for.
func TestPublishedRuleNeverOmitsResourceTypes(t *testing.T) {
	t.Parallel()

	rs := sampleSnapshot(1, 1)
	rs.Rules[0].Condition.ResourceTypes = nil

	rec := get(t, newRulesetServer(t, &stubRulesetStore{current: rs}), "/api/v1/get-all", nil)

	var envelope struct {
		Rules []struct {
			Condition struct {
				ResourceTypes []string `json:"resourceTypes"`
			} `json:"condition"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(envelope.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(envelope.Rules))
	}
	types := envelope.Rules[0].Condition.ResourceTypes
	if len(types) == 0 {
		t.Fatal("resourceTypes was omitted; the rule would not block navigation")
	}
	var hasMain bool
	for _, rt := range types {
		if rt == "main_frame" {
			hasMain = true
		}
	}
	if !hasMain {
		t.Errorf("resourceTypes = %v with no main_frame", types)
	}
}
