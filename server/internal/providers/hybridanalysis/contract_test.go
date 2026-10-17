package hybridanalysis

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"cyberguard/server/internal/providers"
)

// Contract tests against the official specification.
//
// These exist because the adapter decodes with DisallowUnknownFields, and the
// specification defines far more properties than this project reads. That
// combination fails silently in one direction and loudly in the other:
//
//   - A documented property left undeclared makes every real response a
//     malformed-response error, so no verdict is ever produced.
//   - A property the specification does not document, if it were tolerated,
//     would make strict decoding decorative.
//
// The only thing that distinguishes those two cases is the documented field
// set. These tests pin the wire structs to that set so the boundary cannot
// drift by accident, and so a future schema addition is a visible test
// failure rather than a production outage.
//
// Source: https://hybrid-analysis.com/bff/api-docs/v2 (OpenAPI 3.0.0,
// api-version 2.38.0). Distilled contract:
// docs/verified/hybrid-analysis-v2-contract.md.

// documentedSampleSummaryKeys is the full property set of the `SampleSummary`
// schema, with a value of the documented type for each.
//
// This is transcribed from the specification, not generated at test time, so
// the test does not need the network and cannot be satisfied by a change to
// the same struct it is meant to police. All 55 properties are present,
// including the ones this project never reads — that is the point.
var documentedSampleSummaryKeys = map[string]any{
	"analysis_start_time":             "2026-10-17T09:00:00",
	"av_detect":                       7,
	"certificates":                    []any{},
	"certificates_validation_message": "ok",
	"classification_tags":             []any{},
	"compromised_hosts":               []any{},
	"crowdstrike_ai":                  nil,
	"detonation_parameters":           nil,
	"dll_characteristics":             []any{},
	"domains":                         []any{},
	"entrypoint":                      "0x1000",
	"entrypoint_section":              ".text",
	"environment_description":         "Windows 11 64 bit",
	"environment_id":                  140,
	"error_origin":                    "",
	"error_type":                      "",
	"extracted_files":                 []any{},
	"file_metadata":                   nil,
	"hosts":                           []any{},
	"image_base":                      "0x400000",
	"image_file_characteristics":      []any{},
	"imphash":                         "deadbeef",
	"interesting":                     false,
	"is_certificates_valid":           true,
	"job_id":                          "job-abc",
	"machine_learning_models":         []any{},
	"major_os_version":                10,
	"md5":                             "0f1e2d",
	"minor_os_version":                0,
	"mitre_attcks":                    []any{},
	"network_mode":                    "default",
	"processes":                       []any{},
	"sha1":                            "aa",
	"sha256":                          "bb",
	"sha512":                          "cc",
	"signatures":                      []any{},
	"size":                            1024,
	"ssdeep":                          "3::",
	"state":                           "SUCCESS",
	"submissions":                     []any{},
	"submit_name":                     "",
	"subsystem":                       "GUI",
	"tags":                            []any{},
	"target_url":                      "https://example.test/",
	"threat_level":                    1,
	"threat_score":                    2,
	"total_network_connections":       3,
	"total_processes":                 4,
	"total_signatures":                5,
	"type":                            "url",
	"type_short":                      []any{},
	"url_analysis":                    true,
	"verdict":                         "no specific threat",
	"vx_family":                       "",
	"warnings":                        []any{},
}

// A response carrying every documented SampleSummary property must decode.
//
// Before the struct was completed this failed with
// `json: unknown field "environment_description"`, which is how every completed
// analysis in production would have been discarded as a malformed response.
func TestSampleSummaryDecodesEveryDocumentedProperty(t *testing.T) {
	body, err := json.Marshal(documentedSampleSummaryKeys)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}

	var got sampleSummary
	if err := decodeStrict(body, &got); err != nil {
		t.Fatalf("a fully documented SampleSummary was rejected: %v", err)
	}

	if deref(got.State) != "SUCCESS" {
		t.Errorf("state = %q, want SUCCESS", deref(got.State))
	}
	if deref(got.Verdict) != "no specific threat" {
		t.Errorf("verdict = %q, want %q", deref(got.Verdict), "no specific threat")
	}
	if got.AVDetect == nil || *got.AVDetect != 7 {
		t.Errorf("av_detect = %v, want 7", got.AVDetect)
	}
	if got.URLAnalysis == nil || !*got.URLAnalysis {
		t.Errorf("url_analysis = %v, want true", got.URLAnalysis)
	}
}

// Strict decoding must survive completion of the struct: an undeclared property
// is still rejected. Tolerating the documented remainder is not the same thing
// as tolerating everything, and only the first one is safe.
func TestSampleSummaryStillRejectsUndocumentedProperties(t *testing.T) {
	doc := make(map[string]any, len(documentedSampleSummaryKeys)+1)
	for k, v := range documentedSampleSummaryKeys {
		doc[k] = v
	}
	doc["totally_new_provider_field"] = 1

	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}

	var got sampleSummary
	err = decodeStrict(body, &got)
	if err == nil {
		t.Fatal("an undocumented property was accepted; strict decoding is decorative")
	}
	if !strings.Contains(err.Error(), "totally_new_provider_field") {
		t.Errorf("error = %v, want it to name the undocumented property", err)
	}
	if !errors.Is(err, providers.ErrBadResponse) {
		t.Errorf("error = %v, want it to wrap ErrBadResponse", err)
	}
}

// The fixture is only meaningful if it actually covers the documented schema.
// A transcription typo that dropped twenty properties would otherwise leave this
// test asserting nothing.
func TestSampleSummaryFixtureMatchesTheDocumentedSchema(t *testing.T) {
	const wantProperties = 55

	if got := len(documentedSampleSummaryKeys); got != wantProperties {
		t.Fatalf("fixture has %d properties, the specification declares %d: "+
			"the fixture is stale and the tests above prove nothing", got, wantProperties)
	}
	if declared := declaredJSONTags(sampleSummary{}); declared != wantProperties {
		t.Fatalf("sampleSummary declares %d properties, the specification declares %d",
			declared, wantProperties)
	}

	// Every fixture key must be a property the struct declares, and vice versa.
	// Otherwise the two tests above would pass while proving nothing.
	declared := jsonTags(sampleSummary{})
	for k := range documentedSampleSummaryKeys {
		if !declared[k] {
			t.Errorf("fixture has %q but sampleSummary does not declare it", k)
		}
	}
	for k := range declared {
		if _, ok := documentedSampleSummaryKeys[k]; !ok {
			t.Errorf("sampleSummary declares %q, which the specification fixture does not", k)
		}
	}
}

// jsonTags returns the set of JSON property names a struct declares.
func jsonTags(v any) map[string]bool {
	out := make(map[string]bool)
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumField(); i++ {
		out[t.Field(i).Tag.Get("json")] = true
	}
	return out
}

// declaredJSONTags counts the JSON properties a struct declares.
func declaredJSONTags(v any) int { return len(jsonTags(v)) }

// SubmissionStatus plus the one property the specification's UrlSubmissionStatus
// adds. Both shapes must decode, because which one the service returns for a URL
// submission is not documented.
func TestSubmissionStatusAcceptsBothDocumentedShapes(t *testing.T) {
	t.Run("SubmissionStatus", func(t *testing.T) {
		body := `{"job_id":"j1","submission_id":"s1","environment_id":140,"sha256":"ab"}`
		var got submissionStatus
		if err := decodeStrict([]byte(body), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.JobID != "j1" || got.SubmissionType != nil {
			t.Errorf("got %+v, want job j1 and no submission_type", got)
		}
	})

	t.Run("UrlSubmissionStatus", func(t *testing.T) {
		body := `{"job_id":"j1","submission_id":"s1","environment_id":140,"sha256":"ab","submission_type":"url"}`
		var got submissionStatus
		if err := decodeStrict([]byte(body), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if deref(got.SubmissionType) != "url" {
			t.Errorf("submission_type = %v, want url", got.SubmissionType)
		}
	})

	t.Run("undocumented property still rejected", func(t *testing.T) {
		body := `{"job_id":"j1","invented_field":true}`
		var got submissionStatus
		if err := decodeStrict([]byte(body), &got); err == nil {
			t.Fatal("an undocumented property was accepted")
		}
	})
}

// SampleState declares all five documented properties, and SampleVerdict all
// seven. This pins both, because a state response that fails to decode is
// indistinguishable from a provider outage in the logs.
func TestStateShapesDecode(t *testing.T) {
	state := `{
	  "state": "SUCCESS",
	  "error_type": null,
	  "error_origin": null,
	  "error": null,
	  "related_reports": [
	    {"job_id":"j2","environment_id":140,"state":"SUCCESS","error_type":null,
	     "error_origin":null,"sha256":"ab","verdict":"malicious"}
	  ]
	}`
	var st sampleState
	if err := decodeStrict([]byte(state), &st); err != nil {
		t.Fatalf("SampleState rejected: %v", err)
	}
	if deref(st.State) != "SUCCESS" || len(st.RelatedReports) != 1 {
		t.Fatalf("got %+v", st)
	}
	if deref(st.RelatedReports[0].Verdict) != "malicious" {
		t.Errorf("related verdict = %q, want malicious", deref(st.RelatedReports[0].Verdict))
	}

	for _, bad := range []string{
		`{"state":"SUCCESS","error_type":null,"error_origin":null,"error":null,"related_reports":[],"extra":1}`,
		`{"state":"SUCCESS","error_type":null,"error_origin":null,"error":null,"related_reports":[{"job_id":"j2","nope":1}]}`,
	} {
		var rejected sampleState
		if err := decodeStrict([]byte(bad), &rejected); err == nil {
			t.Errorf("accepted an undocumented property: %s", bad)
		}
	}
}

// The quota response the live service actually returned, captured while
// verifying the account. `apikey` and `total` are both null-or-object here,
// which is the case that made an earlier version of this struct fail.
//
// No credential appears in this fixture: /key/submission-quota never echoes the
// key. /key/current does, which is why nothing in this package calls it.
func TestLiveSubmissionQuotaShapeDecodes(t *testing.T) {
	const body = `{"detonation":{"total":null,"apikey":{"quota":{"hour":null,"day":100,"week":null,"month":null,"year":null,"omega":null},"used":{"hour":null,"day":0,"week":null,"month":null,"year":null,"omega":null},"available":{"hour":null,"day":100,"week":null,"month":null,"year":null,"omega":null},"quota_reached":false},"quota_reached":false},"quick_scan":{"total":null,"apikey":null,"quota_reached":false}}`

	c, err := New(Options{APIKey: "test-key-not-a-real-credential"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("api-key"); got != "test-key-not-a-real-credential" {
			t.Errorf("api-key header = %q, want the configured key", got)
		}
		if r.URL.Path != "/key/submission-quota" {
			t.Errorf("path = %q, want /key/submission-quota", r.URL.Path)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c.baseURL = srv.URL

	detonation, quickScan, err := c.GetQuota(t.Context())
	if err != nil {
		t.Fatalf("GetQuota on the live shape: %v", err)
	}
	if detonation || quickScan {
		t.Errorf("quota reached = (%v, %v), want (false, false)", detonation, quickScan)
	}
}
