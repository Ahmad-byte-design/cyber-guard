package hybridanalysis_test

import (
	"net/http"
	"strings"
	"testing"

	"cyberguard/server/internal/providers/hybridanalysis"
)

// Regression coverage for the quota response shape.
//
// The original decoding modelled only `apikey` and `quota_reached`, while
// decoding strictly. The live service returns `total` as well — the v2
// specification declares it, nullable and marked deprecated, but still
// present — so every quota probe failed with:
//
//	json: unknown field "total"
//
// The unit test that missed this fed a hand-written response containing only
// the two modelled fields, so it passed while the real request failed. The
// fixture below is transcribed from the specification's `QuotaOverall` and
// `QuotaForType` schemas instead, which is the whole difference.
//
// No test here contacts the live service.

// quotaBody renders a SubmissionQuota with every documented member present,
// including the nested QuotaForType objects and their nullable values.
func quotaBody(detonationReached, quickScanReached, includeTotal bool) string {
	var b strings.Builder

	quotaForType := func(reached bool) string {
		return `{"quota":null,"used":null,"available":null,"quota_reached":` +
			boolText(reached) + `}`
	}

	overall := func(reached bool) string {
		parts := []string{
			`"apikey":` + quotaForType(reached),
			`"quota_reached":` + boolText(reached),
		}
		if includeTotal {
			parts = append(parts, `"total":`+quotaForType(reached))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}

	b.WriteString(`{"detonation":` + overall(detonationReached) +
		`,"quick_scan":` + overall(quickScanReached) + `}`)
	return b.String()
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// serveJSON wires a client to a server that returns body verbatim.
//
// It also returns an accessor for the last requested path, so a test can assert
// the probe really did hit the quota endpoint.
func serveJSON(t *testing.T, body string) (*hybridanalysis.Client, func() string) {
	t.Helper()

	var lastPath string
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	return c, func() string { return lastPath }
}

// The exact shape that broke the live probe: `total` present and populated.
func TestGetQuotaAcceptsTheDocumentedTotalField(t *testing.T) {
	t.Parallel()

	c, path := serveJSON(t, quotaBody(false, false, true))
	if p := path(); p != "" && p != "/key/submission-quota" {
		t.Errorf("probe hit %s", p)
	}

	det, quick, err := c.GetQuota(t.Context())
	if err != nil {
		t.Fatalf("GetQuota must accept the documented QuotaOverall shape: %v", err)
	}
	if det || quick {
		t.Errorf("quota reached = %v/%v, want false/false", det, quick)
	}
}

// The reverse reading must still be honoured: total must not mask
// quota_reached, and an unreachable quota must be visible.
func TestGetQuotaReadsQuotaReachedAlongsideTotal(t *testing.T) {
	t.Parallel()

	c, _ := serveJSON(t, quotaBody(true, false, true))

	det, quick, err := c.GetQuota(t.Context())
	if err != nil {
		t.Fatalf("GetQuota: %v", err)
	}
	if !det {
		t.Error("detonation quota_reached = false, want true")
	}
	if quick {
		t.Error("quick_scan quota_reached = true, want false")
	}
}

// `total` and `apikey` are declared nullable, so null must decode, not fail.
func TestGetQuotaAcceptsNullMembers(t *testing.T) {
	t.Parallel()

	c, _ := serveJSON(t, `{
	  "detonation": {"apikey": null, "total": null, "quota_reached": true},
	  "quick_scan": {"apikey": null, "total": null, "quota_reached": false}
	}`)

	det, quick, err := c.GetQuota(t.Context())
	if err != nil {
		t.Fatalf("GetQuota with null apikey/total: %v", err)
	}
	if !det {
		t.Error("detonation quota_reached = false, want true")
	}
	if quick {
		t.Error("quick_scan quota_reached = true, want false")
	}
}

// `apikey` absent must not be read as "no quota": quota_reached is a sibling
// of it, not a child of it.
func TestGetQuotaAcceptsAbsentMembers(t *testing.T) {
	t.Parallel()

	c, _ := serveJSON(t, `{
	  "detonation": {"total": {"quota": null, "used": null, "available": null, "quota_reached": true}, "quota_reached": true},
	  "quick_scan": {"total": null, "quota_reached": false}
	}`)

	det, _, err := c.GetQuota(t.Context())
	if err != nil {
		t.Fatalf("GetQuota with absent apikey: %v", err)
	}
	if !det {
		t.Error("detonation quota_reached = false, want true")
	}
}

// Strict decoding stays on.
//
// This is the test that stops someone "fixing" the total problem by switching
// off strict decoding, which would silently hide every future field-name
// mismatch across the entire adapter — including on the endpoints that decide
// whether an analysis was malicious.
func TestGetQuotaStillRejectsUndocumentedFields(t *testing.T) {
	t.Parallel()

	c, _ := serveJSON(t, `{
	  "detonation": {"apikey": null, "total": null, "quota_reached": false,
	                 "not_a_real_field": 1},
	  "quick_scan": {"quota_reached": false}
	}`)

	_, _, err := c.GetQuota(t.Context())
	if err == nil {
		t.Fatal("GetQuota accepted an undocumented field; strict decoding is disabled")
	}
	if !strings.Contains(err.Error(), "not_a_real_field") {
		t.Errorf("error = %q, want it to name the offending field", err)
	}
}

// The same guarantee on the endpoints that matter most: a submission and a
// report must still reject anything the specification does not declare.
func TestQuotaFixDidNotWeakenOtherDecoders(t *testing.T) {
	t.Parallel()

	t.Run("submission", func(t *testing.T) {
		t.Parallel()
		c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"job_id":"j","not_declared":1}`))
		})
		if _, err := c.SubmitURL(t.Context(), "https://example.test/"); err == nil {
			t.Error("SubmitURL accepted an undeclared field")
		}
	})

	t.Run("report state", func(t *testing.T) {
		t.Parallel()
		c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"state":"SUCCESS","not_declared":1}`))
		})
		if _, err := c.GetAnalysis(t.Context(), "job-1"); err == nil {
			t.Error("GetAnalysis accepted an undeclared field")
		}
	})
}
