# CyberGuard AI — Hybrid Analysis Integration

> **Status:** Implemented. The API contract is **verified** against the
> official specification — see
> [`verified/hybrid-analysis-v2-contract.md`](verified/hybrid-analysis-v2-contract.md).
>
> **Still blocking commercial release:** written usage approval, per
> [ADR 0010](decisions/0010-hybrid-analysis-licensing.md). A working adapter is
> not a licence to submit URLs.
>
> **Still unverified:** nine details the specification does not document, listed
> in [§6](#6-open-questions-requiring-manual-verification). None of them is
> guessed in code.

## 1. Design principle

The rest of the application must not know that Hybrid Analysis exists.

```go
// internal/providers — the consumer-defined contract
type AnalysisProvider interface {
    SubmitURL(ctx context.Context, rawURL string) (Submission, error)
    GetAnalysis(ctx context.Context, providerScanID string) (Analysis, error)
}
```

`internal/providers/hybridanalysis` is the only package that knows the provider
exists. It owns authentication, HTTP, wire types, retry classification,
polling, and error mapping, and hands back only CyberGuard types.

If `internal/verdicts` ever imports this package, the boundary is broken.

## 2. Verification status — complete

Verified on **2026-10-16** against the official OpenAPI document at
`https://hybrid-analysis.com/bff/api-docs/v2` — OpenAPI `3.0.0`, docs version
`2.38.0`, 52 endpoints.

The public docs page at `hybrid-analysis.com/docs/api/v2` is a client-rendered
application and serves no specification content; the BFF endpoint above is what
its interactive explorer reads, and is the authoritative source.

### What is verified

| Fact | Value |
|---|---|
| Base URL | `https://hybrid-analysis.com/api/v2` |
| Authentication | header `api-key` |
| Submit endpoint | `POST /submit/url` |
| Submit content type | `application/x-www-form-urlencoded` |
| Required fields | `url`, `environment_id` |
| Submit success status | **`201`** |
| Submit response | `{ job_id, submission_id, environment_id, sha256 }`, all nullable |
| State endpoint | `GET /report/{id}/state`, id is `jobId` or `sha256:environmentId` |
| Summary endpoint | `GET /report/{id}/summary` |
| Quota endpoint | `GET /key/submission-quota` |
| State values | `IN_QUEUE`, `IN_PROGRESS`, `SUCCESS`, `ERROR`, `PARTIAL_SUCCESS` |
| Documented status codes | `200`, `201`, `202`, `410`, `default` |
| `user-agent` header | **Not documented. Not sent.** |

Full transcription with citations:
[`verified/hybrid-analysis-v2-contract.md`](verified/hybrid-analysis-v2-contract.md).

### Two corrections to earlier working notes

Both were wrong and both are now removed rather than left to mislead:

1. **Base URL.** Earlier notes said `https://www.hybrid-analysis.com/api/v2`.
   The specification declares `https://hybrid-analysis.com/api/v2` — no `www`.
2. **`user-agent` header.** An earlier note claimed it was required. It appears
   nowhere in the specification. The adapter sends only `api-key`.

## 3. Provider responsibilities

The adapter owns:

- Endpoint paths and the `api-key` header.
- Form encoding of `url` and `environment_id`.
- Response decoding into typed structs with strict field checking.
- Bounded response bodies.
- Retry classification and jittered backoff.
- Polling: one state request per poll, one summary request once terminal.
- Mapping provider statuses onto CyberGuard error classes.
- Mapping provider verdicts onto CyberGuard verdicts.

It does **not** own: scan persistence, ruleset eligibility, or any HTTP concern
of CyberGuard's own API.

## 4. Submission

```go
sub, err := client.SubmitURL(ctx, rawURL)   // rawURL is plaintext
// sub.ProviderScanID == job_id
// sub.State == providers.StateQueued
```

`rawURL` is plaintext because the provider requires it. This is the only point
in CyberGuard at which a raw URL crosses a network boundary.

### Submission is never retried

The specification declares **no idempotency or deduplication token** for
`POST /submit/url`. A timed-out or dropped submission is therefore *ambiguous*:
the provider may already be analysing the URL.

Retrying it could submit the same URL twice, spend quota twice, and create two
sandbox jobs for one user request. So `SubmitURL` performs exactly one attempt
and returns `ErrUnavailable`; the caller decides.

`GetAnalysis` is a GET and *is* retried, because repeating it is harmless.

This asymmetry is deliberate and is the single most important behavioural
difference between the two methods.

## 5. Polling

- One `GET /report/{id}/state` per poll. A running or queued analysis costs one
  round trip.
- On a terminal state, one `GET /report/{id}/summary` follows to obtain the
  classification.
- **A failed analysis never fetches a summary.** An `ERROR` or
  `PARTIAL_SUCCESS` state returns immediately with no classification, because
  fetching one could only produce a misleading verdict.
- An unrecognised state is surfaced verbatim. It is never coerced into a known
  one.

### States

| Provider state | `Finished` | `Failed()` | Verdict |
|---|---|---|---|
| `IN_QUEUE` | no | no | `unknown` |
| `IN_PROGRESS` | no | no | `unknown` |
| `SUCCESS` | yes | no | from classification |
| `ERROR` | yes | **yes** | `unknown` |
| `PARTIAL_SUCCESS` | yes | **yes** | `unknown` |
| anything else | yes | no | from classification |

`ERROR` is **finished and failed**. Collapsing that into `Finished` alone would
make a failed analysis indistinguishable from a clean one.

## 6. Verdict normalization

The mapping lives in `hybridanalysis.NormaliseVerdict` because only an adapter
that knows a provider's strings can translate them. The *vocabulary* lives in
`internal/verdicts`.

| Provider classification | CyberGuard verdict |
|---|---|
| `malicious` | `malicious` |
| `suspicious` | `suspicious` |
| `no specific threat` | `no_threat_detected` |
| `whitelisted` | `no_threat_detected` |
| `no verdict` | `inconclusive` |
| anything else, or empty | `unknown` |

Only those five names are mapped. They are the vocabulary documented in the
`POST /search/hash` filter description — the **only** verdict vocabulary the
specification contains.

### Four absolute rules

1. A failed or partially-successful analysis is `unknown`.
2. An unfinished analysis is `unknown`.
3. An unrecognised classification is `unknown`.
4. **No input path produces `no_threat_detected` except a recognised "no
   specific threat" or "whitelisted" classification on a completed, successful
   analysis.**

Rules 1 and 2 are checked *before* the classification is read, so a failed
analysis carrying a stale or forged verdict cannot produce a clean one.

`whitelisted` maps to `no_threat_detected` rather than to a separate "trusted"
value because CyberGuard has five verdicts and no notion of trust. It is an
absence of indicators, not an endorsement — see
[ADR 0011](decisions/0011-verdict-semantics-no-threat-detected.md).

## 7. Error normalization

| HTTP | CyberGuard error | Retried |
|---|---|---|
| 2xx | — | — |
| 401, 403 | `ErrAuthFailed` | never — retrying can lock the key |
| 429 | `ErrRateLimited` | caller decides; `Retry-After` parsed if present |
| 410 | `ErrBadResponse` | never |
| other 4xx | `ErrBadResponse` | never — the request itself is wrong |
| 5xx | `ErrUnavailable` | yes, bounded, jittered |
| transport error / timeout | `ErrUnavailable` | GET only |

Provider prose never becomes a CyberGuard error. An error may surface in a
client-visible response, and provider text is untrusted, unbounded input. It is
read only for Debug-level logging, truncated to 200 characters.

## 8. Configuration

```env
HYBRID_ANALYSIS_BASE_URL=https://hybrid-analysis.com/api/v2
HYBRID_ANALYSIS_API_KEY=
HYBRID_ANALYSIS_ENVIRONMENT_ID=140     # Windows 11 64 bit
HYBRID_ANALYSIS_TIMEOUT=30s
HYBRID_ANALYSIS_MAX_RETRIES=3          # idempotent GETs only
HYBRID_ANALYSIS_RETRY_BASE=500ms
```

Environment 140 (Windows 11) is the default because phishing kits target
Windows browsers. That is a judgement call; the specification recommends no
environment. Documented IDs are `EnvironmentName()`.

The API key is read from the environment and handed to the adapter. It is never
logged, never in an error, never in a build argument, never in an image layer,
and never shipped to the extension. Tests assert all of this.

## 9. Testing strategy

Every test runs against `httptest`. **No automated test contacts
hybrid-analysis.com, and none submits a URL to any provider.**

| Layer | Method |
|---|---|
| Wire contract | `httptest` server asserting method, path, content type, form fields, `api-key` header |
| Error mapping | `httptest` returning each status class |
| Retry policy | call counting: submissions must make exactly 1 attempt, GETs must retry transient failures and not permanent ones |
| Response validation | malformed JSON, wrong shape, empty body, oversized body |
| Verdict mapping | table test over the full vocabulary plus near-misses |
| Failure safety | `TestNormaliseVerdictNeverTreatsFailureAsNoThreatDetected` |
| Secret hygiene | asserts no error or log line contains the API key or the submitted URL |
| Cancellation | cancelled context returns promptly |

The mock provider (`internal/providers/mock`) is preserved and remains the
default for local development, so the suite and the app run with **no API key
and no network**.

## 10. Open questions requiring manual verification

These are the places where the specification is silent. **None is guessed in
code**; each is handled conservatively.

| # | Question | How it is handled meanwhile |
|---|---|---|
| V1 | Actual string values of `SampleSummary.verdict` | Mapped from the only documented vocabulary (search filter). Unrecognised → `unknown` |
| V2 | Meaning of `threat_level` (integer) | Not used |
| V3 | Do the read-side strings match the search-filter names? | **Needs one live call to confirm.** If not, update the table — do not widen it by guessing |
| V4 | Specific 4xx/5xx codes | Conventional HTTP semantics applied; documented as an assumption |
| V5 | Is `Retry-After` sent on 429, and in what format? | Parsed if present, otherwise computed backoff |
| V6 | Rate limits and burst behaviour | Not assumed; bounded retries only |
| V7 | Idempotency token for submission | **None exists.** Submissions are never retried |
| V8 | Retention terms for submitted URLs | Unknown — see ADR 0010 |
| V9 | Does the key tier permit automated submission? | **Unknown — blocks commercial release.** See [ADR 0010](decisions/0010-hybrid-analysis-licensing.md) |

### How to close V1–V3

One controlled live call, with an operator present:

```sh
# A URL you are authorised to submit. Do not use a third party's URL.
curl -s -X POST \
  -H "api-key: $HYBRID_ANALYSIS_API_KEY" \
  -H "Accept: application/json" \
  --data-urlencode "url=https://example.invalid/" \
  --data "environment_id=140" \
  "$HYBRID_ANALYSIS_BASE_URL/submit/url"
```

Then poll the returned `job_id` and read `state` and `verdict`. Record the
observed strings here, and update the mapping table deliberately.

**This has not been performed.** No URL has been submitted from this
environment.

## 11. Licensing

Independent of the technical contract, and unresolved. Written approval for
usage and automated submission is required before commercial release. An
adapter that works is not a licence to submit. See
[ADR 0010](decisions/0010-hybrid-analysis-licensing.md).

Because v1 is unauthenticated
([ADR 0014](decisions/0014-abuse-protection-without-authentication.md)), a
leaked API key is a direct path to spending the operator's quota. An API key
was shared in plaintext during design and **must be rotated**.

**A user must not be able to submit a confidential internal URL.** The
extension is unauthenticated, which makes it an exfiltration path for URLs a
user merely visited. At minimum the API must document that submitted URLs are
disclosed to a third party.