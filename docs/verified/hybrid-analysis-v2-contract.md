# Hybrid Analysis API v2 — verified contract

> **Source:** `https://hybrid-analysis.com/bff/api-docs/v2`
> **Retrieved:** 2026-10-16 · OpenAPI `3.0.0` · docs version `2.38.0` · 52 endpoints
>
> Every fact below was read from that document. Nothing here is inferred from
> recollection. Where the specification does not document something, it is listed
> under [Not documented](#not-documented) rather than guessed.

This file exists so the adapter can be audited without re-fetching the spec, and
so a future maintainer can tell verified behaviour from assumption.

## Server and authentication

| Fact | Value | Source |
|---|---|---|
| Base URL | `https://hybrid-analysis.com/api/v2` | `servers[0].url` |
| Auth scheme | `apiKey` in header, name **`api-key`** | `components.securitySchemes.api_key` |
| User-Agent required | **Not documented.** Not sent. | grep: no occurrence in spec |

The earlier working note claiming a `user-agent` header requirement was **wrong**
and has been removed. The adapter sends only the documented `api-key` header.

## `POST /submit/url` — submit a URL for analysis

| Fact | Value |
|---|---|
| Content type | `application/x-www-form-urlencoded` |
| Required fields | `url` (string), `environment_id` (integer) |
| Success status | **`201`** (not 200) |
| Error status | `default` — no specific codes documented |
| Success body | `SubmissionStatus` |

Optional fields relevant to this project: `action_script`,
`network_settings` (`default` \| `tor` \| `simulated`), `comment`. Everything
else is left unset.

### `SubmissionStatus`

```json
{ "job_id": "...", "submission_id": "...", "environment_id": 140, "sha256": "..." }
```

All four fields are nullable. `job_id` is the identifier used to poll.

### Documented environment IDs

| ID | Environment |
|---|---|
| 430 | macOS Tahoe (ARM64) |
| 330 | Linux (Ubuntu 24.04, 64 bit) |
| 200 | Android Static Analysis |
| 160 | Windows 10 64 bit |
| **140** | **Windows 11 64 bit** |
| 120 | Windows 7 64 bit |
| 110 | Windows 7 32 bit (HWP support) |
| 100 | Windows 7 32 bit |

**140 (Windows 11)** is the default, because phishing kits target Windows
browsers. This is a judgement call, not a documented recommendation.

### Documented response headers

`Api-Limits`, `Submission-Limits`, `Api-Version`, `Webservice-Version`.

## `GET /report/{id}/state` — poll analysis state

`id` is either a `jobId` or `sha256:environmentId`.

```json
{
  "state": "...",
  "error_type": "...",
  "error_origin": "...",
  "error": "...",
  "related_reports": [ { "job_id": "...", "verdict": "..." } ]
}
```

### Documented state values

From the `SampleState.state` description:

- `IN_QUEUE` — queued
- `IN_PROGRESS` — running
- `SUCCESS` — processed successfully
- `ERROR` — processed and failed
- `PARTIAL_SUCCESS` — children processed with a mixed state

`SUCCESS` and `ERROR` are both "processed". That distinction is the whole point:
`ERROR` is a **completed** analysis that failed, and must never be read as a
clean result.

## `GET /report/{id}/summary` — the report summary

Returns `SampleSummary`. Fields this project uses:

| Field | Type | Use |
|---|---|---|
| `state` | string, nullable | Terminal-state confirmation |
| `verdict` | **string, nullable** | Provider classification — see below |
| `threat_level` | integer, nullable | Documented type, **undocumented meaning** |
| `av_detect` | string | AV detection string |
| `error_type`, `error_origin` | string, nullable | Failure diagnostics |

### The `verdict` field — the one genuine ambiguity

`SampleSummary.verdict` is typed `string` and the specification **does not
enumerate its values**.

The only documented verdict vocabulary anywhere in the specification is in the
**`POST /search/hash` filter**, which takes an integer:

| Value | Documented name |
|---|---|
| 1 | `whitelisted` |
| 2 | `no verdict` |
| 3 | `no specific threat` |
| 4 | `suspicious` |
| 5 | `malicious` |

This is a *filter* on the search endpoint, not a documented read-side
vocabulary. The adapter therefore:

1. Maps the five **documented** names, case-insensitively, from the summary's
   string verdict.
2. Maps nothing else. An unrecognised string yields `unknown`.
3. Never invents a sixth name.

**This must be confirmed against a live API key before the mapping is trusted**
— see open question V3 in [`../hybrid-analysis-integration.md`](../hybrid-analysis-integration.md).

## `GET /key/submission-quota`

Returns `SubmissionQuota`:

```json
{
  "detonation":  { "apikey": {...}, "quota_reached": false },
  "quick_scan":  { "apikey": {...}, "quota_reached": false }
}
```

`QuotaOverall.total` is documented as **deprecated**; `apikey` and
`quota_reached` are current. The adapter reads `quota_reached` only.

## `GET /key/current`

Returns key metadata. Not yet used; available for operator diagnostics.

## Status codes across the whole specification

Only `200`, `201`, `202`, `410` and `default` appear. **No specific 4xx or 5xx
codes are documented for any endpoint.**

The adapter therefore classifies by conventional HTTP semantics, which is a
deliberate, documented assumption:

| Observed | Mapped to | Retry |
|---|---|---|
| `201`, `200`, `202` | success | — |
| `401`, `403` | `ErrAuthFailed` | never |
| `429` | `ErrRateLimited` | yes, honour `Retry-After` |
| `410` | `ErrBadResponse` | never |
| other `4xx` | `ErrBadResponse` | never |
| `5xx` | `ErrUnavailable` | yes, bounded |
| transport error / timeout | `ErrUnavailable` | GET only — see below |

## Not documented

These are open questions, not assumptions this code silently makes.

| # | Question |
|---|---|
| V1 | Actual string values of `SampleSummary.verdict`. Only the search-filter vocabulary is documented |
| V2 | Semantics of `threat_level` (integer). Type is documented, meaning is not |
| V3 | Whether the read-side `verdict` strings match the search-filter names |
| V4 | Specific error status codes. Only `default` is declared |
| V5 | Whether `Retry-After` is honoured on `429`, and its format |
| V6 | Rate limits and burst behaviour |
| V7 | Whether `POST /submit/url` supports any idempotency or deduplication token. **The specification declares none** |
| V8 | Retention terms for submitted URLs |
| V9 | Whether a key tier permits automated submission |

### V7 has a direct design consequence

Because no idempotency token is documented, **a timed-out submission is
ambiguous**: the provider may already be analysing the URL. Re-submitting could
consume quota twice and create duplicate sandbox jobs.

The adapter therefore **never retries `POST /submit/url`** after a timeout or a
transport error. It returns `ErrUnavailable` and the caller decides. Retries are
safe on `GET` and are performed there.

This is the conservative choice and it is the reason retry logic is not shared
symmetrically between the two methods.

## Licensing

Independent of the technical contract, and still unresolved: see
[`0010-hybrid-analysis-licensing.md`](../decisions/0010-hybrid-analysis-licensing.md).