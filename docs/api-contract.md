# CyberGuard AI — API Contract

> **Status:** Accepted. All three endpoints are implemented end to end against
> MongoDB and Redis, including the generated protection ruleset. See
> [`architecture.md` §8](architecture.md#8-current-implementation-status).
>
> **OpenAPI 3.1 is the authoritative contract** per
> [ADR 0015](decisions/0015-openapi-and-rfc-9457.md). This document is its
> narrative companion and the source for rationale, status-code semantics and
> client guidance. Where they disagree, the OpenAPI document wins and this file
> is a bug.

Version: `v1`. Base path: `/api/v1`. All responses are `application/json;
charset=utf-8`, except errors, which are `application/problem+json`. All
timestamps are RFC 3339 in UTC (`2026-10-16T12:00:00Z`).

## 0. Discovering the contract

The service serves its own documentation. Neither endpoint touches a datastore,
so both remain available while the rest of the service is degraded — which is
when they are most useful.

| Endpoint | Purpose | Gated by |
|---|---|---|
| `GET /openapi.yaml` | The authoritative OpenAPI 3.1 document, as `application/yaml` | `API_DOCS_ENABLED` (default on) |
| `GET /docs/` | Swagger UI, loading `/docs/assets/*` and `../openapi.yaml` | `API_DOCS_ENABLED` (default on) |
| `GET /docs/assets/{name}` | Vendored Swagger UI stylesheet, scripts and favicons | `API_DOCS_ENABLED` (default on) |

Three properties are worth stating because they are deliberate:

- **The served document is the committed document.** `server/openapi.yaml` is
  embedded into the binary with `//go:embed`, so the bytes a client reads are
  the bytes in the repository. A deployment cannot serve a contract that
  disagrees with its own code, which is the failure the contract-drift test
  exists to prevent.
- **Swagger UI is vendored, not fetched.** The assets are pinned at
  `swagger-ui-dist` 5.17.14 (Apache-2.0, licence included in the tree) and
  embedded. No CDN is contacted at runtime, so the page renders in an
  air-gapped environment.
- **No authentication was added for it.** The service has no accounts. Putting a
  login in front of a static document would be security theatre that breaks the
  only use case it has. `API_DOCS_ENABLED=false` is the control.

`/docs` without the trailing slash redirects to `/docs/`, because the page
resolves its asset and specification URLs relative to itself.

Both endpoints support `ETag` / `If-None-Match`, returning `304` when a client
already holds the current representation.

## 1. Naming

The three endpoint names are inherited from the original project brief and are
kept verbatim for compatibility: `check-url`, `get-url/{scanId}`, `get-all`.
They are not idiomatic REST — the verbs are in the path and `get-all` is
ambiguous. Renaming them is a **breaking change**, so the recommendation is:

- Keep the three names as the stable `v1` surface.
- Add idiomatic aliases alongside them in the same release, not as a
  replacement:
  - `POST   /api/v1/assessments`      → same as `check-url`
  - `GET    /api/v1/assessments/{id}` → same as `get-url/{id}`
  - `GET    /api/v1/rulesets`         → same as `get-all`
- Never introduce ambiguous near-synonyms (`get-urls`, `get-all-rules`).

Rationale: the extension is a separately shipped client. Breaking its contract
to improve aesthetics costs a coordinated release for no functional gain.

## 2. Common conventions

### 2.1 Request identifiers

Clients may send `X-Request-ID`. The server echoes it back, or mints a 12-byte
random hex ID if absent or longer than 64 characters. Every log line for that
request carries the same ID.

### 2.2 Request limits

| Limit | Value | Reason |
|---|---|---|
| Body size | 8 KiB | A request is `{"url": "..."}`; 2 KiB of URL is the hard cap. `http.MaxBytesReader` enforces this. |
| URL length | 2048 chars | Bounds parsing, hashing and log cost. |
| Content-Type | `application/json` | Anything else → `400`. |

### 2.3 Error format

**RFC 9457 problem details**, media type `application/problem+json`. This is
binding per [ADR 0015](decisions/0015-openapi-and-rfc-9457.md), which absorbs
[ADR 0006](decisions/0006-error-format.md).

```json
{
  "type": "https://cyberguard.example/problems/validation_error",
  "title": "Validation error",
  "status": 422,
  "detail": "url: scheme must be http or https",
  "instance": "/api/v1/check-url",
  "request_id": "40831b5ecb146081731ec7fb",
  "code": "validation_error"
}
```

- `type` — stable URI identifying the problem class. The last segment is the
  `code` verbatim, underscores included: the implementation appends the code to
  `https://cyberguard.example/problems/`, so the URI for a `validation_error`
  is `.../problems/validation_error`.
- `title` — short human-readable summary.
- `detail` — specific explanation. **Never** contains a raw URL, an API key, a
  driver error, a stack trace, or an internal identifier other than
  `request_id`.
- `code` — extension member, retained: a low-cardinality string is more useful
  to a client branching on outcomes than a `type` URI it must pattern-match.

Every error this service emits uses this shape, with no exceptions:

| `code` | Status | Raised when |
|---|---|---|
| `invalid_request` | 400 | Malformed body, or a malformed path/query parameter |
| `validation_error` | 422 | The URL is unacceptable, including a prohibited target |
| `rate_limited` | 429 | An abuse-control budget is spent |
| `scan_not_found` | 404 | No scan exists for that identifier |
| `not_found` | 404 | No endpoint matches the method and path |
| `not_ready` | 503 | A required secret is unset, so submissions are refused |
| `service_unavailable` | 503 | A datastore or the ruleset store cannot be read |
| `internal_error` | 500 | A panic was recovered |

`not_found` covers both an unknown scan and an unknown route. They are separate
codes rather than one only because a mistyped path and a stale `scan_id` are
different client bugs, and a client that sees the code can tell which happened
without parsing `detail`.

### 2.4 Rate limits, quotas and concurrency

Mandatory per
[ADR 0014](decisions/0014-abuse-protection-without-authentication.md).
**Implemented in phase 4** as Redis fixed-window counters.

| Control | Value | Key |
|---|---|---|
| Per-client request rate | 60 req/min | Client IP, or install token where deployed |
| Per-fingerprint submission rate | 10/hour | `url_fingerprint` |
| Global daily submission ceiling | Configurable | Global counter |
| Concurrent provider submissions | Configurable, ≤ provider limit | Worker semaphore |
| Global concurrent requests | Configurable | Semaphore in middleware |
| Request body | 8 KiB | `http.MaxBytesReader` |
| URL length | 2048 chars | — |

Responses: `429` with `Retry-After`. On every response:
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

Quota exhaustion **fails closed**: `503` with `Retry-After`, and no new
submissions are enqueued. It must never fail open by exceeding the provider's
contract.

The per-fingerprint limit is the control that actually protects quota, because
it works with no client identity at all — it is unaffected by shared NAT egress,
which defeats per-IP limits.

Counters live in Redis. If Redis is unreachable, these controls cannot be
evaluated, so submissions stop rather than proceed unguarded: a limiter error is
a `503`, never a permissive result. Silently allowing traffic when the limiter is
broken would turn a visible outage into an invisible, unbounded provider bill.

Two implementation details that are decisions rather than defaults:

- **`X-Forwarded-For` is ignored.** The rate-limit subject is the peer address.
  Honouring a client-supplied header would let any caller choose its own key and
  disable the limit entirely. A deployment behind a proxy must either accept
  per-proxy limiting or supply the real address through a trusted mechanism.
- **The per-fingerprint budget is charged inside the scan lifecycle, not by
  middleware.** It is consumed only when a submission actually creates a scan.
  Counting every request would charge a cache hit — which costs no provider
  quota — against the quota protection, and would make a repeatedly-visited
  benign URL look like an attack.

The subject is hashed before it becomes a Redis key. A fingerprint is already an
HMAC and safe, but a client address is personal data that should not sit in a
key listing readable with `redis-cli`, and hashing both keeps the rule uniform
rather than dependent on each caller's care.

A refused request is never told to wait zero seconds; `Retry-After` has a one
second floor, because a client told to retry immediately will hammer the
endpoint, which is the opposite of what a limit is for.

### 2.5 Authentication posture

**No application-level authentication in v1.** A browser extension cannot hold
a secret that is not extractable from its own package, so no credential is
shipped to the client.

Abuse control is therefore built from the four controls above plus:

- A server-issued **install token** for managed deployments — a revocable
  identifier issued out of band, granting no user capabilities, used for rate
  limiting and attribution.
- Network placement. The initial deployment is private / self-hosted, which is
  the primary mitigation.

CORS is not authentication and is not counted as a control. A shared API key in
the extension is explicitly rejected: it distributes the credential to every
user and attributes all abuse to the operator.

See [ADR 0014](decisions/0014-abuse-protection-without-authentication.md) for
the full control set and what is deliberately not used as mitigation.

CORS is not authentication. If the API is exposed publicly, add rate limiting
*and* an install token; neither alone is sufficient. **Open question 5.**

## 3. `POST /api/v1/check-url`

Validates a URL and either returns a known verdict or starts an analysis.

### Request

```json
{
  "url": "https://example.test/login"
}
```

Validation, in order. The first failure wins:

| Rule | Failure |
|---|---|
| Body is a single JSON object, no unknown fields | `400 invalid_request` |
| `url` present and non-empty | `422 validation_error` |
| `url` ≤ 2048 characters | `422 validation_error` |
| No control characters | `422 validation_error` |
| Parses as a URL | `422 validation_error` |
| Scheme is `http` or `https` | `422 validation_error` |
| Hostname present | `422 validation_error` |
| No embedded credentials (`user:pass@`) | `422 validation_error` |
| Port numeric | `422 validation_error` |

Unknown fields are rejected so that a client typo (`"urls"` instead of `"url"`)
fails loudly instead of silently submitting nothing.

### Responses

**`200 OK` — a fresh assessment already exists**

```json
{
  "scan_id": "scan_01ABC",
  "status": "completed",
  "cached": true,
  "verdict": "suspicious",
  "evidence": [
    { "type": "provider_verdict", "summary": "Provider returned a suspicious classification" }
  ],
  "analyzed_at": "2026-10-16T12:00:00Z",
  "expires_at": "2026-10-17T12:00:00Z"
}
```

**`202 Accepted` — analysis queued**

```json
{
  "scan_id": "scan_01XYZ",
  "status": "queued",
  "cached": false,
  "status_url": "/api/v1/get-url/scan_01XYZ"
}
```

**`202 Accepted` — an equivalent scan is already running**

```json
{
  "scan_id": "scan_01XYZ",
  "status": "running",
  "cached": false,
  "status_url": "/api/v1/get-url/scan_01XYZ"
}
```

Reusing an in-progress scan is what prevents one user — or a page-reload loop —
from consuming N provider submissions for the same URL.

**`202 Accepted` — a prior attempt failed; a retry is scheduled**

Same body with `"retrying": true` added, so the extension can distinguish
"waiting on a retry" from "waiting on a first attempt".

**`503 Service Unavailable` — fingerprinting unavailable**

```json
{
  "error": {
    "code": "not_ready",
    "message": "URL fingerprinting is unavailable; URL_FINGERPRINT_HMAC_KEY is not set"
  }
}
```

### Status codes

| Code | Meaning |
|---|---|
| `200` | Cached fresh verdict |
| `202` | Queued, running, or retrying |
| `400` | Malformed body |
| `422` | URL failed validation |
| `429` | Rate limited |
| `503` | Dependency unavailable, not configured, or abuse controls unavailable |

### Behaviour guarantees

- **At most one** provider submission per fingerprint per freshness window,
  regardless of how many concurrent clients ask. This is enforced by a partial
  unique index in MongoDB, not by a read-then-write check, so concurrent
  requests cannot both proceed.
- `verdict` is present **only** when `status` is `completed` **and** the
  assessment is still within its freshness window. An expired verdict is
  omitted rather than returned: presenting week-old security information as the
  current answer would let a client act on stale data.
- A `202` response carries **no verdict**. Nothing has been analysed yet.
- The raw URL appears in no log, no metric label, and no response other than
  the client's own request. Not even the hostname is withheld — it is retained
  deliberately for host-level reputation — but the path and query string are
  never stored anywhere.

### Targets that are refused

A URL whose host is loopback, private, link-local, or otherwise non-public is
rejected with `422` **before anything is stored**. Submitting one would disclose
an internal hostname to an external sandbox and could be used to probe the
network reachable from it.

Refused: `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`,
`100.64/10`, `fe80::/10`, `fc00::/7`, multicast, unspecified, the reserved and
documentation ranges, `::ffff:`-mapped forms of all of the above, `localhost`,
any `.local` / `.internal` / `.intranet` / `.lan` / `.corp` / `.private` /
`.home.arpa` / `.arpa` host, and any single-label hostname.

Permitted: reserved documentation names such as `example.test`. They cannot
resolve on the public internet, so they disclose nothing and probe nothing — and
they are the example domain throughout this project's own documentation.

## 4. `GET /api/v1/get-url/{scanId}`

Polls for the outcome of an accepted submission.

### Path parameter

`scanId` — non-empty, ≤ 64 characters, opaque. Clients must treat it as a blob.
A scan ID is used instead of a query-string URL specifically so proxies and
access logs never receive the URL.

### Response

```json
{
  "scan_id": "scan_01XYZ",
  "status": "completed",
  "verdict": "malicious",
  "provider": "hybrid-analysis",
  "evidence": [
    { "type": "provider_verdict", "summary": "Provider returned a malicious classification" }
  ],
  "analyzed_at": "2026-10-16T12:00:00Z",
  "expires_at": "2026-10-17T12:00:00Z"
}
```

`status` is one of `queued`, `running`, `completed`, `failed`, `timed_out`,
`expired`. `verdict` is one of `malicious`, `suspicious`, `no_threat_detected`,
`inconclusive`, `unknown` — see
[ADR 0011](decisions/0011-verdict-semantics-no-threat-detected.md) — and is
**absent unless** `status` is `completed` and the assessment is still fresh.

An absent `verdict` is not an empty verdict and not a safe verdict. It means
"nothing is known yet", and the client should poll again or re-submit.

### Error codes on a non-completed scan

`error_code` uses CyberGuard's own vocabulary so provider internals never reach
a client. The full list is in [`openapi.yaml`](../server/openapi.yaml); the
values a client is most likely to act on are:

| Code | Meaning | Retry? |
|---|---|---|
| `provider_rate_limited` | The provider refused under a rate limit | Yes — re-submit |
| `provider_timeout`, `provider_poll_timeout` | The analysis did not finish in time | Yes — re-submit |
| `provider_unavailable` | Transient network or provider outage | Yes — re-submit |
| `provider_auth_failed`, `provider_not_configured` | Credentials rejected or absent | No — operator action |
| `provider_analysis_failed` | The sandbox reported a failed analysis | Yes — re-submit |
| `submission_outcome_unknown` | A submission timed out; it may already have been accepted upstream | Yes, but do not resubmit from the client immediately |
| `input_unavailable` | The encrypted URL could not be read | Yes — re-submit |
| `attempts_exhausted` | The scan exhausted its recovery budget | Yes — re-submit |

`no_threat_detected` means the analysis completed and found no indicators
sufficient to classify the sample. It is **not** a safety guarantee and must
not be rendered as "safe", "trusted" or "secure". No failure path ever produces
it: a timeout, an auth failure, a rate limit, a malformed response and an
unrecognised status all resolve to `inconclusive` or `unknown`.

On failure, `verdict` is absent and `error_code` carries a safe reason:

```json
{
  "scan_id": "scan_01XYZ",
  "status": "failed",
  "error_code": "provider_auth_failed"
}
```

### Status codes

| Code | Meaning |
|---|---|
| `200` | Scan record found |
| `400` | `scanId` missing or malformed |
| `404` | Unknown scan ID |
| `503` | Datastore unavailable |

### Polling guidance

The extension should poll with exponential backoff (1s, 2s, 4s … capped at
30s) and stop at a client-side deadline (~2 minutes), then show "could not
determine". The scan may still complete server-side and populate the cache for
next time.

## 5. `GET /api/v1/get-all?version={clientVersion}`

Returns the current browser ruleset, not scan history.

### Query parameter

`version` — optional integer: the client's currently installed ruleset version.
Omit to force a full snapshot.

### Response

```json
{
  "version": 12,
  "generated_at": "2026-10-16T12:00:00Z",
  "rules": [
    { "id": 1, "priority": 1, "action": { "type": "block" }, "condition": { "urlFilter": "||example.test^" } }
  ]
}
```

### When the server returns what

| Condition | Response |
|---|---|
| `version` matches current | `200` with `version` and `unchanged: true`, empty `rules` |
| No `version` supplied | `200` with the full snapshot |
| `version` is older | `200` with the full snapshot |
| `version` is **newer** than the server's | `200` full snapshot + header `X-Ruleset-Rolled-Back: true` |

A client ahead of the server means it installed a ruleset from a different
deployment. Saying so explicitly beats silently serving an older one.

Conditional requests are also supported: the response carries `ETag: "v12"`, and
a request carrying `If-None-Match` receives `304` with no body.

**`version` 0 with an empty `rules` array is a valid, truthful answer** meaning
"nothing has been published yet". It is not an error, and it is what a
deployment with no rule-eligible findings returns.

### What becomes a rule

A verdict **never** becomes a rule on its own.

| Verdict | Rule eligible |
|---|---|
| `malicious` | Only with corroboration |
| `suspicious` | Never — a warning surface, not a block |
| `no_threat_detected` | Never, and not evidence of harmlessness at any scope |
| `inconclusive` | Never — unknown is not safe, and unknown is not dangerous |
| `unknown` | Never |

Corroboration counts **distinct URL fingerprints**, so rescanning one URL many
times is one finding rather than many, and expired findings never count.

Scope widens as evidence strengthens, bounded by `RULESET_MAX_SCOPE`
(default `exact_url`, so a default deployment can only ever emit a single-URL
rule). The thresholds and the escalation rule are provisional pending owner
ratification: [ADR 0018](decisions/0018-ruleset-thresholds-and-scope.md).

The full policy is in
[`security-and-privacy.md` §6](security-and-privacy.md#6-ruleset-policy).

### Rules format

`rules` conforms to Chrome's `declarativeNetRequest` `Rule` schema. Every
generated rule is validated against that schema before the snapshot is
published; an invalid rule fails the whole snapshot build rather than shipping
a partial ruleset.

## 6. Health endpoints

| Endpoint | Meaning | Checks |
|---|---|---|
| `GET /health/live` | Process is alive | Nothing. Always `200` while the process serves. |
| `GET /health/ready` | Should traffic be routed here | HMAC key present; URL encryption key present; MongoDB ping; Redis ping; provider configured |

Liveness deliberately excludes dependencies. A MongoDB or Redis outage must
not make an orchestrator restart every replica — that converts a dependency
failure into a full outage.

```json
{
  "status": "ready",
  "checks": [
    { "name": "config", "ok": true },
    { "name": "url_fingerprint_hmac_key", "ok": true },
    { "name": "url_encryption_key", "ok": true },
    { "name": "mongodb", "ok": true },
    { "name": "redis", "ok": false, "why": "rate-limit and queue state unavailable" },
    { "name": "provider", "ok": false, "why": "HYBRID_ANALYSIS_API_KEY is not set" }
  ]
}
```

A `provider` failure is reported as a degraded sub-check rather than a global
`503`, because cached reads still work without a provider. A `redis` failure
**does** fail readiness, because rate-limit and quota enforcement cannot be
evaluated without it ([ADR 0014](decisions/0014-abuse-protection-without-authentication.md)).

Currently implemented: all of them. A healthy deployment reports `config`,
`mongodb`, `redis` and `provider`; `url_fingerprint_hmac_key`,
`url_encryption_key` and `scan_pipeline` appear **only when they fail**, so a
clean response stays short and a failing one names the cause. The `why` field
is a generic description and never carries driver error text, because this
endpoint is unauthenticated and driver errors can embed hosts, topology and
credentials.

## 7. Implementation gaps against this contract

Every row has a decision record and a phase. None is optional.

| Gap | Decision | Consequence if shipped unimplemented |
|---|---|---|
| No rate limits, quotas or concurrency controls | [ADR 0014](decisions/0014-abuse-protection-without-authentication.md) | Endpoint is abusable and the provider quota is unprotected. **This is the only control for abuse in v1** — there is no authentication to fall back on |
| ~~Error bodies are the ad-hoc shape, not RFC 9457~~ | [ADR 0015](decisions/0015-openapi-and-rfc-9457.md) | **Closed.** Every error, including an unmatched path, is `application/problem+json` |
| ~~No OpenAPI document~~ | [ADR 0015](decisions/0015-openapi-and-rfc-9457.md) | **Closed.** `server/openapi.yaml`, embedded and served at `/openapi.yaml`, with Swagger UI at `/docs/` |
| No `Idempotency-Key` | — | A client retry after a timeout can create a second scan. Partially mitigated by per-fingerprint dedup |
| No metrics endpoint | — | Cannot measure the cache hit rate that §5.7 of the original brief requires |

### What is deliberately not a gap

**No authentication.** v1 is intentionally unauthenticated, private/self-hosted,
and protected by rate limits, quotas, request limits and concurrency controls.
Adding auth is a v2+ decision and a breaking client change; see
[ADR 0014](decisions/0014-abuse-protection-without-authentication.md).