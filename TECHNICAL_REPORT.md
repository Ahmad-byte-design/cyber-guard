# CyberGuard AI — Technical Report

**Project:** CyberGuard AI — URL threat-check backend
**Module:** `cyberguard` (Go 1.27)
**Report date:** 2026-10-18
**Scope:** `cmd/api`, `internal/*`, `docs/openapi.yaml`, `Dockerfile`, `docker-compose.yml`

---

## 1. Executive summary

CyberGuard AI is a small, single-binary Go REST API that checks whether a URL
is malicious by delegating to **Hybrid Analysis v2**'s quick-scan surface, with
**MongoDB** as a result cache and persistence layer. The design philosophy is
minimalism: two business endpoints, one collection, no queues, no workers, no
Redis — everything happens synchronously inside one HTTP request.

Key properties:

| Aspect | Status |
| --- | --- |
| Architecture | Monolithic single process + MongoDB |
| Language / runtime | Go 1.27, static binary (CGO disabled) |
| External dependency | Hybrid Analysis `POST /quick-scan/url` + `GET /quick-scan/{id}` only |
| Persistence | MongoDB (single collection `url_submissions`) |
| API contract | OpenAPI 3 served byte-identical at `/openapi.yaml`, Swagger UI vendored |
| Deployment | Docker multi-stage build + Compose (API + `mongo:9.0`) |
| Testing | Unit tests via `httptest` fakes; one opt-in integration test against real MongoDB |

---

## 2. System architecture

```
browser / curl
     │  POST /api/v1/check-url                     (synchronous)
     ▼
┌──────────────┐  MongoDB first:                  ┌────────────────────┐
│  cmd/api     │  cached+fresh ⇒ answer, 0 calls  │ Hybrid Analysis v2 │
│  (Go 1.27)   │  pending ⇒ reuse provider id     │                    │
│              │ ─── POST /quick-scan/url ──────▶ │  (only the two     │
│              │ ◀────────────────────── JSON ──  │   quick-scan       │
│              │ ─── GET /quick-scan/{id} ──────▶ │   endpoints)       │
│              │ ◀────────────────────── JSON ──  └────────────────────┘
└──────┬───────┘
       │ normalized verdict stored atomically (one record per canonical URL)
       ▼
   MongoDB ── one collection: url_submissions
       ▲
       │  GET /api/v1/get-all  (page/limit, newest first)
```

### 2.1 Package layout and responsibilities

```
cmd/api/                    the one binary: config, wiring, graceful shutdown
internal/config/            environment + .env parsing, validation, CORS origins
internal/handlers/          HTTP layer: routing, envelopes, errors, Swagger UI
internal/services/          check-url orchestration, verdict normalization, error mapping
internal/hybridanalysis/    provider client (POST /quick-scan/url, GET /quick-scan/{id})
internal/mongodb/           connection, store: cache lookups, guarded writes, listing
internal/models/            document/response shapes (single source of truth)
internal/docs/assets/       vendored Swagger UI (no CDN, no external requests)
docs/openapi.yaml           the contract served at /openapi.yaml
```

The layering is clean and unidirectional:

- **handlers** never touch provider or store types — they speak only in
  request/response envelopes and the service's stable error vocabulary.
- **services** declares its dependencies (`URLAnalyzer`, `SubmissionStore`) as
  consumer-side interfaces, so tests substitute fakes without a real client.
- **models** is the single source of truth for both the persisted document and
  the wire response shape.

---

## 3. API surface

| Method | Path | Purpose | Success |
| --- | --- | --- | --- |
| POST | `/api/v1/check-url` | Check a URL: cache first, provider only when needed | `200` or `202` |
| GET | `/api/v1/get-all` | List stored assessments, newest stored first | `200` |

### 3.1 Response envelopes

Success and failure share one shape:

```json
{ "success": true,  "message": "…", "data": { … }, "pagination": { … } }
{ "success": false, "message": "…", "error": { "code": "…", "status": 400 } }
```

### 3.2 Stable error vocabulary

| Code | HTTP | When |
| --- | --- | --- |
| `invalid_request` | 400 | Bad JSON, bad `page`/`limit` |
| `validation_error` | 422 | URL parsed but rejected (empty, too long, unsupported scheme, no host, control chars) |
| `provider_not_configured` | 503 | No API key configured |
| `provider_auth_failed` | 502 | Provider rejected the configured API key |
| `provider_rate_limited` | 429 | Provider throttled (`Retry-After` when known) |
| `provider_timeout` | 504 | Provider exceeded the budget (never auto-retried) |
| `provider_rejected` | 502 | Provider refused submission or unknown scan id |
| `provider_unavailable` | 502 | Network error reaching the provider |
| `provider_bad_response` | 502 | Unparseable provider JSON |
| `request_in_progress` | 503 | An equivalent request for the URL is being analysed |
| `store_unavailable` | 503 | MongoDB insert/read failed |
| `method_not_allowed` | 405 | Wrong verb on an existing path |
| `not_found` | 404 | Unknown path |

Provider error details are logged server-side (with request ID and cause);
response bodies carry only the safe message and the code. Provider errors
never fabricate a verdict.

---

## 4. Core workflow: `check-url`

1. **Canonicalize once.** URL is trimmed, scheme/host lowercased, default
   ports (`:80`/`:443`) and fragments dropped; path and query stay
   byte-for-byte intact so signed links keep validating. `SHA-256(canonical)`
   is the cache key (`urlHash`) used for lookups, storage and provider
   submission alike. Maximum accepted length: **2048** characters, rejected
   before parsing.

2. **MongoDB first.**
   - A **completed** assessment inside `ASSESSMENT_TTL` (default 24h) is
     answered immediately — HTTP 200, zero provider calls.
   - A **pending** record reuses its existing provider id and polls the
     retrieval endpoint instead of re-submitting the URL. Pending records
     older than the TTL are re-submitted **in place** (never a second record).

3. **Provider, only when needed.** `POST /quick-scan/url`, exactly once per
   request, **never retried** — the endpoint has no idempotency token, so a
   blind retry could duplicate submissions and burn quota.

4. **Retrieve the final result.** When the submission answers
   `finished: false`, `GET /quick-scan/{id}` is polled — first immediately,
   then every `HYBRID_ANALYSIS_POLL_INTERVAL` (default 1s) — until the
   provider reports `finished: true`, the wait budget (derived from
   `HYBRID_ANALYSIS_TIMEOUT`, default 30s, max 5m) runs out, or the provider
   fails.

5. **Persist honestly, at most forward.** A finished result is normalized and
   saved with a guarded update so a completed assessment can never be
   overwritten by pending data.

### 4.1 Response semantics

- **HTTP 200** — `"URL analysis completed"`: a completed assessment is in the
  response (from cache or obtained during this request).
- **HTTP 202** — `"Analysis is still in progress"`: the provider has not
  finished within the budget. `data.status = "pending"`, `data.verdict = null`;
  the next call with the same URL resumes the existing assessment.

---

## 5. Verdict normalization

The provider's quick scan has **no aggregate verdict field** — it reports
per-scanner statuses (`scanners_v2`, plus the deprecated `scanners` array
classified by the same rules). The verdict is computed only from a
`finished: true` response, by an explicit evidence ladder:

| Scanner status text (case-insensitive) | Evidence |
| --- | --- |
| contains `malicious` | malicious |
| contains `suspicious` | suspicious |
| `no specific threat` / `no threat` / `clean` / `whitelist` | benign |
| `error`, or non-null `errorMessage` on an unclassified entry | errored |
| anything else (`no-classification`, `in-queue`, empty, unrecognized) | unresolved |
| `null` / unusable entry | missing — **not** benign |

Decision order (worst evidence wins, never guessed):

1. any malicious evidence → `malicious`
2. else any suspicious evidence → `suspicious`
3. else benign with no unresolved/errored scanners left → `no_threat_detected`
4. else unresolved or errored scanners remain → `inconclusive`
5. else nothing usable evaluated → `unknown`

Design invariants worth highlighting:

- `verdict` is `null` while pending — the API never implies a result it does
  not have.
- Provider errors are never read as verdicts.
- A SHA-256 digest without scanner evidence proves nothing.
- `scannersV2` is verbatim passthrough of provider data.

---

## 6. Data model and persistence

- **Collection:** `url_submissions` (one record per canonical URL).
- **Indexes:** idempotently ensured at startup, including the unique
  `uniq_url_hash` index — the cross-process coordination mechanism. Index
  creation failure is a **startup error**, not a warning, because the single
  query pattern depends on it.
- **Guarded writes:** a completed assessment can never be overwritten by
  pending data; updates only ever move the record "forward".
- **Listing:** `GET /api/v1/get-all` paginates with `page` (starts at 1, max
  1,000,000) and `limit` (default 20, cap 100); out-of-range parameters are
  `400` — nothing is silently clamped. Sorted by last update time, so a
  record that just obtained its final result surfaces near the top. Empty
  results return `data: []`, never `null`.

---

## 7. Concurrency and consistency

A deliberate two-tier design, matched to the "one process" deployment:

1. **In-process:** equivalent requests for the same canonical URL are admitted
   one at a time via an in-flight set (mutex-guarded map, no queues, no
   workers). The loser either adopts the winner's record or answers
   `request_in_progress` rather than duplicating a submission.

2. **Cross-process:** the unique `uniq_url_hash` index collapses duplicates
   across replicas — losing writers adopt the winner's record instead of
   creating a second submission.

Known residual risk (documented in the README): on a cold URL, two replicas
may still each submit once; the index guarantees the store stays consistent.

---

## 8. Configuration

All configuration is environment-first (`.env` for local runs, environment
variables under Compose/process managers; **environment always wins**):

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_PORT` | `8080` | Host port; the container always listens on 8080 |
| `MONGODB_URI` | `mongodb://localhost:27017` | Connection string (Compose pins `mongodb://mongodb:27017`) |
| `MONGODB_DATABASE` | `cyberguard` | Database name |
| `HYBRID_ANALYSIS_BASE_URL` | `https://hybrid-analysis.com/api/v2` | Provider base URL — **no `www`** (a Go client will not replay a POST body across the 301) |
| `HYBRID_ANALYSIS_API_KEY` | *(empty)* | Without it, check-url answers `503 provider_not_configured` |
| `HYBRID_ANALYSIS_TIMEOUT` | `30s` | Per-request provider budget (max 5m); also bounds the whole check-url wait |
| `HYBRID_ANALYSIS_SCAN_TYPE` | `all` | Validated at startup against the provider's enum |
| `HYBRID_ANALYSIS_POLL_INTERVAL` | `1s` | Pause between retrievals (`> 0`, at most 1m) |
| `ASSESSMENT_TTL` | `24h` | Cache lifetime of a completed assessment (`> 0`, at most 336h) |
| `CORS_ALLOWED_ORIGINS` | localhost:3000/5173 | Exact origins, comma separated; `*` is **rejected at startup** |

The API key is used only in the provider request header — never logged, never
stored, never echoed in any API response.

---

## 9. Runtime behavior and robustness

### 9.1 Process lifecycle (`cmd/api/main.go`)

- `.env` loaded explicitly before config; a wrong `MONGODB_URI` is a **startup
  error** (the connection is pinged through, 10s connect / 5s ping budget).
- `signal.NotifyContext` installed **before** connecting, so a SIGTERM during a
  slow database connect still cancels the attempt.
- Graceful shutdown: 10s deadline taken via `context.WithoutCancel` (the
  signal already cancelled the base context), force-`Close()` fallback so a
  stuck connection cannot block container exit.
- JSON structured logging via `log/slog` on stderr; missing API key is a
  startup **warning**, not a crash (readiness reports it; the process serves).

### 9.2 HTTP server hardening

- `ReadHeaderTimeout: 5s`, `ReadTimeout: 15s` — a stalled client cannot pin a
  goroutine.
- `WriteTimeout = provider budget + 15s` — deliberately larger than the
  provider budget, because check-url may legitimately wait for result
  retrieval.
- `IdleTimeout: 60s`.
- CORS is strict allow-list; wildcard `*` is structurally impossible.

### 9.3 Health endpoints

- `/health/live` → `{"status":"ok"}` (container healthcheck uses this).
- `/health/ready` → process + MongoDB reachable; `503` with
  `"status":"not_ready"` when MongoDB is down, and an explicit
  `checks.provider` note when the key is absent (still serves traffic).

---

## 10. Containerization and deployment

### 10.1 `Dockerfile` (multi-stage)

- **Build:** `golang:1.27-alpine`, BuildKit cache mounts for module and build
  caches, `CGO_ENABLED=0 -trimpath` → one statically linked binary; no runtime
  shared-library risk.
- **Runtime:** `alpine:3.20` + `ca-certificates` only (needed for HTTPS to the
  provider); binary copied with `--chmod=0555`.
- Runs as an **unprivileged user** (`cyberguard`), no init system needed —
  SIGINT/SIGTERM is handled by graceful shutdown in the binary.
- Image healthcheck hits `/health/live` (survives an unconfigured provider);
  Compose uses `/health/ready` instead, which is the one that demands MongoDB.

### 10.2 `docker-compose.yml`

- Two services only: `backend` + `mongodb:9.0` (pinned to 9.x: MongoDB 8.0
  refuses to start on Linux kernel 6.19+ — SERVER-121912).
- MongoDB has **no published ports** — reachable only on the compose network.
- `mongosh`-based healthcheck with `start_period: 20s`; `nofile` ulimit raised
  to 65536 (default 1024 breaks under integration tests that open a client
  per test — it looks exactly like a database outage otherwise).
- `depends_on: service_healthy` ordering.
- Distinct image tag (`cyberguard-api:go-local`) to avoid colliding with a
  sibling Laravel project that also builds `cyberguard-api:local`.
- `APP_PORT` selects the **host** port only; `MONGODB_URI` is re-pinned inside
  the network because the host `.env` value would be wrong there.
- A `go` tool service (profile `tools`) runs build/test/vet/gofmt against the
  host module without requiring Go on the host, matching host UID/GID with
  host-backed caches in `./.cache/`.

---

## 11. Testing

| Package | Test files | Focus |
| --- | --- | --- |
| `internal/config` | 4 tests | env parsing, validation, CORS origin rules |
| `internal/handlers` | 15 tests | routing, envelopes, status codes, pagination errors |
| `internal/hybridanalysis` | 20 + 2 tests | provider client via `httptest`: success, auth failure, rate limit, slow response, malformed body; contract check against `openapi.yaml` |
| `internal/services` | 20 + 2 tests | check-url orchestration and the verdict ladder |
| `internal/mongodb` | 2 tests (integration) | real-store behavior; **skipped** unless `MONGO_TEST_URI` is set |

Properties:

- **No test ever contacts Hybrid Analysis** — provider behavior is faked with
  `httptest` servers.
- One opt-in integration test needs a real MongoDB.
- Tooling runs inside Docker: `gofmt -l`, `go vet ./...`, `go build ./...`,
  `go test -count=1 ./...`, `go test -race ./...` (race needs gcc → debian
  image note).
- Test volume is healthy: ~2,700 lines of test code vs ~4,300 lines of source
  (roughly 1:1.6).

---

## 12. Security assessment

### Strengths

1. **Secret hygiene:** API key only in the provider header; never logged,
   stored, or returned. Provider error prose never reaches the client body.
2. **Strict CORS:** exact-origin allow-list; `*` rejected at startup.
3. **Input validation:** length cap (2048), scheme/host/control-char checks,
   strict query-parameter validation (no silent clamping).
4. **Non-root container**, static binary, minimal runtime image
   (alpine + ca-certs only).
5. **Server timeouts** configured on all four dimensions — slowloris-resistant
   header/body reads.
6. **Safe error surface:** one stable envelope, safe messages, internal
   details logged with request IDs only.

### Gaps (explicitly documented by the project — treat as known risk)

| Gap | Impact | Suggested mitigation |
| --- | --- | --- |
| **No authentication on the API** | Anyone who can reach the port can spend your provider quota | Put an API key / JWT / mTLS in front; or front with an auth proxy |
| **No rate limiting on the API** | Burst abuse burns provider quota; a flood of cold URLs multiplies submissions | Token-bucket middleware; per-origin and per-IP limits |
| **Single-process in-flight coordination** | Two replicas may both submit once on a cold URL | Acceptable at MVP scale; otherwise a distributed lock or provider idempotency token |
| **Provider retention is external** | Provider may drop a pending scan id → record stays pending until TTL re-submission | Already handled honestly (stays pending, re-submits in place); document retention windows |

---

## 13. Limitations and risks

- **`www` redirect trap:** the declared v2 host is
  `https://hybrid-analysis.com/api/v2`; the `www` host answers `301` and a Go
  client will not replay the POST body across it — keeping the default is
  mandatory, not cosmetic.
- **Quick scan surface only:** not the full sandbox analysis; only the two
  documented quick-scan endpoints are called (no quota probes, no search, no
  feeds).
- **One request, one budget:** pending analyses answer `202` when the budget
  runs out; they stay pending and reusable until finished or aged past TTL.
- **Submissions are never auto-retried** (each retry may consume quota);
  result *retrieval* is a read, retried only by the in-request poll loop.
- **Licensing:** automated submission requires Hybrid Analysis usage approval
  before commercial release — verify account terms.

---

## 14. Code quality observations

| Area | Assessment |
| --- | --- |
| Layering | Clean unidirectional flow; consumer-side interfaces keep the service testable |
| Documentation | Exceptional — package doc-comments explain *why*, not just *what*; README is current and honest about limitations |
| Error handling | Stable code vocabulary at the service boundary; wrapped causes for logs; no panic paths observed in handlers |
| Concurrency | Small, contained surface (in-flight set); `-race` is part of the documented dev loop |
| Configuration | Fail-fast validation at startup, including CORS wildcard rejection and scan-type enum check |
| Maintainability | Single source of truth in `models`; contract served from a committed `openapi.yaml` (byte-identical, verified by a contract test) |

Notable craft details:

- `WriteTimeout` is derived from the provider budget — a subtle but correct
  coupling documented at the wiring site.
- The shutdown context uses `context.WithoutCancel` to escape the
  signal-cancelled base context — a common Go pitfall handled correctly.
- Compose comments record *why* pins exist (MongoDB 9.x vs kernel 6.19,
  nofile limits, image-tag collision with a sibling project).

---

## 15. Recommendations

Prioritized, with rationale:

1. **Add authentication and rate limiting** (high): the API currently trusts
   the network. Before any public exposure, add an auth middleware and a
   token-bucket limiter — the README itself flags this as the top operational
   risk.
2. **Add CI** (high): the dev loop is already Docker-based and deterministic;
   wiring it into GitHub Actions (`.github/` exists) — build, vet, gofmt
   check, unit tests, race detector — is nearly free and locks the contract
   test into every push.
3. **Metrics exposure** (medium): `log/slog` JSON logs are good; a minimal
   `/metrics` (request count, provider latency, cache hit ratio, pending
   resumes) would make quota burn and cache efficiency observable.
4. **Graceful degradation metrics for the provider** (medium): track
   `provider_*` error rates per code; a spike in `provider_auth_failed` or
   `provider_rate_limited` is operationally urgent.
5. **Consider `GET /api/v1/check-url/{id}`** (low): clients currently resume
   pending analyses by re-POSTing the same URL. An explicit status endpoint
   would make polling semantics first-class.
6. **Document runbook items** (low): Mongo unreachable at runtime, provider
   outage, TTL expiration behavior — the README covers semantics; a short ops
   runbook would complete the picture.

---

## 16. Conclusion

CyberGuard AI is a well-scoped MVP with unusually disciplined engineering for
its size: honest verdict normalization, guarded writes, canonicalized caching,
fail-fast configuration, graceful shutdown, a vendored contract, and a test
suite that fakes the provider rather than calling it. The two real gaps —
authentication and rate limiting on the API itself — are consciously
documented by the project and are the correct first targets before any public
deployment.
