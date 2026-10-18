# CyberGuard AI — backend

A small Go REST API that checks a URL against Hybrid Analysis's quick-scan
endpoint and reuses the stored result in MongoDB. Two endpoints, one
collection, no queues, no workers. Everything runs in one process.

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

## Endpoints

| Method | Path                 | Purpose                                                       | Success   |
| ------ | -------------------- | ------------------------------------------------------------- | --------- |
| POST   | `/api/v1/check-url`  | Check a URL: cache first, provider only when needed           | `200` or `202` |
| GET    | `/api/v1/get-all`    | List stored assessments, newest stored first                  | `200`     |
| GET    | `/health/live`       | Liveness: is the process serving                              | `200`     |
| GET    | `/health/ready`      | Readiness: process **and** MongoDB reachable                   | `200`     |
| GET    | `/openapi.yaml`      | The OpenAPI 3 contract (byte-identical commit)                | `200`     |
| GET    | `/docs/`             | Swagger UI rendering that contract                            | `200`     |

Swagger UI: <http://localhost:8080/docs/> — fully vendor-embedded, no CDN, no
external requests. Raw contract: <http://localhost:8080/openapi.yaml>.

Health shapes: `/health/live` → `{"status":"ok"}`. `/health/ready` →
`{"status":"ready","checks":{"mongodb":"ok","provider":"configured"}}`, or
`503` with `"status":"not_ready"` when MongoDB is unreachable, and
`checks.provider` spelling out `HYBRID_ANALYSIS_API_KEY is not set` when the
key is absent (readiness marks it, but the process still serves).

## How check-url works

1. **Canonicalize once.** The URL is trimmed, scheme/host are lowercased,
   default ports (`:80`/`:443`) and fragments are dropped; path and query stay
   byte-for-byte intact, so signed links keep validating. The SHA-256 of the
   canonical form is the cache key — lookups, stored records and the provider
   submission all use the same canonical URL.
2. **MongoDB first.**
   - A **completed** assessment inside the cache lifetime (`ASSESSMENT_TTL`,
     default 24h) is returned immediately (HTTP 200). The provider is not
     contacted at all.
   - A **pending** record (provider accepted, `finished: false`) reuses its
     existing provider id and polls the documented retrieval endpoint instead
     of submitting the URL again. Pending records older than the TTL are
     submitted once more, in place (never a second record).
3. **Provider, only when needed.** `POST /quick-scan/url`, exactly once per
   request, never retried (the endpoint has no idempotency token).
4. **Retrieve the final result.** When the submission answers
   `finished: false`, the documented `GET /quick-scan/{id}` is polled — first
   immediately, then every `HYBRID_ANALYSIS_POLL_INTERVAL` — until the provider
   reports `finished: true`, the request budget (based on
   `HYBRID_ANALYSIS_TIMEOUT`) runs out, or the provider fails.
5. **Persist honestly, at most forward.** A finished result is normalized
   (below) and saved with a guarded update so a completed assessment can never
   be overwritten by pending data. Unknown concurrent requests for the same
   canonical URL converge on one record inside the process and via the
   unique `uniq_url_hash` index across processes.

Responses:

- **HTTP 200** — `"URL analysis completed"`: a completed assessment is in the
  response, served from cache or obtained during this request.
- **HTTP 202** — `"Analysis is still in progress"`: the provider has not
  finished within the budget. `data.status` is `pending`, `data.verdict` is
  `null`; the next call with the same URL resumes the existing assessment.

## Verdict normalization

The provider's quick scan has no aggregate verdict field — it reports
per-scanner statuses (`scanners_v2`, plus the deprecated `scanners` array
classified by the same rules). A verdict is computed only from a
`finished: true` response, by this ladder, never guessed and never hardcoded:

| Scanner status text (case-insensitive)            | Evidence      |
| ------------------------------------------------- | ------------- |
| contains `malicious`                              | malicious     |
| contains `suspicious`                             | suspicious    |
| `no specific threat` / `no threat` / `clean` / `whitelist` | benign |
| `error`, or a non-null `errorMessage` on an unclassified entry | errored |
| anything else (`no-classification`, `in-queue`, empty, unrecognized) | unresolved |
| `null` or unusable entry (scanner never produced data) | missing — **not** benign |

1. any malicious evidence → `malicious`
2. else any suspicious evidence → `suspicious` (worst evidence wins over clean)
3. else benign evidence with no unresolved and no errored scanners left →
   `no_threat_detected`
4. else unresolved or errored scanners remain → `inconclusive`
5. else nothing usable evaluated (every entry missing) → `unknown`

`verdict` is `null` while `status` is `pending`. Provider errors are never
read as verdicts; a SHA-256 digest with no scanner evidence proves nothing;
`scannersV2` itself is verbatim passthrough of provider data.

## Quick start

### Docker (recommended — no host Go needed)

```sh
cp .env.example .env         # then put your Hybrid Analysis key in .env
docker compose up -d --build # starts MongoDB + the API on :8080
```

### Host (needs Go 1.27 and a running MongoDB)

```sh
go run ./cmd/api             # reads .env in the working directory
```

MongoDB on the host:

```sh
docker run -d --name cyberguard-mongodb -p 27017:27017 mongo:9.0
```

The server starts without MongoDB running by **failing** at launch — it pings
the database through the connection, so a wrong `MONGODB_URI` is a startup
error, not a runtime mystery.

## Configuration (`.env`)

Every variable is optional; sensible defaults fit `docker compose`.

| Variable                         | Default                                  | Meaning                                                                                        |
| -------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `APP_PORT`                       | `8080`                                   | HTTP port (host port under Compose; the container always listens on 8080)                       |
| `MONGODB_URI`                    | `mongodb://localhost:27017`              | MongoDB connection string (Compose overrides to `mongodb://mongodb:27017`)                      |
| `MONGODB_DATABASE`               | `cyberguard`                             | Database name (one collection: `url_submissions`)                                               |
| `HYBRID_ANALYSIS_BASE_URL`       | `https://hybrid-analysis.com/api/v2`     | Provider base URL — see the "no www" note under Limitations                                     |
| `HYBRID_ANALYSIS_API_KEY`        | *(empty)*                                | Hybrid Analysis API key. Without it check-url answers `503 provider_not_configured`             |
| `HYBRID_ANALYSIS_TIMEOUT`        | `30s`                                    | Per-request provider budget (max `5m`); also bounds the whole check-url wait for a final result |
| `HYBRID_ANALYSIS_SCAN_TYPE`      | `all`                                    | Optional: documented `scan_type` value, validated at startup against the provider's enum         |
| `HYBRID_ANALYSIS_POLL_INTERVAL`  | `1s`                                     | Pause between result retrievals while one request waits (`> 0`, at most `1m`)                    |
| `ASSESSMENT_TTL`                 | `24h`                                    | How long a completed assessment stays reusable as a cached result (`> 0`, at most `336h`)         |
| `CORS_ALLOWED_ORIGINS`           | `http://localhost:3000,http://localhost:5173` | Exact allowed origins, comma separated. `*` is rejected at startup                          |

The key is read from the environment (or `.env`) and used **only** in the
provider request header. It is never logged, never stored, and never appears
in any API response.

## Using the API

### Check a URL — `curl`

```sh
curl -sS -X POST http://localhost:8080/api/v1/check-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'
```

`200` — a completed assessment is available (from cache or finished in this
request); `202` — still pending:

```json
{
  "success": true,
  "message": "URL analysis completed",
  "data": {
    "id": "68f2b4c1a3e6f9001234abcd",
    "url": "https://example.com",
    "provider": "hybrid-analysis",
    "providerId": "120-abcdef123456…",
    "sha256": "…64 hex…",
    "scanType": "all",
    "status": "completed",
    "finished": true,
    "scannersV2": { "…provider passthrough…": {} },
    "reports": ["…"],
    "verdict": "no_threat_detected",
    "createdAt": "2026-10-17T12:34:56.789Z",
    "updatedAt": "2026-10-17T12:34:56.789Z"
  }
}
```

- `id` is the MongoDB document ID; `providerId` is the provider's own ID and
  the handle a pending resume polls.
- `status` is `completed` only when the provider reported `finished: true`;
  otherwise `pending` (message `"Analysis is still in progress"`, HTTP 202).
  Records written by older versions read `submitted` until they are touched;
  they behave exactly like `pending`.
- `verdict` is `null` while pending, otherwise one of the documented values
  above (`malicious`, `suspicious`, `no_threat_detected`, `inconclusive`,
  `unknown`), derived only from a `finished: true` provider response.

Calling the same URL twice costs at most one provider submission: the second
call is answered from MongoDB until the cached assessment expires
(`ASSESSMENT_TTL`), after which it is assessed again — in place.

### List assessments — `curl`

```sh
curl -sS 'http://localhost:8080/api/v1/get-all?page=1&limit=20'
```

```json
{
  "success": true,
  "data": [ { "…assessment as above…" } ],
  "pagination": { "page": 1, "limit": 20, "total": 1, "totalPages": 1 }
}
```

`page` starts at 1 (max 1,000,000; out-of-range is `400`), `limit` defaults to
20 and caps at 100. Unknown or malformed parameters are `400` with the common
error shape — nothing is silently clamped. An empty result set returns
`data: []`, never `null`. Records are sorted by their last update time, so a
record that just obtained its final result sorts near the top.

### From JavaScript

```js
async function checkURL(url) {
  const res = await fetch("/api/v1/check-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const body = await res.json();
  if (!body.success) throw new Error(`${body.error.code}: ${body.message}`);
  return body.data; // { id, status, verdict, scannersV2, ... }
  // status === "pending" ⇒ try again later; the same call resumes it.
}

async function listSubmissions(page = 1, limit = 20) {
  const res = await fetch(`/api/v1/get-all?page=${page}&limit=${limit}`);
  const body = await res.json();
  if (!body.success) throw new Error(`${body.error.code}: ${body.message}`);
  return body; // { data: [...], pagination: {...} }
}
```

CORS is enforced strictly: only origins in `CORS_ALLOWED_ORIGINS` receive
`Access-Control-Allow-Origin`, OPTIONS preflight is answered, `*` is
explicitly impossible.

### Errors

Every failure is one shape:

```json
{
  "success": false,
  "message": "…safe, client-facing reason…",
  "error": { "code": "invalid_request", "status": 400 }
}
```

| Code                      | HTTP | When                                                                 |
| ------------------------- | ---- | -------------------------------------------------------------------- |
| `invalid_request`          | 400  | Bad JSON, bad `page`/`limit` parameters                              |
| `validation_error`         | 422  | URL parsed but rejected (empty, too long, unsupported scheme, no host, control chars) |
| `provider_not_configured`  | 503  | No API key configured                                                |
| `provider_auth_failed`     | 502  | Provider rejected the configured API key                             |
| `provider_rate_limited`    | 429  | Provider throttled the request (`Retry-After` header when known)     |
| `provider_timeout`         | 504  | Provider exceeded `HYBRID_ANALYSIS_TIMEOUT` (never auto-retried)     |
| `provider_rejected`        | 502  | Provider refused the request (submission or unknown scan id)         |
| `provider_unavailable`     | 502  | Provider unreachable (network error)                                 |
| `provider_bad_response`    | 502  | Provider answered unparseable JSON                                   |
| `request_in_progress`      | 503  | An equivalent request for this URL is being analysed; retry shortly  |
| `store_unavailable`        | 503  | MongoDB insert/read failed                                           |
| `method_not_allowed`       | 405  | Wrong verb on an existing path                                       |
| `not_found`                | 404  | Unknown path                                                         |

Provider error details are logged server-side (with request ID and cause);
the response body only ever carries the safe message and the code above.
Provider errors never fabricate a verdict, and a pending record simply stays
pending through them.

## Development

The Go toolchain runs inside Docker (the host needs none):

```sh
docker compose run --rm go gofmt -l cmd internal docs        # formatting
docker compose run --rm go go vet ./...                     # static analysis
docker compose run --rm go go build ./...                   # compiles everything
docker compose run --rm go go test -count=1 ./...           # unit tests (httptest only)
docker compose run --rm go go mod tidy                      # dependency hygiene
docker compose run --rm go go test -race ./...              # race detector (needs gcc: debian image)
```

One integration test needs a real MongoDB and is skipped otherwise:

```sh
docker compose run --rm go \
  go test -count=1 -run TestStore ./internal/mongodb      # needs MONGO_TEST_URI
# or, inside the compose network:
docker compose run --rm \
  -e MONGO_TEST_URI=mongodb://mongodb:27017 \
  go go test -count=1 -run TestStore ./internal/mongodb
```

No test ever contacts Hybrid Analysis — provider behaviour is faked with
`httptest` servers, including success, auth failure, rate-limit, slow
response and malformed body cases.

The container listens on 8080; `APP_PORT` selects the published host port but
not the container's (docker-compose.yml pins the in-container value to 8080):

```sh
APP_PORT=9000 docker compose up -d --build
curl -sS http://localhost:9000/health/ready
```

## Layout

```
cmd/api/               the one binary: config, wiring, graceful shutdown
internal/config/       environment + .env parsing, validation, CORS
internal/handlers/     HTTP layer: routing, envelopes, errors, 200/202, Swagger UI
internal/services/     check-url orchestration, verdict normalization, error mapping
internal/hybridanalysis/  the provider client (POST /quick-scan/url + GET /quick-scan/{id})
internal/mongodb/      connection and the store: cache lookups, guarded writes, listing
internal/models/       the document/response shapes (single source of truth)
internal/docs/assets/  vendored Swagger UI
docs/openapi.yaml      the contract served at /openapi.yaml
```

## Limitations

- **No `www` in the base URL.** The v2 specification declares
  `https://hybrid-analysis.com/api/v2`; the `www` host answers `301` to it,
  and a Go client does not replay a POST body across that redirect, so `www`
  would break every scan. Keep the default.
- **Quick scan surface only.** The provider's quick scan is not the full
  sandbox analysis. Final results come from the documented retrieval endpoint
  (`GET /quick-scan/{id}`) polled inside one request; nothing else is called —
  no quota probes, no search, no feeds.
- **One request, one budget.** A pending analysis is answered `202` when the
  request budget runs out; it stays pending (and reusable) until a later call
  finishes it or it ages past `ASSESSMENT_TTL` and is re-submitted in place.
- **Provider retention is not ours.** If the provider stops knowing a pending
  quick scan id, retrieval reports `provider_rejected` and the record stays
  pending until its TTL re-submission. The provider's own retention windows
  are outside this service's control.
- **Provider failures are not stored.** A failed request persists nothing
  false; an existing pending record stays pending, a completed one is
  untouched.
- **Single-process coordination.** Equivalent requests are collapsed inside
  the API process; across replicas the unique index keeps the store
  consistent (losers adopt the winner's record), but two replicas may both
  submit once on a cold URL. Never auto-retried.
- **No authentication or rate limiting on the API itself.** CORS restricts
  *which pages* can call, not *how often*. Behind a public load balancer add
  auth throttling before exposing check-url.
- **Submissions are never retried.** A failed provider call is reported back
  as-is; the caller decides whether to try again (each attempt may consume
  provider quota). Result retrieval differs — it is a read, retried only by
  the poll loop inside one request.
- **Licensing.** Automated submission requires Hybrid Analysis usage approval
  before commercial release — confirm your account's terms first.

Anything older under `docs/` (architecture, ADRs, prior contract notes) is
historical record from the previous, larger incarnation of this service and
no longer reflects the current code.
