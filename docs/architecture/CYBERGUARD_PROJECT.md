# CyberGuard AI — Project Architecture & Technical Plan

**Version:** 1.1  
**Status:** Initial implementation specification  
**Product:** Open-source URL threat-checking backend + browser extension  
**Backend language:** Go  
**Primary analysis provider:** Hybrid Analysis API v2  
**Database:** MongoDB  
**Queue/cache:** Redis with a Go task-queue adapter, if needed  
**Deployment:** Docker Compose  
**Search engine:** Elasticsearch is optional and deferred until a concrete requirement exists

---

## 1. Project summary

CyberGuard AI is an open-source URL threat-checking backend used by a browser extension. The extension checks its local cache first. If it has no suitable result, it asks the Go backend to check the URL. The backend reuses a fresh stored assessment when possible; otherwise, it creates an asynchronous analysis job and submits the URL to Hybrid Analysis when the configured API key and provider terms permit that workflow.

The backend normalizes provider results into CyberGuard's own verdict model, stores privacy-conscious metadata and a keyed URL fingerprint, and publishes a versioned browser ruleset when an assessment justifies a rule.

**Important scope distinction:** Go is the backend API and worker/orchestration language. Hybrid Analysis is still the external sandbox provider. Rewriting the backend in Go does not make Hybrid Analysis's remote sandbox execute faster; Go gives CyberGuard one backend language and can handle concurrent API/worker tasks efficiently.

### Product principles

1. **Fast path first:** Reuse fresh results; do not start a new remote scan for every request.
2. **Asynchronous analysis:** Do not keep the original HTTP request open for the full analysis lifecycle.
3. **Keep secrets server-side:** Never embed the Hybrid Analysis API key in the extension or frontend assets.
4. **Privacy-conscious storage:** Do not persist raw URLs by default. Use a backend-keyed HMAC fingerprint and redact URLs from logs. The actual URL may be needed transiently for provider submission; minimize its lifetime and protect any queue payload that temporarily contains it.
5. **Clear verdict semantics:** Use `malicious`, `suspicious`, `no_threat_detected`, and `unknown`. Scan status (`queued`, `running`, etc.) is separate from the verdict. Provider errors and timeouts must never be treated as safe.
6. **Rules are not scan records:** The extension's block/redirect rules are a generated, versioned output—not the database itself.
7. **No broad crawling by default:** Analyze the submitted URL and redirects observed by the provider. Do not enumerate arbitrary paths or subdomains unless the target is owned by, or explicitly authorized for testing by, the organization.
8. **Modular monolith first:** Keep one Go codebase with clear internal module boundaries. Run the API and worker as separate processes/binaries using the same application modules.

## 2. MVP scope

### Included

- Go HTTP API with versioned JSON endpoints.
- MongoDB as the source of truth, with indexed URL fingerprints.
- Hybrid Analysis API v2 client behind a provider interface.
- Asynchronous scan lifecycle and duplicate-job prevention.
- URL validation, safe normalization, domain extraction, and HMAC fingerprinting.
- Versioned ruleset endpoint for the browser extension.
- Scan status/result endpoint.
- Docker Compose development environment.
- Health/readiness checks, structured logs, request/scan correlation IDs, and URL redaction.
- Tests for validation, cache hits/misses, duplicate requests, provider failures, and ruleset versioning.

### Explicitly out of scope for the initial MVP

- Building a custom browser sandbox or browser execution farm.
- Scanning every possible path or enumerating every subdomain of a domain.
- Employee accounts, Active Directory, SSO, or a security dashboard unless separately scoped.
- Elasticsearch as a dependency for exact URL fingerprint lookups.
- Guaranteed interception/blocking of every browser navigation. An ordinary extension cannot transparently pause every kind of navigation while waiting for remote analysis; stronger enforcement may require a managed web gateway or network proxy.
- A separate Go microservice solely to call Hybrid Analysis. The Go API/worker can call the provider directly through a provider adapter.

## 3. High-level architecture

```mermaid
flowchart TD
    EXT[Browser Extension] -->|POST URL| API[Go HTTP API]
    EXT -->|GET rules/version| RULES[Ruleset API]
    API --> VALIDATE[URL Validation + Normalization]
    VALIDATE --> FP[HMAC URL Fingerprint]
    FP --> CACHE{Fresh assessment?}
    CACHE -->|Yes| RESULT[Normalized Assessment]
    CACHE -->|No| JOB[Create or reuse scan job]
    JOB --> QUEUE[Redis-backed Queue, if enabled]
    QUEUE --> WORKER[Go Scan Worker]
    WORKER --> HA[Hybrid Analysis Adapter]
    HA --> PROVIDER[Hybrid Analysis API v2]
    PROVIDER --> POLL[Retrieve/poll provider result]
    POLL --> NORMALIZE[Normalize provider result]
    NORMALIZE --> MONGO[(MongoDB: source of truth)]
    NORMALIZE --> RULEGEN[Ruleset Generator]
    RULEGEN --> RULESTORE[(Versioned Ruleset Snapshot)]
    RESULT --> RESPONSE[Extension API Response]
    RULES --> RULESTORE
```

### Component responsibilities

- **Browser extension:** Maintains a bounded local verdict cache and installed ruleset version, requests checks, retrieves scan status, synchronizes rules, and applies supported `declarativeNetRequest` rules.
- **Go HTTP API:** Request validation, routing, rate limiting, scan creation/reuse, status responses, ruleset delivery, and health endpoints.
- **URL Intelligence:** URL validation, carefully defined normalization, hostname/registrable-domain extraction, and HMAC fingerprinting.
- **Scan Management:** Cache lookup, idempotency, state transitions, duplicate-job prevention, timeouts, and retry decisions.
- **Go scan worker:** Executes queue tasks and coordinates submission/polling without blocking API requests.
- **Hybrid Analysis adapter:** Contains all provider-specific authentication, endpoints, request/response types, polling rules, and provider-error translation.
- **Verdict Normalization:** Converts external provider data into CyberGuard's stable result format.
- **Rulesets:** Produces and validates versioned browser rules based on eligible findings.
- **MongoDB:** Authoritative store for scan records, assessment metadata, provider references, and ruleset snapshots.
- **Redis (optional but recommended for async tasks):** Queue broker and short-lived coordination/cache where needed. Do not treat Redis as the authoritative assessment database.
- **Elasticsearch (optional later):** Derived index for large-scale indicator/report search. It is not needed for the primary exact-fingerprint lookup.

## 4. Recommended repository structure

Use idiomatic Go packaging and keep business modules under `internal/` so implementation details are not imported by external applications. Adapt an existing repository's layout if it already has sensible conventions.

```text
cyberguard-ai/
├── cmd/
│   ├── api/
│   │   └── main.go                 # Starts the HTTP API
│   └── worker/
│       └── main.go                 # Starts asynchronous scan workers
├── internal/
│   ├── config/                     # Environment/config parsing and validation
│   ├── transport/
│   │   └── httpapi/
│   │       ├── router.go
│   │       ├── middleware/
│   │       ├── handlers/
│   │       ├── requests/
│   │       └── responses/
│   ├── modules/
│   │   ├── urlintel/               # Validation, normalization, fingerprints, domains
│   │   ├── scans/                  # Scan use cases, state transitions, deduplication
│   │   ├── providers/
│   │   │   └── hybranalysis/       # Provider client, DTOs, polling and errors
│   │   ├── verdicts/               # Canonical verdict model and mapping
│   │   ├── rulesets/               # Browser rules generation and versioning
│   │   └── health/                 # Liveness/readiness use cases
│   ├── platform/
│   │   ├── mongodb/                # MongoDB client, repositories, indexes
│   │   ├── queue/                  # Queue interface + selected adapter
│   │   ├── redis/                  # Redis setup when required
│   │   └── observability/          # Logger, metrics, correlation IDs
│   └── app/                        # Dependency wiring and service composition
├── extension/                      # Separate browser-extension project/build
│   ├── src/
│   │   ├── background/
│   │   ├── popup/
│   │   ├── checking-page/
│   │   ├── blocked-page/
│   │   ├── api/
│   │   ├── rules/
│   │   └── storage/
│   └── manifest.json
├── docs/
│   ├── architecture.md
│   ├── api-contract.md
│   ├── data-model.md
│   ├── module-map.md
│   ├── security-and-privacy.md
│   ├── implementation-plan.md
│   └── decisions/
├── deploy/
│   ├── Dockerfile
│   └── compose.yaml
├── .env.example
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

### Suggested foundational libraries

- **HTTP:** Go standard library `net/http`; consider `github.com/go-chi/chi/v5` for composable routing/middleware without hiding standard HTTP semantics.
- **MongoDB:** Official Go driver (`go.mongodb.org/mongo-driver/v2/mongo`). Verify the driver's Go-version requirement against the Go toolchain selected for the repository.
- **Queue:** Use a small internal queue interface. If using Redis, evaluate a maintained Go task-queue library such as Asynq; check its current release/stability status and operational requirements before committing. It is acceptable to start with synchronous mocked worker logic for the earliest milestone, but do not make provider analysis block normal HTTP handlers.
- **Configuration:** Read environment variables through a small validated config package; avoid a large configuration framework unless needed.
- **Logging:** Use structured logging from the Go standard library (`log/slog`) unless an observed requirement justifies another logger.

Do not create interfaces for every function. Add interfaces at boundaries that need substitution or test doubles: repository, analysis provider, queue, and clock where expiration tests benefit from it.

## 5. Modules and boundaries

### 5.1 `urlintel` — URL Intelligence

**Purpose:** Validate and describe a URL without making provider calls.

Responsibilities:
- Accept only `http` and `https` schemes.
- Reject malformed URLs, embedded credentials, unsupported schemes, and overlong input.
- Normalize deterministically for fingerprinting while preserving meaningful path/query distinctions.
- Remove the fragment from the server-side request identity because fragments are not sent in HTTP requests; document and test this policy.
- Extract hostname and registrable domain with a Public Suffix List-aware library, not a naive “last two labels” algorithm.
- Generate `HMAC-SHA-256` fingerprints using a backend-only secret.
- Never assume different paths or query strings are equivalent unless an explicit, tested policy says so.

Do not casually lowercase paths, remove query parameters, or reorder query values; URL paths and query parameters may affect behavior and may contain sensitive values.

### 5.2 `scans` — Scan Management

**Purpose:** Own scan lifecycle, cache behavior, and idempotency.

Responsibilities:
- Look up a fresh assessment by URL fingerprint.
- Deduplicate concurrent requests for the same fingerprint.
- Create a scan record and queue task when needed.
- Track scan states: `queued`, `submitting`, `submitted`, `running`, `completed`, `failed`, `timed_out`.
- Track attempt count, next retry time, provider scan ID, timestamps, and safe error codes.
- Expose status/result by opaque scan ID.
- Prevent repeated client requests from creating unlimited provider submissions.
- Treat cache expiration as a policy/configuration choice, not a permanent safety guarantee.

### 5.3 `providers/hybranalysis` — Provider integration

**Purpose:** Isolate provider-specific behavior behind a small internal contract.

Suggested Go interface (illustrative; adapt naming to the repository):

```go
type URLAnalysisProvider interface {
    SubmitURL(ctx context.Context, rawURL string) (Submission, error)
    GetAnalysis(ctx context.Context, providerScanID string) (ProviderReport, error)
}
```

Provider adapter responsibilities:
- API base URL and authentication header.
- Exact supported endpoints and request payloads, verified from the current official API v2 docs.
- HTTP client timeouts and response-size limits.
- Provider DTOs separate from internal data models.
- Polling intervals, provider rate limits, terminal statuses, and `Retry-After` behavior.
- Mapping provider failures into safe internal error categories.

Do not spread provider response field names across the codebase. Keep the key in server-side environment configuration or a secret manager. Confirm the API key is permitted to make automated URL submissions before production use.

### 5.4 `verdicts` — Verdict normalization

**Purpose:** Convert provider output to CyberGuard's stable assessment vocabulary.

Canonical verdicts:
- `malicious`
- `suspicious`
- `no_threat_detected`
- `unknown`

Scan state is independent of verdict. A running job has no final verdict. A provider error or incomplete scan must not be converted into `no_threat_detected`.

Store evidence only when it is present in the actual provider response and permitted by provider terms. A clean result means only that the analysis did not identify sufficient threat indicators; it is not proof of safety.

### 5.5 `rulesets` — Extension rule generation

**Purpose:** Convert eligible, current assessments into browser-compatible rules.

Responsibilities:
- Own a monotonically increasing ruleset version.
- Generate and validate supported Chrome `declarativeNetRequest` rules.
- Publish a snapshot with `version`, `generated_at`, and `rules`.
- Increment the version only when effective rules change.
- Support version comparison and/or ETag-based conditional downloads.
- Remove or expire rules when assessments expire or are revoked.
- Never create a block/redirect rule from `unknown`, provider error, expired, or ambiguous findings.

The extension ruleset must not simply be a list of every checked URL. Domain-level rules can affect many pages; prefer the narrowest scope supported by the browser and justified by evidence. Validate rule counts and semantics against current browser limits.

### 5.6 `httpapi` — HTTP transport

**Purpose:** HTTP handlers, request validation, rate limiting, serialization, and errors.

Handlers should remain thin: parse and validate input, invoke module/use-case methods, and serialize the result. Provider polling, cache logic, Mongo queries, and rules generation should not live directly in handler functions.

### 5.7 `observability` and `health`

Provide:
- `GET /health/live`: process is alive.
- `GET /health/ready`: required dependencies can be reached.
- Structured logs with request/scan correlation IDs.
- Metrics for cache hit rate, queue age, provider latency, retries, failures, timeouts, and polling volume.
- Redaction of raw URLs, query strings, API keys, and provider secrets.
- Graceful shutdown with bounded timeouts for API and worker processes.

## 6. API contract

Use versioned routes. The requested names are retained below, while their purposes are explicit.

### 6.1 `POST /api/v1/check-url`

Checks for a usable assessment or creates/reuses an asynchronous scan.

Request:

```json
{
  "url": "https://example.test/login"
}
```

If a fresh assessment exists (`200 OK`):

```json
{
  "scan_id": "scan_01ABC",
  "status": "completed",
  "cached": true,
  "verdict": "suspicious",
  "expires_at": "2026-10-17T12:00:00Z"
}
```

If the scan is queued (`202 Accepted`):

```json
{
  "scan_id": "scan_01XYZ",
  "status": "queued",
  "cached": false,
  "status_url": "/api/v1/get-url/scan_01XYZ"
}
```

Examples are illustrative. Use reserved test domains for automated tests.

### 6.2 `GET /api/v1/get-url/{scanId}`

Returns the current state and, when available, the normalized result. Use an opaque scan ID instead of a full URL in the route.

```json
{
  "scan_id": "scan_01XYZ",
  "status": "completed",
  "verdict": "malicious",
  "provider": "hybrid-analysis",
  "evidence": [
    {
      "type": "provider_verdict",
      "summary": "Provider returned a malicious classification"
    }
  ],
  "analyzed_at": "2026-10-16T12:00:00Z",
  "expires_at": "2026-10-17T12:00:00Z"
}
```

Never fabricate evidence. Populate it only from actual provider output normalized by the provider adapter.

### 6.3 `GET /api/v1/get-all?version={clientVersion}`

Returns the current **browser ruleset**, not every URL stored in MongoDB.

If the client's ruleset is unchanged, use `304 Not Modified` with `ETag`/`If-None-Match`, or return a documented small unchanged response. Otherwise:

```json
{
  "version": 12,
  "generated_at": "2026-10-16T12:00:00Z",
  "rules": []
}
```

Validate the generated rule format before publishing. Do not expose raw URLs or unrelated scan records in the rules response.

### 6.4 General API behavior

- Use request body size limits and URL length limits.
- Apply rate limiting and duplicate-job controls.
- Return consistent JSON error objects.
- Do not expose provider keys, raw provider headers, stack traces, or infrastructure details.
- CORS is not authentication; before public deployment, define an abuse-control and client-trust strategy appropriate to the product.
- Avoid raw URLs in route paths and query strings because they can leak into proxies and logs.

## 7. MongoDB data model

MongoDB is the authoritative store.

### `url_assessments` collection

Suggested document:

```json
{
  "_id": "assessment_01ABC",
  "url_fingerprint": "hmac-sha256-value",
  "hostname": "example.test",
  "registrable_domain": "example.test",
  "verdict": "suspicious",
  "scan_status": "completed",
  "provider": "hybrid-analysis",
  "provider_scan_id": "provider-id",
  "evidence_summary": [],
  "analyzed_at": "2026-10-16T12:00:00Z",
  "expires_at": "2026-10-17T12:00:00Z",
  "created_at": "2026-10-16T12:00:00Z",
  "updated_at": "2026-10-16T12:00:00Z"
}
```

Raw URL is deliberately absent. The raw URL is needed temporarily for provider submission. If an asynchronous queue needs it, prefer a short-lived encrypted payload, minimize retention, restrict access, and ensure logs never print it. Delete the transient value as soon as submission no longer requires it. A fingerprint is not encryption and does not guarantee anonymity.

Suggested indexes:
- Unique index on `url_fingerprint` for exact-URL assessments.
- Index on `hostname` for host-level lookups.
- Index on `registrable_domain` for domain intelligence.
- Index on `expires_at` for selecting expired assessments and cleanup where deletion is appropriate.
- Index on `scan_status` and timestamps for job recovery and operational queries.

Keep exact-URL verdicts separate from hostname/domain reputation. Do not infer that all paths or subdomains are safe or malicious based solely on one URL's result.

### Transient scan jobs

A job record may contain scan metadata, status, attempt count, timestamps, provider scan ID, and a reference to an encrypted short-lived submission payload if necessary. Avoid storing a long-lived copy of raw URLs. Define cleanup behavior and recovery of jobs after a worker restart.

## 8. Elasticsearch decision

Do **not** make Elasticsearch a required MVP dependency for exact fingerprint lookup. MongoDB's indexed lookup is sufficient for that workflow.

Consider Elasticsearch later if the product needs large-scale cross-report searching, IOC exploration, complex filtering, or search across normalized security evidence. If added, treat it as a rebuildable derived index, not the source of truth. Avoid maintaining a second index until query volume and real use cases justify its operational cost.

## 9. Scan lifecycle and reliability

Suggested sequence:

1. Accept the request and validate the URL.
2. Apply URL normalization and compute the HMAC fingerprint.
3. Look up a fresh assessment.
4. If one exists, return it without provider submission.
5. If a scan for the same fingerprint is already in progress, return/reuse its scan ID.
6. Otherwise, create a scan and enqueue an idempotent task.
7. Worker submits the URL through the Hybrid Analysis adapter, if permitted by key privileges and provider terms.
8. Persist the provider scan ID and status.
9. Poll according to current documented provider behavior and rate limits, using bounded backoff.
10. Normalize the provider's terminal result.
11. Persist the assessment and expiry.
12. Regenerate/publish the ruleset only when the effective rules change.
13. Client polls the status endpoint or uses a future push mechanism if added later.

Reliability requirements:
- Use request-level and provider-level timeouts.
- Respect `Retry-After` when present.
- Retry transient network errors and selected 5xx/429 responses with bounded backoff.
- Do not retry invalid requests or authorization failures indefinitely.
- Prevent duplicate submissions for concurrent equivalent requests.
- Use idempotency keys or atomic conditional updates where appropriate.
- Provide graceful shutdown and worker recovery.
- Make TTL/expiry values configurable and verdict-aware; a cached result is not a permanent guarantee of safety.

## 10. Browser extension integration

- Keep a bounded local cache of recent verdicts and the installed ruleset version.
- Use extension-supported storage APIs such as `chrome.storage.local`, not page `localStorage`, for extension-owned state.
- Fetch the ruleset only when its version changes, using version comparison and/or conditional requests.
- Validate rule formats and counts before applying them.
- Apply rules using the supported browser API such as Chrome's `declarativeNetRequest`.
- Only create rules from eligible, current findings and use the narrowest justified scope.
- Do not assume the extension can transparently pause every type of navigation while awaiting a remote API. Strict enforcement may require a managed proxy or secure web gateway.
- Never include the Hybrid Analysis API key in extension JavaScript, storage, configuration bundled with the extension, or frontend build variables.

## 11. Security and privacy requirements

1. Accept only HTTP/HTTPS URL schemes and reject malformed or credential-bearing URLs.
2. Avoid fetching arbitrary URLs from the backend itself; provider submission is different from server-side browsing. If self-fetching is introduced later, design explicit SSRF-safe egress controls.
3. Do not enumerate arbitrary paths or subdomains. Analyze the submitted URL and provider-observed redirects by default.
4. Do not retain raw URLs by default. Where transient retention is unavoidable, encrypt, minimize lifetime, and restrict access.
5. Redact URLs/query strings, API keys, and secrets from logs, traces, errors, and analytics.
6. URLs submitted to Hybrid Analysis are disclosed to an external service. Do not send confidential internal URLs without authorization and provider-term review.
7. Protect the API from abuse with request limits, rate limits, quotas, and an appropriate client trust strategy.
8. Treat provider responses as untrusted input: validate schema, lengths, identifiers, and status values.
9. Never turn `unknown`, timeout, or provider error into a safe verdict.
10. Keep dependency and image updates part of maintenance.
11. Do not expose MongoDB, Redis, Elasticsearch, or worker-control ports publicly by default.
12. Use non-root containers, minimal images, read-only filesystems where practical, and graceful shutdown.
13. Avoid mounting the Docker socket into any application or worker container.

## 12. Configuration and secrets

Example `.env.example` (names may be adjusted during implementation):

```env
APP_ENV=local
HTTP_ADDR=:8080
LOG_LEVEL=info

MONGODB_URI=mongodb://mongodb:27017
MONGODB_DATABASE=cyberguard

REDIS_ADDR=redis:6379
REDIS_PASSWORD=
QUEUE_ENABLED=true

HYBRID_ANALYSIS_BASE_URL=https://www.hybrid-analysis.com/api/v2
HYBRID_ANALYSIS_API_KEY=
URL_FINGERPRINT_HMAC_KEY=

ELASTICSEARCH_ENABLED=false
ELASTICSEARCH_URL=http://elasticsearch:9200
```

Never commit `.env`, production API keys, HMAC keys, or production secrets. Use separate local and production credentials. Verify exact provider endpoint paths, required headers, payload parameters, and automated-submission permissions against the official API v2 documentation before implementing the real client.

## 13. Docker Compose topology

Initial services:
- `api`: Go HTTP API binary.
- `worker`: Go worker binary built from the same codebase/image, with a separate command/entrypoint.
- `mongodb`: source-of-truth data store.
- `redis`: queue broker if the chosen queue implementation uses Redis.

Optional later service:
- `elasticsearch`: derived search index only when justified.

Requirements:
- Internal services connect through Compose service names such as `mongodb` and `redis`, not `localhost` from another container.
- Publish only the API port for local development by default.
- Keep MongoDB, Redis, and Elasticsearch on an internal network.
- Add health checks and dependency readiness handling.
- Use persistent volumes for MongoDB; document that volumes alone are not backups.
- Use multi-stage Docker builds, minimal runtime images, and a non-root user where practical.
- Avoid mounting the Docker socket into application containers.
- Provide a single Go binary with commands such as `api` and `worker`, or separate binaries built from `cmd/api` and `cmd/worker`.

## 14. Testing strategy

### Unit tests
- URL validation and normalization.
- HMAC fingerprint stability and secret handling.
- Domain extraction for public suffix edge cases.
- Provider response-to-verdict mapping.
- Ruleset generation and version changes.
- Expiration and state-transition rules.

### Integration tests
- A fresh cached assessment returns without provider submission.
- A cache miss creates exactly one task.
- Concurrent duplicate requests reuse an in-progress scan.
- MongoDB indexes are created and used as expected.
- Worker recovers after transient provider errors.
- Provider 401, 403, 429, 5xx, timeout, malformed payload, and unknown status are handled safely.
- Raw URLs and secrets are absent from logs.
- Ruleset endpoint returns unchanged state when the version is current and a new snapshot when rules change.

### Extension tests
- Valid rules snapshots are applied.
- Unchanged rulesets are not downloaded repeatedly.
- Malformed or unsupported rules are rejected.
- Backend offline/timeouts result in `unknown`/inconclusive UX rather than “safe”.

Use mocked provider responses for automated tests. Do not submit arbitrary live URLs during test runs.

## 15. Implementation milestones

### Milestone 1 — Go foundation
- Initialize `go.mod` and the repository layout.
- Select and pin compatible versions of Go dependencies.
- Add configuration validation, `log/slog`, HTTP router, graceful shutdown, and health endpoints.
- Add Docker Compose with API, MongoDB, and optional Redis.
- Add CI format/lint/test commands (`gofmt`, `go vet`, unit tests, and any selected linter).

### Milestone 2 — URL Intelligence + MongoDB
- Implement URL validation and tested normalization rules.
- Implement HMAC fingerprinting.
- Implement MongoDB connection, repositories, indexes, and assessment lookup.
- Add cache-hit behavior and expiry handling.

### Milestone 3 — Scan Management + worker
- Define scan states and transitions.
- Implement atomic deduplication for concurrent requests.
- Add the queue adapter and worker.
- Implement safe retry/backoff and provider failure mapping.

### Milestone 4 — Hybrid Analysis adapter
- Verify API-key permissions and automated-submission requirements.
- Implement the provider client from the current official API v2 contract.
- Add mocked provider tests and polling behavior.
- Normalize provider results into internal verdicts.

### Milestone 5 — Ruleset API
- Generate supported browser rules.
- Publish a monotonically versioned snapshot.
- Add version/ETag-based synchronization.
- Ensure rule scope is narrow and only supported verdicts create rules.

### Milestone 6 — Extension integration
- Connect extension to `POST /check-url`.
- Implement scan-status polling/checking page.
- Cache recent verdicts locally.
- Download and apply versioned dynamic rules.

### Milestone 7 — Hardening
- Rate limits, timeouts, provider quotas, URL/log redaction, metrics, recovery tests, and security review.
- Add Elasticsearch only if measured search requirements justify it.
- Consider a custom Go sandbox orchestrator only if CyberGuard plans to replace or supplement the external analysis provider.

## 16. Definition of done for MVP

- A URL sent by the extension reaches the Go API.
- Invalid URL schemes and malformed inputs are rejected.
- A fresh cached result is reused without duplicate provider submission.
- A cache miss creates one asynchronous task.
- Provider responses map to CyberGuard's stable scan-state/verdict model.
- The extension can retrieve scan status and a completed assessment.
- The extension downloads only changed rulesets.
- Failed, expired, and inconclusive results are never mislabeled as safe.
- API keys remain server-side and do not appear in logs.
- MongoDB and Redis ports are not exposed publicly by default.
- Tests cover cache behavior, concurrent deduplication, provider errors, and ruleset versioning.

## 17. Architecture decisions

| Decision | Initial choice | Reason |
|---|---|---|
| Backend | Go modular monolith | One language for API and worker, with explicit module boundaries |
| HTTP | `net/http`, optionally with `chi` | Idiomatic HTTP and small routing layer |
| Sandbox | Hybrid Analysis API | Avoid building and securing a custom sandbox in the initial version |
| Data store | MongoDB | Flexible provider metadata and indexed assessment lookup |
| Queue | Queue interface + Redis-backed implementation if needed | Keeps long-running provider work outside request handlers and permits later replacement |
| Search | MongoDB indexes first; Elasticsearch optional | Avoid unnecessary infrastructure for exact lookups |
| Raw URLs | Not retained by default | Reduces exposure of sensitive query parameters and tokens |
| Scan execution | Asynchronous worker | Supports retries, polling, and duplicate-job controls |
| Extension rules | Versioned ruleset snapshot | Avoids repeatedly downloading unchanged rules and separates enforcement data from scan history |

## 18. Official references

- Hybrid Analysis API v2: https://hybrid-analysis.com/docs/api/v2
- Hybrid Analysis automated-submission API key guidance: https://www.hybrid-analysis.com/knowledge-base/issuing-full-api-key-for-automated-submissions
- MongoDB Go Driver: https://www.mongodb.com/docs/drivers/go/current/
- MongoDB Go Driver repository: https://github.com/mongodb/mongo-go-driver
- `chi` HTTP router: https://github.com/go-chi/chi
- Asynq Go task queue: https://github.com/hibiken/asynq
- Chrome `declarativeNetRequest`: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

**Implementation instruction:** Treat this document as the initial source of truth. Verify current provider/browser behavior and selected dependency compatibility against official documentation before coding. If a detail differs from vendor documentation, record the decision in `docs/decisions/` before implementation.
