# OpenCode Prompt — CyberGuard AI Go Architecture

Copy this prompt into OpenCode from the project repository.

---

Act as a Senior Software Architect and Go Backend Engineer with 10+ years of experience designing secure, modular Go services, asynchronous workers, browser-extension backends, MongoDB data models, and external security-provider integrations.

## Project context

Read `CYBERGUARD_PROJECT.md` completely before making architecture decisions.

CyberGuard AI is an open-source URL threat-checking backend used by a browser extension. The extension checks its local verdict cache. If no suitable result exists, it sends the URL to the Go backend. The backend checks MongoDB, returns fresh stored results when available, or creates/reuses an asynchronous analysis job that submits the URL to Hybrid Analysis API v2 when permitted by the configured key and provider terms. The backend normalizes results, stores privacy-conscious metadata and a keyed URL fingerprint, and distributes a versioned browser ruleset.

## Fixed initial stack

- Go backend (no Laravel, no PHP backend).
- Go HTTP API using `net/http`; `chi` is a candidate router, not a mandatory choice.
- MongoDB using the official Go driver; verify Go and driver compatibility before pinning versions.
- Redis and a Go queue library such as Asynq only if justified for asynchronous job handling; isolate the queue behind an internal interface.
- Hybrid Analysis API v2 as the initial external analysis provider.
- Docker Compose.
- Browser extension using supported browser APIs such as Chrome `declarativeNetRequest`.
- Elasticsearch is optional and must not be included in the MVP unless a concrete search/analytics requirement justifies it.

Go is the API and worker/orchestration language. Hybrid Analysis remains the external sandbox. Do not claim that writing the HTTP client in Go speeds up the provider's remote analysis.

## Primary task

Inspect the existing repository before modifying files. Design the architecture and produce documentation first. Do not implement all runtime features in one large change.

### 1. Repository inspection

- Inspect directory layout, `go.mod`, existing code, tests, Docker files, CI, extension code, and project docs.
- Reuse existing conventions when sensible; do not restructure blindly.
- Never print `.env` or secret values.
- State assumptions and non-blocking unknowns in documentation rather than blocking on questions unnecessarily.

### 2. Go modular architecture

Design a modular monolith with separate API and worker processes built from the same Go codebase. Consider this structure and adapt it based on the actual repository:

```text
cmd/
  api/main.go
  worker/main.go
internal/
  config/
  app/
  transport/httpapi/
    middleware/
    handlers/
    requests/
    responses/
  modules/
    urlintel/
    scans/
    providers/hybranalysis/
    verdicts/
    rulesets/
    health/
  platform/
    mongodb/
    queue/
    redis/
    observability/
extension/
docs/
deploy/
```

Define module responsibilities, public interfaces, data ownership, and allowed dependency direction. Avoid over-abstraction. Add interfaces at meaningful boundaries such as the provider, repository, and queue, where tests or substitution benefit.

### 3. Architecture documents

Create or update these documents:

1. `docs/architecture.md`
   - Context, goals, architecture diagram, sequence diagram, trust boundaries, deployment topology, API and worker flow.
2. `docs/api-contract.md`
   - Request/response contracts, status codes, validation, error shape, rate limits, and idempotency.
3. `docs/data-model.md`
   - MongoDB collections, indexes, retention, state machine, HMAC fingerprint approach, and ruleset versioning.
4. `docs/module-map.md`
   - Each module's purpose, directories, main types, interfaces, tests, and dependencies.
5. `docs/security-and-privacy.md`
   - URL privacy, provider data disclosure, secret management, abuse protection, timeouts, retries, log redaction, and browser-rule limitations.
6. `docs/implementation-plan.md`
   - Small milestones with acceptance criteria and risks.
7. `docs/decisions/`
   - Architecture Decision Records for Go modular monolith, MongoDB source of truth, asynchronous provider integration, raw-URL minimization, and deferring Elasticsearch/custom sandbox until justified.

Update existing documents rather than creating duplicate competing specifications.

### 4. Required API contracts

Use the current project's routes if already depended upon; otherwise document these proposed versioned routes:

- `POST /api/v1/check-url`: validate the URL; return a fresh assessment (`200`) or create/reuse asynchronous scan (`202`).
- `GET /api/v1/get-url/{scanId}`: retrieve scan status/result by opaque ID.
- `GET /api/v1/get-all?version={clientVersion}`: retrieve the current extension ruleset, not all scan documents. Support an unchanged-version/ETag response.
- `GET /health/live` and `GET /health/ready`.

Keep scan status separate from verdict. Possible statuses: `queued`, `submitting`, `submitted`, `running`, `completed`, `failed`, `timed_out`. Possible verdicts: `malicious`, `suspicious`, `no_threat_detected`, `unknown`. Provider errors, timeouts, expired records, and inconclusive analysis must never be reported as safe.

### 5. URL processing and MongoDB

- Accept only HTTP/HTTPS.
- Reject malformed URLs, embedded credentials, unsupported schemes, and excessive length.
- Use deterministic URL normalization and preserve meaningful path/query distinctions.
- Use a Public Suffix List-aware library to extract registrable domains.
- Generate a backend-keyed HMAC-SHA-256 fingerprint.
- Do not persist raw URLs by default. If raw URLs must survive in queue payloads to submit to the provider, encrypt the transient payload, minimize retention, keep it out of logs, and delete it once no longer needed.
- Treat hashes as pseudonymous identifiers, not encryption or guaranteed anonymity.
- Create a unique index for exact-URL fingerprints and indexes needed for host/domain lookup, expiry, and scan recovery.
- Do not assume that different paths/subdomains are equivalent.

### 6. Hybrid Analysis adapter

Before implementing provider calls, read `https://hybrid-analysis.com/docs/api/v2` and verify exact endpoints, headers, payload fields, scan status behavior, polling constraints, quotas, and API-key permissions for automated URL submission.

Encapsulate provider details in `internal/modules/providers/hybranalysis`. Use Go `context.Context`, bounded `http.Client` timeouts, response-size limits, retry/backoff only for retryable failures, and typed internal errors. Do not fabricate provider fields or hard-code unverified assumptions. Keep the API key server-side.

### 7. Async worker and queue

- Do not keep the API request open for the entire remote analysis lifecycle.
- Prevent duplicate concurrent scans for the same canonical fingerprint.
- Use bounded retries and respect `Retry-After` when present.
- Use a queue interface so the implementation can be changed.
- Evaluate a Redis-backed Go task queue such as Asynq, checking current status/compatibility before committing.
- Implement graceful shutdown and worker recovery.
- Treat MongoDB as the source of truth; queue/cache data is transient coordination state.

### 8. Ruleset generation and extension behavior

- Generate supported and validated browser rules from eligible current findings only.
- Increment the ruleset version only when effective rules change.
- Remove/expire rules when a verdict is stale or revoked.
- Apply the narrowest supported scope justified by evidence.
- Never derive block rules from `unknown`, failed, expired, or ambiguous results.
- The extension stores the ruleset version and a bounded local verdict cache using extension-supported storage APIs.
- Do not claim the extension can pause every navigation while waiting for an API response; stricter enforcement may require a managed proxy or secure web gateway.
- Never put provider API credentials in extension assets.

### 9. Docker and operations

Propose a `deploy/compose.yaml` with:
- `api`: Go API process.
- `worker`: Go worker process using the same codebase/image but a different command.
- `mongodb`: database.
- `redis`: only if used for queue/cache.
- Elasticsearch only in an optional profile if specifically justified.

Use service names for container-to-container networking. Keep internal service ports private. Add health checks, dependency readiness, persistent MongoDB storage, multi-stage Go builds, and a non-root runtime where practical. Do not mount the Docker socket into application containers.

### 10. Tests and quality gates

Document or add a staged plan for:
- URL normalization/fingerprint unit tests.
- Public suffix edge cases.
- State transitions and expiration.
- Provider response mapping and mocked provider failures.
- Cache hit, cache miss, and concurrent deduplication.
- Queue retries and recovery.
- Ruleset version stability.
- URL/secret redaction in logs.
- Extension behavior for cached, queued, unknown, and failed results.

Use mocked provider responses in automated tests; do not submit arbitrary live URLs from tests. Include `gofmt`, `go test ./...`, `go vet ./...`, and a chosen linter as CI checks if appropriate.

## Constraints

- Do not use Laravel or PHP.
- Do not add Elasticsearch just because it appeared in an earlier draft; justify it with a real requirement.
- Do not build a custom sandbox in Go for the MVP; Hybrid Analysis is the initial external provider.
- Do not add a dashboard, employee authentication, Active Directory, or unrelated services unless already present or specifically required.
- Do not put provider orchestration and MongoDB business rules directly in HTTP handlers.
- Do not expose secrets or real `.env` values.
- Do not implement the entire project in one change. Deliver architecture and an actionable implementation sequence first.

## Final response

After inspecting/updating the repository, summarize:
1. Existing structure and code found.
2. Documents created/updated.
3. Module boundaries and allowed dependencies.
4. Key decisions and assumptions.
5. Security risks/open questions.
6. Exact next implementation milestone.

Distinguish documentation work from runtime code; do not claim features have been implemented when only documentation was created.
