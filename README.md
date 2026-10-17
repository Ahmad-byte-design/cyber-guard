# CyberGuard AI

Backend service for a browser extension that checks URLs against the
Hybrid Analysis API v2 and publishes a versioned `declarativeNetRequest`
ruleset.

The architecture review and technical documentation live in [`docs/`](docs/).
Start with [`docs/architecture.md`](docs/architecture.md).

The original project brief is
[`docs/architecture/CYBERGUARD_PROJECT.md`](docs/architecture/CYBERGUARD_PROJECT.md);
its backend-language and verdict-vocabulary statements are superseded — see
[`docs/architecture.md` §7](docs/architecture.md#7-conflicts-found-during-review).
This README covers only how to run the service.

## Documentation

| Document | Contents |
|---|---|
| [`architecture.md`](docs/architecture.md) | Overview, diagrams, lifecycle, failure behaviour, conflicts found |
| [`api-contract.md`](docs/api-contract.md) | Endpoints, schemas, status codes, errors, rate limits |
| [`data-model.md`](docs/data-model.md) | Collections, indexes, TTL, dedup, retention |
| [`module-map.md`](docs/module-map.md) | Package layout, dependency direction, enforced boundaries |
| [`security-and-privacy.md`](docs/security-and-privacy.md) | Threat model, ruleset policy, redaction, MV3 limits |
| [`hybrid-analysis-integration.md`](docs/hybrid-analysis-integration.md) | Adapter design and the **unverified** provider checklist |
| [`docker-development.md`](docs/docker-development.md) | Compose topology, health checks, local workflow |
| [`testing-strategy.md`](docs/testing-strategy.md) | Test layers, fakes, acceptance criteria |
| [`implementation-plan.md`](docs/implementation-plan.md) | Phases, risks, open questions |
| [`decisions/`](docs/decisions/) | Architecture decision records |

> **Status: end-to-end scan workflow implemented.** `POST /api/v1/check-url`
> accepts a URL, deduplicates it, encrypts it and leaves it claimable; the scan
> runner claims it, submits it to the provider, polls, normalises the result and
> caches the verdict; `GET /api/v1/get-url/{scanId}` serves the outcome.
> Verified end to end against live MongoDB with a **mock** provider.
>
> The runner is goroutines inside the API process and the `scans` collection is
> the queue, so the deployment is **one application process plus MongoDB**. There
> is no separate worker binary and no Redis. `POST /api/v1/check-url` still
> returns **202** and never waits for an analysis to finish.
>
> **The Hybrid Analysis adapter has never been called against the live API.**
> Its contract was verified against the published OpenAPI document and every
> test uses a mock, but nine specification gaps remain open. See [Status](#status).

## Requirements

Docker with Compose v2. Nothing else — Go runs inside containers, so no
toolchain install is needed on the host.

## Quick start

```sh
docker compose up -d --build
```

That is the whole thing. Docker Compose sets `ANALYSIS_PROVIDER=mock`, so **no
Hybrid Analysis account, no API key and no external request is involved**. The
API is on <http://localhost:8080>.

> The *binary's* own default is `hybrid-analysis`, which requires an API key and
> fails fast without one. That is deliberate — a server should not silently
> pretend to be analysing URLs when it is not — so a binary run outside Compose
> needs `ANALYSIS_PROVIDER=mock` set explicitly.

```sh
curl localhost:8080/health/live          # {"status":"ok"}
curl localhost:8080/health/ready         # {"status":"ready",...}
```

### API documentation

The backend serves its own documentation. Both endpoints are on by default and
need no secret:

| URL | What it is |
|---|---|
| <http://localhost:8080/docs/> | **Swagger UI** — interactive, with *Try it out* on every operation |
| <http://localhost:8080/openapi.yaml> | The OpenAPI 3.1 contract, as raw YAML |

Swagger UI is **vendored into the binary** at a pinned version
(`server/internal/httpapi/docs/assets/`, Apache-2.0). No CDN is used at runtime,
so the page renders with no internet access — including inside an air-gapped
deployment, which is when an operator is most likely to want it. The page prints
the pinned release it was built with, so you can tell what you are reading
without leaving the browser.

To switch it off — the API is unaffected either way:

```sh
# .env
API_DOCS_ENABLED=false
```

```sh
# or per run
API_DOCS_ENABLED=false docker compose up -d backend
```

#### Testing an endpoint with Try it out

With the stack running:

1. Open <http://localhost:8080/docs/>.
2. Expand `POST /api/v1/check-url`.
3. Leave the server on `http://127.0.0.1:8080` (the default) and click
   **Try it out**.
4. Edit the `url` value — `https://example.test/login` works, since `.test`
   never resolves and the request stays inside the mock provider.
5. Click **Execute**. You get `202` with a `scan_id` and a `status_url`, and
   **no verdict**: nothing has been analysed yet.
6. Expand `GET /api/v1/get-url/{scanId}`, paste the `scan_id` into `scanId`,
   click **Try it out** then **Execute**. Repeat every couple of seconds until
   `status` is `completed`, `failed` or `timed_out`.
7. If you lost the `scan_id`, `POST /api/v1/get-url` takes `{"url": "..."}` and
   returns the same result for the URL's most recent scan. It is a POST because
   a URL in a path would land in every access log between here and the server.
8. `GET /api/v1/get-all` returns the browser protection ruleset.

The same two calls with curl:

```sh
# 1. Submit. 202, queued, no verdict.
SCAN=$(curl -sS -X POST localhost:8080/api/v1/check-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.test/login"}' | sed -E 's/.*"scan_id":"([^"]+)".*/\1/')

# 2. Poll. The same poll by URL, for a client that lost the scan ID.
curl -sS "localhost:8080/api/v1/get-url/$SCAN"
curl -sS -X POST localhost:8080/api/v1/get-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.test/login"}'    # 404 if never scanned

# 3. The ruleset.
curl -sS localhost:8080/api/v1/get-all
```

#### Limitations of Try it out

- **The server list is fixed by the contract.** Swagger UI defaults to the
  first entry of `servers` in `openapi.yaml` and offers the rest in a dropdown.
  Behind a proxy or on another port, add your origin to that list and redeploy —
  the dropdown cannot discover deployments on its own.
- **CORS still applies.** Picking a server on a different origin than the one
  serving the page gets the request blocked by the browser before it is sent.
  The same-origin local default always works.
- **It issues one request per *Execute*.** Nothing polls for you; for
  `check-url` you follow `status_url` yourself.
- **No authentication exists**, so there is nothing to supply. The UI is
  configured not to persist credentials.

The contract is validated in CI by Go tests in `internal/httpapi`: it parses,
every documented path matches a registered route and vice versa, every `$ref`
resolves, the `Verdict` and `ScanStatus` enums equal the Go constants, and no
credential appears in it. A full OpenAPI 3.1 schema check needs a linter and is
run by hand:

```sh
npx @redocly/cli lint server/openapi.yaml
```

### Two secrets are required

If you are starting from an empty `.env`:

```sh
cp .env.example .env
openssl rand -hex 32    # -> URL_FINGERPRINT_HMAC_KEY
openssl rand -hex 32    # -> URL_ENCRYPTION_KEY   (a DIFFERENT one)
```

Both are 64 hexadecimal characters. They must differ: rotating the fingerprint
key invalidates the whole cache, while rotating the encryption key only affects
jobs in flight.

Without them the service still starts — so you can read `/health/ready` and be
*told* what is wrong — but it reports **not ready** and refuses URL submissions,
rather than storing raw URLs unencrypted.

`URL_ENCRYPTION_KEY` is generated once and kept. Do not regenerate it on every
start: scans that have not been submitted yet could no longer be decrypted.

### Mock mode (the default)

`ANALYSIS_PROVIDER=mock` analyses URLs **inside the API process**, on the scan
runner's own goroutines. Nothing leaves your machine, results are deterministic
(the same URL always gives the same verdict), and no API key is needed.

The verdict depends on a keyword in the URL, so every branch can be tried:

| URL contains | Result |
|---|---|
| `/malicious` | `verdict: malicious` |
| `/suspicious` | `verdict: suspicious` |
| `/no-threat` or `/clean` | `verdict: no_threat_detected` |
| `/error` | scan `failed`, error `provider_analysis_failed`, **no verdict** |
| `/slow` | never finishes — the scan ends `timed_out` |
| anything else | `verdict: no_threat_detected` |

There is **no silent fallback**. Selecting `hybrid-analysis` without an API key
is a startup error, not a quiet switch to the mock — otherwise the real
integration would rot while its tests still passed.

### Schema migration

`docker compose up` runs a one-shot `migrate` service first, and the API
waits for it to succeed. It creates the indexes the system depends on —
most importantly the partial unique index that makes "one provider submission
per URL" actually true, and `by_claimable` on `scans`, which is what makes a
queued scan findable by the runner.

Run it by hand any time:

```sh
docker compose run --rm migrate            # create/refresh indexes
docker compose run --rm migrate -verify    # check without changing anything
```

### Exercising it end to end

```sh
# 1. Submit a URL. Returns 202 and a scan id — no verdict, nothing analysed yet.
curl -sS -X POST localhost:8080/api/v1/check-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.test/login"}'
# {"scan_id":"scan_3f2a...","status":"queued","cached":false,
#  "status_url":"/api/v1/get-url/scan_3f2a..."}

# 2. Poll. Repeat every 2s until status is completed, failed or timed_out.
curl -sS localhost:8080/api/v1/get-url/scan_3f2a...
# {"scan_id":"scan_3f2a...","status":"completed","verdict":"malicious",
#  "provider":"hybrid-analysis","evidence":[...],"analyzed_at":...,"expires_at":...}

# 3. Submit the same URL again. Served from cache, no provider call, 200.
curl -sS -X POST localhost:8080/api/v1/check-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.test/login"}'
# {"scan_id":"scan_3f2a...","status":"completed","cached":true,"verdict":"malicious",...}
```

An in-flight scan has **no `verdict` field at all**. That is the honest
representation of "not known yet"; it is not an empty verdict and not a safe one.

In Postman: `POST {{base_url}}/api/v1/check-url` with a raw JSON body
(`Body → raw → JSON`) of `{"url": "https://example.test/login"}` and
`Content-Type: application/json`; then `GET {{base_url}}/api/v1/get-url/{scan_id}`,
using the `scan_id` from the first response as the path variable.

### What the responses look like when things go wrong

```sh
# 422 — the URL failed validation
curl -sS -X POST localhost:8080/api/v1/check-url \
  -H 'Content-Type: application/json' -d '{"url":"javascript:alert(1)"}'

# 422 — the target is refused before anything is stored
curl -sS -X POST localhost:8080/api/v1/check-url \
  -H 'Content-Type: application/json' -d '{"url":"http://192.168.1.1/admin"}'

# 429 — the per-fingerprint submission budget for this hour is spent
curl -si -X POST localhost:8080/api/v1/check-url \
  -H 'Content-Type: application/json' -d '{"url":"https://example.test/x"}'
# Retry-After: 3600
# X-RateLimit-Limit: 10
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1763000000

# 503 — a required secret or dependency is missing
curl -sS localhost:8080/health/ready
```

Every error body is an RFC 9457 problem detail with a stable `code` field.
Branch on `code`, never on `detail`.

## Commands

| Task | Command |
|---|---|
| Start / stop | `docker compose up -d --build` · `docker compose down` |
| Re-run the schema migration | `docker compose run --rm migrate` |
| Check the schema is current | `docker compose run --rm migrate -verify` |
| Stop and wipe data | `docker compose down -v` |
| Follow logs | `docker compose logs -f backend` |
| Run tests | `docker compose run --rm go go test ./...` |
| Race detector | `docker compose run --rm go sh -c 'apk add -q build-base && CGO_ENABLED=1 go test -race ./...'` |
| Integration tests | `docker compose run --rm go go test -tags integration ./...` |
| Vet | `docker compose run --rm go go vet ./...` |
| Vet (integration) | `docker compose run --rm go go vet -tags integration ./...` |
| Format | `docker compose run --rm go gofmt -w .` |
| Coverage | `docker compose run --rm go go test -coverpkg=./... -coverprofile=/src/coverage.out ./...` |
| Build a binary | `docker compose run --rm go go build -o bin/api ./cmd/api` |
| Check the version stamp | `docker compose exec backend cyberguard-api -version` |

Integration tests need MongoDB running, and work **with the application
running too** — they use their own MongoDB database, so they never disturb a
live deployment:

```sh
docker compose up -d mongodb
docker compose run --rm go go test -tags integration ./...
```

| Variable | Default | Purpose |
|---|---|---|
| `MONGODB_URI` | `mongodb://mongodb:27017` | datastore the tests connect to |
| `MONGODB_DATABASE` | `cyberguard_integration` | database the tests create and drop |

Rate-limit tests are **not** in that set: the counters are in-process, so they
are ordinary unit tests and need no datastore at all.

## Services

| Service | Image | Published | Purpose |
|---|---|---|---|
| `backend` | built from `server/` | `8080` | JSON API **and** the scan runner |
| `migrate` | same image, different entrypoint | none | one-shot: creates indexes, then exits |
| `mongodb` | `mongo:9.0` | none | authoritative store **and work queue** |
| `go` | `golang:1.27-alpine` | none | dev toolchain for build/test |

MongoDB publishes **no host ports**; containers reach it as `mongodb:27017` on
the Compose network, per §11.11 of the architecture doc. Publish it yourself
only if you need a local client. It is the only datastore, so `docker compose up`
starts two long-running services.

MongoDB is pinned to 9.x on purpose: 8.0 refuses to start on Linux kernel
6.19+ ([SERVER-121912](https://jira.mongodb.org/browse/SERVER-121912)), which
Ubuntu 26.04 runs.

## Configuration

All settings come from the environment; see [`.env.example`](.env.example) for
the full list. The ones that matter most:

- `URL_FINGERPRINT_HMAC_KEY` — **required.** Without it the service reports
  not-ready and rejects submissions, because exact-URL cache lookups cannot
  work. Changing it invalidates every stored fingerprint.
- `HYBRID_ANALYSIS_API_KEY` — optional. Without it remote submission stays
  disabled and readiness reports it as a degraded sub-check, not a failure.
- `MONGODB_URI` / `MONGODB_DATABASE` / `MONGODB_CONNECT_TIMEOUT` /
  `MONGODB_PING_TIMEOUT`
- `WORKER_CLAIM_POLL_GAP` (default `250ms`) — how hard an idle runner queries
  MongoDB for work. MongoDB has no blocking claim primitive, so an idle consumer
  polls; this bounds how fast.
- `CLAIM_LEASE_HEADROOM` (default `30s`) — the claim lease is **derived**, not
  set directly: `WORKER_POLL_DEADLINE + WORKER_POLL_INTERVAL + CLAIM_LEASE_HEADROOM`.
  The lease must outlive the longest possible unit of work, or a second claim
  could land on a scan whose provider analysis is still running — and on the
  submission path that means submitting the URL twice. A headroom of `<= 0` is
  rejected at config load rather than accepted and left to fail in production.
- `HEALTH_CHECK_TIMEOUT` — bounds each readiness probe.
- `API_DOCS_ENABLED` — serves Swagger UI at `/docs/` and the contract at
  `/openapi.yaml`. Defaults to `true`; no secret is involved. Setting it to
  `false` removes both endpoints and leaves the API untouched.

`.env` is gitignored. Never commit real keys. Secrets are read and trimmed, so a
value pasted from a secret manager with a trailing newline cannot silently
become a different key on one replica than on another.

## Layout

```
server/
├── cmd/
│   ├── api/                      # HTTP server entrypoint + the scan runner
│   └── migrate/                  # one-shot index creation
├── internal/
│   ├── app/                      # shared datastore wiring
│   ├── config/                   # env loading and validation
│   ├── health/                   # readiness probes (Check interface + Checker)
│   ├── httpapi/                  # routing, middleware, RFC 9457 handlers
│   │   └── docs/                 # Swagger UI; vendored assets + embedded page
│   ├── logging/                  # slog setup (JSON to stderr)
│   ├── platform/
│   │   ├── mongostore/           # MongoDB repositories + indexes + transient URL crypto
│   │   │                        # + the lease-based claim query
│   │   └── mongoqueue/           # scans collection adapted to the delivery interface
│   ├── ratelimit/                # in-process fixed-window counters
│   ├── providers/                # provider contract (moves to scans in Phase 4)
│   │   ├── hybridanalysis/       # real adapter — the only HA-aware package
│   │   └── mock/                 # deterministic fake provider for tests
│   ├── urlintel/                 # URL validation, canonicalisation, HMAC fingerprints, PSL host intelligence
│   └── verdicts/                 # CyberGuard verdict vocabulary
├── openapi.yaml                  # authoritative API contract
├── spec.go                       # embeds openapi.yaml so /openapi.yaml serves it
├── .redocly.yaml                 # optional hand-run OpenAPI lint config
├── Dockerfile                    # multi-stage: golang builder → alpine runtime
└── go.mod
```

The module has two **runtime** third-party dependencies — the official
MongoDB Go driver and `golang.org/x/net` for the Public Suffix List — and one
**test-only** dependency, `gopkg.in/yaml.v3`, used by
`internal/httpapi/openapi_test.go` to parse and check the contract. Nothing
reaches the request path that is not there for the service itself. `go-redis`
was removed with the worker; the lease-based claim lives in MongoDB, so the
driver is now the only datastore dependency.

`openapi.yaml` lives inside the module so that
`internal/httpapi/openapi_test.go` can assert the router and the contract have
not drifted apart, in any environment.

Known deviations, tracked in
[`docs/implementation-plan.md`](docs/implementation-plan.md#outstanding-deviations):

- **The module path `cyberguard/server` is a placeholder.** There is no Git
  remote and no commit, so it cannot be derived without guessing
  ([ADR 0016](docs/decisions/0016-go-module-path.md), deviation D1). This
  **blocks Phase 4**.

## Status

Implemented:

- URL validation — http/https only, rejects embedded credentials, overlong
  input, control characters, missing host
- Deterministic canonicalisation (path and query case preserved, fragment
  dropped, empty path normalised to `/`)
- HMAC-SHA-256 URL fingerprinting
- **Host intelligence**: hostname normalisation (IDNA/punycode, case, trailing
  dot) kept separate from registrable-domain extraction via the Public Suffix
  List. A public suffix is never returned as a domain; IPs, `localhost` and
  unresolvable hosts are refused rather than guessed at
- Environment-based configuration with validation of every malformed value
- Structured `log/slog` JSON logging to stderr
- HTTP server with request-ID propagation, access logging, panic recovery,
  bounded body reads and graceful shutdown
- `GET /health/live` (dependency-free) and `GET /health/ready` (config +
  MongoDB + provider probes, plus the fingerprint/encryption key checks)
- MongoDB connection management with bounded timeouts, verified by ping, and
  idempotent disconnect
- **MongoDB persistence (Phase 3)**: `scans`, `assessments` and `transient_urls`
  repositories; scan lifecycle and status transitions; provider job ID and
  submission ID retention; verdict cache with expiry; encrypted transient URL
  storage (AES-256-GCM, AAD-bound)
- **Deduplication at the database level**: a partial unique index makes N
  concurrent requests for one URL produce exactly one provider submission
- **Lease-based claiming on MongoDB** — a single atomic `FindOneAndUpdate`
  stamps `lease_owner`/`lease_expires_at` on a claimable scan, so several
  replicas compete safely for the same work with nothing to coordinate
- **RFC 9457** problem-detail error responses
- **OpenAPI 3.1** contract with a CI-enforced drift check against the router
- **End-to-end scan workflow** — submit, deduplicate, encrypt, queue, submit to
  the provider, poll, normalise, cache, serve
- **Crash recovery** — the scan document *is* the dispatch ledger, so a lost or
  failed process delays work rather than losing it: the lease lapses and the
  next claim picks the scan up
- **Abuse controls** — in-process fixed-window per-client and per-fingerprint
  limits, with the same `X-RateLimit-*` headers and the same fail-closed
  contract as before
- **Target gate** — loopback, private, link-local and reserved hosts are refused
  before anything is stored
- `GET /api/v1/get-all` (empty version-0 snapshot — rulesets are not built)
- A deterministic mock `AnalysisProvider`, so no test ever needs a live
  provider
- **Hybrid Analysis API v2 adapter** — contract verified against the official
  OpenAPI document (3.0.0, docs v2.38.0); submission, polling, quota,
  jittered bounded retries, strict response validation, size-bounded bodies
- **Verdict normalization** into `malicious` / `suspicious` /
  `no_threat_detected` / `inconclusive` / `unknown`, with the guarantee that no
  failure path can produce `no_threat_detected`
- Retry-safe submission: a job holding a provider scan ID is never
  re-submitted

Not implemented yet:

- Ruleset generation (§5.5) — `get-all` returns an empty version-0 snapshot
- Live Hybrid Analysis verification — the nine open questions in
  [`hybrid-analysis-integration.md`](docs/hybrid-analysis-integration.md)
- CI pipeline
- Metrics / tracing (structured logs only)

**What has not been proven:** that the Hybrid Analysis adapter produces correct
verdicts against the real API. The contract was verified from the published
OpenAPI document and every test uses a mock provider; the actual `verdict`
string values are still unknown ([V1](docs/hybrid-analysis-integration.md#10-open-questions-requiring-manual-verification)).
Until one controlled live call closes those questions, a
`no_threat_detected` verdict from the real provider is unproven.

## Note on the language choice

The two source documents under `docs/architecture/` were written for a Laravel
backend and state repeatedly that Go is out of scope for the MVP — see §2, §17
of `CYBERGUARD_PROJECT.md` and the "Fixed technology choices" section of
`CYBERGUARD_ARCHITECTURE_PROMPT.md`. This service is written in Go by explicit
decision: [ADR 0009](docs/decisions/0009-go-as-only-backend-language.md).

That contradiction is recorded rather than papered over: see
[`docs/architecture.md` §7](docs/architecture.md#7-conflicts-found-during-review),
which lists all twelve conflicts found during the review and how each was
resolved. The Laravel statements in those two documents are superseded by the
`docs/` review set, but have been left in place — they remain useful as a
record of the original requirements.