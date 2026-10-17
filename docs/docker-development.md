# CyberGuard AI — Docker Development Environment

> **Status:** Implemented and verified on this machine. Describes the existing
> `docker-compose.yml` at the repository root.

## 1. Services

| Service | Image | Published | Purpose |
|---|---|---|---|
| `backend` | built from `server/` | `8080:8080` | JSON API |
| `worker` | same image, different entrypoint | none | Consumes the scan queue: submits, polls, caches verdicts |
| `migrate` | same image, different entrypoint | none | One-shot schema step: creates indexes, then exits |
| `mongodb` | `mongo:9.0` | **none** | Authoritative store |
| `redis` | `redis:8-alpine` | **none** | Optional queue/cache ([ADR 0003](decisions/0003-asynchronous-analysis-jobs.md)) |
| `go` | `golang:1.27-alpine` | none | Dev toolchain: build, test, vet, format |

MongoDB and Redis publish **no host ports**. Containers reach them as
`mongodb:27017` and `redis:6379` on the Compose network. Publishing them would
expose an unauthenticated datastore to the host and anything else on the
network.

## 2. Quick start

```sh
cp .env.example .env
openssl rand -hex 32          # paste into URL_FINGERPRINT_HMAC_KEY in .env
mkdir -p .cache/go-build .cache/go-mod
docker compose up -d --build
curl localhost:8080/health/live
```

The API is on <http://localhost:8080>.

## 3. Commands

| Task | Command |
|---|---|
| Start / rebuild | `docker compose up -d --build` |
| Stop | `docker compose down` |
| Stop and delete all data | `docker compose down -v` |
| Follow API logs | `docker compose logs -f backend` |
| Run tests | `docker compose run --rm go go test ./...` |
| Race detector | `docker compose run --rm go go test -race ./...` |
| Vet | `docker compose run --rm go go vet ./...` |
| Format | `docker compose run --rm go gofmt -w .` |
| Coverage | `docker compose run --rm go go test -coverpkg=./... -coverprofile=/src/coverage.out ./...` |
| Build a binary | `docker compose run --rm go go build -o bin/api ./cmd/api` |
| Check the version stamp | `docker compose run --rm --entrypoint cyberguard-api backend -version` |

`go test -race` is worth making the default locally: the worker is
concurrency-heavy, and the claim path is exactly where races hide.

## 4. Build

`server/Dockerfile` is a two-stage build.

**Stage 1** — `golang:1.27-alpine` compiles static binaries:

```dockerfile
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION} ..." \
        -o /out/api ./cmd/api
```

- `CGO_ENABLED=0` removes the libc dependency, which is what allows the binary
  to run on the bare runtime image.
- `-trimpath` removes local filesystem paths: reproducible builds, and no
  directory layout leaks into the binary.
- `-s -w` drop the symbol table and DWARF data.

**Stage 2** — `alpine:3.22` with `ca-certificates` (required for outbound TLS
to the provider) and `tzdata`. The service runs as an unprivileged user
(`uid 1000`) and binds `:8080`, which needs no capabilities, so none are
granted.

The build stage never ships. The final image has no toolchain, no source and no
module cache.

### Secrets are never build arguments

`VERSION`, `COMMIT` and `BUILD_TIME` are build args. **No secret is ever a
build arg** — an `ARG` or `ENV` holding a key stays recoverable from image
history even if a later layer unsets it. Secrets arrive at runtime through
`env_file`.

## 5. Health checks and startup ordering

| Service | Check | Interval |
|---|---|---|
| `backend` | `GET /health/live` via `wget` | 30s |
| `mongodb` | `mongosh --eval "db.adminCommand('ping').ok"` | 10s |
| `redis` | `redis-cli ping` | 10s |
| `worker` | **disabled** | — |

`backend` and `worker` both declare
`depends_on: { mongodb: { condition: service_healthy }, redis: … }`, so
Compose holds them until the datastores answer. Starting the API before MongoDB
is ready produces a crash loop and a misleading "database down" alert.

**Why the worker's health check is disabled:** the image's `HEALTHCHECK`
probes the API's HTTP listener on `:8080`. The worker runs no listener, so
inheriting that check marks it permanently unhealthy. It must be overridden
until the worker exposes its own liveness signal.

## 6. Failure behaviour

| Failure | Observed behaviour |
|---|---|
| MongoDB down | `backend` exits or readiness fails; Compose restart policy restarts it. Jobs already claimed sit until their lease lapses, then another worker reclaims them |
| Redis down | `backend` unaffected — MongoDB is the source of truth. The `go` service is unaffected |
| Provider down | Readiness reports a degraded `provider` sub-check, not a global `503`. Cached reads keep working |
| HMAC key missing | Readiness `503`; `check-url` `503 not_ready`; the API still serves liveness |
| Worker down | Scans stay `queued`; the API still answers cached reads |

## 7. Known environment constraint: MongoDB 9.x

MongoDB is pinned to `mongo:9.0`, not `mongo:8`.

MongoDB 8.0 refuses to start on Linux kernel 6.19 or newer:

```
MongoDB cannot start: Linux kernel versions 6.19 and newer has a known
incompatibility with this version of MongoDB.
See https://jira.mongodb.org/browse/SERVER-121912
```

The development host runs kernel 7.0.0, so `mongo:8` crash-looped with this
error on every start. MongoDB 9.0 was verified to start and answer a ping on
this kernel before the pin was committed.

If you deploy to a kernel < 6.19 host, 8.x remains a valid choice — but keep
the pin explicit rather than floating on `mongo:latest`.

## 8. Persistent data

| Volume | Holds | Survives `down`? |
|---|---|---|
| `mongo-data` | All CyberGuard collections | Yes |
| `redis-data` | Redis AOF | Yes |
| `.cache/go-build` | Go build cache | Yes (host bind mount) |
| `.cache/go-mod` | Module cache | Yes (host bind mount) |

`docker compose down -v` destroys the databases. **Development volumes are not
a backup.** To reset to a clean state during development, that is the intended
command; in production it would be a data-loss event.

MongoDB and Redis run without authentication, which is acceptable only because
they are unreachable from outside the Compose network. Do not add a published
port to debug locally — use `docker compose exec mongodb mongosh` instead.

## 9. File ownership

Every service runs as `user: "${LOCAL_UID}:${LOCAL_GID}:..."` from `.env`, so
files the container writes into the bind-mounted source tree are owned by your
host user, not `root`. Keeping `.env`'s `LOCAL_UID`/`LOCAL_GID` in sync with
`id -u` / `id -g` avoids a tree of root-owned files that later block ordinary
edits.

The Go module cache lives in `.cache/` on the host rather than in an anonymous
volume precisely so that the non-root user can write to it.

## 10. Production differences

The Compose file is for local development. Before production:

- Add authentication and TLS termination to the API.
- Use a secrets manager instead of `.env`.
- Enable MongoDB authentication and replica set if durability matters.
- Replace the compose restart policies with the orchestrator's.
- Build images in CI and scan them; do not build on the host.
- Keep `mongodb` and `redis` internal, exactly as here.

## 11. `.dockerignore`

`server/.dockerignore` keeps the build context small and prevents leakage:

- `.env` and `.env.*` — secrets must never enter a layer.
- `docs/` — not needed to compile.
- `bin/`, `dist/`, `coverage.out` — build artefacts.
- `Dockerfile` and `.dockerignore` themselves.

The `.env` exclusion is the important one. Without it, a secret could be
copied into an intermediate layer and remain in the image history.

## The `migrate` service

`docker compose up` starts `migrate`, waits for it to exit successfully, and
only then starts the API and worker.

It exists because an unmigrated database **fails silently rather than loudly**.
Without its indexes:

| Missing index | What quietly stops being true |
|---|---|
| `uniq_active_scan` (partial unique) | "One provider submission per URL". Concurrent requests create duplicate scans and duplicate submissions — and no log line looks wrong |
| `ttl_expires_at` on `transient_urls` | Encrypted URLs are never reaped after a worker crash |
| `ttl_expires_at` on `assessments` | Verdicts are never deleted at expiry |
| `by_hostname` / `by_domain` / `by_scan_id` | Every verdict lookup becomes a collection scan |

This was a real defect, found by running the API end to end rather than by any
test: the repository tests call `EnsureIndexes` in their own setup, so they
passed while a freshly-started deployment had only MongoDB's default `_id_`
indexes and silently created two scans for one URL.

Why a separate program rather than index creation on boot: a large collection
would make every replica restart wait on an index build, and a failed migration
would take the service down instead of reporting a degraded one. Running it
nowhere is worse than either — hence the explicit step.

```sh
docker compose run --rm migrate            # create or refresh
docker compose run --rm migrate -verify    # report only, exit 1 if unmigrated
```

It is idempotent: running it against a current database is a no-op.
