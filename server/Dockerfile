# syntax=docker/dockerfile:1
#
# Multi-stage build for the CyberGuard API and worker.
#
# Stage 1 compiles a static binary; stage 2 ships only that binary on a bare
# Alpine base. The build stage never reaches production, so the final image
# carries no toolchain, no source and no module cache.
#
# Build:  docker compose build backend
# Run:    docker compose up -d

# ---------------------------------------------------------------- build stage
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies change far less often than source, so copy the module manifest
# first and let this layer stay cached across ordinary code edits.
# go.sum is not copied because the module currently has no external
# requirements, so no go.sum exists. Once a dependency is added, run
# `go mod tidy`, commit go.sum, and switch this to `COPY go.mod go.sum ./`
# so the build fails loudly on a checksum mismatch instead of silently
# re-resolving versions.
COPY go.mod ./
RUN go mod download && go mod verify

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# CGO_ENABLED=0 produces a binary with no libc dependency, which is what lets
# it run on the bare runtime image below.
# -trimpath removes local filesystem paths so the build is reproducible and
# leaks no directory layout. -s -w drop the symbol table and DWARF data.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w \
          -X main.version=${VERSION} \
          -X main.commit=${COMMIT} \
          -X main.buildTime=${BUILD_TIME}" \
        -o /out/api   ./cmd/api \
 && CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/worker ./cmd/worker \
 && CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/migrate ./cmd/migrate

# -------------------------------------------------------------- runtime stage
FROM alpine:3.22

# ca-certificates is required for outbound TLS to the Hybrid Analysis API.
# tzdata lets the service resolve named timezones rather than assuming UTC.
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 1000 cyberguard

COPY --from=build /out/api     /usr/local/bin/cyberguard-api
COPY --from=build /out/worker  /usr/local/bin/cyberguard-worker
COPY --from=build /out/migrate /usr/local/bin/cyberguard-migrate

# Run unprivileged. Binding :8080 needs no capabilities, so nothing is granted.
USER cyberguard:cyberguard

ENV HTTP_ADDR=:8080 \
    LOG_FORMAT=json \
    LOG_LEVEL=info \
    TZ=UTC

EXPOSE 8080

# The liveness probe doubles as the container health check.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health/live >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/cyberguard-api"]