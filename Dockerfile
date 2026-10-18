# CyberGuard AI — API image.
#
# The final image contains exactly one statically linked binary plus the CA
# certificates it needs to call the provider over HTTPS. Configuration arrives
# only through environment variables at run time: no file, no default secret.
# The process runs as an unprivileged user, and the container is killed on
# SIGINT/SIGTERM the same way the binary expects (graceful shutdown in
# cmd/api/main.go), so no init system is needed for one clean process.
#
#   docker build -t cyberguard-api:dev .
#   docker run --rm -p 8080:8080 --env-file .env cyberguard-api:dev

# --- build stage -----------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# Module downloads change far less often than source code, so they get their
# own mount and copy layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

# CGO is disabled deliberately: the dependency set (the official MongoDB
# driver) does not need it, and a static binary removes the risk of a runtime
# stage missing a shared library.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -o /out/cyberguard-api ./cmd/api

# --- runtime stage ---------------------------------------------------------
FROM alpine:3.20

# TLS to the provider and to a TLS-terminated MongoDB needs a root certificate
# store; everything else in this image is already there.
RUN apk add --no-cache ca-certificates \
    && addgroup -S cyberguard \
    && adduser -S -G cyberguard cyberguard

COPY --from=build --chmod=0555 /out/cyberguard-api /usr/local/bin/cyberguard-api

USER cyberguard

# The container always listens on this port; the host decides which port maps
# to it (see docker-compose.yml). docker-compose.yml pins APP_PORT to this
# value inside the container.
EXPOSE 8080

# wget comes from busybox, which alpine ships by default. The healthcheck must
# survive an unconfigured provider: /health/live answers, while /health/ready
# is the one that also demands MongoDB — compose uses that instead.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD wget -q -O /dev/null "http://127.0.0.1:8080/health/live" || exit 1

ENTRYPOINT ["/usr/local/bin/cyberguard-api"]
