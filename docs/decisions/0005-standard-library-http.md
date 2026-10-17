# 0005 — Standard library HTTP

- **Status:** Accepted, **amended** by
  [ADR 0015](0015-openapi-and-rfc-9457.md)
- **Date:** 2026-10-16
- **Affects:** `internal/httpapi`, `docs/module-map.md`

> **Amended by ADR 0015.** The "revisit when OpenAPI-first" trigger below has
> fired: OpenAPI 3.1 is now the contract format. Its conclusion is unchanged —
> `http.ServeMux` stays, handlers stay handwritten, and contract drift is
> caught by a CI check rather than by code generation. See
> [ADR 0015](0015-openapi-and-rfc-9457.md).

## Context

The review prompt §2 lists both "Go, `net/http`" and "Chi router, if
justified". The question is whether a third-party router earns its place.

The API surface is small and fixed: three resource routes, two health probes.
Go 1.22 added method-and-wildcard patterns to `http.ServeMux`:

```go
mux.HandleFunc("POST /api/v1/check-url", s.handleCheckURL)
mux.HandleFunc("GET /api/v1/get-url/{scanId}", s.handleGetURL)
scanID := r.PathValue("scanId")
```

This covers method matching, path wildcards, and correct `405` responses with
an `Allow` header.

## Decision

Use `net/http` and `http.ServeMux`. Do not add a router dependency unless a
concrete requirement appears.

## Consequences

**Positive**

- The module keeps **zero external dependencies** at this layer, so build, vet
  and test work offline and the build image stays small.
- No third-party upgrade treadmill for a security product's request path.
- Method mismatch returns `405` automatically; a naive `HandleFunc("/x", …)`
  pattern router would return `404`.

**Negative**

- No built-in middleware grouping or sub-routing. Current middleware is a
  simple chain, so this costs nothing; if nested groups become necessary,
  composition by hand is still straightforward.
- No built-in schema validation or OpenAPI integration. Neither is currently
  used.

## When to revisit

Add a router only if one of these becomes true:

- Nested route groups with distinct middleware sets.
- Per-route rate limiting or authorisation policy.
- An OpenAPI-first design where routing is generated from a spec.

At that point Chi or `net/http`-based code generation is reasonable. Until
then a dependency is pure cost. See open question 6 in the implementation plan
for the OpenAPI question specifically — that is the most likely trigger.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Chi | Excellent, but `ServeMux` covers the current surface. Adds a dependency for no capability in use |
| Gin | Heavier, reflection-based, larger supply-chain surface |
| Echo | Same argument as Gin |
| gorilla/mux | Effectively unmaintained; superseded by the standard library |