# 0015 — OpenAPI contract and RFC 9457 errors

- **Status:** Accepted
- **Date:** 2026-10-16
- **Supersedes:** [ADR 0005](0005-standard-library-http.md) (router clause),
  [ADR 0006](0006-error-format.md) (becomes binding rather than proposed)
- **Affects:** `api-contract.md`, `internal/httpapi`, extension client

## Context

Two related decisions were proposed separately in ADR 0005 and ADR 0006:

- **ADR 0005** concluded that `net/http` + `http.ServeMux` is sufficient and
  that a router dependency is not justified, listing "an OpenAPI-first design"
  as a trigger to revisit.
- **ADR 0006** proposed migrating error bodies to RFC 9457, noting it should
  happen before the extension ships because it is a breaking change.

OpenAPI is now adopted as the contract format. That is exactly the trigger
ADR 0005 named, so both records must be updated rather than silently ignored.

## Decision

1. **OpenAPI 3.1 is the authoritative API contract.** `api-contract.md` becomes
   a narrative companion to a machine-readable `openapi.yaml`, not the
   specification itself.
2. **RFC 9457 problem details are the error format.** Media type
   `application/problem+json`.
3. **Handwritten handlers remain**; the OpenAPI document is checked in CI
   against the implementation rather than generating the handlers.

## Rationale

### Why OpenAPI

The extension is a separately shipped client written in a different language.
A machine-readable contract means:

- The client can be generated or type-checked against the spec rather than
  hand-transcribed.
- Contract drift becomes a **test failure** instead of a production bug. Today
  the contract exists only as prose in a markdown file, which nothing verifies.
- The specification, not the markdown, is the source of truth for clients.

### Why handwritten handlers

[ADR 0005](0005-standard-library-http.md) stands: `http.ServeMux` stays. The
route surface is three resource routes and two probes, and method-and-wildcard
patterns cover it.

Drift is caught by CI instead, which is the more robust mechanism anyway — code
generation hides rather than reveals divergence, and a generated handler layer
adds a build dependency to a security product for no behavioural gain.

- Keep ADR 0005 as written.
- Add a CI check that validates `openapi.yaml` and asserts every documented
  route is registered and every registered route is documented.

## Error format

```json
{
  "type": "https://cyberguard.example/problems/validation-error",
  "title": "Validation error",
  "status": 422,
  "detail": "url: scheme must be http or https",
  "instance": "/api/v1/check-url",
  "request_id": "40831b5ecb146081731ec7fb",
  "code": "validation_error"
}
```

- `type` — stable URI per problem class.
- `code` — retained as an extension member: a low-cardinality string is more
  useful to a client branching on outcomes than a `type` URI it must
  pattern-match.

### Invariant on `detail`

`detail` is written for the end user. It must never contain a raw URL, an API
key, a driver error, a stack trace, or an internal identifier other than
`request_id`. This extends the existing `TestRawURLNeverReachesLogs` to assert
the **response body** specifically, not only the log stream.

## Consequences

**Positive**

- Client/contract drift is a CI failure, not a field bug.
- Typed problem classes for the extension to branch on.
- Standard media type; existing tooling understands it.
- The contract becomes reviewable as data rather than prose.

**Negative**

- One more artefact to keep in sync — mitigated by making the CI drift check
  mandatory.
- `openapi.yaml` is a hand-maintained file, so it can be wrong. Mitigated by
  the same drift check.
- RFC 9457 bodies are slightly larger.
- The drift check needs a tool in CI (for example `oapi-codegen` for validation,
  or `kin-openapi` in a test). Accepted: one dev dependency, no runtime
  dependency.

## Sequencing

Both must land **before the first extension release**. Afterwards both are
breaking changes requiring a coordinated client update — the worst time to
discover an extension still expects the old error shape or has drifted from the
routes.

## Supersession notice

- ADR 0005 — **amended**: its "revisit when OpenAPI-first" trigger has fired.
  Its conclusion (standard library) is unchanged and remains in force.
- ADR 0006 — **accepted as binding**. Its proposal is now a decision; its
  rationale and invariants carry forward unchanged.