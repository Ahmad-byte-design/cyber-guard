# 0006 — Error response format

- **Status:** **Accepted as binding** by
  [ADR 0015](0015-openapi-and-rfc-9457.md), which supersedes this record and
  extends it with the OpenAPI contract
- **Date:** 2026-10-16
- **Affects:** `internal/httpapi`, `docs/api-contract.md`, extension client

> **Folded into ADR 0015.** This record's proposal — RFC 9457 problem details —
> is now a decision, not a proposal. Its rationale and its `detail` invariant
> carry forward unchanged. See
> [ADR 0015](0015-openapi-and-rfc-9457.md) for the authoritative text.

## Context

The API returns errors today as:

```json
{
  "error": {
    "code": "validation_error",
    "message": "url: scheme must be http or https",
    "request_id": "40831b5ecb146081731ec7fb"
  }
}
```

This is a reasonable ad-hoc shape, but it is not a standard. RFC 9457
("Problem Details for HTTP APIs", formerly RFC 7807) is the IETF standard for
machine-readable HTTP error bodies, with an established `type` URI, `title`,
`status`, `detail`, and extension members.

The extension is a separately shipped client. Every error format is a contract
it will depend on.

## Decision

Adopt **RFC 9457 problem details** before the extension ships.

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

Media type: `application/problem+json`.

The `code` extension member is retained — a stable, low-cardinality string is
more useful to a client switching on outcomes than a `type` URI it would have
to pattern-match.

## Rationale for doing it now rather than later

This is a breaking change to the response body. The cost of making it before
the first extension release is one implementation change. The cost of making it
afterwards is a coordinated client release, a compatibility window, and a
migration for users who have not updated. The window is free today.

## Consequences

**Positive**

- Clients get typed problems rather than parsing prose.
- Standard media type; tooling and libraries already understand it.
- `status` and `title` are conventional and human-readable without parsing
      `message`.

**Negative**

- Slightly larger bodies.
- `detail` must still be written carefully: it is the field most likely to leak
  internals. The existing rule holds — never put an `err.Error()` string from
  a driver or the provider in `detail`.

## Invariant

`detail` is written for the end user and never contains a raw URL, an API key,
a driver error, a stack trace, or an internal identifier other than
`request_id`. This is already enforced by `TestRawURLNeverReachesLogs` and must
be extended to assert the response body specifically.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep the ad-hoc shape | Works, but reinvents a standard badly and commits the extension to it |
| Plain-text errors | No machine-readable structure; breaks the client's ability to branch |
| Always the same generic body | Loses the ability to tell the user what was wrong with their URL |