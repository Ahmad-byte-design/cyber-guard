# 0014 — Abuse protection without application-level authentication

- **Status:** Accepted
- **Date:** 2026-10-16
- **Affects:** `api-contract.md`, `security-and-privacy.md`, `module-map.md`

## Context

CyberGuard AI v1 has **no application-level authentication and no employee or
user account management**. This is a deliberate product decision, not an
omission.

The reasons are real:

- A browser extension is distributed to end users. Any secret it carries is
  extractable from the package by anyone who wants to look — it is not a
  secret, it is a published string. An API key inside an extension is a
  credential handed to every user and to every extension reviewer.
- Identity implies a user store, password handling, session management, account
  recovery, and an administrative surface — all explicitly outside the MVP in
  the original brief.
- The primary abuse risk is **not** confidentiality. There is no user data to
  steal. It is **quota consumption**: an attacker spending the operator's
  provider credits.

So the endpoint is unauthenticated by design, and the threat model must be
built around that rather than around authentication.

The initial deployment is **private / self-hosted**, which is the primary
mitigation. A self-hosted operator behind their own network boundary has a
fundamentally smaller attack surface than a public SaaS endpoint.

## Decision

**The public API must have rate limits, quotas, request limits and concurrency
controls.** Authentication is not part of the v1 mitigation strategy, and is not
substituted for any of the four.

| Control | Purpose |
|---|---|
| **Rate limits** | Bound request rate per client identity and per fingerprint |
| **Quotas** | Hard ceilings that fail closed before a provider or infrastructure limit is hit |
| **Request limits** | Bound the size and shape of any single request |
| **Concurrency controls** | Bound in-flight work so a burst cannot exhaust the process |

### Required controls

| Control | Value | Key | Rationale |
|---|---|---|---|
| Per-client request rate | 60 req/min | Client IP, or install token where deployed | Bounds a single source |
| Per-fingerprint submission rate | 10/hour | `url_fingerprint` | **The control that actually protects quota** |
| Global daily submission ceiling | Configurable | Global counter | Fails closed before the provider contract is breached |
| Concurrent provider submissions | Configurable, ≤ provider limit | Worker semaphore | Prevents self-inflicted rate limiting |
| Request body size | 8 KiB | — | Bounds memory; prevents oversized-payload DoS |
| URL length | 2048 chars | — | Bounds parsing, hashing, logging |
| Global concurrent requests | Configurable | Semaphore/middleware | Bounds goroutine growth under load |

### Identity without authentication

"Per client" cannot mean "per authenticated user". It means the strongest
identity available without secrets:

1. **Client IP**, where the deployment has a meaningful notion of one.
2. **Server-issued install token** for managed deployments — a revocable
   identifier, not a user identity. It is issued out of band, grants no user
   capabilities, and exists purely to make rate limiting and attribution
   possible.
3. **Per-fingerprint counters**, which work with no identity at all.

Layer 3 is the important one: it protects the quota even when every client is
anonymous and shares a NAT egress.

### Failure mode

Quota exhaustion must **fail closed**: return `503` with `Retry-After` and stop
enqueuing. It must never fail open by silently exceeding the provider's
contract.

### What is explicitly rejected as a mitigation

- **CORS.** A browser control, not authentication. It constrains browsers, not
  scripts.
- **Obfuscation.** Security by obscurity; an extractable "secret" in an
  extension is published.
- **A shared API key in the extension.** Distributes the credential to every
  user, guaranteeing eventual disclosure and attributing all abuse to the
  operator.
- **Rate limiting alone.** Bounds rate, not total volume. Quotas are required
  alongside it.
- **Network placement alone.** Correct and effective for the initial deployment,
  and treated as defence in depth — not as the only control, because a
  self-hosted deployment can be exposed by mistake.

## Consequences

**Positive**

- No credential distribution problem, which is the hardest security problem in
  extension-based products.
- No account system to build, secure, or breach.
- Quota abuse is bounded by controls that work without identity.

**Negative**

- No per-user attribution. Abuse is attributable only by IP.
- A shared-NAT deployment (corporate egress, mobile carrier) can exhaust a
  per-IP limit collectively. Mitigated by per-fingerprint quotas, which are
  unaffected by shared egress.
- A determined distributed attacker is limited but not stopped. Mitigated by
  global quotas that fail closed.
- Distributed rate limiting requires shared state (Redis), which is why
  [ADR 0017](0017-redis-in-the-mvp.md) keeps Redis.

## Consequences for later versions

Adding authentication is a v2+ decision and a breaking change to the client
contract. When it happens:

- It must be additive: unauthenticated requests continue to work at reduced
  limits, or the extension gains a token handshake.
- The install token mechanism from ADR 0013 should be designed so it can be
  upgraded into a real credential without a queue payload format change.

No part of v1 should foreclose that upgrade.