# Architecture Decision Records

Decision records for CyberGuard AI. Newest first within status.

| ADR | Title | Status |
|---|---|---|
| [0017](0017-redis-in-the-mvp.md) | Redis is part of the MVP | Accepted |
| [0016](0016-go-module-path.md) | Go module path derived from the Git repository | Accepted |
| [0015](0015-openapi-and-rfc-9457.md) | OpenAPI contract and RFC 9457 errors | Accepted |
| [0014](0014-abuse-protection-without-authentication.md) | Abuse protection without application-level authentication | Accepted |
| [0013](0013-durable-jobs-and-url-privacy.md) | Durable jobs: scan IDs in the queue, encrypted transient URLs | Accepted |
| [0012](0012-public-suffix-list-dependency.md) | Public Suffix List dependency | Accepted |
| [0011](0011-verdict-semantics-no-threat-detected.md) | Verdict semantics: `no_threat_detected` | Accepted |
| [0010](0010-hybrid-analysis-licensing.md) | Hybrid Analysis licensing and automated submissions | Accepted (gates release) |
| [0009](0009-go-as-only-backend-language.md) | Go as the only backend language | Accepted |
| [0008](0008-defer-elasticsearch.md) | Defer Elasticsearch | Proposed |
| [0007](0007-hmac-url-fingerprinting.md) | HMAC-SHA-256 URL fingerprinting | Accepted |
| [0006](0006-error-format.md) | Error response format | **Superseded** by [0015](0015-openapi-and-rfc-9457.md) |
| [0005](0005-standard-library-http.md) | Standard library HTTP | Accepted, **amended** by [0015](0015-openapi-and-rfc-9457.md) |
| [0004](0004-scan-and-verdict-vocabulary.md) | Scan and verdict vocabulary | **Superseded** by [0011](0011-verdict-semantics-no-threat-detected.md) |
| [0003](0003-asynchronous-analysis-jobs.md) | Asynchronous analysis jobs | **Superseded** by [0013](0013-durable-jobs-and-url-privacy.md) and [0017](0017-redis-in-the-mvp.md) |
| [0002](0002-mongodb-as-source-of-truth.md) | MongoDB as the source of truth | Proposed |
| [0001](0001-modular-monolith.md) | Modular monolith | Proposed |

## Format

Each record states Context, Decision, and Consequences — positive and negative.
Records are immutable once accepted; a decision that changes gets a **new**
number, and the old one is marked superseded rather than edited. That is what
makes the sequence readable as a history.

## Launch blockers

Two items must be closed before any commercial release. Both are recorded as
ADRs rather than tasks because each changes what the system may do:

1. **[ADR 0010](0010-hybrid-analysis-licensing.md)** — written approval for
   Hybrid Analysis usage and automated submission.
2. **[ADR 0017](0017-redis-in-the-mvp.md)** — `maxmemory-policy noeviction`
   configured, or the queue can be silently evicted under memory pressure.

## Related

The eight open questions these records answer were listed in
[`../implementation-plan.md`](../implementation-plan.md); that section is now
resolved and links here instead.
- [0018 — Ruleset thresholds, scope escalation, and URL retention](0018-ruleset-thresholds-and-scope.md) — records two unratified thresholds and the URL-retention trade the policy forces
