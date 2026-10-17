# Architecture Decision Records

Decision records for CyberGuard AI. Newest first within status.

| ADR | Title | Status |
|---|---|---|
| [0019](0019-mongodb-queue-and-in-process-runner.md) | MongoDB is the queue, and the API runs the scan pipeline | Accepted |
| [0018](0018-ruleset-thresholds-and-scope.md) | Ruleset thresholds, scope escalation, and URL retention | Accepted |
| [0017](0017-redis-in-the-mvp.md) | Redis is part of the MVP | **Superseded** by [0019](0019-mongodb-queue-and-in-process-runner.md) |
| [0016](0016-go-module-path.md) | Go module path derived from the Git repository | Accepted |
| [0015](0015-openapi-and-rfc-9457.md) | OpenAPI contract and RFC 9457 errors | Accepted |
| [0014](0014-abuse-protection-without-authentication.md) | Abuse protection without application-level authentication | Accepted |
| [0013](0013-durable-jobs-and-url-privacy.md) | Durable jobs: scan IDs in the queue, encrypted transient URLs | Accepted, **amended** by [0019](0019-mongodb-queue-and-in-process-runner.md) |
| [0012](0012-public-suffix-list-dependency.md) | Public Suffix List dependency | Accepted |
| [0011](0011-verdict-semantics-no-threat-detected.md) | Verdict semantics: `no_threat_detected` | Accepted |
| [0010](0010-hybrid-analysis-licensing.md) | Hybrid Analysis licensing and automated submissions | Accepted (gates release) |
| [0009](0009-go-as-only-backend-language.md) | Go as the only backend language | Accepted |
| [0008](0008-defer-elasticsearch.md) | Defer Elasticsearch | Proposed |
| [0007](0007-hmac-url-fingerprinting.md) | HMAC-SHA-256 URL fingerprinting | Accepted |
| [0006](0006-error-format.md) | Error response format | **Superseded** by [0015](0015-openapi-and-rfc-9457.md) |
| [0005](0005-standard-library-http.md) | Standard library HTTP | Accepted, **amended** by [0015](0015-openapi-and-rfc-9457.md) |
| [0004](0004-scan-and-verdict-vocabulary.md) | Scan and verdict vocabulary | **Superseded** by [0011](0011-verdict-semantics-no-threat-detected.md) |
| [0003](0003-asynchronous-analysis-jobs.md) | Asynchronous analysis jobs | **Superseded** by [0013](0013-durable-jobs-and-url-privacy.md), [0017](0017-redis-in-the-mvp.md) and [0019](0019-mongodb-queue-and-in-process-runner.md) |
| [0002](0002-mongodb-as-source-of-truth.md) | MongoDB as the source of truth | Proposed |
| [0001](0001-modular-monolith.md) | Modular monolith | Proposed |

## Format

Each record states Context, Decision, and Consequences — positive and negative.
Records are immutable once accepted; a decision that changes gets a **new**
number, and the old one is marked superseded rather than edited. That is what
makes the sequence readable as a history.

## Launch blockers

Three items must be closed before any commercial release. Each is recorded as an
ADR rather than a task because each changes what the system may do:

1. **[ADR 0010](0010-hybrid-analysis-licensing.md)** — written approval for
   Hybrid Analysis usage and automated submission. Still open.
2. **[ADR 0019](0019-mongodb-queue-and-in-process-runner.md)** — rate-limit
   counters are in-process, so the configured limits are **per replica**. That is
   acceptable for one replica and not acceptable against a finite provider
   quota at several. Either run a single replica or move the counters to a
   shared store before scaling out.
3. **The `maxmemory-policy noeviction` blocker from
   [ADR 0017](0017-redis-in-the-mvp.md) is closed by that same reversal.** It
   existed because a cache eviction could silently drop a queued job. With the
   scans collection as the queue, there is no queued job for a cache to evict, so
   the hazard is gone by construction rather than by configuration.

## Related

The eight open questions these records answer were listed in
[`../implementation-plan.md`](../implementation-plan.md); that section is now
resolved and links here instead.

## Reading the Redis reversal

Redis was adopted in [0017](0017-redis-in-the-mvp.md) and removed three records
later in [0019](0019-mongodb-queue-and-in-process-runner.md). Both are kept, and
that is the point: 0017 records the reasoning that was sound at the time, and its
"Why this was reversed" section records which parts of it did not survive. The
cost 0019 accepts — per-replica rate limits — is stated there rather than
quietly dropped, and it is the reason the single-replica constraint is a launch
blocker above.
