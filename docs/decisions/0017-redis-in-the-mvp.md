# 0017 — Redis is part of the MVP

- **Status:** **Superseded** by
  [ADR 0019](0019-mongodb-queue-and-in-process-runner.md)
- **Date:** 2026-10-16
- **Reverses:** the "defer Redis" recommendation in
  [ADR 0003](0003-asynchronous-analysis-jobs.md)
- **Affects:** `docker-compose.yml`, `architecture.md`, `data-model.md`

> **Superseded 2026-10-17.** Redis has been removed. Its job queue became a
> time-bounded lease on the scans collection, and its rate-limit counters became
> in-process — see
> [ADR 0019](0019-mongodb-queue-and-in-process-runner.md).
>
> This record is kept because the reasoning below explains why Redis was adopted
> in the first place, and reading it against ADR 0019 is how the reversal becomes
> legible: the second argument for Redis turned out to rest on a premise that did
> not hold. See "Why this was reversed" at the end.

## Context

[ADR 0003](0003-asynchronous-analysis-jobs.md) proposed deferring Redis, on the
grounds that a MongoDB-backed queue was sufficient for MVP-scale traffic and
that one datastore is simpler than two.

Two decisions taken since then make Redis load-bearing:

1. **[ADR 0013](0013-durable-jobs-and-url-privacy.md)** defines the queue
   payload as a scan ID, with a separate short-lived collection for encrypted
   transient URLs. The queue itself now needs a durable, list-shaped structure
   with blocking pops — not a MongoDB collection.
2. **[ADR 0014](0014-abuse-protection-without-authentication.md)** requires
   distributed rate limiting and quota counters. Those counters must be shared
   across API replicas and must be atomic. Redis is the natural home, and a
   MongoDB round trip per request to increment a rate-limit counter is
   indefensible on a hot path.

The original "does Redis actually need to be here?" question now has a
concrete answer: yes, twice over.

## Decision

**Redis is a required MVP service.** It provides:

| Purpose | Mechanism |
|---|---|
| Scan job queue | List, with blocking pop |
| Rate-limit counters | Atomic `INCR` + `EXPIRE` |
| Quota counters | Atomic, with fail-closed threshold |
| Concurrency semaphores | Atomic counters / `SET NX` leases |

The Compose file already defines it and the stack runs it; this ADR ratifies
that as intentional rather than provisional.

## Constraints

Redis remains **internal to the Compose network**. It publishes no host port in
any environment. This is not configurable away — the datastore is
unauthenticated, and exposing it would be a direct data-exposure path. See
`docker-development.md` §1.

Redis is a **cache and coordination store, not a source of truth**. MongoDB
remains authoritative ([ADR 0002](0002-mongodb-as-source-of-truth.md)):

- Losing Redis loses queued jobs and rate counters, not assessments.
- Losing Redis must not lose verdicts, and must not make the API unable to
  serve cached reads. The API degrades: submissions are refused or queued for
  retry, reads continue.
- A Redis flush costs queued work, not history. That asymmetry is the reason
  Redis is acceptable here at all.

## Consequences

**Positive**

- The queue is a purpose-built structure with blocking pop, rather than
  polling a MongoDB collection. Lower latency, less idle load.
- Rate limiting and quota enforcement are cheap atomic operations on the hot
  path rather than database round trips.
- Queue payloads contain scan IDs only, so a Redis dump reveals no URLs —
  reinforced by [ADR 0013](0013-durable-jobs-and-url-privacy.md).

**Negative**

- Two datastores to run, secure, back up and monitor for the MVP.
- Two failure modes instead of one. Redis being down must degrade gracefully,
  which is a requirement on the API's readiness and error paths.
- Distributed counters are eventually consistent by nature. Rate limiting that
  is momentarily imprecise is acceptable; quota enforcement must fail closed.

## Failure behaviour

| Condition | Behaviour |
|---|---|
| Redis down, API | Readiness reports degraded. Cached reads still served. New submissions return `503` with `Retry-After` — **fail closed**, not open |
| Redis down, worker | Cannot claim jobs. Existing claims complete. Queue is preserved by AOF |
| Redis flushed | Queued jobs lost; assessments intact. API reassesses on next request |
| Redis saturated | Evicted keys are queue entries. Documented risk; `maxmemory-policy noeviction` is required so the queue is not silently dropped |

## Required configuration

- `appendonly yes` — already set, so queued jobs survive a restart.
- `maxmemory-policy noeviction` — **must** be set. Under an `allkeys-lru`
  policy Redis would silently evict queue entries under memory pressure, which
  is indistinguishable from a lost job.

That second point is a genuine footgun and should be treated as a launch
blocker alongside the licensing gate in
[ADR 0010](0010-hybrid-analysis-licensing.md).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| MongoDB for the queue and counters | Polling latency, idle load, and a database round trip per rate-limit check on the hot path |
| In-process rate limiting | Per-instance, so a multi-replica deployment multiplies every limit by the replica count |
| Skip rate limiting in v1 | [ADR 0014](0014-abuse-protection-without-authentication.md) makes it mandatory; it is the only protection without authentication |
| Replace Redis with a hosted service | Premature; self-hosted MVP first |

## Revisit when

Never, on the grounds of dependency count alone — Redis is doing two jobs that
MongoDB does poorly. Revisit only if a specific failure mode appears that
neither technology handles.

## Why this was reversed

Read against [ADR 0019](0019-mongodb-queue-and-in-process-runner.md), the two
rejections above resolve differently.

**"MongoDB for the queue — polling latency."** This was the strongest argument
for Redis, and it is the one that did not survive contact with the code. The
lease model does not poll for *work*; it polls only while *idle*, and an idle
poll is a single indexed `FindOneAndUpdate` bounded by `WORKER_CLAIM_POLL_GAP`.
More decisively, the old queue's durability was not buying anything the scan
document was not already providing: a scan was written to MongoDB *before* it was
enqueued, so every queued job already had a document behind it, and the
reconciler already existed to find documents whose job went missing. Redis was
carrying a second, redundant record of work MongoDB already knew about.

**"In-process rate limiting — per-instance limits."** This rejection was correct
as written and remains correct. It is the one cost
[ADR 0019](0019-mongodb-queue-and-in-process-runner.md) accepts rather than
solves, recorded there as the reason not to scale this deployment out. It is
acceptable at one replica and it stays reversed only for as long as that is true.

The third rejection, skipping rate limiting entirely, was never revisited.