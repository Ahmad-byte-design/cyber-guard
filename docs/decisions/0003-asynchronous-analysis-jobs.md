# 0003 — Asynchronous analysis jobs

- **Status:** **Superseded** by
  [ADR 0013](0013-durable-jobs-and-url-privacy.md) and
  [ADR 0017](0017-redis-in-the-mvp.md)
- **Date:** 2026-10-16
- **Affects:** `docs/architecture.md`, `docs/data-model.md`,
  `docs/implementation-plan.md`

> **Superseded.** Two decisions later changed this record's core conclusions:
>
> - **The MongoDB-backed queue is replaced by Redis.** See
>   [ADR 0017](0017-redis-in-the-mvp.md) — Redis is required for the job queue
>   and for distributed rate-limit and quota counters. The `findOneAndUpdate`
>   claim below describes a design that is no longer being built.
> - **The open issue below is resolved.** Queue payloads now carry scan IDs
>   only; raw URLs are encrypted in a separate short-lived collection and
>   deleted immediately. See
>   [ADR 0013](0013-durable-jobs-and-url-privacy.md).
>
> This record is retained as a record of the reasoning, including the reasoning
> that turned out to be wrong about Redis. Its scan-state and deduplication
> concerns remain valid and are carried forward.

## Context

A provider analysis takes seconds to minutes. The HTTP request cannot remain
open for that duration: browser extensions time out, proxies return errors, and
a held connection is a held goroutine.

The original project brief (§13) lists Redis as a service and specifies a queue
worker. The current review prompt (§2, §11) says Redis should be used "only if
asynchronous job processing or caching requires it".

The queue must support:

- At-least-once delivery.
- Atomic claiming so two workers never process one job.
- Recovery when a worker dies mid-job.
- Bounded retries with backoff.
- No duplicate provider submissions for the same URL.

Redis appears in the Compose file because the brief required it, not because a
requirement has been shown to need it.

## Decision

Use a **MongoDB-backed job queue**: an `analysis_jobs` collection claimed with
an atomic `findOneAndUpdate` carrying a lease. Defer Redis; keep it in the
Compose file as an optional service for caching or as a future migration path.

Claiming is a single atomic operation:

```javascript
db.analysis_jobs.findOneAndUpdate(
  { status: "pending",
    available_at: { $lte: now },
    $or: [ { lease_expires_at: null },
           { lease_expires_at: { $lt: now } } ] },
  { $set: { status: "leased", claimed_by: workerID,
            lease_expires_at: now + leaseTTL },
    $inc: { attempts: 1 } },
  { sort: { available_at: 1 }, returnDocument: "after" }
)
```

## Consequences

**Positive**

- One datastore for the MVP instead of two. Less to run, back up, secure and
  reason about.
- Atomicity comes from MongoDB's single-document guarantees rather than from
  Redis semantics the application must then reconcile with MongoDB.
- The lease mechanism makes crashed workers recoverable with no extra
  infrastructure.
- If Redis is added later for caching, the queue's semantics are already
  isolated behind `platform/queue`.

**Negative**

- Polling for work adds latency and generates idle queries. Mitigated by a
  modest poll interval and, later, change streams if justified.
- Under high queue depth this is a weaker design than a purpose-built broker.
- MongoDB write load increases, mixing hot assessment writes with job churn.
  Mitigated by separate collections and indexes.

## Alternatives considered

| Alternative | Why not now |
|---|---|
| Redis + a queue library | Adds a datastore, a second failure mode, and a consistency boundary between "job queued" and "assessment exists" — to solve a problem the MVP does not have |
| Synchronous submission in the request | Violates the async requirement; holds connections for minutes |
| Provider webhook callbacks | Requires an internet-exposed endpoint and inbound auth. Polling is simpler for a self-hosted, possibly air-gapped deployment |

## Open issue

The queue is durable, so the URL must survive a restart — but the privacy
design forbids storing raw URLs. This ADR does not resolve that tension. See
[open question 4](../implementation-plan.md#11-open-questions) in the
implementation plan: encrypt the URL in the job payload with a short TTL, or
submit inline before enqueueing.

## Revisit when

Queue depth, provider throughput or write load shows MongoDB polling is not
keeping up.