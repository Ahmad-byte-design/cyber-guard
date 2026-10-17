# 0019 — MongoDB is the queue, and the API runs the scan pipeline

- **Status:** Accepted
- **Date:** 2026-10-17
- **Reverses:**
  [ADR 0017](0017-redis-in-the-mvp.md) (Redis is part of the MVP)
- **Amends:** [ADR 0003](0003-asynchronous-analysis-jobs.md),
  [ADR 0013](0013-durable-jobs-and-url-privacy.md)
- **Affects:** `docker-compose.yml`, `server/Dockerfile`,
  `internal/platform/mongoqueue`, `internal/ratelimit`, `internal/mongostore`,
  `docs/architecture.md`, `docs/data-model.md`

## Context

[ADR 0017](0017-redis-in-the-mvp.md) made Redis load-bearing for two things:

1. **Job delivery.** A Redis list for pending jobs and a sorted set for
   deferred retries, consumed by a separate `worker` binary.
2. **Rate-limit counters.** Fixed windows in Redis, so limits were shared across
   every replica.

Both were in place and working. Hybrid Analysis had just been verified
end-to-end through the worker, and neither mechanism was broken. So this record
is not about fixing a failure — it is about a deliberate simplification, and the
honest accounting of what it costs is the most important part of it.

The observation that made the change worth making is that **the scans
collection was already the durable ledger for everything Redis was carrying.**
A scan document was written before a job was enqueued, and the reconciler
existed for one reason: to find scans that were durable but undelivered. The
queue was therefore a second source of truth about work the ledger already knew
about, and the reconciler was the permanent tax that kept the two in step.

## Decision

1. **The scans collection is the queue.** Work becomes a job by being
   claimable; there is no separate broker and no second write that can fail.
2. **Claiming is a time-bounded lease.** A single atomic `FindOneAndUpdate`
   matches a claimable scan and stamps `lease_owner` / `lease_expires_at` on it
   in the same operation.
3. **Deferred retries live on the document** as `available_at`. There is nothing
   to promote.
4. **The scan runner is goroutines inside the API.** The `worker` binary is
   deleted.
5. **Rate-limit counters are in-process.**

## Why a lease, and not a pop

Delivery guarantees are easy to over-read here. The old queue gave at-most-once
pop semantics, but that guarantee was never load-bearing: `Process()` already
returns immediately for a finished scan, and a scan that already carries a
`provider_scan_id` polls instead of submitting. Processing a scan twice was
always a no-op.

What *is* load-bearing is that work is not lost. A lease provides exactly that,
and it provides it with fewer moving parts than a broker:

- **Exclusivity comes from the server.** `FindOneAndUpdate` is atomic per
  document, so a second claimant simply matches nothing. Twelve concurrent
  consumers contend for one scan and exactly one wins.
- **Recovery needs no sweeper.** A consumer that is SIGKILLed mid-poll releases
  nothing, and a permanent claim would strand the scan forever with no process
  left to notice. A time-bounded lease means the clock does the recovery.
- **Deferred work needs no promoter.** `available_at` on the document is the
  schedule.

### The one number that must be right

The lease must outlive the longest possible unit of work, which is a provider
poll bounded by `WORKER_POLL_DEADLINE`. A lease shorter than that lets a second
consumer start on a scan whose analysis is still running — and on the submission
path that is the difference between polling an existing provider job and
submitting the URL a second time, which spends quota twice and creates a second
sandbox job nobody can find.

The lease is therefore **derived and validated, not configured**:

```
lease = WORKER_POLL_DEADLINE + WORKER_POLL_INTERVAL + CLAIM_LEASE_HEADROOM
```

and `CLAIM_LEASE_HEADROOM <= 0` is rejected at load. There is no setting an
operator can set that produces a double submission.

## What this costs

Stated plainly, because the trade is real:

| Change | Consequence |
|---|---|
| Rate-limit counters are per-process | The configured limits are **per replica**. Three replicas means three times the submission rate against a finite provider quota. |
| Counters are not durable | A restart is a free reset for every subject. |
| Restarting the API stops analysis | There is no second process to keep draining the queue. Analysis is unavailable for the length of a restart. |
| Two clocks, deliberately | `Claim` measures its block with the real monotonic clock and the lease with the injectable one. Sharing them made a frozen test clock wait forever for a deadline that never arrives. |

The per-replica rate limit is the one that should stop anyone scaling this out.
It is acceptable at one replica and **not acceptable against a hard financial
ceiling at several**. If that changes, the fix is local: move the counters to a
shared store behind the unchanged `ratelimit.Limiter` interface.

## What did not change

- **`POST /api/v1/check-url` still returns `202`.** Analysis runs on its own
  goroutines, so a slow detonation never holds an HTTP request open. The
  decoupling that mattered was between the request and the analysis, not between
  two processes.
- **A submission is still never retried on an ambiguous failure.** The
  specification declares no idempotency token, so a timed-out `POST /submit/url`
  may already have been accepted upstream.
- **Deduplication is still a partial unique index in MongoDB**, not an
  application check.
- **The verdict vocabulary is untouched**, as is the rule that a failed or
  unfinished analysis never produces a clean verdict.
- **Raw URLs still never leave the encrypted transient collection**, and the
  queue still carries scan identifiers only — now structurally, since the queue
  is the scan document itself.

## Consequences

- One application binary and one datastore. `docker compose up` starts two
  containers: `backend` and `mongodb`.
- The image no longer builds or ships `cyberguard-worker`.
- `github.com/redis/go-redis/v9` is no longer a dependency.
- ADR 0017 is superseded. Its `maxmemory-policy noeviction` argument is
  obsolete by construction: no queued job can now be evicted by a cache.