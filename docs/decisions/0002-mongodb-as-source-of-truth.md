# 0002 — MongoDB as the source of truth

- **Status:** Accepted, **amended** by Phase 3 (see
  [Amendment](#amendment-phase-3))
- **Date:** 2026-10-16
- **Affects:** `docs/data-model.md`, `docs/architecture.md`

## Context

The system must store assessments (URL → verdict), jobs, and ruleset
snapshots. The dominant read path is: given a URL fingerprint, is there a fresh
verdict?

Requirements that constrain the choice:

1. Exact-URL lookup by a keyed fingerprint must be fast and exact.
2. A unique constraint on the fingerprint must be enforced by the database —
   this is the correctness guarantee behind job deduplication.
3. Documents have flexible, evolving shape (provider evidence, verdict
   metadata, scan state).
4. Documents must expire automatically on a time basis.
5. Atomic single-document claims must be available for the job queue.

Elasticsearch is sometimes proposed for this. It is a search index, not a
system of record: it is eventually consistent, has no unique constraint
enforceable across documents, and would introduce a second datastore whose
lag must be reasoned about on the hot path.

## Decision

Use MongoDB as the authoritative store with the official Go driver
(`go.mongodb.org/mongo-driver/v2`). Enforce uniqueness, expiry and atomic
claims through MongoDB indexes and `findOneAndUpdate`.

Elasticsearch is explicitly deferred and sits behind a feature boundary if it
is ever needed.

## Consequences

**Positive**

- A unique index on `url_fingerprint` makes "one URL, one assessment" a
  database guarantee rather than an application convention. This is what makes
  job deduplication correct under concurrency.
- `findOneAndUpdate` gives an atomic job claim with a lease, so a crashed
  worker's job is recoverable with no lock service.
- TTL indexes handle expiry and data deletion without a scheduled job.
- Flexible documents suit provider metadata that changes shape.

**Negative**

- TTL deletion is approximate (the monitor runs about every 60 seconds), so
  "deleted by `expires_at`" is not a contract. Only "not fresh after
  `expires_at`" is.
- MongoDB has no relational constraints across collections, so invariants
  spanning collections (for example, a job existing only for a pending
  assessment) are application-enforced and must be tested.
- Operational cost of running and backing up MongoDB.

## Amendment (Phase 3)

The decision — MongoDB is authoritative — stands. Two implementation details
changed while building the repositories, and are recorded here rather than
silently applied:

1. **Scans and assessments are separate collections.** This record's consequences
   section described a single fingerprint-keyed record holding both status and
   verdict. In implementation a scan is rewritten on every state transition while
   an assessment is written once and read on the hot path, so merging them would
   put churn on the read path. The dedup guarantee moved to a partial unique
   index on `scans.url_fingerprint` for active statuses, which is a *stronger*
   guarantee than the check-then-insert described here.

2. **`assessments._id` is the fingerprint**, not a surrogate identifier. This
   makes the uniqueness constraint and the hot lookup the same operation.

Neither change affects the reasoning above: MongoDB is still the source of
truth, and the unique constraint is still enforced by the database rather than by
application convention.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| PostgreSQL | An excellent fit for most of this. Rejected because the project brief names MongoDB and the flexible document shape suits variable provider metadata. Revisit if relational integrity becomes a problem |
| Redis only | Cannot be the source of truth; persistence and query capability are insufficient |
| SQLite | Single-node write contention and no TTL mechanism |
| Elasticsearch as primary store | Eventually consistent, cannot enforce the unique constraint. Would make the hot path depend on index lag |

## Revisit when

Cross-collection integrity becomes error-prone, or when measurements show the
document model is fighting the query patterns.