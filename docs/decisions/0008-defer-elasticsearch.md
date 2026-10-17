# 0008 — Defer Elasticsearch

- **Status:** Proposed
- **Date:** 2026-10-16
- **Affects:** `docs/architecture.md`, `docs/data-model.md`

## Context

Both prior documents raise Elasticsearch and both rule it out of the MVP.
This ADR records the reasoning so the decision is revisited on evidence rather
than on a recurring suggestion.

The proposed use case is searching or analysing threat-intelligence data:
"all suspicious verdicts in the last week", "hosts seen on two phishing
kits". That is a genuine search workload.

The MVP's actual hot path is not. It is: given a fingerprint, is there a fresh
verdict? That is a single-document keyed lookup — the textbook case where an
index adds latency and a consistency problem without adding capability.

## Decision

Do not adopt Elasticsearch for the MVP. If a concrete search or analytics
requirement emerges, add it **behind a feature boundary** as a derived,
rebuildable index — never as a component of the exact-URL lookup path.

## Rationale

Adopting it early would cost:

- A second datastore to run, secure, back up and keep consistent.
- An eventual-consistency window between MongoDB and the index. A scan
  response would depend on how recently the index caught up.
- A rebuild path for every index, and a test that the rebuild works.
- A class of bug — index lag producing inconsistent answers — that provides no
  product value at MVP traffic.

In exchange it would deliver: search capabilities nobody has requested yet,
over data volumes that fit comfortably in one collection.

## Conditions for adopting it

Adopt only when a concrete requirement appears, such as:

- Cross-collection IOC search across historical assessments.
- Dashboards or reporting over time series.
- Queries that cannot be served by MongoDB indexes at measured volume.

## Constraints if adopted

- MongoDB remains the source of truth.
- The index is derived and fully rebuildable from MongoDB.
- Index updates are idempotent and retryable.
- Mappings are explicit; exact-match fields are `keyword`.
- No scan response ever blocks on index success.
- Indexed fields are normalised metadata — never raw URLs or query strings.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Elasticsearch as the primary store | No unique-constraint enforcement; eventually consistent. The dedup guarantee depends on MongoDB's unique index |
| MongoDB full-text search | Not the right tool for fuzzy IOC search, but adequate for the MVP's needs and already available |
| A separate analytics warehouse | Correct long-term shape, wildly premature |