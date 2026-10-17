# CyberGuard AI — Data Model

> **Status:** Implemented. MongoDB persistence landed in Phase 3;
> `server/internal/platform/mongostore` is the implementation of everything on
> this page, and `server/internal/platform/mongoqueue` adapts that same
> collection to the delivery interface the scan lifecycle consumes. Job
> *claiming* belongs on this page rather than in a queue document because a
> claim is a property of these documents.
> Uses the official MongoDB Go driver (`go.mongodb.org/mongo-driver/v2`).

MongoDB is the authoritative store. Everything else — the ruleset served to the
extension, the API's cached reads — is derived and rebuildable.

## 1. Collections

| Collection | Purpose | TTL |
|---|---|---|
| `scans` | Lifecycle and provider submission metadata; the audit trail | **No** |
| `assessments` | Normalised verdict cache, keyed by URL fingerprint | `expires_at`, 0 |
| `transient_urls` | Encrypted raw URL, deleted after submission | `expires_at`, 0 |
| `rulesets` | Versioned ruleset snapshots; `_id` is the version | No |
| ~~`ruleset_meta`~~ | Not implemented — see [ADR 0018](decisions/0018-ruleset-thresholds-and-scope.md#decision-3--no-ruleset_meta-counter) | n/a |
| ~~scan queue~~ | **Gone** — the `scans` collection *is* the queue; see §2, *Work claiming* | n/a |

There is no queue collection because there is no broker. A scan is work by being
claimable, which is a property of the scan document itself — see
[ADR 0019](decisions/0019-mongodb-queue-and-in-process-runner.md).

### Why three collections rather than one

A scan and an assessment have different write patterns and different lifetimes:

- A **scan** is rewritten on every state transition — several writes per
  submission — and retained afterwards as the record that a provider submission
  happened.
- An **assessment** is written once and read on the hot path.

Merging them would mean every status poll rewrites the document the verdict
cache reads, and would entangle verdict expiry with scan lifecycle. Separating
them keeps the hot path a small, stable document with the churn isolated.

This revises the single fingerprint-keyed record in
[ADR 0002](decisions/0002-mongodb-as-source-of-truth.md), which assumed status
and verdict lived together.

## 2. `scans`

Lifecycle record. **No field can hold a raw URL or a provider API key** — this
is structural, enforced by `TestModelsHaveNoRawURLOrKeyFields`, which reflects
over the BSON tags. There is no `url` tag to populate.

```json
{
  "_id": "scan_01ABC",
  "url_fingerprint": "9f2c…(64 hex)",
  "hostname": "example.test",
  "registrable_domain": "example.test",
  "status": "running",
  "attempts": 1,
  "max_attempts": 3,
  "provider": "hybrid-analysis",
  "provider_scan_id": "job-123",
  "provider_submission_id": "sub-456",
  "provider_state": "IN_PROGRESS",
  "provider_environment_id": 140,
  "submitted_at": "2026-10-16T12:00:00Z",
  "created_at": "2026-10-16T12:00:00Z",
  "updated_at": "2026-10-16T12:00:05Z",
  "started_at": "2026-10-16T12:00:05Z",
  "completed_at": null,
  "available_at": "2026-10-16T12:00:05Z",
  "lease_owner": "api-6f4c1/41",
  "lease_expires_at": "2026-10-16T12:05:35Z"
}
```

The last three fields are work-claiming state and are covered in *Work claiming*
below. They are the only reason this collection doubles as the queue.

### Status vocabulary

`queued` · `running` · `completed` · `failed` · `timed_out` · `expired`

Matching `openapi.yaml` and [ADR 0011](decisions/0011-verdict-semantics-no-threat-detected.md).
A scan has **no verdict field**, so "a failed scan carries a clean verdict" is
not merely forbidden — it is unrepresentable.

### Indexes

```javascript
db.scans.createIndex(
  { url_fingerprint: 1 },
  { unique: true,
    name: "uniq_active_scan",
    partialFilterExpression: { status: { $in: ["queued", "running"] } } }
)

db.scans.createIndex({ status: 1, updated_at: 1 }, { name: "by_status_updated" })

db.scans.createIndex(
  { status: 1, available_at: 1, lease_expires_at: 1 },
  { name: "by_claimable" }
)

db.scans.createIndex(
  { provider_scan_id: 1 },
  { name: "by_provider_scan_id",
    partialFilterExpression: { provider_scan_id: { $exists: true } } }
)
```

`by_claimable` backs the claim query — active status, due at or before now, and
either unleased or holding a lapsed lease. It is the one index whose absence
hurts **correctness** rather than latency: without it every consumer poll is a
collection scan over all history, so claiming gets slower forever and a busy
queue gets slower still. The prefix (`status`, then `available_at`) is the order
the filter reads, which is why `lease_expires_at` is last rather than first.

**`uniq_active_scan` is the deduplication guarantee.** It is why N concurrent
requests for one URL produce exactly one provider submission: the database
rejects the second insert, so correctness does not depend on the application
behaving correctly under a race.

It is **partial** so completed and failed scans for the same fingerprint
accumulate freely. History must not be constrained by a rule that only matters
while a scan is in flight.

`$in` inside `partialFilterExpression` was verified against MongoDB 9.0.4 before
this design was committed, not assumed.

### Why a read-then-write check is not enough

`FindActiveScanByFingerprint` followed by `InsertOne` is a TOCTOU race: two
concurrent requests can both observe "no active scan" and both insert. The
partial unique index closes it.

`CreateScan` returns `(scan, created, error)` where `created` reports whether
*this call* inserted. Only a caller that created the scan has work to make
visible — and with no broker, that work is already visible the moment the
document exists, so `Enqueue` is a no-op kept as the seam a future broker would
return through.

### No TTL, deliberately

A scan is the audit trail for a provider submission. Its expiry is *logical* —
`expires_at` on the assessment decides staleness — not physical. A TTL index
here would delete the record that a submission happened, which is the one thing
the collection exists to prove. `TestScansHaveNoTTLIndex` asserts it.

### Work claiming — the queue is this collection

There is no separate broker. A scan becomes work by being *claimable*, and
claiming it is a **single atomic `FindOneAndUpdate`** that selects a claimable
scan and stamps a lease on it in the same operation
(`mongostore.ClaimNextScan`):

```javascript
// Conceptually — the shipped filter, in the order the server evaluates it.
db.scans.findOneAndUpdate(
  { status: { $in: ["queued", "running"] },
    $and: [
      { $or: [ { available_at: { $exists: false } },
               { available_at: { $lte: now } } ] },
      { $or: [ { lease_expires_at: { $exists: false } },
               { lease_expires_at: null },
               { lease_expires_at: { $lte: now } } ] }
    ] },
  { $set: { lease_owner: owner,
            lease_expires_at: nowPlusLease,
            available_at: now,
            updated_at: now } },
  { sort: { available_at: 1, created_at: 1 },
    returnDocument: "after" }
)
```

Three properties follow from that being **one** operation rather than a read
followed by a write:

- **Exclusivity belongs to the server.** `findAndModify` is atomic per
  document, so a second claimant matches nothing: the first update already moved
  the document out of the claimable set. A dozen concurrent consumers contend for
  one scan and exactly one wins, and nothing about *which* of them wins matters.
- **The `$exists` branches are not defensive padding.** `{"available_at":
  {"$lte": now}}` does **not** match a document where the field is missing —
  MongoDB does not compare an absent field against a date in the query language.
  Without the absent branch, every scan written before these fields existed would
  be stranded permanently and never picked up again. `lease_expires_at` needs
  the same three-way treatment (absent, explicit null, lapsed) for the same
  reason.
- **Ordering is by due time, then age.** `sort: {available_at, created_at}`
  means a deferred retry is overtaken only by work that was already due, so
  starvation needs a flood of earlier submissions, not just a busy queue.

Delivery guarantees are easy to over-read here. The old broker gave at-most-once
pop semantics, but that guarantee was never load-bearing: `Process()` returns
immediately for a finished scan, and a scan that already carries a
`provider_scan_id` polls instead of submitting, so processing a scan twice was
always a no-op. What *is* load-bearing is that work is not **lost** — and that is
exactly what a lease on the ledger guarantees.

### Why the lease expires rather than being released

A consumer that is SIGKILLed mid-poll releases nothing, and a permanent claim
would strand that scan forever with no process left to notice. Expiry *is* the
recovery mechanism: no sweeper, no reaper, no cleanup pass, nothing to
reconcile. The clock does it.

The lease must therefore be **longer than the longest possible unit of work**,
which here is a provider poll bounded by `WORKER_POLL_DEADLINE`. A lease shorter
than that would let a second consumer start on a scan whose analysis is still
running — and on the submission path that is the difference between polling an
existing provider job and submitting the URL a second time, which spends quota
twice and creates a sandbox job nobody can find. The lease is therefore derived
rather than configured:

```
lease = WORKER_POLL_DEADLINE + WORKER_POLL_INTERVAL + CLAIM_LEASE_HEADROOM
```

and a non-positive `CLAIM_LEASE_HEADROOM` is rejected when configuration loads.
There is no setting an operator can set that produces a double submission.

`lease_owner` is **diagnostic only**. A lease is released by expiry, by
`ReleaseScanLease`, or by being overwritten — never by matching an owner string,
so a consumer that comes back under a new name cannot strand its own work.

### Retry scheduling

A deferred retry is `available_at` on the document. `ScheduleScanRetry` sets it
and drops the lease in the same update. `ReleaseScanLease` sets it to *now*, so
a retry need not wait out an expiry that recovery has already decided was
unnecessary.

This replaced a Redis sorted set of due times and, with it, the promoter that
moved entries between a pending list and that set. There is nothing to promote:
a deferred scan becomes claimable because its `available_at` has passed, which
the claim query above already tests. `PromoteDue` survives as an inert method
returning zero so the supervisor's log line stays meaningful — and so that a
broker returning later has an obvious seam to grow through.

**What this changed about recovery.** `ListStalledScans` and the reconciler still
exist, but their subject moved. They used to find scans that were *durable but
never delivered* — work a crashed broker could have dropped on the floor. Delivery
is now a property of the document, so the only scans still needing repair are
ones whose **consumer** died mid-analysis, and those recover by themselves once
the lease lapses. The reconciler is now a stalled-progress check, not a delivery
repair.

## 3. `assessments`

The verdict cache. Written once per completed analysis, read on the hot path.

```json
{
  "_id": "9f2c…(the URL fingerprint)",
  "scan_id": "scan_01ABC",
  "hostname": "example.test",
  "registrable_domain": "example.test",
  "verdict": "suspicious",
  "provider": "hybrid-analysis",
  "provider_scan_id": "job-123",
  "evidence": [
    { "type": "provider_verdict", "summary": "Provider returned a suspicious classification" }
  ],
  "analyzed_at": "2026-10-16T12:00:00Z",
  "expires_at": "2026-10-17T12:00:00Z",
  "created_at": "2026-10-16T12:00:00Z",
  "updated_at": "2026-10-16T12:00:00Z"
}
```

**`_id` is the URL fingerprint.** This makes the unique constraint and the hot
lookup the same operation, and makes a duplicate verdict for one URL
unrepresentable without a second index to keep in sync.

This is a deliberate simplification: the earlier design specified a surrogate
`_id` plus a unique index on `url_fingerprint`. Two structures enforcing one
rule can drift; a primary key cannot.

### Indexes

```javascript
db.assessments.createIndex({ expires_at: 1 }, { name: "ttl_expires_at", expireAfterSeconds: 0 })
db.assessments.createIndex({ hostname: 1 },           { name: "by_hostname" })
db.assessments.createIndex({ registrable_domain: 1 }, { name: "by_domain" })
db.assessments.createIndex({ scan_id: 1 },            { name: "by_scan_id" })
```

This is the one collection whose retention policy explicitly permits automatic
deletion: a verdict is worthless once stale. `verdict` is stored as
`verdicts.Verdict`, so reintroducing `benign` would not compile.

### Expiry semantics

Two meanings must not be conflated:

| Concept | Mechanism |
|---|---|
| **Verdict freshness** | `expires_at` compared on read, via `FindFreshAssessment` |
| **Record deletion** | TTL index, plus explicit `ExpireAssessment` |

The TTL monitor runs roughly once a minute, so deletion is approximate.
`FindFreshAssessment` hides an expired verdict by returning "not found", making
stale and absent behave identically to every caller — no caller can serve a
stale verdict by forgetting a check.

## 4. `transient_urls`

The only place a raw URL is ever persisted, and only encrypted.

```json
{
  "_id": "scan_01ABC",
  "ciphertext": "<base64, AES-256-GCM>",
  "nonce": "<base64, 96-bit, fresh per record>",
  "created_at": "2026-10-16T12:00:00Z",
  "expires_at": "2026-10-16T12:10:00Z"
}
```

```javascript
db.transient_urls.createIndex({ expires_at: 1 }, { name: "ttl_expires_at", expireAfterSeconds: 0 })
```

Per [ADR 0013](decisions/0013-durable-jobs-and-url-privacy.md):

- **AES-256-GCM**, so tampering is detected rather than decrypted into garbage.
- **Fresh 96-bit nonce per record.** Reuse under one key destroys GCM's
  authentication guarantee for both records.
- **`_id` is the AAD**, binding ciphertext to its record so an attacker with
  write access cannot move one scan's URL into another's slot.
- **Key separation.** `URL_ENCRYPTION_KEY` differs from
  `URL_FINGERPRINT_HMAC_KEY`: rotating the latter invalidates the whole cache,
  rotating the former only strands in-flight jobs.
- **Deletion is explicit.** `TakeTransientURL` reads and deletes in one
  operation. The TTL index is only a safety net for a crash between store and
  delete.

There is no field that *could* hold the plaintext, so a refactor cannot start
persisting one without adding the field and failing a test.

## 5. Privacy properties

| Data | Retained | Justification |
|---|---|---|
| Full raw URL | **Only encrypted, only briefly** | `transient_urls`, deleted on submit |
| Raw URL in a queue | **Never** | There is no queue payload: the queue *is* the scan document, which has no URL field to put one in |
| HMAC fingerprint | Yes | Required for exact-URL cache lookup |
| Hostname / domain | Yes | Host-level lookup; not anonymous |
| Provider job ID / submission ID | Yes | Resume polling after restart |
| Provider API key | **Never** | Not a field on any document |

`TestNoDocumentCarriesRawURLOrAPIKey` writes a scan, an assessment and an
encrypted URL, reads every raw document back, and asserts no collection
contains the plaintext URL or a key string.

### On "hashing the URL"

A plain unsalted hash is not anonymisation: URLs come from a small effective
space, so a candidate list recovers the original in seconds. HMAC-SHA-256 with a
backend-only key raises that to a full dictionary attack per key. The key is
the security boundary — if it leaks, every fingerprint becomes reversible.

A fingerprint is still a pseudonymous identifier, not anonymisation. A hostname,
a verdict and a timestamp reveal "this user checked a site on this date".

## 6. Retention

| Data | Retention | Mechanism |
|---|---|---|
| Raw URL (encrypted) | Minutes; deleted on submit | Explicit delete, TTL net |
| Scan records | Indefinite | **No TTL** — audit trail |
| Assessments | Until `expires_at` | TTL index, plus explicit expiry |
| Claimable scans | Until claimed, then until the lease lapses | Lease on the scan document — no entry to delete |
| Provider raw reports | Not stored | — |

Development volumes are not a backup: `docker compose down -v` destroys them.

## 7. Index strategy summary

| Collection | Index | Type | Purpose |
|---|---|---|---|
| `scans` | `_id` | unique | Scan identity |
| `scans` | `url_fingerprint` | **partial unique** | One active scan per URL — the dedup guarantee |
| `scans` | `status, updated_at` | compound | Job recovery; `ListStalledScans` |
| `scans` | `status, available_at, lease_expires_at` | compound | **The claim query.** Miss this and every consumer poll is a collection scan over all history |
| `scans` | `provider_scan_id` | partial | Resume polling by provider job ID |
| `assessments` | `_id` | unique | Fingerprint identity and hot lookup |
| `assessments` | `expires_at` | TTL 0 | Deletion at expiry |
| `assessments` | `hostname` | regular | Host-level lookups |
| `assessments` | `registrable_domain` | regular | Domain analytics |
| `assessments` | `scan_id` | regular | Verdict by scan |
| `transient_urls` | `_id` | unique | Scan identity |
| `transient_urls` | `expires_at` | TTL 0 | Crash-window safety net |
| `scans` | `url_fingerprint, created_at desc` | regular | Backs `POST /api/v1/get-url`, which resolves a URL to its most recent scan. The partial `uniq_active_scan` index cannot serve it: that one holds only active scans |
| `rulesets` | `_id` | unique | **The version.** Publication is an insert, so the database rejects a concurrent duplicate |
| `rulesets` | `generated_at` | regular | "When was this last rebuilt?" |

Indexes are created by `Store.EnsureIndexes` and `Store.EnsureRulesetIndexes`,
idempotent steps run separately from application startup — a process that cannot
create indexes should still serve reads against a database an operator has
prepared.

In the Compose topology the `migrate` service runs these before the API
starts. That is not ceremony: a deployment without them has no partial
unique index, so "one provider submission per URL" silently stops being true,
and no log line looks wrong. It was found by running the API end to end, not by
any test — the repository tests create their own indexes. The same applies one
step further: without `by_claimable`, scans are still claimed correctly, just
more slowly, for ever.

### `assessments.scheme` and `assessments.path_prefix`

Two additional fields exist only so a protection rule can be built at a scope
narrower than the whole host. They are written **only** when the verdict is
`malicious`, the one verdict the ruleset policy can ever act on.

The **query string is never stored**, at any point, on any document. The same
detail is captured onto the `scans` record at submission time — the only moment
the scan runner holds the plaintext — and cleared from it once the verdict is
known, because the scan is the long-lived audit trail.

This narrows [ADR 0013](decisions/0013-durable-jobs-and-url-privacy.md), which
promised that a raw URL is never persisted. The trade and its alternatives are
set out in [ADR 0018](decisions/0018-ruleset-thresholds-and-scope.md#decision-2--url-retention-which-weakens-adr-0013).

`registrable_domain` derivation uses `golang.org/x/net/publicsuffix`
([ADR 0012](decisions/0012-public-suffix-list-dependency.md)), which the Phase 3
swap introduces and which becomes the module's third dependency.