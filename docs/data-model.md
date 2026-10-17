# CyberGuard AI — Data Model

> **Status:** Implemented. MongoDB persistence landed in Phase 3;
> `server/internal/platform/mongostore` is the implementation of everything on
> this page. Scan lifecycle and queue *consumption* remain Phase 4.
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
| scan queue | **Redis**, payloads are scan IDs only | n/a |

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
  "completed_at": null
}
```

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
  { provider_scan_id: 1 },
  { name: "by_provider_scan_id",
    partialFilterExpression: { provider_scan_id: { $exists: true } } }
)
```

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
*this call* inserted. Only a caller that created the scan may enqueue a job.

### No TTL, deliberately

A scan is the audit trail for a provider submission. Its expiry is *logical* —
`expires_at` on the assessment decides staleness — not physical. A TTL index
here would delete the record that a submission happened, which is the one thing
the collection exists to prove. `TestScansHaveNoTTLIndex` asserts it.

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
| Raw URL in a queue | **Never** | Queue payloads are scan IDs only |
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
| Queue entries | Until claimed | Blocking pop |
| Provider raw reports | Not stored | — |

Development volumes are not a backup: `docker compose down -v` destroys them.

## 7. Index strategy summary

| Collection | Index | Type | Purpose |
|---|---|---|---|
| `scans` | `_id` | unique | Scan identity |
| `scans` | `url_fingerprint` | **partial unique** | One active scan per URL — the dedup guarantee |
| `scans` | `status, updated_at` | compound | Job recovery; `ListStalledScans` |
| `scans` | `provider_scan_id` | partial | Resume polling by provider job ID |
| `assessments` | `_id` | unique | Fingerprint identity and hot lookup |
| `assessments` | `expires_at` | TTL 0 | Deletion at expiry |
| `assessments` | `hostname` | regular | Host-level lookups |
| `assessments` | `registrable_domain` | regular | Domain analytics |
| `assessments` | `scan_id` | regular | Verdict by scan |
| `transient_urls` | `_id` | unique | Scan identity |
| `transient_urls` | `expires_at` | TTL 0 | Crash-window safety net |

| `rulesets` | `_id` | unique | **The version.** Publication is an insert, so the database rejects a concurrent duplicate |
| `rulesets` | `generated_at` | regular | "When was this last rebuilt?" |

Indexes are created by `Store.EnsureIndexes` and `Store.EnsureRulesetIndexes`,
idempotent steps run separately from application startup — a process that cannot
create indexes should still serve reads against a database an operator has
prepared.

In the Compose topology the `migrate` service runs these before the API and
worker start. That is not ceremony: a deployment without them has no partial
unique index, so "one provider submission per URL" silently stops being true,
and no log line looks wrong. It was found by running the API end to end, not by
any test — the repository tests create their own indexes.

### `assessments.scheme` and `assessments.path_prefix`

Two additional fields exist only so a protection rule can be built at a scope
narrower than the whole host. They are written **only** when the verdict is
`malicious`, the one verdict the ruleset policy can ever act on.

The **query string is never stored**, at any point, on any document. The same
detail is captured onto the `scans` record at submission time — the only moment
the worker holds the plaintext — and cleared from it once the verdict is known,
because the scan is the long-lived audit trail.

This narrows [ADR 0013](decisions/0013-durable-jobs-and-url-privacy.md), which
promised that a raw URL is never persisted. The trade and its alternatives are
set out in [ADR 0018](decisions/0018-ruleset-thresholds-and-scope.md#decision-2--url-retention-which-weakens-adr-0013).

`registrable_domain` derivation uses `golang.org/x/net/publicsuffix`
([ADR 0012](decisions/0012-public-suffix-list-dependency.md)), which the Phase 3
swap introduces and which becomes the module's third dependency.