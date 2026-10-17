# CyberGuard AI — Testing Strategy

> **Status:** Partly implemented. Phases 1–4 are built and tested: unit tests,
> an in-memory `Store`/`Queue`, and an integration harness against live MongoDB.
> What remains specified but unbuilt is the CI pipeline and the fuzz
> target. See [Known gaps](#known-gaps).
>
> **Running the integration suite.** It needs a MongoDB and nothing else:
>
> ```sh
> docker compose up -d mongodb
> docker compose run --rm go go test -tags integration ./...
> ```
>
> There is no Redis to start and no `REDIS_URI` to set. The queue behaviour that
> once needed a second datastore is now a property of the `scans` collection, so
> it is tested against the one server that actually has to provide it.

## 1. Principles

1. **Test behaviour, not implementation.** A test that asserts "the MongoDB
   call happened" breaks on every refactor and proves nothing. Assert the
   resulting state.
2. **No live provider calls, ever.** An automated test that submits to Hybrid
   Analysis spends real quota, depends on the network, and may violate the
   provider's terms. Recorded fixtures and `httptest` only.
3. **Pure logic is tested exhaustively; adapters against a fake.** The URL and
   verdict logic is where correctness actually lives and is cheap to test.
4. **The security tests are load-bearing.** They encode requirements from
   `security-and-privacy.md` and are as important as the feature tests.

## 2. Layers

| Layer | Scope | Needs | Tag |
|---|---|---|---|
| 1. Unit | Pure functions: URL rules, verdicts, ruleset generation | nothing | — |
| 2. Handler | Routes, middleware, validation, status mapping | nothing | — |
| 3. Application | Scan lifecycle, dedup, claim and retry orchestration | fake stores | — |
| 4. Integration | MongoDB indexes, dedup, claim atomicity, leases | real MongoDB | `integration` |
| 5. Adapter | Provider request/response mapping | `httptest.Server` | — |
| 6. Security | Leakage, scheme rejection, secret handling | — | — |
| 7. End-to-end | Full request → scan → verdict → ruleset | Compose stack | `e2e` |

Layers 4 and 7 are behind build tags so `go test ./...` stays fast and
dependency-free.

## 3. Layer 1 — URL intelligence

Pure, dependency-free, and the highest value per line written. Already
implemented in `internal/urlintel/urlintel_test.go`.

### Validation

| Case | Expectation |
|---|---|
| `https://example.test/login` | accepted |
| `  https://example.test/padded  ` | accepted — paste adds whitespace |
| `javascript:alert(1)`, `file:///etc/passwd`, `ftp://`, `data:` | rejected |
| `https://user:pw@host/` | rejected — embedded credentials |
| `https://` | rejected — no host |
| `https://exa\nmple.test` | rejected — control characters |
| Over 2048 characters | rejected |
| `https://host:notaport/` | rejected |

**Fuzz `Validate`.** It parses untrusted input and is the system's outer
boundary:

```go
func FuzzValidate(f *testing.F) {
    f.Add("https://example.test/p?q=1")
    f.Add("http://user:pw@host/")

    f.Fuzz(func(t *testing.T, raw string) {
        u, err := urlintel.Validate(raw)
        if err == nil {
            // Anything accepted must satisfy the invariants we rely on later.
            if u.Scheme != "http" && u.Scheme != "https" {
                t.Fatalf("accepted non-HTTP scheme %q", u.Scheme)
            }
            if u.User != nil {
                t.Fatal("accepted URL with credentials")
            }
            if u.Hostname() == "" {
                t.Fatal("accepted URL with empty hostname")
            }
        }
    })
}
```

### Canonicalisation

The cases that must never regress:

| Input | Canonical form | Why |
|---|---|---|
| `https://example.test` | `https://example.test/` | Same resource; must fingerprint identically |
| `https://EXAMPLE.TEST/x` | `https://example.test/x` | Host is case-insensitive |
| `https://example.test/Path` | `https://example.test/Path` | **Path case preserved** |
| `https://example.test/?B=2&a=1` | unchanged | **Query order preserved** |
| `https://example.test/p#frag` | `https://example.test/p` | Fragments never reach a server |

The last three are the ones a careless "helpful" refactor breaks, and each
breakage silently merges or splits cache entries. Each has a named test.

### Fingerprinting

| Case | Expectation |
|---|---|
| Same input twice | identical fingerprint |
| Host case differs | identical fingerprint |
| Path differs | **different** fingerprint |
| Query differs | **different** fingerprint |
| Different keys, same input | **different** fingerprints |
| Empty key | error, never a fingerprint |

An unkeyed fingerprint would let anyone confirm guesses about URLs already
assessed, so the empty-key case is a security requirement, not an edge case.

### Public Suffix List

`RegistrableDomain` currently uses a hand-rolled list. It needs a corpus test:
a table of hosts across suffixes — `co.uk`, `com.au`, multi-level public
suffixes, IDN/punycode — plus **negative** cases that prove it does not treat
a registrable domain as a public suffix. This must be replaced with a real PSL
implementation before it influences any rule.

## 4. Layer 2 — HTTP handlers

`httptest.NewRecorder` plus the real handler chain. Already implemented in
`internal/httpapi/server_test.go`.

Cover: every documented status code on every endpoint; validation failures;
unknown-field rejection; request-ID echo and generation; panic recovery
returning `500` without leaking the panic value; readiness behaviour with and
without the HMAC key.

Contract tests should be table-driven and assert **status plus the `code`
field**, never the full `message` string — prose changes, codes are contract.

## 5. Layer 3 — Scan lifecycle

Uses in-memory fakes for the store and the queue. No MongoDB.

### The deduplication guarantee

This is the highest-value test in the system:

```go
func TestCheckURL_ConcurrentRequestsProduceOneJob(t *testing.T) {
    store := newFakeStore()
    queue := newFakeQueue()
    svc := scans.New(store, queue, fakeProvider{})

    const n = 50
    var wg sync.WaitGroup
    scanIDs := make([]string, n)

    for i := 0; i < n; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            res, err := svc.CheckURL(t.Context(), "https://example.test/login")
            if err != nil {
                t.Error(err)
                return
            }
            scanIDs[i] = res.ScanID
        }(i)
    }
    wg.Wait()

    // Drain whatever is claimable. The fake records every delivery, repeats
    // included, so this counts deliveries rather than queue length.
    for {
        if _, err := queue.Claim(t.Context(), 0); errors.Is(err, scans.ErrNoJob) {
            break
        }
    }
    if got := len(queue.Claimed); got != 1 {
        t.Fatalf("delivered %d jobs, want exactly 1", got)
    }
    for i, id := range scanIDs {
        if id != scanIDs[0] {
            t.Fatalf("client %d got scan %q, want the shared %q", i, id, scanIDs[0])
        }
    }
}
```

Run it with `-race`. It asserts the externally observable guarantee: one job,
one scan ID, every client polling something that will actually complete.

The assertion counts *deliveries* rather than queue length, and that is the
shape the guarantee takes now. A broker handed the same scan twice would be
caught here, where a length check would only ever have proved that something was
enqueued.

### Lifecycle transitions

Table-driven over the full state machine: each state, each legal transition,
each **illegal** transition (which must be rejected, not silently accepted).
Plus: a fresh verdict returns `cached: true` and creates no new scan; an expired
verdict re-scans; a failed scan retries up to `max_attempts` then terminates.

### Concurrency

- Any package starting goroutines uses `goleak.VerifyTestMain(m)`.
- Time-dependent logic runs inside `testing/synctest` (Go 1.25+) rather than
  `time.Sleep` — fake clock, instant, deterministic. Backoff and polling
  intervals are the obvious candidates.
- `t.Context()` instead of `context.Background()`.

## 6. Layer 4 — MongoDB integration

Behind `//go:build integration`. Runs against a real MongoDB in Compose,
applying the indexes from `data-model.md`. It reads `MONGODB_URI` (default
`mongodb://mongodb:27017`, the Compose service name) and `MONGODB_DATABASE`.

| Test | Asserts |
|---|---|
| Unique fingerprint index | A duplicate insert fails with a duplicate-key error |
| Concurrent identical submissions | N goroutines, one scan document and one `scan_id` |
| TTL index | An expired document is deleted by the TTL monitor |
| **Claim atomicity** | Twelve concurrent claims of one scan return exactly one job |
| Lease exclusivity | A scan under a live lease matches nothing; the same scan is claimable once the lease lapses |
| Deferred retry | A scan scheduled for later is not claimable until `available_at` |
| Legacy documents | A scan written before these fields existed is still claimable |
| Terminal statuses | Completed, failed, timed-out and expired scans are never claimable |
| Ruleset version atomicity | Concurrent `$inc` never produces two snapshots at one version |

The "no raw URL" invariant is asserted directly:

```go
cursor, err := coll.Find(ctx, bson.D{})
// marshal every document and assert none contains a "raw_url" field
// and none contains the submitted URL string
```

Testing indexes against a mock proves nothing. The unique constraint *is* the
correctness guarantee, so it needs a real database.

### Claim atomicity is a property of the server

This is the reason the lease tests live here and not in `internal/mongoqueue`:
**a claim is atomic because `findAndModify` is atomic**, not because of anything
the client does. A double would model its author's belief about MongoDB, and
would keep passing if that belief were wrong — which is exactly the failure a
test exists to catch. `claim_integration_test.go` therefore races real
claimants against a real server and asserts one winner.

The same argument applies to the lease, which is the recovery mechanism. A
lapsed lease has to become claimable *by the next consumer*, on the server's
clock, with nothing running to sweep it — a fake could only ever assert that the
fake's own clock advanced, which is a tautology.

### What the two claim suites cover, and why there are two

| Suite | Layer | Only it can catch |
|---|---|---|
| `mongostore/claim_integration_test.go` | 4, real MongoDB | That the lease semantics hold as *database* behaviour: exclusivity, expiry, deferral, legacy documents |
| `mongoqueue/mongoqueue_test.go` | 3, fake store | That the adapter speaks the lifecycle's vocabulary correctly: idle is not failure, a store error propagates, cancellation stops the poll loop, `Release` and `EnqueueRetry` reach the right store calls |

`mongoqueue` deliberately keeps `Enqueue` and `PromoteDue` — as a validated no-op
and an inert zero — with tests asserting exactly that. They are the seam a future
broker would return through, and a suite that stopped covering them would let
their removal go unnoticed.

The adapter's own tests carry no build tag, so they run on every `go test ./...`.
That is the right shape — they need nothing but a fake store — but it is also why
they are worthless on their own: they assume the lease is exclusive, and only
`claim_integration_test.go` against a real server proves that it is.

## 7. Layer 5 — Provider adapter

`httptest.Server` returning recorded fixtures. Never the live API.

| Test | Asserts |
|---|---|
| Submission success | Correct provider scan ID extracted; correct auth headers sent |
| Auth failure | Maps to `provider_auth_failed`; **not** retried |
| Rate limited | Maps to `provider_rate_limited`; `Retry-After` honoured |
| Transient `5xx` | Retried, then given up |
| Malformed JSON | `provider_bad_response`; no panic, no partial parse |
| Oversized response | Rejected at the length bound |
| Unrecognised state | Maps to `unknown` — **never** `no_threat_detected` |
| Timeout | `provider_timeout`; no retry when the submission outcome is ambiguous |
| **Secret leakage** | No error string, log line or returned struct contains the API key |

That last test is the same shape as the existing log-leakage test and is
mandatory before the adapter merges.

## 8. Layer 6 — Verdict normalization

Table-driven, exhaustive, and the single most important table in the codebase:

| Provider condition | Expected verdict |
|---|---|
| Explicit malicious | `malicious` |
| Explicit suspicious | `suspicious` |
| Explicit clean | `no_threat_detected` |
| Non-conclusive report | `inconclusive` |
| Unrecognised value | `unknown` |
| Timeout | `unknown` |
| Auth failure | `unknown` |
| Malformed report | `unknown` |
| Empty report | `unknown` |

Add a meta-test that walks every error path in the adapter and asserts none
yields `no_threat_detected`:

```go
// Every non-success path must resolve to inconclusive or unknown.
for name, err := range allProviderFailures {
    v := verdicts.Normalise(nil, err)
    if v == verdict.NoThreatDetected {
        t.Errorf("%s normalised to no_threat_detected; a failure is never a clean scan", name)
    }
}
```

This is the single most important test in the system, per
[ADR 0011](decisions/0011-verdict-semantics-no-threat-detected.md).

## 9. Layer 7 — Security

| Test | Requirement |
|---|---|
| `TestRawURLNeverReachesLogs` | No raw URL, token or hostname in logs (**implemented**) |
| No URL in metrics | Label set contains no request-derived values |
| No URL in error responses | Client-visible bodies carry codes, not internal text |
| No API key in logs/errors | Asserted across every adapter failure path |
| Scheme rejection | Only `http`/`https` reach the provider |
| Panic does not leak | Stack traces and panic values stay in logs |
| Rate limiting | `429` + `Retry-After` beyond the cap |
| Oversized body | `400` beyond 8 KiB, no OOM |

## 10. Layer 8 — Rulesets

| Test | Asserts |
|---|---|
| Verdict → rule policy | Only policy-eligible verdicts produce rules |
| Version stability | An unchanged effective rule set does **not** increment the version |
| Version monotonicity | Versions never decrease or repeat |
| Snapshot validity | Every rule validates against the DNR schema |
| All-or-nothing | One invalid rule fails the whole build; no partial snapshot |
| Scope narrowness | A URL verdict never emits a domain-level rule |
| Expiry removal | An expired verdict removes its rule, as a new version |

## 11. End-to-end

Behind `//go:build e2e`. Full Compose stack (`backend` + `mongodb`), fake
provider:

1. `POST /check-url` → `202`.
2. The in-process scan runner claims it, submits to the fake, completes.
3. `GET /get-url/{id}` → `200` with a verdict.
4. Second `POST /check-url` → `200 cached: true`, and **no new scan**.
5. Ruleset version incremented, and `GET /get-all` returns the rule.
6. Raw URL absent from every service's logs.

Step 2 is the one worth reading twice. It is the same asynchronous property the
architecture depends on: the request in step 1 returned `202` before any analysis
began, and the analysis ran on the API's own goroutines. A detonation that takes
minutes cannot hold an HTTP connection open, because no HTTP request is waiting
on it.

## 12. Acceptance criteria for the MVP

The MVP is done when:

- [ ] Invalid schemes are rejected; no non-HTTP(S) URL reaches the provider.
- [ ] A fresh cached assessment is returned without a duplicate submission.
- [ ] N concurrent identical requests produce **exactly one** provider
      submission and one shared `scan_id`.
- [ ] Provider responses map into the CyberGuard verdict model, and no failure
      path yields `no_threat_detected`.
- [ ] The extension can retrieve status and a completed result.
- [ ] Rulesets download only when the version changes.
- [ ] Secrets never appear in logs, responses or images.
- [ ] MongoDB's port is not published, and no second datastore exists to expose.
- [ ] Unit, handler, application, integration, adapter and security tests all
      pass under `-race`.

## 13. Gaps in the current suite

| Gap | Note |
|---|---|
| No `logging` tests | Low value, but the redaction contract deserves one |
| No fuzz target for `Validate` | The system's outer boundary, still untested against garbage |
| No coverage gate in CI | Not yet established |

## What the Phase 4 tests actually cover

The highest-value test in the system — concurrent deduplication — now exists, in
four places, because each catches a different failure:

| Test | What only it can catch |
|---|---|
| `TestConcurrentSubmissionsProduceOneScan` (unit, `memstore`) | 25 goroutines, one scan. Fast enough to run on every change |
| `TestLiveConcurrentSubmissionsCreateOneScan` (integration) | That MongoDB's **partial unique index** is what deduplicates, not an application lock |
| `TestClaimIsExclusive` (integration) | That a claim is exclusive **on the server**, which is the only place that guarantee comes from |
| `TestConcurrentRequestsNeverExceedTheLimit` (unit, `ratelimit`) | That the in-process counter's read-modify-write cannot race past its own limit |

`internal/memstore` is an in-memory implementation of the persistence and queue
interfaces, not a mock. It reproduces deduplication, AES-256-GCM with the scan
ID as additional authenticated data, and read-and-delete semantics, because the
behaviour under test is *ordering* — a call-recording stub passes just as
happily when the calls happen in the wrong order. It also injects failures
(MongoDB reads, writes, enqueue, verdict write), which is the only way to
reproduce the case the reconciler exists for: a scan that is durable but whose
delivery was lost. With the broker gone that case is no longer reachable in
production — a claim either lands or the lease expires — but the double still has
to be able to produce it, or the reconciler's tests stop testing anything.

### What the rate limiter lost, and what it did not

`ratelimit_integration_test.go` and the `redisqueue` package's tests are
**deleted**. They existed to prove that two properties were true of Redis rather
than of our code: that `INCR` + `EXPIRE` could not race past a limit, and that a
list-and-sorted-set queue would not drop or duplicate a job.

Neither is a live question any more. The counter is a mutex in this process, so
the exclusivity argument is local and provable by unit test; the queue is the
`scans` collection, so delivery is a database property tested against a database.
Deleting those suites removed coverage of a *dependency*, not coverage of a
guarantee — and it is worth knowing precisely which guarantees moved to which
layer before anyone reads the shrink as a loss.

### Three real bugs the Redis integration tests found

Recorded because the failure modes are general, and because the last three lines
of the file were deleted rather than remembered:

- `BRPOP` pops from the tail, so the queue was LIFO. `RPUSH` + `BLPOP` is FIFO.
- A sub-second block rounded to `"0"`, which Redis reads as *block forever*.
- go-redis applies a context *deadline* to a socket read but not plain
  cancellation, so a blocked worker ignored `SIGTERM` until its block elapsed.

None of them existed in CyberGuard's logic; all three were in how a broker's
primitives behave under conditions a unit test would have modelled from
assumption. The same lesson now applies to the MongoDB query language, where
`{"available_at": {"$lte": now}}` does not match a *missing* field — a mistake
this time made visible only because `TestScansWithoutLeaseFieldsAreStillClaimable`
asks the server rather than the test author's memory.

There is no CI pipeline yet. The gate should be `go vet`, `go test -race
-coverpkg=./...`, `staticcheck`, and `govulncheck`, with a coverage floor that
only ratchets upward.