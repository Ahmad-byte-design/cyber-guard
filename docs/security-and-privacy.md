# CyberGuard AI — Security and Privacy

> **Status:** Proposed. Some requirements are already enforced by code; the
> rest are design constraints on phases not yet built. Each section states
> which.

## 1. Threat model

### What we are defending against

| Adversary | Capability | Mitigation |
|---|---|---|
| Malicious site operator | Controls a URL submitted for analysis | URL is never fetched by us; provider sandboxes it; verdicts are per-URL not per-domain |
| API abuser | Calls `check-url` to burn provider quota | Per-fingerprint caps, global quota accounting, rate limiting (§7) |
| Extension packager | Has the extension binary | Cannot obtain the provider API key — it is never shipped to the client |
| Network observer | Sees traffic to our backend | TLS in production; scan IDs instead of URLs in paths, so access logs hold no URLs |
| Malicious provider response | Returns crafted or oversized payloads | Treated as untrusted input: schema-validated, length-bounded, never executed (§8) |

### What is explicitly out of scope

- **The backend does not fetch submitted URLs.** We submit them to a sandbox.
  This removes the classic SSRF surface, but see §2 — validation still matters.
- Physical access to the host, compromised build pipeline, and malicious
  insiders with database access are not modelled.

## 2. SSRF and URL handling

### Why it still matters without fetching

We never issue an HTTP request to a submitted URL. But we do parse it, derive
its hostname, aggregate signals about it, and pass it to a third party. That
still admits:

- **Parser confusion.** `http://expected.com\@evil.test/` is parsed
  differently by different libraries. Go's `net/url` and a browser's URL parser
  must be understood to agree, or the same string means two different hosts.
- **Host confusion.** `http://evil.test#@good.test/` and unicode/punycode
  homographs (`аpple.com` with a Cyrillic `а`) can make a user read one host
  and the sandbox visit another.
- **Embedded credentials.** `https://user:pass@host/` leaks a secret into
  logs and provider payloads.

### Enforced in code

`internal/urlintel` rejects, with tests:

- Any scheme other than `http` / `https` — kills `file:`, `gopher:`, `data:`,
  `javascript:`, `dict:`.
- Embedded credentials (`u.User != nil`).
- Missing or separator-only hostname.
- Non-numeric port.
- Control characters, which enable request-splitting and log forging.
- Input over 2048 characters.

### Required before the provider adapter is written

- **Pin the parser.** Use `net/url` and document its behaviour. Do not
  hand-roll URL parsing to "fix" a discrepancy — that introduces new ones.
- **Log the canonical form's hash, never the URL**, when a mismatch between
  "what we validated" and "what the provider saw" must be debugged. Comparing
  fingerprints is enough.
- **Do not resolve DNS.** Resolution introduces TOCTOU and rebinding risks for
  no benefit, since we are not connecting.

## 3. Sensitive query parameters

URLs frequently carry session tokens, one-time codes, reset links and personal
data in the query string. We never store the raw URL, but:

- The **canonical form exists in memory** and is the input to the HMAC. If a
  debug log ever prints the canonical form, tokens leak. It must not.
- The **fingerprint covers the query string**. This is a deliberate
  accuracy-over-anonymity trade: dropping query parameters would merge
  `?reset=abc` with `?reset=xyz`, and those are genuinely different resources.
  The cost is that two URLs differing only in token look identical in the
  cache.
- If a future requirement demands token-insensitive matching, implement a
  *targeted* strip list (`utm_*`, `fbclid`, documented session parameters),
  tested against a fixture corpus. **Never strip all query parameters by
  default.**

## 4. Log and telemetry hygiene

### The rule

> No raw URL, query string, API key, provider secret, or user identifier
> appears in any log line, metric label, span attribute, or error message.

### Enforced in code

`TestRawURLNeverReachesLogs` in `internal/httpapi/server_test.go` submits a URL
containing `?token=…`, captures the full log buffer, and asserts that the URL,
the token value, and the hostname are all absent. It also asserts the error
message returned to the client carries no internal detail.

The access-log middleware logs `r.URL.Path` only — never `RawQuery`, never
`RequestURI`. `/api/v1/get-url/scan_01XYZ` is safe; a design that put the URL
in the query string would leak through this line of code.

### Required

- Metrics must not label on fingerprints, scan IDs, URLs, or user IDs.
  Cardinality would explode *and* the value would leak into the metrics
  backend. Label on route template, method, status, and outcome only.
- Add a CI lint rule banning `%v`/`%s` of a `*url.URL` into slog calls.
- Provider error bodies must never be logged verbatim; map to a stable code
  first.

### What we do log

Stable, low-cardinality strings plus opaque internal IDs:

```json
{"level":"WARN","msg":"rejected submission","reason":"url: scheme must be http or https","request_id":"4083…"}
```

## 5. API key handling

`HYBRID_ANALYSIS_API_KEY` is the most damaging secret in the system: leaking
it costs money, burns quota, and may violate the provider's terms.

| Rule | Detail |
|---|---|
| Never in the extension | Not in JS, not in `chrome.storage`, not in a build variable |
| Never in source control | `.env` is gitignored; `.env.example` holds empty placeholders |
| Never in an image layer | Build args are `VERSION`/`COMMIT`/`BUILD_TIME` only. A `ARG`/`ENV` holding a secret is recoverable from the image history even if later unset |
| Never in logs | Redacted in error mapping; assert in tests |
| Never in a response | Error bodies carry a code, never upstream text |
| Mounted at runtime | Compose `env_file`, not baked in |

The API key arrives over TLS, lives in process memory, and is never written to
disk. It is read from the environment, so it appears in `/proc/<pid>/environ`
to the same user — acceptable for a single-tenant host, worth a secrets manager
for anything shared.

## 6. Ruleset policy

### Analysis findings are not policy

Two separate decisions, in two separate packages:

1. `verdicts` — *what did the provider say?*
2. `rulesets` — *does this warrant a browser rule?*

Conflating them is the single highest-consequence design mistake available
here. It turns a provider's opinion into an automatic, persistent, user-facing
block with no human in the loop.

### A verdict does **not** automatically become a rule

| Verdict | Rule eligible? | Reasoning |
|---|---|---|
| `malicious` | **No**, not automatically | Provider false positives block real sites. Requires corroboration — e.g. ≥2 independent fingerprints on the host, or a confidence floor |
| `suspicious` | No | A warning surface, not a block |
| `no_threat_detected` | No | Nothing to do. It is also **not** evidence of harmlessness at any scope |
| `inconclusive` | **Never** | Unknown is not safe, and unknown is not dangerous |
| `unknown` | **Never** | Same |

### Scope: narrowest defensible rule

A `malicious` verdict on `evil.test/login` licenses a rule for **that URL**. It
does not license a rule for `evil.test/*`, and certainly not for `evil.test`.
Domain-level rules affect every user of that host, including its legitimate
paths.

The extension must therefore support, and the backend must emit, a rule scope
of: exact URL → URL prefix → registrable domain, each requiring stronger
evidence than the last.

### Rule validity

Every generated rule is validated against Chrome's `declarativeNetRequest`
schema before publication. An invalid rule **fails the entire snapshot build**
— never publish a partial ruleset, because a partial set silently under-blocks
and leaves the extension in an unknown state.

Rules are versioned and immutable. A rule is removed only when its underlying
verdict expires or is revoked; removal is itself a version bump.

## 7. Abuse and quota exhaustion

The provider's submission quota is the scarce resource. The abuse case is not
"someone reads verdicts" — it is "someone spends your quota".

Defences, in order of effectiveness:

1. **Cache-first.** A fresh verdict never triggers a submission. The cache hit
   rate is the primary cost control.
2. **Per-fingerprint submission cap.** Ten submissions per fingerprint per hour,
   regardless of client. One attacker cannot multiply a single URL.
3. **Per-client rate limit.** 60 requests/minute, plus quotas.
4. **Global daily ceiling.** A hard stop that fails closed with `503` rather
   than exceeding the provider contract.
5. **Duplicate-job suppression.** The unique index on `url_fingerprint` means
   concurrent identical requests produce one submission, not N.

A retry storm is the realistic failure mode: the provider times out, the worker
retries aggressively, and the retry loop consumes the quota it was meant to
protect. Retries are bounded, jittered, and stop at `max_attempts`.

## 8. Untrusted provider output

Everything the provider returns is untrusted: it is a third party that may be
compromised, may be buggy, and may be adversarially influenced by a submitted
URL.

| Defence | Detail |
|---|---|
| Schema validation | Decode into typed structs with `DisallowUnknownFields`-equivalent strictness; reject on mismatch |
| Length bounds | Cap every string and array. A provider returning a 10 MB "summary" must not reach MongoDB or the extension |
| Verdict mapping | Map only recognised values; anything else becomes `unknown`, never `no_threat_detected` |
| No execution | Provider output is data. Never a URL to fetch, a path to write, or a template to render |
| No HTML | Evidence summaries are plain text; the extension renders them as text, never as HTML |
| Timeouts everywhere | Every provider call has a deadline. A hanging provider call must not hold a worker lease forever |

### The hard rule

> A failed, timed-out, malformed, or unrecognised provider response produces
> `inconclusive` or `unknown`. It must **never** produce
> `no_threat_detected`. See
> [ADR 0011](decisions/0011-verdict-semantics-no-threat-detected.md).

A scan that did not complete is not a clean scan. The extension's UI copy for
these states must say "could not determine", not "safe" — an extension that
displays a reassuring message after a failure trains users to ignore warnings.

## 9. Stale verdicts

| Risk | Mitigation |
|---|---|
| A site becomes malicious after assessment | `expires_at` TTL per verdict category; re-analysis on expiry |
| A site is falsely blocked, then rehabilitated | Expiry forces re-evaluation; rule removal is a version bump |
| Extension holds a stale ruleset forever | `get-all?version=N` and `ETag` make refresh cheap; extension polls on a schedule |
| TTL deletion is approximate | Never assert deletion timing; assert freshness |

Separate TTLs per verdict category are intentional: a `malicious` verdict and a
`no_threat_detected` verdict have different re-validation costs and different
risk if stale.

## 10. Browser enforcement limits

These are **product limitations**, not bugs, and must be stated in the README
and the extension UI. Claiming otherwise is a security failure.

### What a Manifest V3 extension cannot do

- **Pause every navigation and wait for a server response.** Chrome MV3 removed
  the blocking `webRequest` model. A `declarativeNetRequest` rule is evaluated
  locally, from state the extension already holds.
- **Block a navigation the user has already started.** At best, the extension
  intercepts and redirects after the fact.
- **Guarantee coverage for the first visit to an unknown URL.** The URL is
  unknown precisely because it has never been checked, and the check takes
  seconds.
- **Enforce synchronously across the whole fleet.** Organisational-wide
  enforcement needs a managed proxy or secure web gateway, not an extension.

### Honest model

The extension is a **detection and notification layer**, not an enforcement
boundary. It blocks what it already knows about and surfaces "checking…" for
what it does not. For strict enforcement, the deployment target is a network
gateway — and the backend's ruleset feed is designed to serve one as well as a
browser, which is a reason to keep the ruleset format clean and versioned.

### Extension permissions

The extension should request the narrowest set that works:

- `declarativeNetRequest` for rule application.
- `storage` for the local cache and ruleset version.
- Host permissions scoped to matched patterns, not `<all_urls>`, where the
  ruleset format allows it.

Every extra permission is visible to the user and is a trust cost.

## 11. Queue and concurrency safety

| Risk | Mitigation |
|---|---|
| Duplicate provider submissions | Unique index on `url_fingerprint`; unique index on `scan_id` |
| Two workers processing one job | `findOneAndUpdate` claim is atomic |
| A crashed worker stranding a job | `lease_expires_at`; the lease lapses and another worker reclaims |
| Unbounded retry | `max_attempts`, then terminal `failed` |
| Retry amplification | Exponential backoff with jitter |
| Job queue poisoned with garbage | Strict decode + `max_attempts = 0` for unparseable jobs |

## 12. Privacy summary

| Data | Handling |
|---|---|
| Raw URL | Processed in memory; never persisted, never logged, never returned |
| HMAC fingerprint | Stored; pseudonymous identifier, not anonymised |
| Hostname / domain | Stored for host-level lookups |
| Provider key | Backend only; never leaves the server |
| Provider scan ID | Stored until expiry, to resume polling |
| Raw provider report | Not stored |
| User identity | Not collected. There are no accounts in the MVP |

There is no user account system, so there is nothing to identify — which means
any future account system must revisit this entire section.

### Operational obligations

- Rotate the HMAC key only with a planned full re-scan.
- Treat the fingerprint key as a production secret with the same handling as
  the provider key.
- Log retention must exclude raw URLs; a log archive containing URLs
  reintroduces exactly the exposure the design removes.
- Development data volumes are not encrypted and are not a backup.