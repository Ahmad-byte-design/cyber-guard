# 0018 — Ruleset thresholds, scope escalation, and URL retention

- **Status:** Accepted, **provisional**
- **Date:** 2026-10-17
- **Affects:** `security-and-privacy.md` §6, `data-model.md`, `api-contract.md`,
  `internal/rulesets`, `internal/platform/mongostore`
- **Supersedes nothing.** Extends
  [ADR 0011](0011-verdict-semantics-no-threat-detected.md) and
  [ADR 0013](0013-durable-jobs-and-url-privacy.md)

> ## This ADR records two decisions the architecture left open, and asks for
> both to be ratified before any real user is protected by a generated rule.
>
> `security-and-privacy.md` §6 specifies the *shape* of the ruleset policy
> precisely. It does not specify two numbers, and it contains a tension with
> another decision in the same document. Both are recorded here rather than
> guessed at silently.

## What the documentation already settled

These are not reopened here.

| Question | Answer | Source |
|---|---|---|
| Does any verdict become a rule automatically? | **No** | §6 |
| Is `inconclusive` ever eligible? | **Never.** "Unknown is not safe, and unknown is not dangerous." | §6 |
| Is `unknown` ever eligible? | **Never** | §6 |
| Is `suspicious` eligible? | **No.** "A warning surface, not a block." | §6 |
| Is `no_threat_detected` eligible? | **No**, and it is not evidence of harmlessness at any scope | §6 |
| Is `malicious` eligible on its own? | **No.** Requires corroboration | §6 |
| What is the scope ladder? | exact URL → URL prefix → registrable domain | §6 |
| How does the ladder relate to evidence? | "each requiring stronger evidence than the last" | §6 |
| What happens to an invalid rule? | The **entire** snapshot build fails | §6 |
| How are versions assigned? | Only when the effective rule set changes | §6, `implementation-plan.md` |

## Decision 1 — The corroboration thresholds

### The gap

§6 gives the corroboration rule as an example: "≥2 independent fingerprints on
the host, **or** a confidence floor". That is an illustration of the shape, not
a decision. It also offers two alternatives, only one of which is implementable.

### Why the confidence floor is not implemented

There is no confidence value anywhere in the system. The verified Hybrid
Analysis contract does not define one, and inventing a threshold over a number
the provider never reported would be fabricating provider semantics — the thing
this project refuses to do elsewhere. The alternative is therefore not
implemented, and cannot be until either the provider exposes such a field or
CyberGuard derives one by a method that is itself documented.

### What was implemented, and why

"Independent" means **distinct URL fingerprints**. Counting scans rather than
fingerprints would let a client inflate its own corroboration simply by asking
for the same URL repeatedly.

| Scope | Default threshold | Basis |
|---|---|---|
| `exact_url` | 2 | §6's own stated example |
| `url_prefix` | 3 | +1 for the wider blast radius |
| `registrable_domain` | 5 | +2 more for the widest blast radius |

The increments are **a judgement, not a derivation**. They are deliberately
high: a false-positive block sends a user to a support ticket, and the operator
pays for it, while a missed block costs one user one session. All four numbers
are configurable (`RULESET_MIN_CORROBORATION*`) so they can be revised from
real data without a code change.

**These need ratification.** The right values depend on the provider's observed
false-positive rate, which does not exist yet.

### Why evidence escalates breadth rather than narrowing the rule

An earlier reading of §6 — always take the narrowest scope the evidence permits
— makes the ladder's extra thresholds dead configuration: no amount of evidence
would ever produce a prefix or domain rule.

There is also a concrete reason to escalate. A host with nine distinct malicious
findings will be asked about a tenth URL; a per-URL rule covers the nine already
seen and none of the rest. A broader rule covers what has not been scanned yet,
which is the reason to collect the evidence in the first place.

§6's own framing supports this: a rule for a single URL is what *one* verdict
licenses. It does not claim that fifty do.

**The safety valve is scope, not threshold.** `RULESET_MAX_SCOPE` defaults to
`exact_url`, so a default deployment can never emit anything broader than a
single-URL rule no matter how strong the evidence. Every threshold above the
first is inert until an operator deliberately widens the ceiling.

## Decision 2 — URL retention, which weakens ADR 0013

### The tension

ADR 0013 is unambiguous: a raw URL exists in exactly two transient places and is
never persisted. §6 requires the "narrowest defensible rule" — and a rule for
one exact URL *contains* that URL.

These cannot both hold. Something has to give, and it should be a recorded
decision rather than an accident discovered in production.

### What was implemented

- **`scheme` and `path_prefix` are written onto an assessment only when the
  verdict is `malicious`.** Every other verdict stores neither, so URL detail
  exists only where it could plausibly become a published rule.
- **The query string is never stored, at any point.** It routinely carries
  session tokens and identifiers; persisting those would undo the point of the
  fingerprint entirely. A consequence is that two URLs differing only in query
  share a rule, so an exact-URL rule blocks slightly more than true exactness.
- **The detail on the `scans` record is cleared once the verdict is known.** The
  scan is the long-lived audit trail, so a path fragment is captured at
  submission time — the only moment the plaintext exists in the worker's memory
  — copied onto the assessment, and removed from the scan.
- **Provenance stores the fingerprint, not the URL.** The audit trail for a rule
  is a correlation handle, not a copy of the resource it blocks.

### What this leaves standing

A malicious verdict leaves a permanent record of a scheme and path on its host.
That is strictly more than ADR 0013 promised, and the promise is narrowed
accordingly.

**This needs ratification.** An alternative that preserves ADR 0013 exactly is
to emit only host-scoped rules, at the cost of blocking every path on a host
whenever any one of them is malicious. That is a worse outcome for users and
better for storage, and the trade-off is a product decision, not a technical one.

## Decision 3 — No `ruleset_meta` counter

`data-model.md` lists a `ruleset_meta` collection holding a monotonic version
counter. It is not implemented.

The version is the `rulesets._id`, so publication is an insert and the database
rejects a duplicate. A separate counter would add a second source of truth that
can disagree: a counter that advanced past a failed snapshot leaves a permanent
gap in the sequence, and a client that saw version 12 could never install 13.

Deriving the version from the highest snapshot is simpler and has no gap.
Monotonicity under concurrency is enforced by the duplicate-key error, not by a
read-then-write in Go — verified by an integration test with 16 concurrent
publishers.

## Decision 4 — Exact-URL rules use an anchored regex

Chrome's `urlFilter` has no exact-match operator: `||host^` is a host-anchor and
everything after it is a prefix. An exact-URL rule therefore uses
`regexFilter: "^…$"` with RE2 escaping.

Path and hostname characters that are operators in `urlFilter` syntax are
escaped when the prefix and domain forms are used, so a URL containing `|`
cannot widen a rule to match another host.

## Consequences

**Positive**

- No non-malicious verdict can ever become a block; that is a table, not a
  convention.
- The default configuration is the most conservative one available.
- A rebuild that changes nothing does not move the version.
- One invalid rule fails the whole build; a partial ruleset cannot ship.

**Negative**

- Two thresholds and the escalation rule are unratified judgements.
- ADR 0013's no-URL-retention promise is narrowed for malicious verdicts.
- Corroboration means a single malicious URL is never enough, so protection lags
  by at least two distinct findings on a host. That is the intended cost.

## Open questions for the owner

1. Are the corroboration thresholds (2 / 3 / 5) acceptable, or should the
   default be higher while the provider's false-positive rate is unknown?
2. Should evidence escalate breadth at all, given the default ceiling already
   makes escalation invisible?
3. Is storing `scheme` + `path_prefix` on malicious assessments acceptable in
   exchange for single-URL rules, or should the default become host-scoped to
   preserve ADR 0013 exactly?
4. How many historical ruleset versions should be retained? Snapshots are
   immutable and currently unbounded, because a client may be several versions
   behind.