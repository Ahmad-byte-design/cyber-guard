# 0004 — Scan and verdict vocabulary

- **Status:** **Superseded** by
  [ADR 0011](0011-verdict-semantics-no-threat-detected.md)
- **Date:** 2026-10-16
- **Affects:** `docs/api-contract.md`, `docs/architecture.md`, extension client

> **Superseded.** The scan **states** proposed here are carried forward
> unchanged into [ADR 0011](0011-verdict-semantics-no-threat-detected.md). The
> **verdict** names are not: `benign` is replaced by `no_threat_detected`,
> because `benign` reads as a safety guarantee and no sandbox result is one.
>
> This record was never accepted, and superseding it rather than amending it
> avoids leaving two sources of truth for the verdict vocabulary.

## Context

Two prior documents define conflicting vocabularies.

`CYBERGUARD_PROJECT.md` §5.4 gives verdicts `malicious`, `suspicious`,
`no_threat_detected`, `unknown`, and §5.2 gives states `queued`, `submitting`,
`submitted`, `running`, `completed`, `failed`, `timed_out`.

The review prompt §5 gives verdicts `malicious`, `suspicious`, `benign`,
`inconclusive`, `unknown`, and states `queued`, `running`, `completed`,
`failed`, `expired`.

The extension is a separately shipped client that will hard-code these strings.
Changing them later means a coordinated release and a migration for users who
have not updated — the worst time to discover a client still expects
`no_threat_detected`.

## Decision

**Verdicts** (5, from the review prompt):

`malicious` · `suspicious` · `benign` · `inconclusive` · `unknown`

**Scan states** (5): `queued` · `running` · `completed` · `failed` ·
`expired`, plus `timed_out` as a failure subtype surfaced in `error_code`.

Provider-specific phases (`submitting`, `submitted`) are recorded as provider
metadata, not as client-visible states.

## Rationale

States: seven states is more than the observable behaviour justifies. A client
must render exactly one thing for "we are working on it", and distinguishing
"we sent it" from "they started it" helps nobody. `timed_out` is retained as
an `error_code` because its remediation differs from a rejection.

Verdicts: `inconclusive` and `unknown` are kept distinct because they mean
different things — "the analysis ran and found nothing conclusive" versus "we
could not determine". Collapsing them loses the user's ability to distinguish
"probably fine, worth checking" from "we know nothing".

`benign` is the weakest term in the set. It reads as a guarantee, and it is not
one: a clean analysis means no indicators were found. See open question 2 in
the implementation plan.

## Consequences

**Positive**

- Five states means fewer client branches and less client-side state.
- `inconclusive` and `unknown` stay distinguishable.
- Five verdicts map cleanly onto the provider mapping table.

**Negative**

- Clients written against `no_threat_detected` break. Mitigated by shipping an
  alias field during a transition if such clients exist; none ship today, so
  the window is free.
- `benign` invites the "safe" misreading. Mitigated by making it a documented
  contract term and forcing the extension's UI copy to say "no threats
  detected".

## Invariant

> Scan status and verdict are independent. A verdict exists **only** when
> status is `completed`.

A `running` scan has no verdict. A `failed` or `timed_out` scan has no verdict.
This must be enforced by a type-level or schema-level constraint, not by
convention.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep both vocabularies | Two names for overlapping meanings guarantees client confusion |
| Free-text verdict from the provider | Destroys the normalisation boundary and makes rule generation unsafe |
| Single "safe/unsafe" boolean | Discards the distinction the product exists to make, and invites the false-negative failure the design exists to prevent |