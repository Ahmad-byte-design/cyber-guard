# 0011 — Verdict semantics: `no_threat_detected`

- **Status:** Accepted
- **Date:** 2026-10-16
- **Supersedes:** [ADR 0004](0004-scan-and-verdict-vocabulary.md)
- **Affects:** `api-contract.md`, `architecture.md`, `security-and-privacy.md`,
  `testing-strategy.md`, extension client

## Context

[ADR 0004](0004-scan-and-verdict-vocabulary.md) proposed the verdict set
`malicious`, `suspicious`, `benign`, `inconclusive`, `unknown`.

On review, `benign` is the weak link. It reads as a **safety guarantee**: "this
URL is benign" is easily read by an extension author, a reviewer, or a user as
"this URL is safe". It is not a guarantee. A clean analysis means the sandbox
observed no indicators sufficient to classify the sample — not that the URL is
harmless.

The failure mode is concrete and serious: an extension that renders `benign` as
a green "Safe" badge trains users to dismiss warnings, and the one time the
badge is wrong is the time it matters. Product principle 5 in the original
brief already required that these outcomes be "distinct outcomes" and that
"a scan that found no indicators is not a guarantee that the URL is safe". The
identifier itself should carry that meaning.

`CYBERGUARD_PROJECT.md` §5.4 already used `no_threat_detected` for exactly this
reason. The prompt's `benign` was the weaker term.

## Decision

The canonical verdict set is five values:

| Verdict | Meaning |
|---|---|
| `malicious` | Provider positively identified malicious behaviour |
| `suspicious` | Indicators present but below the malicious threshold |
| `no_threat_detected` | Analysis completed; **no indicators sufficient to classify it were found**. Not a safety guarantee |
| `inconclusive` | Analysis completed but the result does not support any classification |
| `unknown` | Could not determine — analysis failed, timed out, was refused, or returned something unrecognised |

`benign` is removed from the vocabulary and must not appear in any API
response, log, metric label, ruleset or extension message.

### Scan states

Carried forward unchanged from ADR 0004, which is superseded only for the
verdict names:

`queued` · `running` · `completed` · `failed` · `expired`, with `timed_out`
surfaced through `error_code` on a `failed` scan. Provider phases
(`submitting`, `submitted`) are provider metadata, not client-visible states.

## Invariants

These are properties of the system, not documentation preferences.

1. **No failure path yields `no_threat_detected`.** Timeout, `401`, `429`,
   `5xx`, malformed response, unrecognised status, connection refused, empty
   report — all resolve to `inconclusive` or `unknown`. A scan that did not
   complete is not a clean scan.
2. **A verdict exists only when status is `completed`.** A `running` scan has
   no verdict; neither has `failed`, `timed_out` or `expired`.
3. **`inconclusive` and `unknown` stay distinct.** "The analysis ran and found
   nothing conclusive" is a different user-facing situation from "we could not
   determine". Collapsing them loses the user's ability to tell "probably fine,
   worth a look" from "we know nothing".
4. **`no_threat_detected` never authorises a blocking rule.** It is not
   evidence of harmlessness at any scope.

## Presentation requirements

The name is not sufficient on its own; the identifier and the UI copy must both
carry the meaning.

- The extension's UI for `no_threat_detected` must read as "No threats
  detected", never "Safe", "Trusted" or "Secure".
- Documentation for API consumers must state that `no_threat_detected` is an
  absence of indicators, not an assurance.
- Any downstream consumer that needs a boolean "should I warn?" must derive it
  explicitly. The derivation is policy, belongs in the extension, and must not
  be computed server-side as a bare boolean — that would collapse five states
  back into the two this decision exists to prevent.

## Consequences

**Positive**

- The identifier cannot be misread as a guarantee.
- Converges with `CYBERGUARD_PROJECT.md` §5.4, so one fewer vocabulary conflict
  between the source documents and the implementation.
- `inconclusive` vs `unknown` remains a meaningful distinction.

**Negative**

- The name is longer. Trivial, and worth it.
- Any client written against `benign` breaks. No client has shipped, so the
  migration window is free — which is exactly why this is settled now rather
  than after launch.
- Consumers who want a simple boolean must write the policy themselves. That
  is deliberate: the policy is the consumer's decision, not the backend's.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep `benign`, document the caveat | A caveat in a document does not stop an extension author from rendering "Safe". The identifier is the contract |
| `safe` | Strictly worse; asserts the guarantee directly |
| `clean` | Same problem as `benign`, less precise about what was checked |
| `not_malicious` | Reads as a positive assertion that the URL is not malicious, which is stronger than what a sandbox can establish |
| Boolean `is_malicious` | Discards `inconclusive` vs `unknown` entirely, and loses the ability to distinguish "ran, found nothing" from "we know nothing" |

## Enforcement

A meta-test walks every error path in the provider adapter and asserts none
normalises to `no_threat_detected`. This is the single most important test in
the system; see `testing-strategy.md` §8.