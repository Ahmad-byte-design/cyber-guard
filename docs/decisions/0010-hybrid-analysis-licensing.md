# 0010 — Hybrid Analysis licensing and automated submissions

- **Status:** Accepted
- **Date:** 2026-10-16
- **Affects:** `hybrid-analysis-integration.md`, `security-and-privacy.md`,
  `implementation-plan.md`
- **Gate:** blocks commercial release and Phase 5

## Context

CyberGuard AI's core function is submitting URLs to Hybrid Analysis for
external sandbox analysis. Two questions govern whether that is permitted:

1. Does the project's intended licence permit automated submission of URLs to a
   third-party analysis service?
2. Does the project's API key tier permit **automated** submission, as opposed
   to interactive use?

Both are legal and commercial questions, not technical ones. Neither can be
answered by inspecting a credential.

### What an API key does and does not establish

A valid API key establishes that *an account with some tier of access exists*.
It does **not** establish:

- that automated submission is included in that tier;
- that the project's licence permits disclosure of user-submitted URLs to a
  third party;
- any rate-limit or quota headroom sufficient for this product's traffic;
- permission to re-publish provider-derived verdicts in a ruleset served to
  end users.

A key that authenticates successfully against one endpoint may still be
prohibited from bulk or automated submission. Treat "the key works" and "we
are allowed to do this" as entirely separate findings.

## Decision

**Written approval for Hybrid Analysis usage is a hard prerequisite for
commercial release.** Until it is obtained:

- The system is developed and tested exclusively against **recorded fixtures
  and a fake provider**.
- No automated test performs a live submission.
- No production deployment submits URLs to the provider.
- The deployment posture is **private / self-hosted**, where the operator is
  the same party operating the backend and can make their own disclosure
  decision.

Commercial release is blocked until all of the following are confirmed in
writing by the provider or by qualified counsel:

1. The project's licence tier permits automated URL submission.
2. The specific key tier permits automated submission, and what quota and rate
  limits apply.
3. Whether re-publishing provider-derived verdicts in a distributed ruleset is
   permitted, and whether attribution is required.
4. Retention terms for submitted URLs, and whether they conflict with
   CyberGuard's privacy posture.
5. Any restrictions on the categories of URL submitted.

## Consequences

**Positive**

- A licence violation is discovered before launch, not after.
- The "does the key work" question stops being mistaken for the "are we
  allowed" question.
- Private/self-hosted deployment is the natural place to develop: the operator
  controls disclosure.

**Negative**

- Phase 5 remains blocked until approval arrives. This is deliberate.
- A commercial launch timeline now depends on a third party's response.
- Self-hosted deployments remain the only sanctioned production posture until
  approval, which limits who can run the product.

## Required engineering controls regardless of outcome

These apply now and are not conditional on approval:

- The API key is a runtime secret. It is never a build argument, never baked
  into an image layer, never committed, never logged, and never returned to a
  client. See `security-and-privacy.md` §5.
- No automated test performs a live submission. Recorded fixtures only.
- The key is environment-specific. Development, staging and production use
  separate keys.

## Operational note

An API key was shared in plaintext conversation during the design of this
system. It must be treated as compromised and **rotated**, with a replacement
issued and stored only in a secret manager or an untracked `.env`. A
credential that has appeared in any transcript, log or chat is no longer
secret, regardless of how briefly it was visible.

Rotation is a documented procedure, not an ad-hoc action: revoke the old key
at the provider, issue a new one, update the secret store, and confirm the
service recovers. Two open slots to note — because the product is unauthenticated
in v1 ([ADR 0013](0014-abuse-protection-without-authentication.md)), a leaked
key is a direct path to spending the operator's quota.

## Open questions

These remain unverified and cannot be closed by any key. See
`hybrid-analysis-integration.md` §9 for the full fifteen-item technical
verification list, and §8 for the licensing items.

| # | Question |
|---|---|
| 1 | Does the project's licence permit automated URL submission? |
| 2 | Does the key tier permit automated submission, and at what rate limits? |
| 3 | May provider-derived verdicts be republished in a ruleset? |
| 4 | What are the retention terms for submitted URLs? |
| 5 | Are there restrictions on URL categories? |