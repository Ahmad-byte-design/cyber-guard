# 0009 — Go as the only backend language

- **Status:** Accepted
- **Date:** 2026-10-16
- **Supersedes:** the backend-language statements in
  `docs/architecture/CYBERGUARD_PROJECT.md` §0, §2, §13, §17 and
  `docs/architecture/CYBERGUARD_ARCHITECTURE_PROMPT.md`
- **Affects:** every document in this set

## Context

The two source documents under `docs/architecture/` specify a Laravel 12
backend with a PHP MongoDB driver, and both state that Go is deliberately out
of scope:

- `CYBERGUARD_PROJECT.md` §17: *"Go | Not included in MVP | Calling an
  external sandbox API is not made faster merely by using Go"*.
- `CYBERGUARD_ARCHITECTURE_PROMPT.md`, "Fixed technology choices": *"Go is not
  part of the initial MVP"*.

`docs/prompt/architecture-review-documentation.md` §2 reverses this and states
that Laravel has been removed entirely. The tension was flagged in
`architecture.md` §7 conflict #1 and is now closed.

## Decision

**Go is the only backend language for CyberGuard AI.** There is no PHP, no
Laravel, and no secondary language in the backend. The only other language in
the project is JavaScript in the browser extension, which is a separate client
artefact and not part of this decision.

## Rationale

The original objection — that calling a remote sandbox API does not get faster
in Go — was correct and is worth restating. Go is **not** adopted for scan
speed. The reasons are:

- **Concurrency shape.** The worker is a polling loop with leases, timeouts and
  bounded cancellation. That is the language's strongest suit.
- **A single static binary.** Two artefacts from one module, no runtime
  dependency, straightforward multi-stage container builds.
- **Explicit error handling at the boundary that matters.** Provider failures
  must be classified precisely and never silently coerced into a clean verdict.
  Checked error returns enforce this at the exact place it can go wrong.
- **Static analysis.** `go vet`, `staticcheck` and `govulncheck` fit a security
  product's supply-chain requirements without extra tooling.
- **Dependency footprint.** The module currently has zero third-party
  dependencies. Keeping it that way for as long as possible materially reduces
  supply-chain surface for a security product.

## Consequences

**Positive**

- One language, one toolchain, one module to reason about.
- The `Laravel MongoDB` reference in `CYBERGUARD_PROJECT.md` §18 is obsolete;
  the official Go driver is used.
- `docs/architecture/CYBERGUARD_PROJECT.md` remains useful as a record of
  original requirements and is retained unmodified for that purpose.

**Negative**

- Diverges from two source documents. Anyone reading only
  `docs/architecture/` will reach the wrong conclusion about the backend.
  Mitigated by this ADR, by `architecture.md` §7, and by a pointer in
  `README.md`.
- Loses the Laravel ecosystem (MongoDB Eloquent, queue integrations). None were
  load-bearing for the actual requirements.

## Status of the source documents

`CYBERGUARD_PROJECT.md` and `CYBERGUARD_ARCHITECTURE_PROMPT.md` are **retained
as historical requirement records**. Their API contract, data model, privacy
requirements and compose topology remain accurate and are used by this set.
Only their statements about the backend language, and §2/§17's exclusion of
Go, are superseded.

They are deliberately not rewritten: silently editing a requirements document
destroys the record of what was originally asked for, and this ADR exists
precisely so the change is visible.