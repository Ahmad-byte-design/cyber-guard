# 0001 — Modular monolith

- **Status:** Proposed
- **Date:** 2026-10-16
- **Deciders:** project maintainers
- **Affects:** `docs/architecture.md`, `docs/module-map.md`

## Context

The system has several components with distinct responsibilities: URL
intelligence, scan lifecycle, provider integration, verdict normalization,
ruleset generation, persistence and HTTP transport. The question is whether to
deploy them as separate services or inside one Go module.

Traffic is expected to be modest — thousands of checks per day, not millions.
There is no team boundary forcing independent deployment, and no scaling
pressure on any single component.

The correctness problem is subtle and semantic: a provider failure must never
become a `no_threat_detected` verdict, a stale verdict must never be presented
as fresh, and two concurrent requests for one URL must produce exactly one
provider submission. These are invariants spread across every component.
Splitting the components across network boundaries adds partial failure,
retries, and eventual consistency to a system whose hardest problem is already
meaning.

## Decision

Build one Go module with two binaries (`api`, `worker`) sharing `internal/`.
Modules are enforced by package boundaries and the compiler, not by the network.

## Consequences

**Positive**

- The dedup guarantee is a single atomic MongoDB operation with no distributed
  lock.
- A verdict can never be `no_threat_detected` because of a transport-level
  mistake: the mapping lives in one package, in one process, covered by one
  table test.
- No inter-service auth, no distributed tracing requirement for correctness,
  no partial-failure states to reason about.
- Refactoring module boundaries is a compile-time change, not a deployment.
- Two deployment artefacts instead of six.

**Negative**

- The API and worker scale independently but ship together.
- One language's ecosystem for everything.
- A memory leak or a runaway goroutine in the worker affects only the worker —
  which is the main isolation we actually want, and it is preserved.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Microservices per module | Adds network failure modes to a correctness-critical system. No scaling or isolation pressure justifies it |
| Single binary, no worker | Provider calls take seconds to minutes. Blocking a request on them would violate the async requirement |
| Serverless functions | Cold starts hurt polling; provider credentials per-invocation; loses the lease-based job model |

## Revisit when

Measured worker throughput cannot keep up, or provider latency varies enough
that the API and worker need independent scaling. Revisit with data, not
anticipation.