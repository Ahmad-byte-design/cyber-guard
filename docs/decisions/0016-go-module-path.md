# 0016 — Go module path derived from the Git repository

- **Status:** Accepted, **not satisfied — BLOCKED**
- **Date:** 2026-10-16
- **Affects:** `go.mod`, every import statement, CI, documentation

> ## Deviation D1 — open, blocked on an external input
>
> The rule is accepted but **cannot be applied**. The evidence, re-verified for
> this change:
>
> ```
> $ git remote -v
> (no output)
> $ git config --get-regexp '^remote\.'
> (no remote.* config keys)
> $ git log --oneline -3
> fatal: your current branch 'main' does not have any commits yet
> ```
>
> There is **no remote and no commit**. The module path therefore cannot be
> derived, and guessing a GitHub organisation would be fabrication: a wrong path
> is discoverable by anyone who tries `go get`, and every import would have to
> be rewritten again later.
>
> Current state: `go.mod` declares `module cyberguard/server`.
>
> **To close this:** create the remote, then derive the path from it:
>
> | Remote | Module path |
> |---|---|
> | `git@github.com:acme/cyberguard.git` | `github.com/acme/cyberguard` |
> | `https://gitlab.com/acme/cyberguard.git` | `gitlab.com/acme/cyberguard` |
> | `https://git.acme.tld/platform/cyberguard.git` | `git.acme.tld/platform/cyberguard` |
>
> Strip the scheme, `.git` suffix, trailing slash and any username. Verify with
> `git remote get-url origin` before editing, then `head -1 server/go.mod` after.
>
> ### Blast radius has already grown
>
> This decision was originally taken with a zero-dependency module. It now has
> three external dependencies, so a path change also means:
>
> - `server/go.mod`, plus every import in `cmd/`, `internal/`.
> - `server/Dockerfile`: `COPY go.mod ./` must become `COPY go.mod go.sum ./`,
>   so a checksum mismatch fails the build loudly instead of silently
>   re-resolving versions. **This has not been done**, because `go.sum` cannot
>   be verified against a path that does not exist yet.
> - Every documentation reference and the `openapi.yaml` drift test's path
>   assumptions.
>
> ### Why this did not block the PSL work
>
> This ADR originally gated the Public Suffix List swap behind the module path,
> on the reasoning that adding a dependency makes a later rename more expensive.
> That coupling was unnecessary and has been dissolved:
>
> - Renaming a module does not invalidate `go.sum`; it rewrites import
>   statements, and those are mechanical to regenerate.
> - The PSL swap is a *correctness* requirement, not a convenience. The
>   hand-rolled registrable-domain function it replaced was returning public
>   suffixes as domains and mangling IP addresses.
>
> [ADR 0012](0012-public-suffix-list-dependency.md) is therefore implemented,
> and deviation [D2](#deviation-d2-resolved) below is closed. Blocking a
> security fix on an unrelated infrastructure detail was the wrong trade.

## Context

`server/go.mod` currently declares:

```go
module cyberguard/server
```

This is not a fetchable repository path. Go tooling assumes the module path is
where the code can be fetched from. A non-URL path means:

- `go get` on this module cannot work for a consumer.
- Import paths are ambiguous: `cyberguard/server/internal/urlnorm` does not
  say which host serves it.
- Publishing to a module proxy would register a path nobody can fetch.
- Internal import paths in generated documentation would be misleading.

The correct value is determined entirely by where the repository actually
lives, which is a fact about the deployment, not a design choice.

## Decision

**The module path is derived from the actual Git remote URL** and is set before
the first external dependency is consumed and before any release.

Derivation:

| Remote | Module path |
|---|---|
| `git@github.com:acme/cyberguard.git` | `github.com/acme/cyberguard` |
| `https://gitlab.com/acme/cyberguard.git` | `gitlab.com/acme/cyberguard` |
| `https://github.com/acme/cyberguard` | `github.com/acme/cyberguard` |
| Self-hosted Gitea, `https://git.acme.tld/acme/cyberguard.git` | `git.acme.tld/acme/cyberguard` |

Rules:

1. Strip the scheme, `.git` suffix, and any trailing slash.
2. Strip any username (`git@`).
3. Preserve case as the remote uses it; Go paths are case-sensitive, though
   the GitHub remote is an exception in practice. Use the canonical form the
   host displays.
4. The module root is the **repository root**, not `server/`. The Go module
   lives at the repository root in the target layout, or `server/go.mod`
   carries the `/server` suffix if the module stays nested.
5. If the repository is renamed or moved, the module path changes. Any
   change after publication requires a `retract`/re-publish decision and
   ideally a `replace`-free major version bump.

## Consequences

**Positive**

- `go get` works for consumers.
- Import paths identify their origin unambiguously.
- Documentation renders with correct, clickable import paths.
- pkg.go.dev-style tooling works.

**Negative**

- The path depends on the hosting decision, so it cannot be fixed until
  hosting is chosen. It must not be guessed.
- Moving the module in the tree changes every import statement. Cheap with
  `gofmt`/`goimports` and one `sed`, but it is a mechanical diff.
- A private repository produces a path that looks public but is not; a
  `GOPRIVATE`/`GONOSUMDB` setting is needed to avoid proxy lookups.

## Deviation D2 — resolved

`internal/urlnorm` was to be renamed to `internal/urlintel` alongside the
Public Suffix List swap, which was itself gated behind D1.

**Done.** `internal/urlintel` now contains:

| File | Contents |
|---|---|
| `urlintel.go` | Validation, canonicalisation, HMAC fingerprinting (unchanged from `urlnorm`) |
| `host.go` | `NormalizeHostname`, `RegistrableDomain`, `ParseHost`, `HostInfo` |

The hand-rolled `RegistrableDomain` was deleted rather than supplemented.
`httpapi` imports `urlintel` instead of `urlnorm`.

## Preconditions

The repository is **not currently a Git repository**. There is no remote to
derive from. This ADR therefore records a *rule*, and the value must be filled
in when `git init` and the remote are established.

Consequences of the ordering:

- `git init` and pushing to a host should happen **before** Phase 3 adds the
  first external dependency, because `go.mod` and `go.sum` must be correct in
  the first commit that anyone can fetch.
- Do not publish to a module proxy. This is an application, not a library;
  publishing is unnecessary and would commit the path permanently.

## Verification

Before the first commit that others will fetch:

```sh
git remote get-url origin          # the source of truth
head -1 server/go.mod              # must match the derivation rule
docker compose run --rm go go list -m
```

And after the module is at the repository root:

```sh
docker compose run --rm go go build ./...
docker compose run --rm go go vet ./...
```

A module path change is complete only when the whole tree still builds and
tests pass.