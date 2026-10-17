# 0012 — Public Suffix List dependency

- **Status:** Accepted, **implemented**
- **Date:** 2026-10-16
- **Affects:** `module-map.md`, `data-model.md`, `security-and-privacy.md`
- **First external Go dependency** — `golang.org/x/net`

## Context

CyberGuard derives the **registrable domain** from a hostname — `login.bank.co.uk`
yields `bank.co.uk`, not `login.bank.co.uk` and not `co.uk`.

That derivation is a security property, not a convenience. Getting it wrong in
either direction has a direct consequence:

- **Too narrow** (treating `co.uk` as the registrable domain) collapses every
  UK site under one entity, so aggregated host signals mix unrelated
  organisations.
- **Too broad** (treating `co.uk` as registrable but computing
  `login.bank.co.uk` as one unit) merges distinct hosts into one reputation,
  which is how a benign subdomain inherits a phishing verdict.

The correct answer requires the **Public Suffix List** — a maintained,
security-critical dataset covering multi-level suffixes (`co.uk`, `com.au`),
private suffixes (`github.io`, `herokuapp.com`), IDN/punycode forms, and
wildcard and exception rules.

Before this decision, `internal/urlnorm` shipped a hand-written map of ~16
common two-part suffixes. It was deliberately marked `TODO` and was never
allowed to drive a rule.

## Decision

Adopt **`golang.org/x/net/publicsuffix`** — the official Go implementation,
maintained by the Go team — as the source of truth for registrable-domain
derivation.

This is the module's **first external dependency**, accepted deliberately.

The hand-written suffix list is deleted, not supplemented.

## Rationale for accepting a dependency here

This is the one place in the codebase where the argument for zero dependencies
does not hold:

- The dataset is large, changes over time, and has intricate rules. A
  hand-maintained subset will be wrong, and will be wrong *silently* — the
  function returns a plausible-looking wrong answer rather than failing.
- Correctness here affects security decisions, not formatting.
- `golang.org/x/net` is a Go-team–maintained module with broad adoption, which
  is the strongest supply-chain position available.
- The dependency is confined to one package with one function. Blast radius is
  small and testable.

Note the asymmetry with [ADR 0008](0008-defer-elasticsearch.md), where a
dependency was deferred because the hot path did not need it. Here the hot path
genuinely does.

## Consequences

**Positive**

- Correct handling of the long tail of the Public Suffix List, including
  private suffixes and IDN forms.
- Maintained upstream, so corrections arrive without local work.
- The `TODO` and its associated risk are removed.

**Negative**

- The module is no longer dependency-free. `go.sum` now exists, the build
  requires module download, and the build image gains a dependency layer.
- Supply-chain surface increases. Mitigated by `govulncheck` in CI, pinned
  versions, and the dependency being confined to a single package.
- The PSL changes over time, so behaviour can shift without a code change. This
  is desirable — the list exists because the domain landscape changes — but
  should be noted in release notes when a PSL update alters results.

## Implementation requirements

1. Replace `RegistrableDomain` with a wrapper over `publicsuffix.EffectiveTLDPlusOne`.
2. Handle the error case: `publicsuffix` returns an error when the host has no
   registrable domain (for example a bare IP address or an unknown suffix).
   Return a typed domain error rather than a silent empty string.
3. IP literals must never reach this function. A submitted URL whose host is an
   IP address should be rejected earlier, or handled as a distinct case.
4. `go.sum` must be committed, and the Dockerfile's build stage must switch
   from `COPY go.mod ./` to `COPY go.mod go.sum ./` so a checksum mismatch fails
   the build loudly instead of silently re-resolving versions.
5. The `.dockerignore` and module-download cache in `docker-compose.yml` need no
   change, but the `go` dev service's `GOMODCACHE` volume now becomes
   load-bearing.

## Implementation

`internal/urlintel/host.go` uses `publicsuffix.EffectiveTLDPlusOne` for
extraction and `idna.Lookup` for normalisation. Both live in `golang.org/x/net`,
so this adds one module, not two.

### What the hand-rolled version actually did

Verified by running it, not assumed:

| Input | Old result | Correct | Why it mattered |
|---|---|---|---|
| `co.uk` | `co.uk` | error | A public suffix returned as a domain — every UK site would share one reputation and one rule |
| `8.8.8.8` | `8.8` | error | An IP address mangled into a domain |
| `192.168.1.1` | `1.1` | error | Likewise |
| `localhost` | `localhost` | error | A bare label treated as a domain |
| `com` | `com` | error | A bare TLD treated as a domain |

Each would have let host-level aggregation group unrelated hosts, or widened a
domain-scoped rule far beyond its evidence.

### Normalisation is separate from extraction

`NormalizeHostname` does spelling only — lower-case, punycoded, trailing dot
removed. `RegistrableDomain` does suffix resolution only. They are separate
functions because they answer different questions and fail differently:

- The PSL matches on the canonical ASCII spelling and rejects a trailing dot
  outright. This was confirmed against the library: `WWW.Example.COM.` fails,
  while `www.example.com` succeeds.
- Collapsing them would hide that dependency, and a stray full stop would turn a
  valid domain into an unresolvable one with no obvious cause.

Single-label hosts are accepted by `NormalizeHostname` and rejected only by
`RegistrableDomain`. Requiring two labels during normalisation would conflate
spelling with suffix resolution — the exact separation this ADR is protecting.

### No fallback rules

When the PSL cannot resolve a host, `RegistrableDomain` returns
`ErrNotRegistrable`. It never guesses. A wrong registrable domain silently
merges unrelated hosts into one reputation, which is a security bug that would
present as "the feature works".

`ParseHost` reports this as an empty `RegistrableDomain` with `IsIP` or
`IsLocal` set, so a caller distinguishes "no domain" from "invalid host".

### Internationalised names

`idna.Lookup` converts Unicode hostnames to punycode. Without it, a homograph
such as `аpple.com` (Cyrillic а) would enter host aggregation as a second,
indistinguishable entry for a domain an operator had already blocked.

## Verification performed

Before designing around the library, its behaviour was probed rather than
assumed. Two findings shaped the design:

1. **`$in` inside `partialFilterExpression`** is supported on MongoDB 9.0.4 —
   relevant to ADR 0013's sibling decision, and checked for the same reason.
2. **`service.gov.uk` is itself listed in the PSL as a private suffix**, so it
   has no registrable domain at all. A hand-written rule would have returned it
   as one. This is now a test case, with the reason recorded in the test.

## Testing requirements

A corpus test covering:

| Category | Examples |
|---|---|
| Simple suffixes | `example.com` → `example.com` |
| Multi-part public suffixes | `example.co.uk`, `example.com.au` |
| Private suffixes | `user.github.io` → `user.github.io`, not `github.io` |
| Deep subdomains | `a.b.c.example.co.uk` → `example.co.uk` |
| IDN / punycode | `xn--80ak6aa92e.com` |
| Wildcard suffixes | e.g. `*.ck` with exceptions |
| **Negative** | A registrable domain must never be returned as a suffix |

The negative cases matter most: a test that only asserts correct extraction
would still pass with an implementation that also returned `co.uk` for
`bank.co.uk`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep the hand-written list | Wrong on the long tail, and fails silently. Unacceptable for a security property |
| Embed a PSL snapshot ourselves | Same maintenance burden, same staleness, with none of the upstream review |
| `publicsuffix` via a third-party module | `golang.org/x/net` is the canonical implementation, Go-team maintained |
| Never derive a registrable domain | The concept is required by host-level reputation aggregation and rule scoping |