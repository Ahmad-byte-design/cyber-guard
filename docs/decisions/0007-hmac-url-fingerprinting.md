# 0007 — HMAC-SHA-256 URL fingerprinting

- **Status:** Accepted (implemented)
- **Date:** 2026-10-16
- **Affects:** `internal/urlintel`, `docs/data-model.md`, `docs/security-and-privacy.md`

## Context

The product's privacy promise is that raw URLs are not retained. But the
fastest path — and the main protection of the provider quota — requires an exact
lookup: "have I already assessed this exact URL?" That needs a deterministic
key derived from the URL, stored in place of the URL.

The obvious approach — a plain SHA-256 of the URL — is not adequate. URLs are
drawn from a small effective space: popular domains, phishing kit landing
pages, common paths. A rainbow table, or simply a candidate list tested against
the digest, recovers the original in seconds. Storing `sha256(url)` while
claiming not to store URLs would be security theatre.

## Decision

Store `HMAC-SHA-256(key, canonical_form)` as hex, where the key
(`URL_FINGERPRINT_HMAC_KEY`) is a backend-only secret of at least 32 random
bytes.

The canonical form lowercases scheme and host, normalises an empty path to
`/`, and drops the fragment — while **preserving path and query byte-for-byte**,
because URLs are case-sensitive there and query parameters change behaviour.

Implemented in `internal/urlintel`: `Canonical`, `Fingerprint`, `Prepare`.

## Consequences

**Positive**

- Recovering a URL from a fingerprint requires the key. Without it, a stolen
  database yields hashes that resist dictionary attack.
- Deterministic: the same URL always maps to the same entry, which is what the
  cache requires.
- Already implemented and tested, including that an empty key is rejected.

**Negative — and these matter**

- **The key is the security boundary.** If it leaks, every stored fingerprint
  becomes reversible to anyone holding a candidate URL list. It requires the
  same handling as the provider API key.
- **Rotation is destructive.** A new key invalidates every fingerprint, i.e.
  the entire cache, forcing a full re-scan. It is a planned operation, not a
  routine one.
- **The key must be identical across all instances** of `api` and `worker`,
  or they compute different fingerprints and the cache silently stops working.
  This is a real operational hazard with multiple replicas.
- **Fingerprints are not anonymous.** A hostname, a verdict and a timestamp
  still identify "this user checked this site on this date". Treat the
  fingerprint as a pseudonymous identifier.

## Query-string policy

The canonical form **includes** the query string. Dropping it would merge
`?reset=abc` with `?reset=xyz`, which are genuinely different resources, and
would degrade detection accuracy.

The trade is accepted: the query may contain tokens, but the query never leaves
the HMAC input. If token-insensitive matching is ever required, implement a
targeted strip list (documented tracking parameters), never a blanket
"remove all parameters".

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Plain SHA-256 | Trivially reversible with a candidate list. Not privacy-preserving |
| Argon2 / bcrypt per URL | Password hashing is designed for low-entropy secrets under attack; it is deliberately slow and salted per entry, so equal URLs would not produce equal keys — which breaks the cache |
| Truncating the digest | Collides more, gaining nothing since the full digest is not itself sensitive |
| Storing the raw URL encrypted at rest | Encryption at rest protects the disk, not the database dump, query logs, or backups. Also restores the operational risk of holding the data at all |
| No fingerprint; store raw URL | Abandons the privacy guarantee, which is the product's differentiator |

## Security requirement

The empty-key case must return an error rather than an unkeyed hash. An
unkeyed fingerprint would let anyone confirm guesses about URLs already
assessed — turning the cache into an oracle for private browsing history.
Implemented and tested.