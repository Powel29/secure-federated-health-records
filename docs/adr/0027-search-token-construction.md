# ADR-0027: Search-token construction for the encrypted index (C12)

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-08-30
- **Deciders:** Nandini (author), Powel (reviewer) → all four for ratification
- **Task / source:** P2-5 (WORKFLOW.md); ARCHITECTURE §2 C12
- **Affects:** `src/search/service.py`, `src/storage/repositories.py`
  (`search_index` table), `tests/security/test_phase2_search.py`

## Context

`ARCHITECTURE.md` §2 C12 specifies only the *shape* of the search construction:
"Encrypted inverted index over record contents, plus search token derivation.
Tokens derive from the emergency key, so search capability exists only while
the record is in Emergency-open and is dead once it expires." Everything else
— the KDF, the domain-separation string, whether tokens are per-record, term
normalisation, salt versioning — is under-specified. P2-5 needs a concrete
construction now, built against a fixed test key until break-glass exists
(WORKFLOW.md P2-5).

The crypto-implementation skill's governing rule is "never invent, improvise,
or improve a cryptographic construction" beyond what §3/§8 specifies. Some
minimum construction is unavoidable to ship P2-5; this ADR is where those
minimum choices are recorded so a reader (or the paper's security section)
can see exactly what was decided and what was deferred.

## Decision

The coded token for one (emergency key, plaintext term) pair is:

```
coded_term = HKDF-SHA256(
    IKM  = emergency_key,          # 32 bytes, from break-glass reconstruction
    salt = b"search-token-v1",     # versioned, so a future construction change
                                   #   is a bytes-level migration, not silent
    info = b"health-record-search:" || term.encode("utf-8"),
    L    = 32 bytes,
)
```

The construction is:

- **Deterministic** in `(emergency_key, term)`. Same inputs always produce the
  same 32-byte token, which is what makes equality search work against
  `search_index.coded_term`.
- **Not bound to a specific `record_id`.** A single derived token matches every
  record in `search_index` whose row was written for that term under that key.
- **Case-sensitive and byte-exact** on the search term. No case-folding or
  unicode normalisation is applied at derivation time.

The domain-separation string (`_KDF_INFO_PREFIX`) and salt (`_KDF_SALT`) live
as module constants in `src/search/service.py`, mirroring the `_KDF_SALT` /
`_KDF_INFO` pattern in `src/pre/elgamal.py`.

## Consequences

**What this makes work.** Equality search: derive one token, ask the store
`SELECT record_id FROM search_index WHERE coded_term = %s`. The store learns
nothing about the plaintext term (HKDF output is indistinguishable from
random) and nothing about the emergency key.

**Documented leakage — deterministic-SSE.** Two records that index the same
plaintext term produce identical `coded_term` values. The store can observe
which records share which coded values (search-pattern and access-pattern
leakage). This is intrinsic to equality-searchable symmetric encryption
without oblivious RAM, and the paper's limitations section must cite it. See
`tests/security/test_phase2_search.py::test_sec_documented_leakage_same_term_same_key_yields_equal_tokens`
— that test locks the leakage in as intentional so a future change that
silently breaks it is caught in CI.

**Salt is versioned.** Bumping to `b"search-token-v2"` on any construction
change forces a full re-index rather than a silent divergence between old
rows and new derivations.

**Two open questions this ADR does *not* decide.** Both are follow-ups, not
required for P2-5's exit; deferring them here is deliberate so they get their
own decision, not a snuck-in choice inside P2-5:

1. **Per-record binding.** Adding `record_id` to the HKDF `info` string would
   prevent an attacker with write access to `search_index` from copying a
   coded_term row from record A onto record B (a false-match forgery). The
   trade is that the searcher must derive one token per candidate record
   (`O(N)`), whereas the current construction is `O(1)`. The honest-but-curious
   store model in ARCHITECTURE §5 does not include write attackers, so this is
   defence-in-depth beyond the stated threat model — worth its own decision.
2. **Term normalisation.** Applying NFKC + casefold + strip at derivation would
   make `"Diabetes"`, `"diabetes"`, and `" DIABETES "` match the same coded
   value. This is a usability improvement, but it is also a policy decision
   about what "same term" means to a clinician searching under emergency; the
   naïve normalisation collapses some medically-distinct strings.

Both open questions get their own ADR if adopted, not a silent commit under
P2-5.

## Alternatives considered

- **Randomised (per-index) tokens with a lookup structure.** Store `coded_term`
  as `HKDF(k, info=term || nonce)` alongside the nonce; search issues an
  `Encrypt(k, term)` trapdoor and the store scans. Hides equality across
  records but forces a linear scan and needs a separate trapdoor scheme.
  Rejected as scope creep for P2-5 given no faculty requirement to hide
  equality; can be revisited as future work in the paper.
- **`salt=None`.** Nandini's initial draft. Safe with a uniform IKM but leaves
  no path for a future construction change short of migrating the whole table
  by another mechanism. Rejected: the cost of adding a version tag now is
  zero, and the cost of adding one later is a migration.
- **Domain-separation string inlined as a bare byte literal.** Nandini's
  initial draft (`b"health-record-search:"` at the call site). Rejected: a
  bare literal duplicated across future modules is how HKDF domain collisions
  happen; keeping it as `_KDF_INFO_PREFIX` in one place matches the
  `pre/elgamal.py` pattern.

## Amendment — 2026-10-13 (clinical review)

Terms are trimmed and case-folded before derivation, on indexing and on
query, so a clinician typing "Penicillin" finds a record indexed under
"penicillin". The KDF, salt and info prefix are unchanged; terms already
indexed in lower case keep their tokens.
