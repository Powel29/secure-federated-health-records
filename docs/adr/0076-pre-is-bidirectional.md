# ADR-0076: The ElGamal PRE is bidirectional and break-glass delivers by KEM

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal) → Ojas (pre), Powel (breakglass gate) → all four
- **Task / source:** Review decision D11, option (a); finding F32
- **Affects:** `src/pre/elgamal.py`, `src/pre/__init__.py` (docstrings only), `ARCHITECTURE.md` §1 table, C3 and §5 step 5, `PROJECT.md` §5 item 10, `docs/explainers/05`, `docs/explainers/09`; supersedes ADR-0012's "unidirectional" and "without decryption" wording

## Context

ADR-0012, ARCHITECTURE C3 and the `pre` docstrings described a unidirectional
proxy re-encryption that re-wraps a DEK without the proxy seeing it. The code
does something else:

- `generate_rekey` computes `rk = sk_a · sk_b⁻¹ mod q`. Its inverse is the
  B → A key, so the scheme is bidirectional, and computing it needs both
  secret keys.
- `reencrypt` is never called outside `pre`. The break-glass gate unwraps the
  DEK at the facility and delivers it with `encapsulate_key` + AES-GCM
  (`breakglass/gate.py` already says so).

## Decision

Correct the description, not the construction (D11-a). The docstrings,
ARCHITECTURE, the explainers and a new `PROJECT.md` §5 caveat now say: the
re-encryption key is bidirectional, and break-glass uses a KEM delivery of a
DEK the facility has unwrapped. ADR-0012's "shrink PRE to one-direction
re-wrap" stands as a scope decision; its unidirectional and decryption-free
wording is superseded by this ADR.

## Consequences

- The paper cannot claim that no server sees the DEK during cross-facility
  handoff; the facility does, for the length of the unlock.
- No code path changes, so no test changes; the subgroup checks (ADR-0023)
  still apply to every input.
- A real unidirectional PRE (e.g. AFGH) needs pairings, which `PROJECT.md` §6
  rules out.

## Alternatives considered

- **D11-b: implement a unidirectional scheme** — needs a pairing library,
  which is out of scope, and would be a new construction the
  `crypto-implementation` rules forbid improvising.
- **Make break-glass call `reencrypt`** — would need the DEK stored under a
  persistent ElGamal key first, a new wrapping format; it still would not make
  the scheme unidirectional.
