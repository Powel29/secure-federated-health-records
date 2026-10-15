# ADR-0071: Proxy re-encryption claims corrected -- KEM delivery, bidirectional toy scheme

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (decision, review D11-a; owns `breakglass`); Ojas (`pre`) to review
- **Task / source:** review D11 / F32
- **Affects:** `pre/elgamal.py` and `pre/__init__.py` docstrings; `breakglass/gate.py` docstring; `ARCHITECTURE.md` §1 table and §2 C3; `PROJECT.md` §5 caveat 8; `tests/pre/test_proxy_reencryption.py` (`test_rekey_inverts_to_the_reverse_direction`); a comment in `tests/security/test_phase1_security.py`; amends ADR-0012's "without decryption"

## Context

The docstrings, ARCHITECTURE.md and ADR-0012 said the PRE is unidirectional
and that break-glass re-wraps the DEK to the clinician "without decryption".
Neither is true of the code:

- `rk = sk_a * sk_b^-1 mod q`, and `rk^-1 mod q` is the key from B to A, so
  whoever holds `rk` re-encrypts in both directions;
- the group is a 256-bit safe prime, well under 128-bit security;
- break-glass never calls `reencrypt`. The facility reconstructs the
  emergency key, unwraps the DEK in its own memory and delivers it under a
  key encapsulated to the clinician's ElGamal public key.

## Decision

Option (a) of D11: correct every statement, keep the construction. The PRE is
described as a bidirectional, toy-sized course demonstration; break-glass is
described as a KEM-style delivery in which the facility sees the DEK; the
paper states both as a limitation (PROJECT.md §5 caveat 8). A test documents
the bidirectionality, so the claim can be checked rather than asserted.

## Consequences

- The paper's PRE claim narrows to what the code does. What keeps the DEK
  from a caller is the threshold, the signed transition and
  log-before-release, not the PRE.
- No code path changes; `tests/security/test_phase1_security.py` keeps its
  assertions (the delegator cannot read a ciphertext re-encrypted for B), but
  no longer calls that "unidirectionality".
- The explainers under `docs/explainers/` (05, 09) still say "unidirectional";
  they are the user's working documents and are updated with them.

## Alternatives considered

- **(b) Implement a unidirectional PRE.** Needs pairings, which are out of
  scope (PROJECT.md §6) and would bring back the Charm-Crypto risk ADR-0001
  rejected.
- **Re-encrypt the DEK with `reencrypt` at break-glass.** Would need the DEK
  stored under a standing PRE public key and a delegator key per record; the
  facility would still compute the re-encryption key, so nothing is gained.
