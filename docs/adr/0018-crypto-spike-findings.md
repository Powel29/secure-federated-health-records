# ADR-0018: Crypto sanity-spike findings (P0-6)

- **Status:** Proposed — flips to Accepted once all four machines sign off below
- **Date:** 2026-08-21
- **Deciders:** Avaneeth (owner), then all four (sign-off table)
- **Task / source:** P0-6 (WORKFLOW.md); ADR-0001 (reject Charm-Crypto)
- **Affects:** `crypto_core` (C1), `pre` (C3); [tests/spike_crypto_sanity.py](../../tests/spike_crypto_sanity.py)

## Context

Before anyone builds on the crypto stack, P0-6 requires proving that the four
primitives the project depends on actually run on every team machine, using the
pinned `cryptography==42.0.5` and pure Python. This validates ADR-0001's decision
to reject Charm-Crypto and hand-roll the exotic primitive (the PRE). The exit
criterion: "a throwaway test script runs cleanly on all four machines; findings
noted in an ADR."

The spike is [tests/spike_crypto_sanity.py](../../tests/spike_crypto_sanity.py):
a standalone script (not pytest-collected) that exercises AES-256-GCM, HKDF-SHA256,
ECDSA P-256, and a toy unidirectional ElGamal PRE, printing PASS/FAIL and exiting
non-zero on any failure.

## Decision

Confirm the stack. `cryptography==42.0.5` installs from a wheel and all four
primitives round-trip. Phase 1 (`crypto_core`, then `pre`) proceeds on this basis.

## Findings

- **`cryptography` installs as a prebuilt wheel** on the dev machine — no C
  compiler or system OpenSSL-dev needed. Confirm per-OS in the sign-off table.
- **AES-256-GCM** round-trips and detects a single flipped ciphertext byte
  (`InvalidTag`). Nonce reuse under one key is a footgun the *module* must
  prevent — the contract already fixes nonce length at 12 bytes.
- **HKDF-SHA256** is deterministic for fixed `(ikm, salt, info)` and
  context-separates on `info`. HKDF objects are single-use — a fresh instance is
  built per derivation (a real gotcha for the module code).
- **ECDSA P-256** signs/verifies, rejects a tampered message, and survives a
  PEM public-key round-trip. Signatures are **non-deterministic** (`cryptography`
  draws a random `k`), so two signatures over the same message differ and both
  verify — tests must verify, never compare signature bytes.
- **Toy unidirectional ElGamal PRE works in pure Python** integer arithmetic, no
  dependency. **Correctness note carried to P1-5:** the re-encryption key is
  `rk = a·b⁻¹ mod q`, *not* `b·a⁻¹`, and the inverse is taken **mod the subgroup
  order q** (safe prime p = 2q+1), not mod p−1 — otherwise not every exponent is
  invertible and B fails to decrypt. The naive ordering silently fails; it was
  caught here rather than in the module.
- **Randomness comes from `secrets` / `os.urandom`**, never `random` (CONVENTIONS
  §2 rule 2; ruff S311 enforces it in CI).

## Consequences

- Phase 1 proceeds; the ARCHITECTURE §1 stack is validated on at least one
  machine and, once the table below is complete, on all four.
- The PRE re-key ordering + subgroup-order-inverse finding is a concrete
  correctness requirement handed to P1-5 (`pre`, owned by Ojas).
- The spike is throwaway: it is kept in `tests/` so all four can run it, but it
  is not a regression test and is not collected by pytest. It must stay
  lint/format-clean because CI (P0-5) scans `tests/`.
- **Honest downside:** the spike proves the primitives *work*, not that they are
  *used correctly* in the modules (constant-time, nonce management, parameter
  sizing). Those are the module authors' and the negative-test suite's job.

## Machine sign-off (completes the exit criterion)

Each member runs `python tests/spike_crypto_sanity.py`, confirms
`ALL CHECKS PASSED`, and records it here.

| Member | OS | `cryptography` installed from wheel? | Result | Date |
|---|---|---|---|---|
| (dev run) | Windows 11 | yes | ALL CHECKS PASSED (exit 0) | 2026-08-21 |
| Avaneeth | | | | |
| Powel | | | | |
| Nandini | | | | |
| Ojas | | | | |

## Alternatives considered

- **Skip the spike, start Phase 1 directly.** Rejected: the exit criterion exists
  precisely so an install or primitive failure surfaces before four people build
  on it. The PRE re-key bug this spike caught is the argument for keeping it.
- **Write it as pytest tests.** Rejected for now: it is a per-machine sanity
  check, not a regression guard, and pytest collection on every CI run would
  couple it to the suite. `crypto_core` gets real KAT-backed pytest tests in
  Phase 1 regardless.
