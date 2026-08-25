# ADR-0023: Validate order-q subgroup membership in the ElGamal PRE

- **Status:** Proposed
- **Date:** 2026-08-25
- **Deciders:** Phase-1 review — owner **Ojas** (`pre`) to ratify
- **Task / source:** Phase-1 review of P1-5; ARCHITECTURE.md §2 C3, ADR-0012
- **Affects:** `src/pre/elgamal.py` (`encrypt_point`, `reencrypt`, `decrypt_point`);
  `tests/pre/test_proxy_reencryption.py`

## Context

The hand-rolled ElGamal proxy re-encryption works in the prime-order-`q`
subgroup of GF(P), where `P = 2q + 1` is a safe prime and `g = 4` generates that
subgroup. Before this change, `encrypt_point` checked only that a public key was
in range `1 < pk < P`, and `reencrypt`/`decrypt_point` exponentiated the
caller-supplied `c1` with no validation at all. A group element that is *in
range but not in the subgroup* — e.g. an element of small order such as `P-1`
(order 2) — is exactly the input a small-subgroup confinement attack uses to
leak information about a private exponent. The PRE is a stated project
contribution and will be scrutinised in the viva; "we validate the exponent
range but not group membership" is precisely the gap an examiner probes. It is
not exploitable in the current flow, where every group element originates from
`generate_keypair`/`encrypt_point`, but relying on that is an unstated trust
assumption rather than an enforced control.

## Decision

Add `_is_subgroup_member(x)` — `1 < x < P` **and** `x^q ≡ 1 (mod P)` — and gate
every caller-supplied group element on it before any exponentiation: the public
key in `encrypt_point`, and the `c1` ciphertext component in `reencrypt` and
`decrypt_point`. A non-member raises `PREKeyError` (fail closed). The plaintext
`message_point` is deliberately *not* constrained: a caller choosing their own
message gains nothing by it, so it is not an attack vector.

## Consequences

- The PRE fails closed on hostile group elements instead of computing on them;
  the trust assumption is now an enforced, tested control
  (`test_encrypt_point_rejects_non_subgroup_public_key`,
  `test_reencrypt_rejects_non_subgroup_c1`,
  `test_decrypt_point_rejects_non_subgroup_c1`).
- Each `encrypt_point`/`reencrypt`/`decrypt_point` call now costs one extra
  modular exponentiation (`x^q mod P`). Negligible for this workload, but it is
  a real ~2x cost on the cheap operations and should be noted if PRE ever shows
  up in the benchmark hot path.
- The paper's PRE section can state subgroup validation as an implemented
  defence, not future work.

## Alternatives considered

- **Document the trust assumption, validate nothing.** Rejected — an unenforced
  precondition on a headline construction is the kind of gap the security
  analysis exists to close, and it costs one line to enforce.
- **Validate public keys only, not `c1`.** Rejected — `c1` is attacker-supplyable
  in the re-encryption and decryption paths (the proxy and any ciphertext
  handler), so it needs the same guard as a public key.
- **Full validation of every component including `c2` and `message_point`.**
  Not adopted — `c2` and a self-chosen plaintext are not small-subgroup attack
  vectors, so validating them adds cost without closing a threat.
