# ADR-0022: Remove the caller-supplied nonce from `aes_gcm_encrypt`

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-08-25
- **Deciders:** Phase-1 review — owner **Powel** (`crypto_core`) to ratify
- **Task / source:** Phase-1 review of P1-1; CONVENTIONS.md §2 rule 5
- **Affects:** `src/crypto_core/symmetric.py`; callers in `src/records/service.py`
  (`encrypt_record`, `wrap_dek`); `src/pre/elgamal.py` (indirect, via HKDF only)

## Context

`aes_gcm_encrypt` accepted an optional `nonce` parameter: when `None` it
generated a fresh 12-byte nonce, otherwise it used the caller's. AES-GCM nonce
reuse under a single key is catastrophic (it destroys both confidentiality of
the XOR difference and the authentication guarantee), and the
`crypto-implementation` guardrails call this out explicitly: *"If you find
yourself passing a nonce in as a parameter, ask why."* No caller ever passed a
nonce — both production call sites relied on the default — so the parameter was
pure attack surface: the one affordance by which a future caller could reuse a
nonce sat in the single module every other module routes crypto through.

## Decision

Drop the `nonce` parameter from `aes_gcm_encrypt`. The function now always
generates a fresh nonce with the CSPRNG and returns it alongside the ciphertext.
There is no supported way to inject a nonce into the encrypt path. `aes_gcm_decrypt`
keeps its `nonce` parameter — decryption necessarily takes the nonce as input.

## Consequences

- The nonce-reuse footgun is removed at the API level, not merely by convention.
- A fixed-nonce AES-GCM *encrypt* known-answer test is no longer expressible
  through this function. This is fine: the P1-1 KAT
  (`test_aes_256_gcm_known_answer_vector`) drives the deterministic direction,
  `aes_gcm_decrypt`, against a published vector (McGrew/Viega GCM Test Case 16),
  which exercises the same AES-GCM core.
- If a genuine need for deterministic encryption ever appears (it should not),
  it must be added as a clearly test-only, separately named primitive — not by
  re-widening this function.

## Alternatives considered

- **Keep the parameter, document the danger.** Rejected — a docstring does not
  stop misuse, and this function lives in the shared audit surface where the
  cost of one slip is highest.
- **Keep the parameter but reject reused nonces.** Rejected — the function is
  stateless and cannot know which nonces a key has already seen; enforcement is
  impossible here.
