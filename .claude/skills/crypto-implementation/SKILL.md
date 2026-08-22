---
name: crypto-implementation
description: Rules and guardrails for writing any cryptographic code in this federated EHR project. Use this skill whenever the task touches encryption, decryption, key wrapping or unwrapping, key derivation, key rotation, signing, verification, hashing, randomness, secret sharing, threshold schemes, proxy re-encryption, policy trees, search tokens, the audit hash chain, or anything under src/crypto_core, src/shamir, src/pre, src/policy, src/records, src/lifecycle, src/breakglass, src/audit, or src/search — even if the request sounds like a small helper, a quick fix, a test fixture, or a refactor.
---

# Cryptographic implementation rules

This project's contribution *is* its cryptography. A subtly wrong construction
here does not produce a bug report — it produces a paper that claims something
false. These rules exist because the failure mode is code that looks correct,
passes its tests, and is wrong.

## The rule that matters most

**Never invent, improvise, or "improve" a cryptographic construction.**

If the exact scheme is not already specified in `ARCHITECTURE.md` §3 (the policy
tree / access structure) or §8 (the application security model), stop and ask
the user. Do not fill the gap with something plausible.

This applies with particular force to the three hand-rolled constructions —
Shamir secret sharing, the ElGamal-style proxy re-encryption, and the policy
tree. Each is a stated project contribution, each will be scrutinised in a
viva, and each is easy to write in a form that appears to work while leaking
the secret. Producing a plausible-looking variant is worse than producing
nothing, because nothing is obviously incomplete and a plausible variant is not.

If a spec seems ambiguous, say which part is ambiguous and what the two readings
would imply. Do not resolve it silently.

## Structural rules

**All primitives go through `crypto_core`.** No module imports
`cryptography.hazmat` directly except `crypto_core` itself. If a primitive you
need isn't exposed there, add it to `crypto_core` — do not reach around it. One
audit surface is the whole point.

**No cryptography in `api/`.** Route handlers orchestrate; they do not compute.
A cipher call in a route handler belongs in a module.

**One owner per module.** Check the task table in `WORKFLOW.md` before editing
under `src/`. If the change belongs in someone else's directory, say so rather
than making it.

## Correctness rules

**Randomness comes from `secrets`, never `random`.** No exceptions, including
in tests where the value "doesn't matter" — a test that seeds from `random`
teaches the next reader the wrong habit.

**Nonces are generated per encryption and never reused under a key.** AES-GCM
nonce reuse is catastrophic, not untidy. If you find yourself passing a nonce
in as a parameter, ask why.

**Never hardcode a key, salt, or IV.** Test vectors live in `tests/vectors/`
and are clearly marked test-only.

**Fail closed.** If a signature does not verify, a share is missing, a chain
head does not match, a credential is expired, or a state transition is illegal:
raise. Never return a default, a partial result, or `None` that a caller might
treat as success. Every `except` on a security path re-raises or carries a
comment explaining why swallowing is correct.

**Never log key material, shares, DEKs, emergency keys, search tokens, or
plaintext record content.** Log identifiers and hashes. This includes temporary
debugging output — a `print(dek)` that reaches a commit is a finding.

**Parameterised queries only.** Never build SQL by concatenation or f-string,
including for values that cannot currently be attacker-controlled.

**Security-sensitive requests carry a one-time ID** and are rejected on reuse.
This covers emergency assertions, share requests, and transition events. A
replayed break-glass request that succeeds defeats the time-boxing the entire
state machine exists to enforce.

## Before writing code

Read the relevant part of `ARCHITECTURE.md` first — §2 for what the module is,
§3 for the access structure, §4 for what it depends on, §5 for how data flows
through it, §8 for the security envelope. The dependency map tells you whether
what you're about to call actually exists yet or is still a stub.

## When writing tests alongside the code

Every module ships tests in the same PR. For cryptographic code, a passing
happy-path test proves almost nothing — it proves the code runs. The test that
carries weight is the one that proves the failure mode. Consult the
`negative-security-test` skill for how to write those; at minimum, for any
control you implement, write the test that disables the control and asserts the
operation fails.

## What to do when a rule blocks the task

Say so plainly and stop. "I can't write this without knowing X" is a useful
answer here. Working around a rule to deliver something is the failure this
skill exists to prevent.
