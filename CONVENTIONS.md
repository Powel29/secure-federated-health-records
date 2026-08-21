# CONVENTIONS.md

How we write code so that four people can work at once without breaking each
other. Repository layout is in `ARCHITECTURE.md` §6; branch and merge rules are
in `WORKFLOW.md`.

---

## 1. Style

- **Python 3.11+.** Formatting by `black` (default line length 88), linting by
  `ruff`. Both run in CI; a PR that fails either is not reviewed until it passes.
- **Type hints on every public function.** Not optional. In a crypto codebase,
  `bytes` vs `str` confusion is a real bug class and annotations catch it.
- Naming: `snake_case` functions and variables, `PascalCase` classes,
  `UPPER_SNAKE` constants, `_leading_underscore` for module-private.
- Docstrings on every public function: one line on what it does, then `Args:`,
  `Returns:`, `Raises:`. For crypto functions, also state the **security
  property** the function is supposed to provide.
- Prefer explicit over clever. Someone else has to defend your module in a viva.

## 2. Crypto-specific rules

These are not style preferences. Violating them invalidates our claims.

1. **All primitives go through `crypto_core`.** No module imports
   `cryptography.hazmat` directly except `crypto_core` itself. This gives us one
   place to audit and one place to fix.
2. **Randomness comes from `secrets`, never `random`.** No exceptions.
3. **Never log key material, shares, DEKs, or plaintext record contents.** Log
   identifiers and hashes. A `.gitignore`d local log that leaks a DEK is still a
   finding in the viva.
4. **Never hardcode a key, salt, or IV.** Test vectors live in `tests/vectors/`
   and are clearly marked as test-only.
5. **Nonce reuse is a bug, not a style issue.** AES-GCM nonces are generated per
   encryption, never reused across a key.
6. **Fail closed.** If a signature does not verify, a share is missing, or a
   chain head does not match, raise — never return a partial or default result.
   Every `except` in security-relevant paths must re-raise or explicitly
   document why swallowing is correct.
7. **Parameterised queries only.** Never build SQL by string concatenation or
   f-string, even for internal values that "can't" be attacker-controlled.
8. **Federated endpoints come from an allowlist in config**, never from a value
   supplied in a request. A discovery response must not be able to redirect us.
9. **Every security-sensitive request carries a one-time ID** and is rejected on
   reuse. Applies to emergency assertions, share requests, and transition events.
10. **No cryptography in `api/`.** The API layer orchestrates; it does not
   compute. If you are writing a cipher call in a route handler, it belongs in a
   module.

## 3. Module ownership

Each directory under `src/` has exactly one owner (see the task table in
`WORKFLOW.md`). **Only the owner edits files in their directory.** If you need a
change in someone else's module, open an issue or ask them — do not edit it
yourself, even if the fix is one line. This is the main mechanism preventing
merge conflicts across four parallel workstreams.

**The one exception is `src/contracts/`.** It holds the shared schemas
(`Record`, `DEKWrapping`, `TransitionEvent`, `AuditEntry`, `AttributeCredential`,
`Facility`, `PolicyTree`, plus `EmergencyAssertion` and `RequestEnvelope` from the
§8 review, and `ConsentRequest` and `ConsentGrant` from ADR-0017 — eleven in
all). It is frozen at the end of Phase 0. After that:

- A change to `contracts/` requires a PR titled `contract: <what changed>`,
  reviewed and approved by **all four** members before merge.
- The PR description must list which modules are affected.
- Contract changes are announced in the team channel, not merged silently. A
  contract change that surprises someone costs more than it saves.

## 4. Commit messages

Conventional-commits format:

```
<type>(<scope>): <subject>

<optional body — why, not what>
```

- **type:** `feat`, `fix`, `test`, `docs`, `refactor`, `bench`, `chore`,
  `contract`
- **scope:** the module directory — `crypto_core`, `lifecycle`, `breakglass`,
  `audit`, `policy`, `search`, `pre`, `identity`, `authority`, `records`,
  `storage`, `federation`, `api`, `bench`, `demo`, `paper`
- **subject:** imperative mood, lowercase, no trailing period, under ~70 chars

Examples:

```
feat(shamir): add 2-of-3 split and combine over GF(p)
fix(audit): verify chain head before releasing threshold share
test(security): revoked user cannot decrypt after re-wrap
contract: add expiry_ts to TransitionEvent
```

Commit small and often. A commit that touches six modules cannot be reviewed and
cannot be reverted cleanly.

## 5. Testing requirements

- **Every module ships with tests in the same PR as the code.** "Tests later"
  means never, and in this project the tests *are* the evidence for the paper's
  claims.
- Test file mirrors source path: `src/shamir/split.py` → `tests/shamir/test_split.py`.
- Test names describe behaviour: `test_two_shares_reconstruct_secret`, not
  `test_shamir_2`.
- **Negative tests are first-class and live in `tests/security/`.** These are
  the ones an evaluator will care about. At minimum, and each of these is a
  named phase exit criterion:
  - a revoked user cannot decrypt after re-wrap
  - break-glass fails closed when the audit service cannot commit its log entry
  - a single share — including the audit service's — cannot open a record
  - a search token does not work once the emergency state has expired
  - a tampered audit log entry is detected by chain verification
  - an illegal state transition is rejected
  - a transition event with an invalid signature is rejected
  - a replayed emergency assertion is rejected, not re-executed
  - a caller authenticated but unauthorised for a patient is denied before any
    crypto or DB work occurs (BOLA)
  - an expired or revoked credential fails validation
- Benchmarks are not tests. They live in `bench/` and must not run in CI.
- Target coverage on `src/` is ~80%, but coverage is a smell detector, not a
  goal. A module at 95% coverage with no negative tests is worse than one at 70%
  with them.

## 6. Documentation as we go

- **Architecture Decision Records** in `docs/adr/NNNN-short-title.md` whenever
  we make a choice with alternatives — context, decision, consequences, in about
  half a page. Copy `docs/adr/template.md`, and **add a row to the tracker table
  in `docs/adr/README.md` in the same PR** — an ADR not in the tracker is not
  tracked. The three we owed (rejecting Charm-Crypto, the secret-sharing access
  structure, simulating the HSM timer) are now written as ADR-0001–0003. These
  become paper prose almost verbatim, so writing them as we go is not overhead.
- Anything surprising gets a comment explaining **why**, not what.
- When a limitation is discovered, add it to `PROJECT.md` §5 immediately.
  Limitations found late and written up honestly are fine; limitations
  discovered by an examiner are not.
