# ADR-0026: Policy engine enforces access cryptographically, not by boolean check alone

- **Status:** Accepted
- **Date:** 2026-08-30
- **Deciders:** Powel (P2-3 / `policy` owner)
- **Task / source:** P2-3 (WORKFLOW.md); ARCHITECTURE.md §3, §8 C6/C7; ADR-0002, ADR-0016
- **Affects:** `policy` (C7); depends on `authority` (C6) for attribute-key material

## Context

P2-3 replaces the P1-6 boolean stub (`policy/stub.py`) with the real access
structure engine. Two readings of "the policy engine" were possible:

- **Reading A — cryptographic enforcement.** ARCHITECTURE.md §3 states it
  precisely: each leaf's secret is *encrypted to the attribute key issued by
  the authority that owns that attribute*; AND nodes k-of-k Shamir-split their
  parent secret across children; OR nodes give every child the same secret;
  the root secret wraps the DEK. Access is obtained only by *decrypting* leaf
  shares with held attribute keys and reconstructing up to the root — the
  boolean satisfaction is a consequence of holding the right keys, not the
  mechanism.
- **Reading B — credential-gated reconstruction.** Evaluate the boolean tree
  over verified credentials, and only on satisfaction hand back a root secret
  the engine was holding. The "attribute key" reduces to possession of a valid
  credential.

The just-merged P2-2 (`authority`) issues *signed credentials only* — it does
not currently mint the per-attribute key material §3/§8-C6 assume. So the spec
(which wants attribute keys) and the merged implementation (which has none)
disagree, and P2-3 had to resolve which it builds against.

## Decision

Adopt **Reading A**, exactly as ARCHITECTURE.md §3 specifies — the
`crypto-implementation` skill's governing rule is to never substitute a
different construction for the one §3 states, and §3 states Reading A. The
engine:

- `compile_policy(tree, root_secret, attribute_keyring)` recurses top-down:
  AND ⇒ `shamir.split_secret(secret, k=m, n=m)`; OR ⇒ same secret to each
  child; leaf ⇒ `crypto_core.aes_gcm_encrypt` of the leaf secret under the
  owning authority's attribute key (fresh nonce per call, CONVENTIONS §2
  rule 5).
- `reconstruct_root_secret(compiled, holder_keyring)` recurses bottom-up:
  leaf ⇒ decrypt with the held attribute key; OR ⇒ any one child suffices;
  AND ⇒ all children required, then `shamir.combine_shares(k=m)`. Fails closed
  (raises `PolicyDeniedError`) if any required leaf cannot be decrypted.
- `evaluate_policy(tree, presented_attributes) -> bool` is retained unchanged
  as the cheap boolean **PDP** pre-check; `reconstruct_root_secret` /
  `unwrap_dek_via_policy` are the enforcing **PEP**.

**Attribute-key material is an injected dependency, not owned by `policy`.**
The engine takes an `attribute_keyring` (keyed `(authority_id, name, value)`)
at compile time and a holder keyring at reconstruct time. Where those keys come
from — the issuing authority — is `authority`'s concern, not the engine's.

## Consequences

- **Authority binding is cryptographic, not asserted.** A leaf owned by
  `authority-net` is encrypted under that authority's key; a holder of some
  other authority's key for the same `name:value` simply cannot decrypt it.
  The wrong-authority case fails closed by construction.
- **`authority` owes attribute-key issuance (follow-up on Ojas's module,
  ADR-0025).** ARCHITECTURE §8-C6 says the authority issues "the attribute key
  material used by the policy engine"; P2-2 as merged does not. Until that
  lands, the engine is exercised with test-supplied keyrings. This is a change
  *request* to `authority`, not something `policy` may reach in and do
  (CONVENTIONS §3, one owner per module). Filed as a P2-2 follow-up.
- **Collusion limit unchanged (ADR-0002).** Two clinicians pooling attribute
  keys still satisfy a policy neither satisfies alone; Reading A does not fix
  this and does not worsen it. A test documents it so the paper's honesty
  caveat is evidence-backed.
- **Honest downside — nested AND inflates share size.** Each AND level
  Shamir-splits its parent secret, and shares exceed the secret per 32-byte
  block, so deep AND trees grow the compiled material. Acceptable at this
  scale; recorded as a ciphertext-expansion data point for `bench/`.
- **Compiled-tree persistence is a later concern.** The engine keeps
  `CompiledPolicy` in memory; serializing it for storage (so a future reader
  reconstructs against stored shares) is P3-14 / storage wiring, not P2-3, and
  is deliberately out of scope here to avoid a premature frozen-contract change.

## Alternatives considered

- **Reading B (credential-gated).** Rejected: it substitutes a boolean gate
  for the construction §3 specifies, quietly weakening the "CP-ABE substitute"
  novelty claim the project rests on — a change that would have to be disclosed
  in the paper. It is faster only because it skips the very mechanism that is
  the contribution.
- **Add attribute-key issuance to `authority` inside this PR.** Rejected:
  `authority` is not `policy`'s to edit (CONVENTIONS §3, ADR-0025 gives it to
  Ojas). The engine instead depends on injected key material and the authority
  change is coordinated separately.
