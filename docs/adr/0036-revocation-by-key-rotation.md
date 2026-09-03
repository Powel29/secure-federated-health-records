# ADR-0036: Revocation by key-rotation, not by policy flag

- **Status:** Proposed
- **Date:** 2026-09-03
- **Deciders:** Powel → all four
- **Task / source:** P3-7 (`WORKFLOW.md`)
- **Affects:** `records` (new `revocation.py`, extended `exceptions.py`),
  `lifecycle` (the `GRANTED → REVOKED` transition, already legal per
  ADR-0030), `policy` (re-compilation on rotation); the paper's
  forward-secrecy claim; P3-12 (who-can-revoke authorization) which layers
  on top.

## Context

The project's central claim is that revocation is a **cryptographic**
event, not a database predicate. ARCHITECTURE.md §5 already sketches the
sequence — signed request, DEK re-generation, wrapping re-computation, log
entry — but no producer existed. Without one, "revocation" would collapse
to a `status='REVOKED'` column, and a revoked clinician who cached the DEK
would still be able to decrypt every future version of the record.

The pieces to compose all exist: `records.service.wrap_dek` /
`encrypt_record` for the crypto rotation, `policy.engine.compile_policy`
for the new tree, `policy.engine.author_policy_with_owner` for the
ADR-0016 owner leaf, and `lifecycle.state_machine.create_transition_event`
for the signed lifecycle event. What was missing was the orchestration
that ties them together and returns one atomic result.

## Decision

`records.revocation.revoke_record_access` performs **full DEK rotation**
on every revocation, not a re-wrap of the same DEK:

1. Decrypt payload with the old DEK (caller-supplied — the caller has
   already satisfied policy).
2. Author a fresh policy tree `OR(new_clinical_policy, owner:<patient_id>)`
   (ADR-0016 preserves patient self-access by construction).
3. Mint a **fresh 32-byte root secret** and compile the tree against the
   authoring attribute keyring.
4. Mint a **fresh 32-byte DEK** and re-encrypt the payload (same
   `record_id` — identity preserved across rotation, only the keys change).
5. Wrap the fresh DEK under the fresh root secret with
   `generation = old_generation + 1`.
6. Emit a signed `GRANTED → REVOKED` `TransitionEvent`
   (`LEGAL_TRANSITIONS` since ADR-0030).
7. Return a `RevocationResult` carrying every artefact; the caller
   persists and audit-logs.

The function does **not** enforce who-may-revoke — that authorization
check is P3-12's job. The rotation pipeline is the cryptographic mechanism;
the authorization layer above it decides whether it should run.

## Consequences

**Guarantees (backed by negative tests):**

- A clinician holding the old DEK cannot decrypt the rotated ciphertext —
  the new DEK is independent (fresh CSPRNG draw).
- The old root secret cannot unwrap the new `DEKWrapping` — the new
  wrapping is under a fresh root secret with AES-GCM authentication.
- A clinician whose attribute keys were dropped from the new policy tree
  cannot reconstruct the new root secret — `policy.engine` fails closed
  with `PolicyDeniedError`.
- The `generation` counter increments monotonically, so stale wrappings
  are distinguishable from current ones at the storage boundary.
- The patient can always still decrypt (ADR-0016 owner leaf is re-added
  automatically).

**Honest limitations:**

- **Not retroactive.** Plaintext a clinician had already decrypted and
  taken elsewhere before revocation is not recoverable. Stated in
  PROJECT.md §5.
- **Not encrypted at the storage layer.** The rotated `Record` and
  `DEKWrapping` still live in the semi-trusted store; forward secrecy
  applies to *read access via the policy path*, not to a store operator
  who has captured full DB dumps across rotation.
- **Authorization is external.** `revoke_record_access` will happily
  rotate any record for any caller who holds `old_dek` and the signing
  key. Without P3-12 wired in, an attacker who compromises a clinician's
  key can revoke on their behalf. P3-12 closes that.
- **Audit chain wiring is deferred.** The `audit_payload` dict is
  returned but not written; end-to-end wiring to `audit.chain.append_entry`
  is Phase 4 (P4-2).

**Enables:**

- P3-9 (re-key search index on rotation) can consume `RevocationResult`
  to rotate index tokens.
- P4-10 patient portal's "revoke" button has a real backend.

## Alternatives considered

- **Soft revocation (status flag only, no DEK rotation).** Rejected —
  defeats the paper's central novelty claim; a clinician with a cached
  DEK still reads every future version.
- **Re-wrap the same DEK under a new policy without regenerating the
  DEK.** Rejected — a cached DEK still decrypts every past *and future*
  ciphertext because the ciphertext itself is unchanged. Rotation must
  reach the DEK, not just its wrapping.
- **Change the record_id on rotation.** Rejected — breaks external
  references (audit correlation IDs, patient's record list, portal
  bookmarks). Identity is preserved; only the keys change.
- **Reason code required.** Rejected for now — `GRANTED → REVOKED`
  differs from `* → EMERGENCY_OPEN`; the state machine already does not
  require a reason here, and the audit metadata captures the caller-side
  context via `correlation_id`. Callers may still pass one for clarity.
