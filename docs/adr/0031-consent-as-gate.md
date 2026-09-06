# ADR-0031: Patient consent is a read-time gate, not a wrap-time re-policy

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-08-31
- **Deciders:** Powel (P3-2 owner) → all four for ratification
- **Task / source:** P3-2 (WORKFLOW.md); ADR-0014 (consent model); ADR-0016
  (owner-attribute self-access); ARCHITECTURE §2 C7 / §5
- **Affects:** `src/consent/service.py`, `src/consent/exceptions.py`,
  `src/contracts/consent.py` (frozen; used as-is), `tests/consent/`,
  `tests/security/test_phase3_consent_security.py`

## Context

`WORKFLOW.md` P3-2 says: *"The grant then wraps the record's key to a policy so
the approved doctor can read it."* This reads two ways at first glance:

- **(A) Consent as wrap-time re-policy.** On grant, re-compile the record's
  policy tree to include the specific grantee (or role, or facility), then
  re-wrap the DEK under the new tree.
- **(B) Consent as a read-time gate.** The record is already wrapped at ingest
  (P3-14) under `OR(clinical_policy, owner:<patient_id>)`. Consent adds a
  signed patient-intent check that a caller runs *before* invoking the crypto
  path.

`contracts/consent.py` resolves the ambiguity in favour of (B). Its docstring
says: *"consent records the patient's signed intent; it never decides
decryption. Keys and the Shamir threshold gate decide access. A ``GRANTED``
consent tells the policy layer the patient approved a scope; the policy layer,
not this record, is what releases anything."* The `ConsentGrant` fields
(`scope`, `expires_at`, `grantee_id`, `status`) are exactly the shape of a
gate, not the inputs to a re-wrap.

Two adjacent tasks would also break under (A):

- **P3-14 (Avaneeth) — ingest** owns the initial DEK wrap and the
  `author_policy_with_owner` step.
- **P3-7 (Avaneeth) — revocation by key-rotation** owns re-wrap-on-revoke.

Interpretation (A) puts P3-2 into both of those spaces at once.

## Decision

Consent is a **read-time predicate**. The consent module offers:

1. `create_consent_request` / `verify_consent_request` — the requester-signed
   ask;
2. `create_consent_grant` / `verify_consent_grant` — the patient-signed
   decision;
3. `revoke_consent_grant` — a fresh patient-signed `ConsentGrant` with
   `status=REVOKED` (grants are immutable signed artifacts; a mutation would
   break the signature);
4. `authorize_read(grant, record_id, grantee_id, patient_public_key, at)` —
   the gate: verify signature, `status is GRANTED`, in the time window,
   `grantee_id` matches, `record_id in scope`. Fail-closed at the first
   failure with a specific `ConsentError` subclass;
5. `read_record_under_consent(...)` — a thin composition of `authorize_read`
   → `policy.unwrap_dek_via_policy` → `crypto_core.aes_gcm_decrypt`, proving
   the single-decryption-path claim (ADR-0016) is honoured.

The consent module **does not** call `records.wrap_dek`, `records.rewrap_dek`,
or `policy.compile_policy`. Those live with ingest and revocation, respectively.

Two behavioural constraints fall out of this shape:

- **Grant scope cannot widen a request.** `create_consent_grant` refuses a
  `scope` that contains records not in `request.scope`, raising
  `ConsentScopeError`. It can be narrowed.
- **Signature failures use `crypto_core.InvalidSignatureError`, not a
  consent-specific alias.** Every signed artifact in the project raises the
  same exception type on tampering; keeping the taxonomy uniform means a
  caller's `except InvalidSignatureError` catches consent, credential,
  transition-event, and PRE-key failures without knowing which module ran.

## Consequences

**What this makes work.** The four P3-2 exit criteria map to
`tests/security/test_phase3_consent_security.py` cases 1-to-1:

| Exit criterion | Test |
|---|---|
| patient-issued grant is signed and scoped | `test_sec_approved_doctor_reads_within_scope` (positive control) |
| approved doctor reads within scope | same |
| unauthorized doctor cannot read | `test_sec_unauthorized_doctor_cannot_read`, `test_sec_grant_cannot_be_replayed_against_a_different_grantee` |
| only the patient can revoke, and post-revocation decryption fails | `test_sec_unauthorized_party_cannot_revoke_consent`, `test_sec_revoked_consent_grant_denies_access` |

Plus the extras: `expired grant → denies`, `denied grant → denies`,
`forged grant signature → denies`, `out-of-scope read → denies`.

**What this makes hard.** A patient cannot use consent to *add* a clinician
whose credentials don't already satisfy the record's clinical policy. In
practice this is fine: the clinical policy is authored broadly at ingest
(e.g. `role:physician OR role:specialist`), so most credentialed clinicians
already crypto-satisfy it; consent is what turns "can decrypt" into "may
decrypt today for this episode."

If we ever need the (A) semantics (patient adds a specific clinician who
doesn't satisfy the clinical branch), that is a separate mechanism: a
patient-signed *policy amendment* that re-compiles the tree and re-wraps.
That would need its own ADR, its own module, and coordination with P3-7 to
avoid stepping on the rekey path. Deferring it explicitly.

**Honesty caveats.**

- Consent enforcement lives in the CALLER, not in the crypto path. A caller
  who forgets to invoke `authorize_read` before `unwrap_dek_via_policy` still
  gets the plaintext (the crypto succeeds). This is why
  `read_record_under_consent` exists as the composed helper: the paper's
  claim is "the *documented* read path enforces consent," and the tests
  cover that path. Portal integration in P4-10 / P4-11 must route through
  the composed helper, not around it.
- Grant `grant_id` uniqueness is not enforced by this module. `ConsentGrant`
  is a value object; whoever persists grants (the audit chain in P3-3, or a
  future consent-registry table) is responsible for rejecting duplicate
  `grant_id` insertions. The consent module treats each verified grant as
  independent.

## Alternatives considered

- **Consent as wrap-time re-policy (interpretation A).** Rejected: overlaps
  with P3-14 (ingest) and P3-7 (revocation-rekey); contradicts ADR-0014's
  frozen invariant that consent records *intent* and does not *decide*
  decryption; would force a full re-compile + re-wrap on every grant, which
  is expensive and pointless if the clinical policy already covers the
  clinician. See "What this makes hard" for when we'd revisit.
- **`UnauthorizedRevocationError` distinct from signature failure.**
  Rejected: an attacker-signed "revocation" fails signature verification
  against the patient's public key, which is already
  `InvalidSignatureError`. A new alias adds nothing except an extra type
  callers must remember to catch.
- **Consent module lives inside `src/policy/consent.py`.** The
  `contracts/consent.py` docstring names "policy/lifecycle grant path" as the
  logical owner. Splitting into its own top-level `src/consent/` keeps the
  gate's public surface (request, grant, revoke, authorize, read) visible
  from one directory and mirrors how `src/authority/`, `src/lifecycle/`, and
  `src/policy/` each own one concept. If in a later phase consent grows
  storage/HTTP surfaces, the module boundary is already right.
