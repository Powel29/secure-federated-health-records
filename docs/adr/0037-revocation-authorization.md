# ADR-0037: Revocation authorization check: only patient owner or home authority may revoke access

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-09-03
- **Deciders:** Avaneeth → all four
- **Task / source:** P3-12 (`WORKFLOW.md`)
- **Affects:** `records` (`revocation.py`, `exceptions.py`), the threat model,
  and the paper's access control claims.

## Context

ADR-0036 (P3-7) introduced the cryptographic mechanism for revocation by
key-rotation: minting a fresh DEK, re-encrypting the ciphertext, incrementing the
generation counter, re-wrapping under a fresh root secret, and producing a
signed `TransitionEvent`. However, ADR-0036 deliberately left authorization
external:

> "The function does not enforce who-may-revoke — that authorization check is
> P3-12's job. Without P3-12 wired in, an attacker who compromises a clinician's
> key can revoke on their behalf. P3-12 closes that."

In a federated EHR architecture, cryptographic signature validity alone is
necessary but not sufficient: an unauthorized entity (e.g. a clinician, a
foreign attribute authority, or another patient) could present a syntactically
valid, correctly-signed request with their own valid ECDSA key pair. If the system
simply checked "is the signature cryptographically valid," an attacker could
trigger denial of service or unauthorized state changes by rotating keys on
records they do not own.

ARCHITECTURE.md §5 explicitly bounds who can initiate revocation:
1. The **record owner** (`patient_id`), exercising self-determination over their
   own health records.
2. The patient's **home authority** (`owner_authority_id`, ADR-0019), which
   holds custody over the `owner:*` attribute namespace and acts on behalf of
   administrative or legal mandate.

## Decision

1. Expose `check_revocation_authorization(*, actor_id: str, record: Record, owner_authority_id: str) -> None`:
   - Checks whether `actor_id == record.patient_id` or `actor_id == owner_authority_id`.
   - If `actor_id` is neither, immediately raises
     `records.exceptions.UnauthorizedRevocationError`.
2. Enforce this check directly inside `records.revocation.revoke_record_access`:
   - Enforced as Step 0 before payload decryption, key generation, or policy
     re-compilation.
   - Any invocation by an actor other than the patient or their home authority
     fails closed before any key rotation or state transition occurs.

## Consequences

**Guarantees (backed by negative security tests):**

- An unauthorized clinician presenting a cryptographically valid ECDSA signature
  is refused with `UnauthorizedRevocationError` and no keys rotate.
- A foreign authority (such as `authority-med`, which issues `role:*` attributes
  rather than owning the patient's identity) is refused with
  `UnauthorizedRevocationError`.
- Another patient attempting to revoke access to a different patient's record is
  refused with `UnauthorizedRevocationError`.
- The patient owner (`record.patient_id`) and the home authority
  (`owner_authority_id`) are authorized to initiate revocation.

**Honest limitations:**

- **Identity mapping is string-based.** `actor_id` matches `record.patient_id` or
  `owner_authority_id`. In Phase 4 (P4-1, P4-2), the calling service layer is
  responsible for authenticating the presenter (e.g. via TLS client certs or
  signed `RequestEnvelope`s) to ensure the presenting actor is legitimately
  bound to `actor_id`.

## Alternatives considered

- **Enforce only at the API layer (P4-1) and leave `revoke_record_access` open.**
  Rejected — leaving `revoke_record_access` open without an authorization check
  creates an internal footgun where any future internal caller could bypass
  who-can-revoke rules. Placing the guard at the entry point of
  `revoke_record_access` while also exposing `check_revocation_authorization`
  provides defence-in-depth.
- **Allow attending clinicians to revoke access.** Rejected — clinicians may
  relinquish or request access, but permanent revocation by key rotation on a
  record's lifecycle belongs solely to the patient or their home authority.

