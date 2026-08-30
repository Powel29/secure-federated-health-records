# ADR-0028: Credential Lifecycle and Revocation Registry

- **Status:** Proposed
- **Date:** 2026-08-30
- **Deciders:** Avaneeth (author), Ojas, Powel → all four for ratification
- **Task / source:** P2-6 (WORKFLOW.md); ARCHITECTURE §8 "Credential lifecycle"
- **Affects:** `src/authority/revocation.py`, `src/authority/issuance.py`, `src/authority/exceptions.py`, `src/authority/__init__.py`, `tests/authority/test_lifecycle.py`, `tests/security/test_phase2_lifecycle.py`

## Context

`ARCHITECTURE.md` §8 states:
"Clinician and authority credentials carry issuer, subject, serial, `valid_from`, `valid_until`, and status. Expired or revoked credentials fail validation. A system whose central claim is that revocation is part of a unified key lifecycle cannot coherently issue credentials that never expire."

`AttributeCredential` (`src/contracts/credentials.py`) already defines the canonical data structure with `serial`, `valid_from`, `valid_until`, and `status`. However, `AttributeCredential` artifacts are cryptographically signed at issuance time with `status = ACTIVE`. Once signed and handed to a subject, the static signature guarantees that the subject, validity window, and initial status have not been tampered with, but it cannot reflect subsequent revocation decisions made by the issuing authority without an authoritative lookup.

P2-6 requires implementing the live credential lifecycle:
1. Validating time windows (`valid_from` <= `now` <= `valid_until`), failing closed if not yet valid or expired.
2. Providing a dynamic revocation registry where an authority can record revocation of issued credentials by serial number (with timestamp and reason).
3. Enforcing that dynamic revocation immediately rejects verification and prevents release of attribute key material at the authority layer.

## Decision

1. **`RevocationRegistry`**:
   - Implemented in `src/authority/revocation.py`.
   - Stores `RevocationEntry(serial, issuer_id, revoked_at, reason)`.
   - Scoped by `(serial, issuer_id)`: An authority only has the authority to revoke credentials within its own namespace/issuer domain.
   - Provides thread-safe / deterministic query methods: `revoke`, `is_revoked`, `get_entry`, `all_revoked`.

2. **Authority Integration**:
   - Each `AttributeAuthority` instance owns its own `RevocationRegistry` instance (`self.revocation_registry`).
   - `AttributeAuthority.revoke_credential(serial, reason, revoked_at)` allows an authority to revoke an active credential it previously issued.
   - `AttributeAuthority.get_credential_status(credential, at)` computes the effective lifecycle state:
     - `REVOKED` if recorded in the authority's revocation registry or if `credential.status == CredentialStatus.REVOKED`.
     - `EXPIRED` if `at > credential.valid_until`.
     - `ACTIVE` if `credential.valid_from <= at <= credential.valid_until` and not revoked.
   - `AttributeAuthority.get_attribute_key(credential, at)` calls `verify_credential` with `self.revocation_registry`. If the presented credential has expired, is not yet valid, or is revoked, it fails closed, raising `CredentialRevokedError` / `CredentialExpiredError` / `CredentialNotYetValidError` and releasing no attribute key material.

3. **Verification**:
   - `verify_credential(credential, issuer_public_key, at=None, revocation_registry=None)` verifies ECDSA signature first, then checks dynamic revocation against `revocation_registry`, static status, and the temporal validity window.

## Consequences

**What this makes work:**
- Dynamic revocation is enforced without requiring re-issuance or key-pair rotation for every unrelated credential.
- Any attempt by a clinician or patient with a revoked or expired credential to unlock policy leaves fails closed at both the PDP and PEP layers.
- Maps directly to the required security negative test: "an expired or revoked credential fails validation."

**Honesty caveats / Trade-offs:**
- In-memory authority registries simulate local authority state in development and integration tests. When authority services run over HTTP (Phase 4), this registry is backed by the authority process state or DB.
- Like CRLs/OCSP in standard PKI, revocation requires checking against the issuing authority or its registry; an offline verifier that does not consult the authority's registry can only detect expiry and static status.

## Alternatives considered

- **Short validity windows only (no revocation list):** Issuing short-lived tokens (e.g. 5 minutes) without revocation. Rejected: ARCHITECTURE §8 explicitly mandates revocation support for credential lifecycle, not just passive expiry.
- **Global shared database table for revocations:** Putting revocations directly in the shared record store. Rejected: Attribute authorities are federated and independent; each authority maintains custody of its own revocation records (matching C6 component boundaries).

