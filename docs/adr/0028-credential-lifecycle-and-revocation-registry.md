# ADR-0028: Credential Lifecycle and Revocation Registry

- **Status:** Proposed
- **Date:** 2026-08-30
- **Deciders:** Avaneeth (author), Ojas, Powel → all four for ratification
- **Task / source:** P2-6 (WORKFLOW.md); ARCHITECTURE §8 "Credential lifecycle"
- **Affects:** `src/authority/revocation.py`, `src/authority/issuance.py`, `src/authority/exceptions.py`, `src/authority/__init__.py`, `tests/authority/test_lifecycle.py`, `tests/security/test_phase2_lifecycle.py`

## Context

`ARCHITECTURE.md` §8 states:
"Clinician and authority credentials carry issuer, subject, serial, `valid_from`, `valid_until`, and status. Expired or revoked credentials fail validation. A system whose central claim is that revocation is part of a unified key lifecycle cannot coherently issue credentials that never expire."

`AttributeCredential` (`src/contracts/credentials.py`) defines the canonical data structure with `serial`, `valid_from`, `valid_until`, and `status`. At issuance time, credentials are cryptographically signed with `status = ACTIVE`. The static ECDSA signature protects the credential attributes, validity window, and initial status from tampering, but static verification cannot detect an authority's post-issuance revocation decision without an authoritative lookup.

P2-6 requires implementing the live credential lifecycle:
1. Validating time windows (`valid_from` <= `now` <= `valid_until`), failing closed if not yet valid or expired.
2. Providing a dynamic revocation registry where an authority records revocation of issued credentials by serial number (with timestamp and reason).
3. Enforcing that dynamic revocation immediately rejects verification and prevents release of attribute key material at the authority layer.

## Decision

1. **Per-Authority `RevocationRegistry`**:
   - Implemented in `src/authority/revocation.py`.
   - Each `AttributeAuthority` instance manages its own isolated `RevocationRegistry` instance (`self.revocation_registry`).
   - Internal storage is a dictionary keyed directly by `serial: str` (`dict[str, RevocationEntry]`), providing instant $O(1)$ revocation lookups (`serial in self._entries`) without multi-tenant key overhead or linear scans.
   - Stores `RevocationEntry(serial, issuer_id, revoked_at, reason)`.

2. **Authority Integration & Status Evaluation**:
   - `AttributeAuthority.revoke_credential(serial, reason, revoked_at)` records revocation in `self.revocation_registry`.
   - `AttributeAuthority.is_credential_revoked(serial)` performs an $O(1)$ lookup in `self.revocation_registry`.
   - `AttributeAuthority.get_credential_status(credential, at)` computes the dynamic lifecycle state:
     - `REVOKED` if recorded in the authority's revocation registry or if `credential.status == CredentialStatus.REVOKED`.
     - `EXPIRED` if `at > credential.valid_until`.
     - `ACTIVE` if within the validity window and not revoked.
   - `AttributeAuthority.get_attribute_key(credential, at)` calls `verify_credential` passing `self.revocation_registry`. If the presented credential has expired, is not yet valid, or is revoked, it fails closed, raising `CredentialRevokedError` / `CredentialExpiredError` / `CredentialNotYetValidError` and releasing no attribute key material.

3. **Fail-Closed Verification Order (`verify_credential`)**:
   - **Signature verification first:** Cryptographic ECDSA signature over the canonical payload is verified before inspecting dynamic or status fields, preventing unsigned/forged artifacts from probing revocation or expiry state.
   - **Static status check:** Fails closed if `credential.status != CredentialStatus.ACTIVE`.
   - **Dynamic revocation lookup:** Fails closed with `CredentialRevokedError` if `revocation_registry.is_revoked(credential.serial)` is true.
   - **Temporal window checks:** Fails closed with `CredentialNotYetValidError` if `at < credential.valid_from`, or `CredentialExpiredError` if `at > credential.valid_until`.

## Consequences

**What this makes work:**
- Dynamic revocation is enforced immediately without requiring key-pair rotation for unrelated credentials.
- Any attempt by a clinician or patient with a revoked or expired credential to unlock policy leaves fails closed at both the PDP and PEP layers.
- Satisfies the required negative security test: "an expired or revoked credential fails validation."

**Honesty caveats / Trade-offs:**
- In-memory authority registries simulate local authority state in development and integration tests. When authority services run over HTTP (Phase 4), this registry is backed by the authority process state or DB.
- Like CRLs/OCSP in standard PKI, revocation requires checking against the issuing authority or its registry; an offline verifier that does not consult the authority's registry can only detect expiry and static status.

## Alternatives considered

- **Composite `(serial, issuer_id)` keys with linear scan fallback:** Storing tuples `(serial, issuer_id)` inside the registry dict. Rejected: Because registries are instantiated per-authority, all entries share the same issuer; keying by `serial` alone provides clean $O(1)$ lookups without iterating through keys.
- **Short validity windows only (no revocation list):** Issuing short-lived tokens (e.g. 5 minutes) without revocation. Rejected: ARCHITECTURE §8 explicitly mandates revocation support for credential lifecycle, not just passive expiry.
- **Global shared database table for revocations:** Putting revocations directly in the shared record store. Rejected: Attribute authorities are federated and independent; each authority maintains custody of its own revocation records (matching C6 component boundaries).
