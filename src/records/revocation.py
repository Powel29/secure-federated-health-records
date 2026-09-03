"""Revocation by key-rotation (P3-7).

Revocation in this system is not a database flag; it is a **cryptographic
key-rotation event**. When a patient (or their home authority) revokes a
clinician's access, the record's DEK is rotated to a fresh 256-bit key, the
payload is re-encrypted, and the new DEK is sealed under a freshly compiled
policy tree that no longer includes the revoked party. A signed
``GRANTED -> REVOKED`` :class:`~contracts.TransitionEvent` closes the loop
so tampering is caught by :class:`~lifecycle.state_machine.LifecycleStateMachine`.

The point is **forward secrecy**: after ``revoke_record_access`` returns, a
clinician who cached the OLD DEK or holds only the OLD attribute keys can
no longer decrypt the record's now-rotated ciphertext. This property is what
the P3-7 negative security tests actually prove
(``tests/security/test_phase3_revocation_security.py``); ADR-0036 records
the design.

Not fixed by this rotation: plaintext the clinician had already decrypted
and taken elsewhere before revocation. That is stated as a limitation in
``PROJECT.md`` §5.

Design (same as ``records.ingest``, ADR-0016): the function returns a
self-contained :class:`RevocationResult` and the caller persists it +
audit-logs. No storage handle, no audit connection — this module is
purely-testable without Postgres or a running audit service.

The ``owner:<patient_id>`` attribute leaf (ADR-0016) is always re-added to
the new policy so the patient can always read their own record; the caller
supplies only the *clinical* branch of the policy in ``new_clinical_policy``.
"""

from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from contracts import TransitionEvent
from contracts.enums import LifecycleState, ReasonCode
from contracts.policy import PolicyTree
from contracts.records import DEKWrapping, Record
from crypto_core.symmetric import generate_key
from cryptography.hazmat.primitives.asymmetric import ec
from lifecycle.state_machine import create_transition_event

from records.exceptions import UnauthorizedRevocationError
from records.service import decrypt_record, encrypt_record, wrap_dek

AttributeKeyring = Mapping[tuple[str, str, str], bytes]


@dataclass(frozen=True)
class RevocationResult:
    """All artefacts produced by one revocation-by-key-rotation.

    The caller persists these to storage and emits an audit entry. The old
    DEK, old wrapping, and old policy compilation are the caller's to
    replace / retire; this result carries only the *new* versions.

    Attributes:
        record_id: The record whose access was revoked (unchanged; identity
            is preserved across key rotation, only the keys change).
        rotated_record: The re-encrypted :class:`~contracts.Record` — same
            ``record_id``, fresh ``ciphertext`` and ``nonce`` under a fresh
            DEK. The ``policy_id`` is new to reflect the rotated tree.
        rotated_wrapping: The new :class:`~contracts.records.DEKWrapping`
            with ``generation = old_generation + 1``, sealing the fresh
            DEK under the fresh root secret.
        compiled_policy: The compiled Shamir layout of the new policy tree
            (``policy.engine.CompiledPolicy``). Persist alongside
            ``rotated_wrapping``.
        policy_tree: The authored policy tree (with the ADR-0016 owner leaf
            OR-ed over the clinical branch).
        new_root_secret: The fresh 32-byte wrapping key. The caller **must
            not persist this** — it is returned only so tests can prove
            round-trip decryption from the compiled policy.
        transition_event: The signed ``GRANTED -> REVOKED``
            :class:`~contracts.TransitionEvent`. Apply it through
            :meth:`~lifecycle.state_machine.LifecycleStateMachine.apply_transition`
            to advance the record's state.
        audit_payload: Metadata dict ready for C10 audit logging — identifiers
            and generation counters only, never key material
            (CONVENTIONS.md §2 rule 3).
    """

    record_id: str
    rotated_record: Record
    rotated_wrapping: DEKWrapping
    compiled_policy: Any  # policy.engine.CompiledPolicy — Any avoids circular typing
    policy_tree: PolicyTree
    new_root_secret: bytes
    transition_event: TransitionEvent
    audit_payload: dict[str, Any]


def check_revocation_authorization(
    *,
    actor_id: str,
    record: Record,
    owner_authority_id: str,
) -> None:
    """Verify that ``actor_id`` is authorized to revoke access to ``record`` (P3-12).

    Only the record's owner (the patient, ``record.patient_id``) or the
    patient's home authority (``owner_authority_id``) is authorized to
    revoke access. Any other party (clinicians, hospitals, foreign authorities,
    or other patients) is rejected, even if they hold a valid cryptographic key
    and signature.

    Args:
        actor_id: The identifier of the party attempting revocation.
        record: The :class:`~contracts.Record` being revoked.
        owner_authority_id: The identifier of the patient's home authority
            (ADR-0019; owns the ``owner`` attribute namespace).

    Raises:
        UnauthorizedRevocationError: ``actor_id`` is neither the record's
            patient nor its home authority.
    """
    if actor_id not in ( record.patient_id, owner_authority_id):

        raise UnauthorizedRevocationError(
            f"actor '{actor_id}' is not authorized to revoke record "
            f"'{record.record_id}'; only patient '{record.patient_id}' or home "
            f"authority '{owner_authority_id}' may revoke"
        )


def revoke_record_access(
    *,
    current_record: Record,
    current_wrapping: DEKWrapping,
    old_dek: bytes,
    new_clinical_policy: PolicyTree,
    owner_authority_id: str,
    attribute_keyring: AttributeKeyring,
    actor_id: str,
    actor_signing_key: ec.EllipticCurvePrivateKey,
    correlation_id: str,
    reason_code: ReasonCode | None = None,
    new_policy_id: str | None = None,
    now: datetime.datetime | None = None,
) -> RevocationResult:
    """Rotate a record's DEK to revoke a clinician's access (P3-7).

    Executes the atomic revocation flow:

    1. Decrypt the current payload with ``old_dek``.
    2. Author a fresh policy tree = ``OR(new_clinical_policy, owner:<patient_id>)``
       via :func:`policy.engine.author_policy_with_owner` (ADR-0016).
    3. Mint a fresh 32-byte root secret and compile the tree against
       ``attribute_keyring`` via :func:`policy.engine.compile_policy`.
    4. Mint a fresh 32-byte DEK and re-encrypt the plaintext via
       :func:`records.service.encrypt_record` (same ``record_id`` — identity
       is preserved across rotation).
    5. Wrap the fresh DEK under the fresh root secret via
       :func:`records.service.wrap_dek` with
       ``generation = current_wrapping.generation + 1``.
    6. Emit a signed ``GRANTED -> REVOKED`` :class:`~contracts.TransitionEvent`
       via :func:`lifecycle.state_machine.create_transition_event`.
    7. Return a :class:`RevocationResult` carrying every artefact.

    Args:
        current_record: The pre-revocation :class:`~contracts.Record`.
        current_wrapping: The pre-revocation :class:`~contracts.records.DEKWrapping`;
            only its ``generation`` counter is read.
        old_dek: The 32-byte DEK that decrypts ``current_record``. The caller
            must have already obtained this via a policy-satisfying
            reconstruct + unwrap; this function does not perform the
            authorization check that entitled the caller to hold it.
        new_clinical_policy: The clinical branch of the new access policy.
            The ADR-0016 ``owner:<patient_id>`` leaf is added automatically
            so the patient can always read their own record.
        owner_authority_id: The patient's home authority (ADR-0019); owns the
            ``owner`` attribute namespace.
        attribute_keyring: Compile-time keyring for every leaf in the new
            tree, including the owner leaf. Must be complete; missing keys
            raise ``policy.exceptions.PolicyCompileError``.
        actor_id: The party performing the revocation (the patient, or a
            service acting on their authority). Bound into the transition
            event's signature.
        actor_signing_key: The actor's ECDSA-P256 private key.
        correlation_id: Audit correlation identifier for the revocation flow.
        reason_code: Optional constrained-enum reason. ``None`` is accepted
            here because ``GRANTED -> REVOKED`` does not require one in the
            state machine (unlike ``* -> EMERGENCY_OPEN``); callers may
            still pass one for audit clarity.
        new_policy_id: Optional explicit policy ID for the rotated tree.
            Auto-generated if omitted; the new ID reflects that the tree
            changed even though the record identity did not.
        now: Optional timestamp (defaults to current UTC).

    Returns:
        A :class:`RevocationResult` with the rotated record, the new
        wrapping, the compiled policy, the signed transition event, and an
        audit payload dict.

    Raises:
        UnauthorizedRevocationError: ``actor_id`` is neither the record's
            patient nor its home authority (P3-12).
        DecryptionError: ``old_dek`` does not decrypt ``current_record`` —
            wrong key or tampered ciphertext.
        PolicyCompileError: ``attribute_keyring`` is incomplete for
            ``new_clinical_policy`` or the owner leaf.
        IllegalTransitionError / MissingReasonCodeError: The state machine
            refuses the emitted event (should not happen — the pair
            ``(GRANTED, REVOKED)`` is legal and no reason is required —
            but included for defence-in-depth).

    Security properties:
        - Fresh DEK per rotation (CONVENTIONS.md §2 rule 5); the new DEK is
          independent of the old, so a captured old DEK cannot decrypt the
          new ciphertext.
        - Fresh root secret per rotation; the new wrapping fails
          authentication against the old root secret.
        - ``generation`` counter increments so a stale wrapping is
          distinguishable from the current one at the storage boundary.
        - Owner leaf preserved (ADR-0016): the patient's access survives
          rotation by construction, not by policy discipline.
        - Revocation authorization enforced (P3-12): only the patient or
          home authority can trigger key rotation.
    """
    # Lazy imports match records.ingest.py — policy.engine imports records
    # (for unwrap_dek in unwrap_dek_via_policy), so importing at module
    # scope from inside records/ creates a circular chain.
    from policy.engine import author_policy_with_owner, compile_policy

    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    if new_policy_id is None:
        new_policy_id = f"pol-{uuid.uuid4()}"

    patient_id = current_record.patient_id
    old_generation = current_wrapping.generation

    # --- Step 0: Check who's allowed to revoke (P3-12) ---
    check_revocation_authorization(
        actor_id=actor_id,
        record=current_record,
        owner_authority_id=owner_authority_id,
    )

    # --- Step 1: Recover the plaintext under the old DEK ---
    plaintext = decrypt_record(current_record, old_dek)

    # --- Step 2: Author the new tree with the owner leaf (ADR-0016) ---
    new_tree = author_policy_with_owner(
        clinical_policy=new_clinical_policy,
        patient_id=patient_id,
        owner_authority_id=owner_authority_id,
    )

    # --- Step 3: Fresh root secret + compile ---
    new_root_secret = generate_key(32)
    compiled = compile_policy(
        tree=new_tree,
        root_secret=new_root_secret,
        attribute_keyring=attribute_keyring,
    )

    # --- Step 4: Fresh DEK + re-encrypt (same record_id — identity preserved) ---
    rotated_record, new_dek = encrypt_record(
        plaintext=plaintext,
        patient_id=patient_id,
        facility_id=current_record.facility_id,
        policy_id=new_policy_id,
        content_type=current_record.content_type,
        aad=current_record.aad,
        record_id=current_record.record_id,
        created_at=now,
    )

    # --- Step 5: Wrap the new DEK under the new root secret, generation++ ---
    rotated_wrapping = wrap_dek(
        dek=new_dek,
        record_id=current_record.record_id,
        wrapping_key=new_root_secret,
        wrapped_for=new_policy_id,
        generation=old_generation + 1,
        created_at=now,
    )

    # --- Step 6: Signed GRANTED -> REVOKED transition event ---
    transition_event = create_transition_event(
        record_id=current_record.record_id,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id=actor_id,
        signing_key=actor_signing_key,
        reason_code=reason_code,
        issued_at=now,
    )

    # --- Step 7: Audit metadata — identifiers and counters only ---
    audit_payload: dict[str, Any] = {
        "event": "record.revoked",
        "record_id": current_record.record_id,
        "actor_id": actor_id,
        "correlation_id": correlation_id,
        "old_generation": old_generation,
        "new_generation": old_generation + 1,
        "old_policy_id": current_record.policy_id,
        "new_policy_id": new_policy_id,
        "reason_code": reason_code.value if reason_code is not None else None,
        "issued_at": now.isoformat(),
    }

    return RevocationResult(
        record_id=current_record.record_id,
        rotated_record=rotated_record,
        rotated_wrapping=rotated_wrapping,
        compiled_policy=compiled,
        policy_tree=new_tree,
        new_root_secret=new_root_secret,
        transition_event=transition_event,
        audit_payload=audit_payload,
    )
