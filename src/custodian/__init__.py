"""Client-side key-agent operations of the Key Custodian (ADR-0043, review F33).

The custodian stands in for every persona's own device: it splits a new
record's emergency key, signs a clinician's emergency assertion, and opens
what the facility delivers back. Those are cryptographic steps, so they live
here; ``api.custodian_service`` only routes requests and calls these
(CONVENTIONS.md §2 rule 10: no cryptography in ``api/``).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from authority.issuance import KEY_RELEASE_OPERATION, credential_binding
from breakglass import create_emergency_assertion
from breakglass.emergency_key import Share, generate_emergency_key, split_emergency_key
from breakglass.envelopes import create_request_envelope
from contracts import (
    AttributeCredential,
    EmergencyAssertion,
    Record,
    RequestEnvelope,
    TransitionEvent,
)
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import sha256_digest
from crypto_core.types import ECPrivateKey
from lifecycle.state_machine import create_transition_event
from pre import open_delivery_package
from records.service import decrypt_record


@dataclass(frozen=True)
class EmergencyProvision:
    """A new record's 2-of-3 emergency key and the two shares that are held.

    Share 1 stays in clinician custody here, share 3 goes to the audit
    service; share 2 (home authority) is not deposited (review F3, D2).
    """

    key: bytes = field(repr=False)
    clinician_share: Share = field(repr=False)
    audit_share: Share = field(repr=False)


def provision_emergency_key() -> EmergencyProvision:
    """Generate and split the emergency key for a record being uploaded."""
    key = generate_emergency_key()
    clinician_share, _home_share, audit_share = split_emergency_key(key)
    return EmergencyProvision(key, clinician_share, audit_share)


@dataclass(frozen=True)
class UnlockRequestMaterial:
    """What a clinician's side signs and presents for one break-glass unlock."""

    assertion: EmergencyAssertion


def prepare_unlock(
    *,
    signing_key: ECPrivateKey,
    patient_id: str,
    clinician_id: str,
    facility_id: str,
    reason_code: ReasonCode,
    assertion_ttl: datetime.timedelta,
    context_digest: str = "",
) -> UnlockRequestMaterial:
    """Sign the clinician's emergency assertion."""
    assertion = create_emergency_assertion(
        patient_id=patient_id,
        clinician_id=clinician_id,
        facility_id=facility_id,
        reason_code=reason_code,
        signing_key=signing_key,
        ttl=assertion_ttl,
        clinical_context_digest=context_digest,
    )
    return UnlockRequestMaterial(assertion=assertion)


def sign_emergency_transition(
    *,
    signing_key: ECPrivateKey,
    record_id: str,
    from_state: LifecycleState,
    clinician_id: str,
    reason_code: ReasonCode,
) -> TransitionEvent:
    """Sign the record's ``from_state -> EMERGENCY_OPEN`` as the clinician (D8-a).

    Signed here, with the clinician's own key, so the key never leaves the
    custodian (ADR-0043) and the event is attributable to the clinician who
    opened the record (ADR-0068). The facility verifies it against the
    clinician's certificate.

    Raises:
        IllegalTransitionError / MissingReasonCodeError: ``from_state`` cannot
            reach ``EMERGENCY_OPEN``.
    """
    return create_transition_event(
        record_id=record_id,
        from_state=from_state,
        to_state=LifecycleState.EMERGENCY_OPEN,
        actor_id=clinician_id,
        signing_key=signing_key,
        reason_code=reason_code,
    )


def sign_revocation_transition(
    *,
    signing_key: ECPrivateKey,
    record_id: str,
    from_state: LifecycleState,
    patient_id: str,
) -> TransitionEvent:
    """Sign the record's ``from_state -> REVOKED`` as its patient (ADR-0080).

    Signed here with the patient's own key, which never leaves the custodian
    (ADR-0043); the facility verifies it against the patient's certificate
    and re-keys the record itself, so no key or DEK crosses the wire.

    Raises:
        IllegalTransitionError: ``from_state`` cannot reach ``REVOKED``.
    """
    return create_transition_event(
        record_id=record_id,
        from_state=from_state,
        to_state=LifecycleState.REVOKED,
        actor_id=patient_id,
        signing_key=signing_key,
    )


def sign_key_release_possession(
    *, signing_key: ECPrivateKey, credential: AttributeCredential
) -> RequestEnvelope:
    """Prove the credential's subject asks for its attribute key (ADR-0082).

    A one-time envelope signed with the subject's own key, addressed to the
    issuing authority, for ``attribute_key.release``, over the credential's
    canonical bytes. A copied credential alone -- public signed data -- no
    longer releases a key (review F15). The existing ``RequestEnvelope``
    construction; nothing new.
    """
    return create_request_envelope(
        caller_id=credential.subject_id,
        recipient_id=credential.issuer_id,
        operation=KEY_RELEASE_OPERATION,
        body=credential_binding(credential),
        signing_key=signing_key,
    )


def open_delivered_dek(
    rewrapped_dek: bytes, *, pre_private_key: int, record_id: str
) -> bytes:
    """Open the facility's PRE delivery package with the clinician's key.

    Raises:
        PREError / InvalidTagError / ValueError: The package does not open.
    """
    return open_delivery_package(
        rewrapped_dek, pre_private_key=pre_private_key, record_id=record_id
    )


def decrypt_delivered_record(record: Record, dek: bytes) -> bytes:
    """Decrypt the stored ciphertext with the delivered DEK.

    Raises:
        DecryptionError: The DEK does not open this record.
    """
    return decrypt_record(record, dek)


def justification_digest(text: str) -> str:
    """Commit UTF-8 justification text without publishing clinical free text."""
    return sha256_digest(text.strip().encode("utf-8")).hex()
