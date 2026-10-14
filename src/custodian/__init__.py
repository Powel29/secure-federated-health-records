"""Client-side key-agent operations of the Key Custodian (ADR-0043, review F33).

The custodian stands in for every persona's own device: it splits a new
record's emergency key, signs a clinician's emergency assertion, and opens
what the facility delivers back. Those are cryptographic steps, so they live
here; ``api.custodian_service`` only routes requests and calls these
(CONVENTIONS.md §2 rule 10: no cryptography in ``api/``).
"""

from __future__ import annotations

import base64
import datetime
from dataclasses import dataclass, field

from breakglass import create_emergency_assertion
from breakglass.emergency_key import Share, generate_emergency_key, split_emergency_key
from contracts import EmergencyAssertion, Record
from contracts.enums import ReasonCode
from crypto_core import generate_ec_keypair, generate_key, private_key_to_pem
from crypto_core.types import ECPrivateKey
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
    # A throwaway key signs the transition so the clinician's own key never
    # leaves the custodian (ADR-0043); D8 decides who should sign it instead.
    transition_signing_key_pem: str = field(repr=False)
    # Not a key to anything: the facility's timer needs a value to register
    # the time-box (ADR-0043 re-baseline gap, review F9).
    baseline_wrapping_key_b64: str = field(repr=False)


def prepare_unlock(
    *,
    signing_key: ECPrivateKey,
    patient_id: str,
    clinician_id: str,
    facility_id: str,
    reason_code: ReasonCode,
    assertion_ttl: datetime.timedelta,
) -> UnlockRequestMaterial:
    """Sign the emergency assertion and mint the per-unlock throwaway values."""
    assertion = create_emergency_assertion(
        patient_id=patient_id,
        clinician_id=clinician_id,
        facility_id=facility_id,
        reason_code=reason_code,
        signing_key=signing_key,
        ttl=assertion_ttl,
    )
    transition_key, _ = generate_ec_keypair()
    return UnlockRequestMaterial(
        assertion=assertion,
        transition_signing_key_pem=private_key_to_pem(transition_key).decode("ascii"),
        baseline_wrapping_key_b64=base64.b64encode(generate_key()).decode("ascii"),
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
