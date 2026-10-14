"""Record encryption and DEK lifecycle management (owner module: ``records``, C8).

Implements envelope encryption: one DEK per record (AES-256-GCM), with the DEK
sealed under an authorized wrapping key (e.g. policy root key or emergency key).
"""

from __future__ import annotations

import datetime
import uuid

from contracts.clinical import ClinicalMetadata
from contracts.records import DEKWrapping, Record
from crypto_core.exceptions import InvalidTagError
from crypto_core.symmetric import aes_gcm_decrypt, aes_gcm_encrypt, generate_key

from records.exceptions import DecryptionError, UnwrappingError


def encrypt_record(
    plaintext: bytes,
    patient_id: str,
    facility_id: str,
    policy_id: str,
    content_type: str = "application/json",
    aad: bytes | None = None,
    record_id: str | None = None,
    created_at: datetime.datetime | None = None,
    clinical: ClinicalMetadata | None = None,
) -> tuple[Record, bytes]:
    """Encrypt a health record and generate a fresh DEK.

    Args:
        plaintext: The raw record content bytes.
        patient_id: The patient identifier.
        facility_id: The facility identifier that created/owns the record.
        policy_id: The access policy identifier governing this record.
        content_type: MIME type of the plaintext (default: 'application/json').
        aad: Optional associated authenticated data.
        record_id: Optional record ID (generated if not provided).
        created_at: Optional timestamp (defaults to current UTC time).

    Returns:
        A tuple of ``(Record_contract, raw_dek_bytes)``.

    Security property:
        Envelope encryption: each record receives a fresh, independent 256-bit DEK
        (CONVENTIONS.md §2 rule 5).
    """
    if record_id is None:
        record_id = f"rec-{uuid.uuid4()}"
    if created_at is None:
        created_at = datetime.datetime.now(datetime.timezone.utc)

    # 1. Mint fresh 256-bit DEK
    dek = generate_key(32)

    # 2. Encrypt record payload under the DEK
    ciphertext, nonce = aes_gcm_encrypt(key=dek, plaintext=plaintext, aad=aad)

    # 3. Construct Record contract
    record = Record(
        record_id=record_id,
        patient_id=patient_id,
        facility_id=facility_id,
        policy_id=policy_id,
        content_type=content_type,
        ciphertext=ciphertext,
        nonce=nonce,
        aad=aad,
        created_at=created_at,
        clinical=clinical or ClinicalMetadata(),
    )

    return record, dek


def decrypt_record(record: Record, dek: bytes) -> bytes:
    """Decrypt a record using its verified DEK.

    Args:
        record: The encrypted Record contract.
        dek: The 32-byte data encryption key.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        DecryptionError: If decryption or tag verification fails.

    Security property:
        Fails closed on any corruption or wrong key (CONVENTIONS.md §2 rule 6).
    """
    try:
        return aes_gcm_decrypt(
            key=dek,
            nonce=record.nonce,
            ciphertext=record.ciphertext,
            aad=record.aad,
        )
    except InvalidTagError as exc:
        raise DecryptionError(
            f"Failed to decrypt record {record.record_id}: invalid tag or incorrect DEK"
        ) from exc


def wrap_dek(
    dek: bytes,
    record_id: str,
    wrapping_key: bytes,
    wrapped_for: str,
    generation: int = 0,
    wrapping_id: str | None = None,
    created_at: datetime.datetime | None = None,
) -> DEKWrapping:
    """Wrap a DEK under an authorized wrapping key.

    Args:
        dek: The 32-byte DEK to seal.
        record_id: Identifier of the record this DEK belongs to.
        wrapping_key: The 32-byte key used to wrap the DEK.
        wrapped_for: Policy ID or party ID authorized to unwrap.
        generation: Rotation counter (default: 0).
        wrapping_id: Optional wrapping identifier.
        created_at: Optional timestamp (defaults to current UTC time).

    Returns:
        A DEKWrapping contract instance.

    Security property:
        Binds the record_id as AAD so wrapped DEKs cannot be substituted across records.
    """
    if wrapping_id is None:
        wrapping_id = f"wrap-{uuid.uuid4()}"
    if created_at is None:
        created_at = datetime.datetime.now(datetime.timezone.utc)

    # Bind record_id as AAD to prevent cross-record wrapping replay
    aad = record_id.encode("utf-8")
    wrapped_dek, nonce = aes_gcm_encrypt(key=wrapping_key, plaintext=dek, aad=aad)

    return DEKWrapping(
        wrapping_id=wrapping_id,
        record_id=record_id,
        wrapped_for=wrapped_for,
        wrapped_dek=wrapped_dek,
        nonce=nonce,
        generation=generation,
        created_at=created_at,
    )


def unwrap_dek(wrapping: DEKWrapping, wrapping_key: bytes) -> bytes:
    """Unwrap a sealed DEK using the authorized wrapping key.

    Args:
        wrapping: The DEKWrapping contract.
        wrapping_key: The 32-byte wrapping key.

    Returns:
        The recovered 32-byte DEK.

    Raises:
        UnwrappingError: If unwrapping or authentication fails.

    Security property:
        Fails closed if the key is unauthorized or ciphertext was tampered with.
    """
    aad = wrapping.record_id.encode("utf-8")
    try:
        return aes_gcm_decrypt(
            key=wrapping_key,
            nonce=wrapping.nonce,
            ciphertext=wrapping.wrapped_dek,
            aad=aad,
        )
    except InvalidTagError as exc:
        raise UnwrappingError(
            f"Failed to unwrap DEK for record {wrapping.record_id}"
        ) from exc


def rewrap_dek(
    wrapping: DEKWrapping,
    old_wrapping_key: bytes,
    new_wrapping_key: bytes,
    new_wrapped_for: str,
    new_wrapping_id: str | None = None,
    created_at: datetime.datetime | None = None,
) -> DEKWrapping:
    """Re-wrap a DEK under a new wrapping key, incrementing the generation counter.

    Args:
        wrapping: Existing DEKWrapping contract.
        old_wrapping_key: Current wrapping key to unseal.
        new_wrapping_key: New wrapping key to seal under.
        new_wrapped_for: New authorized recipient or policy ID.
        new_wrapping_id: Optional new wrapping ID.
        created_at: Optional timestamp for new wrapping.

    Returns:
        A new DEKWrapping with generation = old_generation + 1.

    Security property:
        Auditability of key rotation (ARCHITECTURE.md §2 C8).
    """
    dek = unwrap_dek(wrapping, old_wrapping_key)
    return wrap_dek(
        dek=dek,
        record_id=wrapping.record_id,
        wrapping_key=new_wrapping_key,
        wrapped_for=new_wrapped_for,
        generation=wrapping.generation + 1,
        wrapping_id=new_wrapping_id,
        created_at=created_at,
    )
