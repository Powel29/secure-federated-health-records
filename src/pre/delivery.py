"""Open the PRE delivery package ``breakglass.gate`` hands an emergency clinician.

``breakglass.gate.open_emergency_access`` step 4 re-wraps the recovered DEK for
the emergency clinician as ``c1 (32B) || c2 (32B) || nonce (GCM_NONCE_BYTES)
|| AES-256-GCM(delivery_key, dek, aad=record_id)`` where ``delivery_key`` was
encapsulated under the clinician's ElGamal PRE public key
(:func:`pre.elgamal.encapsulate_key`). The gate's docstring leaves the inverse
-- decapsulate, then AES-GCM-decrypt -- to "the API layer (Phase 4)", but
CONVENTIONS.md §2 rule 10 forbids cipher calls in ``api/``. This module is
that inverse in its proper home: the PRE module owns the delivery envelope, so
it owns the decode. The Key Custodian service (``api.custodian_service``,
ADR-0043) calls this on the clinician's behalf and never touches a primitive.
"""

from __future__ import annotations

from contracts.base import GCM_NONCE_BYTES
from crypto_core import aes_gcm_decrypt

from pre.elgamal import decapsulate_key
from pre.exceptions import PREDecryptionError

# Mirrors ``breakglass.gate._PRE_FIELD_BYTES``: SAFE_PRIME_P is a 256-bit safe
# prime, so each ElGamal ciphertext component fits in 32 bytes.
_PRE_FIELD_BYTES = 32
_HEADER_BYTES = 2 * _PRE_FIELD_BYTES + GCM_NONCE_BYTES


def open_delivery_package(
    rewrapped_dek: bytes, *, pre_private_key: int, record_id: str
) -> bytes:
    """Recover the DEK from a gate-produced delivery package.

    Args:
        rewrapped_dek: ``EmergencyUnlockResult.rewrapped_dek`` exactly as the
            gate packed it (fixed-length framing, see module docstring).
        pre_private_key: The emergency clinician's ElGamal PRE private key --
            the counterpart of the ``pre_rewrap_key`` presented to the gate.
        record_id: The record the package was minted for; bound as AES-GCM
            AAD, so a package for one record cannot be opened as another's.

    Returns:
        The 32-byte record DEK.

    Raises:
        PREDecryptionError: The package is malformed (too short to carry the
            framing) or the encapsulated point does not decrypt under
            ``pre_private_key``.
        crypto_core.InvalidTagError: The AES-GCM tag does not verify -- wrong
            delivery key, wrong ``record_id``, or a tampered package. Fail
            closed; no partial plaintext is ever returned.
    """
    if len(rewrapped_dek) <= _HEADER_BYTES:
        raise PREDecryptionError(
            f"delivery package too short: {len(rewrapped_dek)} bytes, "
            f"need more than {_HEADER_BYTES}"
        )
    c1 = int.from_bytes(rewrapped_dek[:_PRE_FIELD_BYTES], byteorder="big")
    c2 = int.from_bytes(
        rewrapped_dek[_PRE_FIELD_BYTES : 2 * _PRE_FIELD_BYTES], byteorder="big"
    )
    nonce = rewrapped_dek[2 * _PRE_FIELD_BYTES : _HEADER_BYTES]
    ciphertext = rewrapped_dek[_HEADER_BYTES:]

    delivery_key = decapsulate_key(pre_private_key, c1, c2)
    return aes_gcm_decrypt(
        key=delivery_key,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=record_id.encode("utf-8"),
    )
