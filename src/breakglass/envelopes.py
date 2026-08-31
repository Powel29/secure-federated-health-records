"""Request envelope creation and validation (P3-11, ARCHITECTURE.md §8).

A ``RequestEnvelope`` is the signed, one-time-id wrapper around every
inter-service request.  Its purpose is replay protection and payload
integrity: a one-time ``request_id`` the callee's consumed-id store rejects
on reuse, with the signature binding that id, the ``recipient_id``, and the
``body`` together so a captured envelope cannot be replayed or retargeted.

The canonical payload format matches the project-wide convention
(``_FIELD_SEPARATOR = b"\\x1f"``).
"""

from __future__ import annotations

import datetime
import secrets
from uuid import uuid4

from contracts import RequestEnvelope
from crypto_core import sign, verify
from cryptography.hazmat.primitives.asymmetric import ec

from breakglass.exceptions import EnvelopeRecipientMismatchError
from breakglass.replay import ConsumedRequestIds

_FIELD_SEPARATOR = b"\x1f"
_NONCE_BYTES = 16


# ---------------------------------------------------------------------------
# Canonical payload
# ---------------------------------------------------------------------------


def _canonical_envelope_payload(
    *,
    request_id: str,
    caller_id: str,
    recipient_id: str,
    operation: str,
    body: bytes,
    issued_at: datetime.datetime,
    nonce: bytes,
) -> bytes:
    """Build the canonical byte payload the envelope signature covers.

    Every field that participates in the envelope's security binding is
    included.  Changing any one of them without a matching re-signature
    invalidates the envelope.
    """
    fields = [
        request_id.encode("utf-8"),
        caller_id.encode("utf-8"),
        recipient_id.encode("utf-8"),
        operation.encode("utf-8"),
        body,
        issued_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        nonce,
    ]
    return _FIELD_SEPARATOR.join(fields)


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def create_request_envelope(
    *,
    caller_id: str,
    recipient_id: str,
    operation: str,
    body: bytes,
    signing_key: ec.EllipticCurvePrivateKey,
    issued_at: datetime.datetime | None = None,
) -> RequestEnvelope:
    """Build and sign a ``RequestEnvelope``.

    Args:
        caller_id: The calling service's identifier.
        recipient_id: The intended callee's identifier.
        operation: Logical operation name (for routing and audit correlation).
        body: Opaque canonical serialization of the wrapped payload.
        signing_key: The caller service's ECDSA-P256 private key.
        issued_at: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        A signed :class:`~contracts.RequestEnvelope`.

    Security property:
        Nonce and request_id come from :mod:`secrets`; the signature binds
        every field so the envelope cannot be retargeted or tampered with.
    """
    when = issued_at or datetime.datetime.now(datetime.timezone.utc)
    request_id = uuid4()
    nonce = secrets.token_bytes(_NONCE_BYTES)

    payload = _canonical_envelope_payload(
        request_id=str(request_id),
        caller_id=caller_id,
        recipient_id=recipient_id,
        operation=operation,
        body=body,
        issued_at=when,
        nonce=nonce,
    )
    signature = sign(signing_key, payload)

    return RequestEnvelope(
        request_id=request_id,
        caller_id=caller_id,
        recipient_id=recipient_id,
        operation=operation,
        body=body,
        issued_at=when,
        nonce=nonce,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify_request_envelope(
    envelope: RequestEnvelope,
    caller_public_key: ec.EllipticCurvePublicKey,
    expected_recipient_id: str,
    consumed_store: ConsumedRequestIds | None = None,
) -> None:
    """Verify the envelope's signature, recipient binding, and one-time id.

    Checks, in order:

    1. **Signature** — ECDSA over canonical payload, verified against
       ``caller_public_key``.
    2. **Recipient binding** — ``envelope.recipient_id`` matches
       ``expected_recipient_id``.
    3. **Replay** — ``envelope.request_id`` consumed (if store provided).

    Args:
        envelope: The request envelope to validate.
        caller_public_key: The calling service's public key.
        expected_recipient_id: The receiving service's identifier.
        consumed_store: Optional anti-replay store.

    Raises:
        InvalidSignatureError: Signature does not verify.
        EnvelopeRecipientMismatchError: Envelope was not addressed to this
            service.
        ReplayedRequestError: ``request_id`` was already consumed.

    Security property:
        Signature runs first (ADR-0030 §4 ordering).  Consumption runs last
        so a forged envelope cannot burn a legitimate request_id.
    """
    # 1. Signature
    payload = _canonical_envelope_payload(
        request_id=str(envelope.request_id),
        caller_id=envelope.caller_id,
        recipient_id=envelope.recipient_id,
        operation=envelope.operation,
        body=envelope.body,
        issued_at=envelope.issued_at,
        nonce=envelope.nonce,
    )
    verify(caller_public_key, payload, envelope.signature)

    # 2. Recipient binding
    if envelope.recipient_id != expected_recipient_id:
        raise EnvelopeRecipientMismatchError(
            f"envelope recipient_id {envelope.recipient_id!r} does not match "
            f"expected recipient {expected_recipient_id!r}"
        )

    # 3. Replay (last)
    if consumed_store is not None:
        consumed_store.consume(envelope.request_id)
