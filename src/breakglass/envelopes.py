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
from crypto_core.types import ECPrivateKey, ECPublicKey

from breakglass.exceptions import (
    EnvelopeExpiredError,
    EnvelopeOperationMismatchError,
    EnvelopeRecipientMismatchError,
)
from breakglass.replay import ConsumedRequestIds

_FIELD_SEPARATOR = b"\x1f"
_NONCE_BYTES = 16

# How long a signed request stays acceptable, and how far its issued_at may
# run ahead of the callee's clock (ADR-0066). Replay is stopped by the
# consumed-id store; this bounds the window if that store is lost.
MAX_ENVELOPE_AGE = datetime.timedelta(seconds=120)
ENVELOPE_CLOCK_SKEW = datetime.timedelta(seconds=30)


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
    signing_key: ECPrivateKey,
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
    caller_public_key: ECPublicKey,
    expected_recipient_id: str,
    *,
    consumed_store: ConsumedRequestIds,
) -> None:
    """Verify the envelope's signature, recipient binding, and one-time id.

    Checks, in order:

    1. **Signature** — ECDSA over canonical payload, verified against
       ``caller_public_key``.
    2. **Recipient binding** — ``envelope.recipient_id`` matches
       ``expected_recipient_id``.
    3. **Replay** — ``envelope.request_id`` consumed.

    Args:
        envelope: The request envelope to validate.
        caller_public_key: The calling service's public key.
        expected_recipient_id: The receiving service's identifier.
        consumed_store: Anti-replay store. Required, so the replay check can
            never be skipped by omission (F21).

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
    consumed_store.consume(envelope.request_id)


# ---------------------------------------------------------------------------
# Binding to the HTTP request (ADR-0066)
# ---------------------------------------------------------------------------


def check_envelope_binding(
    envelope: RequestEnvelope,
    *,
    expected_operation: str,
    now: datetime.datetime,
    max_age: datetime.timedelta = MAX_ENVELOPE_AGE,
    clock_skew: datetime.timedelta = ENVELOPE_CLOCK_SKEW,
) -> None:
    """Refuse an envelope signed for another request, or outside its window.

    Run before :func:`verify_request_envelope`; it has no side effects, so a
    mismatched envelope never burns its ``request_id``.

    Args:
        envelope: The envelope presented with the request.
        expected_operation: ``"<METHOD> <path>[?<query>]"`` of the request
            actually received.
        now: The callee's current time.
        max_age: Oldest ``issued_at`` accepted.
        clock_skew: How far ``issued_at`` may lie in the future.

    Raises:
        EnvelopeOperationMismatchError: The envelope names another operation.
        EnvelopeExpiredError: ``issued_at`` is outside the window.
    """
    if envelope.operation != expected_operation:
        raise EnvelopeOperationMismatchError(
            f"envelope was signed for {envelope.operation!r}, "
            f"not {expected_operation!r}"
        )
    if envelope.issued_at < now - max_age:
        raise EnvelopeExpiredError(
            f"envelope issued at {envelope.issued_at.isoformat()} is older "
            f"than {max_age}"
        )
    if envelope.issued_at > now + clock_skew:
        raise EnvelopeExpiredError(
            f"envelope issued at {envelope.issued_at.isoformat()} is in the future"
        )
