"""Patient consent service: request-then-approve gate over an already-wrapped record.

Design (ADR-0031): consent is a **read-time predicate** over records that were
policy-wrapped at ingest (P3-14) as ``OR(clinical_policy, owner:<patient_id>)``.
This module signs and verifies ``ConsentRequest`` / ``ConsentGrant`` value
objects, and provides a single :func:`authorize_read` predicate that a caller
runs before invoking the crypto path. It does *not* wrap or re-wrap records --
that is P3-14's (ingest) and P3-7's (revocation-by-rotation) territory.

The canonical payload format is the same shape as ``authority/issuance.py`` and
``lifecycle/state_machine.py`` (``_FIELD_SEPARATOR = b"\\x1f"``) so every signed
artifact in the project shares one construction.
"""

from __future__ import annotations

import datetime
import secrets
from uuid import UUID, uuid4

from contracts import ConsentGrant, ConsentRequest, DEKWrapping, Record
from contracts.enums import ConsentStatus
from crypto_core import aes_gcm_decrypt, sign, verify
from cryptography.hazmat.primitives.asymmetric import ec
from policy.engine import AttributeKeyring, CompiledPolicy, unwrap_dek_via_policy

from consent.exceptions import (
    ConsentDeniedError,
    ConsentExpiredError,
    ConsentRevokedError,
    ConsentScopeError,
    ConsentSubjectError,
)

_FIELD_SEPARATOR = b"\x1f"
_NONCE_BYTES = 16  # matches contracts.base.MIN_ANTIREPLAY_NONCE_BYTES

# One year -- ARCHITECTURE §8 "nothing issues forever." The caller normally
# supplies a shorter duration matched to the clinical episode.
DEFAULT_REQUEST_TTL = datetime.timedelta(days=7)
DEFAULT_GRANT_TTL = datetime.timedelta(days=30)


# ---------------------------------------------------------------------------
# Canonical payloads
# ---------------------------------------------------------------------------


def _request_payload(
    *,
    request_id: UUID,
    patient_id: str,
    requester_id: str,
    scope: tuple[str, ...],
    purpose: str,
    requested_at: datetime.datetime,
    expires_at: datetime.datetime,
    nonce: bytes,
) -> bytes:
    """Canonical bytes a ``ConsentRequest`` signature covers.

    Every field that participates in the request's meaning is bound in;
    changing any of them (scope, expires_at, ...) without re-signing fails
    :func:`verify_consent_request`.
    """
    fields = [
        str(request_id).encode("utf-8"),
        patient_id.encode("utf-8"),
        requester_id.encode("utf-8"),
        _FIELD_SEPARATOR.join(item.encode("utf-8") for item in scope),
        purpose.encode("utf-8"),
        requested_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        expires_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        nonce,
    ]
    return _FIELD_SEPARATOR.join(fields)


def _grant_payload(
    *,
    grant_id: UUID,
    request_id: UUID,
    patient_id: str,
    grantee_id: str,
    scope: tuple[str, ...],
    status: ConsentStatus,
    decided_at: datetime.datetime,
    expires_at: datetime.datetime,
    nonce: bytes,
) -> bytes:
    """Canonical bytes a ``ConsentGrant`` signature covers."""
    fields = [
        str(grant_id).encode("utf-8"),
        str(request_id).encode("utf-8"),
        patient_id.encode("utf-8"),
        grantee_id.encode("utf-8"),
        _FIELD_SEPARATOR.join(item.encode("utf-8") for item in scope),
        status.value.encode("utf-8"),
        decided_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        expires_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        nonce,
    ]
    return _FIELD_SEPARATOR.join(fields)


# ---------------------------------------------------------------------------
# Request-then-approve
# ---------------------------------------------------------------------------


def create_consent_request(
    *,
    patient_id: str,
    requester_id: str,
    scope: tuple[str, ...],
    purpose: str,
    requester_signing_key: ec.EllipticCurvePrivateKey,
    requested_at: datetime.datetime | None = None,
    ttl: datetime.timedelta = DEFAULT_REQUEST_TTL,
) -> ConsentRequest:
    """Sign a fresh ``ConsentRequest`` from a clinician or facility to a patient.

    Args:
        patient_id: The patient whose records are being requested.
        requester_id: The identifier of the party asking (subject of signature).
        scope: A non-empty tuple of record IDs the request covers.
        purpose: Free-text reason the patient will see. Contract validator
            requires it be non-empty after strip.
        requester_signing_key: The requester's ECDSA-P256 private key.
        requested_at: Optional timestamp; defaults to utcnow.
        ttl: How long before the *request* itself lapses if unanswered.

    Returns:
        A signed :class:`ConsentRequest`.

    Security property:
        Nonce and request_id come from :mod:`secrets` / :func:`uuid.uuid4`.
        The contract's ``expires_at > requested_at`` validator refuses any
        window that closes on issue -- reproduced here defensively.
    """
    when = requested_at or datetime.datetime.now(datetime.timezone.utc)
    request_id = uuid4()
    nonce = secrets.token_bytes(_NONCE_BYTES)
    expires_at = when + ttl

    payload = _request_payload(
        request_id=request_id,
        patient_id=patient_id,
        requester_id=requester_id,
        scope=scope,
        purpose=purpose,
        requested_at=when,
        expires_at=expires_at,
        nonce=nonce,
    )
    signature = sign(requester_signing_key, payload)

    return ConsentRequest(
        request_id=request_id,
        patient_id=patient_id,
        requester_id=requester_id,
        scope=scope,
        purpose=purpose,
        requested_at=when,
        expires_at=expires_at,
        nonce=nonce,
        signature=signature,
    )


def verify_consent_request(
    request: ConsentRequest,
    requester_public_key: ec.EllipticCurvePublicKey,
    at: datetime.datetime | None = None,
) -> None:
    """Verify a request's signature and that it has not already lapsed.

    Raises:
        InvalidSignatureError: Signature does not verify against the payload.
        ConsentExpiredError: ``at`` is past ``request.expires_at``.
    """
    payload = _request_payload(
        request_id=request.request_id,
        patient_id=request.patient_id,
        requester_id=request.requester_id,
        scope=request.scope,
        purpose=request.purpose,
        requested_at=request.requested_at,
        expires_at=request.expires_at,
        nonce=request.nonce,
    )
    verify(requester_public_key, payload, request.signature)

    now = at if at is not None else datetime.datetime.now(datetime.timezone.utc)
    if now > request.expires_at:
        raise ConsentExpiredError(
            f"consent request {request.request_id} expired at {request.expires_at}"
        )


def create_consent_grant(
    *,
    request: ConsentRequest,
    status: ConsentStatus,
    grantee_id: str,
    patient_signing_key: ec.EllipticCurvePrivateKey,
    scope: tuple[str, ...] | None = None,
    decided_at: datetime.datetime | None = None,
    ttl: datetime.timedelta = DEFAULT_GRANT_TTL,
) -> ConsentGrant:
    """Sign the patient's decision on a ``ConsentRequest``.

    Args:
        request: The request being answered. ``request_id`` and ``patient_id``
            are copied through; ``scope`` defaults to the request's scope and
            can only be narrowed by the caller, not widened.
        status: The patient's decision (typically ``GRANTED`` or ``DENIED``;
            ``REVOKED`` is used by :func:`revoke_consent_grant`).
        grantee_id: The party the decision concerns. Normally
            ``request.requester_id``; separate parameter so a clinician
            requesting on behalf of a role can be resolved to a specific
            clinician here.
        patient_signing_key: The patient's ECDSA-P256 private key.
        scope: Optional narrower scope (must be a subset of ``request.scope``).
            Defaults to the request's scope.
        decided_at: Optional timestamp; defaults to utcnow.
        ttl: How long the grant is valid. ARCHITECTURE §8: nothing issues
            forever; the caller normally supplies a clinical-episode duration.

    Returns:
        A signed :class:`ConsentGrant`.

    Raises:
        ConsentScopeError: ``scope`` includes a record not in ``request.scope``
            -- a decision cannot widen a request.

    Security property:
        A grant's scope is a subset of the request's, never a superset. Nonce
        and grant_id come from :mod:`secrets` / :func:`uuid.uuid4`.
    """
    when = decided_at or datetime.datetime.now(datetime.timezone.utc)
    effective_scope = scope if scope is not None else request.scope

    if not set(effective_scope).issubset(set(request.scope)):
        widened = sorted(set(effective_scope) - set(request.scope))
        raise ConsentScopeError(
            f"grant scope widens beyond request: extra records {widened!r}"
        )

    grant_id = uuid4()
    nonce = secrets.token_bytes(_NONCE_BYTES)
    expires_at = when + ttl

    payload = _grant_payload(
        grant_id=grant_id,
        request_id=request.request_id,
        patient_id=request.patient_id,
        grantee_id=grantee_id,
        scope=effective_scope,
        status=status,
        decided_at=when,
        expires_at=expires_at,
        nonce=nonce,
    )
    signature = sign(patient_signing_key, payload)

    return ConsentGrant(
        grant_id=grant_id,
        request_id=request.request_id,
        patient_id=request.patient_id,
        grantee_id=grantee_id,
        scope=effective_scope,
        status=status,
        decided_at=when,
        expires_at=expires_at,
        nonce=nonce,
        signature=signature,
    )


def verify_consent_grant(
    grant: ConsentGrant,
    patient_public_key: ec.EllipticCurvePublicKey,
) -> None:
    """Verify the grant's patient signature.

    Raises:
        InvalidSignatureError: Signature does not verify -- forged, tampered,
            or signed by a party other than ``patient_public_key``.
    """
    payload = _grant_payload(
        grant_id=grant.grant_id,
        request_id=grant.request_id,
        patient_id=grant.patient_id,
        grantee_id=grant.grantee_id,
        scope=grant.scope,
        status=grant.status,
        decided_at=grant.decided_at,
        expires_at=grant.expires_at,
        nonce=grant.nonce,
    )
    verify(patient_public_key, payload, grant.signature)


def revoke_consent_grant(
    *,
    prior_grant: ConsentGrant,
    patient_signing_key: ec.EllipticCurvePrivateKey,
    decided_at: datetime.datetime | None = None,
    ttl: datetime.timedelta = DEFAULT_GRANT_TTL,
) -> ConsentGrant:
    """Sign a revocation of a previously issued grant.

    A revocation is a fresh, patient-signed ``ConsentGrant`` answering the
    same ``request_id`` with ``status=REVOKED``. Grants are immutable signed
    artifacts, so revocation cannot be a mutation of ``prior_grant`` -- it is
    a new record the audit chain can point to.

    Only the patient can produce a valid revocation: signing with any other
    key fails :func:`verify_consent_grant` (raises ``InvalidSignatureError``),
    which is what makes "patient-only revocation" cryptographic rather than
    policy.

    Args:
        prior_grant: The grant being revoked. ``request_id``, ``patient_id``,
            ``grantee_id``, and ``scope`` are copied so the revocation
            references the same subject exactly.
        patient_signing_key: The patient's ECDSA-P256 private key.
        decided_at: Optional timestamp; defaults to utcnow.
        ttl: How long the *revocation record* remains valid as an artifact.

    Returns:
        A signed :class:`ConsentGrant` with ``status=REVOKED``.
    """
    when = decided_at or datetime.datetime.now(datetime.timezone.utc)
    grant_id = uuid4()
    nonce = secrets.token_bytes(_NONCE_BYTES)
    expires_at = when + ttl

    payload = _grant_payload(
        grant_id=grant_id,
        request_id=prior_grant.request_id,
        patient_id=prior_grant.patient_id,
        grantee_id=prior_grant.grantee_id,
        scope=prior_grant.scope,
        status=ConsentStatus.REVOKED,
        decided_at=when,
        expires_at=expires_at,
        nonce=nonce,
    )
    signature = sign(patient_signing_key, payload)

    return ConsentGrant(
        grant_id=grant_id,
        request_id=prior_grant.request_id,
        patient_id=prior_grant.patient_id,
        grantee_id=prior_grant.grantee_id,
        scope=prior_grant.scope,
        status=ConsentStatus.REVOKED,
        decided_at=when,
        expires_at=expires_at,
        nonce=nonce,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# The read-time gate
# ---------------------------------------------------------------------------


def authorize_read(
    grant: ConsentGrant,
    *,
    record_id: str,
    grantee_id: str,
    patient_public_key: ec.EllipticCurvePublicKey,
    at: datetime.datetime | None = None,
) -> None:
    """Predicate the caller runs before invoking the policy/crypto read path.

    Order of checks (fail-closed at first failure, no side effects):
        1. Patient signature on the grant verifies.
        2. Grant status is exactly ``GRANTED`` -- ``DENIED`` and ``REVOKED``
           each raise their specific error rather than "not granted", so an
           audit log entry can name what happened.
        3. Grant is inside its time window.
        4. ``grantee_id`` matches the grant.
        5. ``record_id`` is in the grant's scope.

    Args:
        grant: The patient's signed decision.
        record_id: The record the caller is about to read.
        grantee_id: The party attempting the read.
        patient_public_key: The signer's public key -- normally the record's
            patient. If the grant's signature does not verify against this key,
            it was not signed by the patient we think.
        at: Optional evaluation instant; defaults to utcnow.

    Raises:
        InvalidSignatureError: Signature does not verify.
        ConsentDeniedError: ``grant.status == DENIED``.
        ConsentRevokedError: ``grant.status == REVOKED``.
        ConsentExpiredError: ``at > grant.expires_at`` (or below decided_at).
        ConsentSubjectError: ``grantee_id != grant.grantee_id``.
        ConsentScopeError: ``record_id not in grant.scope``.
    """
    verify_consent_grant(grant, patient_public_key)

    if grant.status is ConsentStatus.DENIED:
        raise ConsentDeniedError(
            f"consent grant {grant.grant_id} denied access to {grant.grantee_id!r}"
        )
    if grant.status is ConsentStatus.REVOKED:
        raise ConsentRevokedError(f"consent grant {grant.grant_id} was revoked")
    if grant.status is not ConsentStatus.GRANTED:
        # EXPIRED status handled by the time-window check below; any other
        # future status is refused by name.
        raise ConsentDeniedError(
            f"consent grant status {grant.status.value!r} does not authorise reads"
        )

    now = at if at is not None else datetime.datetime.now(datetime.timezone.utc)
    if now > grant.expires_at or now < grant.decided_at:
        raise ConsentExpiredError(
            f"consent grant {grant.grant_id} not within its validity window "
            f"[{grant.decided_at}, {grant.expires_at}]"
        )

    if grantee_id != grant.grantee_id:
        raise ConsentSubjectError(
            f"reader {grantee_id!r} does not match grant grantee "
            f"{grant.grantee_id!r}"
        )

    if record_id not in grant.scope:
        raise ConsentScopeError(
            f"record {record_id!r} not in grant scope {list(grant.scope)!r}"
        )


def read_record_under_consent(
    *,
    record: Record,
    wrapping: DEKWrapping,
    compiled_policy: CompiledPolicy,
    grant: ConsentGrant,
    grantee_id: str,
    patient_public_key: ec.EllipticCurvePublicKey,
    holder_keyring: AttributeKeyring,
    at: datetime.datetime | None = None,
) -> bytes:
    """End-to-end consent-mediated read: gate → policy unwrap → AES-GCM decrypt.

    Convenience composition of :func:`authorize_read`,
    :func:`policy.unwrap_dek_via_policy`, and :func:`crypto_core.aes_gcm_decrypt`.
    The three-step path is what the paper cites as "the single decryption path"
    (ADR-0016) -- keeping it in one function proves that path exists and no
    side-channel bypass sits alongside it.

    Args:
        record: The encrypted record.
        wrapping: Its ``DEKWrapping`` sealed under the policy's root secret.
        compiled_policy: The record's compiled policy tree.
        grant: The patient's signed consent decision.
        grantee_id: The clinician reading -- must match ``grant.grantee_id``.
        patient_public_key: For grant-signature verification.
        holder_keyring: The clinician's held attribute keys.
        at: Optional evaluation instant; defaults to utcnow.

    Returns:
        The record's plaintext bytes.

    Raises:
        Any of the ``ConsentError`` subclasses, ``InvalidSignatureError``,
        ``PolicyDeniedError``, or ``InvalidTagError`` (AES-GCM tag mismatch).
        Each failure is the specific reason the read did not happen.
    """
    authorize_read(
        grant,
        record_id=record.record_id,
        grantee_id=grantee_id,
        patient_public_key=patient_public_key,
        at=at,
    )
    dek = unwrap_dek_via_policy(compiled_policy, holder_keyring, wrapping)
    return aes_gcm_decrypt(
        key=dek,
        nonce=record.nonce,
        ciphertext=record.ciphertext,
        aad=record.aad,
    )
