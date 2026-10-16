"""Emergency assertion creation and validation (P3-10, ARCHITECTURE.md §8).

An ``EmergencyAssertion`` is the signed trigger for break-glass.  Before any
threshold share is requested, the assertion must pass a five-point validation
sequence (ARCHITECTURE.md §8 "Validation, in order"):

1. Signature verifies against a currently-valid clinician certificate.
2. ``clinician_id`` matches the certificate's subject CN.
3. ``facility_id`` matches the receiving node.
4. ``expires_at`` is in the future.
5. ``assertion_id`` has not been consumed (anti-replay, P3-11).

Failure at any step is fail-closed — no share request is made.

Signed bytes use ``crypto_core.encode_fields``: a domain tag, then
length-prefixed fields
(ADR-0077), like every other signed artefact in the project.
"""

from __future__ import annotations

import datetime
import json
import secrets
from uuid import UUID, uuid4

from contracts import EmergencyAssertion
from contracts.enums import ReasonCode
from crypto_core import (
    certificate_public_key,
    encode_fields,
    sha256_digest,
    sign,
    verify,
)
from crypto_core.exceptions import InvalidSignatureError
from crypto_core.types import ECPrivateKey, ECPublicKey
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from identity.chain import validate_chain
from identity.exceptions import ChainValidationError

from breakglass.exceptions import (
    AssertionExpiredError,
    AssertionLifetimeError,
    CertificateRevokedError,
    ClinicianMismatchError,
    FacilityMismatchError,
)
from breakglass.replay import ConsumedAssertionIds

# encode_fields domain tag (ADR-0077): an assertion signature never verifies
# as a transition event signed by the same clinician key.
_DOMAIN = "ehr/emergency-assertion/v1"

# Longest an assertion may live (expires_at - issued_at), and how far in the
# future issued_at may be to tolerate clock drift between custodian and
# facility (F6). An unused assertion is a one-time token, so it lives minutes,
# not days (ADR-0056 replaces ADR-0049's 3 days); the session window it opens
# is configured separately.
MAX_ASSERTION_TTL = datetime.timedelta(minutes=15)
ASSERTION_CLOCK_SKEW = datetime.timedelta(seconds=30)

# Matches ``contracts.base.MIN_ANTIREPLAY_NONCE_BYTES``.
_NONCE_BYTES = 16


# ---------------------------------------------------------------------------
# Canonical payload
# ---------------------------------------------------------------------------


def _canonical_assertion_payload(
    *,
    assertion_id: UUID,
    patient_id: str,
    clinician_id: str,
    facility_id: str,
    reason_code: ReasonCode,
    issued_at: datetime.datetime,
    expires_at: datetime.datetime,
    nonce: bytes,
    clinical_context_digest: str = "",
) -> bytes:
    """Build the canonical byte payload the assertion signature covers.

    Every field that participates in the assertion's meaning is bound in.
    Changing any one of them without a matching re-signature is what
    "tampered" means here and is precisely what :func:`verify_emergency_assertion`
    catches.
    """
    fields = [
        str(assertion_id).encode("utf-8"),
        patient_id.encode("utf-8"),
        clinician_id.encode("utf-8"),
        facility_id.encode("utf-8"),
        reason_code.value.encode("utf-8"),
        issued_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        expires_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        nonce,
    ]
    fields.append(clinical_context_digest.encode("ascii"))
    return encode_fields(_DOMAIN, fields)


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def create_emergency_assertion(
    *,
    patient_id: str,
    clinician_id: str,
    facility_id: str,
    reason_code: ReasonCode,
    signing_key: ECPrivateKey,
    issued_at: datetime.datetime | None = None,
    expires_at: datetime.datetime | None = None,
    ttl: datetime.timedelta | None = None,
    clinical_context_digest: str = "",
) -> EmergencyAssertion:
    """Build and sign an ``EmergencyAssertion``.

    Args:
        patient_id: The patient this assertion opens.
        clinician_id: The presenting clinician (must match certificate CN).
        facility_id: The facility where the emergency is being declared.
        reason_code: Clinical justification (constrained enum).
        signing_key: The clinician's ECDSA-P256 private key.
        issued_at: Optional timestamp; defaults to ``utcnow()``.
        expires_at: Explicit expiry timestamp.  If not provided, computed
            from ``issued_at + ttl``.
        ttl: Time-to-live for the assertion (default 15 minutes).

    Returns:
        A signed :class:`~contracts.EmergencyAssertion`.

    Security property:
        Nonce and assertion_id come from :mod:`secrets`; the signature is
        produced by ``crypto_core.sign`` over the canonical payload.
    """
    when = issued_at or datetime.datetime.now(datetime.timezone.utc)
    if expires_at is None:
        duration = ttl if ttl is not None else datetime.timedelta(minutes=15)
        expires_at = when + duration

    assertion_id = uuid4()
    nonce = secrets.token_bytes(_NONCE_BYTES)

    payload = _canonical_assertion_payload(
        assertion_id=assertion_id,
        patient_id=patient_id,
        clinician_id=clinician_id,
        facility_id=facility_id,
        reason_code=reason_code,
        issued_at=when,
        expires_at=expires_at,
        nonce=nonce,
        clinical_context_digest=clinical_context_digest,
    )
    signature = sign(signing_key, payload)

    return EmergencyAssertion(
        assertion_id=assertion_id,
        patient_id=patient_id,
        clinician_id=clinician_id,
        facility_id=facility_id,
        reason_code=reason_code,
        issued_at=when,
        expires_at=expires_at,
        nonce=nonce,
        clinical_context_digest=clinical_context_digest,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Verify signature only
# ---------------------------------------------------------------------------


def verify_emergency_assertion_signature(
    assertion: EmergencyAssertion,
    clinician_public_key: ECPublicKey,
) -> None:
    """Verify the assertion's ECDSA signature against ``clinician_public_key``.

    Raises:
        InvalidSignatureError: Signature does not verify — forged, tampered,
            or wrong-signer assertion.

    Security property:
        Signature check only; does not validate cert chain, binding, expiry,
        or replay.  Use :func:`validate_emergency_assertion` for the full
        five-point sequence.
    """
    payload = _canonical_assertion_payload(
        assertion_id=assertion.assertion_id,
        patient_id=assertion.patient_id,
        clinician_id=assertion.clinician_id,
        facility_id=assertion.facility_id,
        reason_code=assertion.reason_code,
        issued_at=assertion.issued_at,
        expires_at=assertion.expires_at,
        nonce=assertion.nonce,
        clinical_context_digest=assertion.clinical_context_digest,
    )
    verify(clinician_public_key, payload, assertion.signature)


def clinical_context_digest(record_id: str, justification: str, sensitive: str) -> str:
    """Bind the declared necessity and exact record to the existing signature."""
    payload = json.dumps(
        [record_id, justification.strip(), sensitive.strip()],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_digest(payload).hex()


def validate_clinical_context(
    assertion: EmergencyAssertion, record_id: str, justification: str, sensitive: str
) -> None:
    """Reject substitution of a record or clinical justification after signing."""
    if assertion.clinical_context_digest != clinical_context_digest(
        record_id, justification, sensitive
    ):
        raise ValueError("Clinical justification does not match the signed assertion")


# ---------------------------------------------------------------------------
# Full validation (ARCHITECTURE.md §8 five-point sequence)
# ---------------------------------------------------------------------------


def validate_emergency_assertion(
    assertion: EmergencyAssertion,
    clinician_certificate: Certificate,
    facility_ca_certificate: Certificate,
    trusted_root: Certificate,
    expected_facility_id: str,
    *,
    consumed_store: ConsumedAssertionIds,
    revoked_serials: frozenset[int],
    at: datetime.datetime | None = None,
    max_ttl: datetime.timedelta = MAX_ASSERTION_TTL,
    clock_skew: datetime.timedelta = ASSERTION_CLOCK_SKEW,
) -> None:
    """Full fail-closed validation of an emergency assertion (ARCHITECTURE.md §8).

    Checks, in order:

    1. **Signature** — ECDSA over canonical payload, verified against the
       clinician certificate's public key.
    2. **Certificate chain** — clinician cert chains to ``trusted_root``
       through ``facility_ca_certificate``.
    3. **Clinician binding** — ``assertion.clinician_id`` == certificate CN.
    4. **Facility binding** — ``assertion.facility_id`` ==
       ``expected_facility_id``.
    3a. **Revocation** — the certificate serial is not in ``revoked_serials``.
    5. **Expiry** — ``assertion.expires_at > at``; lifetime at most
       ``max_ttl``; ``issued_at`` no later than ``at + clock_skew``.
    6. **Replay** — ``assertion.assertion_id`` consumed.

    Args:
        assertion: The emergency assertion to validate.
        clinician_certificate: The presenting clinician's X.509 certificate.
        facility_ca_certificate: The facility CA certificate that issued the
            clinician cert (intermediate in the chain).
        trusted_root: The federation root trust anchor certificate.
        expected_facility_id: The receiving facility's identifier.
        consumed_store: Anti-replay store. Required: ``assertion_id`` is
            consumed on success and replays are rejected (F21).
        revoked_serials: Serial numbers of revoked clinician certificates.
            Required; pass ``frozenset()`` when none are revoked (F1).
        at: The instant to check expiry and cert validity against; defaults
            to now (UTC).
        max_ttl: Longest allowed ``expires_at - issued_at`` (default 15 min).
        clock_skew: How far ``issued_at`` may lie in the future (default 30s).

    Raises:
        InvalidSignatureError: Assertion signature does not verify.
        ChainValidationError / CertificateExpiredError: Certificate chain
            is broken or expired.
        ClinicianMismatchError: ``clinician_id`` does not match cert CN.
        FacilityMismatchError: ``facility_id`` does not match receiving node.
        AssertionExpiredError: ``expires_at`` is not in the future.
        AssertionLifetimeError: Lifetime exceeds ``max_ttl``, or ``issued_at``
            is in the future beyond ``clock_skew``.
        CertificateRevokedError: The clinician certificate is revoked.
        ReplayedAssertionError: ``assertion_id`` was already consumed.

    Security property:
        Fail-closed at every step.  Signature verification runs first so
        a tampered assertion is reported as tampered, not as an expiry or
        binding error.  Consumption runs last so a forged assertion cannot
        burn a legitimate ID (ADR-0030 §4 ordering invariant).
    """
    now = at if at is not None else datetime.datetime.now(datetime.timezone.utc)

    # 1. Signature
    clinician_pub = certificate_public_key(clinician_certificate)
    verify_emergency_assertion_signature(assertion, clinician_pub)

    # 2. Certificate chain. A link whose signature does not verify is a broken
    # chain, reported as such -- InvalidSignatureError from this function
    # means the assertion itself was tampered with (F1).
    try:
        validate_chain(
            leaf=clinician_certificate,
            intermediates=[facility_ca_certificate],
            trusted_root=trusted_root,
            at=now,
        )
    except InvalidSignatureError as exc:
        raise ChainValidationError(
            f"clinician certificate chain does not verify: {exc}"
        ) from exc

    # 3. Clinician binding
    cert_attrs = clinician_certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )
    cert_cn = str(cert_attrs[0].value) if cert_attrs else None
    if assertion.clinician_id != cert_cn:
        raise ClinicianMismatchError(
            f"assertion clinician_id {assertion.clinician_id!r} does not match "
            f"certificate CN {cert_cn!r}"
        )

    # 3a. Revocation
    if clinician_certificate.serial_number in revoked_serials:
        raise CertificateRevokedError(
            f"clinician certificate serial {clinician_certificate.serial_number} "
            "is revoked"
        )

    # 4. Facility binding
    if assertion.facility_id != expected_facility_id:
        raise FacilityMismatchError(
            f"assertion facility_id {assertion.facility_id!r} does not match "
            f"expected facility {expected_facility_id!r}"
        )

    # 5. Expiry
    if assertion.expires_at <= now:
        raise AssertionExpiredError(
            f"assertion expired at {assertion.expires_at.isoformat()}, "
            f"checked at {now.isoformat()}"
        )

    if assertion.expires_at - assertion.issued_at > max_ttl:
        raise AssertionLifetimeError(
            f"assertion lifetime {assertion.expires_at - assertion.issued_at} "
            f"exceeds the maximum {max_ttl}"
        )
    if assertion.issued_at > now + clock_skew:
        raise AssertionLifetimeError(
            f"assertion issued_at {assertion.issued_at.isoformat()} is in the future"
        )

    # 6. Replay (last — do not burn IDs on a forged/invalid assertion)
    consumed_store.consume(assertion.assertion_id)
