"""Multi-authority attribute issuance (C6, ARCHITECTURE.md §2).

Each attribute authority (medical council, hospital network) issues signed
``AttributeCredential`` (contracts/credentials.py) to subjects -- usually
clinicians, but under ADR-0016 also a patient, for their own
``owner:<patient_id>`` attribute. Credentials carry the full lifecycle shape
required by ARCHITECTURE.md §8 (serial, validity window, status); this module
issues and verifies them. A live revocation *registry* -- turning a credential
that was ACTIVE at issuance into one an authority can later mark REVOKED -- is
P2-6's job; this module establishes the shape and the issuance-time checks
P2-6 builds on.
"""

from __future__ import annotations

import datetime
import secrets

from contracts import Attribute, AttributeCredential, CredentialStatus
from crypto_core import generate_ec_keypair, sign, verify
from cryptography.hazmat.primitives.asymmetric import ec

from authority.exceptions import (
    CredentialExpiredError,
    CredentialNotYetValidError,
    CredentialStatusError,
    UnauthorizedAttributeError,
)

DEFAULT_CREDENTIAL_VALID_DAYS = 365  # ARCHITECTURE.md §8: nothing issues forever
_FIELD_SEPARATOR = b"\x1f"  # ASCII unit separator -- keeps fields unambiguous


class AttributeAuthority:
    """One federated attribute authority (e.g. ``authority-med``).

    Args:
        authority_id: The authority's identifier.
        private_key: The authority's ECDSA signing key.
        public_key: The authority's ECDSA public key.
        owned_attribute_names: The attribute names (e.g. ``{"role"}``) this
            authority is allowed to issue, per its ADR-0019 namespace. Issuing
            outside this set is refused, so a compromised or misconfigured
            authority cannot mint attributes belonging to another authority's
            namespace.
    """

    def __init__(
        self,
        authority_id: str,
        private_key: ec.EllipticCurvePrivateKey,
        public_key: ec.EllipticCurvePublicKey,
        owned_attribute_names: frozenset[str],
    ) -> None:
        self.authority_id = authority_id
        self.private_key = private_key
        self.public_key = public_key
        self.owned_attribute_names = owned_attribute_names


def generate_authority(
    authority_id: str, owned_attribute_names: frozenset[str]
) -> AttributeAuthority:
    """Generate a fresh attribute authority with its own signing keypair.

    Args:
        authority_id: The authority's identifier.
        owned_attribute_names: The attribute names this authority may issue.

    Returns:
        A new :class:`AttributeAuthority`.
    """
    private_key, public_key = generate_ec_keypair()
    return AttributeAuthority(
        authority_id, private_key, public_key, owned_attribute_names
    )


def _signing_payload(
    *,
    serial: str,
    issuer_id: str,
    subject_id: str,
    attribute: Attribute,
    valid_from: datetime.datetime,
    valid_until: datetime.datetime,
    status: CredentialStatus,
) -> bytes:
    """Build the canonical byte payload an attribute credential's signature covers.

    Every field that participates in the credential's meaning is bound into
    the signature; changing any one of them (subject, attribute, validity
    window, status) without a matching re-signature is what "forged" means
    here and is exactly what :func:`verify_credential` catches.
    """
    fields = [
        serial,
        issuer_id,
        subject_id,
        f"{attribute.name}:{attribute.value}",
        valid_from.astimezone(datetime.timezone.utc).isoformat(),
        valid_until.astimezone(datetime.timezone.utc).isoformat(),
        status.value,
    ]
    return _FIELD_SEPARATOR.join(field.encode("utf-8") for field in fields)


def issue_credential(
    authority: AttributeAuthority,
    subject_id: str,
    attribute: Attribute,
    valid_from: datetime.datetime,
    valid_until: datetime.datetime,
) -> AttributeCredential:
    """Issue a signed attribute credential to ``subject_id``.

    Args:
        authority: The issuing authority.
        subject_id: The credential's subject (usually a clinician id).
        attribute: The attribute being certified, e.g. ``role:physician``.
        valid_from: Start of the validity window.
        valid_until: End of the validity window.

    Returns:
        A signed, ``ACTIVE`` :class:`AttributeCredential`.

    Raises:
        UnauthorizedAttributeError: ``attribute.name`` is outside this
            authority's owned namespace.

    Security property:
        The signature binds subject, attribute, and validity window together;
        no field can be altered post-issuance without invalidating it.
    """
    if attribute.name not in authority.owned_attribute_names:
        raise UnauthorizedAttributeError(
            f"authority {authority.authority_id!r} does not own attribute "
            f"namespace {attribute.name!r}"
        )

    serial = secrets.token_hex(16)
    status = CredentialStatus.ACTIVE
    payload = _signing_payload(
        serial=serial,
        issuer_id=authority.authority_id,
        subject_id=subject_id,
        attribute=attribute,
        valid_from=valid_from,
        valid_until=valid_until,
        status=status,
    )
    signature = sign(authority.private_key, payload)

    return AttributeCredential(
        serial=serial,
        issuer_id=authority.authority_id,
        subject_id=subject_id,
        attribute=attribute,
        valid_from=valid_from,
        valid_until=valid_until,
        status=status,
        signature=signature,
    )


def issue_owner_credential(
    authority: AttributeAuthority,
    patient_id: str,
    valid_from: datetime.datetime,
    valid_until: datetime.datetime,
) -> AttributeCredential:
    """Issue a patient their own ``owner:<patient_id>`` attribute (ADR-0016).

    This is what lets a patient reconstruct the root secret of their own
    record's policy tree via the same path a clinician uses (ADR-0016) --
    same issuance mechanism as any other attribute credential, just with the
    subject and the attribute both bound to the patient.

    Args:
        authority: The patient's home authority (owns the ``owner`` namespace
            per ADR-0019).
        patient_id: The patient's identifier.
        valid_from: Start of the validity window.
        valid_until: End of the validity window.

    Returns:
        A signed, ``ACTIVE`` ``owner:<patient_id>`` credential whose
        ``subject_id`` is the patient.
    """
    return issue_credential(
        authority,
        subject_id=patient_id,
        attribute=Attribute(name="owner", value=patient_id),
        valid_from=valid_from,
        valid_until=valid_until,
    )


def verify_credential(
    credential: AttributeCredential,
    issuer_public_key: ec.EllipticCurvePublicKey,
    at: datetime.datetime | None = None,
) -> None:
    """Verify a credential's signature, status, and validity window.

    Args:
        credential: The credential to verify.
        issuer_public_key: The purported issuer's public key.
        at: The instant to check the validity window against; defaults to now.

    Raises:
        InvalidSignatureError: The signature does not verify against the
            recomputed payload -- a forged or tampered credential.
        CredentialStatusError: ``credential.status`` is not ``ACTIVE``.
        CredentialNotYetValidError: ``at`` is before ``valid_from``.
        CredentialExpiredError: ``at`` is after ``valid_until``.

    Security property:
        Fails closed on every check, in order -- signature first, so an
        attacker cannot use an unsigned or forged credential's other fields to
        probe status/expiry behaviour (CONVENTIONS.md §2 rule 6).
    """
    payload = _signing_payload(
        serial=credential.serial,
        issuer_id=credential.issuer_id,
        subject_id=credential.subject_id,
        attribute=credential.attribute,
        valid_from=credential.valid_from,
        valid_until=credential.valid_until,
        status=credential.status,
    )
    # Raises InvalidSignatureError on failure.
    verify(issuer_public_key, payload, credential.signature)

    if credential.status != CredentialStatus.ACTIVE:
        raise CredentialStatusError(
            f"credential {credential.serial!r} has status "
            f"{credential.status.value!r}, not active"
        )

    now = at if at is not None else datetime.datetime.now(datetime.timezone.utc)
    if now < credential.valid_from:
        raise CredentialNotYetValidError(
            f"credential {credential.serial!r} is not valid until "
            f"{credential.valid_from.isoformat()}"
        )
    if now > credential.valid_until:
        raise CredentialExpiredError(
            f"credential {credential.serial!r} expired at "
            f"{credential.valid_until.isoformat()}"
        )
