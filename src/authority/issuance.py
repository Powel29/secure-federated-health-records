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

Beyond credentials, an authority also owns the **attribute key material** the
policy engine seals leaf shares to (ARCHITECTURE.md §3, §8 C6; ADR-0026). A key
is per-attribute, not per-holder -- every holder of ``role:physician`` recovers
the *same* key, which is precisely why the scheme is not collusion-resistant
(ADR-0002). :meth:`AttributeAuthority.attribute_key` is the authoring-side
accessor (used to compile a policy); :meth:`AttributeAuthority.get_attribute_key`
is the holder-facing, credential-gated release.
"""

from __future__ import annotations

import datetime
import secrets

from contracts import Attribute, AttributeCredential, CredentialStatus
from crypto_core import generate_ec_keypair, generate_key, sign, verify
from crypto_core.types import ECPrivateKey, ECPublicKey

from authority.exceptions import (
    CredentialExpiredError,
    CredentialNotYetValidError,
    CredentialRevokedError,
    CredentialStatusError,
    UnauthorizedAttributeError,
)
from authority.revocation import RevocationEntry, RevocationRegistry

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
        private_key: ECPrivateKey,
        public_key: ECPublicKey,
        owned_attribute_names: frozenset[str],
    ) -> None:
        self.authority_id = authority_id
        self.private_key = private_key
        self.public_key = public_key
        self.owned_attribute_names = owned_attribute_names
        # Per-attribute key material, keyed (name, value), minted on demand for
        # attributes this authority owns.
        self._attribute_keys: dict[tuple[str, str], bytes] = {}
        # Revocation registry for credentials issued by this authority (P2-6).
        self.revocation_registry: RevocationRegistry = RevocationRegistry()

    def revoke_credential(
        self,
        serial: str,
        reason: str = "",
        revoked_at: datetime.datetime | None = None,
    ) -> RevocationEntry:
        """Revoke an issued credential by its serial identifier.

        Args:
            serial: The credential serial number to revoke.
            reason: Optional human-readable or coded reason for revocation.
            revoked_at: The timestamp of revocation; defaults to utcnow.

        Returns:
            The created :class:`RevocationEntry`.

        Security property:
            Revocation is immediate: subsequent calls to :meth:`get_attribute_key`
            or :func:`verify_credential` presenting this credential will fail closed.
        """
        return self.revocation_registry.revoke(
            serial=serial,
            issuer_id=self.authority_id,
            reason=reason,
            revoked_at=revoked_at,
        )

    def is_credential_revoked(self, serial: str) -> bool:
        """Return True if this authority has revoked the given credential serial."""
        return self.revocation_registry.is_revoked(serial)

    def get_credential_status(
        self,
        credential: AttributeCredential,
        at: datetime.datetime | None = None,
    ) -> CredentialStatus:
        """Compute the dynamic lifecycle status of a credential.

        This is a *query* helper. Full temporal validation -- including the
        not-yet-valid case (``at < credential.valid_from``) -- lives in
        :func:`verify_credential`, which raises the specific error. The
        ``CredentialStatus`` enum has only ``ACTIVE`` / ``REVOKED`` / ``EXPIRED``
        (contracts are frozen; see ARCHITECTURE §8), so a not-yet-valid
        credential returned here reads as its raw stored status. Callers that
        need a hard authorisation decision must call ``verify_credential``.

        Args:
            credential: The credential to check.
            at: The instant to evaluate against; defaults to utcnow.

        Returns:
            :class:`CredentialStatus.REVOKED` if revoked in registry or marked revoked,
            :class:`CredentialStatus.EXPIRED` if past valid_until or marked expired,
            otherwise ``credential.status`` (typically ``ACTIVE``) -- including
            when ``at < credential.valid_from``.
        """
        if (
            self.is_credential_revoked(credential.serial)
            or credential.status == CredentialStatus.REVOKED
        ):
            return CredentialStatus.REVOKED

        now = at if at is not None else datetime.datetime.now(datetime.timezone.utc)
        if (
            now > credential.valid_until
            or credential.status == CredentialStatus.EXPIRED
        ):
            return CredentialStatus.EXPIRED

        return credential.status

    def attribute_key(self, name: str, value: str) -> bytes:
        """Return the 32-byte attribute key for an owned ``name:value`` (authoring).

        Minted on first request and stable thereafter, so every leaf naming this
        attribute -- and every holder issued it -- shares one key. This is the
        accessor a policy author (record ingest, P3-14) uses to seal a leaf; it
        is not a credential-gated release (see :meth:`get_attribute_key`).

        Args:
            name: The attribute name (must be in this authority's namespace).
            value: The attribute value.

        Returns:
            The attribute's 32-byte key.

        Raises:
            UnauthorizedAttributeError: ``name`` is outside this authority's
                owned namespace -- it cannot mint keys it does not own.

        Security property:
            One key per attribute (ADR-0026). Namespace ownership is enforced so
            an authority cannot produce key material for another's attributes.
        """
        if name not in self.owned_attribute_names:
            raise UnauthorizedAttributeError(
                f"authority {self.authority_id!r} does not own attribute "
                f"namespace {name!r}"
            )
        return self._attribute_keys.setdefault((name, value), generate_key())

    def get_attribute_key(
        self,
        credential: AttributeCredential,
        at: datetime.datetime | None = None,
    ) -> bytes:
        """Release an attribute key to a holder presenting a valid credential.

        This is the gate that connects the credential lifecycle to the policy
        engine (ARCHITECTURE.md §8 C6): a holder only obtains the key that
        decrypts a leaf if their credential for that attribute verifies --
        correct signature, ACTIVE status, not revoked, inside its validity window,
        and issued by this authority. A forged, expired, revoked, or wrong-authority
        credential yields no key.

        Args:
            credential: The holder's credential for the attribute.
            at: The instant to check the validity window against; defaults to now.

        Returns:
            The attribute's 32-byte key.

        Raises:
            UnauthorizedAttributeError: The credential was not issued by this
                authority, or names an attribute outside its namespace.
            InvalidSignatureError: The credential signature does not verify.
            CredentialStatusError / CredentialRevokedError /
            CredentialNotYetValidError / CredentialExpiredError: The credential is
                not currently valid.

        Security property:
            Fails closed -- verification runs before any key is returned, so an
            invalid credential cannot extract key material (CONVENTIONS.md §2
            rule 6).
        """
        if credential.issuer_id != self.authority_id:
            raise UnauthorizedAttributeError(
                f"credential issued by {credential.issuer_id!r}, not this "
                f"authority {self.authority_id!r}"
            )
        # Raises on bad signature / revoked / status / validity window;
        # no key on failure.
        verify_credential(
            credential,
            self.public_key,
            at=at,
            revocation_registry=self.revocation_registry,
        )
        return self.attribute_key(credential.attribute.name, credential.attribute.value)


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
    issuer_public_key: ECPublicKey,
    at: datetime.datetime | None = None,
    *,
    revocation_registry: RevocationRegistry,
) -> None:
    """Verify a credential's signature, status, revocation and validity window.

    Args:
        credential: The credential to verify.
        issuer_public_key: The purported issuer's public key.
        at: The instant to check the validity window against; defaults to now.
        revocation_registry: Registry checked for post-issuance revocation.
            Required, so the check can never be skipped by omission (F21).

    Raises:
        InvalidSignatureError: The signature does not verify against the
            recomputed payload -- a forged or tampered credential.
        CredentialStatusError: ``credential.status`` is not ``ACTIVE``.
        CredentialRevokedError: The credential has been recorded as revoked in
            the revocation registry.
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

    if revocation_registry.is_revoked(credential.serial):
        raise CredentialRevokedError(
            f"credential {credential.serial!r} has been revoked by authority "
            f"{credential.issuer_id!r}"
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
