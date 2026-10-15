"""Certificate issuance for facility CAs, authorities, clinicians, services (C5).

One generic signer (:func:`issue_certificate`) backs three role-specific
helpers so every issued certificate in the federation goes through the same
code path -- the only thing that differs by role is who signs, what CA flag is
set, and the default validity window.
"""

from __future__ import annotations

from crypto_core import build_certificate
from crypto_core.types import ECPrivateKey, ECPublicKey
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from identity.root_anchor import RootAnchor


def _common_name(cert: Certificate) -> str:
    """Extract the bare CN value from a certificate's subject (no ``CN=`` prefix)."""
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value)


DEFAULT_FACILITY_VALID_DAYS = 3650  # facility CAs are long-lived, like the root
DEFAULT_AUTHORITY_VALID_DAYS = 3650  # attribute authorities are long-lived too
DEFAULT_CLINICIAN_VALID_DAYS = 365  # ARCHITECTURE.md §8: credentials must expire
DEFAULT_PATIENT_VALID_DAYS = 365  # patient identity certificates expire too
DEFAULT_SERVICE_VALID_DAYS = 365  # one deployment's lifetime, re-issued at bootstrap

# Subject OU of a patient certificate. A clinician certificate carries none, so
# neither can stand in for the other (ADR-0064).
PATIENT_ROLE = "patient"

# Subject OU of a federation service certificate is ``service:<kind>``
# (ADR-0066). The kind decides which endpoints of another service it may call;
# the CN is the service id its signed requests carry.
SERVICE_ROLE_PREFIX = "service:"
SERVICE_KINDS = frozenset(
    {"facility", "custodian", "audit", "authority", "portal", "bootstrap"}
)


def issue_certificate(
    *,
    issuer_private_key: ECPrivateKey,
    issuer_certificate: Certificate,
    subject_public_key: ECPublicKey,
    subject_common_name: str,
    valid_days: int,
    is_ca: bool = False,
    subject_role: str | None = None,
) -> Certificate:
    """Issue a certificate signed by ``issuer_private_key``.

    Args:
        issuer_private_key: The issuer's signing key.
        issuer_certificate: The issuer's own certificate, used only for its
            subject name (so the new certificate's issuer name matches).
        subject_public_key: The public key being certified.
        subject_common_name: CN identifying the subject (facility/authority/
            clinician id).
        valid_days: Validity window length in days, starting now.
        is_ca: Whether the subject may itself sign certificates.
        subject_role: Optional role recorded in the subject's OU (e.g.
            :data:`PATIENT_ROLE`).

    Returns:
        The signed certificate.
    """
    issuer_common_name = _common_name(issuer_certificate)
    return build_certificate(
        subject_public_key=subject_public_key,
        subject_common_name=subject_common_name,
        issuer_private_key=issuer_private_key,
        issuer_common_name=issuer_common_name,
        valid_days=valid_days,
        is_ca=is_ca,
        subject_role=subject_role,
    )


def issue_facility_ca_certificate(
    root: RootAnchor,
    facility_id: str,
    facility_public_key: ECPublicKey,
    valid_days: int = DEFAULT_FACILITY_VALID_DAYS,
) -> Certificate:
    """Issue a facility CA certificate signed by the root anchor.

    This is what ARCHITECTURE.md §7 step 2 calls issuing facility CA
    certificates. Because every facility CA is signed by the *same* root
    (ADR-0019: one shared root, two facilities), any facility that trusts the
    root transitively trusts every other facility's clinician certificates --
    this single step is what "cross-certify the facilities" means in a
    single-root federation (see ADR-0024 for the alternative considered and
    rejected).

    Args:
        root: The federation's root anchor.
        facility_id: The facility's identifier (e.g. ``"facility-a"``).
        facility_public_key: The facility CA's own public key.
        valid_days: Validity window length in days, starting now.

    Returns:
        The facility's CA certificate (``is_ca=True``), signed by the root.
    """
    return issue_certificate(
        issuer_private_key=root.private_key,
        issuer_certificate=root.certificate,
        subject_public_key=facility_public_key,
        subject_common_name=facility_id,
        valid_days=valid_days,
        is_ca=True,
    )


def issue_authority_certificate(
    root: RootAnchor,
    authority_id: str,
    authority_public_key: ECPublicKey,
    valid_days: int = DEFAULT_AUTHORITY_VALID_DAYS,
) -> Certificate:
    """Issue an attribute authority's identity certificate, signed by the root.

    This is the C6-needs-C5 dependency (ARCHITECTURE.md §4): an attribute
    authority's issuing key is itself verifiable back to the shared root, so a
    forged authority cannot be distinguished from a real one just because it
    can produce a plausible-looking signature -- the signer's own certificate
    must also chain to the root.

    Args:
        root: The federation's root anchor.
        authority_id: The authority's identifier (e.g. ``"authority-med"``).
        authority_public_key: The authority's own signing public key.
        valid_days: Validity window length in days, starting now.

    Returns:
        The authority's certificate (``is_ca=False`` -- an authority signs
        attribute credentials, not further certificates).
    """
    return issue_certificate(
        issuer_private_key=root.private_key,
        issuer_certificate=root.certificate,
        subject_public_key=authority_public_key,
        subject_common_name=authority_id,
        valid_days=valid_days,
        is_ca=False,
    )


def issue_clinician_certificate(
    facility_ca_private_key: ECPrivateKey,
    facility_ca_certificate: Certificate,
    clinician_id: str,
    clinician_public_key: ECPublicKey,
    valid_days: int = DEFAULT_CLINICIAN_VALID_DAYS,
) -> Certificate:
    """Issue a clinician certificate, signed by their enrolling facility's CA.

    Args:
        facility_ca_private_key: The enrolling facility CA's private key.
        facility_ca_certificate: The enrolling facility CA's own certificate.
        clinician_id: The clinician's identifier.
        clinician_public_key: The clinician's own public key.
        valid_days: Validity window length in days, starting now. Defaults to
            one year -- clinician credentials are the leaves of this PKI and
            must expire (ARCHITECTURE.md §8 credential lifecycle).

    Returns:
        The clinician's leaf certificate (``is_ca=False``).
    """
    return issue_certificate(
        issuer_private_key=facility_ca_private_key,
        issuer_certificate=facility_ca_certificate,
        subject_public_key=clinician_public_key,
        subject_common_name=clinician_id,
        valid_days=valid_days,
        is_ca=False,
    )


def issue_patient_certificate(
    facility_ca_private_key: ECPrivateKey,
    facility_ca_certificate: Certificate,
    patient_id: str,
    patient_public_key: ECPublicKey,
    valid_days: int = DEFAULT_PATIENT_VALID_DAYS,
) -> Certificate:
    """Issue a patient certificate, signed by the patient's home facility CA.

    The same issuance path as a clinician's (ADR-0064), marked with
    :data:`PATIENT_ROLE`, so a facility can verify a patient's signature (on
    record labels or a consent decision) against a key it has certified rather
    than one a caller hands it.

    Args:
        facility_ca_private_key: The home facility CA's private key.
        facility_ca_certificate: The home facility CA's own certificate.
        patient_id: The patient's identifier.
        patient_public_key: The patient's own signing public key.
        valid_days: Validity window length in days, starting now.

    Returns:
        The patient's leaf certificate (``is_ca=False``, OU ``patient``).
    """
    return issue_certificate(
        issuer_private_key=facility_ca_private_key,
        issuer_certificate=facility_ca_certificate,
        subject_public_key=patient_public_key,
        subject_common_name=patient_id,
        valid_days=valid_days,
        is_ca=False,
        subject_role=PATIENT_ROLE,
    )


def issue_service_certificate(
    root: RootAnchor,
    service_id: str,
    kind: str,
    service_public_key: ECPublicKey,
    valid_days: int = DEFAULT_SERVICE_VALID_DAYS,
) -> Certificate:
    """Issue a federation service's identity certificate, signed by the root.

    The certificate a service presents with every signed request it sends
    (ADR-0066, review D5-a): the callee checks it chains to the federation
    root, reads the caller's id from the CN and its kind from the OU, and
    verifies the request's signature against its key. Signed by the root
    directly, like an authority certificate, so no facility CA can mint a
    service identity.

    Args:
        root: The federation's root anchor.
        service_id: The service's identifier, e.g. ``"facility-a"`` or
            ``"custodian"``.
        kind: One of :data:`SERVICE_KINDS`.
        service_public_key: The service's request-signing public key.
        valid_days: Validity window length in days, starting now.

    Returns:
        The service's leaf certificate (``is_ca=False``, OU ``service:<kind>``).

    Raises:
        ValueError: ``kind`` is not a known service kind.
    """
    if kind not in SERVICE_KINDS:
        raise ValueError(f"unknown service kind {kind!r}")
    return issue_certificate(
        issuer_private_key=root.private_key,
        issuer_certificate=root.certificate,
        subject_public_key=service_public_key,
        subject_common_name=service_id,
        valid_days=valid_days,
        is_ca=False,
        subject_role=SERVICE_ROLE_PREFIX + kind,
    )
