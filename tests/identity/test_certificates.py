"""Tests for facility CA / authority / clinician certificate issuance (C5)."""

from __future__ import annotations

from crypto_core import (
    generate_ec_keypair,
    is_ca_certificate,
    verify_certificate_signature,
)
from identity.certificates import (
    issue_authority_certificate,
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.root_anchor import RootAnchor


def test_facility_ca_certificate_signed_by_root(
    root: RootAnchor, facility_a_keys: tuple
) -> None:
    """A facility CA certificate must verify against the root's public key."""
    _, facility_pk = facility_a_keys
    cert = issue_facility_ca_certificate(root, "facility-a", facility_pk)

    verify_certificate_signature(cert, root.public_key)
    assert is_ca_certificate(cert) is True
    assert cert.subject.rfc4514_string() == "CN=facility-a"


def test_authority_certificate_signed_by_root(root: RootAnchor) -> None:
    """An attribute authority's certificate must verify against the root's key."""
    _, authority_pk = generate_ec_keypair()
    cert = issue_authority_certificate(root, "authority-med", authority_pk)

    verify_certificate_signature(cert, root.public_key)
    assert is_ca_certificate(cert) is False


def test_clinician_certificate_signed_by_facility_ca(
    facility_a_keys: tuple, facility_a_ca_cert: object
) -> None:
    """A clinician certificate must verify against the enrolling facility's key."""
    facility_sk, _ = facility_a_keys
    _, clinician_pk = generate_ec_keypair()
    cert = issue_clinician_certificate(
        facility_sk, facility_a_ca_cert, "dr-jane-doe", clinician_pk
    )

    verify_certificate_signature(cert, facility_a_keys[1])
    assert is_ca_certificate(cert) is False
    assert cert.subject.rfc4514_string() == "CN=dr-jane-doe"
