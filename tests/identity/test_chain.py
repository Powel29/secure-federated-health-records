"""Tests for certificate chain validation (C5)."""

from __future__ import annotations

import datetime

import pytest
from crypto_core import (
    CertificateExpiredError,
    InvalidSignatureError,
    generate_ec_keypair,
)
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.chain import validate_chain
from identity.exceptions import ChainValidationError
from identity.root_anchor import RootAnchor, generate_root_anchor


def test_clinician_chain_validates_to_root(
    root: RootAnchor,
    facility_a_keys: tuple,
    facility_a_ca_cert: object,
    clinician_at_facility_a_cert: object,
) -> None:
    """A legitimate clinician certificate validates through its facility CA to root."""
    validate_chain(clinician_at_facility_a_cert, [facility_a_ca_cert], root.certificate)


def test_facility_ca_chain_validates_directly_to_root(
    root: RootAnchor, facility_a_ca_cert: object
) -> None:
    """A facility CA certificate (no intermediates) validates directly to the root."""
    validate_chain(facility_a_ca_cert, [], root.certificate)


def test_chain_rejects_wrong_root() -> None:
    """A chain that is internally consistent but anchored elsewhere must be rejected.

    Security property backing P2-1's "a forged one is rejected": an attacker
    who runs their own private root and signs a plausible-looking facility CA
    and clinician certificate must not be trusted just because the chain is
    self-consistent.
    """
    attacker_root = generate_root_anchor(common_name="attacker-root")
    real_root = generate_root_anchor(common_name="real-root")

    _, facility_pk = generate_ec_keypair()
    facility_sk, _ = generate_ec_keypair()
    facility_cert = issue_facility_ca_certificate(
        attacker_root, "facility-a", facility_pk
    )

    _, clinician_pk = generate_ec_keypair()
    clinician_cert = issue_clinician_certificate(
        facility_sk, facility_cert, "dr-forged", clinician_pk
    )

    with pytest.raises((InvalidSignatureError, ChainValidationError)):
        validate_chain(clinician_cert, [facility_cert], real_root.certificate)


def test_chain_rejects_tampered_intermediate(
    root: RootAnchor, facility_a_ca_cert: object, clinician_at_facility_a_cert: object
) -> None:
    """Substituting an unrelated (but validly root-signed) CA in the chain must fail.

    The substitute intermediate is itself a real, root-signed facility CA --
    it is simply not the one that signed this clinician's certificate. If
    chain validation only checked "is each cert individually signed by
    something," this would incorrectly pass.
    """
    _, other_facility_pk = generate_ec_keypair()
    unrelated_but_valid_ca = issue_facility_ca_certificate(
        root, "unrelated-ca", other_facility_pk
    )

    with pytest.raises((InvalidSignatureError, ChainValidationError)):
        validate_chain(
            clinician_at_facility_a_cert, [unrelated_but_valid_ca], root.certificate
        )


def test_chain_rejects_expired_leaf(
    root: RootAnchor, facility_a_keys: tuple, facility_a_ca_cert: object
) -> None:
    """An expired clinician certificate must be rejected even with a valid chain."""
    facility_sk, _ = facility_a_keys
    _, clinician_pk = generate_ec_keypair()
    expired_cert = issue_clinician_certificate(
        facility_sk, facility_a_ca_cert, "dr-expired", clinician_pk, valid_days=1
    )

    far_future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=30
    )
    with pytest.raises(CertificateExpiredError):
        validate_chain(
            expired_cert, [facility_a_ca_cert], root.certificate, at=far_future
        )


def test_chain_rejects_non_ca_intermediate(root: RootAnchor) -> None:
    """An intermediate lacking the CA basic constraint must be refused as a signer."""
    # Issue a leaf (non-CA) certificate directly off the root, then try to use
    # it as though it were an intermediate CA for a further certificate.
    non_ca_sk, non_ca_pk = generate_ec_keypair()
    non_ca_cert = issue_clinician_certificate(
        root.private_key, root.certificate, "not-a-ca", non_ca_pk
    )

    _, leaf_pk = generate_ec_keypair()
    forged_leaf = issue_clinician_certificate(
        non_ca_sk, non_ca_cert, "dr-under-non-ca", leaf_pk
    )

    with pytest.raises(ChainValidationError):
        validate_chain(forged_leaf, [non_ca_cert], root.certificate)
