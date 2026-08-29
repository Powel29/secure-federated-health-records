"""Shared fixtures for identity module tests -- a two-facility federation."""

from __future__ import annotations

import pytest
from crypto_core import generate_ec_keypair
from cryptography.hazmat.primitives.asymmetric import ec
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.root_anchor import RootAnchor, generate_root_anchor


@pytest.fixture
def root() -> RootAnchor:
    """The federation's one shared trust root (ADR-0019)."""
    return generate_root_anchor()


@pytest.fixture
def facility_a_keys() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """The patient's home facility's CA keypair (ADR-0019: facility-a)."""
    return generate_ec_keypair()


@pytest.fixture
def facility_b_keys() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """The out-of-network facility's CA keypair (ADR-0019: facility-b)."""
    return generate_ec_keypair()


@pytest.fixture
def facility_a_ca_cert(root: RootAnchor, facility_a_keys: tuple) -> object:
    """facility-a's CA certificate, signed by the root."""
    _, pk = facility_a_keys
    return issue_facility_ca_certificate(root, "facility-a", pk)


@pytest.fixture
def facility_b_ca_cert(root: RootAnchor, facility_b_keys: tuple) -> object:
    """facility-b's CA certificate, signed by the root."""
    _, pk = facility_b_keys
    return issue_facility_ca_certificate(root, "facility-b", pk)


@pytest.fixture
def clinician_at_facility_a_cert(
    facility_a_keys: tuple, facility_a_ca_cert: object
) -> object:
    """A clinician certificate issued by facility-a's CA (in-network enrollment)."""
    sk, _ = facility_a_keys
    clinician_sk, clinician_pk = generate_ec_keypair()
    del clinician_sk
    return issue_clinician_certificate(
        sk, facility_a_ca_cert, "dr-jane-doe", clinician_pk
    )
