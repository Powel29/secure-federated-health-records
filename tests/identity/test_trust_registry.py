"""Tests for the federation-wide trust registry (C5)."""

from __future__ import annotations

import pytest
from crypto_core import InvalidSignatureError, generate_ec_keypair
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.exceptions import UnknownFacilityError
from identity.root_anchor import RootAnchor, generate_root_anchor
from identity.trust_registry import TrustRegistry


def test_out_of_network_clinician_validates_against_shared_root(
    root: RootAnchor,
    facility_a_keys: tuple,
    facility_b_keys: tuple,
    facility_a_ca_cert: object,
    facility_b_ca_cert: object,
    clinician_at_facility_a_cert: object,
) -> None:
    """P2-1 exit criterion: facility-b can validate a clinician enrolled at facility-a.

    facility-b never enrolled this clinician and holds no direct relationship
    with facility-a; it only trusts the shared root. This is what
    "cross-certification" buys the federation (ARCHITECTURE.md §5 step 1).
    """
    registry_at_facility_b = TrustRegistry(root=root)
    registry_at_facility_b.register_facility("facility-a", facility_a_ca_cert)
    registry_at_facility_b.register_facility("facility-b", facility_b_ca_cert)

    registry_at_facility_b.validate_clinician_certificate(
        clinician_at_facility_a_cert, enrolling_facility_id="facility-a"
    )


def test_unknown_facility_rejected(
    root: RootAnchor, clinician_at_facility_a_cert: object
) -> None:
    """A clinician claiming enrollment at an unregistered facility is refused."""
    registry = TrustRegistry(root=root)

    with pytest.raises(UnknownFacilityError):
        registry.validate_clinician_certificate(
            clinician_at_facility_a_cert, enrolling_facility_id="facility-unknown"
        )


def test_registry_refuses_to_register_ca_not_signed_by_its_root() -> None:
    """Registering a facility CA not actually signed by this registry's root must fail.

    Prevents a compromised or careless caller from adding a facility whose CA
    key was never certified by the federation's real root.
    """
    real_root = generate_root_anchor()
    other_root = generate_root_anchor()
    _, rogue_facility_pk = generate_ec_keypair()
    rogue_ca_cert = issue_facility_ca_certificate(
        other_root, "facility-a", rogue_facility_pk
    )

    registry = TrustRegistry(root=real_root)
    with pytest.raises(InvalidSignatureError):
        registry.register_facility("facility-a", rogue_ca_cert)


def test_forged_clinician_certificate_rejected(
    root: RootAnchor, facility_a_ca_cert: object
) -> None:
    """A clinician certificate not signed by the claimed facility CA is refused."""
    registry = TrustRegistry(root=root)
    registry.register_facility("facility-a", facility_a_ca_cert)

    forger_sk, _ = generate_ec_keypair()
    _, clinician_pk = generate_ec_keypair()
    forged_cert = issue_clinician_certificate(
        forger_sk, facility_a_ca_cert, "dr-forged", clinician_pk
    )

    with pytest.raises(InvalidSignatureError):
        registry.validate_clinician_certificate(
            forged_cert, enrolling_facility_id="facility-a"
        )
