"""Negative security tests for Phase 2 federation/identity primitives (CONVENTIONS §5).

Backs the P2-1 and P2-2 exit criteria in WORKFLOW.md: an out-of-network
clinician's certificate validates via cross-certification and a forged one is
rejected; two independent authorities issue valid attribute credentials and a
forged one is rejected.
"""

from __future__ import annotations

import datetime

import pytest
from authority.exceptions import UnauthorizedAttributeError
from authority.issuance import generate_authority, issue_credential, verify_credential
from authority.revocation import RevocationRegistry
from contracts import Attribute
from crypto_core import InvalidSignatureError, generate_ec_keypair
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.chain import validate_chain
from identity.exceptions import ChainValidationError
from identity.root_anchor import generate_root_anchor
from identity.trust_registry import TrustRegistry


def test_sec_out_of_network_clinician_validates_via_cross_certification() -> None:
    """Security property: cross-certification lets facility-b trust a facility-a doctor.

    Backs the P2-1 claim -- an out-of-network doctor's certificate validates
    against the shared root without facility-b having any prior relationship
    with facility-a beyond both trusting the same root anchor (ADR-0019).
    """
    root = generate_root_anchor()
    facility_a_sk, facility_a_pk = generate_ec_keypair()
    _, facility_b_pk = generate_ec_keypair()
    facility_a_cert = issue_facility_ca_certificate(root, "facility-a", facility_a_pk)
    facility_b_cert = issue_facility_ca_certificate(root, "facility-b", facility_b_pk)

    _, clinician_pk = generate_ec_keypair()
    clinician_cert = issue_clinician_certificate(
        facility_a_sk, facility_a_cert, "dr-jane-doe", clinician_pk
    )

    registry_at_facility_b = TrustRegistry(root=root)
    registry_at_facility_b.register_facility("facility-a", facility_a_cert)
    registry_at_facility_b.register_facility("facility-b", facility_b_cert)

    # Positive control: the legitimate chain validates.
    registry_at_facility_b.validate_clinician_certificate(
        clinician_cert, enrolling_facility_id="facility-a"
    )


def test_sec_forged_certificate_rejected_by_a_different_root() -> None:
    """Security property: a chain anchored at an attacker's own root is rejected.

    Backs the P2-1 claim "a forged one is rejected" -- an attacker who can
    run their own CA and issue an internally-consistent chain still cannot
    pass validation against the federation's real trusted root.
    """
    real_root = generate_root_anchor()
    attacker_root = generate_root_anchor()

    forged_facility_sk, forged_facility_pk = generate_ec_keypair()
    forged_facility_cert = issue_facility_ca_certificate(
        attacker_root, "facility-a", forged_facility_pk
    )

    _, clinician_pk = generate_ec_keypair()
    forged_clinician_cert = issue_clinician_certificate(
        forged_facility_sk, forged_facility_cert, "dr-forged", clinician_pk
    )

    with pytest.raises((InvalidSignatureError, ChainValidationError)):
        validate_chain(
            forged_clinician_cert, [forged_facility_cert], real_root.certificate
        )


def test_sec_two_authorities_issue_valid_credentials_forgery_rejected() -> None:
    """Security property backing P2-2: two authorities issue validly, forgery does not.

    Positive control (two independent authorities issuing real credentials)
    is asserted in the same test as the negative case, so the negative
    assertion cannot pass merely because the setup itself was broken.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from, valid_until = (
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=365),
    )

    authority_med = generate_authority("authority-med", frozenset({"role"}))
    authority_net = generate_authority(
        "authority-net", frozenset({"specialty", "owner"})
    )

    med_cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )
    net_cred = issue_credential(
        authority_net,
        "dr-jane-doe",
        Attribute(name="specialty", value="cardiology"),
        valid_from,
        valid_until,
    )

    # Positive control: both real credentials verify under their own issuer.
    verify_credential(
        med_cred, authority_med.public_key, revocation_registry=RevocationRegistry()
    )
    verify_credential(
        net_cred, authority_net.public_key, revocation_registry=RevocationRegistry()
    )

    # Negative: a credential forged by altering the subject after issuance
    # fails signature verification against the real issuer.
    forged = med_cred.model_copy(update={"subject_id": "dr-attacker"})
    with pytest.raises(InvalidSignatureError):
        verify_credential(
            forged, authority_med.public_key, revocation_registry=RevocationRegistry()
        )

    # Negative: an authority cannot mint outside its own attribute namespace.
    with pytest.raises(UnauthorizedAttributeError):
        issue_credential(
            authority_med,
            "dr-jane-doe",
            Attribute(name="specialty", value="cardiology"),
            valid_from,
            valid_until,
        )
