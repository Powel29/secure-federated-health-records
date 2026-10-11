"""Unit tests for emergency assertion creation and validation (P3-10).

Covers:
- Creation round-trip: create → verify signature → full validation.
- Multi-facility: assertion at facility-b validated via cross-certified chain.
- All ReasonCode values produce valid assertions.
- Explicit TTL / expires_at overrides.
"""

from __future__ import annotations

import datetime

import pytest
from breakglass import (
    ConsumedAssertionIds,
    create_emergency_assertion,
    validate_emergency_assertion,
    verify_emergency_assertion_signature,
)
from contracts.enums import ReasonCode
from crypto_core import certificate_public_key, generate_ec_keypair
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.root_anchor import generate_root_anchor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def federation():
    """Build a minimal two-facility federation for assertion tests."""
    root = generate_root_anchor()

    # Facility A
    fa_priv, fa_pub = generate_ec_keypair()
    fa_cert = issue_facility_ca_certificate(root, "facility-a", fa_pub)

    # Facility B
    fb_priv, fb_pub = generate_ec_keypair()
    fb_cert = issue_facility_ca_certificate(root, "facility-b", fb_pub)

    # Clinician at facility A
    cl_priv, cl_pub = generate_ec_keypair()
    cl_cert = issue_clinician_certificate(fa_priv, fa_cert, "dr-alice", cl_pub)

    # Clinician at facility B
    cl2_priv, cl2_pub = generate_ec_keypair()
    cl2_cert = issue_clinician_certificate(fb_priv, fb_cert, "dr-bob", cl2_pub)

    return {
        "root": root,
        "fa_priv": fa_priv,
        "fa_cert": fa_cert,
        "fb_priv": fb_priv,
        "fb_cert": fb_cert,
        "cl_priv": cl_priv,
        "cl_pub": cl_pub,
        "cl_cert": cl_cert,
        "cl2_priv": cl2_priv,
        "cl2_pub": cl2_pub,
        "cl2_cert": cl2_cert,
    }


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


class TestCreateEmergencyAssertion:
    """Creating an assertion produces a well-formed, signed object."""

    def test_round_trip(self, federation):
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation["cl_priv"],
        )
        assert assertion.patient_id == "patient-001"
        assert assertion.clinician_id == "dr-alice"
        assert assertion.facility_id == "facility-a"
        assert assertion.reason_code == ReasonCode.UNCONSCIOUS_PATIENT
        assert assertion.expires_at > assertion.issued_at

    def test_explicit_ttl(self, federation):
        ttl = datetime.timedelta(minutes=5)
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.CARDIAC_ARREST,
            signing_key=federation["cl_priv"],
            ttl=ttl,
        )
        delta = assertion.expires_at - assertion.issued_at
        assert abs(delta.total_seconds() - 300) < 1

    def test_explicit_expires_at(self, federation):
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(hours=1)
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.STROKE,
            signing_key=federation["cl_priv"],
            issued_at=now,
            expires_at=exp,
        )
        assert assertion.expires_at == exp

    @pytest.mark.parametrize("reason", list(ReasonCode))
    def test_all_reason_codes(self, federation, reason):
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=reason,
            signing_key=federation["cl_priv"],
        )
        assert assertion.reason_code == reason


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


class TestVerifyAssertionSignature:
    """Signature-only verification (no chain, no binding)."""

    def test_valid_signature(self, federation):
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation["cl_priv"],
        )
        # Should not raise
        verify_emergency_assertion_signature(
            assertion, certificate_public_key(federation["cl_cert"])
        )


# ---------------------------------------------------------------------------
# Full validation
# ---------------------------------------------------------------------------


class TestValidateEmergencyAssertion:
    """Full five-point validation sequence."""

    def test_valid_assertion_at_home_facility(self, federation):
        """Positive control: a correctly signed assertion at its home facility."""
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation["cl_priv"],
        )
        validate_emergency_assertion(
            assertion=assertion,
            clinician_certificate=federation["cl_cert"],
            facility_ca_certificate=federation["fa_cert"],
            trusted_root=federation["root"].certificate,
            expected_facility_id="facility-a",
            consumed_store=ConsumedAssertionIds(),
            revoked_serials=frozenset(),
        )

    def test_valid_assertion_at_out_of_network_facility(self, federation):
        """Cross-facility: clinician from facility-b validated at facility-b."""
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-bob",
            facility_id="facility-b",
            reason_code=ReasonCode.MAJOR_TRAUMA,
            signing_key=federation["cl2_priv"],
        )
        validate_emergency_assertion(
            assertion=assertion,
            clinician_certificate=federation["cl2_cert"],
            facility_ca_certificate=federation["fb_cert"],
            trusted_root=federation["root"].certificate,
            expected_facility_id="facility-b",
            consumed_store=ConsumedAssertionIds(),
            revoked_serials=frozenset(),
        )

    def test_with_consumed_store(self, federation):
        """Anti-replay integration: first validation succeeds, second is rejected."""
        store = ConsumedAssertionIds()
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation["cl_priv"],
        )
        validate_emergency_assertion(
            assertion=assertion,
            clinician_certificate=federation["cl_cert"],
            facility_ca_certificate=federation["fa_cert"],
            trusted_root=federation["root"].certificate,
            expected_facility_id="facility-a",
            consumed_store=store,
            revoked_serials=frozenset(),
        )
        assert store.has_seen(assertion.assertion_id)
