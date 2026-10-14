"""Negative security tests for P3-10 / P3-11 emergency assertion and replay defense.

Backs the P3-10 exit criteria in WORKFLOW.md ("unsigned or unbound assertions
are rejected and break-glass refuses to proceed without one") and the P3-11
exit criteria ("a replayed request is rejected, not re-run").

Each test states the paper claim it backs and includes a positive control in
the same fixture so a broken setup cannot masquerade as a passing test.

Adversarial cases proved here:

- Field tampering: mutating any assertion field (patient_id, clinician_id,
  facility_id, reason_code, issued_at, expires_at, nonce) breaks signature
  verification.
- Untrusted certificate: presenting a cert not rooted in the trusted anchor
  is rejected.
- Clinician mismatch: cert CN ≠ assertion.clinician_id is rejected.
- Facility mismatch: assertion presented at wrong facility is rejected.
- Expired assertion: assertion past expires_at is rejected.
- Replay attack: replayed assertion_id is rejected.
- Order of operations: forged assertion does not burn legitimate IDs.
- Wrong signer: valid cert but different key than the assertion signer.
- Envelope field tampering: mutating envelope fields breaks verification.
- Envelope retargeting: envelope addressed to one service rejected at another.
"""

from __future__ import annotations

import datetime

import pytest
from breakglass import (
    AssertionExpiredError,
    ClinicianMismatchError,
    ConsumedAssertionIds,
    ConsumedRequestIds,
    EnvelopeRecipientMismatchError,
    FacilityMismatchError,
    ReplayedAssertionError,
    ReplayedRequestError,
    create_emergency_assertion,
    create_request_envelope,
    validate_emergency_assertion,
    verify_request_envelope,
)
from breakglass.assertion import MAX_ASSERTION_TTL
from breakglass.exceptions import AssertionLifetimeError
from contracts.enums import ReasonCode
from crypto_core import InvalidSignatureError, generate_ec_keypair
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.exceptions import ChainValidationError
from identity.root_anchor import generate_root_anchor

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def federation():
    """Two-facility federation with one clinician each."""
    root = generate_root_anchor()

    fa_priv, fa_pub = generate_ec_keypair()
    fa_cert = issue_facility_ca_certificate(root, "facility-a", fa_pub)

    fb_priv, fb_pub = generate_ec_keypair()
    fb_cert = issue_facility_ca_certificate(root, "facility-b", fb_pub)

    cl_priv, cl_pub = generate_ec_keypair()
    cl_cert = issue_clinician_certificate(fa_priv, fa_cert, "dr-alice", cl_pub)

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


def _valid_assertion(federation, **overrides):
    """Helper: produce a valid assertion with optional field overrides."""
    defaults = dict(
        patient_id="patient-001",
        clinician_id="dr-alice",
        facility_id="facility-a",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        signing_key=federation["cl_priv"],
    )
    defaults.update(overrides)
    return create_emergency_assertion(**defaults)


def _validate(federation, assertion, **overrides):
    """Helper: run full validation with optional param overrides."""
    defaults = dict(
        assertion=assertion,
        clinician_certificate=federation["cl_cert"],
        facility_ca_certificate=federation["fa_cert"],
        trusted_root=federation["root"].certificate,
        expected_facility_id="facility-a",
        consumed_store=ConsumedAssertionIds(),
        revoked_serials=frozenset(),
    )
    defaults.update(overrides)
    validate_emergency_assertion(**defaults)


# ---------------------------------------------------------------------------
# Field tampering (ARCHITECTURE §8 payload integrity)
# ---------------------------------------------------------------------------


class TestAssertionFieldTampering:
    """Paper claim: mutating any assertion field invalidates the signature.

    A positive control precedes each tamper test so a broken fixture cannot
    masquerade as a passing test.
    """

    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("patient_id", "patient-EVIL"),
            ("clinician_id", "dr-evil"),
            ("facility_id", "facility-evil"),
            ("reason_code", ReasonCode.CARDIAC_ARREST),
        ],
    )
    def test_field_tamper_rejected(self, federation, field, bad_value):
        assertion = _valid_assertion(federation)
        # Positive control
        _validate(federation, assertion)
        # Tamper
        tampered = assertion.model_copy(update={field: bad_value})
        with pytest.raises(InvalidSignatureError):
            _validate(federation, tampered)

    def test_tamper_issued_at(self, federation):
        assertion = _valid_assertion(federation)
        _validate(federation, assertion)
        future = assertion.issued_at + datetime.timedelta(hours=1)
        tampered = assertion.model_copy(update={"issued_at": future})
        with pytest.raises(InvalidSignatureError):
            _validate(federation, tampered)

    def test_tamper_expires_at(self, federation):
        assertion = _valid_assertion(federation)
        _validate(federation, assertion)
        far_future = assertion.expires_at + datetime.timedelta(days=365)
        tampered = assertion.model_copy(update={"expires_at": far_future})
        with pytest.raises(InvalidSignatureError):
            _validate(federation, tampered)

    def test_tamper_nonce(self, federation):
        assertion = _valid_assertion(federation)
        _validate(federation, assertion)
        bad_nonce = b"\xff" * 16
        tampered = assertion.model_copy(update={"nonce": bad_nonce})
        with pytest.raises(InvalidSignatureError):
            _validate(federation, tampered)


# ---------------------------------------------------------------------------
# Certificate chain (ARCHITECTURE §8 step 1-2)
# ---------------------------------------------------------------------------


class TestUntrustedCertificate:
    """Paper claim: a cert not rooted in the trusted anchor is rejected."""

    def test_forged_root_rejected(self, federation):
        """Clinician cert from a different PKI is rejected."""
        assertion = _valid_assertion(federation)
        # Positive control
        _validate(federation, assertion)

        # Build a completely independent PKI
        evil_root = generate_root_anchor()
        evil_fa_priv, evil_fa_pub = generate_ec_keypair()
        evil_fa_cert = issue_facility_ca_certificate(
            evil_root, "facility-a", evil_fa_pub
        )
        evil_cl_priv, evil_cl_pub = generate_ec_keypair()
        evil_cl_cert = issue_clinician_certificate(
            evil_fa_priv, evil_fa_cert, "dr-alice", evil_cl_pub
        )

        # Sign a new assertion with the evil key so signature is valid
        evil_assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=evil_cl_priv,
        )
        # Validation against the REAL root must fail
        with pytest.raises((InvalidSignatureError, ChainValidationError)):
            validate_emergency_assertion(
                assertion=evil_assertion,
                clinician_certificate=evil_cl_cert,
                facility_ca_certificate=evil_fa_cert,
                trusted_root=federation["root"].certificate,
                expected_facility_id="facility-a",
                consumed_store=ConsumedAssertionIds(),
                revoked_serials=frozenset(),
            )

    def test_wrong_signer_rejected(self, federation):
        """Assertion signed by a different clinician's key than the presenting cert."""
        assertion = _valid_assertion(federation)
        _validate(federation, assertion)

        # Present dr-bob's cert but the assertion was signed by dr-alice's key
        with pytest.raises(InvalidSignatureError):
            validate_emergency_assertion(
                assertion=assertion,
                clinician_certificate=federation["cl2_cert"],
                facility_ca_certificate=federation["fb_cert"],
                trusted_root=federation["root"].certificate,
                expected_facility_id="facility-a",
                consumed_store=ConsumedAssertionIds(),
                revoked_serials=frozenset(),
            )


# ---------------------------------------------------------------------------
# Clinician mismatch (ARCHITECTURE §8 step 3)
# ---------------------------------------------------------------------------


class TestClinicianMismatch:
    """Paper claim: assertion.clinician_id must match the presenting cert's CN."""

    def test_mismatch_rejected(self, federation):
        assertion = _valid_assertion(federation)
        _validate(federation, assertion)

        # Build a cert with a different CN but signed by the same facility CA
        other_priv, other_pub = generate_ec_keypair()
        other_cert = issue_clinician_certificate(
            federation["fa_priv"],
            federation["fa_cert"],
            "dr-other",
            other_pub,
        )

        # Sign a valid assertion claiming to be dr-alice, but present dr-other's cert
        # Signature will fail because keys differ, but even if we construct it
        # to pass signature (by signing with other_priv but claiming dr-alice),
        # the CN check catches it.
        assertion_for_other = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",  # claims to be dr-alice
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=other_priv,  # signed with dr-other's key
        )
        # Signature is valid against dr-other's cert, but clinician_id mismatch
        with pytest.raises(ClinicianMismatchError):
            validate_emergency_assertion(
                assertion=assertion_for_other,
                clinician_certificate=other_cert,
                facility_ca_certificate=federation["fa_cert"],
                trusted_root=federation["root"].certificate,
                expected_facility_id="facility-a",
                consumed_store=ConsumedAssertionIds(),
                revoked_serials=frozenset(),
            )


# ---------------------------------------------------------------------------
# Facility mismatch (ARCHITECTURE §8 step 4)
# ---------------------------------------------------------------------------


class TestFacilityMismatch:
    """Paper claim: assertion presented at the wrong facility is rejected."""

    def test_wrong_facility_rejected(self, federation):
        assertion = _valid_assertion(federation)
        _validate(federation, assertion)

        with pytest.raises(FacilityMismatchError):
            validate_emergency_assertion(
                assertion=assertion,
                clinician_certificate=federation["cl_cert"],
                facility_ca_certificate=federation["fa_cert"],
                trusted_root=federation["root"].certificate,
                expected_facility_id="facility-b",  # wrong facility,
                consumed_store=ConsumedAssertionIds(),
                revoked_serials=frozenset(),
            )


# ---------------------------------------------------------------------------
# Expiry (ARCHITECTURE §8 step 5)
# ---------------------------------------------------------------------------


class TestAssertionExpiry:
    """Paper claim: an assertion past its expires_at is rejected."""

    def test_expired_assertion_rejected(self, federation):
        now = datetime.datetime.now(datetime.timezone.utc)
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation["cl_priv"],
            issued_at=now - datetime.timedelta(hours=2),
            expires_at=now - datetime.timedelta(hours=1),
        )
        with pytest.raises(AssertionExpiredError):
            _validate(federation, assertion)

    def test_assertion_at_exact_expiry_rejected(self, federation):
        """expires_at == now is rejected (must be strictly in the future)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation["cl_priv"],
            issued_at=now - datetime.timedelta(minutes=5),
            expires_at=now,
        )
        with pytest.raises(AssertionExpiredError):
            validate_emergency_assertion(
                assertion=assertion,
                clinician_certificate=federation["cl_cert"],
                facility_ca_certificate=federation["fa_cert"],
                trusted_root=federation["root"].certificate,
                expected_facility_id="facility-a",
                at=now,
                consumed_store=ConsumedAssertionIds(),
                revoked_serials=frozenset(),
            )


class TestAssertionLifetime:
    """Paper claim (F6): an assertion is short-lived, never a standing permission.

    The maximum lifetime is 3 days (team choice); the issue time may be at
    most 30 seconds in the future to tolerate clock drift.
    """

    def _assertion(self, federation, issued_at, expires_at):
        return create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation["cl_priv"],
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def test_assertion_at_the_three_day_limit_accepted(self, federation):
        """Setup is valid: exactly the maximum lifetime passes."""
        now = datetime.datetime.now(datetime.timezone.utc)
        _validate(
            federation,
            self._assertion(federation, now, now + MAX_ASSERTION_TTL),
        )

    def test_assertion_with_ten_year_lifetime_rejected(self, federation):
        now = datetime.datetime.now(datetime.timezone.utc)
        assertion = self._assertion(
            federation, now, now + datetime.timedelta(days=3650)
        )
        with pytest.raises(AssertionLifetimeError, match="exceeds the maximum"):
            _validate(federation, assertion)

    def test_assertion_one_second_over_three_days_rejected(self, federation):
        now = datetime.datetime.now(datetime.timezone.utc)
        assertion = self._assertion(
            federation,
            now,
            now + MAX_ASSERTION_TTL + datetime.timedelta(seconds=1),
        )
        with pytest.raises(AssertionLifetimeError):
            _validate(federation, assertion)

    def test_future_dated_assertion_rejected(self, federation):
        now = datetime.datetime.now(datetime.timezone.utc)
        assertion = self._assertion(
            federation,
            now + datetime.timedelta(minutes=5),
            now + datetime.timedelta(minutes=10),
        )
        with pytest.raises(AssertionLifetimeError, match="in the future"):
            _validate(federation, assertion)

    def test_rejected_lifetime_does_not_burn_the_assertion_id(self, federation):
        """A refused assertion's id is not consumed (ADR-0030 ordering)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        store = ConsumedAssertionIds()
        assertion = self._assertion(
            federation, now, now + datetime.timedelta(days=3650)
        )
        with pytest.raises(AssertionLifetimeError):
            _validate(federation, assertion, consumed_store=store)
        assert not store.has_seen(assertion.assertion_id)


# ---------------------------------------------------------------------------
# Replay (ARCHITECTURE §8 replay protection, P3-11)
# ---------------------------------------------------------------------------


class TestAssertionReplay:
    """Paper claim: a replayed assertion is rejected, not re-run."""

    @pytest.mark.claim("C8", level="module")
    def test_replay_rejected(self, federation):
        store = ConsumedAssertionIds()
        assertion = _valid_assertion(federation)
        _validate(federation, assertion, consumed_store=store)
        # Second presentation of the same assertion
        with pytest.raises(ReplayedAssertionError):
            _validate(federation, assertion, consumed_store=store)

    def test_forged_assertion_does_not_burn_legitimate_id(self, federation):
        """ADR-0030 §4: consumption after signature → a forged message cannot
        burn a legitimate ID from a future re-sign.
        """
        store = ConsumedAssertionIds()
        assertion = _valid_assertion(federation)

        # Build a tampered assertion with the same assertion_id
        tampered = assertion.model_copy(update={"patient_id": "patient-EVIL"})

        # Tampered assertion fails at signature check
        with pytest.raises(InvalidSignatureError):
            _validate(federation, tampered, consumed_store=store)

        # The legitimate ID was NOT burned
        assert not store.has_seen(assertion.assertion_id)

        # The real assertion still works
        _validate(federation, assertion, consumed_store=store)
        assert store.has_seen(assertion.assertion_id)


# ---------------------------------------------------------------------------
# Request envelope security (P3-11)
# ---------------------------------------------------------------------------


class TestEnvelopeSecurity:
    """Adversarial tests for request envelope integrity and replay."""

    def test_tampered_body_rejected(self):
        priv, pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="request_share",
            body=b"legitimate-payload",
            signing_key=priv,
        )
        # Positive control
        verify_request_envelope(
            envelope, pub, "audit-service", consumed_store=ConsumedRequestIds()
        )

        tampered = envelope.model_copy(update={"body": b"evil-payload"})
        with pytest.raises(InvalidSignatureError):
            verify_request_envelope(
                tampered, pub, "audit-service", consumed_store=ConsumedRequestIds()
            )

    def test_tampered_operation_rejected(self):
        priv, pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="request_share",
            body=b"data",
            signing_key=priv,
        )
        tampered = envelope.model_copy(update={"operation": "grant_admin"})
        with pytest.raises(InvalidSignatureError):
            verify_request_envelope(
                tampered, pub, "audit-service", consumed_store=ConsumedRequestIds()
            )

    def test_tampered_caller_rejected(self):
        priv, pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="op",
            body=b"data",
            signing_key=priv,
        )
        tampered = envelope.model_copy(update={"caller_id": "facility-evil"})
        with pytest.raises(InvalidSignatureError):
            verify_request_envelope(
                tampered, pub, "audit-service", consumed_store=ConsumedRequestIds()
            )

    def test_retargeted_envelope_rejected(self):
        priv, pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="op",
            body=b"data",
            signing_key=priv,
        )
        # Signature is valid but recipient is wrong
        with pytest.raises(EnvelopeRecipientMismatchError):
            verify_request_envelope(
                envelope, pub, "authority-med", consumed_store=ConsumedRequestIds()
            )

    def test_envelope_replay_rejected(self):
        priv, pub = generate_ec_keypair()
        store = ConsumedRequestIds()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit",
            operation="op",
            body=b"data",
            signing_key=priv,
        )
        verify_request_envelope(envelope, pub, "audit", consumed_store=store)
        with pytest.raises(ReplayedRequestError):
            verify_request_envelope(envelope, pub, "audit", consumed_store=store)

    def test_forged_envelope_does_not_burn_legitimate_id(self):
        """Forged envelope fails at signature → does not consume the request_id."""
        priv, pub = generate_ec_keypair()
        store = ConsumedRequestIds()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit",
            operation="op",
            body=b"data",
            signing_key=priv,
        )
        tampered = envelope.model_copy(update={"body": b"evil"})

        with pytest.raises(InvalidSignatureError):
            verify_request_envelope(tampered, pub, "audit", consumed_store=store)

        # ID was not burned
        assert not store.has_seen(envelope.request_id)

        # Real envelope still works
        verify_request_envelope(envelope, pub, "audit", consumed_store=store)

    def test_wrong_signer_rejected(self):
        priv, pub = generate_ec_keypair()
        other_priv, other_pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit",
            operation="op",
            body=b"data",
            signing_key=priv,
        )
        with pytest.raises(InvalidSignatureError):
            verify_request_envelope(
                envelope, other_pub, "audit", consumed_store=ConsumedRequestIds()
            )
