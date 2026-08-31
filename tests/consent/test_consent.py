"""Unit tests for the patient-consent request/approve/revoke flow (P3-2).

Covers request-then-approve round-trips, canonical-payload sensitivity, and
the semantics of the :func:`authorize_read` gate. End-to-end reads through the
policy path and negative security cases live in
``tests/security/test_phase3_consent_security.py``.
"""

from __future__ import annotations

import datetime

import pytest
from consent import (
    ConsentDeniedError,
    ConsentExpiredError,
    ConsentRevokedError,
    ConsentScopeError,
    ConsentSubjectError,
    authorize_read,
    create_consent_grant,
    create_consent_request,
    revoke_consent_grant,
    verify_consent_grant,
    verify_consent_request,
)
from contracts.enums import ConsentStatus
from crypto_core import InvalidSignatureError, generate_ec_keypair

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def patient_keys():
    return generate_ec_keypair()


@pytest.fixture
def clinician_keys():
    return generate_ec_keypair()


@pytest.fixture
def sample_request(clinician_keys):
    clinician_sk, _ = clinician_keys
    return create_consent_request(
        patient_id="pat-101",
        requester_id="dr-alice",
        scope=("rec-1", "rec-2"),
        purpose="Follow-up cardiology consult",
        requester_signing_key=clinician_sk,
    )


@pytest.fixture
def sample_grant(sample_request, patient_keys):
    patient_sk, _ = patient_keys
    return create_consent_grant(
        request=sample_request,
        status=ConsentStatus.GRANTED,
        grantee_id="dr-alice",
        patient_signing_key=patient_sk,
    )


# ---------------------------------------------------------------------------
# Request-side round-trip
# ---------------------------------------------------------------------------


def test_create_and_verify_consent_request(sample_request, clinician_keys):
    _, clinician_pk = clinician_keys
    verify_consent_request(sample_request, clinician_pk)
    assert sample_request.requester_id == "dr-alice"
    assert sample_request.scope == ("rec-1", "rec-2")
    assert sample_request.expires_at > sample_request.requested_at


def test_expired_request_raises(sample_request, clinician_keys):
    _, clinician_pk = clinician_keys
    future = sample_request.expires_at + datetime.timedelta(seconds=1)
    with pytest.raises(ConsentExpiredError):
        verify_consent_request(sample_request, clinician_pk, at=future)


def test_request_signature_verified_by_owner_key_only(sample_request, clinician_keys):
    _, wrong_pk = generate_ec_keypair()
    with pytest.raises(InvalidSignatureError):
        verify_consent_request(sample_request, wrong_pk)


# ---------------------------------------------------------------------------
# Grant-side round-trip
# ---------------------------------------------------------------------------


def test_create_and_verify_consent_grant(sample_grant, patient_keys):
    _, patient_pk = patient_keys
    verify_consent_grant(sample_grant, patient_pk)
    assert sample_grant.status is ConsentStatus.GRANTED
    assert sample_grant.grantee_id == "dr-alice"


def test_grant_scope_defaults_to_request_scope(sample_request, patient_keys):
    patient_sk, _ = patient_keys
    grant = create_consent_grant(
        request=sample_request,
        status=ConsentStatus.GRANTED,
        grantee_id=sample_request.requester_id,
        patient_signing_key=patient_sk,
    )
    assert grant.scope == sample_request.scope


def test_grant_scope_can_be_narrowed(sample_request, patient_keys):
    patient_sk, _ = patient_keys
    grant = create_consent_grant(
        request=sample_request,
        status=ConsentStatus.GRANTED,
        grantee_id=sample_request.requester_id,
        scope=("rec-1",),
        patient_signing_key=patient_sk,
    )
    assert grant.scope == ("rec-1",)


def test_grant_scope_cannot_be_widened(sample_request, patient_keys):
    patient_sk, _ = patient_keys
    with pytest.raises(ConsentScopeError):
        create_consent_grant(
            request=sample_request,
            status=ConsentStatus.GRANTED,
            grantee_id=sample_request.requester_id,
            scope=("rec-1", "rec-2", "rec-999"),
            patient_signing_key=patient_sk,
        )


# ---------------------------------------------------------------------------
# authorize_read gate
# ---------------------------------------------------------------------------


def test_authorize_read_accepts_in_scope_within_window(sample_grant, patient_keys):
    _, patient_pk = patient_keys
    authorize_read(
        sample_grant,
        record_id="rec-1",
        grantee_id="dr-alice",
        patient_public_key=patient_pk,
    )  # no return; either passes or raises


def test_authorize_read_refuses_out_of_scope(sample_grant, patient_keys):
    _, patient_pk = patient_keys
    with pytest.raises(ConsentScopeError):
        authorize_read(
            sample_grant,
            record_id="rec-99",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
        )


def test_authorize_read_refuses_wrong_grantee(sample_grant, patient_keys):
    _, patient_pk = patient_keys
    with pytest.raises(ConsentSubjectError):
        authorize_read(
            sample_grant,
            record_id="rec-1",
            grantee_id="dr-bob",
            patient_public_key=patient_pk,
        )


def test_authorize_read_refuses_after_expiry(sample_grant, patient_keys):
    _, patient_pk = patient_keys
    late = sample_grant.expires_at + datetime.timedelta(seconds=1)
    with pytest.raises(ConsentExpiredError):
        authorize_read(
            sample_grant,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
            at=late,
        )


def test_authorize_read_refuses_denied_grant(sample_request, patient_keys):
    patient_sk, patient_pk = patient_keys
    denial = create_consent_grant(
        request=sample_request,
        status=ConsentStatus.DENIED,
        grantee_id="dr-alice",
        patient_signing_key=patient_sk,
    )
    with pytest.raises(ConsentDeniedError):
        authorize_read(
            denial,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
        )


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def test_revocation_produces_signed_grant_with_revoked_status(
    sample_grant, patient_keys
):
    patient_sk, patient_pk = patient_keys
    revocation = revoke_consent_grant(
        prior_grant=sample_grant,
        patient_signing_key=patient_sk,
    )
    verify_consent_grant(revocation, patient_pk)
    assert revocation.status is ConsentStatus.REVOKED
    assert revocation.request_id == sample_grant.request_id
    assert revocation.grantee_id == sample_grant.grantee_id
    assert revocation.grant_id != sample_grant.grant_id


def test_authorize_read_refuses_revoked_grant(sample_grant, patient_keys):
    patient_sk, patient_pk = patient_keys
    revocation = revoke_consent_grant(
        prior_grant=sample_grant,
        patient_signing_key=patient_sk,
    )
    with pytest.raises(ConsentRevokedError):
        authorize_read(
            revocation,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
        )
