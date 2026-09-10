"""Unit tests for repository consent-grant listing (P4-7 backend support).

``list_consent_grants_by_patient`` powers the patient portal's "who has access"
view. These tests verify it returns every grant for a patient regardless of
status, and -- the isolation property that matters -- never returns another
patient's grants.
"""

from __future__ import annotations

from api.repository import InMemoryStorageRepository
from consent.service import create_consent_grant, create_consent_request
from contracts.enums import ConsentStatus
from crypto_core import generate_ec_keypair


def _grant(patient_id: str, grantee_id: str, status: ConsentStatus):
    requester_priv, _ = generate_ec_keypair()
    patient_priv, _ = generate_ec_keypair()
    req = create_consent_request(
        patient_id=patient_id,
        requester_id=grantee_id,
        scope=("rec-1",),
        purpose="test",
        requester_signing_key=requester_priv,
    )
    return create_consent_grant(
        request=req,
        status=status,
        grantee_id=grantee_id,
        patient_signing_key=patient_priv,
    )


def test_lists_all_grants_for_a_patient_regardless_of_status():
    repo = InMemoryStorageRepository()
    granted = _grant("patient-001", "dr-alice", ConsentStatus.GRANTED)
    denied = _grant("patient-001", "dr-bob", ConsentStatus.DENIED)
    revoked = _grant("patient-001", "dr-carol", ConsentStatus.REVOKED)
    for g in (granted, denied, revoked):
        repo.store_consent_grant(g)

    result = repo.list_consent_grants_by_patient("patient-001")

    assert {g.grant_id for g in result} == {
        granted.grant_id,
        denied.grant_id,
        revoked.grant_id,
    }


def test_never_returns_another_patients_grants():
    """Isolation: a patient's listing must not leak grants about someone else."""
    repo = InMemoryStorageRepository()
    mine = _grant("patient-001", "dr-alice", ConsentStatus.GRANTED)
    someone_else = _grant("patient-999", "dr-alice", ConsentStatus.GRANTED)
    repo.store_consent_grant(mine)
    repo.store_consent_grant(someone_else)

    result = repo.list_consent_grants_by_patient("patient-001")

    assert [g.grant_id for g in result] == [mine.grant_id]
    assert all(g.patient_id == "patient-001" for g in result)


def test_empty_when_patient_has_no_grants():
    repo = InMemoryStorageRepository()
    assert repo.list_consent_grants_by_patient("patient-unknown") == []
