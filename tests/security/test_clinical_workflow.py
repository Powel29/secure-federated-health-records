"""Clinical review controls: real threshold/consent paths, synthetic data only."""

from __future__ import annotations

import datetime
import json

import pytest
from breakglass.assertion import (
    clinical_context_digest,
    create_emergency_assertion,
    validate_clinical_context,
)
from contracts.clinical import ClinicalMetadata
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import generate_ec_keypair
from pre.elgamal import generate_keypair
from pydantic import ValidationError

from tests.api.test_custodian_service import (
    DOC_CARDIO,
    DOC_ER,
    PATIENT,
    RECORD,
    _custodian,
    _deposit_all,
    _upload,
    federation,
)

# Imported fixture is intentionally exposed to pytest in this module.
__all__ = ["federation"]


def _grant(client, clinician, record_id):
    request = client.post(
        f"/subjects/{clinician}/consent/request",
        json={
            "patient_id": PATIENT,
            "scope": [record_id],
            "purpose": "Treating this patient during the current care episode",
        },
    )
    assert request.status_code == 200, request.text
    response = client.post(
        f"/subjects/{PATIENT}/consent/decide",
        json={"request": request.json()["request"], "status": "granted"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_revoked_episode_cannot_be_reopened_with_the_old_grant(federation):
    """A stored revocation defeats replay of the previously valid signed grant."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    signed = _grant(client, DOC_CARDIO, RECORD)
    body = {"record_id": RECORD, "facility_id": "facility-a", "grant": signed["grant"]}
    assert client.post(f"/subjects/{DOC_CARDIO}/read", json=body).status_code == 200
    revoked = client.post(
        f"/subjects/{PATIENT}/consent/revoke", json={"prior_grant": signed["grant"]}
    ).json()
    other_facility = federation["services"].client(
        federation["apps"]["facility-b"], "facility-b", caller="portal"
    )
    assert other_facility.post("/consent/grants", json=revoked).status_code == 200
    # Re-submitting the old grant cannot remove the separate revocation artifact.
    assert other_facility.post("/consent/grants", json=signed).status_code == 200
    denied = client.post(f"/subjects/{DOC_CARDIO}/read", json=body)
    assert denied.status_code == 403
    assert "revocation" in denied.json()["detail"]
    assert "plaintext" not in denied.json()


@pytest.mark.parametrize("clinician", [DOC_ER, DOC_CARDIO])
def test_treating_physicians_need_consent_not_matching_specialty(federation, clinician):
    """A physician role plus a scoped signed grant supports ED and other specialties."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    policy = {
        "node_type": "or",
        "children": [
            {
                "node_type": "leaf",
                "attribute": {"name": "role", "value": role},
                "authority_id": "authority-med",
            }
            for role in ("physician", "emergency-physician")
        ],
    }
    uploaded = _upload(client, b"Synthetic encounter", clinical_policy=policy)
    assert uploaded.status_code == 201, uploaded.text
    rid = uploaded.json()["record_id"]
    body = {"record_id": rid, "facility_id": "facility-a"}
    assert client.post(f"/subjects/{clinician}/read", json=body).status_code == 403
    body["grant"] = _grant(client, clinician, rid)["grant"]
    assert client.post(f"/subjects/{clinician}/read", json=body).status_code == 200
    body["record_id"] = RECORD
    assert client.post(f"/subjects/{clinician}/read", json=body).status_code == 403


def test_sensitive_necessity_is_required_before_any_audit_share_release(federation):
    """Restricted records cannot use the ordinary emergency declaration alone."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    record = federation["repo"].get_record(RECORD)
    federation["repo"].insert_record(
        record.model_copy(
            update={"clinical": ClinicalMetadata(sensitivity="mental_health")}
        )
    )
    body = {
        "patient_id": PATIENT,
        "record_id": RECORD,
        "reason_code": "overdose",
        "justification": (
            "Unconscious patient with suspected overdose requires history."
        ),
    }
    before = len(client.app_audit.state.log["entries"])
    response = client.post(f"/subjects/{DOC_ER}/breakglass", json=body)
    assert response.status_code == 403
    assert "Restricted record" in response.json()["detail"]
    assert len(client.app_audit.state.log["entries"]) == before
    body["sensitive_justification"] = (
        "The psychiatric medication list is essential to assess the suspected overdose."
    )
    assert client.post(f"/subjects/{DOC_ER}/breakglass", json=body).status_code == 200
    entry = client.app_audit.state.log["entries"][-1]["event_data"]
    assert entry["restricted"] is True
    assert entry["sensitive_justification_digest"]
    assert body["justification"] not in json.dumps(entry)


def test_clinical_context_cannot_be_changed_after_signing():
    """The emergency assertion commits to record and both necessity statements."""
    private, _ = generate_ec_keypair()
    context = clinical_context_digest("rec-1", "clinical need", "restricted need")
    assertion = create_emergency_assertion(
        patient_id="pat-1",
        clinician_id="doc-1",
        facility_id="facility-a",
        reason_code=ReasonCode.SEIZURE,
        signing_key=private,
        clinical_context_digest=context,
    )
    validate_clinical_context(assertion, "rec-1", "clinical need", "restricted need")
    for record, need, restricted in [
        ("rec-2", "clinical need", "restricted need"),
        ("rec-1", "changed", "restricted need"),
        ("rec-1", "clinical need", "changed"),
    ]:
        with pytest.raises(ValueError, match="does not match the signed assertion"):
            validate_clinical_context(assertion, record, need, restricted)


def test_metadata_future_dates_and_non_emergency_reason_are_rejected():
    ClinicalMetadata(clinical_date=datetime.date.today())
    with pytest.raises(ValidationError, match="future"):
        ClinicalMetadata(
            clinical_date=datetime.date.today() + datetime.timedelta(days=2)
        )
    with pytest.raises(ValueError):
        ReasonCode("unknown_medication_history")


def test_future_structured_report_date_is_rejected_before_storage(federation):
    """Omitting metadata cannot hide a future performed_at in supported JSON."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    future = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    response = _upload(
        client,
        json.dumps({"encounter": {"performed_at": future}}).encode(),
        content_type="application/json",
        record_id="future-report",
    )
    assert response.status_code == 400, response.text
    assert "future" in response.json()["detail"]
    assert federation["repo"].get_record("future-report") is None


def test_clinician_of_another_facility_cannot_join_the_open_window(federation):
    """ADR-0063: a window opened by facility-b staff is not joinable from facility-a."""
    private, public = generate_keypair()
    federation["material"][DOC_CARDIO].update(
        pre_private_key=private, pre_public_key=public
    )
    client = _custodian(federation)
    _deposit_all(client, federation)
    payload = {
        "patient_id": PATIENT,
        "record_id": RECORD,
        "reason_code": "sepsis",
        "emergency_duration_seconds": 30,
    }
    first = client.post(
        f"/subjects/{DOC_ER}/breakglass", json={**payload, "facility_id": "facility-b"}
    )
    assert first.status_code == 200, first.text
    second = client.post(
        f"/subjects/{DOC_CARDIO}/breakglass",
        json={**payload, "facility_id": "facility-a"},
    )
    assert second.status_code == 403, second.text
    assert "cannot join" in second.text
    assert "plaintext_b64" not in second.text
    assert (
        federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN
    )
    # The opener's facility still joins: only the facility check refused above.
    again = client.post(
        f"/subjects/{DOC_ER}/breakglass", json={**payload, "facility_id": "facility-b"}
    )
    assert again.status_code == 200, again.text
    assert again.json()["joined"] is True


def test_clinical_note_author_is_bound_to_authenticated_subject(federation):
    """New notes are separately encrypted and cannot impersonate hospital authors."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    signed = _grant(client, DOC_CARDIO, RECORD)
    import base64

    from tests.api.test_custodian_service import CARDIO_POLICY

    body = {
        "patient_id": PATIENT,
        "facility_id": "facility-a",
        "grant": signed["grant"],
        "content_b64": base64.b64encode(b"Synthetic care note").decode(),
        "clinical_policy": CARDIO_POLICY,
        "clinical": {
            "author_id": "impersonated-author",
            "source": "hospital",
            "title": "Care note",
        },
    }
    response = client.post(f"/subjects/{DOC_CARDIO}/records", json=body)
    assert response.status_code == 201, response.text
    record = federation["repo"].get_record(response.json()["record_id"])
    assert record.clinical.author_id == DOC_CARDIO
    assert record.clinical.source == "clinician_note"
    body["patient_id"] = "another-patient"
    denied = client.post(f"/subjects/{DOC_CARDIO}/records", json=body)
    assert denied.status_code == 403
    assert "another patient" in denied.json()["detail"]
