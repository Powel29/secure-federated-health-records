# ruff: noqa: F811  (pytest fixtures arrive as same-named parameters)
"""Regression tests for the PR #40 review fixes.

- A stored revocation that does not verify is skipped, not a 500; a genuine
  one still refuses the read.
- ``join_only`` never opens a new emergency session.
- The future-date check accepts any date that is today somewhere, and a JSON
  report's non-ISO dates do not block an upload.
"""

from __future__ import annotations

import datetime
import json

import pytest
from consent.service import (
    create_consent_grant,
    create_consent_request,
    revoke_consent_grant,
)
from contracts.clinical import ClinicalMetadata, latest_local_date
from contracts.enums import ConsentStatus, LifecycleState
from crypto_core import generate_ec_keypair
from pydantic import ValidationError
from records.ingest import ingest_record

from tests.api.conftest import (  # noqa: F401
    attribute_materials,
    federation_pki,
    test_setup,
)
from tests.api.test_breakglass import _payload

RECORD = "rec-001"


def _grant(pki):
    request = create_consent_request(
        patient_id="patient-001",
        requester_id="dr-alice",
        scope=(RECORD,),
        purpose="Follow-up",
        requester_signing_key=pki["alice_priv"],
    )
    return create_consent_grant(
        request=request,
        status=ConsentStatus.GRANTED,
        grantee_id="dr-alice",
        patient_signing_key=pki["pat_priv"],
        scope=(RECORD,),
    )


def _consent_read(setup, grant):
    keyring = {
        k: v for k, v in setup["attrs"]["b64_keyring"].items() if ":owner:" not in k
    }
    return setup["client"].post(
        f"/records/{RECORD}/read",
        json={
            "requester_id": "dr-alice",
            "holder_keyring": keyring,
            "grant": grant.model_dump(mode="json"),
            "patient_certificate_pem": setup["pki"]["pat_cert_pem"],
        },
    )


def test_unverifiable_stored_revocation_is_skipped_not_a_500(test_setup):
    pki = test_setup["pki"]
    repo = test_setup["repo"]
    grant = _grant(pki)

    forger_key, _ = generate_ec_keypair()
    repo.store_consent_grant(
        revoke_consent_grant(prior_grant=grant, patient_signing_key=forger_key)
    )
    response = _consent_read(test_setup, grant)
    assert response.status_code == 200, response.text

    # The control still holds: the patient's own revocation refuses the read.
    repo.store_consent_grant(
        revoke_consent_grant(prior_grant=grant, patient_signing_key=pki["pat_priv"])
    )
    response = _consent_read(test_setup, grant)
    assert response.status_code == 403, response.text
    assert "plaintext_b64" not in response.text


def test_join_only_never_opens_an_emergency_session(test_setup):
    client = test_setup["client"]
    repo = test_setup["repo"]

    refused = client.post(
        f"/records/{RECORD}/breakglass", json=_payload(test_setup, join_only=True)
    )
    assert refused.status_code == 409, refused.text
    assert "rewrapped_dek_b64" not in refused.text
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    assert repo.transition_events == {}

    # Setup is valid: the same request without join_only opens the session.
    opened = client.post(f"/records/{RECORD}/breakglass", json=_payload(test_setup))
    assert opened.status_code == 200, opened.text


def test_today_somewhere_is_not_the_future():
    # The latest date that is today anywhere (UTC+14) is accepted -- e.g. a
    # clinic in UTC+5:30 filing today's record before 05:30 local time -- and
    # the day after it is refused.
    today_somewhere = latest_local_date()
    assert (
        ClinicalMetadata(clinical_date=today_somewhere).clinical_date == today_somewhere
    )
    with pytest.raises(ValidationError):
        ClinicalMetadata(clinical_date=today_somewhere + datetime.timedelta(days=1))


def test_non_iso_report_dates_do_not_block_an_upload(attribute_materials):
    result = ingest_record(
        plaintext=json.dumps({"performed_at": "yesterday evening"}).encode(),
        patient_id="patient-001",
        facility_id="facility-a",
        owner_authority_id="authority-net",
        clinical_policy=attribute_materials["clinical_policy"],
        attribute_keyring=attribute_materials["attr_keyring"],
        content_type="application/json",
    )
    assert result.record.record_id

    future = (latest_local_date() + datetime.timedelta(days=2)).isoformat()
    with pytest.raises(ValueError, match="cannot be in the future"):
        ingest_record(
            plaintext=json.dumps({"performed_at": future}).encode(),
            patient_id="patient-001",
            facility_id="facility-a",
            owner_authority_id="authority-net",
            clinical_policy=attribute_materials["clinical_policy"],
            attribute_keyring=attribute_materials["attr_keyring"],
            content_type="application/json",
        )
