# ruff: noqa: F811  (pytest fixtures arrive as same-named parameters)
"""Patient certificates, signed clinical labels and certified consent keys (ADR-0064).

Claims:
- A record's clinical labels are trusted only with its patient's valid
  signature; editing, stripping, copying or self-signing them can only make
  access stricter, never looser.
- A consent grant is verified against a patient key certified by a configured
  facility CA, never against a key the caller supplies.
"""

from __future__ import annotations

from consent.service import create_consent_grant, create_consent_request
from contracts.clinical import ClinicalMetadata
from contracts.enums import ConsentStatus
from crypto_core import certificate_to_pem, generate_ec_keypair
from identity import (
    generate_root_anchor,
    issue_facility_ca_certificate,
    issue_patient_certificate,
)
from records.labels import disclosure_rules, sign_clinical_labels

from tests.api.conftest import (  # noqa: F401
    attribute_materials,
    federation_pki,
    make_trust,
    signed_labels,
    test_setup,
)
from tests.api.test_breakglass import _payload

RECORD = "rec-001"
PATIENT = "patient-001"


def _label_trust(pki):
    from records.labels import LabelTrust

    return LabelTrust(
        facility_cas={"facility-a": pki["fa_cert"], "facility-b": pki["fb_cert"]},
        trusted_root=pki["root"].certificate,
    )


def _relabel(setup, clinical: ClinicalMetadata) -> None:
    """Replace the stored record's labels, as a store write would."""
    repo = setup["repo"]
    repo.records[RECORD] = repo.records[RECORD].model_copy(
        update={"clinical": clinical}
    )


def _policy_read(setup):
    return setup["client"].post(
        f"/records/{RECORD}/read",
        json={
            "requester_id": "dr-alice",
            "holder_keyring": setup["attrs"]["b64_keyring"],
        },
    )


def test_editing_a_signed_restrictive_label_does_not_loosen_break_glass(
    test_setup,
):
    """Changing a signed 'hiv' label to 'general' in the store leaves the
    restricted-record justification required."""
    pki = test_setup["pki"]
    restricted = signed_labels(pki, RECORD, sensitivity="hiv")
    record = test_setup["repo"].records[RECORD]

    # Setup is valid: the genuine label verifies and demands the justification.
    genuine = disclosure_rules(
        record.model_copy(update={"clinical": restricted}), _label_trust(pki)
    )
    assert genuine.labels_verified and genuine.sensitive_justification

    _relabel(test_setup, restricted.model_copy(update={"sensitivity": "general"}))
    response = test_setup["client"].post(
        f"/records/{RECORD}/breakglass", json=_payload(test_setup)
    )
    # Refused under the strictest rules: no key is released.
    assert response.status_code == 403, response.text
    assert "rewrapped_dek_b64" not in response.text


def test_stripping_the_label_signature_does_not_loosen_reads(test_setup):
    """Unsigned labels require patient consent for a clinician's read."""
    # Setup is valid: with the patient's signed labels, policy alone reads.
    assert _policy_read(test_setup).status_code == 200

    stored = test_setup["repo"].records[RECORD].clinical
    _relabel(
        test_setup,
        stored.model_copy(update={"signature": None, "signer_certificate_pem": None}),
    )
    response = _policy_read(test_setup)
    assert response.status_code == 403, response.text
    assert "grant is required" in response.json()["detail"]


def test_labels_signed_with_a_clinician_certificate_are_not_trusted(
    test_setup,
):
    """Only a patient certificate can vouch for a record's labels."""
    pki = test_setup["pki"]
    record = test_setup["repo"].records[RECORD]
    forged = sign_clinical_labels(
        ClinicalMetadata(),
        record_id=RECORD,
        patient_id=PATIENT,
        signing_key=pki["alice_priv"],
        certificate_pem=certificate_to_pem(pki["alice_cert"]).decode("ascii"),
    )
    rules = disclosure_rules(
        record.model_copy(update={"clinical": forged}), _label_trust(pki)
    )
    assert not rules.labels_verified
    assert rules.consent_for_read and rules.sensitive_justification
    assert "not a patient certificate" in rules.reason


def test_labels_copied_from_another_record_do_not_verify(test_setup):
    """A signature binds the labels to one record; moved labels are untrusted."""
    pki = test_setup["pki"]
    record = test_setup["repo"].records[RECORD]
    assert disclosure_rules(record, _label_trust(pki)).labels_verified  # setup

    elsewhere = signed_labels(pki, "rec-999")
    rules = disclosure_rules(
        record.model_copy(update={"clinical": elsewhere}), _label_trust(pki)
    )
    assert not rules.labels_verified
    assert rules.consent_for_read


def _grant(pki, signing_key):
    request = create_consent_request(
        patient_id=PATIENT,
        requester_id="dr-alice",
        scope=(RECORD,),
        purpose="Consultation",
        requester_signing_key=pki["alice_priv"],
    )
    return create_consent_grant(
        request=request,
        status=ConsentStatus.GRANTED,
        grantee_id="dr-alice",
        patient_signing_key=signing_key,
    )


def test_consent_grant_signed_by_a_forger_with_their_own_certificate_is_refused(
    test_setup,
):
    """A forger who mints their own 'patient-001' certificate is refused."""
    pki = test_setup["pki"]
    client = test_setup["client"]

    # Setup is valid: the genuine patient's grant and certificate are accepted.
    genuine = client.post(
        "/consent/grants",
        json={
            "grant": _grant(pki, pki["pat_priv"]).model_dump(mode="json"),
            "patient_certificate_pem": pki["pat_cert_pem"],
        },
    )
    assert genuine.status_code == 200, genuine.text

    rogue_root = generate_root_anchor()
    rogue_ca_key, rogue_ca_pub = generate_ec_keypair()
    rogue_ca = issue_facility_ca_certificate(rogue_root, "facility-a", rogue_ca_pub)
    forger_key, forger_pub = generate_ec_keypair()
    forger_cert = issue_patient_certificate(rogue_ca_key, rogue_ca, PATIENT, forger_pub)
    response = client.post(
        "/consent/grants",
        json={
            "grant": _grant(pki, forger_key).model_dump(mode="json"),
            "patient_certificate_pem": certificate_to_pem(forger_cert).decode("ascii"),
        },
    )
    assert response.status_code == 403, response.text
    assert "Patient certificate refused" in response.json()["detail"]


def test_consent_grant_with_another_patients_certificate_is_refused(
    test_setup,
):
    """A real certificate of a different patient does not vouch for this one."""
    pki = test_setup["pki"]
    other_key, other_pub = generate_ec_keypair()
    other_cert = issue_patient_certificate(
        pki["fa_priv"], pki["fa_cert"], "patient-002", other_pub
    )
    response = test_setup["client"].post(
        "/consent/grants",
        json={
            "grant": _grant(pki, other_key).model_dump(mode="json"),
            "patient_certificate_pem": certificate_to_pem(other_cert).decode("ascii"),
        },
    )
    assert response.status_code == 403, response.text
    assert "does not belong to patient" in response.json()["detail"]


def test_a_bare_public_key_is_no_longer_accepted(test_setup):
    """The old caller-supplied key field cannot stand in for a certificate."""
    from crypto_core import public_key_to_pem

    pki = test_setup["pki"]
    response = test_setup["client"].post(
        "/consent/grants",
        json={
            "grant": _grant(pki, pki["pat_priv"]).model_dump(mode="json"),
            "patient_public_key_pem": public_key_to_pem(pki["pat_pub"]).decode(),
        },
    )
    assert response.status_code == 422, response.text
