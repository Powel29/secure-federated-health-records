"""Synthetic patient dataset generator and federation seeding orchestrator (P4-5).

Produces realistic, clinically meaningful fake patient records (cardiac, diabetes,
trauma) and seeds them into the federated health network.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from typing import Any

import httpx
import psycopg
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts.clinical import ClinicalMetadata
from contracts.enums import PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    certificate_from_pem,
    certificate_to_pem,
    generate_ec_keypair,
    private_key_from_pem,
    private_key_to_pem,
)
from identity.certificates import issue_clinician_certificate, issue_patient_certificate
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.labels import sign_clinical_labels
from storage.repositories import get_patient, insert_patient

from deploy.run_scenario import ScenarioEndpoints


@dataclass(frozen=True)
class SyntheticPatient:
    patient_id: str
    name: str
    date_of_birth: str
    blood_type: str
    home_facility: str
    owner_authority: str


@dataclass(frozen=True)
class SyntheticRecord:
    record_id: str
    patient_id: str
    facility_id: str
    title: str
    clinical_policy: PolicyTree
    search_terms: list[str]
    payload: dict[str, Any]
    target_specialty: str


@dataclass(frozen=True)
class SyntheticClinician:
    clinician_id: str
    name: str
    facility_id: str
    role: str
    specialty: str | None


@dataclass(frozen=True)
class SyntheticDataset:
    patients: list[SyntheticPatient] = field(default_factory=list)
    records: list[SyntheticRecord] = field(default_factory=list)
    clinicians: list[SyntheticClinician] = field(default_factory=list)


def create_synthetic_dataset() -> SyntheticDataset:
    alice = SyntheticPatient(
        patient_id="pat-101",
        name="Alice Vance",
        date_of_birth="1982-04-15",
        blood_type="O+",
        home_facility="facility-a",
        owner_authority="authority-net",
    )

    david = SyntheticPatient(
        patient_id="pat-102",
        name="David Miller",
        date_of_birth="1965-11-20",
        blood_type="A-",
        home_facility="facility-b",
        owner_authority="authority-net",
    )

    emma = SyntheticPatient(
        patient_id="pat-103",
        name="Emma Hartwell",
        date_of_birth="1994-07-03",
        blood_type="B+",
        home_facility="facility-a",
        owner_authority="authority-net",
    )

    doc_house = SyntheticClinician(
        clinician_id="doc-201",
        name="Dr. Arjun Rao",
        facility_id="facility-b",
        role="emergency-physician",
        specialty="emergency-medicine",
    )

    doc_chase = SyntheticClinician(
        clinician_id="doc-301",
        name="Dr. Leela Menon",
        facility_id="facility-a",
        role="physician",
        specialty="cardiology",
    )

    doc_cameron = SyntheticClinician(
        clinician_id="doc-202",
        name="Dr. Samuel Okafor",
        facility_id="facility-b",
        role="physician",
        specialty="endocrinology",
    )

    policy_cardiology = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=[
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="role", value="physician"),
                authority_id="authority-med",
            ),
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="specialty", value="cardiology"),
                authority_id="authority-net",
            ),
        ],
    )

    policy_endocrinology = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=[
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="role", value="physician"),
                authority_id="authority-med",
            ),
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="specialty", value="endocrinology"),
                authority_id="authority-net",
            ),
        ],
    )

    policy_trauma = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=[
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="role", value="physician"),
                authority_id="authority-med",
            ),
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(
                    name="role",
                    value="emergency-physician",
                ),
                authority_id="authority-med",
            ),
        ],
    )

    rec_alice = SyntheticRecord(
        record_id="rec-001",
        patient_id="pat-101",
        facility_id="facility-a",
        title="Emergency Department & Inpatient Cardiology Encounter",
        target_specialty="cardiology",
        clinical_policy=PolicyTree(
            node_type=PolicyNodeType.OR,
            children=[policy_cardiology.children[0], policy_trauma.children[1]],
        ),
        search_terms=[
            "cardiac",
            "infarction",
            "aspirin",
            "troponin",
            "stemi",
            "penicillin",
            "anaphylaxis",
        ],
        payload={
            "patient_id": "pat-101",
            "encounter_id": "enc-2026-09-10-01",
            "facility": "Northvale General Hospital (facility-a)",
            "admission_type": "EMERGENCY",
            "chief_complaint": (
                "Crushing retrosternal chest pain radiating to left arm and jaw"
            ),
            "diagnosis": ("Acute Myocardial Infarction (STEMI), anterolateral wall"),
            "vitals": {
                "heart_rate_bpm": 112,
                "blood_pressure": "85/55 mmHg",
                "respiratory_rate": 24,
                "oxygen_saturation": "91% on room air",
                "temperature_c": 36.8,
            },
            "labs": {
                "troponin_i_ng_ml": 4.2,
                "ck_mb_ng_ml": 48.0,
                "potassium_mmol_l": 4.1,
            },
            "medications": [
                {
                    "name": "Aspirin",
                    "dose": "325 mg",
                    "route": "PO chewed",
                },
                {
                    "name": "Ticagrelor",
                    "dose": "180 mg",
                    "route": "PO load",
                },
                {
                    "name": "Noradrenaline",
                    "dose": "0.1 mcg/kg/min",
                    "route": "IV infusion, titrated to MAP >= 65 mmHg",
                },
                {
                    "name": "Heparin",
                    "dose": "5000 units",
                    "route": "IV bolus",
                },
            ],
            "allergies": [
                {
                    "substance": "Penicillin",
                    "reaction": ("Anaphylaxis (severe bronchospasm and urticaria)"),
                }
            ],
            "notes": (
                "Patient presents in cardiogenic shock secondary to acute STEMI. "
                "Catheterization lab activated immediately. Beta-blocker withheld "
                "while in shock. Avoid penicillins (confirmed anaphylaxis); other "
                "beta-lactams only after allergy review."
            ),
        },
    )

    rec_david = SyntheticRecord(
        record_id="rec-002",
        patient_id="pat-102",
        facility_id="facility-b",
        title="Endocrinology Outpatient Consultation & Glycemic Control Plan",
        target_specialty="endocrinology",
        clinical_policy=PolicyTree(
            node_type=PolicyNodeType.OR,
            children=[policy_endocrinology.children[0], policy_trauma.children[1]],
        ),
        search_terms=[
            "endocrinology",
            "diabetes",
            "metformin",
            "insulin",
            "glucose",
        ],
        payload={
            "patient_id": "pat-102",
            "encounter_id": "enc-2026-08-14-03",
            "facility": "Eastbrook Hospital (facility-b)",
            "admission_type": "OUTPATIENT",
            "chief_complaint": (
                "Follow-up for poorly controlled blood sugar, polyuria, polydipsia"
            ),
            "diagnosis": (
                "Type 2 diabetes mellitus with hyperglycaemia, poorly controlled "
                "(HbA1c 10.8%)"
            ),
            "vitals": {
                "heart_rate_bpm": 78,
                "blood_pressure": "138/84 mmHg",
                "bmi": 31.4,
            },
            "labs": {
                "glucose_random_mg_dl": 340,
                "hba1c_pct": 10.8,
                "creatinine_mg_dl": 1.1,
            },
            "medications": [
                {
                    "name": "Metformin HCl",
                    "dose": "1000 mg",
                    "frequency": "BID",
                },
                {
                    "name": "Glipizide",
                    "dose": "10 mg",
                    "frequency": "Daily",
                },
                {
                    "name": "Insulin Glargine",
                    "dose": "24 units",
                    "frequency": "QHS",
                },
            ],
            "allergies": [
                {
                    "substance": "Sulfa drugs",
                    "reaction": "Maculopapular rash",
                }
            ],
            "notes": (
                "Insulin glargine increased to 24 units at night. "
                "Sulfa antibiotic rash noted; tolerating glipizide. "
                "Dietitian counseling scheduled."
            ),
        },
    )

    rec_emma = SyntheticRecord(
        record_id="rec-003",
        patient_id="pat-103",
        facility_id="facility-a",
        title="Trauma Resuscitation & Emergency Surgical Evaluation",
        target_specialty="emergency-medicine",
        clinical_policy=PolicyTree(
            node_type=PolicyNodeType.OR, children=list(policy_trauma.children)
        ),
        search_terms=[
            "trauma",
            "emergency",
            "hemorrhage",
            "fracture",
            "resuscitation",
        ],
        payload={
            "patient_id": "pat-103",
            "encounter_id": "enc-2026-09-02-09",
            "facility": "Northvale General Hospital (facility-a)",
            "admission_type": "TRAUMA_LEVEL_1",
            "chief_complaint": (
                "Motor vehicle collision, restrained driver with steering wheel impact"
            ),
            "diagnosis": (
                "Polytrauma: Grade II splenic laceration, closed left femur fracture"
            ),
            "vitals": {
                "heart_rate_bpm": 128,
                "blood_pressure": "90/60 mmHg",
                "gcs": 13,
            },
            "labs": {
                "hemoglobin_g_dl": 9.2,
                "lactate_mmol_l": 3.8,
            },
            "medications": [
                {
                    "name": "Fentanyl",
                    "dose": "50 mcg",
                    "route": "IV PRN pain",
                },
                {
                    "name": "Cefazolin",
                    "dose": "2 g",
                    "route": "IV perioperative",
                },
                {
                    "name": "Tranexamic Acid",
                    "dose": "1 g",
                    "route": "IV over 10 min",
                },
                {
                    "name": "Packed red blood cells",
                    "dose": "2 units (crossmatched)",
                    "route": "IV, massive transfusion protocol activated",
                },
            ],
            "allergies": [],
            "allergy_status": "No known drug allergies (confirmed with patient, GCS 13)",
            "notes": (
                "Emergency FAST examination positive for fluid in splenorenal recess. "
                "Orthopedic surgery on standby."
            ),
        },
    )

    return SyntheticDataset(
        patients=[alice, david, emma],
        records=[rec_alice, rec_david, rec_emma],
        clinicians=[doc_house, doc_chase, doc_cameron],
    )


def _parse_ca_credentials(ca_data: object) -> tuple[object, object]:
    if isinstance(ca_data, dict):
        priv_pem = ca_data["ca_private_key_pem"]
        cert_pem = ca_data["ca_certificate_pem"]
    else:
        priv_pem = ca_data.ca_private_key_pem
        cert_pem = ca_data.ca_certificate_pem

    return (
        private_key_from_pem(priv_pem.encode("ascii")),
        certificate_from_pem(cert_pem.encode("ascii")),
    )


def _signed_labels(
    patient: dict[str, Any], record_id: str, patient_id: str, labels: dict[str, Any]
) -> dict[str, Any]:
    """The record's clinical labels, signed by its patient (ADR-0064).

    Unsigned labels would get the strictest disclosure rules at the facility.
    """
    return sign_clinical_labels(
        ClinicalMetadata(**labels),
        record_id=record_id,
        patient_id=patient_id,
        signing_key=patient["private_key"],
        certificate_pem=patient["certificate_pem"],
    ).model_dump(mode="json")


def seed_synthetic_data(
    endpoints: ScenarioEndpoints,
    config: dict[str, Any] | None = None,
    dataset: SyntheticDataset | None = None,
    client: httpx.Client | None = None,
    *,
    database_url: str | None = None,
    verbose: bool = False,
) -> dict[str, Any]:

    if dataset is None:
        dataset = create_synthetic_dataset()

    database_url = database_url or os.environ.get("DATABASE_URL")
    if database_url:
        conn = psycopg.connect(database_url)
        try:
            for patient in dataset.patients:
                # Path A/B bootstrap already registers these (populate_registry).
                if get_patient(conn, patient.patient_id) is None:
                    insert_patient(
                        conn,
                        patient.patient_id,
                        patient.owner_authority,
                    )
            conn.commit()
        finally:
            conn.close()

    http = client or httpx.Client(timeout=15.0)

    if config and "root_certificate_pem" in config:
        root_cert_pem = config["root_certificate_pem"]
        fa_ca_priv, fa_ca_cert = _parse_ca_credentials(
            config["facilities"]["facility-a"]
        )
        fb_ca_priv, fb_ca_cert = _parse_ca_credentials(
            config["facilities"]["facility-b"]
        )
    else:
        from deploy.bootstrap import generate_federation_pki

        _, fed_pki = generate_federation_pki(["facility-a", "facility-b"])
        root_cert_pem = fed_pki.root_certificate_pem
        fa_ca_priv, fa_ca_cert = _parse_ca_credentials(fed_pki.facilities["facility-a"])
        fb_ca_priv, fb_ca_cert = _parse_ca_credentials(fed_pki.facilities["facility-b"])

    facility_cas = {
        "facility-a": (fa_ca_priv, fa_ca_cert),
        "facility-b": (fb_ca_priv, fb_ca_cert),
    }

    clinician_meta: dict[str, Any] = {}

    for clinician in dataset.clinicians:
        ca_priv, ca_cert = facility_cas[clinician.facility_id]
        priv, pub = generate_ec_keypair()

        cert = issue_clinician_certificate(
            ca_priv,
            ca_cert,
            clinician.clinician_id,
            pub,
        )

        cert_pem = certificate_to_pem(cert).decode("ascii")
        pre_priv, pre_pub = generate_pre_keypair()

        # Issued credentials are kept (not just acknowledged) so the portal
        # seed step (deploy/seed_portal.py, ADR-0043) can deposit them with
        # each persona's key agent -- the custodian exchanges them for
        # attribute keys at read time.
        issued: list[dict[str, Any]] = []
        role_res = http.post(
            f"{endpoints.authority_med}/credentials/issue",
            json={
                "subject_id": clinician.clinician_id,
                "attribute": {
                    "name": "role",
                    "value": clinician.role,
                },
            },
        )
        role_res.raise_for_status()
        issued.append(role_res.json()["credential"])

        if clinician.specialty:
            spec_res = http.post(
                f"{endpoints.authority_net}/credentials/issue",
                json={
                    "subject_id": clinician.clinician_id,
                    "attribute": {
                        "name": "specialty",
                        "value": clinician.specialty,
                    },
                },
            )
            spec_res.raise_for_status()
            issued.append(spec_res.json()["credential"])

        clinician_meta[clinician.clinician_id] = {
            "clinician": clinician,
            "credentials": issued,
            "private_key": priv,
            "public_key": pub,
            "certificate": cert,
            "certificate_pem": cert_pem,
            "pre_private_key": pre_priv,
            "pre_public_key": pre_pub,
            "private_key_pem": private_key_to_pem(priv).decode("ascii"),
        }

    patient_meta: dict[str, Any] = {}
    for patient in dataset.patients:
        owner_res = http.post(
            f"{endpoints.authority_net}/credentials/issue",
            json={
                "subject_id": patient.patient_id,
                "attribute": {
                    "name": "owner",
                    "value": patient.patient_id,
                },
                "owner": True,
            },
        )
        owner_res.raise_for_status()
        # Each patient gets a signing keypair so the portal's key agent can
        # sign consent decisions on their behalf (ADR-0043). Kept in memory
        # only, like every other key here.
        pat_priv, pat_pub = generate_ec_keypair()
        # The home facility certifies the patient's key (ADR-0064), so a
        # facility verifies their signatures -- on record labels and consent
        # decisions -- against a key it trusts, not one a caller supplies.
        home_ca_priv, home_ca_cert = facility_cas[patient.home_facility]
        pat_cert = issue_patient_certificate(
            home_ca_priv, home_ca_cert, patient.patient_id, pat_pub
        )
        patient_meta[patient.patient_id] = {
            "patient": patient,
            "credentials": [owner_res.json()["credential"]],
            "private_key": pat_priv,
            "public_key": pat_pub,
            "private_key_pem": private_key_to_pem(pat_priv).decode("ascii"),
            "certificate": pat_cert,
            "certificate_pem": certificate_to_pem(pat_cert).decode("ascii"),
        }

    def get_author_key(
        base_url: str,
        name: str,
        val: str,
    ) -> bytes:
        res = http.post(
            f"{base_url}/attribute-keys/author",
            json={"name": name, "value": val},
        )
        res.raise_for_status()
        return base64.b64decode(res.json()["key_b64"])

    attribute_keys: dict[str, bytes] = {
        "authority-med:role:physician": get_author_key(
            endpoints.authority_med,
            "role",
            "physician",
        ),
        "authority-med:role:emergency-physician": get_author_key(
            endpoints.authority_med,
            "role",
            "emergency-physician",
        ),
        "authority-net:specialty:cardiology": get_author_key(
            endpoints.authority_net,
            "specialty",
            "cardiology",
        ),
        "authority-net:specialty:endocrinology": get_author_key(
            endpoints.authority_net,
            "specialty",
            "endocrinology",
        ),
        "authority-net:specialty:emergency-medicine": get_author_key(
            endpoints.authority_net,
            "specialty",
            "emergency-medicine",
        ),
    }

    for patient in dataset.patients:
        k_owner = get_author_key(
            endpoints.authority_net,
            "owner",
            patient.patient_id,
        )
        attribute_keys[f"authority-net:owner:{patient.patient_id}"] = k_owner

    record_meta: dict[str, Any] = {}

    facility_endpoints = {
        "facility-a": endpoints.facility_a,
        "facility-b": endpoints.facility_b,
    }

    for rec in dataset.records:
        emergency_key = generate_emergency_key()
        shares = split_emergency_key(emergency_key)
        share1, share2, share3 = shares[0], shares[1], shares[2]

        audit_deposit_res = http.post(
            f"{endpoints.audit}/breakglass/shares",
            json={
                "share_key": rec.record_id,
                "x": share3[0],
                "share_hex": share3[1].hex(),
            },
        )
        audit_deposit_res.raise_for_status()

        record_keyring_b64 = {
            k: base64.b64encode(v).decode("ascii") for k, v in attribute_keys.items()
        }

        plaintext_bytes = json.dumps(rec.payload).encode("utf-8")
        target_facility_url = facility_endpoints[rec.facility_id]

        ingest_res = http.post(
            f"{target_facility_url}/records/ingest",
            json={
                "plaintext_b64": base64.b64encode(plaintext_bytes).decode("ascii"),
                "patient_id": rec.patient_id,
                "owner_authority_id": "authority-net",
                "clinical_policy": rec.clinical_policy.model_dump(mode="json"),
                "attribute_keyring": record_keyring_b64,
                "search_terms": rec.search_terms,
                "emergency_key_b64": base64.b64encode(emergency_key).decode("ascii"),
                "record_id": rec.record_id,
                "clinical": _signed_labels(
                    patient_meta[rec.patient_id],
                    rec.record_id,
                    rec.patient_id,
                    {
                        "title": rec.title,
                        "author_id": (
                            "doc-301"
                            if rec.record_id == "rec-001"
                            else (
                                "doc-202" if rec.record_id == "rec-002" else "doc-201"
                            )
                        ),
                        "clinical_date": rec.payload["encounter_id"][4:14],
                        "record_type": "clinical_encounter",
                        "episode_id": rec.payload["encounter_id"],
                        "source": "hospital",
                        "care_team_consent": True,
                    },
                ),
            },
        )
        ingest_res.raise_for_status()
        ingest_data = ingest_res.json()

        record_meta[rec.record_id] = {
            "record": rec,
            "plaintext": plaintext_bytes,
            "emergency_key": emergency_key,
            "shares": shares,
            "share1": share1,
            "share2": share2,
            "share3": share3,
            "policy_id": ingest_data["policy_id"],
            "wrapping_id": ingest_data["wrapping_id"],
            "search_terms_indexed": ingest_data["search_terms_indexed"],
        }

    return {
        "dataset": dataset,
        "clinicians": clinician_meta,
        "patients": patient_meta,
        "records": record_meta,
        "root_cert_pem": root_cert_pem,
        "facility_cas": facility_cas,
        "attribute_keys": attribute_keys,
    }
