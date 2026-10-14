"""Pytest fixtures for Hospital Node REST API testing (P4-1).

Constructs a simulated federation with:
- Root anchor and Facility A / Facility B CAs (cross-certified).
- Clinicians enrolled at Facility A (Alice) and Facility B (Bob).
- Patient 001 with ECDSA signing keys.
- Attribute authorities (Medical Council and Network Authority).
- Sample encrypted record with clinical access policy and owner leaf.
- Configured FastAPI test clients.
"""

from __future__ import annotations

import base64

import pytest
from api.hospital import FacilityTrust, create_hospital_app
from api.repository import InMemoryStorageRepository
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts.clinical import ClinicalMetadata
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    certificate_to_pem,
    generate_ec_keypair,
)
from fastapi.testclient import TestClient
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
    issue_patient_certificate,
)
from identity.root_anchor import generate_root_anchor
from lifecycle.expiry import EmergencyExpiryManager
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.ingest import ingest_record
from records.labels import sign_clinical_labels


@pytest.fixture()
def federation_pki():
    """Build root anchor, facilities CAs, and clinician certificates."""
    root = generate_root_anchor()

    # Facility A
    fa_priv, fa_pub = generate_ec_keypair()
    fa_cert = issue_facility_ca_certificate(root, "facility-a", fa_pub)

    # Facility B
    fb_priv, fb_pub = generate_ec_keypair()
    fb_cert = issue_facility_ca_certificate(root, "facility-b", fb_pub)

    # Clinician Alice at Facility A
    alice_priv, alice_pub = generate_ec_keypair()
    alice_cert = issue_clinician_certificate(fa_priv, fa_cert, "dr-alice", alice_pub)

    # Clinician Bob at Facility B
    bob_priv, bob_pub = generate_ec_keypair()
    bob_cert = issue_clinician_certificate(fb_priv, fb_cert, "dr-bob", bob_pub)

    # Patient 001, certified by their home facility (ADR-0064)
    pat_priv, pat_pub = generate_ec_keypair()
    pat_cert = issue_patient_certificate(fa_priv, fa_cert, "patient-001", pat_pub)

    # Facility lifecycle signing key
    life_priv, life_pub = generate_ec_keypair()

    # Pre keypairs for clinicians
    alice_pre_priv, alice_pre_pub = generate_pre_keypair()
    bob_pre_priv, bob_pre_pub = generate_pre_keypair()

    return {
        "root": root,
        "fa_priv": fa_priv,
        "fa_pub": fa_pub,
        "fa_cert": fa_cert,
        "fb_priv": fb_priv,
        "fb_pub": fb_pub,
        "fb_cert": fb_cert,
        "alice_priv": alice_priv,
        "alice_pub": alice_pub,
        "alice_cert": alice_cert,
        "alice_pre_priv": alice_pre_priv,
        "alice_pre_pub": alice_pre_pub,
        "bob_priv": bob_priv,
        "bob_pub": bob_pub,
        "bob_cert": bob_cert,
        "bob_pre_priv": bob_pre_priv,
        "bob_pre_pub": bob_pre_pub,
        "pat_priv": pat_priv,
        "pat_pub": pat_pub,
        "pat_cert": pat_cert,
        "pat_cert_pem": certificate_to_pem(pat_cert).decode("ascii"),
        "life_priv": life_priv,
        "life_pub": life_pub,
    }


class FromHost:
    """ASGI wrapper that presents a fixed client address to the wrapped app.

    Starlette's TestClient sends no client address at all, so address-based
    checks (the F14 authoring allowlist) would refuse every test call.
    """

    def __init__(self, app, host: str = "testclient") -> None:
        self.app = app
        self.host = host

    def __getattr__(self, name):
        return getattr(self.app, name)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] in ("http", "websocket"):
            scope = {**scope, "client": (self.host, 50000)}
        await self.app(scope, receive, send)


class RecordingAuditSink:
    """An explicit in-memory audit destination (review F19) that tests can read."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def __call__(self, event_type, event_data, actor_id, correlation_id) -> None:
        self.events.append(
            {
                "event_type": event_type,
                "event_data": event_data,
                "actor_id": actor_id,
                "correlation_id": correlation_id,
            }
        )

    def of_type(self, event_type: str) -> list[dict]:
        return [e for e in self.events if e["event_type"] == event_type]


def signed_labels(
    pki, record_id: str, patient_id: str = "patient-001", **labels
) -> ClinicalMetadata:
    """Clinical labels signed by the patient, as the custodian signs them."""
    return sign_clinical_labels(
        ClinicalMetadata(**labels),
        record_id=record_id,
        patient_id=patient_id,
        signing_key=pki["pat_priv"],
        certificate_pem=pki["pat_cert_pem"],
    )


def make_trust(pki, revoked_serials=frozenset()) -> FacilityTrust:
    """The facility's configured break-glass trust anchors (review F1)."""
    return FacilityTrust(
        root=pki["root"].certificate,
        facility_cas={"facility-a": pki["fa_cert"], "facility-b": pki["fb_cert"]},
        revoked_serials=frozenset(revoked_serials),
    )


@pytest.fixture()
def attribute_materials():
    """Build mock attribute keys for policy compilation and evaluation."""
    key_physician = b"k_role_physician_32bytes_sample!"
    key_cardio = b"k_specialty_cardio_32bytes_samp!"
    key_owner = b"k_owner_patient001_32bytes_samp!"

    attr_keyring: dict[tuple[str, str, str], bytes] = {
        ("authority-med", "role", "physician"): key_physician,
        ("authority-net", "specialty", "cardiology"): key_cardio,
        ("authority-net", "owner", "patient-001"): key_owner,
    }

    # B64 string keyring for API payloads
    b64_keyring: dict[str, str] = {
        "authority-med:role:physician": base64.b64encode(key_physician).decode("ascii"),
        "authority-net:specialty:cardiology": base64.b64encode(key_cardio).decode(
            "ascii"
        ),
        "authority-net:owner:patient-001": base64.b64encode(key_owner).decode("ascii"),
    }

    def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
        return PolicyTree(
            node_type=PolicyNodeType.LEAF,
            attribute=Attribute(name=name, value=value),
            authority_id=authority_id,
        )

    clinical_policy = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            _leaf("role", "physician", "authority-med"),
            _leaf("specialty", "cardiology", "authority-net"),
        ),
    )

    return {
        "attr_keyring": attr_keyring,
        "b64_keyring": b64_keyring,
        "clinical_policy": clinical_policy,
    }


@pytest.fixture()
def test_setup(federation_pki, attribute_materials):
    """Seed in-memory repo with ingested record, emergency keys, and client."""
    repo = InMemoryStorageRepository()
    life_priv = federation_pki["life_priv"]

    expiry_manager = EmergencyExpiryManager(
        signing_key=life_priv,
        default_duration_seconds=60.0,
    )

    em_key = generate_emergency_key()
    em_shares = split_emergency_key(em_key)

    plaintext = b'{"diagnosis": "Coronary artery disease", "severity": "acute"}'

    ingest_res = ingest_record(
        plaintext=plaintext,
        patient_id="patient-001",
        facility_id="facility-a",
        owner_authority_id="authority-net",
        clinical_policy=attribute_materials["clinical_policy"],
        attribute_keyring=attribute_materials["attr_keyring"],
        search_terms=["cardiac", "acute"],
        emergency_key=em_key,
        content_type="application/json",
        record_id="rec-001",
        # Verified default labels: the record keeps the pre-label rules.
        clinical=signed_labels(federation_pki, "rec-001"),
    )

    repo.insert_record(ingest_res.record)
    repo.insert_dek_wrapping(ingest_res.dek_wrapping)
    repo.store_compiled_policy(ingest_res.record.policy_id, ingest_res.compiled_policy)
    repo.upsert_lifecycle_state(
        record_id=ingest_res.record.record_id,
        state=LifecycleState.GRANTED,
    )
    for _term, token in ingest_res.search_tokens.items():
        repo.insert_search_term(ingest_res.record.record_id, token)

    # The emergency wrapping ingest produced: the record's DEK under the
    # emergency key. (Wrapping the policy root secret here instead would hand
    # a break-glass clinician the wrong key.)
    em_wrapping = ingest_res.emergency_dek_wrapping
    repo.insert_dek_wrapping(em_wrapping)

    audit_sink = RecordingAuditSink()
    app = create_hospital_app(
        facility_id="facility-a",
        repository=repo,
        expiry_manager=expiry_manager,
        trust=make_trust(federation_pki),
        audit_sink=audit_sink,
    )
    client = TestClient(app)

    return {
        "repo": repo,
        "audit_sink": audit_sink,
        "app": app,
        "client": client,
        "expiry_manager": expiry_manager,
        "record": ingest_res.record,
        "wrapping": ingest_res.dek_wrapping,
        "em_wrapping": em_wrapping,
        "plaintext": plaintext,
        "em_key": em_key,
        "em_shares": em_shares,
        "pki": federation_pki,
        "attrs": attribute_materials,
    }
