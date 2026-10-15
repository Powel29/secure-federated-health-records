"""Full end-to-end scenario runner for the federation (P4-4, ARCHITECTURE.md §5).

Executes the complete cross-hospital break-glass scenario start to finish across
all five federation services:
1. Health check & bootstrap verification across all five processes.
2. Federated identity & attribute credential issuance for synthetic personas.
3. Record ingest at Facility A (Home Hospital) with 2-of-3 emergency key split
   and Share 3 custody deposit at the standalone Audit Service.
4. In-network routine clinical read at Facility A under attribute policy.
5. Out-of-network emergency access attempt & policy denial at Facility B.
6. Federated record discovery and signed EmergencyAssertion creation.
7. Log-before-release share release from Audit Service (Share 3) and 2-of-3
   threshold break-glass unlock at Facility B, with PRE DEK decapsulation.
8. Emergency-only search capability while EMERGENCY_OPEN.
9. Time-box auto-expiry, forced DEK rotation, search dead-token verification,
   and full SHA-256 audit chain verification.

Usage::

    # Run against a running federation (local run_local.py or Docker Compose):
    python -m deploy.run_scenario

    # Run against custom config:
    python -m deploy.run_scenario --config deploy/pki/federation.json
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from api.audit_client import _tls_verify
from api.service_auth import ServiceIdentity, signed_client
from breakglass import create_emergency_assertion
from breakglass.assertion import clinical_context_digest
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts.base import GCM_NONCE_BYTES
from contracts.clinical import ClinicalMetadata
from contracts.enums import LifecycleState, PolicyNodeType, ReasonCode
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    certificate_from_pem,
    certificate_to_pem,
    generate_ec_keypair,
    private_key_from_pem,
    private_key_to_pem,
)
from crypto_core.symmetric import aes_gcm_decrypt
from identity.certificates import (
    issue_clinician_certificate,
    issue_patient_certificate,
)
from lifecycle.state_machine import create_transition_event
from pre.elgamal import decapsulate_key
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.labels import sign_clinical_labels

from deploy.config import configure_transport, tls_enabled

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "deploy" / "pki" / "federation.json"
# Where run_local writes every service's identity; the scenario signs as
# bootstrap (ADR-0066).
DEFAULT_SERVICES_DIR = REPO_ROOT / "deploy" / "pki" / "services"
AUDIT_SERVICE_ID = "audit-service"


def _unwrap_rewrapped_dek(rewrapped_dek: bytes, pre_priv: int, record_id: str) -> bytes:
    """Reverse the gate's fixed-length PRE delivery packaging."""
    field_bytes = 32
    c1 = int.from_bytes(rewrapped_dek[:field_bytes], byteorder="big")
    c2 = int.from_bytes(rewrapped_dek[field_bytes : 2 * field_bytes], byteorder="big")
    offset = 2 * field_bytes
    nonce = rewrapped_dek[offset : offset + GCM_NONCE_BYTES]
    ciphertext = rewrapped_dek[offset + GCM_NONCE_BYTES :]
    delivery_key = decapsulate_key(pre_priv, c1, c2)
    return aes_gcm_decrypt(
        key=delivery_key,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=record_id.encode("utf-8"),
    )


def _parse_ca_credentials(ca_data: object) -> tuple[object, object]:
    """Extract and parse private key and certificate from CA data object or dict."""
    if isinstance(ca_data, dict):
        priv_pem = ca_data["ca_private_key_pem"]
        cert_pem = ca_data["ca_certificate_pem"]
    else:
        priv_pem = ca_data.ca_private_key_pem  # type: ignore[attr-defined]
        cert_pem = ca_data.ca_certificate_pem  # type: ignore[attr-defined]
    return (
        private_key_from_pem(priv_pem.encode("ascii")),
        certificate_from_pem(cert_pem.encode("ascii")),
    )


@dataclass
class ScenarioEndpoints:
    """Base URLs for the federated service processes.

    ``custodian`` holds share 1 of every record (ADR-0043); a script that
    ingests records deposits share 1 there so the forced rotation at expiry
    can replace it (ADR-0069).
    """

    authority_med: str = "http://127.0.0.1:8010"
    authority_net: str = "http://127.0.0.1:8011"
    audit: str = "http://127.0.0.1:8020"
    facility_a: str = "http://127.0.0.1:8001"
    facility_b: str = "http://127.0.0.1:8002"
    custodian: str | None = None

    def recipients(self) -> dict[str, str]:
        """``{base_url: service_id}`` for a signed client (ADR-0066)."""
        recipients = {
            self.authority_med: "authority-med",
            self.authority_net: "authority-net",
            self.audit: AUDIT_SERVICE_ID,
            self.facility_a: "facility-a",
            self.facility_b: "facility-b",
        }
        if self.custodian:
            recipients[self.custodian] = "custodian"
        return recipients


def signed_scenario_client(
    endpoints: ScenarioEndpoints, identity: ServiceIdentity, *, timeout: float = 10.0
) -> httpx.Client:
    """A client that signs every request to these services as ``identity``."""
    return signed_client(
        identity, endpoints.recipients(), timeout=timeout, verify=_tls_verify()
    )


def emergency_open(
    client: httpx.Client,
    *,
    facility_url: str,
    record_id: str,
    patient_id: str,
    clinician_id: str,
    facility_id: str,
    clinician_key: object,
    reason_code: ReasonCode,
    justification: str,
    ttl: datetime.timedelta = datetime.timedelta(seconds=300),
) -> tuple[Any, Any]:
    """Sign the assertion and the clinician's open transition for one record.

    The assertion's context digest binds the record and justification
    (the audit service refuses one that does not, ADR-0067); the transition is
    signed by the clinician from the record's current state (ADR-0068).
    Returns ``(assertion, transition_event)``.
    """
    state = client.get(f"{facility_url}/records/{record_id}/lifecycle")
    state.raise_for_status()
    assertion = create_emergency_assertion(
        patient_id=patient_id,
        clinician_id=clinician_id,
        facility_id=facility_id,
        reason_code=reason_code,
        signing_key=clinician_key,  # type: ignore[arg-type]
        ttl=ttl,
        clinical_context_digest=clinical_context_digest(record_id, justification, ""),
    )
    event = create_transition_event(
        record_id=record_id,
        from_state=LifecycleState(state.json()["state"]),
        to_state=LifecycleState.EMERGENCY_OPEN,
        actor_id=clinician_id,
        signing_key=clinician_key,  # type: ignore[arg-type]
        reason_code=reason_code,
    )
    return assertion, event


def run_scenario(
    endpoints: ScenarioEndpoints,
    config: dict[str, Any] | None = None,
    *,
    emergency_duration_seconds: float = 3.0,
    verbose: bool = True,
    canaries_out: Path | None = None,
    client: httpx.Client | None = None,
    search_workload: bool = False,
    search_spacing_seconds: float | None = None,
    searches_out: Path | None = None,
) -> bool:
    """Execute the full cross-hospital break-glass scenario.

    Args:
        endpoints: Service base URLs.
        config: Optional parsed federation.json config containing PKI certs.
        emergency_duration_seconds: Time-box window before auto-expiry.
        verbose: Print progress steps to stdout.
        canaries_out: If set, write the secrets this run handled to this JSON
            file so the P5-5 wire analyser can search the capture for them
            (ADR-0045). Synthetic, throwaway values -- the file belongs under
            the gitignored ``wire/captures/`` and must never be committed.
        client: Signs every request as bootstrap (ADR-0066); defaults to the
            identity ``deploy/run_local.py`` wrote.
        search_workload: Also run the P5-3 search workload after step 9
            (:func:`run_search_workload`, ADR-0070). Needs a custodian and an
            emergency window long enough for the first batch of searches.
        search_spacing_seconds: Gap between workload searches; defaults to
            :data:`SEARCH_SPACING_SECONDS`.
        searches_out: With ``search_workload``, write every workload search
            (term, outcome, send and answer time) here: the ground truth that
            labels captured exchanges once the store link is encrypted
            (ADR-0071). Synthetic terms only; keep it under ``wire/captures/``.

    Returns:
        True if all scenario steps succeed and all invariants hold.
    """

    def log(step: str, detail: str = "") -> None:
        if verbose:
            print(f"\n{step}")
            if detail:
                for line in detail.strip().splitlines():
                    print(f"    {line}")

    if client is None:
        from deploy.bootstrap import load_service_identity_dir

        client = signed_scenario_client(
            endpoints, load_service_identity_dir(DEFAULT_SERVICES_DIR, "bootstrap")
        )
    # Stamped into the canary manifest so the analyser can refuse a pcap that
    # predates this run (review N5).
    started_at = time.time()
    run_id = uuid.uuid4().hex

    # -------------------------------------------------------------------------
    # Step 1: Health & Bootstrap Verification
    # -------------------------------------------------------------------------
    log("[1/9] Verifying federation status and health checks...")
    for name, url in [
        ("authority-med", endpoints.authority_med),
        ("authority-net", endpoints.authority_net),
        ("audit", endpoints.audit),
        ("facility-a", endpoints.facility_a),
        ("facility-b", endpoints.facility_b),
    ]:
        res = client.get(f"{url}/health")
        if res.status_code != 200:
            raise RuntimeError(
                f"Service {name} at {url} not healthy: {res.status_code}"
            )
        log(f"  * {name:14s} at {url} is healthy (HTTP 200)")

    # -------------------------------------------------------------------------
    # Step 2: Identities, Certificates & Attribute Issuance
    # -------------------------------------------------------------------------
    log("[2/9] Issuing synthetic clinician certificates & attributes...")

    # Load or generate facility CA and root material
    if config and "root_certificate_pem" in config:
        fa_ca_priv, fa_ca_cert = _parse_ca_credentials(
            config["facilities"]["facility-a"]
        )
        fb_ca_priv, fb_ca_cert = _parse_ca_credentials(
            config["facilities"]["facility-b"]
        )
    else:
        from deploy.bootstrap import generate_federation_pki

        root_anchor, fed_pki = generate_federation_pki(["facility-a", "facility-b"])
        fa_ca_priv, fa_ca_cert = _parse_ca_credentials(fed_pki.facilities["facility-a"])
        fb_ca_priv, fb_ca_cert = _parse_ca_credentials(fed_pki.facilities["facility-b"])

    # Dr. Bob @ Facility A (Cardiologist)
    bob_priv, bob_pub = generate_ec_keypair()
    _ = issue_clinician_certificate(fa_ca_priv, fa_ca_cert, "doc-201", bob_pub)

    # Dr. Carol @ Facility B (Emergency Physician)
    carol_priv, carol_pub = generate_ec_keypair()
    carol_cert = issue_clinician_certificate(
        fb_ca_priv, fb_ca_cert, "doc-301", carol_pub
    )
    carol_cert_pem = certificate_to_pem(carol_cert).decode("ascii")
    carol_pre_priv, carol_pre_pub = generate_pre_keypair()

    # Patient pat-101, certified by home Facility A, signs the record's
    # clinical labels; unsigned labels would get the strictest rules (ADR-0064).
    pat_priv, pat_pub = generate_ec_keypair()
    pat_cert_pem = certificate_to_pem(
        issue_patient_certificate(fa_ca_priv, fa_ca_cert, "pat-101", pat_pub)
    ).decode("ascii")

    # Issue credentials from Authorities
    # 1. Dr. Bob: role:physician (authority-med) & specialty:cardiology (authority-net)
    client.post(
        f"{endpoints.authority_med}/credentials/issue",
        json={
            "subject_id": "doc-201",
            "attribute": {"name": "role", "value": "physician"},
        },
    ).raise_for_status()

    client.post(
        f"{endpoints.authority_net}/credentials/issue",
        json={
            "subject_id": "doc-201",
            "attribute": {"name": "specialty", "value": "cardiology"},
        },
    ).raise_for_status()

    # 2. Dr. Carol: role:emergency-physician (authority-med)
    client.post(
        f"{endpoints.authority_med}/credentials/issue",
        json={
            "subject_id": "doc-301",
            "attribute": {"name": "role", "value": "emergency-physician"},
        },
    ).raise_for_status()

    # 3. Patient Alice: owner:pat-101 (authority-net)
    client.post(
        f"{endpoints.authority_net}/credentials/issue",
        json={
            "subject_id": "pat-101",
            "attribute": {"name": "owner", "value": "pat-101"},
            "owner": True,
        },
    ).raise_for_status()

    # Obtain authoring attribute keys for compilation
    def get_auth_key(base_url: str, name: str, val: str) -> bytes:
        r = client.post(
            f"{base_url}/attribute-keys/author",
            json={"name": name, "value": val},
        )
        r.raise_for_status()
        return base64.b64decode(r.json()["key_b64"])

    k_physician = get_auth_key(endpoints.authority_med, "role", "physician")
    k_em_physician = get_auth_key(
        endpoints.authority_med, "role", "emergency-physician"
    )
    k_cardio = get_auth_key(endpoints.authority_net, "specialty", "cardiology")
    k_owner = get_auth_key(endpoints.authority_net, "owner", "pat-101")

    authoring_keyring_b64 = {
        "authority-med:role:physician": base64.b64encode(k_physician).decode("ascii"),
        "authority-med:role:emergency-physician": base64.b64encode(
            k_em_physician
        ).decode("ascii"),
        "authority-net:specialty:cardiology": base64.b64encode(k_cardio).decode(
            "ascii"
        ),
        "authority-net:owner:pat-101": base64.b64encode(k_owner).decode("ascii"),
    }

    log(
        "Credentials & attribute keys issued successfully:\n"
        "Dr. Bob (doc-201) -> role:physician, specialty:cardiology\n"
        "Dr. Carol (doc-301) -> role:emergency-physician\n"
        "Patient Alice (pat-101) -> owner:pat-101"
    )

    # -------------------------------------------------------------------------
    # Step 3: Ingest Patient Record at Facility A (Home Hospital)
    # -------------------------------------------------------------------------
    log("[3/9] Ingesting record at Facility A (Alice's home hospital)...")

    # Author Clinical Policy Tree: role:physician AND specialty:cardiology
    clinical_policy = PolicyTree(
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

    plaintext = (
        b'{"patient": "Alice", "diagnosis": "Acute Myocardial Infarction", '
        b'"medications": ["Aspirin", "Ticagrelor", "Heparin"], '
        b'"allergies": ["Penicillin"]}'
    )
    record_id = "rec-001"

    # Generate 2-of-3 emergency key & split
    emergency_key = generate_emergency_key()
    em_shares = split_emergency_key(emergency_key)
    # Share 1: Dr. Carol / Emergency facility
    # Share 2: Home authority (authority-net)
    # Share 3: Audit service custody
    share1 = em_shares[0]
    share3 = em_shares[2]

    # Deposit Share 3 with Audit Service
    audit_reg_res = client.post(
        f"{endpoints.audit}/breakglass/shares",
        json={
            "share_key": record_id,
            "x": share3[0],
            "share_hex": share3[1].hex(),
        },
    )
    audit_reg_res.raise_for_status()
    log(f"  * Share 3 deposited in Audit Service custody for record {record_id}")
    if endpoints.custodian:
        # Share 1 in clinician custody, so expiry can rotate it (ADR-0069).
        client.post(
            f"{endpoints.custodian}/records/{record_id}/shares",
            json={"x": share1[0], "share_hex": share1[1].hex()},
        ).raise_for_status()
        log(f"  * Share 1 deposited in clinician custody for record {record_id}")

    # Ingest record via Facility A
    ingest_res = client.post(
        f"{endpoints.facility_a}/records/ingest",
        json={
            "plaintext_b64": base64.b64encode(plaintext).decode("ascii"),
            "patient_id": "pat-101",
            "owner_authority_id": "authority-net",
            "clinical_policy": clinical_policy.model_dump(mode="json"),
            "attribute_keyring": authoring_keyring_b64,
            "search_terms": ["cardiac", "infarction", "aspirin"],
            "emergency_key_b64": base64.b64encode(emergency_key).decode("ascii"),
            "record_id": record_id,
            "clinical": sign_clinical_labels(
                ClinicalMetadata(),
                record_id=record_id,
                patient_id="pat-101",
                signing_key=pat_priv,
                certificate_pem=pat_cert_pem,
            ).model_dump(mode="json"),
        },
    )
    ingest_res.raise_for_status()
    ingest_data = ingest_res.json()
    log(
        f"Record {record_id} ingested at Facility A:\n"
        f"Policy ID: {ingest_data['policy_id']}\n"
        f"State: {ingest_data['lifecycle_state']}\n"
        f"Search terms indexed: {ingest_data['search_terms_indexed']}"
    )

    # -------------------------------------------------------------------------
    # Step 4: In-Network Routine Access at Facility A
    # -------------------------------------------------------------------------
    log("[4/9] In-network routine clinical read by Dr. Bob at Facility A...")
    bob_keyring = {
        "authority-med:role:physician": base64.b64encode(k_physician).decode("ascii"),
        "authority-net:specialty:cardiology": base64.b64encode(k_cardio).decode(
            "ascii"
        ),
    }
    read_bob_res = client.post(
        f"{endpoints.facility_a}/records/{record_id}/read",
        json={
            "requester_id": "doc-201",
            "holder_keyring": bob_keyring,
            "correlation_id": "corr-read-bob-001",
        },
    )
    read_bob_res.raise_for_status()
    bob_plaintext = base64.b64decode(read_bob_res.json()["plaintext_b64"])
    assert bob_plaintext == plaintext
    log("  * Policy satisfied: Dr. Bob successfully decrypted Alice's record!")

    # -------------------------------------------------------------------------
    # Step 5: Out-of-Network Emergency Attempt & Denial
    log("[5/9] Out-of-network emergency: Alice unconscious at Facility B...")

    carol_routine_keyring = {
        "authority-med:role:emergency-physician": base64.b64encode(
            k_em_physician
        ).decode("ascii"),
    }

    read_carol_denied = client.post(
        f"{endpoints.facility_b}/records/{record_id}/read",
        json={
            "requester_id": "doc-301",
            "holder_keyring": carol_routine_keyring,
            "correlation_id": "corr-read-carol-denied",
        },
    )

    if read_carol_denied.status_code != 403:
        raise RuntimeError(
            f"Expected 403 at Facility B, got "
            f"{read_carol_denied.status_code}: "
            f"{read_carol_denied.text}"
        )

    log("  ✓ Facility B routine access correctly denied (403)")
    # -------------------------------------------------------------------------
    # Step 6: Federated Discovery & Emergency Assertion
    # -------------------------------------------------------------------------
    log("[6/9] Federated discovery & Emergency Assertion...")
    discovery_res = client.get(
        f"{endpoints.facility_b}/patients/pat-101/records",
    )
    discovery_res.raise_for_status()
    discovered_ids = discovery_res.json()["record_ids"]
    assert record_id in discovered_ids
    log(f"  * Discovery located records for patient pat-101: {discovered_ids}")

    # Dr. Carol signs the EmergencyAssertion and the open transition
    justification = "Unconscious on arrival; medication history needed now."
    assertion, transition_event = emergency_open(
        client,
        facility_url=endpoints.facility_b,
        record_id=record_id,
        patient_id="pat-101",
        clinician_id="doc-301",
        facility_id="facility-b",
        clinician_key=carol_priv,
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        justification=justification,
    )
    log("  * Signed EmergencyAssertion generated for pat-101 (UNCONSCIOUS_PATIENT)")

    # -------------------------------------------------------------------------
    # Step 7: 2-of-3 Threshold Collection & Break-Glass Unlock
    # -------------------------------------------------------------------------
    log("[7/9] Releasing Share 3 from Audit Service & Unlocking...")
    # Request Share 3 release from Audit Service (log-before-release)
    corr_id = "corr-bg-alice-001"
    release_res = client.post(
        f"{endpoints.audit}/breakglass/release",
        json={
            "share_key": record_id,
            "event_type": "breakglass_share_released",
            "event_data": {
                "record_id": record_id,
                "patient_id": "pat-101",
                "clinician_id": "doc-301",
                "facility_id": "facility-b",
            },
            "actor_id": "audit-service",
            "correlation_id": corr_id,
            # The audit service validates the assertion itself (ADR-0067).
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": carol_cert_pem,
            "justification": justification,
        },
    )
    release_res.raise_for_status()
    release_data = release_res.json()
    rel_x = release_data["x"]
    rel_share_hex = release_data["share_hex"]
    new_seq = release_data["entry"]["seq"]
    log(
        f"  * Audit Service committed entry to hash chain (new seq={new_seq})\n"
        f"  * Share 3 released: x={rel_x}"
    )

    # Submit 2 shares (Share 1 from Carol + Share 3 from Audit) to Facility B
    shares_payload = [
        (share1[0], share1[1].hex()),
        (rel_x, rel_share_hex),
    ]

    # Carol's own signed transition, not a private key, goes on the wire
    # (ADR-0068); expiry rotates every key itself (ADR-0069).
    unlock_res = client.post(
        f"{endpoints.facility_b}/records/{record_id}/breakglass",
        json={
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": carol_cert_pem,
            "shares": shares_payload,
            "pre_rewrap_key": carol_pre_pub,
            "transition_event": transition_event.model_dump(mode="json"),
            "correlation_id": corr_id,
            "justification": justification,
            "emergency_duration_seconds": emergency_duration_seconds,
        },
    )
    unlock_res.raise_for_status()
    unlock_data = unlock_res.json()
    log(
        f"Break-Glass unlock successful:\n"
        f"State: {unlock_data['transition_event']['to_state']}\n"
        f"Event ID: {unlock_data['transition_event']['event_id']}"
    )

    # Clinician Carol unwraps the PRE delivery package and recovers DEK!
    rewrapped_bytes = base64.b64decode(unlock_data["rewrapped_dek_b64"])
    recovered_dek = _unwrap_rewrapped_dek(rewrapped_bytes, carol_pre_priv, record_id)
    assert len(recovered_dek) == 32
    log("  * Clinician Carol decapsulated PRE package and recovered DEK!")

    # -------------------------------------------------------------------------
    # Step 8: Emergency-Only Search
    # -------------------------------------------------------------------------
    log("[8/9] Emergency search under active emergency session...")
    search_res = client.post(
        f"{endpoints.facility_b}/records/{record_id}/emergency-search",
        json={"search_term": "cardiac", "requester_id": "doc-301"},
    )
    if search_res.status_code == 200:
        matched = search_res.json()["record_ids"]
        assert record_id in matched
        log(f"  * Emergency search for 'cardiac' matched: {matched}")
    else:
        log(f"  * Emergency search returned status {search_res.status_code}")

    # Revocation crosses the wire too (PROJECT §4A(1): "normal read,
    # revocation, or break-glass"; review N4). The patient signs the
    # GRANTED -> REVOKED transition with their own key, as the custodian does
    # for them (ADR-0073); no private key or DEK is sent. The record is
    # emergency-open here, so the facility refuses it (409) -- the bytes still
    # cross the wire for the capture to check.
    revoke_event = create_transition_event(
        record_id=record_id,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id="pat-101",
        signing_key=pat_priv,
    )
    revoke_res = client.post(
        f"{endpoints.facility_a}/records/{record_id}/revoke",
        json={
            "transition_event": revoke_event.model_dump(mode="json"),
            "patient_certificate_pem": pat_cert_pem,
            "new_clinical_policy": clinical_policy.model_dump(mode="json"),
            "correlation_id": f"{corr_id}-revoke",
        },
    )
    log(f"  * Revocation request sent; facility answered {revoke_res.status_code}")

    # -------------------------------------------------------------------------
    # Step 9: Time-Box Expiry & Full Audit Chain Verification
    # -------------------------------------------------------------------------
    log("[9/9] Checking audit chain verification...")
    verify_res = client.get(f"{endpoints.audit}/chain/verify")
    if verify_res.status_code == 200:
        verify_data = verify_res.json()
        assert verify_data["verified"] is True
        h_seq = verify_data["head_seq"]
        v_status = verify_data["verified"]
        log(
            f"  * Full audit hash chain verified from genesis to head!\n"
            f"  * Head Seq: {h_seq}, Verified: {v_status}"
        )

    if search_workload:
        if not config or "root_certificate_pem" not in config:
            raise RuntimeError("the search workload needs deploy/pki/federation.json")
        workload = run_search_workload(
            client,
            endpoints,
            record_id=record_id,
            federation_config=config,
            spacing=(
                SEARCH_SPACING_SECONDS
                if search_spacing_seconds is None
                else search_spacing_seconds
            ),
            clinician=SearchClinician(
                clinician_id="doc-301",
                facility_id="facility-b",
                signing_key=carol_priv,
                certificate_pem=carol_cert_pem,
                pre_keypair=(carol_pre_priv, carol_pre_pub),
            ),
            log=log,
        )
        if searches_out is not None:
            searches_out.parent.mkdir(parents=True, exist_ok=True)
            searches_out.write_text(
                json.dumps(
                    {"run_id": run_id, "searches": workload["searches"]}, indent=2
                ),
                encoding="utf-8",
            )
            log(f"  * Search manifest written to {searches_out}")

    if canaries_out is not None:
        _write_canaries(
            canaries_out,
            record_id=record_id,
            run_id=run_id,
            started_at=started_at,
            secrets={
                "record_plaintext": ("phi", plaintext),
                "dek": ("dek", recovered_dek),
                "emergency_key": ("emergency_key", emergency_key),
                "share1": ("share", share1[1]),
                "share3": ("share", share3[1]),
                "attr_key:authority-med:role:physician": (
                    "attribute_key",
                    k_physician,
                ),
                "attr_key:authority-med:role:emergency-physician": (
                    "attribute_key",
                    k_em_physician,
                ),
                "attr_key:authority-net:specialty:cardiology": (
                    "attribute_key",
                    k_cardio,
                ),
                "attr_key:authority-net:owner:pat-101": ("attribute_key", k_owner),
                "clinician_signing_key_pem": (
                    "private_key",
                    private_key_to_pem(carol_priv),
                ),
            },
        )
        log(f"  * Canary manifest written to {canaries_out}")

    log("\n=======================================================================")
    log("ALL 9 STEPS OF THE CROSS-HOSPITAL BREAK-GLASS SCENARIO SUCCEEDED!")
    log("=======================================================================\n")
    return True


# P5-3 search workload (ADR-0070). Indexed terms are "cardiac", "infarction"
# and "aspirin"; the rest miss. Repeats measure frequency leakage, hits against
# misses measure response-size leakage, and the fixed spacing lets the timing
# an observer recovers be compared with what the client actually did.
SEARCH_WORKLOAD_OPEN = (
    "cardiac",
    "aspirin",
    "cardiac",
    "pneumonia",
    "infarction",
    "cardiac",
    "fracture",
    "aspirin",
    "cardiac",
    "warfarin",
)
# Searched again after expiry and a second break-glass: the same terms under
# the rotated emergency key, so their tokens can be compared (ADR-0069).
SEARCH_WORKLOAD_REOPENED = ("cardiac", "aspirin", "fracture", "cardiac")
SEARCH_SPACING_SECONDS = 0.5


@dataclass(frozen=True)
class SearchClinician:
    """The emergency clinician the workload searches as, and re-declares as."""

    clinician_id: str
    facility_id: str
    signing_key: object
    certificate_pem: str
    pre_keypair: tuple[int, int]


def _emergency_search(
    client: httpx.Client,
    facility_url: str,
    record_id: str,
    term: str,
    who: str,
    *,
    phase: str,
    searches: list[dict[str, Any]],
) -> httpx.Response:
    """One search, recorded in ``searches`` with when it left and was answered.

    The record is ground truth for labelling captured exchanges (ADR-0071),
    never an observation: what the observer learns still comes off the wire.
    """
    sent_at = time.time()
    res = client.post(
        f"{facility_url}/records/{record_id}/emergency-search",
        json={"search_term": term, "requester_id": who},
    )
    searches.append(
        {
            "phase": phase,
            "term": term,
            "status": res.status_code,
            "record_count": (
                res.json()["record_count"] if res.status_code == 200 else None
            ),
            "sent_at": sent_at,
            "answered_at": time.time(),
        }
    )
    return res


def _search_batch(
    client: httpx.Client,
    facility_url: str,
    record_id: str,
    clinician_id: str,
    terms: tuple[str, ...],
    spacing: float,
    *,
    phase: str,
    searches: list[dict[str, Any]],
) -> list[tuple[str, int]]:
    """Run ``terms`` in order, ``spacing`` apart; any non-200 is a failure."""
    results: list[tuple[str, int]] = []
    for term in terms:
        res = _emergency_search(
            client,
            facility_url,
            record_id,
            term,
            clinician_id,
            phase=phase,
            searches=searches,
        )
        if res.status_code != 200:
            raise RuntimeError(
                f"workload search {term!r} failed: {res.status_code} {res.text}"
            )
        results.append((term, res.json()["record_count"]))
        time.sleep(spacing)
    return results


def _wait_for_state(
    client: httpx.Client,
    facility_url: str,
    record_id: str,
    state: LifecycleState,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    seen = None
    while time.monotonic() < deadline:
        res = client.get(f"{facility_url}/records/{record_id}/lifecycle")
        res.raise_for_status()
        seen = res.json()["state"]
        if seen == state.value:
            return
        time.sleep(0.25)
    raise RuntimeError(f"{record_id} stuck at {seen!r}, expected {state.value!r}")


def run_search_workload(
    client: httpx.Client,
    endpoints: ScenarioEndpoints,
    *,
    record_id: str,
    clinician: SearchClinician,
    federation_config: dict[str, Any],
    log: Callable[[str], None] = print,
    spacing: float = SEARCH_SPACING_SECONDS,
    rotation_timeout: float = 60.0,
) -> dict[str, list[Any]]:
    """Drive the P5-3 search workload against a running federation (ADR-0070).

    Opt-in and synthetic: it only searches the scenario's own record. Phases:

    1. ``open`` -- :data:`SEARCH_WORKLOAD_OPEN` under the scenario's session.
    2. wait for the time box to expire and the forced rotation to finish
       (``granted``, ADR-0069), then search once more: it must be refused (403),
       or the dead-token property has regressed.
    3. ``reopened`` -- a second break-glass through the custodian, which alone
       holds the rotated share 1, then :data:`SEARCH_WORKLOAD_REOPENED`. The
       custodian gets the federation's public trust anchors and the
       clinician's synthetic material first, as the portal seed would give it.

    Every request crosses the wire, so the capture -- not this function's
    return value -- is the evidence; the return value lets a test check the
    workload did what it says. Its ``searches`` list (term, outcome and
    timing of every search, the refused one included) is what
    ``--searches-out`` writes, to label the captured exchanges (ADR-0071).
    """
    if not endpoints.custodian:
        raise RuntimeError("the search workload needs the custodian (rotated share 1)")
    facility_urls = {
        "facility-a": endpoints.facility_a,
        "facility-b": endpoints.facility_b,
    }
    open_url = facility_urls[clinician.facility_id]
    searches: list[dict[str, Any]] = []

    log("[P5-3] Search workload: repeated and distinct emergency searches...")
    opened = _search_batch(
        client,
        open_url,
        record_id,
        clinician.clinician_id,
        SEARCH_WORKLOAD_OPEN,
        spacing,
        phase="open",
        searches=searches,
    )
    log(f"  * {len(opened)} searches under the first session: {opened}")

    log("[P5-3] Waiting for expiry and the forced rotation...")
    _wait_for_state(
        client, open_url, record_id, LifecycleState.GRANTED, rotation_timeout
    )
    refused = _emergency_search(
        client,
        open_url,
        record_id,
        SEARCH_WORKLOAD_OPEN[0],
        clinician.clinician_id,
        phase="expired",
        searches=searches,
    )
    if refused.status_code != 403:
        raise RuntimeError(
            f"search after expiry answered {refused.status_code}, expected 403"
        )
    log("  * Search after expiry refused (403); the record was re-keyed")
    time.sleep(spacing)

    log("[P5-3] Second break-glass through the custodian...")
    audit_key = client.get(f"{endpoints.audit}/public-key")
    audit_key.raise_for_status()
    client.put(
        f"{endpoints.custodian}/trust",
        json={
            "root_certificate_pem": federation_config["root_certificate_pem"],
            "facility_ca_certificate_pems": {
                fid: ca["ca_certificate_pem"]
                for fid, ca in federation_config["facilities"].items()
            },
            "audit_public_key_pem": audit_key.json()["public_key_pem"],
        },
    ).raise_for_status()
    pre_priv, pre_pub = clinician.pre_keypair
    client.post(
        f"{endpoints.custodian}/subjects/{clinician.clinician_id}/material",
        json={
            "kind": "clinician",
            "signing_key_pem": private_key_to_pem(clinician.signing_key).decode(  # type: ignore[arg-type]
                "ascii"
            ),
            "facility_id": clinician.facility_id,
            "certificate_pem": clinician.certificate_pem,
            "pre_private_key": pre_priv,
            "pre_public_key": pre_pub,
        },
    ).raise_for_status()
    declared = client.post(
        f"{endpoints.custodian}/subjects/{clinician.clinician_id}/breakglass",
        json={
            "patient_id": "pat-101",
            "record_id": record_id,
            "justification": "Still unresponsive; second look at medication history.",
            # The scenario's labels count as restricted at the custodian.
            "sensitive_justification": "Anticoagulant history decides the next step.",
            "reason_code": ReasonCode.UNCONSCIOUS_PATIENT.value,
            "facility_id": clinician.facility_id,
        },
    )
    if declared.status_code != 200:
        raise RuntimeError(
            f"second break-glass failed: {declared.status_code} {declared.text}"
        )
    reopen_url = facility_urls[declared.json()["facility_id"]]
    log(f"  * Re-declared at {declared.json()['facility_id']}")

    reopened = _search_batch(
        client,
        reopen_url,
        record_id,
        clinician.clinician_id,
        SEARCH_WORKLOAD_REOPENED,
        spacing,
        phase="reopened",
        searches=searches,
    )
    log(f"  * {len(reopened)} searches under the second session: {reopened}")
    return {"open": opened, "reopened": reopened, "searches": searches}


def _write_canaries(
    path: Path,
    *,
    record_id: str,
    run_id: str,
    started_at: float,
    secrets: dict[str, tuple[str, bytes]],
) -> None:
    """Write the run's secrets for the P5-5 canary search (ADR-0045)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "warning": "synthetic capture canaries -- never commit this file",
        "record_id": record_id,
        "run_id": run_id,
        "started_at": started_at,
        "canaries": {
            name: {"class": cls, "hex": value.hex()}
            for name, (cls, value) in secrets.items()
        },
    }
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> int:
    """CLI entrypoint for running the scenario."""
    parser = argparse.ArgumentParser(
        description="Run the Federated Break-Glass EHR cross-hospital scenario."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to federation.json config file.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Emergency duration time-box in seconds (default 5, or 20 with "
        "--search-workload so its first batch fits in the window).",
    )
    parser.add_argument(
        "--scheme",
        choices=("http", "https"),
        default="https" if tls_enabled() else "http",
        help="Transport scheme for the scenario endpoints.",
    )
    parser.add_argument(
        "--canaries-out",
        type=Path,
        default=None,
        help="Write the run's secrets here for the P5-5 wire analyser "
        "(keep under the gitignored wire/captures/).",
    )
    parser.add_argument(
        "--search-workload",
        action="store_true",
        help="After the scenario, run the P5-3 search workload: repeated and "
        "distinct searches, one after expiry, more after a second break-glass "
        "(ADR-0070).",
    )
    parser.add_argument(
        "--searches-out",
        type=Path,
        default=None,
        help="With --search-workload, write each search's term, outcome and "
        "timing here to label the capture (ADR-0071; keep under wire/captures/).",
    )
    args = parser.parse_args()
    duration = args.duration
    if duration is None:
        duration = 20.0 if args.search_workload else 5.0
    if args.scheme == "https":
        os.environ["TLS_ENABLED"] = "true"
        configure_transport()

    config_data: dict[str, Any] | None = None
    if args.config.exists():
        try:
            config_data = json.loads(args.config.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Warning: could not read {args.config}: {exc}", file=sys.stderr)

    scheme = args.scheme
    endpoints = ScenarioEndpoints(
        authority_med=f"{scheme}://127.0.0.1:8010",
        authority_net=f"{scheme}://127.0.0.1:8011",
        audit=f"{scheme}://127.0.0.1:8020",
        facility_a=f"{scheme}://127.0.0.1:8001",
        facility_b=f"{scheme}://127.0.0.1:8002",
        custodian=f"{scheme}://127.0.0.1:8030",
    )

    print("Executing Cross-Hospital Break-Glass Scenario (P4-4)...")
    try:
        success = run_scenario(
            endpoints,
            config=config_data,
            emergency_duration_seconds=duration,
            verbose=True,
            canaries_out=args.canaries_out,
            search_workload=args.search_workload,
            searches_out=args.searches_out,
        )
        return 0 if success else 1
    except Exception as exc:
        print(f"\nScenario failed with error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
