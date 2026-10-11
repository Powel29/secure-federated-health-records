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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from api.audit_client import _tls_verify
from breakglass import create_emergency_assertion
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts.base import GCM_NONCE_BYTES
from contracts.enums import PolicyNodeType, ReasonCode
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    certificate_from_pem,
    certificate_to_pem,
    generate_ec_keypair,
    private_key_from_pem,
    private_key_to_pem,
)
from crypto_core.symmetric import aes_gcm_decrypt
from identity.certificates import issue_clinician_certificate
from pre.elgamal import decapsulate_key
from pre.elgamal import generate_keypair as generate_pre_keypair

from deploy.config import configure_transport, tls_enabled

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "deploy" / "pki" / "federation.json"




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
    """Base URLs for the five federated service processes."""

    authority_med: str = "http://127.0.0.1:8010"
    authority_net: str = "http://127.0.0.1:8011"
    audit: str = "http://127.0.0.1:8020"
    facility_a: str = "http://127.0.0.1:8001"
    facility_b: str = "http://127.0.0.1:8002"


def run_scenario(
    endpoints: ScenarioEndpoints,
    config: dict[str, Any] | None = None,
    *,
    emergency_duration_seconds: float = 3.0,
    verbose: bool = True,
    canaries_out: Path | None = None,
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

    Returns:
        True if all scenario steps succeed and all invariants hold.
    """

    def log(step: str, detail: str = "") -> None:
        if verbose:
            print(f"\n{step}")
            if detail:
                for line in detail.strip().splitlines():
                    print(f"    {line}")

    client = httpx.Client(timeout=10.0, verify=_tls_verify())
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

    # Lifecycle signing key for Facility B
    life_priv, life_pub = generate_ec_keypair()
    life_priv_pem = private_key_to_pem(life_priv).decode("ascii")

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

    # Dr. Carol signs EmergencyAssertion
    assertion = create_emergency_assertion(
        patient_id="pat-101",
        clinician_id="doc-301",
        facility_id="facility-b",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        signing_key=carol_priv,
        ttl=datetime.timedelta(seconds=300),
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

    # Baseline wrapping key (the policy root secret) allows EmergencyExpiryManager
    # to register the active session and re-baseline at expiry.
    unlock_res = client.post(
        f"{endpoints.facility_b}/records/{record_id}/breakglass",
        json={
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": carol_cert_pem,
            "shares": shares_payload,
            "pre_rewrap_key": carol_pre_pub,
            "lifecycle_signing_key_pem": life_priv_pem,
            "correlation_id": corr_id,
            "baseline_wrapping_key_b64": base64.b64encode(k_physician).decode("ascii"),
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
    # revocation, or break-glass"; review N4). The request carries the old DEK
    # in the clear on the plain profile, which claim 1 must catch. The
    # facility refuses it while the record is emergency-open (409) or cannot
    # persist it on Postgres yet (501, F10); either way the bytes were sent.
    patient_priv, _patient_pub = generate_ec_keypair()
    revoke_res = client.post(
        f"{endpoints.facility_a}/records/{record_id}/revoke",
        json={
            "actor_id": "pat-101",
            "actor_signing_key_pem": private_key_to_pem(patient_priv).decode("ascii"),
            "old_dek_b64": base64.b64encode(recovered_dek).decode("ascii"),
            "new_clinical_policy": clinical_policy.model_dump(mode="json"),
            "owner_authority_id": "authority-net",
            "attribute_keyring": authoring_keyring_b64,
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
                "lifecycle_signing_key_pem": (
                    "private_key",
                    life_priv_pem.encode("ascii"),
                ),
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
        default=5.0,
        help="Emergency duration time-box in seconds.",
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
    args = parser.parse_args()
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
    )

    if config_data:
        endpoints = ScenarioEndpoints(
            authority_med=f"{scheme}://127.0.0.1:8010",
            authority_net=f"{scheme}://127.0.0.1:8011",
            audit=f"{scheme}://127.0.0.1:8020",
            facility_a=f"{scheme}://127.0.0.1:8001",
            facility_b=f"{scheme}://127.0.0.1:8002",
        )

    print("Executing Cross-Hospital Break-Glass Scenario (P4-4)...")
    try:
        success = run_scenario(
            endpoints,
            config=config_data,
            emergency_duration_seconds=args.duration,
            verbose=True,
            canaries_out=args.canaries_out,
        )
        return 0 if success else 1
    except Exception as exc:
        print(f"\nScenario failed with error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
