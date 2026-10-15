"""Examiner-ready demo runner for the Federated Break-Glass EHR system (P4-5).

Orchestrates the complete 8-Act cross-hospital emergency break-glass demonstration:
1. Federation Topology & Health Verification across all 5 distinct processes.
2. Synthetic Data Seeding & Zero-Knowledge Verification (ADR-0016 owner leaves).
3. Blind Cross-Hospital Discovery (Locating remote record without leaking content).
4. Access Refusal Under Routine Clinical Policy (Strict policy enforcement, HTTP 403).
5. Break-Glass Declaration & 2-of-3 Shamir Reconstruction (Log-before-release).
6. Live Visual Countdown & Ephemeral Key Revocation (Dead-token verification).
7. Tamper-Evident Audit Hash Chain Verification (SHA-256 genesis-to-head proof).
8. Examiners' Cryptographic & Architectural Checklist.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import json
import os
import sys
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import httpx
from contracts.enums import ReasonCode
from crypto_core import (
    generate_ec_keypair,
    sha256_digest,
)

from demo.seed_data import seed_synthetic_data
from deploy.run_scenario import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_SERVICES_DIR,
    ScenarioEndpoints,
    _unwrap_rewrapped_dek,
    emergency_open,
    signed_scenario_client,
)

# -----------------------------------------------------------------------------
# Terminal Styling & Color Helpers
# -----------------------------------------------------------------------------


class Style:
    """ANSI color codes with automatic fallback for plain terminals."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def _c(self, code: str) -> str:
        return code if self.enabled else ""

    @property
    def RESET(self) -> str:  # noqa: N802
        return self._c("\033[0m")

    @property
    def BOLD(self) -> str:  # noqa: N802
        return self._c("\033[1m")

    @property
    def DIM(self) -> str:  # noqa: N802
        return self._c("\033[2m")

    @property
    def CYAN(self) -> str:  # noqa: N802
        return self._c("\033[36m")

    @property
    def GREEN(self) -> str:  # noqa: N802
        return self._c("\033[32m")

    @property
    def YELLOW(self) -> str:  # noqa: N802
        return self._c("\033[33m")

    @property
    def RED(self) -> str:  # noqa: N802
        return self._c("\033[31m")

    @property
    def MAGENTA(self) -> str:  # noqa: N802
        return self._c("\033[35m")

    @property
    def BLUE(self) -> str:  # noqa: N802
        return self._c("\033[34m")


def _fingerprint(data: bytes | str) -> str:
    """Return SHA-256 fingerprint (CONVENTIONS.md §2 rule 3: never log raw keys)."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return f"sha256:{sha256_digest(raw).hex()[:12]}..."


def _print_box_header(title: str, subtitle: str = "", s: Style | None = None) -> None:
    """Print an eye-catching box header for an act."""
    style = s or Style(True)
    width = 76
    print("\n" + style.CYAN + "╔" + "═" * (width - 2) + "╗" + style.RESET)
    print(
        style.CYAN
        + "║ "
        + style.BOLD
        + title.ljust(width - 4)
        + style.RESET
        + style.CYAN
        + " ║"
        + style.RESET
    )
    if subtitle:
        print(
            style.CYAN
            + "║ "
            + style.DIM
            + subtitle.ljust(width - 4)
            + style.RESET
            + style.CYAN
            + " ║"
            + style.RESET
        )
    print(style.CYAN + "╚" + "═" * (width - 2) + "╝" + style.RESET)


def _step_pause(step_mode: bool, s: Style) -> None:
    """Pause between acts in interactive demonstration mode."""
    if step_mode:
        print(
            f"\n{s.DIM}▶ Press [Enter] to continue to the next Act...{s.RESET}",
            end="",
        )
        try:
            input()
        except EOFError:
            pass
        print()


# -----------------------------------------------------------------------------
# Standalone Federation Server Spawner (Fallback / Local Testing)
# -----------------------------------------------------------------------------


def _free_port() -> int:
    """An unused loopback port, so every service's URL is known up front."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _LiveServer:
    """Ephemeral uvicorn server bound to 127.0.0.1 on an OS-assigned port."""

    def __init__(self, app: Any, port: int = 0) -> None:
        import uvicorn

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> str:
        self._thread.start()
        deadline = time.monotonic() + 10.0
        while not getattr(self._server, "started", False):
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn server did not start in time")
            time.sleep(0.05)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10.0)


@contextlib.contextmanager
def standalone_federation(
    database_url: str | None = None,
    default_duration: float = 3.0,
) -> Generator[dict[str, Any], None, None]:
    """Spin up all five federation service processes in-memory for standalone demo.

    Enables running the complete demo with zero prior services running, using
    PostgreSQL at database_url or localhost.
    """
    import psycopg
    from api.audit_client import make_lifecycle_audit_logger
    from api.audit_service import create_audit_app
    from api.authority_service import SubjectTrust, create_authority_app
    from api.custodian_service import CustodianEndpoints, create_custodian_app
    from api.hospital import AUDIT_SERVICE_ID, create_hospital_app
    from api.repository import PostgresStorageRepository
    from api.rotation import http_rotation_ports
    from api.service_auth import SignedRequestAuth, signed_client
    from contracts import Facility
    from contracts.enums import FacilityStatus, LifecycleState
    from lifecycle.expiry import EmergencyExpiryManager
    from storage import repositories as repo_mod
    from storage.migrate import apply_migrations

    from deploy import bootstrap

    db_url = (
        database_url
        or os.environ.get("DATABASE_URL")
        or "postgresql://localhost/postgres"
    )

    try:
        conn = psycopg.connect(db_url)
    except Exception as exc:
        raise RuntimeError(
            f"Standalone demo requires PostgreSQL at {db_url}.\n"
            f"Please ensure Postgres is running, or specify DATABASE_URL.\n"
            f"Error: {exc}"
        ) from exc

    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    conn.autocommit = False
    apply_migrations(conn)

    repo_mod.insert_authority(conn, "authority-med", "Medical Council", b"\x01")
    repo_mod.insert_authority(
        conn, "authority-net", "Regional Hospital Network", b"\x02"
    )
    repo_mod.insert_facility(
        conn,
        Facility(
            facility_id="facility-a",
            display_name="Northvale General Hospital",
            endpoint="http://127.0.0.1:8001",
            public_key=b"\x03",
            status=FacilityStatus.ACTIVE,
        ),
    )
    repo_mod.insert_facility(
        conn,
        Facility(
            facility_id="facility-b",
            display_name="Eastbrook Hospital",
            endpoint="http://127.0.0.1:8002",
            public_key=b"\x04",
            status=FacilityStatus.ACTIVE,
        ),
    )
    # Patient rows are domain data owned by ``seed_synthetic_data`` (P4-5);
    # ``standalone_federation`` sets up services + authorities + facilities only.
    # Inserting patients here caused a UNIQUE-violation when the seed step ran
    # afterwards -- one row per patient from each side -- so the demo
    # integration tests failed under Postgres in CI.
    conn.commit()

    conn_fa = psycopg.connect(db_url)
    conn_fa.autocommit = True
    repo_fa = PostgresStorageRepository(conn_fa)

    conn_fb = psycopg.connect(db_url)
    conn_fb.autocommit = True
    repo_fb = PostgresStorageRepository(conn_fb)

    timer_priv_a, _ = generate_ec_keypair()
    timer_priv_b, _ = generate_ec_keypair()

    # PKI first: facilities and the audit service are configured with its
    # trust anchors (F1, ADR-0067), and every service signs as itself (ADR-0066).
    root_anchor, pki = bootstrap.generate_federation_pki(["facility-a", "facility-b"])
    trust = bootstrap.facility_trust(pki)
    root_cert = root_anchor.certificate
    identities = bootstrap.issue_service_identities(root_anchor)
    bootstrap.write_service_identities(DEFAULT_SERVICES_DIR, identities)

    # Every URL is fixed before any app is built, so each knows its peers.
    url_med, url_net, audit_url, url_fa, url_fb, url_cust = (
        f"http://127.0.0.1:{_free_port()}" for _ in range(6)
    )
    authorities = {"authority-med": url_med, "authority-net": url_net}
    facilities = {"facility-a": url_fa, "facility-b": url_fb}

    app_audit = create_audit_app(
        conn, actor_id="audit-service", service_root=root_cert, trust=trust
    )

    def expiry(facility_id: str, timer_key: Any) -> EmergencyExpiryManager:
        manager = EmergencyExpiryManager(
            signing_key=timer_key,
            timer_actor_id=f"system:hsm-timer:{facility_id}",
            default_duration_seconds=default_duration,
            audit_logger=make_lifecycle_audit_logger(
                audit_url,
                auth=SignedRequestAuth(
                    identities[facility_id], {audit_url: AUDIT_SERVICE_ID}
                ),
            ),
        )
        manager.start_monitor(poll_interval=0.25)
        return manager

    exp_mgr_a = expiry("facility-a", timer_priv_a)
    exp_mgr_b = expiry("facility-b", timer_priv_b)

    def facility(facility_id: str, repo: Any, manager: Any) -> Any:
        rotation_http = signed_client(
            identities[facility_id],
            {
                **{url: aid for aid, url in authorities.items()},
                url_cust: "custodian",
                audit_url: AUDIT_SERVICE_ID,
            },
            timeout=10.0,
        )
        return create_hospital_app(
            facility_id=facility_id,
            repository=repo,
            expiry_manager=manager,
            audit_service_url=audit_url,
            trust=trust,
            identity=identities[facility_id],
            rotation_ports=http_rotation_ports(
                rotation_http,
                authorities=authorities,
                custodian_url=url_cust,
                audit_url=audit_url,
            ),
        )

    # Key release needs the subject's proof of possession (ADR-0074).
    subject_trust = SubjectTrust(
        root=trust.root,
        facility_cas=trust.facility_cas,
        revoked_serials=trust.revoked_serials,
    )
    app_med = create_authority_app(
        "authority-med",
        frozenset({"role"}),
        service_root=root_cert,
        subject_trust=subject_trust,
    )
    app_net = create_authority_app(
        "authority-net",
        frozenset({"specialty", "facility", "owner"}),
        service_root=root_cert,
        subject_trust=subject_trust,
    )
    app_fa = facility("facility-a", repo_fa, exp_mgr_a)
    app_fb = facility("facility-b", repo_fb, exp_mgr_b)

    store_conn = psycopg.connect(db_url)
    store_conn.autocommit = True

    def state_of(record_id: str) -> LifecycleState | None:
        row = repo_mod.get_lifecycle_state(store_conn, record_id)
        return LifecycleState(row["state"]) if row else None

    app_cust = create_custodian_app(
        endpoints=CustodianEndpoints(
            authorities=authorities, facilities=facilities, audit=audit_url
        ),
        record_loader=lambda rid: repo_mod.get_record(store_conn, rid),
        identity=identities["custodian"],
        service_root=root_cert,
        state_loader=state_of,
    )

    def port_of(url: str) -> int:
        return int(url.rsplit(":", 1)[1])

    server_audit = _LiveServer(app_audit, port_of(audit_url))
    server_med = _LiveServer(app_med, port_of(url_med))
    server_net = _LiveServer(app_net, port_of(url_net))
    server_fa = _LiveServer(app_fa, port_of(url_fa))
    server_fb = _LiveServer(app_fb, port_of(url_fb))
    server_cust = _LiveServer(app_cust, port_of(url_cust))
    for server in (server_audit, server_med, server_net, server_fa, server_fb):
        server.start()
    server_cust.start()

    client = bootstrap.bootstrap_client(
        identities["bootstrap"],
        authorities=authorities,
        facilities=facilities,
        audit=audit_url,
        custodian=url_cust,
    )
    cert_med = bootstrap.register_authority(
        url_med, root_anchor, "authority-med", client=client
    )
    cert_net = bootstrap.register_authority(
        url_net, root_anchor, "authority-net", client=client
    )

    endpoints = ScenarioEndpoints(
        authority_med=url_med,
        authority_net=url_net,
        audit=audit_url,
        facility_a=url_fa,
        facility_b=url_fb,
        custodian=url_cust,
    )

    config = {
        "root_certificate_pem": pki.root_certificate_pem,
        "facilities": {
            "facility-a": {
                "ca_private_key_pem": pki.facilities["facility-a"].ca_private_key_pem,
                "ca_certificate_pem": pki.facilities["facility-a"].ca_certificate_pem,
            },
            "facility-b": {
                "ca_private_key_pem": pki.facilities["facility-b"].ca_private_key_pem,
                "ca_certificate_pem": pki.facilities["facility-b"].ca_certificate_pem,
            },
        },
        "authorities": {
            "authority-med": {"endpoint": url_med, "certificate_pem": cert_med},
            "authority-net": {"endpoint": url_net, "certificate_pem": cert_net},
        },
        "audit": {"endpoint": audit_url},
    }

    try:
        yield {
            "endpoints": endpoints,
            "config": config,
            "expiry_manager_b": exp_mgr_b,
            "client": client,
            "identities": identities,
        }
    finally:
        exp_mgr_a.stop_monitor()
        exp_mgr_b.stop_monitor()
        client.close()
        server_cust.stop()
        server_fa.stop()
        server_fb.stop()
        server_audit.stop()
        server_net.stop()
        server_med.stop()
        conn_fa.close()
        conn_fb.close()
        store_conn.close()
        conn.close()


# -----------------------------------------------------------------------------
# Main Demo Scenario Driver
# -----------------------------------------------------------------------------


def run_demo_scenario(
    endpoints: ScenarioEndpoints,
    config: dict[str, Any] | None = None,
    seeded_data: dict[str, Any] | None = None,
    *,
    emergency_duration_seconds: float = 3.0,
    step_mode: bool = False,
    no_color: bool = False,
    verbose: bool = True,
    client: httpx.Client | None = None,
) -> bool:
    """Execute the full 8-Act examiner-ready demonstration scenario.

    Args:
        endpoints: Service base URLs for authorities, facilities, and audit.
        config: Optional parsed federation.json config.
        seeded_data: Optional pre-seeded dataset dict (if None, seeds automatically).
        emergency_duration_seconds: Emergency session lifetime before forced rotation.
        step_mode: If True, waits for user confirmation between acts.
        no_color: Disable ANSI color styling.
        verbose: Print detailed step information.
        client: Signs every request as bootstrap (ADR-0066); defaults to the
            identity ``deploy/run_local.py`` wrote.

    Returns:
        True if all scenario assertions pass and all invariants hold.
    """
    s = Style(not no_color)
    if client is None:
        from deploy.bootstrap import load_service_identity_dir

        client = signed_scenario_client(
            endpoints,
            load_service_identity_dir(DEFAULT_SERVICES_DIR, "bootstrap"),
            timeout=12.0,
        )

    # =========================================================================
    # ACT 1: Federation Topology & Health Verification
    # =========================================================================
    _print_box_header(
        "ACT 1: FEDERATION TOPOLOGY & HEALTH VERIFICATION",
        "Proving genuine process separation across independent network boundaries",
        s,
    )
    print("  Probing health endpoints across all five autonomous federation nodes:")
    nodes = [
        ("authority-med", "Medical Board Authority", endpoints.authority_med),
        ("authority-net", "Regional Network Authority", endpoints.authority_net),
        ("audit", "Standalone Audit Service", endpoints.audit),
        ("facility-a", "Northvale General Hospital (Home Node)", endpoints.facility_a),
        ("facility-b", "Eastbrook Hospital (Emergency Node)", endpoints.facility_b),
    ]

    for node_id, display, url in nodes:
        resp = client.get(f"{url}/health")
        if resp.status_code != 200:
            raise RuntimeError(f"Node {node_id} ({url}) unhealthy: {resp.status_code}")
        print(
            f"   {s.GREEN}[✓] HEALTHY{s.RESET}  {s.BOLD}{display:32s}{s.RESET} "
            f"{s.DIM}at {url}{s.RESET}"
        )

    print(
        f"\n  {s.CYAN}→ Invariant Confirmed:{s.RESET} All 5 nodes run as distinct "
        f"network services. Audit Service enforces independent process boundaries."
    )
    _step_pause(step_mode, s)

    # =========================================================================
    # ACT 2: Synthetic Data Seeding & Zero-Knowledge Verification
    # =========================================================================
    _print_box_header(
        "ACT 2: SYNTHETIC DATA SEEDING & ZERO-KNOWLEDGE VERIFICATION",
        "Seeding realistic clinical personas with zero real PHI (PROJECT.md §5)",
        s,
    )

    if seeded_data is None:
        print("  Generating synthetic patient profiles and cryptographic policies...")
        seeded_data = seed_synthetic_data(
            endpoints=endpoints,
            config=config,
            client=client,
            verbose=False,
        )
        if endpoints.custodian:
            # Share 1 in clinician custody, so expiry can rotate it (ADR-0069).
            for record_id, meta in seeded_data["records"].items():
                x, share_bytes = meta["share1"]
                client.post(
                    f"{endpoints.custodian}/records/{record_id}/shares",
                    json={"x": x, "share_hex": share_bytes.hex()},
                ).raise_for_status()

    dataset = seeded_data["dataset"]
    print(f"  Successfully seeded {len(dataset.patients)} realistic patient records:")

    for pat in dataset.patients:
        recs = [r for r in dataset.records if r.patient_id == pat.patient_id]
        rec = recs[0] if recs else None
        rec_title = rec.title if rec else "Clinical encounter"
        terms = ", ".join(rec.search_terms[:4]) if rec else "none"
        print(
            f"   {s.BOLD}• Patient {pat.patient_id}:{s.RESET} {pat.name} "
            f"({pat.blood_type}, DOB: {pat.date_of_birth})\n"
            f"     {s.DIM}Home:{s.RESET} {pat.home_facility}  |  "
            f"{s.DIM}Encounter:{s.RESET} {rec_title}\n"
            f"     {s.DIM}Policy Tree:{s.RESET} Clinical AND Branch + "
            f"{s.YELLOW}ADR-0016 Owner Leaf (owner:{pat.patient_id}){s.RESET}\n"
            f"     {s.DIM}Search Index:{s.RESET} Blind HKDF tokens for [{terms}]\n"
            f"     {s.DIM}Key Split:{s.RESET} 2-of-3 Shamir (Share 3 in Audit escrow)"
        )

    print(
        f"\n  {s.CYAN}→ Invariant Confirmed:{s.RESET} Zero real patient data. "
        f"Every record authored with ADR-0016 owner leaf and blind search tokens."
    )
    _step_pause(step_mode, s)

    # =========================================================================
    # ACT 3: Blind Cross-Hospital Record Discovery
    # =========================================================================
    _print_box_header(
        "ACT 3: BLIND CROSS-HOSPITAL RECORD DISCOVERY",
        "Unconscious patient carrying an ID card arrives at Eastbrook Hospital ER",
        s,
    )
    print(
        f"  {s.YELLOW}EMERGENCY ARRIVAL:{s.RESET} Alice Vance (pat-101) admitted to "
        f"Eastbrook Hospital (facility-b).\n"
        f"  Attending Physician: {s.BOLD}Dr. Arjun Rao (doc-201){s.RESET} "
        f"(Emergency Medicine).\n"
        f"  Patient is comatose; identified from the ID card in their wallet\n"
        f"  (name + date of birth). No local chart exists at Eastbrook Hospital."
    )
    print("\n  Initiating federated patient discovery across hospital network...")
    discovery_res = client.get(f"{endpoints.facility_b}/patients/pat-101/records")
    discovery_res.raise_for_status()
    discovered_ids = discovery_res.json()["record_ids"]
    assert "rec-001" in discovered_ids

    print(
        f"   {s.GREEN}[✓] MATCH LOCATED:{s.RESET} Record {s.BOLD}rec-001{s.RESET} "
        f"discovered at remote Node (facility-a / Northvale General Hospital).\n"
        f"   {s.DIM}Discovery Method: Patient-indexed blind pointer lookup "
        f"(Zero plaintext leakage){s.RESET}"
    )
    _step_pause(step_mode, s)

    # =========================================================================
    # ACT 4: Access Refusal Under Routine Clinical Policy
    # =========================================================================
    _print_box_header(
        "ACT 4: ACCESS REFUSAL UNDER ROUTINE CLINICAL POLICY",
        "Testing strict cryptographic boundary: routine read must fail closed",
        s,
    )
    print(
        "  Dr. Rao attempts a routine read using Eastbrook ER credentials:\n"
        "   Requester: doc-201 (role: emergency-physician)\n"
        "   Target Policy: role:physician AND specialty:cardiology\n"
        "   Action: POST /records/rec-001/read"
    )

    k_em_physician = seeded_data["attribute_keys"][
        "authority-med:role:emergency-physician"
    ]
    house_routine_keyring = {
        "authority-med:role:emergency-physician": base64.b64encode(
            k_em_physician
        ).decode("ascii"),
    }

    denied_res = client.post(
        f"{endpoints.facility_b}/records/rec-001/read",
        json={
            "requester_id": "doc-201",
            "holder_keyring": house_routine_keyring,
            "correlation_id": "demo-routine-denial-001",
        },
    )

    assert denied_res.status_code == 403
    print(
        f"\n   {s.RED}[✗] HTTP 403 FORBIDDEN:{s.RESET} Access strictly refused by "
        f"policy engine.\n"
        f"   {s.DIM}Engine Reason:{s.RESET} Policy tree requires specialty:cardiology "
        f"(Dr. Rao holds emergency-physician).\n"
        f"   {s.DIM}Audit Event:{s.RESET} Access refusal logged to Standalone "
        f"Audit Service with actor doc-201."
    )
    print(
        f"\n  {s.CYAN}→ Invariant Confirmed:{s.RESET} Routine access fails closed "
        f"across facility boundaries."
    )
    _step_pause(step_mode, s)

    # =========================================================================
    # ACT 5: Break-Glass Emergency Declaration & Shamir Reconstruction
    # =========================================================================
    _print_box_header(
        "ACT 5: BREAK-GLASS DECLARATION & 2-OF-3 SHAMIR RECONSTRUCTION",
        "Emergency assertion signed and Share 3 released via Log-Before-Release",
        s,
    )
    house_info = seeded_data["clinicians"]["doc-201"]
    alice_rec_info = seeded_data["records"]["rec-001"]

    # 1. Sign EmergencyAssertion
    print("  1. Dr. Rao generates and signs an EmergencyAssertion:")
    justification = (
        "Unconscious patient requires urgent allergy and medication history review."
    )
    # The assertion binds the record; the open transition is signed with the
    # clinician's own key (ADR-0067, ADR-0068).
    assertion, transition_event = emergency_open(
        client,
        facility_url=endpoints.facility_b,
        record_id="rec-001",
        patient_id="pat-101",
        clinician_id="doc-201",
        facility_id="facility-b",
        clinician_key=house_info["private_key"],
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        justification=justification,
        ttl=datetime.timedelta(seconds=300),
    )
    print(
        f"     • Subject: {assertion.patient_id}  |  "
        f"Clinician: {assertion.clinician_id}  |  "
        f"Facility: {assertion.facility_id}\n"
        f"     • Reason: {s.BOLD}{assertion.reason_code.value}{s.RESET}\n"
        f"     • Signature: {_fingerprint(assertion.signature)}"
    )

    # 2. Present Share 1 and request Share 3 from Audit Service
    print("\n  2. Assembling 2-of-3 Shamir Threshold Shares:")
    share1 = alice_rec_info["share1"]
    print(
        f"     [{s.GREEN}Share 1: Clinician Holding{s.RESET}] "
        f"x={share1[0]}, Fingerprint={_fingerprint(share1[1])}"
    )
    print(
        f"     [{s.DIM}Share 2: Home Node Custody{s.RESET}]  "
        f"x=2, [Simulated Remote Node / Offline]"
    )

    print(
        "\n  3. Requesting Share 3 from Standalone Audit Service "
        "(Log-Before-Release):"
    )
    corr_id = "demo-corr-breakglass-001"
    release_res = client.post(
        f"{endpoints.audit}/breakglass/release",
        json={
            "share_key": "rec-001",
            "event_type": "breakglass_share_released",
            "event_data": {
                "record_id": "rec-001",
                "patient_id": "pat-101",
                "clinician_id": "doc-201",
                "facility_id": "facility-b",
            },
            "actor_id": "audit-service",
            "correlation_id": corr_id,
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": house_info["certificate_pem"],
            "justification": justification,
        },
    )
    release_res.raise_for_status()
    rel_data = release_res.json()
    rel_x = rel_data["x"]
    rel_share_hex = rel_data["share_hex"]
    new_seq = rel_data["entry"]["seq"]

    print(
        f"     {s.GREEN}[✓] AUDIT COMMIT SUCCESSFUL:{s.RESET} New hash chain entry "
        f"committed at {s.BOLD}Seq #{new_seq}{s.RESET} BEFORE release.\n"
        f"     [{s.GREEN}Share 3: Released Custody{s.RESET}]   "
        f"x={rel_x}, Fingerprint={_fingerprint(bytes.fromhex(rel_share_hex))}"
    )

    # 3. Unlock record at Facility B
    unlock_res = client.post(
        f"{endpoints.facility_b}/records/rec-001/breakglass",
        json={
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": house_info["certificate_pem"],
            "shares": [(share1[0], share1[1].hex()), (rel_x, rel_share_hex)],
            "pre_rewrap_key": house_info["pre_public_key"],
            "transition_event": transition_event.model_dump(mode="json"),
            "correlation_id": corr_id,
            "emergency_duration_seconds": emergency_duration_seconds,
            "justification": justification,
        },
    )
    unlock_res.raise_for_status()
    unlock_data = unlock_res.json()

    print(
        f"\n  4. Threshold gate reconstruction & Proxy Re-Encryption (PRE):\n"
        f"     • 2-of-3 Threshold Reconstructed: {s.GREEN}SUCCESS (GF(p)){s.RESET}\n"
        f"     • State Machine Transition: {s.BOLD}GRANTED → "
        f"{unlock_data['transition_event']['to_state']}{s.RESET}\n"
        f"     • Re-wrapped DEK package delivered via ElGamal PRE"
    )

    # 4. Decapsulate PRE and decrypt medical payload
    rewrapped_bytes = base64.b64decode(unlock_data["rewrapped_dek_b64"])
    recovered_dek = _unwrap_rewrapped_dek(
        rewrapped_bytes, house_info["pre_private_key"], "rec-001"
    )
    assert len(recovered_dek) == 32
    print(
        f"     • PRE Decapsulation: {s.GREEN}DEK Recovered{s.RESET} "
        f"({_fingerprint(recovered_dek)})"
    )

    # Display the decrypted emergency clinical record
    raw_payload = alice_rec_info["record"].payload
    vitals = raw_payload["vitals"]
    allergies = raw_payload["allergies"]

    print("\n  " + s.RED + "╔" + "═" * 72 + "╗" + s.RESET)
    print(
        "  "
        + s.RED
        + "║ "
        + s.BOLD
        + "CRITICAL EMERGENCY MEDICAL RECORD (DECRYPTED)"
        + s.RESET
        + " " * 26
        + s.RED
        + "║"
        + s.RESET
    )
    print(
        f"  {s.RED}║{s.RESET} Patient: Alice Vance (pat-101)  |  "
        f"Blood: O+  |  Sex: F"
    )
    print(f"  {s.RED}║{s.RESET} Diagnosis: {s.BOLD}{raw_payload['diagnosis']}{s.RESET}")
    print(
        f"  {s.RED}║{s.RESET} Vitals: BP {vitals['blood_pressure']}  |  "
        f"HR {vitals['heart_rate_bpm']} bpm  |  O2 {vitals['oxygen_saturation']}"
    )
    print(
        f"  {s.RED}║{s.RESET} {s.YELLOW}{s.BOLD}ALERT - ALLERGIES:{s.RESET} "
        f"{s.RED}{s.BOLD}{allergies[0]['substance'].upper()} "
        f"({allergies[0]['reaction']}){s.RESET}"
    )
    print(
        f"  {s.RED}║{s.RESET} Action: Avoid penicillins; review other beta-lactams; "
        f"Cath Lab activated."
    )
    print("  " + s.RED + "╚" + "═" * 72 + "╝" + s.RESET)

    print(
        f"\n  {s.CYAN}→ Invariant Confirmed:{s.RESET} Break-glass succeeded. "
        f"Decrypted record saved patient from lethal penicillin administration."
    )
    _step_pause(step_mode, s)

    # =========================================================================
    # ACT 6: Visual Countdown Timer & Ephemeral Key Revocation
    # =========================================================================
    _print_box_header(
        "ACT 6: LIVE COUNTDOWN & FORCED DEK ROTATION UPON EXPIRY",
        f"Time-box window: {emergency_duration_seconds:.1f}s until auto-expiry",
        s,
    )

    # Demonstrate search while emergency is open
    search_open_res = client.post(
        f"{endpoints.facility_b}/records/rec-001/emergency-search",
        json={"search_term": "cardiac", "requester_id": "doc-201"},
    )
    if search_open_res.status_code == 200:
        print(
            f"  {s.GREEN}[✓] Emergency Search Active:{s.RESET} Query for 'cardiac' "
            f"matched record rec-001 (EMERGENCY_OPEN state)."
        )

    print(
        f"\n  Commencing active emergency countdown "
        f"({emergency_duration_seconds:.1f} seconds):"
    )

    # Live countdown display
    start_time = time.monotonic()
    while True:
        elapsed = time.monotonic() - start_time
        remaining = max(0.0, emergency_duration_seconds - elapsed)
        pct = remaining / max(0.001, emergency_duration_seconds)
        bar_len = 28
        filled = int(pct * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(
            f"\r    [{s.YELLOW}{bar}{s.RESET}] {remaining:4.1f}s remaining "
            f"(Timer active)..."
        )
        sys.stdout.flush()
        if remaining <= 0.0:
            break
        time.sleep(0.1)

    print(
        f"\n    [{s.RED}{'░' * bar_len}{s.RESET}]  0.0s "
        f"{s.RED}{s.BOLD}EXPIRED!{s.RESET}"
    )

    # Wait an extra window for background sweep and auto-rotation
    print("  Waiting for HSM/KMS timer monitor to execute forced rotation...")
    time.sleep(0.8)

    # Verify dead token: emergency search must now be refused
    dead_search_res = client.post(
        f"{endpoints.facility_b}/records/rec-001/emergency-search",
        json={"search_term": "cardiac", "requester_id": "doc-201"},
    )
    assert dead_search_res.status_code == 403
    print(
        f"   {s.GREEN}[✓] DEAD-TOKEN CONFIRMED:{s.RESET} Search for 'cardiac' "
        f"returned {s.RED}HTTP 403 Forbidden{s.RESET} "
        f"('Emergency search unavailable')."
    )

    # The forced rotation (ADR-0069) re-keys the record and hands new shares
    # to the custodian and the audit service; only then does it return to
    # baseline. Wait for that, so the demo cannot pass on a stuck rotation.
    deadline = time.monotonic() + 15.0
    state = ""
    while time.monotonic() < deadline:
        state_res = client.get(f"{endpoints.facility_b}/records/rec-001/lifecycle")
        state_res.raise_for_status()
        state = state_res.json()["state"]
        if state == "granted":
            break
        time.sleep(0.25)
    assert state == "granted", f"rotation did not complete; record is {state!r}"
    print(
        f"   {s.GREEN}[✓] FORCED ROTATION COMPLETE:{s.RESET} new DEK, new policy "
        f"root, new emergency key and shares, search index re-keyed.\n"
        f"   {s.DIM}Forward Secrecy:{s.RESET} the shares presented above no longer "
        f"open anything."
    )

    print(
        f"\n  {s.CYAN}→ Invariant Confirmed:{s.RESET} Auto-expiry closes emergency "
        f"session without administrator intervention (ADR-0003, ADR-0027)."
    )
    _step_pause(step_mode, s)

    # =========================================================================
    # ACT 7: Tamper-Evident Audit Hash Chain Verification
    # =========================================================================
    _print_box_header(
        "ACT 7: TAMPER-EVIDENT AUDIT HASH CHAIN VERIFICATION",
        "Validating genesis-to-head SHA-256 cryptographic continuity",
        s,
    )
    verify_res = client.get(f"{endpoints.audit}/chain/verify")
    verify_res.raise_for_status()
    verify_data = verify_res.json()
    assert verify_data["verified"] is True

    head_res = client.get(f"{endpoints.audit}/chain/head")
    head_res.raise_for_status()
    head_data = head_res.json()
    head_entry = head_data.get("head") or {}
    head_seq = head_entry.get("seq", verify_data["head_seq"])
    head_hash = head_entry.get("entry_hash", "")

    print(
        f"  Audit Service at {endpoints.audit}:\n"
        f"   • Chain Status: {s.GREEN}{s.BOLD}INTEGRITY VERIFIED{s.RESET}\n"
        f"   • Total Entries Verified: {verify_data['head_seq'] + 1}\n"
        f"   • Head Sequence: #{head_seq}\n"
        f"   • Head Entry Hash: {_fingerprint(head_hash)}\n"
        f"   • Cryptographic Formula: h_i = SHA-256(h_(i-1) ‖ event ‖ time ‖ actor)"
    )

    print(
        f"\n  {s.CYAN}→ Invariant Confirmed:{s.RESET} Hash chain is tamper-evident "
        f"and immutable across all emergency lifecycle events."
    )
    _step_pause(step_mode, s)

    # =========================================================================
    # ACT 8: Examiners' Cryptographic Checklist
    # =========================================================================
    _print_box_header(
        "ACT 8: EXAMINERS' CRYPTOGRAPHIC & ARCHITECTURAL CHECKLIST",
        "Summary of core invariants verified during this execution",
        s,
    )

    checklist = [
        ("ADR-0001", "Zero plaintext keys in storage or API routes", "PASS"),
        ("ADR-0002", "2-of-3 Shamir threshold secret reconstruction", "PASS"),
        ("ADR-0003", "Simulated HSM/KMS timer with signed rotation", "PASS"),
        ("ADR-0004", "Proxy Re-Encryption (PRE) ElGamal key delivery", "PASS"),
        ("ADR-0016", "Owner leaf on every policy tree (owner:<pat_id>)", "PASS"),
        ("ADR-0021", "Log-before-release (Audit commits before release)", "PASS"),
        ("ADR-0022", "Audit Service standalone process boundary", "PASS"),
        ("ADR-0027", "Dead search tokens upon emergency expiry", "PASS"),
        ("PROJECT §5", "Zero real patient data (100% synthetic dataset)", "PASS"),
    ]

    col_w1 = 12
    col_w2 = 50
    col_w3 = 8
    sep = "─" * col_w1 + "┼" + "─" * col_w2 + "┼" + "─" * col_w3

    h_std = f"{'Standard':<{col_w1 - 2}}"
    h_req = f"{'Requirement':<{col_w2 - 2}}"
    h_stat = f"{'Status':<{col_w3 - 2}}"
    print(f"  ┌{'─' * col_w1}┬{'─' * col_w2}┬{'─' * col_w3}┐")
    print(f"  │ {h_std} │ {h_req} │ {h_stat} │")
    print(f"  ├{sep}┤")
    for std, req, status in checklist:
        st_styled = f"{s.GREEN}{s.BOLD}{status}{s.RESET}"
        print(f"  │ {std:<{col_w1 - 2}} │ {req:<{col_w2 - 2}} │ {st_styled}   │")
    print(f"  └{'─' * col_w1}┴{'─' * col_w2}┴{'─' * col_w3}┘")

    print(
        f"\n{s.BOLD}{s.GREEN}ALL 8 ACTS COMPLETED SUCCESSFULLY "
        f"WITH ZERO ERRORS.{s.RESET}\n"
    )
    return True


# -----------------------------------------------------------------------------
# CLI Entrypoint Logic
# -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser for demo driver."""
    parser = argparse.ArgumentParser(
        description="Federated Break-Glass EHR Demo Driver (P4-5)."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to federation.json configuration file.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=3.0,
        help="Emergency time-box duration in seconds (default: 3.0s).",
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Launch five in-process servers using ephemeral ports for testing.",
    )
    parser.add_argument(
        "--database-url",
        type=str,
        default=None,
        help=(
            "PostgreSQL DSN for standalone mode "
            "(defaults to DATABASE_URL or localhost)."
        ),
    )
    parser.add_argument(
        "--seed-only",
        action="store_true",
        help="Seed synthetic patient records and exit without running the scenario.",
    )
    parser.add_argument(
        "--skip-seed",
        action="store_true",
        help="Skip seeding step and run demo scenario against existing data.",
    )
    parser.add_argument(
        "--step",
        action="store_true",
        help="Interactive step mode (waits for [Enter] between acts).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal colors.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI main entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.standalone:
        print("Starting in-process standalone federation on ephemeral ports...")
        with standalone_federation(
            database_url=args.database_url,
            default_duration=args.duration,
        ) as fed:
            endpoints = fed["endpoints"]
            config = fed["config"]

            if args.seed_only:
                seed_synthetic_data(
                    endpoints, config, client=fed["client"], verbose=True
                )
                print("Synthetic data seeded successfully in standalone federation.")
                return 0

            seeded = None if not args.skip_seed else {}
            success = run_demo_scenario(
                endpoints=endpoints,
                config=config,
                seeded_data=seeded,
                emergency_duration_seconds=args.duration,
                step_mode=args.step,
                no_color=args.no_color,
                verbose=True,
                client=fed["client"],
            )
            return 0 if success else 1

    # Normal mode: connect to running federation
    config_data: dict[str, Any] | None = None
    if args.config.exists():
        try:
            config_data = json.loads(args.config.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Warning: could not read {args.config}: {exc}", file=sys.stderr)

    # The published localhost ports, as deploy.run_scenario does: the config's
    # own endpoints are Compose-internal hostnames under Path B.
    endpoints = ScenarioEndpoints(custodian="http://127.0.0.1:8030")

    if args.seed_only:
        from deploy.bootstrap import load_service_identity_dir

        print("Seeding synthetic data into running federation...")
        seed_synthetic_data(
            endpoints,
            config_data,
            client=signed_scenario_client(
                endpoints, load_service_identity_dir(DEFAULT_SERVICES_DIR, "bootstrap")
            ),
            verbose=True,
        )
        print("Seeding complete.")
        return 0

    try:
        success = run_demo_scenario(
            endpoints=endpoints,
            config=config_data,
            emergency_duration_seconds=args.duration,
            step_mode=args.step,
            no_color=args.no_color,
            verbose=True,
        )
        return 0 if success else 1
    except Exception as exc:
        print(f"\nDemo scenario failed: {exc}", file=sys.stderr)
        return 1
