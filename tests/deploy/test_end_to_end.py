"""Full End-to-End Cross-Hospital Break-Glass Integration Tests (P4-4).

Exercises the entire federated system across live HTTP processes bound to
ephemeral OS sockets via real HTTP requests (httpx):
- Two facilities: facility-a (home) and facility-b (out-of-network)
- Two independent attribute authorities: authority-med and authority-net
- Dedicated standalone audit service with hash-chain custody (C10/C11)
- Root trust anchor with cross-certified facility CAs (C5)

Verifies:
1. Multi-process bootstrap & health checks across all five live services.
2. Authority credential issuance & authoring attribute key exchange.
3. Record ingest at Facility A with 2-of-3 emergency key split & Share 3 deposit.
4. In-network routine clinical read under attribute policy at Facility A.
5. Out-of-network emergency access refusal (403 Policy Denied) at Facility B.
6. Federated patient record discovery across the shared store.
7. Log-before-release share custody: Audit Service commits log entry before
   releasing Share 3.
8. 2-of-3 threshold break-glass unlock at Facility B: assertion validated,
   state -> EMERGENCY_OPEN.
9. PRE decapsulation by emergency clinician & AES-256-GCM medical record decryption.
10. Active emergency search capability while EMERGENCY_OPEN.
11. Time-box session expiry, forced key rotation, and emergency search shutoff.
12. Full SHA-256 audit hash chain verification from genesis through all scenario events.
"""

from __future__ import annotations

import json
import os
import time

import psycopg
import pytest
from contracts.enums import LifecycleState
from storage import repositories as repo_mod

from demo.driver import standalone_federation
from deploy.run_scenario import _write_canaries, run_scenario
from tests.security.conftest import skip_or_fail_without_postgres

_DATABASE_URL = os.environ.get("DATABASE_URL")


@pytest.fixture()
def postgres_federation():
    """All federation services over live sockets against real Postgres."""
    yield from _postgres_federation(default_duration=5.0)


@pytest.fixture()
def workload_federation():
    """The same federation with a 20 s cap, so the P5-3 workload fits in it."""
    yield from _postgres_federation(default_duration=20.0)


def _postgres_federation(default_duration: float):
    """All federation services over live sockets against real Postgres.

    The same in-process federation the demo runs (``demo.driver``): every
    service signs and checks requests (ADR-0066), and the custodian is part of
    it, so the forced rotation at expiry can hand it the new share 1
    (ADR-0069).
    """
    if not _DATABASE_URL:
        skip_or_fail_without_postgres(
            "DATABASE_URL not set; postgres federation test skipped"
        )
    try:
        psycopg.connect(_DATABASE_URL).close()
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")

    with standalone_federation(_DATABASE_URL, default_duration=default_duration) as fed:
        # The scenario ingests its own record for pat-101.
        with psycopg.connect(_DATABASE_URL) as conn:
            repo_mod.insert_patient(conn, "pat-101", "authority-net")
        yield fed


def test_canary_manifest_round_trips(tmp_path):
    """The P5-5 manifest records every secret as class + hex, nothing else."""
    out = tmp_path / "captures" / "plain.canaries.json"
    _write_canaries(
        out,
        record_id="rec-001",
        run_id="run-1",
        started_at=1234.5,
        secrets={"share1": ("share", b"\x01\x02"), "dek": ("dek", b"\xff" * 32)},
    )
    manifest = json.loads(out.read_text(encoding="utf-8"))
    assert manifest["record_id"] == "rec-001"
    # Review N5: the run stamp ties the manifest to its pcap.
    assert (manifest["run_id"], manifest["started_at"]) == ("run-1", 1234.5)
    assert manifest["canaries"]["share1"] == {"class": "share", "hex": "0102"}
    assert bytes.fromhex(manifest["canaries"]["dek"]["hex"]) == b"\xff" * 32


def test_full_scenario_with_postgres(postgres_federation, tmp_path):
    """Run the full scenario on PostgreSQL; expiry closes search and rotates."""
    endpoints = postgres_federation["endpoints"]
    client = postgres_federation["client"]

    # 1. Run all 9 steps of the scenario with a 1.0-second emergency time-box
    success = run_scenario(
        endpoints=endpoints,
        config=postgres_federation["config"],
        emergency_duration_seconds=1.0,
        verbose=True,
        canaries_out=tmp_path / "canaries.json",
        client=client,
    )
    assert success is True
    manifest = json.loads((tmp_path / "canaries.json").read_text(encoding="utf-8"))
    assert {"share1", "share3", "dek", "emergency_key"} <= set(manifest["canaries"])
    # No private key is sent for the transition any more (ADR-0068).
    assert "lifecycle_signing_key_pem" not in manifest["canaries"]

    # 2. The monitor expires the 1.0s window and runs the forced rotation,
    # which needs the authorities, the custodian and the audit service.
    deadline = time.monotonic() + 15.0
    state = None
    while time.monotonic() < deadline:
        row = client.get(f"{endpoints.facility_b}/records/rec-001/lifecycle")
        state = row.json()["state"]
        if state == LifecycleState.GRANTED.value:
            break
        time.sleep(0.25)
    assert state == LifecycleState.GRANTED.value, f"rotation stuck at {state!r}"

    # 3. Emergency search is refused once the session has expired
    res = client.post(
        f"{endpoints.facility_b}/records/rec-001/emergency-search",
        json={"search_term": "cardiac", "requester_id": "doc-201"},
    )
    assert res.status_code == 403
    assert "Emergency search unavailable" in res.json()["detail"]

    # 4. The record now has a next-generation emergency wrapping (ADR-0069).
    with psycopg.connect(_DATABASE_URL) as conn:
        generations = [
            row[0]
            for row in conn.execute(
                "SELECT generation FROM dek_wrappings"
                " WHERE record_id = %s AND wrapped_for = 'emergency'"
                " ORDER BY generation",
                ("rec-001",),
            ).fetchall()
        ]
    assert generations == [0, 1]


def test_search_workload_with_postgres(workload_federation, monkeypatch):
    """The P5-3 workload runs end to end: searches, expiry, a second session.

    The workload itself fails closed: a search after expiry that is not
    refused, or a second break-glass that does not open, raises.
    """
    import deploy.run_scenario as scenario

    results: dict[str, list[tuple[str, int]]] = {}
    original = scenario.run_search_workload

    def recording(*args, **kwargs):
        results.update(original(*args, **kwargs))
        return results

    monkeypatch.setattr(scenario, "run_search_workload", recording)
    assert run_scenario(
        endpoints=workload_federation["endpoints"],
        config=workload_federation["config"],
        emergency_duration_seconds=15.0,
        verbose=False,
        client=workload_federation["client"],
        search_workload=True,
        search_spacing_seconds=0.05,
    )

    indexed = {"cardiac", "infarction", "aspirin"}
    assert [t for t, _ in results["open"]] == list(scenario.SEARCH_WORKLOAD_OPEN)
    assert [t for t, _ in results["reopened"]] == list(
        scenario.SEARCH_WORKLOAD_REOPENED
    )
    for term, count in results["open"] + results["reopened"]:
        assert count == (1 if term in indexed else 0), term
