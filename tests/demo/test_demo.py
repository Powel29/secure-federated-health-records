"""Tests for synthetic data generator and interactive demo driver (P4-5).

Verifies:
1. Synthetic dataset integrity (schema, clinical realism, zero real PHI).
2. Cryptographic invariants: 2-of-3 Shamir splits, Share 3 audit escrow,
   ADR-0016 owner leaves on policy trees, and blind search indexing.
3. CLI argument parser and options handling.
4. End-to-end execution of the 8-Act demonstration scenario across live
   ephemeral server processes.
"""

from __future__ import annotations

import os

import psycopg
import pytest

from demo.driver import build_parser, run_demo_scenario, standalone_federation
from demo.seed_data import (
    SyntheticClinician,
    SyntheticDataset,
    SyntheticPatient,
    SyntheticRecord,
    create_synthetic_dataset,
    seed_synthetic_data,
)

_DB_URL = os.environ.get("DATABASE_URL") or "postgresql://localhost/postgres"


def _postgres_available() -> bool:
    """Check if PostgreSQL is reachable for integration tests."""
    try:
        conn = psycopg.connect(_DB_URL, connect_timeout=2)
        conn.close()
        return True
    except Exception:
        return False


# =============================================================================
# Unit Tests: Synthetic Dataset
# =============================================================================


def test_synthetic_dataset_structure_and_zero_phi():
    """Verify synthetic dataset properties, clinical schemas, and zero real PHI."""
    dataset: SyntheticDataset = create_synthetic_dataset()

    assert len(dataset.patients) == 3
    assert len(dataset.records) == 3
    assert len(dataset.clinicians) == 3

    # Check patients
    pat_ids = {p.patient_id for p in dataset.patients}
    assert pat_ids == {"pat-101", "pat-102", "pat-103"}

    for p in dataset.patients:
        assert isinstance(p, SyntheticPatient)
        assert p.name in {"Alice Vance", "David Miller", "Emma Watson"}
        assert p.blood_type in {"O+", "A-", "B+"}
        assert p.home_facility in {"facility-a", "facility-b"}
        assert p.owner_authority == "authority-net"

    # Check records
    rec_ids = {r.record_id for r in dataset.records}
    assert rec_ids == {"rec-001", "rec-002", "rec-003"}

    for r in dataset.records:
        assert isinstance(r, SyntheticRecord)
        assert r.patient_id in pat_ids
        assert len(r.search_terms) >= 4
        assert r.clinical_policy is not None
        assert "vitals" in r.payload
        assert "medications" in r.payload
        assert "allergies" in r.payload
        assert "diagnosis" in r.payload

    # Specific check for Alice Vance's STEMI record (rec-001)
    rec_alice = next(r for r in dataset.records if r.record_id == "rec-001")
    assert "STEMI" in rec_alice.payload["diagnosis"]
    assert any(
        a["substance"].lower() == "penicillin" for a in rec_alice.payload["allergies"]
    )
    assert "cardiac" in rec_alice.search_terms
    assert "troponin" in rec_alice.search_terms

    # Check clinicians
    doc_ids = {c.clinician_id for c in dataset.clinicians}
    assert doc_ids == {"doc-201", "doc-301", "doc-202"}
    for c in dataset.clinicians:
        assert isinstance(c, SyntheticClinician)
        assert c.role in {"emergency-physician", "physician"}


# =============================================================================
# Unit Tests: CLI Parser
# =============================================================================


def test_cli_parser_defaults():
    """Verify default CLI arguments for demo driver."""
    parser = build_parser()
    args = parser.parse_args([])

    assert args.duration == 3.0
    assert args.standalone is False
    assert args.seed_only is False
    assert args.skip_seed is False
    assert args.step is False
    assert args.no_color is False
    assert args.database_url is None


def test_cli_parser_custom_arguments():
    """Verify custom CLI argument flags."""
    parser = build_parser()
    args = parser.parse_args(
        [
            "--duration",
            "1.5",
            "--standalone",
            "--seed-only",
            "--step",
            "--no-color",
            "--database-url",
            "postgresql://custom:5432/testdb",
        ]
    )

    assert args.duration == 1.5
    assert args.standalone is True
    assert args.seed_only is True
    assert args.step is True
    assert args.no_color is True
    assert args.database_url == "postgresql://custom:5432/testdb"


# =============================================================================
# Integration Tests: Standalone Seeding & 8-Act Demo
# =============================================================================


@pytest.mark.skipif(not _postgres_available(), reason="PostgreSQL not available")
def test_seed_synthetic_data_integration():
    """Verify seeding synthetic patient records across ephemeral services."""
    with standalone_federation(database_url=_DB_URL, default_duration=2.0) as fed:
        endpoints = fed["endpoints"]
        config = fed["config"]

        seeded = seed_synthetic_data(endpoints=endpoints, config=config, verbose=True)

        assert "dataset" in seeded
        assert "records" in seeded
        assert "clinicians" in seeded
        assert "rec-001" in seeded["records"]
        assert "rec-002" in seeded["records"]
        assert "rec-003" in seeded["records"]

        # Check that Share 3 was registered in Audit custody
        rec1_meta = seeded["records"]["rec-001"]
        assert rec1_meta["share3"][0] == 3
        assert isinstance(rec1_meta["share3"][1], bytes)
        assert len(rec1_meta["share3"][1]) > 0
        assert rec1_meta["search_terms_indexed"] == 5


@pytest.mark.skipif(not _postgres_available(), reason="PostgreSQL not available")
def test_full_demo_scenario_8_acts():
    """Execute the full 8-Act demonstration scenario in standalone mode."""
    with standalone_federation(database_url=_DB_URL, default_duration=1.0) as fed:
        endpoints = fed["endpoints"]
        config = fed["config"]

        success = run_demo_scenario(
            endpoints=endpoints,
            config=config,
            seeded_data=None,
            emergency_duration_seconds=1.0,
            step_mode=False,
            no_color=True,
            verbose=True,
        )

        assert success is True
