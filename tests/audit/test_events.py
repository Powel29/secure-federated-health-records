"""Unit tests for denial and federation audit events (P3-13)."""

from __future__ import annotations

import json

from audit import (
    DENIED_BY_POLICY,
    EVENT_ACCESS_DENIED,
    EVENT_FEDERATION_DISCOVERY,
    EVENT_FEDERATION_REWRAP,
    create_genesis_entry,
    log_access_denied,
    log_federation_discovery,
    log_federation_rewrap,
)
from crypto_core import sha256_digest
from storage import repositories as repo


def _seed_genesis(conn, signing_key):
    genesis = create_genesis_entry(signing_key=signing_key)
    repo.insert_audit_entry(conn, genesis)
    return genesis


def test_log_access_denied_appends_a_shaped_entry(conn, audit_keypair):
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    entry = log_access_denied(
        conn,
        record_id="rec-1",
        requester_id="dr-mallory",
        denied_by=DENIED_BY_POLICY,
        reason="held attribute keys do not satisfy the policy tree",
        actor_id="facility-a",
        correlation_id="flow-denied-1",
        signing_key=priv,
    )

    assert entry.event_type == EVENT_ACCESS_DENIED
    assert entry.event_data == {
        "record_id": "rec-1",
        "requester_id": "dr-mallory",
        "denied_by": DENIED_BY_POLICY,
        "reason": "held attribute keys do not satisfy the policy tree",
    }
    assert repo.get_chain_head(conn) == entry


def test_log_federation_discovery_hashes_patient_id_not_raw(conn, audit_keypair):
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    entry = log_federation_discovery(
        conn,
        patient_id="patient-secret-101",
        requester_id="facility-b",
        record_ids=["rec-1", "rec-2"],
        actor_id="facility-b",
        correlation_id="flow-discovery-1",
        signing_key=priv,
    )

    assert entry.event_type == EVENT_FEDERATION_DISCOVERY
    assert (
        entry.event_data["patient_id_hash"]
        == sha256_digest(b"patient-secret-101").hex()
    )
    assert entry.event_data["record_count"] == 2
    assert entry.event_data["record_ids"] == ["rec-1", "rec-2"]

    # The raw patient id never appears anywhere in the persisted entry.
    persisted = json.dumps(entry.event_data)
    assert "patient-secret-101" not in persisted


def test_log_federation_discovery_logs_empty_results_too(conn, audit_keypair):
    """ARCHITECTURE §5 step 0: a lookup is logged whether or not it matches."""
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    entry = log_federation_discovery(
        conn,
        patient_id="patient-no-match",
        requester_id="facility-b",
        record_ids=[],
        actor_id="facility-b",
        correlation_id="flow-discovery-2",
        signing_key=priv,
    )

    assert entry.event_data["record_count"] == 0
    assert entry.event_data["record_ids"] == []


def test_log_federation_rewrap_appends_a_shaped_entry(conn, audit_keypair):
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    entry = log_federation_rewrap(
        conn,
        record_id="rec-9",
        source_facility_id="facility-a",
        target_actor_id="dr-out-of-network",
        actor_id="facility-b",
        correlation_id="flow-rewrap-1",
        signing_key=priv,
    )

    assert entry.event_type == EVENT_FEDERATION_REWRAP
    assert entry.event_data == {
        "record_id": "rec-9",
        "source_facility_id": "facility-a",
        "target_actor_id": "dr-out-of-network",
    }
