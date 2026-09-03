"""Unit tests for the hash-chained audit log (P3-3)."""

from __future__ import annotations

from audit import (
    GENESIS_PREV_HASH,
    append_entry,
    create_genesis_entry,
    verify_chain,
    verify_full_chain,
)
from storage import repositories as repo


def _seed_genesis(conn, signing_key):
    genesis = create_genesis_entry(signing_key=signing_key)
    repo.insert_audit_entry(conn, genesis)
    return genesis


def test_genesis_entry_verifies(conn, audit_keypair):
    priv, pub = audit_keypair
    genesis = _seed_genesis(conn, priv)

    assert genesis.seq == 0
    assert genesis.prev_hash == GENESIS_PREV_HASH
    verify_chain([genesis], pub)


def test_appended_entries_form_a_valid_chain(conn, audit_keypair):
    priv, pub = audit_keypair
    genesis = _seed_genesis(conn, priv)

    e1 = append_entry(
        conn,
        event_type="transition",
        event_data={"record_id": "rec-1", "to_state": "granted"},
        actor_id="clinician-1",
        correlation_id="flow-1",
        signing_key=priv,
    )
    e2 = append_entry(
        conn,
        event_type="breakglass_share_release",
        event_data={"assertion_id": "assn-1"},
        actor_id="audit-service",
        correlation_id="flow-1",
        signing_key=priv,
    )

    assert e1.seq == 1 and e1.prev_hash == genesis.entry_hash
    assert e2.seq == 2 and e2.prev_hash == e1.entry_hash

    # Proves the setup is meaningful: the full chain verifies end to end.
    verify_chain([genesis, e1, e2], pub)


def test_chain_head_reflects_last_appended_entry(conn, audit_keypair):
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)
    e1 = append_entry(
        conn,
        event_type="transition",
        event_data={"record_id": "rec-2"},
        actor_id="clinician-2",
        correlation_id="flow-2",
        signing_key=priv,
    )

    head = repo.get_chain_head(conn)
    assert head == e1


def test_verify_full_chain_returns_head(conn, audit_keypair):
    priv, pub = audit_keypair
    _seed_genesis(conn, priv)
    e1 = append_entry(
        conn,
        event_type="transition",
        event_data={"record_id": "rec-3"},
        actor_id="clinician-3",
        correlation_id="flow-3",
        signing_key=priv,
    )

    head = verify_full_chain(conn, pub)
    assert head == e1
