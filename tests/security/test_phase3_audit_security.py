"""Negative security tests for the P3-3/P3-4 audit hash chain and share
custody (CONVENTIONS.md §5).

Backs two of the ten named negative tests in CONVENTIONS.md §5:

- "a tampered audit log entry is detected by chain verification" (P3-3)
- "break-glass fails closed when the audit service cannot commit its log
  entry" (P3-4) -- the headline test.

Each test states the paper claim it backs and pairs its negative assertion
with a positive control in the same fixture, so a broken setup cannot
masquerade as a passing test (see the ``negative-security-test`` skill).
"""

from __future__ import annotations

import pytest
from audit import (
    AuditCommitFailedError,
    ChainBreakError,
    append_entry,
    create_genesis_entry,
    release_share_after_commit,
    verify_chain,
)
from crypto_core import InvalidSignatureError
from storage import repositories as repo


def _seed_genesis(conn, signing_key):
    genesis = create_genesis_entry(signing_key=signing_key)
    repo.insert_audit_entry(conn, genesis)
    return genesis


def _chain_of_three(conn, signing_key):
    genesis = _seed_genesis(conn, signing_key)
    e1 = append_entry(
        conn,
        event_type="transition",
        event_data={"record_id": "rec-tamper"},
        actor_id="clinician-x",
        correlation_id="flow-tamper",
        signing_key=signing_key,
    )
    e2 = append_entry(
        conn,
        event_type="transition",
        event_data={"record_id": "rec-tamper", "to_state": "revoked"},
        actor_id="clinician-x",
        correlation_id="flow-tamper",
        signing_key=signing_key,
    )
    return genesis, e1, e2


# ---------------------------------------------------------------------------
# P3-3: tampering is detected
# ---------------------------------------------------------------------------


def test_tampered_event_data_detected_by_chain_verification(conn, audit_keypair):
    """Claim: a tampered audit log entry is detected by chain verification."""
    priv, pub = audit_keypair
    genesis, e1, e2 = _chain_of_three(conn, priv)

    # Positive control: the untampered chain verifies.
    verify_chain([genesis, e1, e2], pub)

    tampered_e1 = e1.model_copy(
        update={"event_data": {"record_id": "rec-tamper", "injected": True}}
    )
    with pytest.raises(InvalidSignatureError):
        verify_chain([genesis, tampered_e1, e2], pub)


def test_broken_prev_hash_link_detected(conn, audit_keypair):
    """Claim: the log is tamper-evident -- a spliced/reordered entry is caught."""
    priv, pub = audit_keypair
    genesis, e1, e2 = _chain_of_three(conn, priv)

    # Positive control.
    verify_chain([genesis, e1, e2], pub)

    # e2 presented directly after genesis: each entry's own signature still
    # verifies (nothing about e2's *content* was touched), but e2.prev_hash
    # does not match genesis.entry_hash -- the link itself is broken, e.g.
    # by an entry having been deleted or the chain having been spliced.
    with pytest.raises(ChainBreakError):
        verify_chain([genesis, e2], pub)


def test_replayed_entry_in_chain_position_detected(conn, audit_keypair):
    """Claim: the log is tamper-evident -- replaying an entry breaks the chain."""
    priv, pub = audit_keypair
    genesis, e1, e2 = _chain_of_three(conn, priv)

    verify_chain([genesis, e1, e2], pub)

    # e1 presented twice (a captured entry replayed into a later position):
    # each entry's own signature still verifies individually, but the
    # second occurrence's seq/prev_hash no longer link to its predecessor.
    with pytest.raises(ChainBreakError):
        verify_chain([genesis, e1, e1, e2], pub)


# ---------------------------------------------------------------------------
# P3-4: log-before-release, the headline test
# ---------------------------------------------------------------------------


def test_breakglass_share_not_released_when_log_commit_fails(
    conn, audit_keypair, monkeypatch
):
    """Claim: break-glass fails closed when the audit service cannot commit
    its log entry -- "no log, no share."
    """
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)
    head_before = repo.get_chain_head(conn)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated log-write failure (disk full / DB down)")

    # Disable the log-commit control at its exact point of use.
    monkeypatch.setattr(repo, "insert_audit_entry", _boom)

    share = (2, b"share-bytes-must-never-escape")
    with pytest.raises(AuditCommitFailedError) as excinfo:
        release_share_after_commit(
            conn,
            share=share,
            event_type="breakglass_share_release",
            event_data={"assertion_id": "assn-fail"},
            actor_id="audit-service",
            correlation_id="flow-fail",
            signing_key=priv,
        )

    # The raised exception is the only thing that came back -- confirm no
    # share value was ever produced by inspecting what actually happened:
    # no return value exists (the call raised, it did not return), and the
    # chain head is exactly what it was before the attempt.
    assert excinfo.value is not None
    assert repo.get_chain_head(conn) == head_before


def test_share_released_only_after_successful_commit(conn, audit_keypair):
    """Positive control for the headline test: a legitimate commit does
    release the share, and the entry is durably present in the chain.
    """
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    share = (2, b"share-bytes")
    released_share, entry = release_share_after_commit(
        conn,
        share=share,
        event_type="breakglass_share_release",
        event_data={"assertion_id": "assn-ok"},
        actor_id="audit-service",
        correlation_id="flow-ok",
        signing_key=priv,
    )

    assert released_share == share
    assert repo.get_chain_head(conn) == entry
    assert repo.get_audit_entry(conn, entry.seq) == entry
