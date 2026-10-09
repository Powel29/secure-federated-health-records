"""Round-trip write/read for each table, plus a DB-level fail-closed check."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import psycopg
import pytest
from contracts import AuditEntry, DEKWrapping, Facility, Record, TransitionEvent
from contracts.enums import FacilityStatus, LifecycleState, ReasonCode
from federation import find_record_ids_by_patient
from storage import repositories as repo


def _now():
    return datetime.now(timezone.utc)


def _seed_refs(conn):
    """Insert the authority/facility/patient a record depends on (FKs)."""
    repo.insert_authority(conn, "authority-net", "Regional Health Network", b"\x01")
    repo.insert_facility(
        conn,
        Facility(
            facility_id="facility-a",
            display_name="Metropolitan General",
            endpoint="http://facility-a:8001",
            public_key=b"\x02\x03",
            status=FacilityStatus.ACTIVE,
        ),
    )
    repo.insert_patient(conn, "pat-101", "authority-net")


def test_record_and_wrapping_round_trip(conn):
    _seed_refs(conn)
    rec = Record(
        record_id="rec-501",
        patient_id="pat-101",
        facility_id="facility-a",
        policy_id="pol-77",
        content_type="image/png",
        ciphertext=b"\x9f\x3a\xc7",
        nonce=b"n" * 12,
        aad=None,
        created_at=_now(),
    )
    repo.insert_record(conn, rec)
    assert repo.get_record(conn, "rec-501") == rec

    wrap = DEKWrapping(
        wrapping_id="wrap-1",
        record_id="rec-501",
        wrapped_for="pol-77",
        wrapped_dek=b"\xa1\x88",
        nonce=b"w" * 12,
        generation=0,
        created_at=_now(),
    )
    repo.insert_dek_wrapping(conn, wrap)
    assert repo.get_dek_wrapping(conn, "wrap-1") == wrap


def test_facility_round_trip(conn):
    fac = Facility(
        facility_id="facility-b",
        display_name="St. Jude Trauma",
        endpoint="http://facility-b:8002",
        public_key=b"\x04",
        status=FacilityStatus.ACTIVE,
    )
    repo.insert_facility(conn, fac)
    assert repo.get_facility(conn, "facility-b") == fac


def test_transition_event_round_trip(conn):
    _seed_refs(conn)
    repo.insert_record(
        conn,
        Record(
            record_id="rec-9",
            patient_id="pat-101",
            facility_id="facility-a",
            policy_id="pol-1",
            content_type="application/json",
            ciphertext=b"x",
            nonce=b"n" * 12,
            created_at=_now(),
        ),
    )
    ev = TransitionEvent(
        event_id=uuid4(),
        record_id="rec-9",
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.EMERGENCY_OPEN,
        actor_id="doc-301",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        issued_at=_now(),
        nonce=b"z" * 16,
        signature=b"sig",
    )
    repo.insert_transition_event(conn, ev)
    assert repo.get_transition_event(conn, str(ev.event_id)) == ev


def test_audit_entry_round_trip(conn):
    entry = AuditEntry(
        seq=0,
        prev_hash=b"\x00" * 32,
        entry_hash=b"\x11" * 32,
        event_type="breakglass_share_release",
        event_data={"patient_id": "pat-101"},
        actor_id="audit",
        correlation_id="corr-1",
        timestamp=_now(),
        signature=b"sig",
    )
    repo.insert_audit_entry(conn, entry)
    assert repo.get_audit_entry(conn, 0) == entry


def test_registry_tables(conn):
    _seed_refs(conn)
    repo.insert_attribute(conn, "authority-net", "owner", "pat-101")
    repo.upsert_lifecycle_state(conn, _seed_record(conn), LifecycleState.GRANTED)

    assert repo.get_authority(conn, "authority-net")["display_name"] == (
        "Regional Health Network"
    )
    assert repo.get_patient(conn, "pat-101")["home_authority_id"] == "authority-net"


def _seed_record(conn):
    repo.insert_record(
        conn,
        Record(
            record_id="rec-ls",
            patient_id="pat-101",
            facility_id="facility-a",
            policy_id="pol-1",
            content_type="text/plain",
            ciphertext=b"c",
            nonce=b"n" * 12,
            created_at=_now(),
        ),
    )
    return "rec-ls"


def test_lifecycle_upsert_updates_in_place(conn):
    _seed_refs(conn)
    rid = _seed_record(conn)
    repo.upsert_lifecycle_state(conn, rid, LifecycleState.GRANTED)
    repo.upsert_lifecycle_state(conn, rid, LifecycleState.REVOKED)
    assert repo.get_lifecycle_state(conn, rid)["state"] == "revoked"


def test_db_rejects_bad_nonce_fail_closed(conn):
    # Bypass the contract to prove the DB CHECK also fails closed on an 11-byte
    # nonce -- storage does not rely on the contract having validated first.
    _seed_refs(conn)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO records (record_id, patient_id, facility_id,"
                " policy_id, content_type, ciphertext, nonce, created_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    "rec-bad",
                    "pat-101",
                    "facility-a",
                    "pol-1",
                    "text/plain",
                    b"c",
                    b"n" * 11,
                    _now(),
                ),
            )


def _make_record(record_id: str, patient_id: str) -> Record:
    return Record(
        record_id=record_id,
        patient_id=patient_id,
        facility_id="facility-a",
        policy_id="pol-77",
        content_type="text/plain",
        ciphertext=b"\xde\xad",
        nonce=b"n" * 12,
        aad=None,
        created_at=_now(),
    )


def test_find_record_ids_by_patient_returns_only_ids_for_that_patient(conn):
    """P2-4: discovery is a projection over record_id, scoped to one patient."""
    _seed_refs(conn)
    repo.insert_patient(conn, "pat-102", "authority-net")

    repo.insert_record(conn, _make_record("rec-a-1", "pat-101"))
    repo.insert_record(conn, _make_record("rec-a-2", "pat-101"))
    repo.insert_record(conn, _make_record("rec-b-1", "pat-102"))

    ids = find_record_ids_by_patient(conn, "pat-101")

    assert set(ids) == {"rec-a-1", "rec-a-2"}
    # Every element is a bare record-id string; there is no attribute path
    # from the discovery result to ciphertext, nonce, or aad.
    assert all(isinstance(x, str) for x in ids)


def test_lifecycle_compare_and_set_moves_only_from_the_expected_state(conn):
    """F12: a transition succeeds only from the state the caller expected."""
    _seed_refs(conn)
    rid = _seed_record(conn)
    repo.upsert_lifecycle_state(conn, rid, LifecycleState.GRANTED)

    assert repo.transition_lifecycle_state(
        conn, rid, LifecycleState.GRANTED, LifecycleState.EMERGENCY_OPEN
    )
    # A second transition from the now-stale GRANTED loses, and changes nothing.
    assert not repo.transition_lifecycle_state(
        conn, rid, LifecycleState.GRANTED, LifecycleState.REVOKED
    )
    assert repo.get_lifecycle_state(conn, rid)["state"] == "emergency_open"


def test_consumed_id_is_first_use_once_then_replay(conn):
    """F22: the durable one-time-id table reports a replay as such."""
    item = uuid4()
    assert not repo.has_consumed_id(conn, "assertion", item)
    assert repo.consume_id(conn, "assertion", item)
    assert not repo.consume_id(conn, "assertion", item)
    assert repo.has_consumed_id(conn, "assertion", item)
    # Kinds are separate namespaces.
    assert repo.consume_id(conn, "transition_event", item)
