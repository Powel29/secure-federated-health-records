"""The expiry timer's store mirror and failure handling (review N1, N2, F20).

Claims:
- The store is written only after the transition's audit entry is committed,
  and only as a compare-and-set from the event's ``from_state`` (N1).
- A changed state (e.g. a revocation mid-session) is never overwritten (N1).
- A failed expiry is retried, resumes where it stopped, and never leaves the
  record stuck in EXPIRED; the monitor thread survives every failure (N2, F20).
- Access stays closed while an expiry is being retried.
"""

from __future__ import annotations

import time

import pytest
from api.audit_client import AuditServiceError
from api.repository import InMemoryStorageRepository
from contracts.enums import LifecycleState
from lifecycle.exceptions import EmergencySessionExpiredError, SessionNotFoundError
from lifecycle.expiry import EmergencyExpiryManager

from tests.lifecycle.test_expiry import (
    FAKE_START,
    _build_scenario,
    _FakeClock,
    _register,
)

RECORD = "rec-expiry-001"


class _FlakyAudit:
    """Fails the first ``failures`` appends whose to_state is ``fail_on``."""

    def __init__(self, fail_on: str | None = None, failures: int = 0) -> None:
        self.fail_on = fail_on
        self.failures = failures
        self.entries: list[dict] = []

    def __call__(self, entry: dict) -> None:
        if self.failures and entry["to_state"] == self.fail_on:
            self.failures -= 1
            raise AuditServiceError("audit unavailable")
        self.entries.append(entry)


def _setup(signing_key, *, audit, clock=None):
    repo = InMemoryStorageRepository()
    repo.upsert_lifecycle_state(RECORD, LifecycleState.EMERGENCY_OPEN)
    manager = EmergencyExpiryManager(
        signing_key=signing_key,
        audit_logger=audit,
        state_writer=repo.transition_lifecycle_state,
        clock=clock,
    )
    scenario = _build_scenario(RECORD)
    _register(manager, scenario, duration_seconds=10)
    return repo, manager


@pytest.fixture
def signing_key():
    from crypto_core import generate_ec_keypair

    return generate_ec_keypair()[0]


def test_expiry_state_follows_audit_and_refuses_failed_append(signing_key):
    """Audit first, then store; a failed append writes nothing to the store."""
    operations: list[str] = []
    repo = InMemoryStorageRepository()
    repo.upsert_lifecycle_state(RECORD, LifecycleState.EMERGENCY_OPEN)

    def audit(entry):
        operations.append(f"audit:{entry['to_state']}")

    def writer(record_id, expected, new, last_event_id):
        operations.append(f"store:{new.value}")
        repo.transition_lifecycle_state(record_id, expected, new, last_event_id)

    clock = _FakeClock(FAKE_START)
    manager = EmergencyExpiryManager(
        signing_key=signing_key, audit_logger=audit, state_writer=writer, clock=clock
    )
    _register(manager, _build_scenario(RECORD), duration_seconds=10)
    clock.advance(10)
    manager.check_and_expire_due()

    assert operations == [
        "audit:expired",
        "store:expired",
        "audit:granted",
        "store:granted",
    ]
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED

    # A failed append: nothing reaches the store.
    failing = _FlakyAudit(fail_on="expired", failures=1)
    repo2, manager2 = _setup(signing_key, audit=failing, clock=clock)
    clock.advance(10)
    manager2.check_and_expire_due()
    assert repo2.get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN


def test_expiry_retries_after_second_append_fails(signing_key):
    """N2: the GRANTED append fails once; the retry finishes, not stuck in EXPIRED."""
    clock = _FakeClock(FAKE_START)
    audit = _FlakyAudit(fail_on="granted", failures=1)
    repo, manager = _setup(signing_key, audit=audit, clock=clock)

    clock.advance(10)
    assert manager.check_and_expire_due() == []  # first attempt fails
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.EXPIRED
    # Access stays closed while the expiry is pending.
    with pytest.raises(EmergencySessionExpiredError):
        manager.get_active_emergency_key(RECORD)

    # Not retried before the backoff runs out.
    assert manager.check_and_expire_due() == []
    clock.advance(5)
    results = manager.check_and_expire_due()

    assert len(results) == 1
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    # The EXPIRED transition was emitted once, not again under a new id.
    assert [e["to_state"] for e in audit.entries] == ["expired", "granted"]
    with pytest.raises(SessionNotFoundError):
        manager.get_active_emergency_key(RECORD)


@pytest.mark.parametrize("failing_write", ["expired", "granted"])
def test_store_write_failure_is_retried_not_lost(signing_key, failing_write):
    """A store error after the audit append is retried, never silently dropped,
    and the retry does not append the already-logged transition again."""
    clock = _FakeClock(FAKE_START)
    repo = InMemoryStorageRepository()
    repo.upsert_lifecycle_state(RECORD, LifecycleState.EMERGENCY_OPEN)
    audit = _FlakyAudit()
    failed = {"done": False}

    def flaky_writer(record_id, expected, new, last_event_id):
        if new.value == failing_write and not failed["done"]:
            failed["done"] = True
            raise RuntimeError("store down")
        repo.transition_lifecycle_state(record_id, expected, new, last_event_id)

    manager = EmergencyExpiryManager(
        signing_key=signing_key,
        audit_logger=audit,
        state_writer=flaky_writer,
        clock=clock,
    )
    _register(manager, _build_scenario(RECORD), duration_seconds=10)
    clock.advance(10)
    assert manager.check_and_expire_due() == []  # the store write failed
    assert failed["done"]

    clock.advance(5)
    assert len(manager.check_and_expire_due()) == 1
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    # Each transition is in the chain exactly once, under one event id.
    assert [e["to_state"] for e in audit.entries] == ["expired", "granted"]
    assert len({e["event_id"] for e in audit.entries}) == 2


def test_timer_mirror_does_not_overwrite_a_changed_state(signing_key, caplog):
    """N1: a record revoked mid-session stays REVOKED after the timer expires it."""
    clock = _FakeClock(FAKE_START)
    repo, manager = _setup(signing_key, audit=lambda entry: None, clock=clock)
    repo.upsert_lifecycle_state(RECORD, LifecycleState.REVOKED)

    clock.advance(10)
    with caplog.at_level("ERROR", logger="lifecycle.expiry"):
        results = manager.check_and_expire_due()

    assert len(results) == 1  # the session itself ended
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.REVOKED
    assert "not overwriting" in caplog.text


def test_monitor_survives_audit_outage_and_retries(signing_key):
    """F20: an audit outage no longer kills the monitor thread for good."""
    audit = _FlakyAudit(fail_on="expired", failures=1)
    repo = InMemoryStorageRepository()
    repo.upsert_lifecycle_state(RECORD, LifecycleState.EMERGENCY_OPEN)
    manager = EmergencyExpiryManager(
        signing_key=signing_key,
        audit_logger=audit,
        state_writer=repo.transition_lifecycle_state,
    )
    _register(manager, _build_scenario(RECORD), duration_seconds=0.05)
    manager.start_monitor(poll_interval=0.05)
    try:
        deadline = time.monotonic() + 5.0
        while (
            repo.get_lifecycle_state(RECORD) is not LifecycleState.GRANTED
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
        assert manager._monitor_thread is not None
        assert manager._monitor_thread.is_alive()
    finally:
        manager.stop_monitor()
