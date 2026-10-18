"""Unit tests for the key-lifecycle state machine (P3-1).

Covers legal transitions round-tripping through create/verify/apply, and the
happy paths for each of the six ARCHITECTURE §5 legal transitions. Negative
security tests -- illegal transitions, forged signatures, replay, tampering --
live in ``tests/security/test_phase3_security.py``.
"""

from __future__ import annotations

import datetime
from uuid import uuid4

import pytest
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import generate_ec_keypair
from lifecycle import (
    LEGAL_TRANSITIONS,
    ConsumedEventIds,
    LifecycleStateMachine,
    ReplayedEventError,
    create_transition_event,
    validate_transition,
    verify_transition_event,
)


def _issue_signing_keypair():
    return generate_ec_keypair()


@pytest.fixture
def actor_keys():
    return _issue_signing_keypair()


def _new_event(
    actor_keys,
    *,
    from_state: LifecycleState,
    to_state: LifecycleState,
    reason_code: ReasonCode | None = None,
    record_id: str = "rec-001",
    actor_id: str = "actor-001",
):
    signing_key, _ = actor_keys
    return create_transition_event(
        record_id=record_id,
        from_state=from_state,
        to_state=to_state,
        actor_id=actor_id,
        signing_key=signing_key,
        reason_code=reason_code,
    )


# ---------------------------------------------------------------------------
# Transition-set shape
# ---------------------------------------------------------------------------


def test_legal_transition_set_matches_architecture() -> None:
    """The seven legal transitions are the ARCHITECTURE §5 set, nothing more."""
    expected = {
        (LifecycleState.GRANTED, LifecycleState.REVOKED),
        (LifecycleState.GRANTED, LifecycleState.EMERGENCY_OPEN),
        (LifecycleState.REVOKED, LifecycleState.GRANTED),
        (LifecycleState.REVOKED, LifecycleState.EMERGENCY_OPEN),
        (LifecycleState.EMERGENCY_OPEN, LifecycleState.EXPIRED),
        (LifecycleState.EXPIRED, LifecycleState.GRANTED),
        (LifecycleState.EXPIRED, LifecycleState.REVOKED),
    }
    assert LEGAL_TRANSITIONS == expected


def test_no_self_transitions_are_legal() -> None:
    """A state cannot legally transition to itself."""
    for state in LifecycleState:
        assert (state, state) not in LEGAL_TRANSITIONS


# ---------------------------------------------------------------------------
# validate_transition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("from_state,to_state", sorted(LEGAL_TRANSITIONS))
def test_validate_transition_accepts_every_legal_pair(from_state, to_state) -> None:
    """Each documented legal pair passes when a reason_code is supplied where needed."""
    reason = (
        ReasonCode.CARDIAC_ARREST if to_state == LifecycleState.EMERGENCY_OPEN else None
    )
    validate_transition(from_state, to_state, reason)


# ---------------------------------------------------------------------------
# create / verify round-trip
# ---------------------------------------------------------------------------


def test_create_and_verify_transition_event_round_trips(actor_keys) -> None:
    """A freshly signed event verifies under the same public key."""
    _, public_key = actor_keys
    event = _new_event(
        actor_keys,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
    )

    # No return value on success -- either it verifies or it raises.
    verify_transition_event(event, public_key)

    assert event.from_state == LifecycleState.GRANTED
    assert event.to_state == LifecycleState.REVOKED
    assert event.reason_code is None
    assert len(event.nonce) >= 16
    assert len(event.signature) > 0


def test_create_event_populates_reason_for_emergency(actor_keys) -> None:
    """Emergency transitions carry the reason_code through into the event."""
    _, public_key = actor_keys
    event = _new_event(
        actor_keys,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.EMERGENCY_OPEN,
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
    )
    verify_transition_event(event, public_key)
    assert event.reason_code == ReasonCode.UNCONSCIOUS_PATIENT


# ---------------------------------------------------------------------------
# LifecycleStateMachine.apply_transition
# ---------------------------------------------------------------------------


def test_apply_transition_returns_new_state(actor_keys) -> None:
    """Applying a legal, signed, matching event returns the target state."""
    _, public_key = actor_keys
    machine = LifecycleStateMachine()
    event = _new_event(
        actor_keys,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
    )

    new_state = machine.apply_transition(LifecycleState.GRANTED, event, public_key)

    assert new_state == LifecycleState.REVOKED
    assert machine.consumed_ids.has_seen(event.event_id)


def test_apply_walks_full_lifecycle_loop(actor_keys) -> None:
    """Walk Granted -> Emergency -> Expired -> Granted -> Revoked -> Granted."""
    signing_key, public_key = actor_keys
    machine = LifecycleStateMachine()

    def step(current, target, reason=None):
        event = create_transition_event(
            record_id="rec-loop",
            from_state=current,
            to_state=target,
            actor_id="lifecycle-actor",
            signing_key=signing_key,
            reason_code=reason,
        )
        return machine.apply_transition(current, event, public_key)

    state = LifecycleState.GRANTED
    state = step(state, LifecycleState.EMERGENCY_OPEN, ReasonCode.CARDIAC_ARREST)
    assert state == LifecycleState.EMERGENCY_OPEN

    state = step(state, LifecycleState.EXPIRED)
    assert state == LifecycleState.EXPIRED

    state = step(state, LifecycleState.GRANTED)
    assert state == LifecycleState.GRANTED

    state = step(state, LifecycleState.REVOKED)
    assert state == LifecycleState.REVOKED

    state = step(state, LifecycleState.GRANTED)
    assert state == LifecycleState.GRANTED


# ---------------------------------------------------------------------------
# ConsumedEventIds
# ---------------------------------------------------------------------------


def test_consumed_event_ids_first_consume_succeeds_second_raises() -> None:
    """The store is idempotent-fail-closed: second consume raises."""
    from uuid import uuid4

    from lifecycle import ReplayedEventError

    store = ConsumedEventIds()
    event_id = uuid4()

    store.consume(event_id)  # first time is fine
    assert store.has_seen(event_id)

    with pytest.raises(ReplayedEventError):
        store.consume(event_id)


# ---------------------------------------------------------------------------
# Canonical payload sensitivity
# ---------------------------------------------------------------------------


def test_two_events_for_same_transition_differ_in_event_id_and_nonce(
    actor_keys,
) -> None:
    """Each signed event is unique -- no static payload the store can predict."""
    e1 = _new_event(
        actor_keys,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
    )
    e2 = _new_event(
        actor_keys,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
    )
    assert e1.event_id != e2.event_id
    assert e1.nonce != e2.nonce
    assert e1.signature != e2.signature


def test_timestamps_are_utc_aware(actor_keys) -> None:
    """``issued_at`` on a freshly-created event is timezone-aware UTC."""
    event = _new_event(
        actor_keys,
        from_state=LifecycleState.EMERGENCY_OPEN,
        to_state=LifecycleState.EXPIRED,
    )
    assert event.issued_at.tzinfo is not None
    assert event.issued_at.utcoffset() == datetime.timedelta(0)


class TestConsumedEventIdsConcurrencyAndDurability:
    """F12 lock and F22 backend for transition-event one-time ids."""

    def test_concurrent_consumers_of_one_id_exactly_one_succeeds(self):
        import threading

        store = ConsumedEventIds()
        event_id = uuid4()
        outcomes: list[bool] = []
        barrier = threading.Barrier(16)

        def worker() -> None:
            barrier.wait()
            try:
                store.consume(event_id)
                outcomes.append(True)
            except ReplayedEventError:
                outcomes.append(False)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes.count(True) == 1

    def test_backend_survives_a_new_store(self):
        from api.repository import InMemoryStorageRepository

        backend = InMemoryStorageRepository()
        event_id = uuid4()
        ConsumedEventIds(backend=backend).consume(event_id)
        with pytest.raises(ReplayedEventError):
            ConsumedEventIds(backend=backend).consume(event_id)
