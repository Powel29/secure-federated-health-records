"""In-memory repository: lifecycle compare-and-set (F12) and one-time ids (F22)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from api.repository import InMemoryStorageRepository, StateConflictError
from contracts.enums import LifecycleState


def test_transition_from_the_expected_state_succeeds():
    repo = InMemoryStorageRepository()
    repo.upsert_lifecycle_state("rec-1", LifecycleState.GRANTED)
    repo.transition_lifecycle_state(
        "rec-1", LifecycleState.GRANTED, LifecycleState.EMERGENCY_OPEN
    )
    assert repo.get_lifecycle_state("rec-1") is LifecycleState.EMERGENCY_OPEN


def test_transition_from_a_stale_state_conflicts_and_changes_nothing():
    repo = InMemoryStorageRepository()
    repo.upsert_lifecycle_state("rec-1", LifecycleState.EMERGENCY_OPEN)
    with pytest.raises(StateConflictError):
        repo.transition_lifecycle_state(
            "rec-1", LifecycleState.GRANTED, LifecycleState.REVOKED
        )
    assert repo.get_lifecycle_state("rec-1") is LifecycleState.EMERGENCY_OPEN


def test_consume_once_reports_first_use_then_replay():
    repo = InMemoryStorageRepository()
    item = uuid4()
    assert repo.consume_once("assertion", item) is True
    assert repo.consume_once("assertion", item) is False
    assert repo.has_consumed("assertion", item)
    assert repo.consume_once("request", item) is True
