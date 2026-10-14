"""Unit tests for time-boxed emergency access and forced auto-expiry (P3-6).

Covers registration/countdown, timebox durations, the full
``EMERGENCY_OPEN -> EXPIRED -> GRANTED`` rotation cycle with signature
verification, the Phase-4 audit-callback seam, replay protection via the
shared ``LifecycleStateMachine``, and the background monitor thread that lets
expiry happen with no admin action. Negative security tests -- fail-closed
key access, forged events, illegal transitions -- live in
``tests/security/test_phase3_expiry_security.py``.

Five of six tests use an injectable clock for determinism; only the
background-monitor test uses real wall-clock time (with a very short
time-box and poll interval).
"""

from __future__ import annotations

import datetime
import time

import pytest
from contracts.clinical import ClinicalMetadata
from contracts.enums import LifecycleState
from crypto_core import generate_ec_keypair
from crypto_core.symmetric import generate_key
from lifecycle import ReplayedEventError
from lifecycle.exceptions import EmergencySessionExpiredError, SessionNotFoundError
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import verify_transition_event
from records.service import decrypt_record, encrypt_record, unwrap_dek, wrap_dek

FAKE_START = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class _FakeClock:
    """A settable clock so expiry tests are deterministic, not time-flaky."""

    def __init__(self, start: datetime.datetime) -> None:
        self.now = start

    def __call__(self) -> datetime.datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + datetime.timedelta(seconds=seconds)


def _build_scenario(record_id: str = "rec-expiry-001") -> dict:
    """One record's DEK, wrapped both under a policy-root ('baseline') key and
    under a break-glass emergency key -- the two wrappings an already-open
    emergency session carries, per the P3-6 plan's ``EmergencySession`` shape.
    """
    plaintext = b'{"note": "synthetic test record for P3-6"}'
    baseline_key = generate_key(32)
    emergency_key = generate_key(32)

    record, dek = encrypt_record(
        plaintext=plaintext,
        patient_id="pat-001",
        facility_id="fac-001",
        policy_id="policy-001",
        record_id=record_id,
    )
    baseline_wrapping = wrap_dek(
        dek=dek,
        record_id=record_id,
        wrapping_key=baseline_key,
        wrapped_for="policy-001",
    )
    emergency_wrapping = wrap_dek(
        dek=dek,
        record_id=record_id,
        wrapping_key=emergency_key,
        wrapped_for="emergency",
    )
    return {
        "plaintext": plaintext,
        "dek": dek,
        "baseline_key": baseline_key,
        "emergency_key": emergency_key,
        "record": record,
        "baseline_wrapping": baseline_wrapping,
        "emergency_wrapping": emergency_wrapping,
    }


def _register(
    manager,
    scenario,
    *,
    actor_id="dr-alice",
    correlation_id="corr-001",
    duration_seconds=None,
    return_state=LifecycleState.GRANTED,
):
    return manager.register_session(
        record_id=scenario["record"].record_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        emergency_key=scenario["emergency_key"],
        baseline_wrapping_key=scenario["baseline_key"],
        baseline_wrapping=scenario["baseline_wrapping"],
        emergency_wrapping=scenario["emergency_wrapping"],
        current_record=scenario["record"],
        return_state=return_state,
        duration_seconds=duration_seconds,
    )


@pytest.fixture
def clock():
    return _FakeClock(FAKE_START)


@pytest.fixture
def signing_keys():
    return generate_ec_keypair()


@pytest.fixture
def scenario():
    return _build_scenario()


# ---------------------------------------------------------------------------
# Registration and countdown
# ---------------------------------------------------------------------------


def test_session_registration_and_countdown(scenario, signing_keys, clock) -> None:
    """remaining_seconds decreases with the clock; is_expired flips at expires_at."""
    signing_key, _ = signing_keys
    manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)

    session = _register(manager, scenario, duration_seconds=100.0)

    assert session.expires_at == FAKE_START + datetime.timedelta(seconds=100)
    assert session.remaining_seconds(clock.now) == pytest.approx(100.0)
    assert not session.is_expired(clock.now)

    clock.advance(60)
    assert session.remaining_seconds(clock.now) == pytest.approx(40.0)
    assert not session.is_expired(clock.now)

    clock.advance(40)  # now == expires_at exactly
    assert session.is_expired(clock.now)
    assert session.remaining_seconds(clock.now) == 0.0


# ---------------------------------------------------------------------------
# Timebox durations
# ---------------------------------------------------------------------------


def test_custom_and_default_timebox_duration(signing_keys, clock) -> None:
    """60s default; explicit durations (900s, 0.05s) are honoured verbatim."""
    signing_key, _ = signing_keys
    manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)

    default_scenario = _build_scenario("rec-default")
    default_session = _register(manager, default_scenario)
    assert default_session.duration_seconds == 60.0
    assert default_session.expires_at == FAKE_START + datetime.timedelta(seconds=60)

    long_scenario = _build_scenario("rec-custom-long")
    long_session = _register(manager, long_scenario, duration_seconds=900.0)
    assert long_session.duration_seconds == 900.0

    short_scenario = _build_scenario("rec-custom-short")
    short_session = _register(manager, short_scenario, duration_seconds=0.05)
    assert short_session.duration_seconds == 0.05
    assert short_session.expires_at == FAKE_START + datetime.timedelta(seconds=0.05)


# ---------------------------------------------------------------------------
# Full rotation cycle
# ---------------------------------------------------------------------------


def test_auto_expiry_full_rotation_cycle(scenario, signing_keys, clock) -> None:
    """expire_session emits both signed transitions and rotates the DEK."""
    signing_key, public_key = signing_keys
    clinical = ClinicalMetadata(
        title="Synthetic sensitive report",
        source="hospital",
        sensitivity="mental_health",
        care_team_consent=True,
    )
    scenario["record"] = scenario["record"].model_copy(update={"clinical": clinical})
    manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
    _register(manager, scenario, duration_seconds=30.0)
    clock.advance(30)  # now == expires_at

    result = manager.expire_session(scenario["record"].record_id)
    assert result.rotated_record.clinical == clinical

    assert result.expired_event.from_state == LifecycleState.EMERGENCY_OPEN
    assert result.expired_event.to_state == LifecycleState.EXPIRED
    assert result.expired_event.actor_id == "system:hsm-timer"

    assert result.rebaselined_event.from_state == LifecycleState.EXPIRED
    assert result.rebaselined_event.to_state == LifecycleState.GRANTED
    assert result.rebaselined_event.actor_id == "system:hsm-timer"

    assert (
        result.rotated_wrapping.generation
        == scenario["baseline_wrapping"].generation + 1
    )
    assert result.rotated_record.ciphertext != scenario["record"].ciphertext

    # Should not raise.
    verify_transition_event(result.expired_event, public_key)
    verify_transition_event(result.rebaselined_event, public_key)

    new_dek = unwrap_dek(result.rotated_wrapping, scenario["baseline_key"])
    recovered_plaintext = decrypt_record(result.rotated_record, new_dek)
    assert recovered_plaintext == scenario["plaintext"]


# ---------------------------------------------------------------------------
# Audit callback seam
# ---------------------------------------------------------------------------


def test_audit_callback_invoked_on_expiry(scenario, signing_keys, clock) -> None:
    """The Phase-4 audit_logger seam receives metadata for both transitions."""
    signing_key, _ = signing_keys
    captured: list[dict] = []
    manager = EmergencyExpiryManager(
        signing_key=signing_key, clock=clock, audit_logger=captured.append
    )
    _register(manager, scenario, correlation_id="corr-audit-001", duration_seconds=10.0)
    clock.advance(10)

    result = manager.expire_session(scenario["record"].record_id)

    assert len(captured) == 2
    assert captured[0]["to_state"] == "expired"
    assert captured[1]["to_state"] == "granted"
    events = [result.expired_event, result.rebaselined_event]
    for entry, event in zip(captured, events, strict=True):
        assert entry["event_id"] == str(event.event_id)
        assert entry["actor_id"] == "system:hsm-timer"
        assert entry["record_id"] == scenario["record"].record_id
        assert entry["correlation_id"] == "corr-audit-001"
        # No key material ever appears in an audit entry (CONVENTIONS.md §2 rule 3).
        assert "emergency_key" not in entry
        assert "dek" not in entry
    assert result.audit_entries == captured


# ---------------------------------------------------------------------------
# Replay protection via the shared state machine
# ---------------------------------------------------------------------------


def test_state_machine_consumed_ids_rejects_replay(
    scenario, signing_keys, clock
) -> None:
    """Re-applying an already-emitted expiry event is rejected as a replay."""
    signing_key, public_key = signing_keys
    manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
    _register(manager, scenario, duration_seconds=5.0)
    clock.advance(5)

    result = manager.expire_session(scenario["record"].record_id)

    with pytest.raises(ReplayedEventError):
        manager.state_machine.apply_transition(
            LifecycleState.EMERGENCY_OPEN, result.expired_event, public_key
        )


# ---------------------------------------------------------------------------
# Background monitor
# ---------------------------------------------------------------------------


def test_background_monitor_expires_without_admin_action(
    scenario, signing_keys
) -> None:
    """The daemon thread expires a due session with no explicit expire call."""
    signing_key, _ = signing_keys
    manager = EmergencyExpiryManager(
        signing_key=signing_key, default_duration_seconds=0.05
    )
    manager.register_session(
        record_id=scenario["record"].record_id,
        actor_id="dr-alice",
        correlation_id="corr-monitor-001",
        emergency_key=scenario["emergency_key"],
        baseline_wrapping_key=scenario["baseline_key"],
        baseline_wrapping=scenario["baseline_wrapping"],
        emergency_wrapping=scenario["emergency_wrapping"],
        current_record=scenario["record"],
        return_state=LifecycleState.GRANTED,
        duration_seconds=0.05,
    )

    manager.start_monitor(poll_interval=0.05)
    try:
        deadline = time.monotonic() + 3.0
        swept = False
        while time.monotonic() < deadline:
            try:
                manager.get_active_emergency_key(scenario["record"].record_id)
            except SessionNotFoundError:
                swept = True
                break
            except EmergencySessionExpiredError:
                pass  # expired but not yet swept by the monitor -- keep polling
            time.sleep(0.02)
        assert swept, "background monitor did not expire the session in time"
    finally:
        manager.stop_monitor()
