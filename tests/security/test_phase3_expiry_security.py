"""Negative security tests for P3-6 time-boxed emergency access / auto-expiry.

Backs the P3-6 exit criteria: an emergency session that has run past its
time-box is inert everywhere it matters -- the key it granted, the DEK
wrapping it produced, and the signed events that moved it there -- and the
state machine refuses any shortcut around the two-step expiry sequence.

Each test states the paper claim it backs and includes a positive control in
the same fixture so a broken setup cannot masquerade as a passing test.

Adversarial cases proved here:

- Forward secrecy after forced rotation: the DEK a clinician held during the
  emergency session cannot decrypt the record's post-rotation ciphertext.
  Documented limitation (also called out per-test): this does *not* protect
  data the clinician already decrypted and cached before rotation happened --
  nothing at this layer can claw that back (ADR-0035 "Consequences").
- The retired emergency key cannot unwrap the new (post-rotation) DEK
  wrapping -- rotation is a real key change, not a relabeling.
- ``get_active_emergency_key`` fails closed the moment ``now >= expires_at``,
  even before the background sweep has run.
- A forged (wrong-key) or tampered (mutated-field) expiry ``TransitionEvent``
  fails signature verification.
- ``EMERGENCY_OPEN -> GRANTED`` (skipping ``EXPIRED``) and
  ``GRANTED -> EXPIRED`` (skipping ``EMERGENCY_OPEN``) are both rejected by
  the state machine's legal-transition set.
"""

from __future__ import annotations

import datetime

import pytest
from contracts.enums import LifecycleState
from crypto_core import InvalidSignatureError, generate_ec_keypair
from lifecycle.exceptions import (
    EmergencySessionExpiredError,
    IllegalTransitionError,
    SessionNotFoundError,
)
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import create_transition_event, verify_transition_event
from records.exceptions import DecryptionError, UnwrappingError
from records.service import decrypt_record, unwrap_dek
from search.service import SearchTermsError, open_search_terms
from shamir.split import combine_shares

from tests.rotation_support import (
    SEARCH_TERMS,
    PlanRotator,
    build_rotation_scenario,
    rotated_dek,
)

FAKE_START = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class _FakeClock:
    """A settable clock so expiry tests are deterministic, not time-flaky."""

    def __init__(self, start: datetime.datetime) -> None:
        self.now = start

    def __call__(self) -> datetime.datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + datetime.timedelta(seconds=seconds)


def _build_scenario(record_id: str = "rec-expiry-security-001") -> dict:
    """One ingested record and the material an open emergency session holds."""
    return build_rotation_scenario(
        record_id, patient_id="pat-security-001", facility_id="fac-security-001"
    )


def _register(
    manager,
    scenario,
    *,
    actor_id="dr-alice",
    correlation_id="corr-sec-001",
    duration_seconds=None,
    return_state=LifecycleState.GRANTED,
):
    # Expiry runs the real rotation for this scenario (ADR-0069).
    scenario.setdefault("rotator", PlanRotator(scenario))
    manager.attach_rotator(scenario["rotator"])
    return manager.register_session(
        record_id=scenario["record"].record_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        emergency_key=scenario["emergency_key"],
        emergency_wrapping=scenario["emergency_wrapping"],
        current_record=scenario["record"],
        return_state=return_state,
        duration_seconds=duration_seconds,
    )


def _register_and_expire(manager, scenario, clock, *, duration_seconds=5.0):
    _register(manager, scenario, duration_seconds=duration_seconds)
    clock.advance(duration_seconds)
    return manager.expire_session(scenario["record"].record_id)


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
# Forward secrecy after rotation
# ---------------------------------------------------------------------------


class TestPostExpiryClinicianCannotDecryptRotatedRecord:
    """Paper claim: forced key rotation on expiry gives forward secrecy for
    the record's ciphertext going forward.

    Documented limitation (must not be overclaimed): this does NOT protect
    anything the emergency clinician already decrypted -- or cached the
    pre-rotation DEK for -- *before* expiry fired. A clinician who copied the
    plaintext, or held onto ``old_dek``, still has what they already had;
    nothing at this layer revokes memory the clinician already holds. What
    this test proves is narrower and still load-bearing: that same
    pre-rotation DEK is *useless against the new ciphertext* produced by
    rotation -- it cannot follow the record forward in time.
    """

    def test_positive_control_pre_rotation_dek_decrypts_pre_rotation_ciphertext(
        self, scenario
    ) -> None:
        old_dek = unwrap_dek(scenario["emergency_wrapping"], scenario["emergency_key"])
        plaintext = decrypt_record(scenario["record"], old_dek)
        assert plaintext == scenario["plaintext"]

    def test_pre_rotation_dek_cannot_decrypt_post_rotation_ciphertext(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)

        old_dek = unwrap_dek(scenario["emergency_wrapping"], scenario["emergency_key"])
        with pytest.raises(DecryptionError):
            decrypt_record(result.rotated_record, old_dek)


# ---------------------------------------------------------------------------
# Retired emergency key cannot unwrap the new wrapping
# ---------------------------------------------------------------------------


class TestOldEmergencyKeyCannotUnwrapNewDekWrapping:
    """Paper claim: rotation is a genuine key change -- the retired emergency
    key does not simply keep working against the new wrapping."""

    def test_positive_control_baseline_key_unwraps_rotated_wrapping(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)

        new_dek = rotated_dek(scenario, result)
        assert len(new_dek) == 32

    def test_old_emergency_key_cannot_unwrap_rotated_wrapping(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)

        with pytest.raises(UnwrappingError):
            unwrap_dek(result.rotated_wrapping, scenario["emergency_key"])


# ---------------------------------------------------------------------------
# Emergency key access fails closed after expiry
# ---------------------------------------------------------------------------


class TestEmergencyKeyAccessFailsClosedAfterExpiry:
    """Paper claim: emergency key access is time-boxed -- the manager refuses
    to hand back the key the instant ``now >= expires_at``, even before any
    sweep has processed the session."""

    def test_positive_control_key_accessible_before_expiry(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        _register(manager, scenario, duration_seconds=100.0)

        key = manager.get_active_emergency_key(scenario["record"].record_id)
        assert key == scenario["emergency_key"]

    def test_key_access_fails_closed_after_expiry(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        _register(manager, scenario, duration_seconds=5.0)
        clock.advance(5)  # now == expires_at; no expire_session call yet

        with pytest.raises(EmergencySessionExpiredError):
            manager.get_active_emergency_key(scenario["record"].record_id)


# ---------------------------------------------------------------------------
# Forged or tampered expiry events
# ---------------------------------------------------------------------------


class TestForgedOrTamperedExpiryEventRejected:
    """Paper claim: expiry transitions are non-repudiable, signed artefacts --
    a forged signer or a mutated field is caught, not silently accepted."""

    def test_positive_control_genuine_expiry_event_verifies(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, public_key = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)

        # Should not raise.
        verify_transition_event(result.expired_event, public_key)

    def test_wrong_signing_key_rejected(self, scenario, signing_keys, clock) -> None:
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)

        _, wrong_public_key = generate_ec_keypair()
        with pytest.raises(InvalidSignatureError):
            verify_transition_event(result.expired_event, wrong_public_key)

    def test_tampered_field_rejected(self, scenario, signing_keys, clock) -> None:
        signing_key, public_key = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)

        tampered = result.rebaselined_event.model_copy(update={"actor_id": "dr-evil"})
        with pytest.raises(InvalidSignatureError):
            verify_transition_event(tampered, public_key)


# ---------------------------------------------------------------------------
# Illegal expiry transitions fail closed
# ---------------------------------------------------------------------------


class TestIllegalExpiryTransitionsFailClosed:
    """Paper claim: the two-step expiry sequence
    (``EMERGENCY_OPEN -> EXPIRED -> GRANTED``) is enforced by the shared
    state machine's legal-transition set -- neither step can be skipped."""

    def test_positive_control_legal_expiry_step_accepted(self, signing_keys) -> None:
        signing_key, _ = signing_keys
        event = create_transition_event(
            record_id="rec-illegal-001",
            from_state=LifecycleState.EMERGENCY_OPEN,
            to_state=LifecycleState.EXPIRED,
            actor_id="system:hsm-timer",
            signing_key=signing_key,
        )
        assert event.to_state == LifecycleState.EXPIRED

    def test_emergency_open_to_granted_directly_rejected(self, signing_keys) -> None:
        """Skipping EXPIRED entirely is not a shortcut to re-baselining."""
        signing_key, _ = signing_keys
        with pytest.raises(IllegalTransitionError):
            create_transition_event(
                record_id="rec-illegal-002",
                from_state=LifecycleState.EMERGENCY_OPEN,
                to_state=LifecycleState.GRANTED,
                actor_id="system:hsm-timer",
                signing_key=signing_key,
            )

    def test_granted_to_expired_directly_rejected(self, signing_keys) -> None:
        """A record that was never in EMERGENCY_OPEN cannot be marked EXPIRED."""
        signing_key, _ = signing_keys
        with pytest.raises(IllegalTransitionError):
            create_transition_event(
                record_id="rec-illegal-003",
                from_state=LifecycleState.GRANTED,
                to_state=LifecycleState.EXPIRED,
                actor_id="system:hsm-timer",
                signing_key=signing_key,
            )


# ---------------------------------------------------------------------------
# Expiry restores the pre-emergency state (ADR-0058)
# ---------------------------------------------------------------------------


class TestEmergencyCannotUndoRevocation:
    """Paper claim: an emergency on a revoked record ends REVOKED, never GRANTED
    -- break-glass overrides a revocation for its window only (ADR-0058)."""

    def test_positive_control_granted_record_returns_to_granted(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)
        assert result.rebaselined_event.to_state == LifecycleState.GRANTED

    def test_revoked_record_returns_to_revoked_after_expiry(
        self, scenario, signing_keys, clock
    ) -> None:
        signing_key, public_key = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        _register(
            manager,
            scenario,
            return_state=LifecycleState.REVOKED,
            duration_seconds=5.0,
        )
        clock.advance(5)
        result = manager.expire_session(scenario["record"].record_id)

        assert result.rebaselined_event.from_state == LifecycleState.EXPIRED
        assert result.rebaselined_event.to_state == LifecycleState.REVOKED
        verify_transition_event(result.rebaselined_event, public_key)

    def test_session_cannot_return_to_emergency_or_expired(
        self, scenario, signing_keys, clock
    ) -> None:
        """Only GRANTED or REVOKED are pre-emergency states; anything else fails."""
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        for bad in (LifecycleState.EMERGENCY_OPEN, LifecycleState.EXPIRED):
            with pytest.raises(ValueError, match="only return to granted or revoked"):
                _register(manager, scenario, return_state=bad)
        with pytest.raises(SessionNotFoundError):
            manager.get_active_emergency_key(scenario["record"].record_id)


# ---------------------------------------------------------------------------
# Full rotation (ADR-0069, review D3-a): every old key is dead
# ---------------------------------------------------------------------------


class TestRotationReplacesEveryKey:
    """Paper claim (C4): after expiry nothing from the emergency -- the old
    emergency key, its shares, the old policy root, the old search tokens --
    opens or finds anything. Each negative test has its positive control."""

    def _expire(self, scenario, signing_keys, clock):
        signing_key, _ = signing_keys
        manager = EmergencyExpiryManager(signing_key=signing_key, clock=clock)
        result = _register_and_expire(manager, scenario, clock)
        return result, scenario["rotator"].last

    def test_positive_control_new_shares_open_the_new_emergency_wrapping(
        self, scenario, signing_keys, clock
    ) -> None:
        result, plan = self._expire(scenario, signing_keys, clock)
        new_key = combine_shares([plan.share(1), plan.share(3)], k=2)
        assert unwrap_dek(result.emergency_wrapping, new_key) == rotated_dek(
            scenario, result
        )

    def test_old_shares_do_not_open_the_new_emergency_wrapping(
        self, scenario, signing_keys, clock
    ) -> None:
        result, _ = self._expire(scenario, signing_keys, clock)
        old_shares = scenario["shares"]
        old_key = combine_shares([old_shares[0], old_shares[2]], k=2)
        assert old_key == scenario["emergency_key"]  # they still combine...
        with pytest.raises(UnwrappingError):  # ...to a key that opens nothing
            unwrap_dek(result.emergency_wrapping, old_key)

    def test_emergency_wrapping_moves_up_one_generation(
        self, scenario, signing_keys, clock
    ) -> None:
        result, plan = self._expire(scenario, signing_keys, clock)
        assert result.emergency_wrapping.generation == (
            scenario["emergency_wrapping"].generation + 1
        )
        assert plan.generation == result.emergency_wrapping.generation

    def test_old_policy_root_cannot_unwrap_the_new_policy_wrapping(
        self, scenario, signing_keys, clock
    ) -> None:
        result, _ = self._expire(scenario, signing_keys, clock)
        assert rotated_dek(scenario, result)  # positive: the new root opens it
        with pytest.raises(UnwrappingError):
            unwrap_dek(result.rotated_wrapping, scenario["baseline_key"])

    def test_old_search_tokens_are_gone_from_the_new_index(
        self, scenario, signing_keys, clock
    ) -> None:
        _, plan = self._expire(scenario, signing_keys, clock)
        assert len(plan.search_tokens) == len(SEARCH_TERMS)  # still indexed
        assert not set(plan.search_tokens) & set(scenario["search_tokens"].values())

    def test_search_terms_open_only_under_the_new_dek(
        self, scenario, signing_keys, clock
    ) -> None:
        result, plan = self._expire(scenario, signing_keys, clock)
        record_id = scenario["record"].record_id
        assert plan.sealed_search_terms is not None
        assert open_search_terms(
            plan.sealed_search_terms, rotated_dek(scenario, result), record_id
        ) == list(SEARCH_TERMS)
        with pytest.raises(SearchTermsError):
            open_search_terms(plan.sealed_search_terms, scenario["dek"], record_id)

    def test_a_retried_expiry_finishes_the_same_rotation(
        self, scenario, signing_keys, clock
    ) -> None:
        """A failure after the plan is made must not mint a second key whose
        shares would not match the ones already handed out (ADR-0069)."""
        signing_key, _ = signing_keys
        calls = {"n": 0}
        inner = PlanRotator(scenario)

        def flaky(session):
            outcome = inner(session)
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("share holder unreachable")
            return outcome

        manager = EmergencyExpiryManager(
            signing_key=signing_key, clock=clock, rotator=flaky
        )
        manager.register_session(
            record_id=scenario["record"].record_id,
            actor_id="dr-alice",
            correlation_id="corr-retry",
            emergency_key=scenario["emergency_key"],
            emergency_wrapping=scenario["emergency_wrapping"],
            current_record=scenario["record"],
            return_state=LifecycleState.GRANTED,
            duration_seconds=5.0,
        )
        clock.advance(5)
        with pytest.raises(RuntimeError):
            manager.expire_session(scenario["record"].record_id)
        clock.advance(120)
        manager.expire_session(scenario["record"].record_id)
        assert len(inner.plans) == 2
        assert inner.plans[0] is inner.plans[1]
