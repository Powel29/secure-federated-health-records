"""Negative security tests for the P3-1 key-lifecycle state machine.

Backs the P3-1 exit criteria in WORKFLOW.md ("illegal transitions are rejected,
every transition produces a verifiable signed event") and the CONVENTIONS §5
required negative tests that map to this component:

- "an illegal state transition is rejected"
- "a transition event with an invalid signature is rejected"

Additional adversarial cases proved here:

- state mismatch: a validly-signed event whose from_state disagrees with the
  record's current state is refused (replay-against-stale-state defense);
- consumed-id replay: the same signed event applied twice is rejected the
  second time (the ``TransitionEvent`` contract's declared one-time property);
- emergency without reason: a transition into EMERGENCY_OPEN with no
  reason_code is refused before any signature is produced;
- field tampering: mutating record_id / to_state / actor_id / issued_at on a
  signed event breaks signature verification.

Each test states the paper claim it backs and includes a positive control in
the same fixture so a broken setup cannot masquerade as a passing test.
"""

from __future__ import annotations

import datetime
from uuid import uuid4

import pytest
from contracts import TransitionEvent
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import InvalidSignatureError, generate_ec_keypair
from lifecycle import (
    ConsumedEventIds,
    IllegalTransitionError,
    LifecycleStateMachine,
    MissingReasonCodeError,
    ReplayedEventError,
    StateMismatchError,
    create_transition_event,
    verify_transition_event,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _actor():
    return generate_ec_keypair()


def _granted_to_revoked(signing_key, *, record_id="rec-101", actor_id="dr-alice"):
    return create_transition_event(
        record_id=record_id,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id=actor_id,
        signing_key=signing_key,
    )


# ---------------------------------------------------------------------------
# Illegal transitions
# ---------------------------------------------------------------------------


def test_sec_illegal_state_transition_is_rejected() -> None:
    """Security property: a from/to pair outside the legal set is refused.

    Backs the CONVENTIONS §5 required negative test "an illegal state
    transition is rejected." The specific pair ``GRANTED -> EXPIRED`` bypasses
    the emergency-window flow entirely; if the state machine ever accepted it,
    the ARCHITECTURE §5 promise that expiry only follows a time-boxed
    emergency would be false.
    """
    signing_key, public_key = _actor()

    # Positive control: the legal neighbour ``GRANTED -> REVOKED`` still works
    # under the same signing key, proving the fixture is not itself broken.
    legit = _granted_to_revoked(signing_key)
    verify_transition_event(legit, public_key)

    # Negative: attempt to construct the illegal event.
    with pytest.raises(IllegalTransitionError):
        create_transition_event(
            record_id="rec-101",
            from_state=LifecycleState.GRANTED,
            to_state=LifecycleState.EXPIRED,
            actor_id="dr-alice",
            signing_key=signing_key,
        )


def test_sec_self_transition_is_rejected() -> None:
    """Security property: a state cannot transition to itself.

    A signed self-transition would let a stale event replay as an in-place
    "confirm" of the current state -- meaningless but noisy in the audit
    chain, and, worse, indistinguishable from real progress at a glance.
    """
    signing_key, _ = _actor()

    with pytest.raises(IllegalTransitionError):
        create_transition_event(
            record_id="rec-101",
            from_state=LifecycleState.GRANTED,
            to_state=LifecycleState.GRANTED,
            actor_id="dr-alice",
            signing_key=signing_key,
        )


# ---------------------------------------------------------------------------
# Signature validity
# ---------------------------------------------------------------------------


def test_sec_transition_event_with_invalid_signature_is_rejected() -> None:
    """Security property: an event signed by the wrong key fails verification.

    Backs the CONVENTIONS §5 required negative test "a transition event with
    an invalid signature is rejected." An attacker who can produce plausible
    ``TransitionEvent`` payloads but does not hold the actor's signing key
    cannot pass verification.
    """
    signing_key, public_key = _actor()
    _, wrong_public_key = _actor()

    event = _granted_to_revoked(signing_key)

    # Positive control: the real public key verifies the real signature.
    verify_transition_event(event, public_key)

    # Negative: any other public key does not.
    with pytest.raises(InvalidSignatureError):
        verify_transition_event(event, wrong_public_key)


@pytest.mark.parametrize(
    "mutation",
    [
        {"record_id": "rec-999"},
        {"actor_id": "attacker"},
        {"to_state": LifecycleState.EMERGENCY_OPEN},
    ],
)
def test_sec_field_tampering_breaks_signature(mutation) -> None:
    """Security property: mutating any signed field invalidates the signature.

    Every field in the canonical payload is bound into the signature; changing
    any of them without a matching re-signature is what "forged" means here,
    and is precisely what :func:`verify_transition_event` catches. A regression
    that dropped a field from the canonical payload would let an attacker
    swap that field freely -- this parametrised test guards against it.
    """
    signing_key, public_key = _actor()

    event = _granted_to_revoked(signing_key)
    verify_transition_event(event, public_key)  # positive control

    tampered = event.model_copy(update=mutation)
    with pytest.raises(InvalidSignatureError):
        verify_transition_event(tampered, public_key)


def test_sec_issued_at_tamper_breaks_signature() -> None:
    """Security property: shifting the timestamp on a signed event fails verify.

    Timestamps are bound into the canonical payload so an attacker cannot
    back- or forward-date an old event to fit a new window.
    """
    signing_key, public_key = _actor()

    event = _granted_to_revoked(signing_key)
    tampered = event.model_copy(
        update={"issued_at": event.issued_at + datetime.timedelta(hours=1)}
    )
    with pytest.raises(InvalidSignatureError):
        verify_transition_event(tampered, public_key)


# ---------------------------------------------------------------------------
# Reason-code requirement
# ---------------------------------------------------------------------------


def test_sec_emergency_open_without_reason_code_is_rejected() -> None:
    """Security property: entering EMERGENCY_OPEN requires a reason_code.

    ARCHITECTURE.md §8 requires a closed-enum clinical justification for every
    emergency transition. If this ever regressed, the audit log's "why did
    break-glass fire?" field would silently degrade to None for real emergency
    events -- a viva finding.
    """
    signing_key, _ = _actor()

    # Positive control: with a valid reason_code, the event is produced.
    ok = create_transition_event(
        record_id="rec-101",
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.EMERGENCY_OPEN,
        actor_id="dr-alice",
        signing_key=signing_key,
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
    )
    assert ok.reason_code == ReasonCode.UNCONSCIOUS_PATIENT

    # Negative: same transition with no reason_code is refused before signing.
    with pytest.raises(MissingReasonCodeError):
        create_transition_event(
            record_id="rec-101",
            from_state=LifecycleState.GRANTED,
            to_state=LifecycleState.EMERGENCY_OPEN,
            actor_id="dr-alice",
            signing_key=signing_key,
            reason_code=None,
        )


# ---------------------------------------------------------------------------
# State mismatch
# ---------------------------------------------------------------------------


def test_sec_state_mismatch_transition_is_rejected() -> None:
    """Security property: an event whose from_state disagrees with the record fails.

    A validly-signed ``GRANTED -> REVOKED`` event captured earlier cannot be
    replayed while the record is in a different state (e.g. currently
    ``REVOKED`` or ``EMERGENCY_OPEN``) -- this is the replay-against-stale-
    state defense that makes the state machine an actual state machine and
    not just an event checker.
    """
    signing_key, public_key = _actor()
    machine = LifecycleStateMachine()

    event = _granted_to_revoked(signing_key)

    # Positive control: applying against the matching state works.
    result = machine.apply_transition(LifecycleState.GRANTED, event, public_key)
    assert result == LifecycleState.REVOKED

    # Negative: the same event's from_state (GRANTED) no longer matches now
    # the record is REVOKED, so a second apply against the new state fails.
    with pytest.raises(StateMismatchError):
        machine.apply_transition(LifecycleState.REVOKED, event, public_key)


# ---------------------------------------------------------------------------
# Event-id replay
# ---------------------------------------------------------------------------


def test_sec_replayed_event_id_is_rejected() -> None:
    """Security property: the same signed event applied twice is refused.

    Backs the ``TransitionEvent`` contract's declared property "event_id is
    one-time; consumed-id store rejects reuse." Without this check, a captured
    ``EXPIRED -> GRANTED`` event could be re-fired the next time the record
    reached EXPIRED, silently forcing a rotation nobody asked for.
    """
    signing_key, public_key = _actor()
    machine = LifecycleStateMachine()

    event = _granted_to_revoked(signing_key)

    # Positive control: first application succeeds and marks the id consumed.
    machine.apply_transition(LifecycleState.GRANTED, event, public_key)
    assert machine.consumed_ids.has_seen(event.event_id)

    # Even if the record has legitimately cycled back to GRANTED, replaying
    # the *same* signed event is refused.
    with pytest.raises(ReplayedEventError):
        machine.apply_transition(LifecycleState.GRANTED, event, public_key)


def test_sec_consumed_id_check_runs_after_signature_check() -> None:
    """Security property: a forged event cannot burn a legitimate event_id.

    If the consumed-id check ran *before* signature verification, an attacker
    who observed a real event_id in flight could forge an event carrying that
    id, present it first, and 'consume' the id -- causing the real event to
    later fail as a spurious replay. The ordering in
    :meth:`LifecycleStateMachine.apply_transition` is: verify signature first,
    consume id only after. This test locks that ordering in.
    """
    signing_key, public_key = _actor()
    _, wrong_public_key = _actor()

    machine = LifecycleStateMachine()
    event = _granted_to_revoked(signing_key)

    # Attacker presents the event with a bad public key -- signature check
    # fails before the id can be consumed.
    with pytest.raises(InvalidSignatureError):
        machine.apply_transition(LifecycleState.GRANTED, event, wrong_public_key)
    assert not machine.consumed_ids.has_seen(event.event_id)

    # The legitimate holder can still apply the real event.
    result = machine.apply_transition(LifecycleState.GRANTED, event, public_key)
    assert result == LifecycleState.REVOKED
    assert machine.consumed_ids.has_seen(event.event_id)


# ---------------------------------------------------------------------------
# Contract-level fail-closed on short nonce
# ---------------------------------------------------------------------------


def test_sec_short_nonce_is_rejected_by_contract() -> None:
    """Security property: the contract itself refuses a sub-16-byte nonce.

    Anti-replay nonces below 128 bits are refused at contract construction
    (``contracts/lifecycle.py`` field validator). The state machine relies on
    this so it never has to re-check nonce length itself -- this test proves
    the contract does the check so the module's assumption holds.
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TransitionEvent(
            event_id=uuid4(),
            record_id="rec-1",
            from_state=LifecycleState.GRANTED,
            to_state=LifecycleState.REVOKED,
            actor_id="a",
            issued_at=datetime.datetime.now(datetime.timezone.utc),
            nonce=b"\x00" * 8,  # too short
            signature=b"\x00" * 64,
        )


# ---------------------------------------------------------------------------
# Sanity: the machine's consumed-store is not shared across instances
# ---------------------------------------------------------------------------


def test_two_machines_do_not_share_consumed_ids() -> None:
    """Each ``LifecycleStateMachine`` owns its own store unless one is passed in.

    Prevents a subtle regression: if the default ``ConsumedEventIds()`` were a
    module-level mutable default, two machines would share state and one
    machine's replay would silently poison another's independent flow.
    """
    signing_key, public_key = _actor()
    m1 = LifecycleStateMachine()
    m2 = LifecycleStateMachine()

    event = _granted_to_revoked(signing_key)
    m1.apply_transition(LifecycleState.GRANTED, event, public_key)

    # m2 has never seen this event; a fresh signed event applies cleanly.
    fresh = _granted_to_revoked(signing_key, record_id="rec-102")
    result = m2.apply_transition(LifecycleState.GRANTED, fresh, public_key)
    assert result == LifecycleState.REVOKED
    assert not m2.consumed_ids.has_seen(event.event_id)


def test_shared_consumed_store_is_honored_when_passed_in() -> None:
    """A caller can share one ``ConsumedEventIds`` between machines by choice."""
    signing_key, public_key = _actor()
    shared = ConsumedEventIds()
    m1 = LifecycleStateMachine(shared)
    m2 = LifecycleStateMachine(shared)

    event = _granted_to_revoked(signing_key)
    m1.apply_transition(LifecycleState.GRANTED, event, public_key)

    with pytest.raises(ReplayedEventError):
        m2.apply_transition(LifecycleState.GRANTED, event, public_key)
