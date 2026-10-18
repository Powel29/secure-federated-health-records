"""Clinician-signed break-glass transitions for tests (ADR-0068, D8-a).

The custodian signs a record's ``-> EMERGENCY_OPEN`` transition with the
clinician's own key; tests that drive the gate or the facility directly sign
it the same way here.
"""

from __future__ import annotations

from contracts import TransitionEvent
from contracts.enums import LifecycleState, ReasonCode
from crypto_core.types import ECPrivateKey
from lifecycle.state_machine import create_transition_event


def open_event(
    record_id: str,
    from_state: LifecycleState,
    actor_id: str,
    reason_code: ReasonCode,
    signing_key: ECPrivateKey,
) -> TransitionEvent:
    """``from_state -> EMERGENCY_OPEN`` for ``record_id``, signed by the actor."""
    return create_transition_event(
        record_id=record_id,
        from_state=from_state,
        to_state=LifecycleState.EMERGENCY_OPEN,
        actor_id=actor_id,
        signing_key=signing_key,
        reason_code=reason_code,
    )
