"""Key-lifecycle state machine (C9). Public surface for the ``lifecycle`` module."""

from lifecycle.exceptions import (
    IllegalTransitionError,
    LifecycleError,
    MissingReasonCodeError,
    ReplayedEventError,
    StateMismatchError,
)
from lifecycle.state_machine import (
    LEGAL_TRANSITIONS,
    ConsumedEventIds,
    LifecycleStateMachine,
    create_transition_event,
    validate_transition,
    verify_transition_event,
)

__all__ = [
    "ConsumedEventIds",
    "IllegalTransitionError",
    "LEGAL_TRANSITIONS",
    "LifecycleError",
    "LifecycleStateMachine",
    "MissingReasonCodeError",
    "ReplayedEventError",
    "StateMismatchError",
    "create_transition_event",
    "validate_transition",
    "verify_transition_event",
]
