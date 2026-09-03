"""Key-lifecycle state machine (C9). Public surface for the ``lifecycle`` module."""

from lifecycle.exceptions import (
    EmergencySessionExpiredError,
    IllegalTransitionError,
    LifecycleError,
    MissingReasonCodeError,
    ReplayedEventError,
    SessionNotExpiredError,
    SessionNotFoundError,
    StateMismatchError,
)
from lifecycle.expiry import (
    EmergencyExpiryManager,
    EmergencySession,
    ExpiryResult,
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
    "EmergencyExpiryManager",
    "EmergencySession",
    "EmergencySessionExpiredError",
    "ExpiryResult",
    "IllegalTransitionError",
    "LEGAL_TRANSITIONS",
    "LifecycleError",
    "LifecycleStateMachine",
    "MissingReasonCodeError",
    "ReplayedEventError",
    "SessionNotExpiredError",
    "SessionNotFoundError",
    "StateMismatchError",
    "create_transition_event",
    "validate_transition",
    "verify_transition_event",
]
