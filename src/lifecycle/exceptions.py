"""Exceptions for the key-lifecycle state machine (C9)."""

from __future__ import annotations

from crypto_core.exceptions import CryptoError


class LifecycleError(CryptoError):
    """Base exception for all lifecycle state-machine failures."""


class IllegalTransitionError(LifecycleError):
    """The ``(from_state, to_state)`` pair is not in the legal transition set."""


class StateMismatchError(LifecycleError):
    """The event's ``from_state`` does not match the record's actual current state.

    Raised by :meth:`LifecycleStateMachine.apply_transition` when a caller tries
    to apply a validly-signed event whose ``from_state`` disagrees with the
    record's current state -- the standard replay-against-stale-state defense.
    """


class MissingReasonCodeError(LifecycleError):
    """A transition into ``EMERGENCY_OPEN`` was attempted without a ``reason_code``.

    ARCHITECTURE.md §8 requires a closed-enum clinical justification whenever
    a record enters emergency access; the state machine refuses to sign or
    accept an event that lacks one.
    """


class ReplayedEventError(LifecycleError):
    """An event with an already-consumed ``event_id`` was re-presented.

    Backs the ``TransitionEvent`` contract's declared property: ``event_id`` is
    one-time and a consumed-id store rejects reuse (contracts/lifecycle.py).
    Without this check a captured signed event could be re-fired the next time
    the record cycles back into the matching ``from_state``.
    """
