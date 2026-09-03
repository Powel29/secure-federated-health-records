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


# ---------------------------------------------------------------------------
# Time-boxed emergency access (P3-6)
# ---------------------------------------------------------------------------


class EmergencySessionExpiredError(LifecycleError):
    """An emergency session was used at or after its ``expires_at``.

    ``EmergencyExpiryManager.get_active_emergency_key`` raises this instead of
    returning the emergency key once ``now >= expires_at`` -- fail closed, per
    the time-boxing requirement in ARCHITECTURE.md §5 step 7. A session past
    its expiry is not a standing permission, even if it has not yet been swept
    by :meth:`~lifecycle.expiry.EmergencyExpiryManager.expire_session`.
    """


class SessionNotFoundError(LifecycleError):
    """No emergency session is registered for the given ``record_id``.

    Raised by both :meth:`~lifecycle.expiry.EmergencyExpiryManager.expire_session`
    and :meth:`~lifecycle.expiry.EmergencyExpiryManager.get_active_emergency_key`
    when the caller names a record with no active (or ever-registered) session.
    """


class SessionNotExpiredError(LifecycleError):
    """``expire_session`` was called before ``expires_at`` without ``force=True``.

    The timer sweep
    (:meth:`~lifecycle.expiry.EmergencyExpiryManager.check_and_expire_due`)
    never triggers this -- it only expires sessions already past their deadline.
    This guards the manual/administrative path from short-circuiting the
    time-box a clinician was granted.
    """
