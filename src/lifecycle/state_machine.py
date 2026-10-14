"""Key-lifecycle state machine (C9, ARCHITECTURE.md §2, §5).

The four states -- ``GRANTED``, ``REVOKED``, ``EMERGENCY_OPEN``, ``EXPIRED`` --
and the legal moves between them are the spine of the project. Every legal move
produces a signed ``TransitionEvent`` (contracts/lifecycle.py); every illegal
move -- illegal pair, missing reason code, stale from_state, tampered payload,
replayed event_id -- fails closed with a specific exception (see
``exceptions.py``).

The module is stateless with respect to a record's current state: callers pass
``current_state`` into :meth:`LifecycleStateMachine.apply_transition`. Only
consumed event IDs are tracked internally (in-memory for P3-1; a persisted
store lands with the audit chain in P3-3). See
``docs/adr/0030-lifecycle-state-machine.md`` for the design.
"""

from __future__ import annotations

import datetime
import secrets
import threading
from typing import Protocol
from uuid import UUID, uuid4

from contracts import TransitionEvent
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import sign, verify
from crypto_core.types import ECPrivateKey, ECPublicKey

from lifecycle.exceptions import (
    IllegalTransitionError,
    MissingReasonCodeError,
    ReplayedEventError,
    StateMismatchError,
)

# ASCII unit separator -- keeps fields unambiguous under concatenation.
# Matches the pattern in ``src/authority/issuance.py`` so the two payload
# formats are visibly the same shape.
_FIELD_SEPARATOR = b"\x1f"

# Matches ``contracts.base.MIN_ANTIREPLAY_NONCE_BYTES``. The contract validator
# would reject anything smaller anyway; keeping the constant local means the
# state machine states its own requirement rather than importing it.
_NONCE_BYTES = 16

# The seven legal transitions the ARCHITECTURE §5 flows enumerate (ADR-0030;
# EXPIRED -> REVOKED added by ADR-0058 so expiry restores a revocation). Any pair not
# in this set is refused by :func:`validate_transition`. Extensions (for
# example, ``EMERGENCY_OPEN -> REVOKED`` for premature termination) need an ADR
# per the standing rule in ``CLAUDE.md``; adding one silently here would put
# the spine of the project out of sync with the documented flows.
LEGAL_TRANSITIONS: frozenset[tuple[LifecycleState, LifecycleState]] = frozenset(
    {
        (LifecycleState.GRANTED, LifecycleState.REVOKED),
        (LifecycleState.GRANTED, LifecycleState.EMERGENCY_OPEN),
        (LifecycleState.REVOKED, LifecycleState.GRANTED),
        (LifecycleState.REVOKED, LifecycleState.EMERGENCY_OPEN),
        (LifecycleState.EMERGENCY_OPEN, LifecycleState.EXPIRED),
        (LifecycleState.EXPIRED, LifecycleState.GRANTED),
        (LifecycleState.EXPIRED, LifecycleState.REVOKED),
    }
)

_EMERGENCY_TRANSITIONS: frozenset[tuple[LifecycleState, LifecycleState]] = frozenset(
    {
        (LifecycleState.GRANTED, LifecycleState.EMERGENCY_OPEN),
        (LifecycleState.REVOKED, LifecycleState.EMERGENCY_OPEN),
    }
)


def _canonical_payload(
    *,
    event_id: UUID,
    record_id: str,
    from_state: LifecycleState,
    to_state: LifecycleState,
    actor_id: str,
    reason_code: ReasonCode | None,
    issued_at: datetime.datetime,
    nonce: bytes,
) -> bytes:
    """Build the canonical byte payload the signature covers.

    Every field that participates in the transition's meaning is bound in.
    Changing any one of them (``to_state``, ``record_id``, ``actor_id``,
    ``issued_at``, ...) without a matching re-signature is what "tampered"
    means here and is precisely what :func:`verify_transition_event` catches.
    """
    reason_bytes = reason_code.value.encode("utf-8") if reason_code else b""
    fields = [
        str(event_id).encode("utf-8"),
        record_id.encode("utf-8"),
        from_state.value.encode("utf-8"),
        to_state.value.encode("utf-8"),
        actor_id.encode("utf-8"),
        reason_bytes,
        issued_at.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        nonce,
    ]
    return _FIELD_SEPARATOR.join(fields)


def validate_transition(
    from_state: LifecycleState,
    to_state: LifecycleState,
    reason_code: ReasonCode | None = None,
) -> None:
    """Check the ``(from, to, reason_code)`` triple is legal.

    Raises:
        IllegalTransitionError: ``(from_state, to_state)`` is not in
            :data:`LEGAL_TRANSITIONS`. Self-transitions and undocumented pairs
            both fall out here.
        MissingReasonCodeError: The transition enters ``EMERGENCY_OPEN`` but
            no ``reason_code`` was supplied.

    Security property:
        Pure predicate -- no side effects on failure. The caller can rely on
        "if it did not raise, the transition is well-formed" without further
        checks.
    """
    if (from_state, to_state) not in LEGAL_TRANSITIONS:
        raise IllegalTransitionError(
            f"{from_state.value} -> {to_state.value} is not a legal transition"
        )
    if (from_state, to_state) in _EMERGENCY_TRANSITIONS and reason_code is None:
        raise MissingReasonCodeError(
            f"transition into {to_state.value} requires a reason_code"
        )


def create_transition_event(
    *,
    record_id: str,
    from_state: LifecycleState,
    to_state: LifecycleState,
    actor_id: str,
    signing_key: ECPrivateKey,
    reason_code: ReasonCode | None = None,
    issued_at: datetime.datetime | None = None,
) -> TransitionEvent:
    """Build and sign one ``TransitionEvent`` after validating the transition.

    Args:
        record_id: The record the transition applies to.
        from_state: The state the record is transitioning out of.
        to_state: The state the record is transitioning into.
        actor_id: Identifier for the party causing the transition.
        signing_key: The actor's ECDSA-P256 private key.
        reason_code: Required when ``to_state`` is ``EMERGENCY_OPEN``.
        issued_at: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        A signed :class:`~contracts.TransitionEvent` ready for persistence.

    Raises:
        IllegalTransitionError / MissingReasonCodeError: See
            :func:`validate_transition`. No signature is produced on failure.

    Security property:
        Nonce and event_id come from :mod:`secrets` (via
        :func:`secrets.token_bytes` and :func:`uuid.uuid4`); the signature is
        produced only after :func:`validate_transition` accepts the triple, so
        an illegal transition never emits a signed artifact.
    """
    validate_transition(from_state, to_state, reason_code)
    event_id = uuid4()
    nonce = secrets.token_bytes(_NONCE_BYTES)
    when = issued_at or datetime.datetime.now(datetime.timezone.utc)

    payload = _canonical_payload(
        event_id=event_id,
        record_id=record_id,
        from_state=from_state,
        to_state=to_state,
        actor_id=actor_id,
        reason_code=reason_code,
        issued_at=when,
        nonce=nonce,
    )
    signature = sign(signing_key, payload)

    return TransitionEvent(
        event_id=event_id,
        record_id=record_id,
        from_state=from_state,
        to_state=to_state,
        actor_id=actor_id,
        reason_code=reason_code,
        issued_at=when,
        nonce=nonce,
        signature=signature,
    )


def verify_transition_event(
    event: TransitionEvent,
    actor_public_key: ECPublicKey,
) -> None:
    """Verify the event's signature and re-check that the transition is legal.

    Raises:
        InvalidSignatureError: The recomputed payload does not verify against
            ``actor_public_key`` -- a forged, tampered, or wrong-signer event.
        IllegalTransitionError / MissingReasonCodeError: See
            :func:`validate_transition`. Only reachable when the signer
            themselves put an illegal transition into a validly-signed event.

    Security property:
        The signature check runs first, so a tampered event is reported as
        tampered rather than as "illegal": a mutation of ``to_state`` cannot
        masquerade as a policy error. Signature verification is delegated to
        :func:`crypto_core.verify`, which raises :class:`InvalidSignatureError`
        and never returns silently.
    """
    payload = _canonical_payload(
        event_id=event.event_id,
        record_id=event.record_id,
        from_state=event.from_state,
        to_state=event.to_state,
        actor_id=event.actor_id,
        reason_code=event.reason_code,
        issued_at=event.issued_at,
        nonce=event.nonce,
    )
    verify(actor_public_key, payload, event.signature)

    # Only after the signature is proven authentic do we ask whether the
    # signer actually stated a legal transition -- an authenticated but
    # illegal transition still fails, just for a different reason.
    validate_transition(event.from_state, event.to_state, event.reason_code)


class ConsumedIdBackend(Protocol):
    """Durable one-time-id storage (review F22).

    ``consume_once`` returns ``True`` on first use and ``False`` on a replay.
    The stores below turn ``False`` into their replay error, so the
    fail-closed contract stays in one place.
    """

    def consume_once(self, kind: str, item_id: UUID) -> bool: ...

    def has_consumed(self, kind: str, item_id: UUID) -> bool: ...


class ConsumedEventIds:
    """One-time-id store for ``TransitionEvent.event_id`` values.

    The ``TransitionEvent`` contract declares that ``event_id`` is one-time and
    that a consumed-id store rejects reuse. In memory by default; pass a
    :class:`ConsumedIdBackend` (the facility's storage repository) to make the
    consumed set survive a restart (review F22).

    Security property:
        :meth:`consume` is idempotent-fail-closed: the *first* consume of a
        given id succeeds silently, every subsequent consume raises
        :class:`ReplayedEventError`. Never returns a "was_new" boolean, since
        that would push the fail-open decision onto the caller.
    """

    _KIND = "transition_event"

    def __init__(self, backend: ConsumedIdBackend | None = None) -> None:
        # The lock mirrors breakglass.replay (review F12): two threads must not
        # both pass the membership check for the same id.
        self._lock = threading.Lock()
        self._seen: set[UUID] = set()
        self._backend = backend

    def consume(self, event_id: UUID) -> None:
        """Mark ``event_id`` consumed; raise if it was already consumed."""
        with self._lock:
            if self._backend is not None:
                first_use = self._backend.consume_once(self._KIND, event_id)
            else:
                first_use = event_id not in self._seen
                self._seen.add(event_id)
            if not first_use:
                raise ReplayedEventError(f"event_id {event_id} already consumed")

    def has_seen(self, event_id: UUID) -> bool:
        """Check without consuming -- for tests and diagnostics only."""
        with self._lock:
            if self._backend is not None:
                return self._backend.has_consumed(self._KIND, event_id)
            return event_id in self._seen


class LifecycleStateMachine:
    """Applies verified transitions to a record's current state.

    The machine holds no per-record state itself; the caller passes the
    record's current state on every call. It does hold a
    :class:`ConsumedEventIds` store, because event-id replay defense must live
    somewhere that persists across calls.
    """

    def __init__(self, consumed_ids: ConsumedEventIds | None = None) -> None:
        self._consumed = (
            consumed_ids if consumed_ids is not None else ConsumedEventIds()
        )

    @property
    def consumed_ids(self) -> ConsumedEventIds:
        """Expose the consumed-id store so callers can compose several machines."""
        return self._consumed

    def apply_transition(
        self,
        current_state: LifecycleState,
        event: TransitionEvent,
        actor_public_key: ECPublicKey,
    ) -> LifecycleState:
        """Verify, check state, mark event consumed, and return the new state.

        Order of checks (all fail-closed, no side effects until the last step):
            1. Signature and legality (:func:`verify_transition_event`).
            2. State compatibility (``event.from_state == current_state``).
            3. Event-id novelty (:meth:`ConsumedEventIds.consume`).

        Only when all three pass is the event id marked consumed. This ordering
        matters: consuming the id before signature verification would let a
        forged event burn a legitimate id from a future re-sign.

        Args:
            current_state: The record's authoritative current state.
            event: The signed transition event to apply.
            actor_public_key: The purported signer's public key.

        Returns:
            The new state (``event.to_state``) if every check passes.

        Raises:
            IllegalTransitionError / MissingReasonCodeError: See
                :func:`validate_transition`.
            InvalidSignatureError: The signature does not verify.
            StateMismatchError: ``event.from_state`` disagrees with
                ``current_state``.
            ReplayedEventError: ``event.event_id`` has already been consumed.
        """
        verify_transition_event(event, actor_public_key)
        if event.from_state != current_state:
            raise StateMismatchError(
                f"event's from_state {event.from_state.value!r} does not match "
                f"current state {current_state.value!r}"
            )
        self._consumed.consume(event.event_id)
        return event.to_state
