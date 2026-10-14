"""Time-boxed emergency access and forced auto-expiry (P3-6).

ARCHITECTURE.md §5 step 7 requires that break-glass access terminate on its
own -- "no admin action required" -- and that whatever comes after expiry is
forward-secret from what came before. :class:`EmergencyExpiryManager`
implements both: it is a simulated HSM/KMS timer (ADR-0003) that, once a
session's ``expires_at`` passes, emits two *signed* ``TransitionEvent``\\ s
through the shared :class:`~lifecycle.state_machine.LifecycleStateMachine` --
``EMERGENCY_OPEN -> EXPIRED`` and then ``EXPIRED`` back to the state the
record was in before break-glass (``GRANTED`` or ``REVOKED``, ADR-0058) -- and, between
the two, forces a fresh DEK and re-encrypts the record's payload so nothing
wrapped under the (retired) emergency key can decrypt the record's ciphertext
going forward.

The manager owns none of the cryptographic material for the record itself;
callers hand it everything a break-glass unlock (P3-5, ``breakglass.gate``)
already produced -- the reconstructed emergency key, the DEK wrapped under it,
and the DEK wrapped under the policy root secret the record rotates *back*
to. This module does not import ``breakglass`` at all: it consumes plain
``bytes``/``DEKWrapping``/``Record`` values so it has no opinion on how the
emergency session was opened, only on how it ends.

Signing identity: every emitted event's ``actor_id`` is ``timer_actor_id``
("system:hsm-timer" by default), a dedicated timer-service identity per
ADR-0003 -- never the clinician's key and never the audit service's key. The
timer is a trusted process standing in for hardware; ADR-0003 already accepts
that a compromised timer process could decline to expire a session, and
relies on the signed, logged rotation to make that tamper-evident rather than
silent.

Audit chain wiring (P3-3/P3-4) is a Phase 4 seam. End-to-end wiring to
``audit.share_custody.release_share_after_commit`` and
``audit.chain.append_entry`` happens at Phase 4 API integration (P4-2).
Passing ``audit_logger=None`` here means expiry events do not enter the hash
chain; a Phase 4 caller supplies the real callback.

Failure handling (review F20, N2): a session is *claimed* (marked
``expiring``) rather than deleted while it is being expired. If any step
fails -- an audit outage, a store error -- the session is put back with a
retry count and a backoff, and the next sweep resumes where the last attempt
stopped: a transition that was already emitted is not emitted again under a
new id. The monitor thread survives every failure. Access stays closed
throughout, because ``get_active_emergency_key`` refuses any session past
``expires_at`` or being expired.

Store mirror (review N1): an optional ``state_writer`` persists each emitted
transition into the facility's store *after* the audit append, as a
compare-and-set from the event's ``from_state``. A conflict means someone else
changed the record's state; the timer logs it and never overwrites it.
"""

from __future__ import annotations

import datetime
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from contracts import TransitionEvent
from contracts.enums import LifecycleState
from contracts.records import DEKWrapping, Record
from crypto_core.types import ECPrivateKey
from records.service import decrypt_record, encrypt_record, unwrap_dek, wrap_dek

from lifecycle.exceptions import (
    EmergencySessionExpiredError,
    SessionNotExpiredError,
    SessionNotFoundError,
    StateConflictError,
)
from lifecycle.state_machine import LifecycleStateMachine, create_transition_event

# Best-effort "zeroize" sentinel for a retired emergency key. Python offers no
# guaranteed in-memory zeroization (immutable `bytes`, GC-managed, possibly
# copied by the interpreter) -- overwriting the session's reference is the
# most this layer can do. A real HSM/KMS would zeroize the key material
# itself; this is the documented limitation ADR-0035 accepts.
EMERGENCY_KEY_ZERO_BYTES = b"\x00" * 32

_DEFAULT_DURATION_SECONDS = 60.0

# Retry backoff after a failed expiry attempt: 1s, 2s, 4s ... capped at 60s.
_RETRY_BASE_SECONDS = 1.0
_RETRY_MAX_SECONDS = 60.0

_logger = logging.getLogger(__name__)

# ``state_writer(record_id, expected, new, last_event_id)`` -- the facility
# repository's compare-and-set. Raises StateConflictError if the state moved.
StateWriter = Callable[[str, LifecycleState, LifecycleState, str], None]


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@dataclass
class EmergencySession:
    """One record's active break-glass window, tracked until it expires.

    Carries *two* DEK wrappings so expiry can rotate cleanly: the DEK wrapped
    under the emergency key (what the clinician currently holds) and the DEK
    wrapped under the pre-break-glass policy root secret (what the record
    rotates back *to*, and under which key it was wrapped before this session
    ever opened). ``baseline_wrapping_key`` is carried alongside so
    :meth:`EmergencyExpiryManager.expire_session` can produce the *new*
    baseline wrapping directly, without re-entering the policy engine.
    """

    record_id: str
    opened_at: datetime.datetime
    duration_seconds: float
    expires_at: datetime.datetime
    actor_id: str
    correlation_id: str
    emergency_key: bytes = field(repr=False)
    baseline_wrapping_key: bytes = field(repr=False)
    baseline_wrapping: DEKWrapping
    emergency_wrapping: DEKWrapping
    current_record: Record
    # The state the record was in before break-glass; expiry returns it there
    # so an emergency never undoes a patient's revocation (ADR-0058).
    return_state: LifecycleState = LifecycleState.GRANTED
    # The opener's home facility; only its clinicians may join (ADR-0063).
    # Empty means nobody can join.
    opener_facility_id: str = ""
    # Expiry progress, so a failed attempt can be retried without repeating
    # what already happened (review F20, N2).
    expiring: bool = False
    attempts: int = 0
    retry_at: datetime.datetime | None = None
    expired_event: TransitionEvent | None = None
    expired_emitted: bool = False
    rebaselined_event: TransitionEvent | None = None
    # Events already in the audit chain: a retry after a store failure only
    # repeats the store write, never the append.
    audited_event_ids: set[str] = field(default_factory=set)

    def is_expired(self, now: datetime.datetime) -> bool:
        """Whether ``now`` is at or past ``expires_at`` -- inclusive, fail closed."""
        return now >= self.expires_at

    def remaining_seconds(self, now: datetime.datetime) -> float:
        """Seconds left before expiry; never negative."""
        return max(0.0, (self.expires_at - now).total_seconds())


@dataclass(frozen=True)
class ExpiryResult:
    """Everything one :meth:`EmergencyExpiryManager.expire_session` call produced.

    Attributes:
        record_id: The record whose session just expired.
        expired_event: Signed ``EMERGENCY_OPEN -> EXPIRED`` transition.
        rebaselined_event: Signed ``EXPIRED -> return_state`` transition
            (``GRANTED`` or ``REVOKED``), emitted after the forced key rotation.
        rotated_record: Fresh ciphertext under a freshly generated DEK.
        rotated_wrapping: The new DEK wrapped under the session's
            ``baseline_wrapping_key``, ``generation = old_generation + 1``.
        audit_entries: One metadata dict per emitted transition, in emission
            order. Always populated regardless of whether ``audit_logger``
            was configured -- see the module docstring on the Phase 4 seam.
    """

    record_id: str
    expired_event: TransitionEvent
    rebaselined_event: TransitionEvent
    rotated_record: Record
    rotated_wrapping: DEKWrapping
    audit_entries: list[dict[str, Any]]


class EmergencyExpiryManager:
    """Simulated HSM timer (ADR-0003) enforcing emergency time-boxing.

    Uses a ``timer_actor_id``-owned signing key to emit two signed
    ``TransitionEvent``\\ s at expiry: ``EMERGENCY_OPEN -> EXPIRED``, then
    ``EXPIRED -> GRANTED|REVOKED`` (the pre-emergency state, ADR-0058) after a
    forced key rotation. No admin action is
    required -- expiry fires either from an explicit :meth:`expire_session`
    call, a :meth:`check_and_expire_due` sweep, or the background thread
    started by :meth:`start_monitor`.

    Audit chain wiring (P3-3/P3-4) is deferred to Phase 4 API integration
    (P4-2); pass an ``audit_logger`` callback then. With
    ``audit_logger=None``, expiry events do NOT enter the hash chain --
    documented limitation (ADR-0035).
    """

    def __init__(
        self,
        *,
        signing_key: ECPrivateKey,
        state_machine: LifecycleStateMachine | None = None,
        timer_actor_id: str = "system:hsm-timer",
        default_duration_seconds: float = _DEFAULT_DURATION_SECONDS,
        audit_logger: Callable[[dict[str, Any]], None] | None = None,
        state_writer: StateWriter | None = None,
        clock: Callable[[], datetime.datetime] | None = None,
    ) -> None:
        """Configure the timer.

        Args:
            signing_key: The ECDSA-P256 private key belonging to the
                dedicated timer-service identity (ADR-0003) -- not the
                clinician's key, not the audit service's key. Every emitted
                ``TransitionEvent.actor_id`` is ``timer_actor_id`` and is
                signed with this key.
            state_machine: Shared :class:`LifecycleStateMachine` to apply
                transitions through (and whose ``ConsumedEventIds`` store
                thereby also guards these events). A fresh one is created if
                omitted.
            timer_actor_id: Identity recorded as ``actor_id`` on every
                emitted event. Defaults to ``"system:hsm-timer"``.
            default_duration_seconds: Time-box length used by
                :meth:`register_session` when no ``duration_seconds`` is
                given for that session.
            audit_logger: Optional callback invoked once per emitted
                transition with a metadata dict. End-to-end wiring to
                ``audit.share_custody.release_share_after_commit`` and
                ``audit.chain.append_entry`` happens at Phase 4 API
                integration (P4-2). Passing ``None`` here means expiry
                events do not enter the hash chain; a Phase 4 caller
                supplies the real callback.
            state_writer: Optional compare-and-set into the facility's store,
                called after ``audit_logger`` for each transition (review N1).
                ``create_hospital_app`` attaches its repository's writer.
            clock: Optional zero-arg callable returning the current UTC
                time, for deterministic tests. Defaults to
                ``datetime.datetime.now(timezone.utc)``.
        """
        self._signing_key = signing_key
        self._public_key = signing_key.public_key()
        self._state_machine = (
            state_machine if state_machine is not None else LifecycleStateMachine()
        )
        self._timer_actor_id = timer_actor_id
        self._default_duration_seconds = default_duration_seconds
        self._audit_logger = audit_logger
        self._state_writer = state_writer
        self._clock = clock if clock is not None else _utcnow

        self._sessions: dict[str, EmergencySession] = {}
        self._lock = threading.Lock()
        self._monitor_thread: threading.Thread | None = None
        self._monitor_stop = threading.Event()

    @property
    def state_machine(self) -> LifecycleStateMachine:
        """The shared state machine transitions are applied through."""
        return self._state_machine

    @property
    def timer_actor_id(self) -> str:
        """The identity recorded as ``actor_id`` on every emitted event."""
        return self._timer_actor_id

    @property
    def default_duration_seconds(self) -> float:
        """The configured time-box; a caller may only shorten it (review F6)."""
        return self._default_duration_seconds

    def attach_state_writer(self, state_writer: StateWriter) -> None:
        """Persist every emitted transition into a facility store (review N1)."""
        self._state_writer = state_writer

    def unregister_session(self, record_id: str) -> None:
        """Drop a session whose break-glass open failed after it was registered.

        Used only to roll back a failed unlock (review F7). A session that is
        already being expired is left to the timer.
        """
        with self._lock:
            session = self._sessions.get(record_id)
            if session is None or session.expiring:
                return
            del self._sessions[record_id]
        session.emergency_key = EMERGENCY_KEY_ZERO_BYTES

    def register_session(
        self,
        *,
        record_id: str,
        actor_id: str,
        correlation_id: str,
        emergency_key: bytes,
        baseline_wrapping_key: bytes,
        baseline_wrapping: DEKWrapping,
        emergency_wrapping: DEKWrapping,
        current_record: Record,
        return_state: LifecycleState,
        duration_seconds: float | None = None,
        opener_facility_id: str = "",
    ) -> EmergencySession:
        """Register a session on break-glass unlock, starting its time-box now.

        Args:
            record_id: The record the emergency session covers.
            actor_id: The clinician (or service) that opened the session --
                carried for reference, distinct from ``timer_actor_id``,
                which is what signs the eventual expiry transitions.
            correlation_id: Caller's audit-correlation identifier, threaded
                into the per-transition metadata this manager later emits.
            emergency_key: The reconstructed 256-bit emergency key (P3-5
                ``open_emergency_access`` output).
            baseline_wrapping_key: The policy root secret to re-wrap under at
                expiry -- kept so rotation needs no further trip through the
                policy engine.
            baseline_wrapping: The record's DEK wrapping from *before*
                break-glass opened -- what the record returns to.
            emergency_wrapping: The record's DEK wrapped under
                ``emergency_key`` -- what the clinician currently holds.
            current_record: The record as it stands during the emergency
                session (its ciphertext decrypts under the DEK
                ``emergency_wrapping`` unwraps to).
            return_state: The record's state before break-glass --
                ``GRANTED`` or ``REVOKED`` -- which expiry restores
                (ADR-0058).
            duration_seconds: Time-box length; defaults to
                ``default_duration_seconds``.
            opener_facility_id: The opening clinician's home facility, taken
                from the CA that issued their certificate. Only clinicians of
                this facility may join the session (ADR-0063); empty means
                nobody can.

        Returns:
            The registered :class:`EmergencySession`.

        Raises:
            ValueError: ``return_state`` is not GRANTED or REVOKED.
            ValueError: A session is already registered for ``record_id`` --
                one active emergency session per record at a time.
        """
        if return_state not in (LifecycleState.GRANTED, LifecycleState.REVOKED):
            raise ValueError(
                f"an emergency session can only return to granted or revoked, "
                f"not {return_state.value!r}"
            )
        duration = (
            duration_seconds
            if duration_seconds is not None
            else self._default_duration_seconds
        )
        now = self._clock()
        session = EmergencySession(
            record_id=record_id,
            opened_at=now,
            duration_seconds=duration,
            expires_at=now + datetime.timedelta(seconds=duration),
            actor_id=actor_id,
            correlation_id=correlation_id,
            emergency_key=emergency_key,
            baseline_wrapping_key=baseline_wrapping_key,
            baseline_wrapping=baseline_wrapping,
            emergency_wrapping=emergency_wrapping,
            current_record=current_record,
            return_state=return_state,
            opener_facility_id=opener_facility_id,
        )
        with self._lock:
            if record_id in self._sessions:
                raise ValueError(
                    f"an emergency session is already registered for record "
                    f"{record_id!r}"
                )
            self._sessions[record_id] = session
        return session

    def join_window(self, record_id: str) -> tuple[datetime.datetime, str]:
        """``(expires_at, opener_facility_id)`` of the record's live session;
        raises exactly as :meth:`get_active_emergency_key` does if there is
        none (ADR-0057, ADR-0063)."""
        session = self._active_session(record_id)
        return session.expires_at, session.opener_facility_id

    def get_active_emergency_key(self, record_id: str) -> bytes:
        """Return the emergency key IFF a session exists and is not expired.

        Args:
            record_id: The record to look up.

        Returns:
            The session's emergency key.

        Raises:
            SessionNotFoundError: No session is registered for ``record_id``.
            EmergencySessionExpiredError: The session exists but
                ``now >= expires_at`` -- fail closed rather than hand back a
                key whose time-box has run out, even if
                :meth:`expire_session` has not yet swept it -- or the session
                is being expired.
        """
        return self._active_session(record_id).emergency_key

    def _active_session(self, record_id: str) -> EmergencySession:
        with self._lock:
            session = self._sessions.get(record_id)
        if session is None:
            raise SessionNotFoundError(
                f"no emergency session registered for record {record_id!r}"
            )
        now = self._clock()
        if session.expiring or session.is_expired(now):
            raise EmergencySessionExpiredError(
                f"emergency session for record {record_id!r} expired at "
                f"{session.expires_at.isoformat()}"
            )
        return session

    def expire_session(self, record_id: str, *, force: bool = False) -> ExpiryResult:
        """Expire one session: sign, rotate, sign again, zeroize.

        Order of operations:
            1. Look up the session; ``SessionNotFoundError`` if missing.
            2. If not expired and not ``force``, raise
               ``SessionNotExpiredError`` -- the manual/administrative path
               cannot short-circuit a clinician's granted time-box.
            3. Atomically remove the session from the registry so a
               concurrent caller (e.g. the background monitor racing an
               explicit call) cannot double-process it.
            4. Emit a signed ``EMERGENCY_OPEN -> EXPIRED`` transition through
               the shared state machine, which also consumes its
               ``event_id`` (ADR-0030).
            5. Rotate: unwrap the old DEK from ``emergency_wrapping``,
               decrypt the current payload, mint a fresh DEK, re-encrypt,
               and wrap the fresh DEK under ``baseline_wrapping_key`` at
               ``generation = old_generation + 1``.
            6. Emit a signed ``EXPIRED -> return_state`` transition.
            7. Invoke ``audit_logger`` (if configured) for each transition.
            8. Best-effort zeroize: overwrite the session's ``emergency_key``
               reference with 32 zero bytes (Python cannot guarantee true
               zeroization) and drop the session.

        Args:
            record_id: The record whose session to expire.
            force: Bypass the "already past ``expires_at``" requirement --
                used only by callers that have independently established the
                deadline has passed (the background sweep supplies this
                itself; a caller reaching for it directly should not).

        Returns:
            The :class:`ExpiryResult` describing both transitions and the
            rotation.

        Raises:
            SessionNotFoundError: No session is registered for ``record_id``.
            SessionNotExpiredError: The session has not reached
                ``expires_at`` and ``force`` was not set.

        Security property:
            Nothing that decrypted under the old (emergency) DEK can decrypt
            ``rotated_record`` -- the AES-256-GCM ciphertext, nonce, and DEK
            are all freshly generated (CONVENTIONS.md §2 rule 5). This is the
            forward-secrecy property the time-boxing exists to provide,
            *except* for whatever the emergency clinician already decrypted
            and cached locally before rotation -- nothing at this layer
            prevents that; it is a documented limitation (ADR-0035).
        """
        with self._lock:
            session = self._sessions.get(record_id)
            if session is None or session.expiring:
                raise SessionNotFoundError(
                    f"no emergency session registered for record {record_id!r}"
                )
            now = self._clock()
            if not force and not session.is_expired(now):
                raise SessionNotExpiredError(
                    f"emergency session for record {record_id!r} has not "
                    f"reached its expiry at {session.expires_at.isoformat()} "
                    f"(now={now.isoformat()}); pass force=True to override"
                )
            # Claim the session before doing any work so a concurrent
            # expirer (background monitor vs. an explicit call) cannot also
            # see it and double-rotate the same record. It stays registered
            # until expiry completes, so a failure can be retried (F20).
            session.expiring = True

        try:
            result = self._run_expiry(session, now)
        except Exception:
            with self._lock:
                session.expiring = False
                session.attempts += 1
                delay = min(
                    _RETRY_MAX_SECONDS,
                    _RETRY_BASE_SECONDS * 2 ** (session.attempts - 1),
                )
                session.retry_at = self._clock() + datetime.timedelta(seconds=delay)
            raise

        # --- Step 8: best-effort zeroize, then drop -----------------------------
        with self._lock:
            self._sessions.pop(record_id, None)
        session.emergency_key = EMERGENCY_KEY_ZERO_BYTES
        return result

    def _run_expiry(
        self, session: EmergencySession, now: datetime.datetime
    ) -> ExpiryResult:
        """Steps 4-7 of :meth:`expire_session`, resumable after a failure."""
        record_id = session.record_id

        # --- Step 4: EMERGENCY_OPEN -> EXPIRED (signed once per session) ------
        if session.expired_event is None:
            expired_event = create_transition_event(
                record_id=record_id,
                from_state=LifecycleState.EMERGENCY_OPEN,
                to_state=LifecycleState.EXPIRED,
                actor_id=self._timer_actor_id,
                signing_key=self._signing_key,
                issued_at=now,
            )
            self._state_machine.apply_transition(
                LifecycleState.EMERGENCY_OPEN, expired_event, self._public_key
            )
            session.expired_event = expired_event
        if not session.expired_emitted:
            self._emit(session.expired_event, session)
            session.expired_emitted = True

        # --- Step 5: forced key rotation ---------------------------------------
        old_dek = unwrap_dek(session.emergency_wrapping, session.emergency_key)
        plaintext = decrypt_record(session.current_record, old_dek)

        rotated_record, fresh_dek = encrypt_record(
            plaintext=plaintext,
            patient_id=session.current_record.patient_id,
            facility_id=session.current_record.facility_id,
            policy_id=session.current_record.policy_id,
            content_type=session.current_record.content_type,
            aad=session.current_record.aad,
            record_id=session.current_record.record_id,
            created_at=session.current_record.created_at,
            clinical=session.current_record.clinical,
        )
        rotated_wrapping = wrap_dek(
            dek=fresh_dek,
            record_id=record_id,
            wrapping_key=session.baseline_wrapping_key,
            wrapped_for=session.baseline_wrapping.wrapped_for,
            generation=session.baseline_wrapping.generation + 1,
        )

        # --- Step 6: EXPIRED -> pre-emergency state (signed once) -------------
        if session.rebaselined_event is None:
            rebaselined_event = create_transition_event(
                record_id=record_id,
                from_state=LifecycleState.EXPIRED,
                to_state=session.return_state,
                actor_id=self._timer_actor_id,
                signing_key=self._signing_key,
                issued_at=now,
            )
            self._state_machine.apply_transition(
                LifecycleState.EXPIRED, rebaselined_event, self._public_key
            )
            session.rebaselined_event = rebaselined_event
        # --- Step 7: audit and store, for the second transition ---------------
        self._emit(session.rebaselined_event, session)

        return ExpiryResult(
            record_id=record_id,
            expired_event=session.expired_event,
            rebaselined_event=session.rebaselined_event,
            rotated_record=rotated_record,
            rotated_wrapping=rotated_wrapping,
            audit_entries=[
                self._transition_metadata(session.expired_event, session),
                self._transition_metadata(session.rebaselined_event, session),
            ],
        )

    def check_and_expire_due(
        self, now: datetime.datetime | None = None
    ) -> list[ExpiryResult]:
        """Sweep active sessions and expire every one past its ``expires_at``.

        Args:
            now: Timestamp to compare against; defaults to the manager's
                clock.

        Returns:
            One :class:`ExpiryResult` per session that was due, in no
            particular order.
        """
        when = now if now is not None else self._clock()
        with self._lock:
            due_ids = [
                record_id
                for record_id, session in self._sessions.items()
                if session.is_expired(when)
                and not session.expiring
                and (session.retry_at is None or session.retry_at <= when)
            ]
        results: list[ExpiryResult] = []
        for record_id in due_ids:
            try:
                results.append(self.expire_session(record_id, force=True))
            except SessionNotFoundError:
                # Already claimed and expired by a concurrent sweep/call
                # between the snapshot above and this call -- not an error.
                continue
            except Exception:
                # The session was put back with a backoff and is retried on a
                # later sweep; access stays closed meanwhile (review F20).
                # Log the record id only, never key material.
                _logger.exception(
                    "emergency expiry failed for record %s; will retry", record_id
                )
        return results

    def start_monitor(self, poll_interval: float = 0.5) -> None:
        """Spawn a daemon thread that repeatedly calls :meth:`check_and_expire_due`.

        This is what lets emergency access terminate with "no admin action
        required" (ARCHITECTURE.md §5 step 7) -- the thread notices an
        expired session and rotates it without anyone calling
        :meth:`expire_session` by hand. Idempotent: calling this while a
        monitor is already running is a no-op.

        Args:
            poll_interval: Seconds between sweeps.
        """
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            return
        self._monitor_stop.clear()

        def _loop() -> None:
            while not self._monitor_stop.is_set():
                try:
                    self.check_and_expire_due()
                except Exception:
                    # Swallowing is correct here: the loop must survive, and
                    # a failed session is retried on the next sweep (F20).
                    _logger.exception("emergency expiry sweep failed")
                self._monitor_stop.wait(poll_interval)

        self._monitor_thread = threading.Thread(
            target=_loop, name="EmergencyExpiryManager-monitor", daemon=True
        )
        self._monitor_thread.start()

    def stop_monitor(self) -> None:
        """Signal the monitor thread to exit and join it.

        Safe to call whether or not a monitor is running.
        """
        self._monitor_stop.set()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=5.0)
            self._monitor_thread = None

    def _transition_metadata(
        self, event: TransitionEvent, session: EmergencySession
    ) -> dict[str, Any]:
        """Build the metadata dict passed to ``audit_logger`` for one transition.

        Deliberately excludes key material -- no DEK, emergency key, or
        wrapped bytes -- per CONVENTIONS.md §2 rule 3 (never log key
        material). Only identifiers, states, and timestamps.
        """
        return {
            "event_id": str(event.event_id),
            "record_id": event.record_id,
            "from_state": event.from_state.value,
            "to_state": event.to_state.value,
            "actor_id": event.actor_id,
            "issued_at": event.issued_at.isoformat(),
            "correlation_id": session.correlation_id,
        }

    def _emit(self, event: TransitionEvent, session: EmergencySession) -> None:
        """Audit first, then mirror into the store as a compare-and-set (N1).

        An audit or store failure raises, so the attempt is retried; an event
        already appended is not appended again. A state conflict means someone
        else changed the record's state; overwriting it could undo a
        revocation, so it is logged and left alone.
        """
        event_id = str(event.event_id)
        if self._audit_logger is not None and event_id not in session.audited_event_ids:
            self._audit_logger(self._transition_metadata(event, session))
            session.audited_event_ids.add(event_id)
        if self._state_writer is None:
            return
        try:
            self._state_writer(
                event.record_id, event.from_state, event.to_state, str(event.event_id)
            )
        except StateConflictError:
            _logger.error(
                "expiry transition %s -> %s for record %s not stored: the state "
                "changed underneath the timer; not overwriting it",
                event.from_state.value,
                event.to_state.value,
                event.record_id,
            )
