"""Anti-replay consumed-ID stores for emergency assertions and request envelopes.

Implements P3-11 (WORKFLOW.md): one-time IDs for emergency assertions, share
requests, and request envelopes so that a captured request cannot be replayed
for repeated access.

Design follows the ``ConsumedEventIds`` pattern established by P3-1 in
``lifecycle/state_machine.py`` (ADR-0030 §3): an in-memory store per instance,
idempotent-fail-closed ``.consume()`` that raises on reuse, never returning a
boolean. A persisted backing store rides with P3-3 (audit chain) and swaps in
via the same interface.

Ordering invariant (ADR-0030 §4): consumption happens **after** signature
verification, never before. Consuming before would let a forged message burn
a legitimate ID from a future re-sign.
"""

from __future__ import annotations

import threading
from uuid import UUID

from breakglass.exceptions import (
    BreakglassError,
    ReplayedAssertionError,
    ReplayedRequestError,
)


class _ConsumedIdStore:
    """Thread-safe one-time-ID store base.

    Security property:
        :meth:`consume` is idempotent-fail-closed: the first consume of a
        given id succeeds silently; every subsequent consume raises
        the configured :attr:`_error_cls`. Never returns a ``was_new`` boolean.
    """

    _error_cls: type[BreakglassError] = BreakglassError
    _id_name: str = "id"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: set[UUID] = set()

    def consume(self, item_id: UUID) -> None:
        """Mark ``item_id`` consumed; raise if already consumed."""
        with self._lock:
            if item_id in self._seen:
                raise self._error_cls(f"{self._id_name} {item_id} already consumed")
            self._seen.add(item_id)

    def has_seen(self, item_id: UUID) -> bool:
        """Check without consuming -- for tests and diagnostics only."""
        with self._lock:
            return item_id in self._seen


class ConsumedAssertionIds(_ConsumedIdStore):
    """Thread-safe one-time-ID store for ``EmergencyAssertion.assertion_id``."""

    _error_cls = ReplayedAssertionError
    _id_name = "assertion_id"


class ConsumedRequestIds(_ConsumedIdStore):
    """Thread-safe one-time-ID store for ``RequestEnvelope.request_id``."""

    _error_cls = ReplayedRequestError
    _id_name = "request_id"
