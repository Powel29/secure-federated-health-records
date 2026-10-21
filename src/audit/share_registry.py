"""In-memory custody of a holder's break-glass shares (P4-2, C11 <- C10).

ARCHITECTURE.md §5 step 3 names three break-glass holders of the weighted
3-of-4 split (ADR-0089): the attending clinician's custody (share 1), the
patient's home authority (share 2) and the audit service (shares 3 and 4).
This module is where a holder service keeps its *holding* for a record -- the
audit service's two shares, the home authority's one -- between being handed
it and releasing it (the audit service through
``audit.share_custody.release_share_after_commit``). It does not check which
share indices a holding contains; each service checks its own set with
``breakglass.emergency_key.check_holding`` before it stores one.

Deliberately in-memory only: ARCHITECTURE.md §7 bootstraps the whole
federation fresh at every run (a new root anchor, new authority keys, and
reseeded data), so nothing here needs to outlive one process's lifetime. A
restart loses every holding (PROJECT.md §5 item 8). A holding is looked up by
an opaque ``share_key`` the caller chooses -- normally a ``record_id`` -- one
per split this service was given shares of.

Reads are non-destructive (:meth:`ShareRegistry.get` does not remove the
holding). :meth:`ShareRegistry.put` never overwrites (review F4): a second
deposit under the same key would silently replace a live record's shares and
break its break-glass for good. Rotation at expiry -- which invalidates the
old emergency key and mints a new one with a fresh split (ADR-0069) --
replaces the holding with :meth:`ShareRegistry.replace`, only ever with a
later generation, so a stale or repeated rotation cannot roll a holding back.
A later generation may skip one: a rotation recovered after a crash
(ADR-0081) starts after whatever the store already holds. This mirrors how a
real custodian holds standing shares rather than a one-time token: what makes
a share safe to reuse across repeated legitimate emergency sessions for the
same record is the gate on each release, not the share being consumed.
"""

from __future__ import annotations

import threading

from crypto_core import CryptoError

# Matches shamir.split.split_secret's return shape and
# audit.share_custody.Share: an opaque (x, share_bytes) pair.
Share = tuple[int, bytes]
# One holder's shares for one record, in x order.
Holding = tuple[Share, ...]


class ShareNotFoundError(CryptoError):
    """No holding is registered under the requested key."""


class ShareAlreadyHeldError(CryptoError):
    """A holding is already registered under this key; it is never overwritten."""


class ShareGenerationError(CryptoError):
    """A replacement is not for a later generation than the one held (ADR-0069)."""


class ShareRegistry:
    """Thread-safe registry of ``share_key -> Holding`` held by this process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._holdings: dict[str, Holding] = {}
        # Emergency-key generation each holding belongs to: 0 at ingest, +1
        # per rotation (ADR-0069).
        self._generations: dict[str, int] = {}

    def put(self, share_key: str, holding: Holding) -> None:
        """Register the holding kept under ``share_key``; never replace one.

        Args:
            share_key: Caller-chosen identifier for this holding -- normally
                the ``record_id`` the underlying emergency key protects.
            holding: The opaque ``(x, share_bytes)`` threshold shares.

        Raises:
            ShareAlreadyHeldError: A holding is already kept under the key
                (review F4).
        """
        with self._lock:
            if share_key in self._holdings:
                raise ShareAlreadyHeldError(
                    f"a share is already held for key {share_key!r}"
                )
            self._holdings[share_key] = holding
            self._generations[share_key] = 0

    def replace(self, share_key: str, holding: Holding, generation: int) -> None:
        """Replace the held shares with a later generation's (ADR-0069).

        Idempotent for a retry: replacing with the holding already kept at
        ``generation`` is a no-op. A generation may be skipped: a rotation
        recovered after a crash (ADR-0081) starts one after the store's, which
        can be ahead of this holder's if the crash came between deposits.

        Raises:
            ShareNotFoundError: No holding is kept under the key.
            ShareGenerationError: ``generation`` is not after the held one
                (or is the same generation with a different holding).
        """
        with self._lock:
            current = self._holdings.get(share_key)
            if current is None:
                raise ShareNotFoundError(f"no share held for key {share_key!r}")
            held = self._generations[share_key]
            if generation == held and current == holding:
                return
            if generation <= held:
                raise ShareGenerationError(
                    f"share for {share_key!r} is at generation {held}; "
                    f"refusing generation {generation}"
                )
            self._holdings[share_key] = holding
            self._generations[share_key] = generation

    def generation(self, share_key: str) -> int:
        """The generation of the holding kept under ``share_key``.

        Raises:
            ShareNotFoundError: Nothing is registered under ``share_key``.
        """
        with self._lock:
            if share_key not in self._generations:
                raise ShareNotFoundError(f"no share held for key {share_key!r}")
            return self._generations[share_key]

    def has(self, share_key: str) -> bool:
        """Whether a holding is currently registered under ``share_key``."""
        with self._lock:
            return share_key in self._holdings

    def get(self, share_key: str) -> Holding:
        """Return the holding kept under ``share_key`` without removing it.

        Raises:
            ShareNotFoundError: Nothing is registered under ``share_key``.
        """
        with self._lock:
            holding = self._holdings.get(share_key)
        if holding is None:
            raise ShareNotFoundError(
                f"no share held for key {share_key!r} "
                "(never registered, or forgotten after rotation)"
            )
        return holding

    def forget(self, share_key: str) -> None:
        """Remove any holding kept under ``share_key``; a no-op if absent.

        Used when a record's emergency key is rotated (P3-6/P3-7) and the
        retired shares must no longer be releasable.
        """
        with self._lock:
            self._holdings.pop(share_key, None)
            self._generations.pop(share_key, None)
