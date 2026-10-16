"""In-memory custody of the audit service's break-glass share (P4-2, C11 <- C10).

ARCHITECTURE.md §5 step 3 names three break-glass custodians: the attending
clinician, the patient's home authority, and the audit service (share 3). This
module is where the audit service's copy of a record's share 3 lives between
being handed to the service and being released through
``audit.share_custody.release_share_after_commit``.

Deliberately in-memory only: ARCHITECTURE.md §7 bootstraps the whole
federation fresh at every run (a new root anchor, new authority keys, and
reseeded data), so nothing here needs to outlive one process's lifetime. A
share is looked up by an opaque ``share_key`` the caller chooses -- normally a
``record_id`` -- one per 2-of-3 split this service was given a share of.

Reads are non-destructive (:meth:`ShareRegistry.get` does not remove the
share). :meth:`ShareRegistry.put` never overwrites (review F4): a second
deposit under the same key would silently replace a live record's share and
break its break-glass for good. Rotation at expiry -- which invalidates the
old emergency key and mints a new one with a fresh 3-way split (ADR-0069) --
replaces the share with :meth:`ShareRegistry.replace`, only ever with a later
generation, so a stale or repeated rotation cannot roll a share back. A later
generation may skip one: a rotation recovered after a crash (ADR-0081) starts
after whatever the store already holds. This
mirrors how a real custodian holds a standing share rather than a one-time
token: what makes a share safe to reuse across repeated legitimate emergency
sessions for the same record is the log-before-release gate on each release,
not the share being consumed.
"""

from __future__ import annotations

import threading

from crypto_core import CryptoError

# Matches shamir.split.split_secret's return shape and
# audit.share_custody.Share: an opaque (x, share_bytes) pair.
Share = tuple[int, bytes]


class ShareNotFoundError(CryptoError):
    """No share is registered under the requested key."""


class ShareAlreadyHeldError(CryptoError):
    """A share is already registered under this key; it is never overwritten."""


class ShareGenerationError(CryptoError):
    """A replacement is not for a later generation than the one held (ADR-0069)."""


class ShareRegistry:
    """Thread-safe registry of ``share_key -> Share`` held by this process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._shares: dict[str, Share] = {}
        # Emergency-key generation each share belongs to: 0 at ingest, +1 per
        # rotation at expiry (ADR-0069).
        self._generations: dict[str, int] = {}

    def put(self, share_key: str, share: Share) -> None:
        """Register the share held under ``share_key``; never replace one.

        Args:
            share_key: Caller-chosen identifier for this share -- normally
                the ``record_id`` the underlying emergency key protects.
            share: The opaque ``(x, share_bytes)`` threshold share.

        Raises:
            ShareAlreadyHeldError: A share is already held under the key
                (review F4).
        """
        with self._lock:
            if share_key in self._shares:
                raise ShareAlreadyHeldError(
                    f"a share is already held for key {share_key!r}"
                )
            self._shares[share_key] = share
            self._generations[share_key] = 0

    def replace(self, share_key: str, share: Share, generation: int) -> None:
        """Replace the held share with a later generation's (ADR-0069).

        Idempotent for a retry: replacing with the share already held at
        ``generation`` is a no-op. A generation may be skipped: a rotation
        recovered after a crash (ADR-0081) starts one after the store's, which
        can be ahead of this holder's if the crash came between deposits.

        Raises:
            ShareNotFoundError: No share is held under the key.
            ShareGenerationError: ``generation`` is not after the held one
                (or is the same generation with a different share).
        """
        with self._lock:
            current = self._shares.get(share_key)
            if current is None:
                raise ShareNotFoundError(f"no share held for key {share_key!r}")
            held = self._generations[share_key]
            if generation == held and current == share:
                return
            if generation <= held:
                raise ShareGenerationError(
                    f"share for {share_key!r} is at generation {held}; "
                    f"refusing generation {generation}"
                )
            self._shares[share_key] = share
            self._generations[share_key] = generation

    def generation(self, share_key: str) -> int:
        """The generation of the share held under ``share_key``.

        Raises:
            ShareNotFoundError: Nothing is registered under ``share_key``.
        """
        with self._lock:
            if share_key not in self._generations:
                raise ShareNotFoundError(f"no share held for key {share_key!r}")
            return self._generations[share_key]

    def has(self, share_key: str) -> bool:
        """Whether a share is currently registered under ``share_key``."""
        with self._lock:
            return share_key in self._shares

    def get(self, share_key: str) -> Share:
        """Return the share held under ``share_key`` without removing it.

        Raises:
            ShareNotFoundError: Nothing is registered under ``share_key``.
        """
        with self._lock:
            share = self._shares.get(share_key)
        if share is None:
            raise ShareNotFoundError(
                f"no share held for key {share_key!r} "
                "(never registered, or forgotten after rotation)"
            )
        return share

    def forget(self, share_key: str) -> None:
        """Remove any share held under ``share_key``; a no-op if absent.

        Used when a record's emergency key is rotated (P3-6/P3-7) and the
        retired share must no longer be releasable.
        """
        with self._lock:
            self._shares.pop(share_key, None)
            self._generations.pop(share_key, None)
