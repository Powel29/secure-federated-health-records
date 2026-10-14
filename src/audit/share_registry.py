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
break its break-glass for good. Rotation -- which invalidates the old
emergency key and mints a new one with a fresh 3-way split (P3-6/P3-7) --
retires the old share with :meth:`ShareRegistry.forget` first. This
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


class ShareRegistry:
    """Thread-safe registry of ``share_key -> Share`` held by this process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._shares: dict[str, Share] = {}

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
