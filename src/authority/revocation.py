"""Revocation registry for attribute credentials (C6, ARCHITECTURE.md §8).

This module implements the dynamic revocation registry for the credential lifecycle
(P2-6). An authority issues credentials that are ACTIVE at issuance time; when an
authority revokes a credential post-issuance, its serial number is recorded in the
authority's revocation registry.

Verification checks (`verify_credential` and `AttributeAuthority.get_attribute_key`)
consult this registry and fail closed with ``CredentialRevokedError`` if a credential
has been revoked.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass


@dataclass(frozen=True)
class RevocationEntry:
    """An entry in the credential revocation registry.

    Attributes:
        serial: The unique serial identifier of the revoked credential.
        issuer_id: The identifier of the issuing authority that revoked it.
        revoked_at: The timestamp when revocation was recorded.
        reason: Optional human-readable or coded reason for revocation.
    """

    serial: str
    issuer_id: str
    revoked_at: datetime.datetime
    reason: str = ""


class RevocationRegistry:
    """Authority-scoped registry of revoked credential serials.

    Each authority maintains its own isolated revocation registry instance.
    """

    def __init__(self) -> None:
        self._entries: dict[str, RevocationEntry] = {}

    def revoke(
        self,
        serial: str,
        issuer_id: str,
        reason: str = "",
        revoked_at: datetime.datetime | None = None,
    ) -> RevocationEntry:
        """Record the revocation of a credential by its serial.

        Args:
            serial: The credential serial number to revoke.
            issuer_id: The authority issuing the revocation.
            reason: Optional reason string describing why it was revoked.
            revoked_at: The effective revocation timestamp; defaults to utcnow.

        Returns:
            The created :class:`RevocationEntry`.

        Security property:
            Revocation is idempotent and immediate: once recorded, any subsequent
            lookup for this serial reports revoked.
        """
        if revoked_at is None:
            revoked_at = datetime.datetime.now(datetime.timezone.utc)
        elif revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=datetime.timezone.utc)

        entry = RevocationEntry(
            serial=serial,
            issuer_id=issuer_id,
            revoked_at=revoked_at,
            reason=reason,
        )
        self._entries[serial] = entry
        return entry

    def is_revoked(self, serial: str) -> bool:
        """Check if a credential serial is marked as revoked in this registry."""
        return serial in self._entries

    def get_entry(self, serial: str) -> RevocationEntry | None:
        """Fetch the revocation entry for a serial, or None if not revoked."""
        return self._entries.get(serial)

    def all_revoked(self) -> list[RevocationEntry]:
        """Return all revocation entries recorded in this registry."""
        return list(self._entries.values())
