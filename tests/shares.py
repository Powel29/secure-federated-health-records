"""Which points of the weighted 3-of-4 break-glass split a test presents (ADR-0089).

Share 1 is the custodian's, share 2 the home authority's, shares 3 and 4 the
audit service's. A reconstruction needs three points; shares 1 and 2 are
only two, so every set of three contains at least one share only the audit
service releases (and it releases 3 and 4 together, after its log commit).
The two sets the system actually presents:

- :func:`unlock_points` -- the normal path: share 1 plus shares 3 and 4;
- :func:`fallback_points` -- share 1 lost: share 2 plus shares 3 and 4.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from breakglass.emergency_key import (
    AUDIT_SHARE_XS,
    CLINICIAN_SHARE_XS,
    HOME_AUTHORITY_SHARE_XS,
)

Share = tuple[int, bytes]


def points(shares: Iterable[Share], xs: Iterable[int]) -> list[Share]:
    """The shares of a split at x-coordinates ``xs``, in x order."""
    wanted = set(xs)
    return sorted((s for s in shares if s[0] in wanted), key=lambda s: s[0])


def unlock_points(shares: Iterable[Share]) -> list[Share]:
    """Share 1 plus the audit service's shares 3 and 4."""
    return points(shares, CLINICIAN_SHARE_XS | AUDIT_SHARE_XS)


def fallback_points(shares: Iterable[Share]) -> list[Share]:
    """The home authority's share 2 plus the audit service's shares 3 and 4."""
    return points(shares, HOME_AUTHORITY_SHARE_XS | AUDIT_SHARE_XS)


def deposited_unlock_points(deposit: Mapping[str, Any]) -> list[Share]:
    """Share 1 and shares 3 and 4 of a rotation the recording ports saw."""
    return [deposit["clinician_share"], *deposit["audit_shares"]]
