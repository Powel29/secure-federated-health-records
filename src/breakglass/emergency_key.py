"""Emergency key generation and weighted 3-of-4 threshold split (P3-5, ADR-0089).

The emergency key is the 256-bit secret that authorizes break-glass DEK
recovery. It is never held whole by any single party: it is a Shamir 3-of-4
sharing whose points have fixed holders (ARCHITECTURE.md C11, §5 step 3):

- x = 1: the attending clinician's custody (the custodian);
- x = 2: the patient's home authority (issuer of the ``owner`` credential);
- x = 3 and x = 4: the federation audit service.

Any three points reconstruct the key. The audit service holds two, so every
reconstruction includes it, and the custodian plus the home authority (two
points) cannot open a record; neither can the audit service alone (see
``tests/security/test_phase3_breakglass_security.py``). Giving one holder two
points is Shamir's own weighting device -- the split itself is the unchanged
``shamir.split.split_secret``.
"""

from __future__ import annotations

from collections.abc import Iterable

from crypto_core.symmetric import generate_key
from shamir.split import split_secret

from breakglass.exceptions import ShareHoldingError

EMERGENCY_KEY_BYTES = 32  # 256-bit emergency key
THRESHOLD = 3  # k: shares required to reconstruct
TOTAL_SHARES = 4  # n: shares issued

# Which share x-coordinates each holder takes (ADR-0089). Every holder refuses
# a holding that is not exactly its own set, so a misrouted share cannot give
# two non-audit holders three points.
CLINICIAN_SHARE_XS = frozenset({1})
HOME_AUTHORITY_SHARE_XS = frozenset({2})
AUDIT_SHARE_XS = frozenset({3, 4})

# Matches shamir.split.split_secret's return shape: (x, share_bytes) per share.
Share = tuple[int, bytes]


def generate_emergency_key() -> bytes:
    """Generate a fresh 256-bit emergency key.

    Returns:
        32 random bytes from the system CSPRNG.

    Security property:
        Entropy is drawn via ``crypto_core.symmetric.generate_key``
        (CONVENTIONS.md §2 rule 2); never derived or reused.
    """
    return generate_key(EMERGENCY_KEY_BYTES)


def split_emergency_key(key: bytes) -> list[Share]:
    """Split an emergency key into the weighted 3-of-4 Shamir sharing.

    Args:
        key: The 256-bit emergency key to split.

    Returns:
        ``TOTAL_SHARES`` shares with x = 1..4, in x order; any ``THRESHOLD``
        of them reconstruct ``key`` via :func:`shamir.split.combine_shares`.
        Route them with :func:`holder_shares`.

    Security property:
        Information-theoretic: any ``THRESHOLD - 1`` shares reveal nothing
        about ``key`` (shamir's guarantee, CONVENTIONS.md §2).
    """
    return split_secret(secret=key, k=THRESHOLD, n=TOTAL_SHARES)


def holder_shares(
    shares: Iterable[Share], holder_xs: frozenset[int]
) -> tuple[Share, ...]:
    """The shares of a split that belong to one holder, in x order.

    Args:
        shares: A full split, as :func:`split_emergency_key` returns it.
        holder_xs: The holder's set, e.g. :data:`AUDIT_SHARE_XS`.

    Raises:
        ShareHoldingError: The split does not contain exactly one share for
            each of the holder's x-coordinates.
    """
    picked = tuple(sorted((s for s in shares if s[0] in holder_xs), key=lambda s: s[0]))
    check_holding(picked, holder_xs)
    return picked


def check_holding(holding: Iterable[Share], holder_xs: frozenset[int]) -> None:
    """Refuse a holding that is not exactly one share per x in ``holder_xs``.

    Every holder calls this before it stores a deposited or replacement
    holding (ADR-0089): the custodian with :data:`CLINICIAN_SHARE_XS`, the
    home authority with :data:`HOME_AUTHORITY_SHARE_XS` and the audit
    service with :data:`AUDIT_SHARE_XS`.

    Raises:
        ShareHoldingError: A share index is outside the set, repeated, or
            missing.
    """
    xs = [share[0] for share in holding]
    if len(xs) != len(set(xs)) or set(xs) != holder_xs:
        raise ShareHoldingError(
            f"holding has share indices {sorted(xs)}; this holder takes exactly "
            f"{sorted(holder_xs)}"
        )
