"""Exceptions for the break-glass module (C11, ARCHITECTURE.md §8).

Every failure mode that can occur during emergency-assertion validation,
request-envelope verification, or anti-replay enforcement has its own
exception. All extend ``BreakglassError`` so callers can catch the whole
family, and ``BreakglassError`` itself extends ``CryptoError`` to stay in
the project-wide exception hierarchy.
"""

from __future__ import annotations

from crypto_core.exceptions import CryptoError


class BreakglassError(CryptoError):
    """Base exception for all break-glass failures."""


# ---------------------------------------------------------------------------
# Emergency assertion validation (P3-10)
# ---------------------------------------------------------------------------


class AssertionExpiredError(BreakglassError):
    """The emergency assertion's ``expires_at`` is not in the future.

    ARCHITECTURE.md §8: ``expires_at`` is in the future is a precondition
    of share collection.  A stale assertion is not a standing permission.
    """


class AssertionLifetimeError(BreakglassError):
    """The assertion's lifetime is too long or it is dated in the future.

    ``expires_at - issued_at`` must not exceed the configured maximum, and
    ``issued_at`` must not be later than now plus the allowed clock skew (F6).
    A long-lived assertion would be a standing permission, not an emergency.
    """


class CertificateRevokedError(BreakglassError):
    """The presenting clinician's certificate serial is on the revoked list (F1)."""


class ClinicianMismatchError(BreakglassError):
    """``assertion.clinician_id`` does not match the presenting certificate's CN.

    ARCHITECTURE.md §8: ``clinician_id`` matches the certificate subject.
    A valid signature from the wrong clinician's key is still a rejection.
    """


class FacilityMismatchError(BreakglassError):
    """``assertion.facility_id`` does not match the receiving facility.

    ARCHITECTURE.md §8: ``facility_id`` matches the receiving node.
    An assertion issued for one facility cannot be presented at another.
    """


# ---------------------------------------------------------------------------
# Replay protection (P3-11)
# ---------------------------------------------------------------------------


class ReplayedAssertionError(BreakglassError):
    """An ``EmergencyAssertion.assertion_id`` was already consumed.

    Without this check a captured break-glass assertion could be replayed for
    repeated emergency sessions, defeating the time-boxing the state machine
    exists to enforce (ARCHITECTURE.md §8 replay protection).
    """


class ReplayedRequestError(BreakglassError):
    """A ``RequestEnvelope.request_id`` was already consumed.

    Backs the ``RequestEnvelope`` contract's declared one-time property:
    ``request_id`` is consumed on use and rejected on reuse.
    """


# ---------------------------------------------------------------------------
# Request envelope validation (P3-11)
# ---------------------------------------------------------------------------


class EnvelopeRecipientMismatchError(BreakglassError):
    """``envelope.recipient_id`` does not match the target service.

    ARCHITECTURE.md §8: the envelope is bound to its destination so a
    captured envelope at one service cannot be presented to another.
    """


class EnvelopeOperationMismatchError(BreakglassError):
    """``envelope.operation`` names another method or path than the request's.

    An envelope signed for one endpoint must not authorize another (ADR-0066).
    """


class EnvelopeExpiredError(BreakglassError):
    """``envelope.issued_at`` is too old, or too far in the future (ADR-0066).

    Bounds how long a captured request stays usable if a callee's
    consumed-id store is lost, e.g. on a restart of an in-memory store.
    """


# ---------------------------------------------------------------------------
# Emergency unlock gate (P3-5)
# ---------------------------------------------------------------------------


class InsufficientSharesError(BreakglassError):
    """Fewer than ``THRESHOLD`` unique shares presented -- break-glass fails closed.

    Uniqueness is by share x-coordinate: presenting the same share twice, any
    single holder's shares alone (including the audit service's two), or the
    custodian's and home authority's together does not satisfy the 3-of-4
    threshold. No single party can open a record unilaterally, and no pair
    without the audit service can (ARCHITECTURE.md C11, ADR-0089).
    """


class ShareHoldingError(BreakglassError):
    """A holding is not exactly the holder's own share indices (ADR-0089).

    The custodian takes {1}, the home authority {2}, the audit service
    {3, 4}. A deposit or replacement outside that set is refused, so a
    misrouted share cannot give two non-audit holders three points.
    """


# ---------------------------------------------------------------------------
# Share transport (ADR-0079)
# ---------------------------------------------------------------------------


class SealedShareError(BreakglassError):
    """A sealed share or a share-key statement does not check out.

    The statement is not signed by a root-issued service certificate of the
    expected kind, or a sealed share does not open for this recipient and
    record (wrong key, wrong recipient, wrong record, or tampered). Fail
    closed: the share is never used.
    """
