"""Exceptions for the patient-consent gate (P3-2).

Signature failures are surfaced as :class:`crypto_core.InvalidSignatureError`
consistently with the rest of the project, not as a consent-specific alias --
one signature error type across all modules keeps callers' ``except`` clauses
uniform (CONVENTIONS.md §2 rule 6).
"""

from __future__ import annotations

from crypto_core.exceptions import CryptoError


class ConsentError(CryptoError):
    """Base exception for all consent-gate failures."""


class ConsentExpiredError(ConsentError):
    """The consent grant (or request) has passed its ``expires_at``.

    A grant whose validity window has closed is treated as absent -- the
    caller must obtain a fresh grant, not renew this one.
    """


class ConsentDeniedError(ConsentError):
    """The consent grant carries ``status == ConsentStatus.DENIED``.

    A denial is a signed patient decision; it is not the same as "no grant
    exists" -- it is a first-class artifact the audit chain must record.
    """


class ConsentRevokedError(ConsentError):
    """The consent grant carries ``status == ConsentStatus.REVOKED``.

    Revocation is a patient-only signed act (a fresh ``ConsentGrant``
    answering the same ``request_id`` with ``status=REVOKED``). Once a
    revocation is present, subsequent reads fail closed here.
    """


class ConsentScopeError(ConsentError):
    """A read targeted a ``record_id`` not present in ``grant.scope``.

    Scope is the primary defense against a compromised or over-authorised
    grant leaking beyond the records the patient actually approved.
    """


class ConsentSubjectError(ConsentError):
    """The reader does not match the grant's ``grantee_id``.

    A ``ConsentGrant`` names *who* the patient approved. A different party
    presenting the same grant is refused even if the record is in scope --
    consent is not transferable.
    """
