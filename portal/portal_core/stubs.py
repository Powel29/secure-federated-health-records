"""Explicit boundaries for backends the portal must never implement itself (ADR-0021).

Anywhere the portal would need a crypto/backend action that has not been built,
it calls one of these. They raise loudly rather than faking success, so no page
can accidentally shortcut the security model while the shells exist.

The governing invariant (ADR-0021): a portal account alone grants zero access.
Credentials are ISSUED by an authority, never by a signup form -- so
``issue_credential`` lives here until ``authority`` (P2-2) exists, and can never
be satisfied from within the portal.
"""

from __future__ import annotations


class NotWiredYet(Exception):
    """Raised when a portal action needs a backend action that belongs to another service."""


def issue_credential(request_id: int) -> None:
    """Issue an authority-signed attribute credential for a registration request.

    Deliberately unimplemented: issuance is the authority's job (P2-2), never the
    portal's. A doctor self-registers a *request*; only an authority *issues*.
    """
    raise NotWiredYet(
        "credential issuance belongs to `authority` (P2-2); the portal only "
        "records the request -- it never issues an attribute itself"
    )


def request_access(clinician_id: str, patient_id: str) -> None:
    """Ask a patient to grant access. Consent + grant land with lifecycle (P3)."""
    raise NotWiredYet(
        "access requests need the consent/grant path (lifecycle, P3); the portal "
        "records the request but cannot grant access"
    )


def declare_breakglass(clinician_id: str, patient_id: str, reason: str) -> None:
    """Declare an emergency. The 3-of-4 threshold gate belongs to breakglass (P3-5)."""
    raise NotWiredYet(
        "break-glass needs the Emergency Assertion + 3-of-4 threshold gate "
        "(breakglass, P3-5); the portal cannot open a record itself"
    )


def ingest_upload(patient_id: str, filename: str, data: bytes) -> None:
    """Encrypt-and-store an uploaded record via the ingest path.

    Deliberately unimplemented: encryption + the store write belong to the
    `records` ingest path (P3-14), never to Django. The portal forwards; it does
    not encrypt and it does not write the store.
    """
    raise NotWiredYet(
        "record ingest belongs to the `records` path (P3-14); the portal never "
        "encrypts or writes the store itself"
    )
