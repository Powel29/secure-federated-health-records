"""Shared helpers for portal tests (SQLite settings, services mocked).

The portals are tested at their boundary: every call into
``portal_core.services`` (custodian / facility / audit) and
``portal_core.store_reader`` (read-only store) is patched, so a test asserts
what the portal *does* with a refusal or a success -- never re-tests the
crypto core, which has its own suites under ``tests/``.
"""

from __future__ import annotations

import re
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator
from unittest import mock

from django.contrib.auth.models import User

from accounts.models import Profile, Role
from portal_core.services import ServiceError

# Generated per test run so no login password is committed.
TEST_PASSWORD = secrets.token_urlsafe(16)


def make_user(username: str, role: str, subject_id: str, facility: str = "") -> User:
    user = User.objects.create_user(username=username, password=TEST_PASSWORD)
    Profile.objects.create(
        user=user, role=role, subject_id=subject_id, home_facility_id=facility
    )
    return user


def patient(username: str = "alice", subject_id: str = "pat-101") -> User:
    return make_user(username, Role.PATIENT, subject_id)


def clinician(username: str = "house", subject_id: str = "doc-201") -> User:
    return make_user(username, Role.CLINICIAN, subject_id, "facility-b")


def admin(username: str = "auditor") -> User:
    return make_user(username, Role.ADMIN, f"admin-{username}")


def declare_token(response: Any) -> str:
    """The one-time declare token a rendered break-glass form carries (ADR-0065)."""
    match = re.search(
        r'name="declare_token" value="([^"]+)"', response.content.decode("utf-8")
    )
    if match is None:
        raise AssertionError("the break-glass form carries no declare token")
    return match.group(1)


def arm_declare(client: Any) -> str:
    """Put a declare token in a test client's session, as a form render would."""
    token = secrets.token_urlsafe(16)
    session = client.session
    session["clinician.declare_token"] = token
    session.save()
    return token


def refuse(status: int, detail: str, service: str = "custodian") -> ServiceError:
    return ServiceError(service, status, detail)


class AuditLog:
    """Stand-in for ``services.audit_append``: records entries, can be 'down'."""

    def __init__(self, down: bool = False) -> None:
        self.entries: list[dict[str, Any]] = []
        self.down = down

    def __call__(self, **kw: Any) -> dict[str, Any]:
        if self.down:
            raise ServiceError("audit", None, "service unreachable")
        entry = {"seq": len(self.entries) + 1, **kw}
        self.entries.append(entry)
        return entry

    def of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["event_type"] == event_type]


@contextmanager
def patched(**overrides: Any) -> Iterator[dict[str, Any]]:
    """Patch ``portal_core.services.*`` names; returns the mocks by name."""
    patches = {
        name: mock.patch(f"portal_core.services.{name}", value)
        for name, value in overrides.items()
    }
    mocks: dict[str, Any] = {}
    try:
        for name, p in patches.items():
            mocks[name] = p.start()
        yield mocks
    finally:
        for p in patches.values():
            p.stop()


SUBJECT_CLINICIAN = {
    "subject_id": "doc-201",
    "kind": "clinician",
    "display_name": "Dr. Arjun Rao",
    "facility_id": "facility-b",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFk\n-----END PUBLIC KEY-----\n",
    "certificate_pem": "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n",
    "pre_public_key": 12345,
    "credentials": [
        {
            "serial": "s1",
            "issuer_id": "authority-med",
            "name": "role",
            "value": "emergency-physician",
            "valid_until": "2027-01-01T00:00:00Z",
            "status": "active",
        }
    ],
}

SUBJECT_PATIENT = {
    "subject_id": "pat-101",
    "kind": "patient",
    "display_name": "Alice Vance",
    "facility_id": None,
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFk\n-----END PUBLIC KEY-----\n",
    "certificate_pem": None,
    "pre_public_key": None,
    "credentials": [
        {
            "serial": "s2",
            "issuer_id": "authority-net",
            "name": "owner",
            "value": "pat-101",
            "valid_until": "2027-01-01T00:00:00Z",
            "status": "active",
        }
    ],
}

RECORD_META = {
    "record_id": "rec-001",
    "patient_id": "pat-101",
    "facility_id": "facility-a",
    "facility_name": "Northvale General Hospital",
    "content_type": "application/json",
    "ciphertext_bytes": 512,
    # A real datetime, as the store reader returns -- the session cache must cope.
    "created_at": datetime(2026, 9, 6, 14, 30, tzinfo=timezone.utc),
    "lifecycle_state": "granted",
}

SIGNED_REQUEST = {
    "request_id": "0c0a4a1e-2f7e-4a3a-9d2b-3d1d7a5f8b21",
    "patient_id": "pat-101",
    "requester_id": "doc-201",
    "scope": ["rec-001"],
    "purpose": "pre-op review",
    "requested_at": "2026-09-13T10:00:00+00:00",
    "expires_at": "2026-09-20T10:00:00+00:00",
    "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
    "signature": "c2ln",
}


def signed_grant(status: str = "granted") -> dict[str, Any]:
    return {
        "grant_id": "7d2b4f6c-1111-4c3d-9e4f-aaaaaaaaaaaa",
        "request_id": SIGNED_REQUEST["request_id"],
        "patient_id": "pat-101",
        "grantee_id": "doc-201",
        "scope": ["rec-001"],
        "status": status,
        "decided_at": "2026-09-13T11:00:00+00:00",
        "expires_at": "2026-09-18T11:00:00+00:00",
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        "signature": "c2ln",
    }
