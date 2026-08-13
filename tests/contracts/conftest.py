"""Valid-instance factories for contract tests.

Each helper returns the keyword arguments for one schema with all-valid,
structurally-correct values. A test that wants a negative case takes these and
overrides one field, so every negative test differs from a known-good baseline by
exactly the thing under test.

The byte values here are non-secret test-only constants (CONVENTIONS.md §2
rule 4): they are not keys, not derived from any real material, and exist only to
give the type-checkers something correctly shaped to chew on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

_NOW = datetime(2026, 8, 12, 12, 0, 0, tzinfo=timezone.utc)
_LATER = _NOW + timedelta(minutes=15)

# Test-only byte fixtures. Not key material.
GCM_NONCE = bytes(range(12))  # 12 bytes -> valid GCM nonce
ANTIREPLAY_NONCE = bytes(range(16))  # 16 bytes -> valid anti-replay nonce
SIG = b"\x30" + b"\x00" * 40  # non-empty stand-in for an ECDSA signature
DIGEST = b"\xab" * 32  # 32 bytes -> valid SHA-256 digest
GENESIS = b"\x00" * 32
PUBKEY = b"\x30\x59" + b"\x11" * 30  # non-empty stand-in for an SPKI public key


def record_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        record_id="rec-1",
        patient_id="pat-1",
        facility_id="fac-a",
        policy_id="pol-1",
        content_type="application/json",
        ciphertext=b"ciphertext-bytes",
        nonce=GCM_NONCE,
        aad=None,
        created_at=_NOW,
    )
    base.update(overrides)
    return base


def dek_wrapping_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        wrapping_id="wrap-1",
        record_id="rec-1",
        wrapped_for="pol-1",
        wrapped_dek=b"sealed-dek",
        nonce=GCM_NONCE,
        generation=0,
        created_at=_NOW,
    )
    base.update(overrides)
    return base


def attribute_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(name="role", value="physician")
    base.update(overrides)
    return base


def leaf_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        node_type="leaf",
        attribute=attribute_kwargs(),
        authority_id="auth-med-council",
    )
    base.update(overrides)
    return base


def transition_event_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        event_id=uuid4(),
        record_id="rec-1",
        from_state="granted",
        to_state="revoked",
        actor_id="auth-med-council",
        reason_code=None,
        issued_at=_NOW,
        nonce=ANTIREPLAY_NONCE,
        signature=SIG,
    )
    base.update(overrides)
    return base


def audit_entry_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        seq=0,
        prev_hash=GENESIS,
        entry_hash=DIGEST,
        event_type="transition",
        event_data={"record_id": "rec-1", "to_state": "revoked"},
        actor_id="audit-svc",
        timestamp=_NOW,
        signature=SIG,
    )
    base.update(overrides)
    return base


def attribute_credential_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        serial="cred-0001",
        issuer_id="auth-med-council",
        subject_id="dr-1",
        attribute=attribute_kwargs(),
        valid_from=_NOW,
        valid_until=_LATER,
        status="active",
        signature=SIG,
    )
    base.update(overrides)
    return base


def facility_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        facility_id="fac-a",
        display_name="Facility A",
        endpoint="http://fac-a.lab.local:8001",
        public_key=PUBKEY,
        status="active",
    )
    base.update(overrides)
    return base


def emergency_assertion_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        assertion_id=uuid4(),
        patient_id="pat-1",
        clinician_id="dr-1",
        facility_id="fac-b",
        reason_code="cardiac_arrest",
        issued_at=_NOW,
        expires_at=_LATER,
        nonce=ANTIREPLAY_NONCE,
        signature=SIG,
    )
    base.update(overrides)
    return base


def request_envelope_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        request_id=uuid4(),
        caller_id="facility-svc-a",
        recipient_id="audit-svc",
        operation="commit_transition",
        body=b"canonical-serialized-body",
        issued_at=_NOW,
        nonce=ANTIREPLAY_NONCE,
        signature=SIG,
    )
    base.update(overrides)
    return base
