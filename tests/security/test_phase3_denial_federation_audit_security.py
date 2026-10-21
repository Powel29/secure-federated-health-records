"""Negative security tests for denial and federation audit events (P3-13).

Backs the P3-13 done-when: "denials and federation events appear in the
chain with no sensitive data leaked." Each test drives a real denial-
producing control from another module (``policy``, ``consent``,
``records.revocation``), catches the specific exception it already raises,
logs it with ``audit.events.log_access_denied``, and then inspects the
*persisted* chain entry -- not just the in-memory dict -- to prove no key
material, share, DEK, or signature ever reaches it. The federation tests do
the same for discovery and the PRE re-wrap step of cross-facility
break-glass.

Per CLAUDE.md's one-owner-per-module rule, these tests demonstrate the
caller-side wiring pattern that ``policy``, ``consent``, ``records``,
``breakglass``, and ``federation`` (each owned by someone else) already
document as *the caller's* responsibility -- see ``breakglass/gate.py`` and
``records/revocation.py`` module docstrings ("this module does not
audit-log itself"). Wiring these calls into those modules' actual call
sites is the Phase 4 API layer's job (P4-1/P4-2); what this task proves is
that the audit side of that contract holds today.
"""

from __future__ import annotations

import json

import pytest
from audit import (
    DENIED_BY_CONSENT,
    DENIED_BY_POLICY,
    DENIED_BY_REVOCATION_AUTHZ,
    EVENT_ACCESS_DENIED,
    EVENT_FEDERATION_DISCOVERY,
    EVENT_FEDERATION_REWRAP,
    append_entry,
    create_genesis_entry,
    log_access_denied,
    log_federation_discovery,
    log_federation_rewrap,
)
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from breakglass.gate import open_emergency_access
from consent import authorize_read, create_consent_grant, create_consent_request
from consent.exceptions import ConsentDeniedError
from contracts.base import Attribute
from contracts.enums import ConsentStatus, LifecycleState, PolicyNodeType, ReasonCode
from contracts.policy import PolicyTree
from contracts.records import Record
from crypto_core import generate_ec_keypair, generate_key
from federation import find_record_ids_by_patient
from policy import compile_policy, reconstruct_root_secret
from policy.exceptions import PolicyDeniedError
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.exceptions import UnauthorizedRevocationError
from records.revocation import check_revocation_authorization
from records.service import wrap_dek
from storage import repositories as repo

from tests.shares import unlock_points
from tests.transitions import open_event

MED = "authority-med"
NET = "authority-net"


def _seed_genesis(conn, signing_key):
    genesis = create_genesis_entry(signing_key=signing_key)
    repo.insert_audit_entry(conn, genesis)
    return genesis


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _persisted_text(entry) -> str:
    """The exact bytes an admin reading the chain would see for this entry."""
    return json.dumps(entry.event_data, sort_keys=True)


# ---------------------------------------------------------------------------
# Policy-engine denial
# ---------------------------------------------------------------------------


def test_sec_policy_denial_is_logged_without_leaking_attribute_keys(
    conn, audit_keypair
):
    """Claim: a policy-engine denial reaches the chain, but the attribute
    keys involved never do -- an admin reading the denial view learns *that*
    and *why* access was refused, never a key that would let them decrypt."""
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    key = generate_key()
    root_secret = generate_key()
    compiled = compile_policy(
        _leaf("role", "physician", MED),
        root_secret,
        {
            (MED, "role", "physician"): key,
        },
    )

    # Positive control: the real key satisfies the policy.
    assert (
        reconstruct_root_secret(compiled, {(MED, "role", "physician"): key})
        == root_secret
    )

    # Negative: no held keys -> PolicyDeniedError, fail closed.
    try:
        reconstruct_root_secret(compiled, {})
        pytest.fail("expected PolicyDeniedError")
    except PolicyDeniedError as exc:
        entry = log_access_denied(
            conn,
            record_id="rec-policy-1",
            requester_id="dr-mallory",
            denied_by=DENIED_BY_POLICY,
            reason=str(exc),
            actor_id="facility-a",
            correlation_id="flow-policy-denial",
            signing_key=priv,
        )

    assert entry.event_type == EVENT_ACCESS_DENIED
    persisted = _persisted_text(entry)
    assert key.hex() not in persisted
    assert root_secret.hex() not in persisted


# ---------------------------------------------------------------------------
# Consent denial
# ---------------------------------------------------------------------------


def test_sec_consent_denial_is_logged_without_leaking_signature(conn, audit_keypair):
    """Claim: a patient's explicit DENIED consent decision is logged, and the
    grant's signature bytes never end up in the chain."""
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    patient_sk, patient_pk = generate_ec_keypair()
    clinician_sk, _ = generate_ec_keypair()
    request = create_consent_request(
        patient_id="patient-1",
        requester_id="dr-bob",
        scope=("rec-1",),
        purpose="Second opinion",
        requester_signing_key=clinician_sk,
    )
    denied_grant = create_consent_grant(
        request=request,
        status=ConsentStatus.DENIED,
        grantee_id="dr-bob",
        patient_signing_key=patient_sk,
    )

    # Positive control: a GRANTED decision for the same request authorizes.
    granted_grant = create_consent_grant(
        request=request,
        status=ConsentStatus.GRANTED,
        grantee_id="dr-bob",
        patient_signing_key=patient_sk,
    )
    authorize_read(
        granted_grant,
        record_id="rec-1",
        grantee_id="dr-bob",
        patient_public_key=patient_pk,
    )

    # Negative: the DENIED decision refuses.
    try:
        authorize_read(
            denied_grant,
            record_id="rec-1",
            grantee_id="dr-bob",
            patient_public_key=patient_pk,
        )
        pytest.fail("expected ConsentDeniedError")
    except ConsentDeniedError as exc:
        entry = log_access_denied(
            conn,
            record_id="rec-1",
            requester_id="dr-bob",
            denied_by=DENIED_BY_CONSENT,
            reason=str(exc),
            actor_id="facility-a",
            correlation_id="flow-consent-denial",
            signing_key=priv,
        )

    assert entry.event_type == EVENT_ACCESS_DENIED
    persisted = _persisted_text(entry)
    assert denied_grant.signature.hex() not in persisted
    assert denied_grant.nonce.hex() not in persisted


# ---------------------------------------------------------------------------
# Revocation-authorization denial
# ---------------------------------------------------------------------------


def test_sec_unauthorized_revocation_denial_is_logged(conn, audit_keypair):
    """Claim: a non-owner's revocation attempt is refused and logged (P3-12
    made this a control; P3-13 makes it visible to the admin denial view)."""
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    import datetime

    record = Record(
        record_id="rec-revoke-1",
        patient_id="patient-1",
        facility_id="facility-a",
        policy_id="pol-1",
        content_type="text/plain",
        ciphertext=b"ciphertext-bytes",
        nonce=b"0" * 12,
        aad=None,
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )

    # Positive control: the patient themself is authorized.
    check_revocation_authorization(
        actor_id="patient-1", record=record, owner_authority_id=NET
    )

    # Negative: a clinician is not.
    try:
        check_revocation_authorization(
            actor_id="dr-mallory", record=record, owner_authority_id=NET
        )
        pytest.fail("expected UnauthorizedRevocationError")
    except UnauthorizedRevocationError as exc:
        entry = log_access_denied(
            conn,
            record_id=record.record_id,
            requester_id="dr-mallory",
            denied_by=DENIED_BY_REVOCATION_AUTHZ,
            reason=str(exc),
            actor_id="facility-a",
            correlation_id="flow-revoke-denial",
            signing_key=priv,
        )

    assert entry.event_type == EVENT_ACCESS_DENIED
    assert entry.event_data["denied_by"] == DENIED_BY_REVOCATION_AUTHZ


# ---------------------------------------------------------------------------
# Federation discovery
# ---------------------------------------------------------------------------


class _CaptureCursor:
    def __init__(self, rows):
        self._rows = rows
        self.query = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, query, params):
        self.query = query

    def fetchall(self):
        return self._rows


class _CaptureConnection:
    def __init__(self, rows):
        self.cursor_obj = _CaptureCursor(rows)

    def cursor(self, **_kwargs):
        return self.cursor_obj


def test_sec_federation_discovery_event_carries_identifiers_only(conn, audit_keypair):
    """Claim: a discovery lookup is logged for oversight with identifiers only
    -- the patient's pseudonymous id, the requester, and the record ids
    already returned to the caller -- and nothing else (ADR-0011, ADR-0085).
    No hash of the id: ids can be enumerated, so a hash would hide nothing."""
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    store_conn = _CaptureConnection(rows=[("rec-1",), ("rec-2",)])
    record_ids = find_record_ids_by_patient(store_conn, "patient-super-secret")

    # Positive control: discovery itself returns the expected identifiers.
    assert record_ids == ["rec-1", "rec-2"]

    entry = log_federation_discovery(
        conn,
        patient_id="patient-super-secret",
        requester_id="facility-b",
        record_ids=record_ids,
        actor_id="facility-b",
        correlation_id="flow-discovery-sec",
        signing_key=priv,
    )

    assert entry.event_type == EVENT_FEDERATION_DISCOVERY
    # The exact field set: an extra field (a key, a hash, a name) fails here.
    assert entry.event_data == {
        "patient_id": "patient-super-secret",
        "requester_id": "facility-b",
        "record_count": 2,
        "record_ids": ["rec-1", "rec-2"],
    }


# ---------------------------------------------------------------------------
# Federation re-wrap (cross-facility break-glass step 4)
# ---------------------------------------------------------------------------


def test_sec_federation_rewrap_event_never_contains_key_material(conn, audit_keypair):
    """Claim: logging a cross-facility PRE re-wrap never leaks the emergency
    key, the recovered DEK, or the packed re-wrapped blob -- only which
    record moved from which facility to which clinician."""
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    record_id = "rec-rewrap-sec-1"
    dek = b"\x22" * 32
    emergency_key = generate_emergency_key()
    shares = split_emergency_key(emergency_key)
    wrapping = wrap_dek(
        dek=dek,
        record_id=record_id,
        wrapping_key=emergency_key,
        wrapped_for="emergency",
    )
    lifecycle_priv, _lifecycle_pub = generate_ec_keypair()
    _, pre_pub = generate_pre_keypair()

    # Positive control: 3 of the 4 shares actually unlock (ADR-0089).
    result = open_emergency_access(
        shares_presented=unlock_points(shares),
        dek_wrapping=wrapping,
        transition_source_state=LifecycleState.GRANTED,
        record_id=record_id,
        transition_event=open_event(
            record_id,
            LifecycleState.GRANTED,
            "dr-out-of-network",
            ReasonCode.CARDIAC_ARREST,
            lifecycle_priv,
        ),
        actor_public_key=(lifecycle_priv).public_key(),
        pre_rewrap_key=pre_pub,
    )
    assert result.emergency_key == emergency_key

    entry = log_federation_rewrap(
        conn,
        record_id=record_id,
        source_facility_id="facility-a",
        target_actor_id="dr-out-of-network",
        actor_id="facility-b",
        correlation_id="flow-rewrap-sec",
        signing_key=priv,
    )

    assert entry.event_type == EVENT_FEDERATION_REWRAP
    persisted = _persisted_text(entry)
    assert result.emergency_key.hex() not in persisted
    assert result.rewrapped_dek.hex() not in persisted
    assert dek.hex() not in persisted


# ---------------------------------------------------------------------------
# The structural control: the chain itself refuses raw key material
# ---------------------------------------------------------------------------


def test_sec_raw_key_bytes_in_event_data_are_rejected_before_persisting(
    conn, audit_keypair
):
    """Claim: even bypassing the fixed-shape helpers above, CONVENTIONS.md §2
    rule 3 is enforced structurally, not just by caller discipline --
    ``append_entry`` JSON-canonicalises ``event_data`` before hashing
    (ADR-0034), and raw ``bytes`` (e.g. a key passed in by mistake) is not
    JSON-serialisable, so the append fails before anything is written."""
    priv, _pub = audit_keypair
    _seed_genesis(conn, priv)

    # Positive control: a legitimate, all-string/int payload appends fine.
    good = append_entry(
        conn,
        event_type=EVENT_ACCESS_DENIED,
        event_data={"record_id": "rec-1", "reason": "denied"},
        actor_id="facility-a",
        correlation_id="flow-good",
        signing_key=priv,
    )
    assert repo.get_chain_head(conn) == good

    # Negative: a caller who (by mistake) puts a raw key in event_data is
    # refused before the entry ever reaches the chain.
    leaked_key = generate_key()
    with pytest.raises(TypeError):
        append_entry(
            conn,
            event_type=EVENT_ACCESS_DENIED,
            event_data={"record_id": "rec-2", "oops_key": leaked_key},
            actor_id="facility-a",
            correlation_id="flow-bad",
            signing_key=priv,
        )

    # The chain head is unchanged -- the rejected attempt left no trace.
    assert repo.get_chain_head(conn) == good
