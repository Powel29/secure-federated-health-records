"""Per-schema structural validators, each proven to fail closed.

These are the negative tests: for every structural invariant a contract enforces,
a case that violates it must raise, not construct. A validator without a test
that proves it rejects is not evidence of anything.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from contracts import (
    AttributeCredential,
    AuditEntry,
    ConsentGrant,
    ConsentRequest,
    DEKWrapping,
    EmergencyAssertion,
    Facility,
    PolicyTree,
    Record,
    RequestEnvelope,
    TransitionEvent,
)
from pydantic import ValidationError

from .conftest import (
    attribute_credential_kwargs,
    audit_entry_kwargs,
    consent_grant_kwargs,
    consent_request_kwargs,
    dek_wrapping_kwargs,
    emergency_assertion_kwargs,
    facility_kwargs,
    leaf_kwargs,
    record_kwargs,
    request_envelope_kwargs,
    transition_event_kwargs,
)

# --- GCM nonce length (Record, DEKWrapping) ---------------------------------


@pytest.mark.parametrize("bad_len", [0, 8, 11, 13, 16])
def test_record_rejects_non_gcm_nonce(bad_len: int) -> None:
    with pytest.raises(ValidationError):
        Record(**record_kwargs(nonce=b"\x00" * bad_len))


def test_dek_wrapping_rejects_non_gcm_nonce() -> None:
    with pytest.raises(ValidationError):
        DEKWrapping(**dek_wrapping_kwargs(nonce=b"\x00" * 8))


def test_dek_wrapping_rejects_negative_generation() -> None:
    with pytest.raises(ValidationError):
        DEKWrapping(**dek_wrapping_kwargs(generation=-1))


# --- Anti-replay nonce length (assertion, envelope, transition) -------------


@pytest.mark.parametrize(
    "model, factory",
    [
        (EmergencyAssertion, emergency_assertion_kwargs),
        (RequestEnvelope, request_envelope_kwargs),
        (TransitionEvent, transition_event_kwargs),
        (ConsentRequest, consent_request_kwargs),
        (ConsentGrant, consent_grant_kwargs),
    ],
)
def test_short_antireplay_nonce_rejected(model, factory) -> None:
    with pytest.raises(ValidationError):
        model(**factory(nonce=b"\x00" * 15))


# --- Empty signatures fail closed everywhere they appear --------------------


@pytest.mark.parametrize(
    "model, factory",
    [
        (TransitionEvent, transition_event_kwargs),
        (AuditEntry, audit_entry_kwargs),
        (AttributeCredential, attribute_credential_kwargs),
        (EmergencyAssertion, emergency_assertion_kwargs),
        (RequestEnvelope, request_envelope_kwargs),
        (ConsentRequest, consent_request_kwargs),
        (ConsentGrant, consent_grant_kwargs),
    ],
)
def test_empty_signature_rejected(model, factory) -> None:
    with pytest.raises(ValidationError):
        model(**factory(signature=b""))


# --- Audit chain hash lengths -----------------------------------------------


@pytest.mark.parametrize("field", ["prev_hash", "entry_hash"])
@pytest.mark.parametrize("bad_len", [0, 16, 31, 33, 64])
def test_audit_entry_rejects_wrong_hash_length(field: str, bad_len: int) -> None:
    with pytest.raises(ValidationError):
        AuditEntry(**audit_entry_kwargs(**{field: b"\x00" * bad_len}))


def test_audit_entry_rejects_negative_seq() -> None:
    with pytest.raises(ValidationError):
        AuditEntry(**audit_entry_kwargs(seq=-1))


# --- Time-window ordering ----------------------------------------------------


def test_emergency_assertion_rejects_expiry_before_issue() -> None:
    kw = emergency_assertion_kwargs()
    with pytest.raises(ValidationError):
        EmergencyAssertion(**{**kw, "expires_at": kw["issued_at"]})


def test_credential_rejects_validity_window_not_ordered() -> None:
    kw = attribute_credential_kwargs()
    with pytest.raises(ValidationError):
        AttributeCredential(
            **{**kw, "valid_until": kw["valid_from"] - timedelta(seconds=1)}
        )


# --- Timezone-aware timestamps only -----------------------------------------


def test_naive_datetime_rejected() -> None:
    """A naive timestamp in a signed struct is ambiguous; reject it (AwareDatetime)."""
    from datetime import datetime

    naive = datetime(2026, 8, 12, 12, 0, 0)  # noqa: DTZ001 -- deliberately naive
    with pytest.raises(ValidationError):
        Record(**record_kwargs(created_at=naive))


# --- Constrained enums -------------------------------------------------------


def test_reason_code_rejects_free_text() -> None:
    """reason_code is a closed enum, never free text (§8)."""
    with pytest.raises(ValidationError):
        EmergencyAssertion(**emergency_assertion_kwargs(reason_code="because"))


def test_lifecycle_state_rejects_unknown() -> None:
    with pytest.raises(ValidationError):
        TransitionEvent(**transition_event_kwargs(to_state="halfway"))


# --- Empty identifiers -------------------------------------------------------


def test_empty_identifier_rejected() -> None:
    with pytest.raises(ValidationError):
        Record(**record_kwargs(patient_id=""))


def test_facility_rejects_empty_public_key() -> None:
    with pytest.raises(ValidationError):
        Facility(**facility_kwargs(public_key=b""))


# --- Policy tree well-formedness (ARCHITECTURE.md §3) ------------------------


def test_policy_leaf_constructs() -> None:
    tree = PolicyTree(**leaf_kwargs())
    assert tree.attribute is not None


def test_policy_and_or_tree_constructs() -> None:
    tree = PolicyTree(
        node_type="or",
        children=(
            PolicyTree(**leaf_kwargs()),
            PolicyTree(
                node_type="and",
                children=(
                    PolicyTree(**leaf_kwargs()),
                    PolicyTree(
                        **leaf_kwargs(
                            attribute={"name": "specialty", "value": "cardiology"}
                        )
                    ),
                ),
            ),
        ),
    )
    assert tree.node_type.value == "or"


def test_leaf_with_children_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyTree(**leaf_kwargs(children=(PolicyTree(**leaf_kwargs()),)))


def test_leaf_without_attribute_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyTree(node_type="leaf", authority_id="auth-1")


def test_internal_node_with_attribute_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyTree(
            node_type="and",
            attribute={"name": "role", "value": "physician"},
            children=(PolicyTree(**leaf_kwargs()), PolicyTree(**leaf_kwargs())),
        )


def test_internal_node_with_one_child_rejected() -> None:
    """A boolean node with a single child is degenerate; require >= 2."""
    with pytest.raises(ValidationError):
        PolicyTree(node_type="and", children=(PolicyTree(**leaf_kwargs()),))


# --- Audit correlation id (ADR-0014) ----------------------------------------


def test_audit_entry_requires_correlation_id() -> None:
    """Every audit entry must be correlatable end to end (ADR-0014)."""
    kw = audit_entry_kwargs()
    kw.pop("correlation_id")
    with pytest.raises(ValidationError):
        AuditEntry(**kw)


def test_audit_entry_rejects_empty_correlation_id() -> None:
    with pytest.raises(ValidationError):
        AuditEntry(**audit_entry_kwargs(correlation_id=""))


# --- Consent scope, purpose, and expiry (ADR-0014, ADR-0017) ----------------


@pytest.mark.parametrize(
    "model, factory",
    [
        (ConsentRequest, consent_request_kwargs),
        (ConsentGrant, consent_grant_kwargs),
    ],
)
def test_consent_rejects_empty_scope(model, factory) -> None:
    """Consent must name what it covers; an empty scope fails closed."""
    with pytest.raises(ValidationError):
        model(**factory(scope=()))


def test_consent_request_rejects_blank_purpose() -> None:
    with pytest.raises(ValidationError):
        ConsentRequest(**consent_request_kwargs(purpose="   "))


def test_consent_request_rejects_expiry_before_request() -> None:
    kw = consent_request_kwargs()
    with pytest.raises(ValidationError):
        ConsentRequest(**{**kw, "expires_at": kw["requested_at"]})


def test_consent_grant_rejects_expiry_before_decision() -> None:
    kw = consent_grant_kwargs()
    with pytest.raises(ValidationError):
        ConsentGrant(**{**kw, "expires_at": kw["decided_at"]})


def test_consent_grant_rejects_unknown_status() -> None:
    """status is a closed enum (ConsentStatus), never free text."""
    with pytest.raises(ValidationError):
        ConsentGrant(**consent_grant_kwargs(status="approved"))


def test_consent_grant_denied_is_valid() -> None:
    """A denial is a first-class, well-formed decision, not an error."""
    assert ConsentGrant(**consent_grant_kwargs(status="denied"))
