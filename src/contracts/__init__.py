"""Frozen interface contracts shared across every module (T02).

This is the one package everybody imports and nobody edits casually. After
Phase 0 it is **frozen**: changes require a ``contract:`` PR approved by all four
members and announced before merge (CONVENTIONS.md §3). Import schemas by their
bare names::

    from contracts import Record, EmergencyAssertion, LifecycleState

The eleven schemas
------------------
CONVENTIONS.md §3 and the WORKFLOW build order both name seven schemas (Record,
DEKWrapping, TransitionEvent, AuditEntry, AttributeCredential, Facility,
PolicyTree). The external security review (ARCHITECTURE.md §8) then added two
more -- EmergencyAssertion and RequestEnvelope -- and the T02 task row lists them
explicitly (the "7" in those older references predates the review). ADR-0017
then added two more for the ADR-0014 consent model -- ConsentRequest and
ConsentGrant -- bringing the frozen set to **eleven**. ADR-0017 is a ``contract:``
change and requires all-four approval before merge.

These are typed value objects only. No contract computes cryptography; all
signing, hashing, and encryption happen in the owning modules through
``crypto_core`` (CONVENTIONS.md §2 rule 1). ``bytes`` fields carry opaque crypto
material and serialize to base64 in JSON.
"""

from __future__ import annotations

from contracts.audit import AuditEntry
from contracts.base import Attribute, ContractModel
from contracts.consent import ConsentGrant, ConsentRequest
from contracts.credentials import AttributeCredential, Facility
from contracts.enums import (
    ConsentStatus,
    CredentialStatus,
    FacilityStatus,
    LifecycleState,
    PolicyNodeType,
    ReasonCode,
)
from contracts.lifecycle import TransitionEvent
from contracts.messaging import EmergencyAssertion, RequestEnvelope
from contracts.policy import PolicyTree
from contracts.records import DEKWrapping, Record

__all__ = [
    # the eleven frozen schemas
    "Record",
    "DEKWrapping",
    "PolicyTree",
    "TransitionEvent",
    "AuditEntry",
    "AttributeCredential",
    "Facility",
    "EmergencyAssertion",
    "RequestEnvelope",
    "ConsentRequest",
    "ConsentGrant",
    # shared value object + base
    "Attribute",
    "ContractModel",
    # enums
    "LifecycleState",
    "ReasonCode",
    "CredentialStatus",
    "FacilityStatus",
    "PolicyNodeType",
    "ConsentStatus",
]
