"""Constrained enumerations used across the contracts.

Every enum is a closed set on purpose: a field that must not be free text
(a reason code, a lifecycle state, a credential status) is safer as an enum,
because an unrecognised value fails validation at the boundary instead of
propagating an unexpected string into a security decision.
"""

from __future__ import annotations

from enum import Enum


class LifecycleState(str, Enum):
    """The four states of the key-lifecycle state machine (ARCHITECTURE.md §2 C9)."""

    GRANTED = "granted"
    REVOKED = "revoked"
    EMERGENCY_OPEN = "emergency_open"
    EXPIRED = "expired"


class ReasonCode(str, Enum):
    """Why an emergency is being declared. Constrained, never free text (§8).

    Provisional starter set -- the *shape* (a closed enum) is the frozen
    contract; the specific clinical taxonomy needs sign-off and may be revised
    through a ``contract:`` PR without changing any field type.
    """

    CARDIAC_ARREST = "cardiac_arrest"
    RESPIRATORY_FAILURE = "respiratory_failure"
    UNCONSCIOUS_PATIENT = "unconscious_patient"
    MAJOR_TRAUMA = "major_trauma"
    STROKE = "stroke"
    SEVERE_ALLERGIC_REACTION = "severe_allergic_reaction"
    OVERDOSE = "overdose"
    SEPSIS = "sepsis"
    SEIZURE = "seizure"
    OBSTETRIC_EMERGENCY = "obstetric_emergency"
    DIABETIC_KETOACIDOSIS = "diabetic_ketoacidosis"
    HAEMORRHAGE = "haemorrhage"
    OTHER_LIFE_THREATENING = "other_life_threatening"


class CredentialStatus(str, Enum):
    """Status of a clinician/authority credential (ARCHITECTURE.md §8).

    Only ``ACTIVE`` credentials pass validation; expired or revoked ones fail
    closed.
    """

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class FacilityStatus(str, Enum):
    """Participation status of a federation facility node."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


class PolicyNodeType(str, Enum):
    """Kind of node in an access-policy tree (ARCHITECTURE.md §3)."""

    LEAF = "leaf"  # an attribute test
    AND = "and"  # k-of-k Shamir split across children
    OR = "or"  # every child receives the same secret; any one suffices


class ConsentStatus(str, Enum):
    """Outcome of a patient consent decision (ADR-0014 consent model).

    A :class:`~contracts.consent.ConsentGrant` answers a request with exactly one
    of these. ``GRANTED`` is the only status that authorises access; the others
    all fail closed at the policy/enforcement layer. Consent never *decides*
    decryption on its own -- keys and the threshold gate do (ADR-0014) -- it
    records the patient's signed intent that the policy layer then honours.
    """

    GRANTED = "granted"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"
