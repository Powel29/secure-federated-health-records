"""A real record and a real rotator for the expiry tests (ADR-0069).

The forced rotation at expiry now re-authors the policy and mints a fresh
emergency key, so its tests need a record ingested the real way -- a compiled
policy, an authoring keyring, a sealed term list -- and a rotator that runs
``lifecycle.rotation.plan_rotation`` against them. :class:`PlanRotator` is
that rotator without a store or share holders: it keeps every plan so a test
can check what rotation produced.
"""

from __future__ import annotations

from typing import Any

from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts.clinical import ClinicalMetadata
from contracts.enums import PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core.symmetric import generate_key
from lifecycle.expiry import EmergencySession, ExpiryResult, RotationOutcome
from lifecycle.rotation import RotationPlan, plan_rotation
from policy.engine import unwrap_dek_via_policy
from records.ingest import ingest_record
from records.service import unwrap_dek

PLAINTEXT = b'{"note": "synthetic test record for the expiry rotation"}'
SEARCH_TERMS = ("cardiac", "acute")


def build_rotation_scenario(
    record_id: str,
    *,
    patient_id: str = "pat-001",
    facility_id: str = "fac-001",
    clinical: ClinicalMetadata | None = None,
) -> dict[str, Any]:
    """One ingested record and everything an open emergency session holds.

    Keys kept for the existing tests: ``plaintext``, ``dek``, ``baseline_key``
    (the policy root secret), ``emergency_key``, ``record``,
    ``baseline_wrapping``, ``emergency_wrapping``; plus ``compiled_policy``,
    ``keyring``, ``sealed_search_terms`` and ``shares`` for rotation.
    """
    keyring = {
        ("authority-med", "role", "physician"): generate_key(32),
        ("authority-net", "owner", patient_id): generate_key(32),
    }
    policy = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="role", value="physician"),
        authority_id="authority-med",
    )
    emergency_key = generate_emergency_key()
    ingested = ingest_record(
        plaintext=PLAINTEXT,
        patient_id=patient_id,
        facility_id=facility_id,
        owner_authority_id="authority-net",
        clinical_policy=policy,
        attribute_keyring=keyring,
        search_terms=list(SEARCH_TERMS),
        emergency_key=emergency_key,
        record_id=record_id,
        clinical=clinical,
    )
    assert ingested.emergency_dek_wrapping is not None
    return {
        "plaintext": PLAINTEXT,
        "dek": unwrap_dek(ingested.emergency_dek_wrapping, emergency_key),
        "baseline_key": ingested.root_secret,
        "emergency_key": emergency_key,
        "record": ingested.record,
        "baseline_wrapping": ingested.dek_wrapping,
        "emergency_wrapping": ingested.emergency_dek_wrapping,
        "compiled_policy": ingested.compiled_policy,
        "keyring": keyring,
        "sealed_search_terms": ingested.sealed_search_terms,
        "search_tokens": dict(ingested.search_tokens),
        "shares": split_emergency_key(emergency_key),
    }


class PlanRotator:
    """Runs ``plan_rotation`` for a scenario; keeps each plan it made."""

    def __init__(self, scenario: dict[str, Any]) -> None:
        self.scenario = scenario
        self.plans: list[RotationPlan] = []

    def __call__(self, session: EmergencySession) -> RotationOutcome:
        if session.rotation_plan is None:
            session.rotation_plan = plan_rotation(
                record=session.current_record,
                emergency_wrapping=session.emergency_wrapping,
                emergency_key=session.emergency_key,
                baseline_generation=self.scenario["baseline_wrapping"].generation,
                compiled_policy=self.scenario["compiled_policy"],
                authoring_keyring=self.scenario["keyring"],
                sealed_search_terms=self.scenario["sealed_search_terms"],
            )
        plan: RotationPlan = session.rotation_plan
        self.plans.append(plan)
        return RotationOutcome(
            rotated_record=plan.record,
            baseline_wrapping=plan.baseline_wrapping,
            emergency_wrapping=plan.emergency_wrapping,
        )

    @property
    def last(self) -> RotationPlan:
        return self.plans[-1]


def rotated_dek(scenario: dict[str, Any], result: ExpiryResult) -> bytes:
    """The new DEK, recovered the way a policy reader would: through the
    re-authored policy, with the scenario's attribute keys."""
    rotator: PlanRotator = scenario["rotator"]
    return unwrap_dek_via_policy(
        rotator.last.compiled_policy, scenario["keyring"], result.rotated_wrapping
    )
