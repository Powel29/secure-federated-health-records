"""The facility's forced rotation at emergency expiry (ADR-0069, review D3-a).

:class:`FacilityRotator` is what ``create_hospital_app`` attaches to its
``EmergencyExpiryManager``. When a session expires it:

1. fetches an authoring key for every leaf of the record's access tree from
   the owning authority (a signed request, ADR-0066);
2. computes the rotation with ``lifecycle.rotation.plan_rotation`` -- once:
   the plan is kept on the session, so a retry finishes the same rotation;
3. stores it in one transaction (``StorageRepository.apply_rotation``): new
   ciphertext, new policy wrapping and compiled policy, new emergency
   wrapping, new search index and sealed terms;
4. hands the new share 1 to the custodian and share 3 to the audit service,
   each replacing the previous generation's share and sealed to the holder's
   verified share key (ADR-0079). Share 2 is not deposited, exactly as at
   ingest (share 2 reserved, ADR-0074).

Storing before handing out shares means the old shares are dead the moment
the store commits: they open the replaced emergency wrapping only, which no
longer exists. If a holder is unreachable the expiry is retried and the record
stays closed until both have the new share.

The same rotation, planned from the store instead of from a session's
emergency key (:meth:`FacilityRotator.plan_from_store`), serves a patient's
revocation (ADR-0080) and the sessions a restarted facility recovers
(:func:`recover_emergency_sessions`, ADR-0081).

No cryptography here (CONVENTIONS.md §2 rule 10): ``lifecycle.rotation``
computes, this module fetches, stores and delivers.
"""

from __future__ import annotations

import base64
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass

import httpx
from breakglass.emergency_key import Share
from contracts.enums import LifecycleState
from contracts.policy import PolicyTree
from contracts.records import Record
from cryptography.x509 import Certificate
from lifecycle.expiry import EmergencyExpiryManager, EmergencySession, RotationOutcome
from lifecycle.rotation import (
    EMERGENCY_WRAPPED_FOR,
    RotationPlan,
    plan_rotation,
    plan_rotation_via_policy,
)
from policy.engine import CompiledPolicy, policy_leaves, policy_tree_of

from api.repository import StorageRepository
from api.share_transport import fetch_share_recipient, sealed_json

_logger = logging.getLogger(__name__)

AttributeKey = tuple[str, str, str]

# Which share goes where: the same split the custodian makes at ingest.
CLINICIAN_SHARE_X = 1
AUDIT_SHARE_X = 3

_STORED = "stored"
_SHARES = "shares"


class RotationError(RuntimeError):
    """A rotation step could not run; the expiry is retried."""


@dataclass(frozen=True)
class RotationPorts:
    """The two calls a rotation makes outside the facility.

    Attributes:
        author_keys: ``leaves -> {leaf: authoring key}`` from the authorities.
        deposit_shares: ``(record_id, generation, share 1, share 3)`` --
            replace the holders' shares with this generation's.
    """

    author_keys: Callable[[list[AttributeKey]], dict[AttributeKey, bytes]]
    deposit_shares: Callable[[str, int, Share, Share], None]


class FacilityRotator:
    """Runs (or finishes) the forced rotation for one expiring session."""

    def __init__(self, repo: StorageRepository, ports: RotationPorts) -> None:
        self._repo = repo
        self._ports = ports

    def __call__(self, session: EmergencySession) -> RotationOutcome:
        record = session.current_record
        record_id = session.record_id
        plan = session.rotation_plan
        if plan is None and session.recovered:
            # The key died with the process that opened the session
            # (ADR-0081): recover the DEK through the record's policy.
            plan = self.plan_from_store(record_id)
            session.rotation_plan = plan
        if plan is None:
            compiled = self._compiled_policy(record)
            baseline = self._repo.get_wrapping_for_record(
                record_id, wrapped_for=record.policy_id
            )
            keyring = self._ports.author_keys(policy_leaves(policy_tree_of(compiled)))
            plan = plan_rotation(
                record=record,
                emergency_wrapping=session.emergency_wrapping,
                emergency_key=session.emergency_key,
                baseline_generation=baseline.generation if baseline else 0,
                compiled_policy=compiled,
                authoring_keyring=keyring,
                sealed_search_terms=self._repo.get_sealed_search_terms(record_id),
            )
            session.rotation_plan = plan

        if _STORED not in session.rotation_steps:
            self._repo.apply_rotation(plan)
            session.rotation_steps.add(_STORED)
        if _SHARES not in session.rotation_steps:
            self.deposit(plan)
            session.rotation_steps.add(_SHARES)

        outcome = RotationOutcome(
            rotated_record=plan.record,
            baseline_wrapping=plan.baseline_wrapping,
            emergency_wrapping=plan.emergency_wrapping,
        )
        # The shares have reached their holders; drop this copy (best effort,
        # as for the emergency key, ADR-0035).
        session.rotation_plan = None
        return outcome

    def plan_from_store(
        self, record_id: str, new_tree: PolicyTree | None = None
    ) -> RotationPlan:
        """Plan a rotation of the record as stored, with no emergency key.

        For a patient's revocation (``new_tree``, ADR-0080) and for a session
        recovered after a restart (ADR-0081). The DEK is recovered through
        the record's current policy with the authoring keys of its leaves;
        the new policy root is compiled over ``new_tree`` (default: the
        current tree).

        Raises:
            RotationError: The record, its policy or a wrapping is missing.
            httpx.HTTPError: An authority refused or was unreachable.
            PolicyDeniedError, UnwrappingError, DecryptionError: The stored
                artefacts do not open one another.
        """
        record = self._repo.get_record(record_id)
        if record is None:
            raise RotationError(f"record {record_id!r} not found")
        compiled = self._compiled_policy(record)
        baseline = self._repo.get_wrapping_for_record(
            record_id, wrapped_for=record.policy_id
        )
        emergency = self._repo.get_wrapping_for_record(
            record_id, wrapped_for=EMERGENCY_WRAPPED_FOR
        )
        if baseline is None or emergency is None:
            raise RotationError(f"wrappings of {record_id!r} not found")
        leaves = policy_leaves(policy_tree_of(compiled))
        if new_tree is not None:
            leaves += [leaf for leaf in policy_leaves(new_tree) if leaf not in leaves]
        return plan_rotation_via_policy(
            record=record,
            baseline_wrapping=baseline,
            emergency_generation=emergency.generation,
            compiled_policy=compiled,
            authoring_keyring=self._ports.author_keys(leaves),
            sealed_search_terms=self._repo.get_sealed_search_terms(record_id),
            new_tree=new_tree,
        )

    def deposit(self, plan: RotationPlan) -> None:
        """Hand the plan's share 1 to the custodian and share 3 to audit."""
        self._ports.deposit_shares(
            plan.record.record_id,
            plan.generation,
            plan.share(CLINICIAN_SHARE_X),
            plan.share(AUDIT_SHARE_X),
        )

    def _compiled_policy(self, record: Record) -> CompiledPolicy:
        compiled = self._repo.get_compiled_policy(record.policy_id)
        if compiled is None:
            raise RotationError(f"compiled policy of {record.record_id!r} not found")
        return compiled


class RepositorySessionStore:
    """Keeps a facility's open emergency sessions in its store (ADR-0081).

    Identifiers, the return state and times only: never the emergency key.
    """

    def __init__(self, repo: StorageRepository, facility_id: str) -> None:
        self._repo = repo
        self._facility_id = facility_id

    def save(self, session: EmergencySession) -> None:
        self._repo.save_emergency_session(
            {
                "record_id": session.record_id,
                "facility_id": self._facility_id,
                "return_state": session.return_state.value,
                "actor_id": session.actor_id,
                "correlation_id": session.correlation_id,
                "opener_facility_id": session.opener_facility_id,
                "opened_at": session.opened_at,
                "expires_at": session.expires_at,
            }
        )

    def delete(self, record_id: str) -> None:
        self._repo.delete_emergency_session(record_id)


def recover_emergency_sessions(
    repo: StorageRepository, manager: EmergencyExpiryManager, facility_id: str
) -> list[str]:
    """Hand the sessions a previous process left open back to the timer.

    Only this facility's rows (ADR-0081): another facility's sessions are
    its own to finish. A row whose record is no longer open or expiring is
    left over from a finished expiry and is dropped.

    Returns:
        The record ids whose sessions were recovered.
    """
    recovered: list[str] = []
    for row in repo.list_emergency_sessions(facility_id):
        record_id = row["record_id"]
        if manager.has_session(record_id):
            continue
        state = repo.get_lifecycle_state(record_id)
        record = repo.get_record(record_id)
        emergency = repo.get_wrapping_for_record(
            record_id, wrapped_for=EMERGENCY_WRAPPED_FOR
        )
        if (
            state not in (LifecycleState.EMERGENCY_OPEN, LifecycleState.EXPIRED)
            or record is None
            or emergency is None
        ):
            repo.delete_emergency_session(record_id)
            continue
        manager.recover_session(
            record_id=record_id,
            actor_id=row["actor_id"],
            correlation_id=row["correlation_id"],
            opened_at=row["opened_at"],
            return_state=LifecycleState(row["return_state"]),
            emergency_wrapping=emergency,
            current_record=record,
            already_expired=state is LifecycleState.EXPIRED,
        )
        _logger.warning(
            "recovered the emergency session of %s left open by a previous "
            "process; closing it with a rotation",
            record_id,
        )
        recovered.append(record_id)
    return recovered


def http_rotation_ports(
    http: httpx.Client,
    *,
    authorities: Mapping[str, str],
    custodian_url: str,
    audit_url: str,
    trusted_root: Certificate,
) -> RotationPorts:
    """Rotation ports over signed HTTP (``http`` must sign, ADR-0066).

    URLs come from the facility's configuration (CONVENTIONS.md §2 rule 8);
    each holder's share key is verified against ``trusted_root`` before a
    share is sealed to it (ADR-0079).

    Raises (from the returned callables):
        RotationError: A leaf names an authority with no configured URL.
        httpx.HTTPError: A call failed or was refused; the expiry retries.
    """

    def author_keys(leaves: list[AttributeKey]) -> dict[AttributeKey, bytes]:
        keyring: dict[AttributeKey, bytes] = {}
        for authority_id, name, value in leaves:
            url = authorities.get(authority_id)
            if not url:
                raise RotationError(
                    f"policy leaf names unconfigured authority {authority_id!r}"
                )
            resp = http.post(
                f"{url}/attribute-keys/author", json={"name": name, "value": value}
            )
            resp.raise_for_status()
            keyring[(authority_id, name, value)] = base64.b64decode(
                resp.json()["key_b64"], validate=True
            )
        return keyring

    def deposit_shares(
        record_id: str, generation: int, clinician_share: Share, audit_share: Share
    ) -> None:
        for base, kind, path, share in (
            (
                custodian_url,
                "custodian",
                f"/records/{record_id}/shares",
                clinician_share,
            ),
            (audit_url, "audit", f"/breakglass/shares/{record_id}", audit_share),
        ):
            recipient = fetch_share_recipient(
                http, base, kind=kind, trusted_root=trusted_root
            )
            sealed = sealed_json(share, record_id=record_id, recipient=recipient)
            resp = http.put(
                f"{base}{path}", json={"sealed_share": sealed, "generation": generation}
            )
            resp.raise_for_status()

    return RotationPorts(author_keys=author_keys, deposit_shares=deposit_shares)
