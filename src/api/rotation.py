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
   each replacing the previous generation's share. Share 2 is not deposited,
   exactly as at ingest (review F3, D2).

Storing before handing out shares means the old shares are dead the moment
the store commits: they open the replaced emergency wrapping only, which no
longer exists. If a holder is unreachable the expiry is retried and the record
stays closed until both have the new share.

No cryptography here (CONVENTIONS.md §2 rule 10): ``lifecycle.rotation``
computes, this module fetches, stores and delivers.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass

import httpx
from breakglass.emergency_key import Share
from lifecycle.expiry import EmergencySession, RotationOutcome
from lifecycle.rotation import plan_rotation
from policy.engine import policy_leaves, policy_tree_of

from api.repository import StorageRepository

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
        if plan is None:
            compiled = self._repo.get_compiled_policy(record.policy_id)
            if compiled is None:
                raise RotationError(f"compiled policy of {record_id!r} not found")
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
            self._ports.deposit_shares(
                record_id,
                plan.generation,
                plan.share(CLINICIAN_SHARE_X),
                plan.share(AUDIT_SHARE_X),
            )
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


def http_rotation_ports(
    http: httpx.Client,
    *,
    authorities: Mapping[str, str],
    custodian_url: str,
    audit_url: str,
) -> RotationPorts:
    """Rotation ports over signed HTTP (``http`` must sign, ADR-0066).

    URLs come from the facility's configuration (CONVENTIONS.md §2 rule 8).

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
        for url, (x, share) in (
            (f"{custodian_url}/records/{record_id}/shares", clinician_share),
            (f"{audit_url}/breakglass/shares/{record_id}", audit_share),
        ):
            resp = http.put(
                url, json={"x": x, "share_hex": share.hex(), "generation": generation}
            )
            resp.raise_for_status()

    return RotationPorts(author_keys=author_keys, deposit_shares=deposit_shares)
