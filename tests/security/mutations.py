"""P5-1 mutation check: switch each control off and watch its tests go red.

A negative test that has never been seen failing is not known to work
(negative-security-test skill). Each mutation below disables one control at
its point of use -- by monkeypatching at pytest start-up, never by editing
source -- and the runner re-runs every non-xfail test tagged with that claim.
A test passes the check if at least one of its claim's mutations turns it
red; a test that stays green under all of them is decorative.

    python -m tests.security.mutations            # all claims
    python -m tests.security.mutations C3 C8      # selected claims

Tests that need Postgres report ``skipped`` without ``DATABASE_URL``; run the
check with it set (as CI does) to cover them.

Also a pytest plugin: ``-p tests.security.mutations`` with
``P51_MUTATION=<mutation id>`` applies one mutation for the whole run.
"""

from __future__ import annotations

import dataclasses
import importlib
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from tests.security.claims import REPO_ROOT, collect

_monkeypatch: pytest.MonkeyPatch | None = None


def _swap(mp: pytest.MonkeyPatch, module: str, name: str, new: object) -> None:
    """Replace ``module.name`` and every already-imported binding of it.

    ``from x import f`` copies the reference, so patching ``x.f`` alone misses
    re-exports (``audit.verify_chain``) and callers imported earlier.
    """
    original = getattr(importlib.import_module(module), name)
    for mod in list(sys.modules.values()):
        if mod is not None and getattr(mod, name, None) is original:
            mp.setattr(mod, name, new)


@dataclass(frozen=True)
class Mutation:
    id: str
    control: str
    apply: Callable[[pytest.MonkeyPatch], None]


# --- C1 ----------------------------------------------------------------------


def _keep_revoked_party(mp: pytest.MonkeyPatch) -> None:
    import policy.engine
    from contracts.enums import PolicyNodeType
    from contracts.policy import Attribute, PolicyTree

    real = policy.engine.author_policy_with_owner

    def leaky(*args, **kwargs):
        physician = PolicyTree(
            node_type=PolicyNodeType.LEAF,
            attribute=Attribute(name="role", value="physician"),
            authority_id="authority-med",
        )
        return PolicyTree(
            node_type=PolicyNodeType.OR, children=(real(*args, **kwargs), physician)
        )

    _swap(mp, "policy.engine", "author_policy_with_owner", leaky)


def _no_reencryption(mp: pytest.MonkeyPatch) -> None:
    import records.revocation

    real = records.revocation.revoke_record_access

    def stale(*args, **kwargs):
        result = real(*args, **kwargs)
        return dataclasses.replace(result, rotated_record=kwargs["current_record"])

    _swap(mp, "records.revocation", "revoke_record_access", stale)


# --- C2 ----------------------------------------------------------------------


def _release_without_commit(mp: pytest.MonkeyPatch) -> None:
    import audit.share_custody
    from audit.exceptions import AuditCommitFailedError

    real = audit.share_custody.release_share_after_commit

    def careless(*args, **kwargs):
        try:
            return real(*args, **kwargs)
        except AuditCommitFailedError:
            return kwargs["share"], None

    _swap(mp, "audit.share_custody", "release_share_after_commit", careless)


# --- C3 / C4 -----------------------------------------------------------------


def _threshold_one(mp: pytest.MonkeyPatch) -> None:
    import breakglass.gate

    mp.setattr(breakglass.gate, "THRESHOLD", 1)


def _audit_skips_assertion_checks(mp: pytest.MonkeyPatch) -> None:
    """The audit service releases share 3 without validating the assertion."""
    import api.audit_service
    from api.hospital import FacilityTrust

    mp.setattr(api.audit_service, "validate_emergency_assertion", lambda **k: None)
    mp.setattr(api.audit_service, "validate_clinical_context", lambda *a: None)
    mp.setattr(
        FacilityTrust,
        "issuing_ca",
        lambda self, leaf: next(iter(self.facility_cas.items()), None),
    )


def _expiry_does_not_rotate(mp: pytest.MonkeyPatch) -> None:
    """Expiry re-baselines without replacing any key (the pre-ADR-0069 state)."""
    import api.rotation
    from lifecycle.expiry import RotationOutcome

    def nothing(self, session):
        return RotationOutcome(
            rotated_record=session.current_record,
            baseline_wrapping=session.emergency_wrapping,
            emergency_wrapping=session.emergency_wrapping,
        )

    mp.setattr(api.rotation.FacilityRotator, "__call__", nothing)


def _key_outlives_session(mp: pytest.MonkeyPatch) -> None:
    from lifecycle.expiry import EmergencyExpiryManager

    remembered: dict[str, bytes] = {}
    real_register = EmergencyExpiryManager.register_session
    real_get = EmergencyExpiryManager.get_active_emergency_key

    def register(self, *args, **kwargs):
        remembered[kwargs["record_id"]] = kwargs["emergency_key"]
        return real_register(self, *args, **kwargs)

    def get(self, record_id):
        session = self._sessions.get(record_id)
        if session is not None:
            return session.emergency_key
        if record_id in remembered:
            return remembered[record_id]
        return real_get(self, record_id)

    mp.setattr(EmergencyExpiryManager, "register_session", register)
    mp.setattr(EmergencyExpiryManager, "get_active_emergency_key", get)


# --- C5 ----------------------------------------------------------------------


def _skip_entry_signature(mp: pytest.MonkeyPatch) -> None:
    import audit.chain

    mp.setattr(audit.chain, "verify", lambda *a, **k: None)


def _signatures_only(mp: pytest.MonkeyPatch) -> None:
    """verify_chain checks each signature but not the prev_hash/seq links."""
    import audit.chain

    def lenient(entries, public_key):
        for entry in entries:
            payload = audit.chain._entry_signing_payload(
                seq=entry.seq,
                prev_hash=entry.prev_hash,
                entry_hash=entry.entry_hash,
                event_type=entry.event_type,
                event_data=entry.event_data,
                actor_id=entry.actor_id,
                correlation_id=entry.correlation_id,
                timestamp=entry.timestamp,
            )
            audit.chain.verify(public_key, payload, entry.signature)
        return entries[-1]

    _swap(mp, "audit.chain", "verify_chain", lenient)


# --- C6 / C7 / C8 / C10 ------------------------------------------------------


def _skip_transition_rules(mp: pytest.MonkeyPatch) -> None:
    import lifecycle.state_machine

    mp.setattr(lifecycle.state_machine, "validate_transition", lambda *a, **k: None)


def _state_writes_unchecked(mp: pytest.MonkeyPatch) -> None:
    """The store's compare-and-set overwrites whatever state it finds (N1)."""
    from api.repository import InMemoryStorageRepository

    def overwrite(self, record_id, expected, new, last_event_id=None):
        self.upsert_lifecycle_state(record_id, new, last_event_id)

    mp.setattr(InMemoryStorageRepository, "transition_lifecycle_state", overwrite)


def _skip_transition_signature(mp: pytest.MonkeyPatch) -> None:
    import lifecycle.state_machine

    mp.setattr(lifecycle.state_machine, "verify", lambda *a, **k: None)


def _any_caller_is_bootstrap(mp: pytest.MonkeyPatch) -> None:
    """Service authentication waves every request through as bootstrap."""
    import api.service_auth

    caller = api.service_auth.CallerIdentity("bootstrap", "bootstrap")
    mp.setattr(api.service_auth, "authenticate_request", lambda *a, **k: caller)


def _read_loads_before_checking(mp: pytest.MonkeyPatch) -> None:
    """read_record touches the store before refusing a keyless requester."""
    import api.hospital

    mp.setattr(api.hospital, "_presents_no_key", lambda payload: False)


def _forget_consumed_ids(mp: pytest.MonkeyPatch) -> None:
    from breakglass.replay import ConsumedAssertionIds

    mp.setattr(ConsumedAssertionIds, "consume", lambda self, item_id: None)


def _skip_credential_checks(mp: pytest.MonkeyPatch) -> None:
    _swap(mp, "authority.issuance", "verify_credential", lambda *a, **k: None)


MUTATIONS: dict[str, list[Mutation]] = {
    "C1": [
        Mutation("C1a", "new tree still admits the revoked party", _keep_revoked_party),
        Mutation("C1b", "rotation does not re-encrypt the record", _no_reencryption),
    ],
    "C2": [
        Mutation(
            "C2a", "share released despite a failed commit", _release_without_commit
        )
    ],
    "C3": [
        Mutation("C3a", "gate threshold lowered to one share", _threshold_one),
        Mutation(
            "C3b",
            "audit service releases without validating the assertion",
            _audit_skips_assertion_checks,
        ),
    ],
    "C4": [
        Mutation("C4a", "emergency key outlives its session", _key_outlives_session),
        Mutation(
            "C4b", "expiry re-baselines without rotating", _expiry_does_not_rotate
        ),
    ],
    "C5": [
        Mutation("C5a", "entry signatures not checked", _skip_entry_signature),
        Mutation("C5b", "prev_hash/seq links not checked", _signatures_only),
    ],
    "C6": [
        Mutation("C6a", "LEGAL_TRANSITIONS not enforced", _skip_transition_rules),
        Mutation(
            "C6b",
            "state compare-and-set overwrites any state",
            _state_writes_unchecked,
        ),
    ],
    "C7": [
        Mutation("C7a", "transition signature not checked", _skip_transition_signature)
    ],
    "C8": [Mutation("C8a", "consumed assertion ids forgotten", _forget_consumed_ids)],
    "C9": [
        Mutation(
            "C9a", "service authentication lets any caller in", _any_caller_is_bootstrap
        ),
        Mutation(
            "C9b",
            "read loads the record before the key check",
            _read_loads_before_checking,
        ),
    ],
    "C10": [Mutation("C10a", "credential validation skipped", _skip_credential_checks)],
}
_BY_ID = {m.id: m for group in MUTATIONS.values() for m in group}

# C11's control is the absence of key material -- there is no switch to flip;
# its tests carry a positive control (the owner key does open the record).
NOT_MUTATED = {
    "C11": "control is the absence of the owner key; covered by a positive control",
}


# --- pytest plugin hooks ------------------------------------------------------


# Printed when a mutation cannot be applied (e.g. its target was renamed),
# so the runner reports an error instead of counting the crash as "caught".
APPLY_FAILED = "P51_MUTATION_APPLY_FAILED"


def pytest_configure(config: pytest.Config) -> None:
    global _monkeypatch
    mutation_id = os.environ.get("P51_MUTATION")
    if mutation_id:
        _monkeypatch = pytest.MonkeyPatch()
        try:
            _BY_ID[mutation_id].apply(_monkeypatch)
        except Exception as exc:
            print(f"{APPLY_FAILED}: {mutation_id}: {exc!r}", file=sys.stderr)
            raise pytest.UsageError(f"mutation {mutation_id} did not apply") from exc


def pytest_unconfigure(config: pytest.Config) -> None:
    if _monkeypatch is not None:
        _monkeypatch.undo()


# --- runner -------------------------------------------------------------------


def _run(nodeid: str, mutation_id: str | None) -> str:
    env = dict(os.environ)
    env.pop("P51_MUTATION", None)
    if mutation_id:
        env["P51_MUTATION"] = mutation_id
    proc = subprocess.run(
        [  # noqa: S603 -- fixed argv, this interpreter
            sys.executable,
            "-m",
            "pytest",
            nodeid,
            "-p",
            "no:cacheprovider",
            "-p",
            "tests.security.mutations",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return _classify(proc)


def _classify(proc: subprocess.CompletedProcess) -> str:
    """Only "tests failed" (exit 1) counts as caught (review N7).

    Exit 2-5 is an interruption, internal error, usage error or no tests --
    none of which shows the control mattered.
    """
    if APPLY_FAILED in proc.stdout + proc.stderr:
        return "ERROR (mutation did not apply)"
    if proc.returncode == 0:
        return "skipped" if "SKIPPED" in proc.stdout else "green"
    if proc.returncode == 1:
        return "red"
    return f"ERROR (pytest exit {proc.returncode})"


def main(argv: list[str] | None = None) -> int:
    wanted = (argv if argv is not None else sys.argv[1:]) or list(MUTATIONS)
    tests = [t for t in collect() if t.xfail_reason is None]
    print("| Claim | Test | Baseline | Mutations (red = caught) |")
    print("|---|---|---|---|")
    decorative = []
    errors = []
    for claim in wanted:
        if claim in NOT_MUTATED:
            print(f"| {claim} | n/a: {NOT_MUTATED[claim]} | | |")
            continue
        for test in (t for t in tests if t.claim == claim):
            base = _run(test.nodeid, None)
            if base != "green":
                # A test that is not green unmutated cannot show anything
                # about a mutation (review N7).
                print(f"| {claim} | `{test.nodeid}` | {base} | not run |")
                if base != "skipped":
                    errors.append(f"{test.nodeid}: baseline {base}")
                continue
            results = {m.id: _run(test.nodeid, m.id) for m in MUTATIONS[claim]}
            cells = ", ".join(f"{mid}: {r}" for mid, r in results.items())
            print(f"| {claim} | `{test.nodeid}` | {base} | {cells} |")
            errors += [
                f"{test.nodeid} under {mid}: {r}"
                for mid, r in results.items()
                if r.startswith("ERROR")
            ]
            if "red" not in results.values():
                decorative.append(test.nodeid)
    for claim, group in MUTATIONS.items():
        if claim in wanted:
            for m in group:
                print(f"\n{m.id}: {m.control}", end="")
    print()
    if errors:
        print("\nERRORS (not evidence either way):")
        for line in errors:
            print(f"  {line}")
    if decorative:
        print("\nDECORATIVE (green under every mutation of its claim):")
        for nodeid in decorative:
            print(f"  {nodeid}")
    return 1 if decorative or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
