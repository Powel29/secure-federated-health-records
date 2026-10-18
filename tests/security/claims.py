"""The P5-1 claim registry: paper claims C1-C11 and the tests that back them.

Every claim-bearing test carries ``@pytest.mark.claim("Cn", level=...)``:

- ``level="module"`` -- the control holds inside its module.
- ``level="system"`` -- the control holds through the running services.

The paper may state a claim only if every one of its system-level tests *ran
and passed* -- a skipped, erroring or never-run test is not evidence, and the
status is computed from a real run, not from collection (review N3). A system
test that fails today is kept at full strength and
marked ``xfail(strict=True, reason="<finding>")``: CI stays green, the
failure is on record, and the run turns red the day the fix lands so the
marker must come off (ADR-0046).

Print the claim table (the input to P6-4's security-properties table); this
runs the claim-tagged tests, so it needs Postgres like the suite does::

    python -m tests.security.claims --table
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LEVELS = ("module", "system")


@dataclass(frozen=True)
class Claim:
    id: str
    text: str
    review_findings: tuple[str, ...] = ()


# CONVENTIONS.md §5's ten exit-criterion tests, plus ADR-0016 (P5-1 "What").
CLAIMS: dict[str, Claim] = {
    c.id: c
    for c in (
        Claim(
            "C1",
            "A revoked user cannot decrypt after re-wrap",
            ("F10", "D3", "D4"),
        ),
        Claim(
            "C2",
            "Break-glass fails closed when the audit service cannot commit",
            ("F7",),
        ),
        Claim(
            "C3",
            "A single share, including the audit service's, cannot open a record",
            ("F2", "D1", "D2"),
        ),
        Claim(
            "C4",
            "Search capability does not survive the emergency's expiry",
            ("F9", "D3"),
        ),
        Claim("C5", "A tampered audit entry is detected by chain verification"),
        Claim("C6", "An illegal state transition is rejected", ("F11", "D7")),
        Claim(
            "C7",
            "A transition event with an invalid signature is rejected",
            ("D8", "F11"),
        ),
        Claim(
            "C8",
            "A replayed emergency assertion is rejected, not re-executed",
            ("F22",),
        ),
        Claim(
            "C9",
            "An authenticated but unauthorised caller is denied before any "
            "crypto or DB work (BOLA)",
            ("F34", "D5"),
        ),
        Claim(
            "C10",
            "An expired or revoked credential fails validation and releases " "no key",
            ("F14", "F15", "D10"),
        ),
        Claim(
            "C11",
            "A patient login alone never releases a DEK (ADR-0016)",
        ),
    )
}


@dataclass(frozen=True)
class TaggedTest:
    nodeid: str
    claim: str
    level: str
    xfail_reason: str | None
    xfail_strict: bool = False


class ClaimCollectionError(RuntimeError):
    """pytest could not collect (or run) the suite; the claim table is void."""


def _pytest(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    # Fixed argv and this interpreter -- nothing request-supplied.
    return subprocess.run(
        [  # noqa: S603
            sys.executable,
            "-m",
            "pytest",
            *args,
            "-q",
            "-p",
            "tests.security._claim_collector",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def collect() -> list[TaggedTest]:
    """Collect every claim-tagged test in ``tests/`` (pytest, collect-only).

    Runs in a subprocess so the collection never shares state with a calling
    test session. A collection error is an error, not a smaller set of
    tests: a module that fails to import would otherwise silently drop the
    very xfail that records a claim as failing (review N3).

    Raises:
        ClaimCollectionError: pytest exited non-zero.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "claims.json"
        env = dict(os.environ, P51_CLAIMS_OUT=str(out))
        proc = _pytest(["tests", "--collect-only"], env)
        if proc.returncode != 0 or not out.exists():
            raise ClaimCollectionError(
                f"claim collection failed (exit {proc.returncode}):"
                f" {proc.stdout} {proc.stderr}"
            )
        rows = json.loads(out.read_text(encoding="utf-8"))
    return [TaggedTest(**row) for row in rows]


def run(tests: list[TaggedTest]) -> dict[str, str]:
    """Run every claim-tagged test and return ``nodeid -> outcome``.

    Outcomes: ``passed``, ``failed``, ``skipped``, ``xfailed``, ``xpassed``
    or ``error``. A test missing from the result never ran.
    """
    nodeids = sorted({t.nodeid for t in tests})
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "outcomes.json"
        env = dict(os.environ, P51_OUTCOMES_OUT=str(out))
        proc = _pytest(nodeids, env)
        if not out.exists():
            raise ClaimCollectionError(
                f"claim test run failed (exit {proc.returncode}):"
                f" {proc.stdout} {proc.stderr}"
            )
        return json.loads(out.read_text(encoding="utf-8"))


def claim_status(
    claim_id: str, tests: list[TaggedTest], outcomes: dict[str, str] | None = None
) -> str:
    """The claim's standing, decided by how its system tests actually ran.

    "holds" requires every system test to have *passed* (review N3). With no
    ``outcomes`` (collection only), the status is never "holds".
    """
    system = [t for t in tests if t.claim == claim_id and t.level == "system"]
    if not system:
        return "NO SYSTEM TEST"
    if outcomes is None:
        return "NOT RUN (collection only)"
    results = {t.nodeid: outcomes.get(t.nodeid, "not run") for t in system}
    broken = sorted(
        n for n, r in results.items() if r not in ("passed", "skipped", "xfailed")
    )
    if broken:
        return "BROKEN: " + "; ".join(f"{n} ({results[n]})" for n in broken)
    failing = [t for t in system if results[t.nodeid] == "xfailed"]
    if failing:
        return "fails today: " + "; ".join(
            sorted({t.xfail_reason or "xfailed" for t in failing})
        )
    if any(r == "skipped" for r in results.values()):
        return "UNVERIFIED (skipped)"
    return "holds"


def render_table(tests: list[TaggedTest], outcomes: dict[str, str] | None) -> str:
    lines = [
        "| Claim | Statement | Status | Module tests | System tests |",
        "|---|---|---|---|---|",
    ]
    for claim in CLAIMS.values():
        mine = [t for t in tests if t.claim == claim.id]

        def names(level: str, mine: list[TaggedTest] = mine) -> str:
            picked = [t for t in mine if t.level == level]
            return (
                "<br>".join(
                    f"`{t.nodeid}`" + (" (xfail)" if t.xfail_reason else "")
                    for t in picked
                )
                or "none"
            )

        lines.append(
            f"| {claim.id} | {claim.text} | {claim_status(claim.id, tests, outcomes)} "
            f"| {names('module')} | {names('system')} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="P5-1 claim registry")
    parser.add_argument("--table", action="store_true", help="print the claim table")
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="list the tests without running them (no claim can show as holding)",
    )
    args = parser.parse_args()
    tests = collect()
    outcomes = None if args.collect_only else run(tests)
    if args.table:
        print(render_table(tests, outcomes))
    else:
        for claim in CLAIMS.values():
            print(f"{claim.id}: {claim_status(claim.id, tests, outcomes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
