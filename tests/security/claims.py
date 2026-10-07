"""The P5-1 claim registry: paper claims C1-C11 and the tests that back them.

Every claim-bearing test carries ``@pytest.mark.claim("Cn", level=...)``:

- ``level="module"`` -- the control holds inside its module.
- ``level="system"`` -- the control holds through the running services.

The paper may state a claim only if every one of its system-level tests runs
without ``xfail``. A system test that fails today is kept at full strength and
marked ``xfail(strict=True, reason="<finding>")``: CI stays green, the
failure is on record, and the run turns red the day the fix lands so the
marker must come off (ADR-0046).

Print the claim table (the input to P6-4's security-properties table)::

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


def collect() -> list[TaggedTest]:
    """Collect every claim-tagged test in ``tests/`` (pytest, collect-only).

    Runs in a subprocess so the collection never shares state with a calling
    test session.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "claims.json"
        env = dict(os.environ, P51_CLAIMS_OUT=str(out))
        # Fixed argv and this interpreter -- nothing request-supplied.
        proc = subprocess.run(
            [  # noqa: S603
                sys.executable,
                "-m",
                "pytest",
                "tests",
                "--collect-only",
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
        if not out.exists():
            raise RuntimeError(
                f"claim collection failed:\n{proc.stdout}\n{proc.stderr}"
            )
        rows = json.loads(out.read_text(encoding="utf-8"))
    return [TaggedTest(**row) for row in rows]


def claim_status(claim_id: str, tests: list[TaggedTest]) -> str:
    system = [t for t in tests if t.claim == claim_id and t.level == "system"]
    if not system:
        return "NO SYSTEM TEST"
    failing = [t for t in system if t.xfail_reason]
    if not failing:
        return "holds"
    return "fails today: " + "; ".join(sorted({t.xfail_reason for t in failing}))


def render_table(tests: list[TaggedTest]) -> str:
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
            f"| {claim.id} | {claim.text} | {claim_status(claim.id, tests)} "
            f"| {names('module')} | {names('system')} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="P5-1 claim registry")
    parser.add_argument("--table", action="store_true", help="print the claim table")
    args = parser.parse_args()
    tests = collect()
    if args.table:
        print(render_table(tests))
    else:
        for claim in CLAIMS.values():
            print(f"{claim.id}: {claim_status(claim.id, tests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
