"""Pytest plugin used by :mod:`tests.security.claims`.

Loaded with ``-p tests.security._claim_collector``. It writes every
``claim``-marked test to the JSON file named by ``P51_CLAIMS_OUT`` and, when
the tests actually run, each one's outcome to ``P51_OUTCOMES_OUT`` -- a claim
holds only on tests that ran and passed, never on collection alone (review
N3). Not a test module (leading underscore keeps pytest from collecting it).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def pytest_collection_modifyitems(
    session: pytest.Session, config: pytest.Config, items: list[pytest.Item]
) -> None:
    out = os.environ.get("P51_CLAIMS_OUT")
    if not out:
        return
    rows = []
    for item in items:
        xfail = item.get_closest_marker("xfail")
        for marker in item.iter_markers("claim"):
            rows.append(
                {
                    "nodeid": item.nodeid,
                    "claim": marker.args[0] if marker.args else "",
                    "level": marker.kwargs.get("level", ""),
                    "xfail_reason": (xfail.kwargs.get("reason") if xfail else None),
                    "xfail_strict": bool(xfail and xfail.kwargs.get("strict")),
                }
            )
    Path(out).write_text(json.dumps(rows), encoding="utf-8")


_outcomes: dict[str, str] = {}


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Record each test's outcome: passed / failed / skipped / xfailed / error."""
    if report.when == "setup" and report.failed:
        _outcomes[report.nodeid] = "error"
    elif report.when == "setup" and report.skipped:
        _outcomes[report.nodeid] = (
            "xfailed" if hasattr(report, "wasxfail") else "skipped"
        )
    elif report.when == "call":
        if hasattr(report, "wasxfail"):
            _outcomes[report.nodeid] = "xfailed" if report.skipped else "xpassed"
        else:
            _outcomes[report.nodeid] = report.outcome
    elif report.when == "teardown" and report.failed:
        _outcomes[report.nodeid] = "error"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    out = os.environ.get("P51_OUTCOMES_OUT")
    if out:
        Path(out).write_text(json.dumps(_outcomes), encoding="utf-8")
