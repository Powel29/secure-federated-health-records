"""Pytest plugin used by :func:`tests.security.claims.collect`.

Loaded with ``-p tests.security._claim_collector`` during a collect-only run;
writes every ``claim``-marked test to the JSON file named by
``P51_CLAIMS_OUT``. Not a test module (leading underscore keeps pytest from
collecting it).
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
