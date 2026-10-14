"""Live P5-5 run: the analyser against real captures (ADR-0045).

Needs tshark and the four files ``wire.capture`` writes (plain/tls pcap plus
their canary manifests), so it skips cleanly without them -- the repo's
Postgres-skip convention (ADR-0042). On a machine with captures this test is
the course-module evidence: the analyser exits 0 only if every claim holds.

The claim-1 scope comes from ``WIRE_CLAIM1_SCOPE`` (default ``all``, the
unnarrowed claim; set ``tls`` only once decision D6 adopts D6-b).
"""

from __future__ import annotations

import os
import shutil

import pytest

from wire.analyze_traffic import CAPTURE_DIR, check_preconditions, main

from .synthetic import make_canaries, plain_scenario, tls_scenario

_REQUIRED = ("plain.pcap", "plain.canaries.json", "tls.pcap", "tls.canaries.json")


def test_preconditions_reject_an_incomplete_plain_capture():
    canaries = make_canaries()
    result = check_preconditions(plain_scenario(canaries), tls_scenario(canaries))
    assert not result.passed
    assert "missing endpoints" in result.summary


def test_live_captures_satisfy_every_claim(tmp_path):
    if shutil.which("tshark") is None:
        pytest.skip("tshark not installed; live capture analysis skipped")
    missing = [name for name in _REQUIRED if not (CAPTURE_DIR / name).exists()]
    if missing:
        pytest.skip(f"no captures yet ({missing}); run `python -m wire.capture`")

    # "all" until decision D6 narrows claim 1 (review N15): the paper must
    # defend the unnarrowed claim, which the plain profile fails today.
    scope = os.environ.get("WIRE_CLAIM1_SCOPE", "all")
    code = main(
        [
            "--captures",
            str(CAPTURE_DIR),
            "--claim1-scope",
            scope,
            "--json",
            str(tmp_path / "report.json"),
            "--csv",
            str(tmp_path / "search.csv"),
        ]
    )
    assert code == 0, (tmp_path / "report.json").read_text(encoding="utf-8")
