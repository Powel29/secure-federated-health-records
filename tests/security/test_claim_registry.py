"""Meta-tests for the P5-1 claim registry (ADR-0046).

These keep "each test maps to a specific paper claim" true as the suite
changes: every claim needs a system-level test, every tag must name a known
claim and level, and every expected failure must be strict and cite a finding.
"""

from __future__ import annotations

import pytest

from tests.security.claims import CLAIMS, LEVELS, TaggedTest, collect


@pytest.fixture(scope="module")
def tagged() -> list[TaggedTest]:
    return collect()


def test_every_claim_has_a_system_level_test(tagged):
    covered = {t.claim for t in tagged if t.level == "system"}
    missing = sorted(set(CLAIMS) - covered, key=lambda c: int(c[1:]))
    assert not missing, f"claims with no system-level test: {missing}"


def test_every_claim_has_a_module_or_system_test(tagged):
    covered = {t.claim for t in tagged}
    assert set(CLAIMS) <= covered


def test_tags_name_known_claims_and_levels(tagged):
    bad = [t.nodeid for t in tagged if t.claim not in CLAIMS or t.level not in LEVELS]
    assert not bad, f"claim markers with unknown id or level: {bad}"


def test_expected_failures_cite_a_review_finding(tagged):
    """An xfail with no finding is a hidden failure, not a recorded one."""
    for test in tagged:
        if test.xfail_reason is None:
            continue
        assert test.xfail_strict, f"{test.nodeid}: xfail must be strict=True"
        findings = CLAIMS[test.claim].review_findings
        assert any(f in test.xfail_reason for f in findings), (
            f"{test.nodeid}: xfail reason {test.xfail_reason!r} cites none of "
            f"{findings}"
        )
