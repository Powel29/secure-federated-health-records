"""Meta-tests for the P5-1 claim registry (ADR-0046).

These keep "each test maps to a specific paper claim" true as the suite
changes: every claim needs a system-level test, every tag must name a known
claim and level, and every expected failure must be strict and cite a finding.
"""

from __future__ import annotations

import re

import pytest

from tests.security.claims import CLAIMS, LEVELS, TaggedTest, claim_status, collect


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
        # Word boundaries: "F2" must not match "F22", nor "D1" match "D10"
        # (review N15).
        assert any(
            re.search(r"\b" + re.escape(f) + r"\b", test.xfail_reason) for f in findings
        ), (
            f"{test.nodeid}: xfail reason {test.xfail_reason!r} cites none of "
            f"{findings}"
        )


# --- Review N3: a claim holds only on tests that ran and passed ---------------


def _system(nodeid: str, claim: str = "C5", reason: str | None = None) -> TaggedTest:
    return TaggedTest(nodeid, claim, "system", reason, reason is not None)


def test_skipped_system_test_is_not_reported_as_holding():
    tests = [_system("t::a"), _system("t::b")]
    assert claim_status("C5", tests, {"t::a": "passed", "t::b": "passed"}) == "holds"
    assert (
        claim_status("C5", tests, {"t::a": "passed", "t::b": "skipped"})
        == "UNVERIFIED (skipped)"
    )


def test_erroring_or_unrun_system_test_is_broken():
    tests = [_system("t::a"), _system("t::b")]
    assert claim_status("C5", tests, {"t::a": "error", "t::b": "passed"}).startswith(
        "BROKEN"
    )
    assert claim_status("C5", tests, {"t::a": "passed"}).startswith("BROKEN")


def test_xfailed_system_test_reports_its_finding():
    tests = [_system("t::a", reason="F2: open release")]
    assert claim_status("C5", tests, {"t::a": "xfailed"}) == (
        "fails today: F2: open release"
    )


def test_collection_alone_never_reports_holding():
    assert claim_status("C5", [_system("t::a")]) == "NOT RUN (collection only)"


def test_collection_error_is_an_error(monkeypatch):
    """A module that fails to import must void the table, not shrink it."""
    import subprocess

    from tests.security import claims

    def broken_collection(*args, **kwargs):
        return subprocess.CompletedProcess(args, 2, "ImportError in test_x", "")

    monkeypatch.setattr(claims.subprocess, "run", broken_collection)
    with pytest.raises(claims.ClaimCollectionError, match="exit 2"):
        claims.collect()


# --- Review N7: a crash is not a caught mutation ------------------------------


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "expected"),
    [
        (1, "1 failed", "", "red"),
        (0, "1 passed", "", "green"),
        (0, "SKIPPED [1] needs Postgres", "", "skipped"),
        (2, "", "Interrupted: 1 error during collection", "ERROR (pytest exit 2)"),
        (4, "", "usage error", "ERROR (pytest exit 4)"),
        (
            4,
            "",
            "P51_MUTATION_APPLY_FAILED: C3a: AttributeError('no attribute')",
            "ERROR (mutation did not apply)",
        ),
    ],
)
def test_mutation_that_fails_to_apply_is_error_not_caught(
    returncode, stdout, stderr, expected
):
    import subprocess

    from tests.security.mutations import _classify

    proc = subprocess.CompletedProcess([], returncode, stdout, stderr)
    assert _classify(proc) == expected
