"""Negative tests for the four P5-5 wire-level checks (ADR-0045).

Every check is driven on synthetic traffic both where the claim holds and
where it is deliberately violated, so a pass from the live analyser means
the check can fail, not that it cannot.
"""

from __future__ import annotations

import pytest

from wire.checks import (
    Capture,
    check_breakglass_metadata_only,
    check_commit_before_release,
    check_no_plaintext,
    check_search_leakage,
    denylisted_fields,
)
from wire.tls import SERVICES

from .synthetic import (
    DB_PORT,
    Wire,
    http_request,
    http_response,
    make_canaries,
    plain_scenario,
    tls_scenario,
)


@pytest.fixture()
def canaries():
    return make_canaries()


def _clean_plain(canaries) -> Capture:
    w = Wire()
    w.exchange(
        "facility-b",
        http_request("GET", "/patients/pat-101/records"),
        http_response(200, {"record_ids": ["rec-001"]}),
    )
    return Capture(
        "plain", w.segments, list(canaries.values()), dict(SERVICES), DB_PORT
    )


class TestClaim1NoPlaintext:
    def test_scope_all_fails_on_todays_plain_profile(self, canaries):
        result = check_no_plaintext(
            plain_scenario(canaries), tls_scenario(canaries), "all"
        )
        assert not result.passed
        assert "share3" in result.evidence["plain_hits"]
        assert result.evidence["plain_denylisted_fields"]

    def test_scope_all_passes_when_both_captures_are_clean(self, canaries):
        result = check_no_plaintext(
            _clean_plain(canaries), tls_scenario(canaries), "all"
        )
        assert result.passed, result.summary

    def test_secret_in_tls_capture_fails_any_scope(self, canaries):
        leak = canaries["emergency_key"].value.hex().encode()
        for scope in ("all", "tls"):
            result = check_no_plaintext(
                plain_scenario(canaries), tls_scenario(canaries, leak=leak), scope
            )
            assert not result.passed
            assert "emergency_key" in result.evidence["tls_hits"]

    def test_scope_tls_passes_with_positive_control(self, canaries):
        result = check_no_plaintext(
            plain_scenario(canaries), tls_scenario(canaries), "tls"
        )
        assert result.passed, result.summary
        assert result.evidence["positive_control_fired"] is True

    def test_scope_tls_fails_when_positive_control_does_not_fire(self, canaries):
        result = check_no_plaintext(
            _clean_plain(canaries), tls_scenario(canaries), "tls"
        )
        assert not result.passed
        assert "positive control" in result.summary

    def test_unknown_scope_rejected(self, canaries):
        with pytest.raises(ValueError):
            check_no_plaintext(_clean_plain(canaries), tls_scenario(canaries), "x")

    def test_denylisted_json_fields_reported(self, canaries):
        fields = denylisted_fields(plain_scenario(canaries))
        assert fields["POST /attribute-keys/author [resp]"] == ["key_b64"]
        assert "share_hex" in fields["POST /breakglass/release [resp]"]


class TestClaim2CommitBeforeRelease:
    def test_commit_before_response_passes(self, canaries):
        result = check_commit_before_release(plain_scenario(canaries))
        assert result.passed, result.summary
        assert result.evidence["commit_lead_ms"] >= 0

    def test_commit_after_response_fails(self, canaries):
        result = check_commit_before_release(
            plain_scenario(canaries, commit_before_response=False)
        )
        assert not result.passed

    def test_share_on_wire_before_release_fails(self, canaries):
        result = check_commit_before_release(
            plain_scenario(canaries, share3_early=True)
        )
        assert not result.passed
        assert "before the release response" in result.summary

    def test_custody_registration_is_not_a_release(self, canaries):
        """Share 3 crosses the wire at custody setup, before release, by design."""
        plain = plain_scenario(canaries)
        share3_frames = [h.frame for h in plain.hits if h.canary == "share3"]
        result = check_commit_before_release(plain)
        assert min(share3_frames) < result.evidence["release_response_frame"]
        assert result.passed, result.summary

    def test_missing_db_traffic_fails_closed(self, canaries):
        result = check_commit_before_release(plain_scenario(canaries, include_db=False))
        assert not result.passed
        assert "Postgres" in result.summary

    def test_no_release_exchange_fails(self, canaries):
        result = check_commit_before_release(_clean_plain(canaries))
        assert not result.passed


class TestClaim3SearchLeakage:
    def test_searches_are_measured_with_hashed_queries(self, canaries):
        result = check_search_leakage(plain_scenario(canaries, searches=3))
        assert result.passed
        rows = result.evidence["rows"]
        assert len(rows) == 3
        assert all("cardiac" not in str(row) for row in rows)
        assert list(result.evidence["repeated_query_hashes"].values()) == [3]

    def test_no_searches_fails(self, canaries):
        result = check_search_leakage(plain_scenario(canaries, searches=0))
        assert not result.passed


class TestClaim4BreakglassMetadataOnly:
    def test_scope_tls_passes(self, canaries):
        result = check_breakglass_metadata_only(
            plain_scenario(canaries), tls_scenario(canaries), "tls"
        )
        assert result.passed, result.summary
        assert result.evidence["metadata_pick_validated_on_plain"] is True

    def test_scope_all_fails_while_shares_travel_in_plain(self, canaries):
        result = check_breakglass_metadata_only(
            plain_scenario(canaries), tls_scenario(canaries), "all"
        )
        assert not result.passed

    def test_secret_in_tls_breakglass_fails(self, canaries):
        leak = canaries["share1"].value.hex().encode()
        result = check_breakglass_metadata_only(
            plain_scenario(canaries), tls_scenario(canaries, leak=leak), "tls"
        )
        assert not result.passed

    def test_heuristic_that_misidentifies_unlock_fails(self, canaries):
        result = check_breakglass_metadata_only(
            plain_scenario(canaries, oversized_read=True), tls_scenario(canaries), "tls"
        )
        assert not result.passed
        assert result.evidence["metadata_pick_validated_on_plain"] is False
