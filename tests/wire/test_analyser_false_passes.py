"""The analyser never reports a pass it did not earn (review N4, N5, N8, N9, N15).

Each test plants one way the old analyser could pass on evidence that did
not show the claim -- a stale pcap, a lost segment, a canary too short to
search for, a TLS run that never reached the unlock -- and checks it fails.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from wire import capture as capture_mod
from wire.analyze_traffic import (
    StaleCaptureError,
    check_capture_matches_run,
    check_preconditions,
)
from wire.canaries import Canary, UnsearchableCanaryError, find_hits, load_manifest
from wire.checks import (
    check_breakglass_metadata_only,
    check_no_plaintext,
    search_leakage_rows,
)
from wire.http_messages import parse_flow
from wire.streams import Segment, reassemble
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

# --- N8: TCP gaps ------------------------------------------------------------


def test_flow_with_missing_segment_makes_claim1_inconclusive():
    canaries = make_canaries()
    plain = plain_scenario(canaries)  # leaks: the positive control fires
    tls = tls_scenario(canaries)
    # Setup is valid: with every segment present, the TLS scope holds.
    assert check_no_plaintext(plain, tls, "tls").passed

    to_fb = [s for s in tls.segments if s.dst_port == SERVICES["facility-b"]]
    lost = to_fb[1]  # the unlock request spans several segments; lose one
    holed = [s for s in tls.segments if s is not lost]
    gapped = type(tls)("tls", holed, tls.canaries, dict(SERVICES), DB_PORT)
    result = check_no_plaintext(plain, gapped, "tls")
    assert not result.passed
    assert "inconclusive" in result.summary
    assert result.evidence["gapped_flows"]


def test_match_is_never_invented_across_a_gap():
    """Bytes either side of a hole must not combine into a 'secret'."""
    secret = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    canary = Canary("joined", "dek", secret)
    segs = [
        Segment(1, 1.0, 0, 50000, 8001, 1, secret[:16]),
        # 10 bytes lost here, then the second half arrives.
        Segment(2, 1.1, 0, 50000, 8001, 1 + 16 + 10, secret[16:]),
    ]
    flows = reassemble(segs)
    assert next(iter(flows.values())).gaps == [16]
    assert find_hits(flows, [canary]) == []


def test_flow_start_timestamp_is_the_earliest_frame():
    segs = [
        Segment(2, 5.0, 0, 50000, 8001, 1, b"a" * 10),
        Segment(1, 4.0, 0, 50000, 8001, 11, b"b" * 10),  # sent first, seq later
    ]
    assert next(iter(reassemble(segs).values())).start_timestamp == 4.0


# --- N9: canaries too short to search ----------------------------------------


def test_manifest_with_unsearchable_canary_is_rejected(tmp_path):
    manifest = tmp_path / "plain.canaries.json"
    manifest.write_text(
        json.dumps({"canaries": {"tiny": {"class": "phi", "hex": b"abc".hex()}}}),
        encoding="utf-8",
    )
    with pytest.raises(UnsearchableCanaryError, match="tiny"):
        load_manifest(manifest)


# --- N5: stale or empty captures ---------------------------------------------


def _manifest(tmp_path, started_at):
    path = tmp_path / "plain.canaries.json"
    body = {"run_id": "r1", "canaries": {}}
    if started_at is not None:
        body["started_at"] = started_at
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_stale_pcap_older_than_manifest_rejected(tmp_path):
    segments = [Segment(1, 100.0, 0, 50000, 8001, 1, b"x")]
    # Setup is valid: a pcap with frames from the run is accepted.
    check_capture_matches_run(segments, _manifest(tmp_path, 99.0))
    with pytest.raises(StaleCaptureError, match="older than its canary manifest"):
        check_capture_matches_run(segments, _manifest(tmp_path, 200.0))
    with pytest.raises(StaleCaptureError, match="no run stamp"):
        check_capture_matches_run(segments, _manifest(tmp_path, None))


def test_tls_capture_with_single_handshake_fails_preconditions():
    canaries = make_canaries()
    plain = plain_scenario(canaries)
    w = Wire()
    w.exchange("audit", b"\x16\x03\x01" + b"h" * 200, b"\x16\x03\x03" + b"s" * 90)
    tls = type(plain)("tls", w.segments, list(canaries.values()), dict(SERVICES))
    result = check_preconditions(plain, tls)
    assert not result.passed
    assert "no TLS traffic to ports" in result.summary


def test_tls_breakglass_without_unlock_burst_fails_claim4():
    canaries = make_canaries()
    plain = plain_scenario(canaries, leak_keys=False)
    full = tls_scenario(canaries)
    # Setup is valid: the complete TLS run passes claim 4.
    assert check_breakglass_metadata_only(plain, full, "tls").passed

    w = Wire()
    w.exchange("facility-b", b"\x17\x03\x03" + b"r" * 400, b"\x17\x03\x03" + b"s" * 90)
    aborted = type(plain)("tls", w.segments, list(canaries.values()), dict(SERVICES))
    result = check_breakglass_metadata_only(plain, aborted, "tls")
    assert not result.passed
    assert "TLS run incomplete" in result.summary


def test_failed_capture_never_leaves_an_old_pcap_to_analyse(tmp_path, monkeypatch):
    """A dumpcap that writes nothing fails the capture and the old file is gone."""
    out = tmp_path / "plain.pcap"
    out.write_bytes(b"old run's packets")

    class _Silent:
        def __init__(self, *args, **kwargs):
            pass

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(capture_mod, "_require_dumpcap", lambda: "dumpcap")
    monkeypatch.setattr(subprocess, "Popen", _Silent)
    with pytest.raises(capture_mod.CaptureFailed, match="wrote no capture"):
        capture_mod.capture_scenario(
            lambda: None, output_path=out, interface="lo", settle_seconds=0
        )
    assert not out.exists()


# --- N4: revocation on the wire ----------------------------------------------


def test_revoke_exchange_carrying_old_dek_fails_claim1():
    canaries = make_canaries()
    clean = plain_scenario(canaries, leak_keys=False)
    tls = tls_scenario(canaries)
    w = Wire(segments=list(clean.segments))
    w._frame = max(s.frame for s in clean.segments)
    w._clock = max(s.timestamp for s in clean.segments)
    w._next_stream = max(s.stream for s in clean.segments) + 1
    w.exchange(
        "facility-a",
        http_request(
            "POST",
            "/records/rec-001/revoke",
            {"old_dek_b64": canaries["dek"].value.hex()},
        ),
        http_response(501, {"detail": "not implemented"}),
    )
    with_revoke = type(clean)(
        "plain", w.segments, list(canaries.values()), dict(SERVICES), DB_PORT
    )
    result = check_no_plaintext(with_revoke, tls, "all")
    assert not result.passed
    assert "dek" in result.evidence["plain_hits"]
    assert any(
        "old_dek_b64" in keys
        for keys in result.evidence["plain_denylisted_fields"].values()
    )


# --- N15: small correctness ----------------------------------------------------


def test_malformed_status_line_stops_the_flow_instead_of_crashing():
    segs = [Segment(1, 1.0, 0, 8001, 50000, 1, b"HTTP/1.1 abc OK\r\n\r\n")]
    flow = next(iter(reassemble(segs).values()))
    assert parse_flow(flow) == []


def test_search_csv_labels_queries_without_reversible_hashes():
    rows = search_leakage_rows(plain_scenario(make_canaries(), searches=3))
    assert [r["query_id"] for r in rows] == ["q1", "q1", "q1"]
    assert all("cardiac" not in json.dumps(r) for r in rows)


def test_db_port_defaults_to_database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres@127.0.0.1:55432/ehr")
    assert capture_mod.default_db_port() == 55432
    monkeypatch.delenv("DATABASE_URL")
    assert capture_mod.default_db_port() == 5432
