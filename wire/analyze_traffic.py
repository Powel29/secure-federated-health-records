"""P5-5 traffic analysis: assert the four wire-level claims (PROJECT.md §4A).

Reads the two captures produced by :mod:`wire.capture` and the canary
manifest each scenario run wrote beside it, then runs the checks in
:mod:`wire.checks`::

    python -m wire.analyze_traffic --captures wire/captures
    python -m wire.analyze_traffic --claim1-scope tls   # if D6-b is adopted

Expects, in ``--captures``: ``plain.pcap``, ``plain.canaries.json``,
``tls.pcap``, ``tls.canaries.json``. Writes a per-claim JSON report and the
claim-3 search CSV under ``bench/results/``. Exits non-zero if any
precondition or claim fails -- explicit checks, not ``assert`` (which ``-O``
strips; review F18).
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict
from pathlib import Path

from wire.canaries import load_manifest
from wire.checks import (
    CLAIM1_SCOPES,
    DEFAULT_DB_PORT,
    Capture,
    ClaimResult,
    run_all,
    search_leakage_rows,
)
from wire.streams import read_segments
from wire.tls import SERVICES

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURE_DIR = Path(__file__).resolve().parent / "captures"
RESULTS_DIR = REPO_ROOT / "bench" / "results"

# Scenario endpoints the plain capture must show, or the run was incomplete.
EXPECTED_HTTP_ENDPOINTS = {
    "/credentials/issue",
    "/attribute-keys/author",
    "/breakglass/shares",
    "/breakglass/release",
    "/records/ingest",
    "/records/rec-001/read",
    "/records/rec-001/breakglass",
    "/records/rec-001/emergency-search",
}

# TLS record header: content type (handshake 0x16 / application 0x17), 0x03.
_TLS_RECORD_PREFIXES = (b"\x16\x03", b"\x17\x03")


def load_capture(directory: Path, mode: str, db_port: int) -> Capture:
    pcap = directory / f"{mode}.pcap"
    manifest = directory / f"{mode}.canaries.json"
    if not manifest.exists():
        raise FileNotFoundError(
            f"Canary manifest not found: {manifest} -- capture with "
            "`python -m wire.capture`, which writes it beside the pcap"
        )
    return Capture(
        mode=mode,
        segments=read_segments(pcap),
        canaries=load_manifest(manifest),
        ports=dict(SERVICES),
        db_port=db_port,
    )


def check_preconditions(plain: Capture, tls: Capture) -> ClaimResult:
    """The captures are what they claim to be before any claim is judged."""
    problems = []
    seen = {ex.request.path for ex in plain.exchanges}
    missing = sorted(EXPECTED_HTTP_ENDPOINTS - seen)
    if missing:
        problems.append(f"plain capture missing endpoints {missing}")
    if not plain.canaries or not tls.canaries:
        problems.append("a canary manifest is empty")
    if tls.exchanges:
        problems.append(f"TLS capture exposes {len(tls.exchanges)} HTTP exchange(s)")
    tls_records = any(
        flow.data.startswith(_TLS_RECORD_PREFIXES)
        for key, flow in tls.flows.items()
        if key.dst_port in tls.service_ports
    )
    if not tls_records:
        problems.append("TLS capture contains no TLS records on service ports")
    return ClaimResult(
        "0-preconditions",
        not problems,
        "strong",
        "; ".join(problems) or "plain shows the full scenario; TLS shows only TLS",
        {"plain_endpoints_seen": sorted(seen)},
    )


def write_reports(
    results: list[ClaimResult], plain: Capture, json_path: Path, csv_path: Path
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps([asdict(r) for r in results], indent=2, default=str),
        encoding="utf-8",
    )
    rows = search_leakage_rows(plain)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "frame",
                "timestamp",
                "path",
                "query_sha256",
                "request_bytes",
                "response_status",
                "response_bytes",
                "result_count",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P5-5 wire-level claim checks.")
    parser.add_argument("--captures", type=Path, default=CAPTURE_DIR)
    parser.add_argument(
        "--claim1-scope",
        choices=CLAIM1_SCOPES,
        default="all",
        help="all: neither capture may expose a secret (default); "
        "tls: only TLS must be clean, plain is the positive control (D6-b)",
    )
    parser.add_argument("--db-port", type=int, default=DEFAULT_DB_PORT)
    parser.add_argument(
        "--json", type=Path, default=RESULTS_DIR / "p55_wire_checks.json"
    )
    parser.add_argument(
        "--csv", type=Path, default=RESULTS_DIR / "p55_search_leakage.csv"
    )
    args = parser.parse_args(argv)

    plain = load_capture(args.captures, "plain", args.db_port)
    tls = load_capture(args.captures, "tls", args.db_port)

    results = [check_preconditions(plain, tls)]
    if results[0].passed:
        results += run_all(plain, tls, args.claim1_scope)

    print("P5-5 Traffic Analysis -- PROJECT.md §4A wire-level claims")
    print("=" * 60)
    for result in results:
        mark = "PASS" if result.passed else "FAIL"
        print(f"[{mark}] {result.claim} ({result.strength})")
        print(f"       {result.summary}")

    write_reports(results, plain, args.json, args.csv)
    print(f"\nReport: {args.json}\nSearch CSV: {args.csv}")

    failed = [r.claim for r in results if not r.passed]
    if failed:
        print(f"\nFAILED: {', '.join(failed)}")
        return 1
    print("\nAll wire-level claims hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
