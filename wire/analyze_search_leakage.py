"""P5-3 search leakage analysis from real PyShark captures.

Measures what a network observer learns from search traffic (PROJECT.md §4A
claim 3): access pattern, query volume, response-size leakage and timing,
plus whether the query itself crossed the wire in the clear.

Requests and responses are counted separately. A response carries the URI of
the request it answers (``http.response_for.uri``), so matching on URI alone
double-counts every query; here only ``http.request`` packets count as
queries, and each response is paired to its request by frame number.

This intentionally analyzes captured traffic rather than relying on
application arguments or source-code assumptions.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pyshark

SEARCH_MARKERS = (
    "/search",
    "/emergency-search",
)

# /records/<record_id>/emergency-search -> record_id
_RECORD_URI = re.compile(r"/records/([^/?]+)/")

# JSON keys whose presence in a readable request body means the query (or its
# token) was visible to the observer.
_QUERY_BODY_KEYS = ("search_term", "token")


def _int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def is_search_uri(uri: str) -> bool:
    lowered = uri.lower().split("?", 1)[0]
    return any(lowered.endswith(marker) for marker in SEARCH_MARKERS)


def record_id_from_uri(uri: str) -> str | None:
    match = _RECORD_URI.search(uri)
    return match.group(1) if match else None


def _body_text(http: object) -> str | None:
    """Readable HTTP body, or None when the observer cannot see one."""
    body = getattr(http, "file_data", None)
    return str(body) if body else None


def extract_http_event(packet: object) -> dict[str, Any] | None:
    """Flatten one PyShark packet into a request/response event, or None."""
    if not hasattr(packet, "http"):
        return None
    http = packet.http
    frame = _int(getattr(packet, "number", None))
    common = {
        "frame": frame,
        "timestamp": _float(getattr(packet, "sniff_timestamp", None)),
        "frame_bytes": _int(getattr(packet, "length", None)) or 0,
        "content_length": _int(getattr(http, "content_length_header", None)),
        "body": _body_text(http),
    }
    if hasattr(http, "request_method"):
        return {
            "kind": "request",
            "method": str(http.request_method),
            "uri": str(getattr(http, "request_uri", "")),
            "host": str(getattr(http, "host", "")),
            **common,
        }
    if hasattr(http, "response_code"):
        return {
            "kind": "response",
            "status": _int(http.response_code),
            "request_frame": _int(getattr(http, "request_in", None)),
            "uri": str(getattr(http, "response_for_uri", "")),
            **common,
        }
    return None


def _result_count(body: str | None) -> int | None:
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    count = parsed.get("record_count") if isinstance(parsed, dict) else None
    return count if isinstance(count, int) else None


def summarize_search_leakage(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the leakage profile from flattened HTTP events.

    Pure function so the measurement logic is testable without tshark.
    """
    requests = [e for e in events if e["kind"] == "request" and is_search_uri(e["uri"])]
    responses_by_request = {
        e["request_frame"]: e
        for e in events
        if e["kind"] == "response" and e.get("request_frame") is not None
    }

    queries: list[dict[str, Any]] = []
    for req in requests:
        resp = responses_by_request.get(req["frame"])
        body = req["body"] or ""
        queries.append(
            {
                "timestamp": req["timestamp"],
                "method": req["method"],
                "uri": req["uri"],
                "record_id": record_id_from_uri(req["uri"]),
                "request_bytes": req["content_length"],
                "query_visible_in_clear": any(k in body for k in _QUERY_BODY_KEYS),
                "response_status": resp["status"] if resp else None,
                "response_bytes": resp["content_length"] if resp else None,
                "result_count": _result_count(resp["body"]) if resp else None,
            }
        )

    uri_counter = Counter(q["uri"] for q in queries)
    record_counter = Counter(q["record_id"] or "<none>" for q in queries)
    timestamps = [q["timestamp"] for q in queries if q["timestamp"] is not None]

    # Response-size leakage: does the observable size vary with the hidden
    # result count?  Group sizes by count where the body was readable.
    sizes_by_count: dict[str, list[int]] = {}
    for q in queries:
        if q["result_count"] is not None and q["response_bytes"] is not None:
            sizes_by_count.setdefault(str(q["result_count"]), []).append(
                q["response_bytes"]
            )
    response_sizes = sorted(
        {q["response_bytes"] for q in queries if q["response_bytes"] is not None}
    )

    return {
        "query_volume": len(queries),
        "answered_queries": sum(1 for q in queries if q["response_status"]),
        "unique_observable_requests": len(uri_counter),
        "repeated_requests": {
            uri: count for uri, count in sorted(uri_counter.items()) if count > 1
        },
        "access_pattern_by_record": dict(sorted(record_counter.items())),
        "queries_visible_in_clear": sum(
            1 for q in queries if q["query_visible_in_clear"]
        ),
        "distinct_response_sizes": response_sizes,
        "response_bytes_by_result_count": dict(sorted(sizes_by_count.items())),
        "inter_query_seconds": [
            timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))
        ],
        "queries": queries,
    }


def analyze_search_capture(path: Path) -> dict[str, Any]:
    """Analyze search-related traffic in one real PCAP."""
    if not path.exists():
        raise FileNotFoundError(f"Capture not found: {path}")

    capture = pyshark.FileCapture(str(path), keep_packets=False, display_filter="tcp")

    events: list[dict[str, Any]] = []
    total_tcp_packets = 0
    total_bytes = 0
    tls_packets = 0
    try:
        for packet in capture:
            total_tcp_packets += 1
            total_bytes += _int(getattr(packet, "length", None)) or 0
            if hasattr(packet, "tls"):
                tls_packets += 1
            event = extract_http_event(packet)
            if event is not None:
                events.append(event)
    finally:
        capture.close()

    summary = summarize_search_leakage(events)
    return {
        "capture": str(path),
        "total_tcp_packets": total_tcp_packets,
        "total_capture_bytes": total_bytes,
        "http_events": len(events),
        "tls_packets": tls_packets,
        # Over TLS without a key log the observer sees no URIs at all; the
        # profile above then under-reports, and that must be said, not hidden.
        "uris_observable": bool(events),
        **summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze search leakage from real PyShark PCAP captures."
    )
    parser.add_argument(
        "--capture",
        type=Path,
        required=True,
        help="PCAP containing captured search traffic.",
    )
    parser.add_argument("--json", type=Path, help="Optional output JSON path.")
    args = parser.parse_args()

    result = analyze_search_capture(args.capture)

    print("P5-3 Search Leakage Analysis")
    print("=" * 40)
    print(f"Capture                  : {result['capture']}")
    print(f"URIs observable          : {result['uris_observable']}")
    print(f"Query volume             : {result['query_volume']}")
    print(f"Answered queries         : {result['answered_queries']}")
    print(f"Queries visible in clear : {result['queries_visible_in_clear']}")
    print(f"Total TCP packets        : {result['total_tcp_packets']}")
    print(f"TLS packets              : {result['tls_packets']}")

    print("\n[Access pattern by record]")
    for record_id, count in result["access_pattern_by_record"].items():
        print(f"  {record_id}: {count}")

    print("\n[Frequency leakage]")
    if result["repeated_requests"]:
        for uri, count in result["repeated_requests"].items():
            print(f"  {count}x {uri}")
    else:
        print("  No repeated observable search requests.")

    print("\n[Response-size leakage]")
    print(f"  distinct response sizes: {result['distinct_response_sizes']}")
    for count, sizes in result["response_bytes_by_result_count"].items():
        print(f"  result_count={count}: bytes={sizes}")

    print("\n[Timing leakage]")
    if result["inter_query_seconds"]:
        for delta in result["inter_query_seconds"]:
            print(f"  {delta:.6f} s")
    else:
        print("  Insufficient searches for timing comparison.")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nJSON report written to: {args.json}")

    if result["query_volume"] == 0:
        print(
            "\nERROR: no search traffic was found in this capture. "
            "P5-3 evidence requires a capture containing real searches."
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
