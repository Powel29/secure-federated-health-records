"""P5-3 search leakage analysis from real PyShark captures.

Measures observable search-traffic leakage:
- access pattern (destination and endpoint)
- frequency (repeated observable request values)
- volume (packets and bytes)
- timing between searches
- plaintext visibility in HTTP captures

This intentionally analyzes captured traffic rather than relying on
application arguments or source-code assumptions.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pyshark


SEARCH_MARKERS = (
    "search",
    "emergency-search",
)


def _packet_bytes(packet: Any) -> int:
    """Return captured frame length when available."""
    try:
        return int(packet.length)
    except (AttributeError, TypeError, ValueError):
        return 0


def _timestamp(packet: Any) -> float | None:
    try:
        return float(packet.sniff_timestamp)
    except (AttributeError, TypeError, ValueError):
        return None


def _is_search_uri(uri: str) -> bool:
    lowered = uri.lower()
    return any(marker in lowered for marker in SEARCH_MARKERS)


def analyze_search_capture(path: Path) -> dict[str, Any]:
    """Analyze search-related traffic in one real PCAP."""
    if not path.exists():
        raise FileNotFoundError(f"Capture not found: {path}")

    capture = pyshark.FileCapture(
        str(path),
        keep_packets=False,
        display_filter="tcp",
    )

    searches: list[dict[str, Any]] = []
    total_tcp_packets = 0
    total_bytes = 0

    try:
        for packet in capture:
            total_tcp_packets += 1
            total_bytes += _packet_bytes(packet)

            if not hasattr(packet, "http"):
                continue

            http = packet.http

            uri = getattr(http, "request_uri", "")
            if not uri or not _is_search_uri(str(uri)):
                continue

            host = getattr(http, "host", "")
            method = getattr(http, "request_method", "")
            timestamp = _timestamp(packet)

            # HTTP exposes the request URI directly.  Capture the observable
            # URI, but do not invent application-level values when absent.
            searches.append(
                {
                    "timestamp": timestamp,
                    "method": str(method),
                    "host": str(host),
                    "uri": str(uri),
                    "bytes": _packet_bytes(packet),
                }
            )
    finally:
        capture.close()

    uri_counter = Counter(item["uri"] for item in searches)
    host_counter = Counter(item["host"] for item in searches)

    timestamps = [
        item["timestamp"]
        for item in searches
        if item["timestamp"] is not None
    ]
    deltas = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    return {
        "capture": str(path),
        "search_requests": len(searches),
        "unique_observable_requests": len(uri_counter),
        "repeated_requests": {
            uri: count
            for uri, count in sorted(uri_counter.items())
            if count > 1
        },
        "request_frequency": dict(sorted(uri_counter.items())),
        "access_pattern": dict(sorted(host_counter.items())),
        "search_packet_count": len(searches),
        "search_bytes": sum(item["bytes"] for item in searches),
        "total_tcp_packets": total_tcp_packets,
        "total_capture_bytes": total_bytes,
        "inter_search_seconds": deltas,
        "searches": searches,
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
    parser.add_argument(
        "--json",
        type=Path,
        help="Optional output JSON path.",
    )
    args = parser.parse_args()

    result = analyze_search_capture(args.capture)

    print("P5-3 Search Leakage Analysis")
    print("=" * 40)
    print(f"Capture                  : {result['capture']}")
    print(f"Search requests          : {result['search_requests']}")
    print(f"Unique observable       : {result['unique_observable_requests']}")
    print(f"Search packets           : {result['search_packet_count']}")
    print(f"Search bytes             : {result['search_bytes']}")
    print(f"Total TCP packets        : {result['total_tcp_packets']}")
    print(f"Total capture bytes      : {result['total_capture_bytes']}")

    print("\n[Access pattern]")
    for host, count in result["access_pattern"].items():
        print(f"  {host}: {count}")

    print("\n[Frequency leakage]")
    if result["repeated_requests"]:
        for uri, count in result["repeated_requests"].items():
            print(f"  {count}x {uri}")
    else:
        print("  No repeated observable search requests.")

    print("\n[Timing leakage]")
    if result["inter_search_seconds"]:
        for delta in result["inter_search_seconds"]:
            print(f"  {delta:.6f} s")
    else:
        print("  Insufficient searches for timing comparison.")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )
        print(f"\nJSON report written to: {args.json}")

    if result["search_requests"] == 0:
        print(
            "\nWARNING: no search traffic was found in this capture. "
            "P5-3 evidence requires a capture containing real searches."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
