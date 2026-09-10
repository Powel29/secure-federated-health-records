"""P4-6 traffic capture analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path

import pyshark


CAPTURE_DIR = Path(__file__).resolve().parent / "captures"

EXPECTED_HTTP_ENDPOINTS = {
    "/credentials/issue",
    "/attribute-keys/author",
    "/breakglass/shares",
    "/records/ingest",
    "/records/rec-001/read",
}


def analyze_capture(path: Path) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"Capture not found: {path}")

    capture = pyshark.FileCapture(
        str(path),
        keep_packets=False,
        display_filter="tcp",
    )

    tcp_packets = 0
    http_packets = 0
    tls_packets = 0
    http_endpoints: set[str] = set()

    try:
        for packet in capture:
            tcp_packets += 1

            if hasattr(packet, "http"):
                http_packets += 1

                if hasattr(packet.http, "request_uri"):
                    http_endpoints.add(packet.http.request_uri)

            if hasattr(packet, "tls"):
                tls_packets += 1
    finally:
        capture.close()

    return {
        "tcp_packets": tcp_packets,
        "http_packets": http_packets,
        "tls_packets": tls_packets,
        "http_endpoints": http_endpoints,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze P4-6 traffic captures.")
    parser.add_argument(
        "--captures",
        type=Path,
        default=CAPTURE_DIR,
    )
    args = parser.parse_args()

    plain = args.captures / "plain.pcap"
    tls = args.captures / "tls.pcap"

    print("P4-6 Traffic Analysis")
    print("=" * 40)

    plain_result = analyze_capture(plain)
    tls_result = analyze_capture(tls)

    print("\n[HTTP / Plain]")
    print(f"TCP packets : {plain_result['tcp_packets']}")
    print(f"HTTP packets: {plain_result['http_packets']}")
    print(f"TLS packets : {plain_result['tls_packets']}")

    print("\nCaptured HTTP endpoints:")
    for endpoint in sorted(plain_result["http_endpoints"]):
        print(f"  {endpoint}")

    print("\n[TLS / HTTPS]")
    print(f"TCP packets : {tls_result['tcp_packets']}")
    print(f"HTTP packets: {tls_result['http_packets']}")
    print(f"TLS packets : {tls_result['tls_packets']}")

    # Plain HTTP must expose application-layer HTTP.
    assert plain_result["http_packets"] > 0, (
        "Plain capture does not contain HTTP traffic."
    )

    # Required application endpoints must be visible in the plain capture.
    missing = EXPECTED_HTTP_ENDPOINTS - plain_result["http_endpoints"]
    assert not missing, f"Missing expected HTTP endpoints: {sorted(missing)}"

    # HTTPS must contain TLS and must not expose HTTP.
    assert tls_result["tls_packets"] > 0, (
        "TLS capture does not contain TLS traffic."
    )

    assert tls_result["http_packets"] == 0, (
        "TLS capture exposes HTTP at the application layer."
    )

    print("\n✓ Plain HTTP traffic detected")
    print("✓ Required scenario endpoints detected")
    print("✓ TLS traffic detected")
    print("✓ TLS capture does not expose HTTP")
    print("\nP4-6 traffic checks PASSED.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())