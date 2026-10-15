"""Traffic-capture harness for the federation (P4-6).

Produces one packet-capture file per scenario in each of two modes:

- ``plain`` -- the default ``capture-plain`` profile: services speak plain HTTP
  (P4-3), so the capture is what an on-path observer sees with no TLS.
- ``tls``   -- the ``capture-tls`` profile: services speak TLS using the
  throwaway certs from :mod:`wire.tls`, so the capture is the encrypted wire.

The *analysis* of these captures (asserting no plaintext leaks, log-before-
release ordering, break-glass visible only as metadata) is P5-5's job
(:mod:`wire.analyze_traffic`); this module only *produces* the ``.pcap`` and,
beside it, the scenario's canary manifest ``<mode>.canaries.json`` (ADR-0045).

The filter also includes the Postgres port: claim 2 (commit-before-release)
is proven by seeing the audit service's ``COMMIT`` on the wire before the
share-carrying release response.

Capture tooling: shells out to ``dumpcap`` (ships with Wireshark/tshark), which
``pyshark`` then reads. If it is not on ``PATH`` this raises
:class:`CaptureToolUnavailable` with a clear message rather than pretending to
capture.

**Loopback only.** Per CLAUDE.md, we capture only our own synthetic federation
on the loopback interface (or the Docker bridge), never a shared or third-party
network. The default interface is loopback and the BPF filter is pinned to the
federation service ports.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from wire.tls import SERVICES

CAPTURE_DIR = Path(__file__).resolve().parent / "captures"
DEFAULT_DB_PORT = 5432


def default_db_port() -> int:
    """The Postgres port claim 2 traces: ``DATABASE_URL``'s, else 5432.

    This project's Postgres listens on 55432/55433, so a fixed 5432 default
    made claim 2 fail unless the flag was passed (review N15).
    """
    url = os.environ.get("DATABASE_URL")
    if url:
        port = urlparse(url).port
        if port:
            return port
    return DEFAULT_DB_PORT


# Default loopback interface name by platform family. dumpcap on Windows with
# Npcap exposes loopback as this friendly name; Linux/macOS use "lo"/"lo0".
_DEFAULT_LOOPBACK = {
    "linux": "lo",
    "darwin": "lo0",
    "win32": "\\Device\\NPF_Loopback",
}


# CLAUDE.md: capture only our own synthetic federation, on loopback or the
# Docker bridge -- never a campus, shared or third-party network (review F39).
_LOOPBACK_INTERFACES = frozenset(
    {
        "lo",
        "lo0",
        "\\Device\\NPF_Loopback",
        "Adapter for loopback traffic capture",
    }
)
_BRIDGE_INTERFACES = frozenset({"docker0"})
# Docker names its user-defined bridges br-<first 12 hex of the network id>;
# a looser "br-*" also admitted host bridges such as br-lan (review N15).
_DOCKER_BRIDGE = re.compile(r"br-[0-9a-f]{12}")
CAPTURE_RULE = (
    "capture is allowed only on loopback (lo, lo0, \\Device\\NPF_Loopback, "
    "'Adapter for loopback traffic capture') or the Docker bridge (docker0, br-*) "
    "-- never a shared or third-party network (CLAUDE.md)"
)


class CaptureToolUnavailable(RuntimeError):
    """``dumpcap`` is not installed / not on PATH -- capture cannot run."""


class CaptureInterfaceRefused(ValueError):
    """The requested interface is not loopback or the Docker bridge."""


class CaptureFailed(RuntimeError):
    """dumpcap did not produce a usable capture (review N5)."""


def is_allowed_interface(name: str) -> bool:
    """True only for loopback adapters and the Docker bridge (F39)."""
    return (
        name in _LOOPBACK_INTERFACES
        or name in _BRIDGE_INTERFACES
        or _DOCKER_BRIDGE.fullmatch(name) is not None
    )


def default_loopback_interface() -> str:
    """Best-guess loopback interface for the current platform (overridable)."""
    import sys

    return _DEFAULT_LOOPBACK.get(sys.platform, "lo")


def _federation_bpf(db_port: int = DEFAULT_DB_PORT) -> str:
    """BPF filter pinning capture to the federation's own loopback ports."""
    ports = sorted({*SERVICES.values(), db_port})
    return "tcp and (" + " or ".join(f"port {p}" for p in ports) + ")"


def _require_dumpcap() -> str:
    path = shutil.which("dumpcap")
    if path is None:
        raise CaptureToolUnavailable(
            "dumpcap not found on PATH; install Wireshark/tshark to run the "
            "P4-6 capture (pyshark wraps the same tshark binary)"
        )
    return path


def capture_scenario(
    scenario: Callable[[], None],
    *,
    output_path: Path,
    interface: str | None = None,
    settle_seconds: float = 0.5,
    db_port: int = DEFAULT_DB_PORT,
) -> Path:
    """Run ``scenario`` while capturing federation loopback traffic to a pcap.

    Args:
        scenario: A zero-arg callable that drives the federation (e.g. the demo
            standalone run or ``deploy.run_scenario``). Capture spans exactly
            its execution.
        output_path: Where to write the ``.pcap``.
        interface: Capture interface; defaults to platform loopback. Must be a
            loopback / Docker-bridge interface -- never a shared network.
        settle_seconds: Grace period after starting dumpcap (and before/after
            the scenario) so no packets are clipped at the edges.
        db_port: Postgres port to include in the filter (claim 2 evidence).

    Returns:
        ``output_path``, now containing the capture.

    Raises:
        CaptureInterfaceRefused: ``interface`` is not loopback / Docker bridge.
        CaptureToolUnavailable: ``dumpcap`` is not installed.
        CaptureFailed: dumpcap stopped on its own, or wrote nothing (N5).
    """
    iface = interface or default_loopback_interface()
    if not is_allowed_interface(iface):
        raise CaptureInterfaceRefused(f"refusing interface {iface!r}: {CAPTURE_RULE}")
    dumpcap = _require_dumpcap()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Never leave an older run's pcap behind: a failed capture would otherwise
    # be analysed against this run's canaries and pass (review N5).
    output_path.unlink(missing_ok=True)

    proc = subprocess.Popen(
        [
            dumpcap,
            "-i",
            iface,
            "-f",
            _federation_bpf(db_port),
            "-w",
            str(output_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(settle_seconds)  # let dumpcap bind before traffic starts
        scenario()
        time.sleep(settle_seconds)  # let trailing packets flush
        exited_early = proc.poll()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if exited_early is not None:
        raise CaptureFailed(
            f"dumpcap exited with status {exited_early} before the scenario ended"
        )
    if not output_path.exists() or output_path.stat().st_size == 0:
        raise CaptureFailed(f"dumpcap wrote no capture to {output_path}")
    return output_path


def _run_scenario_via_subprocess(
    scheme: str, canaries_out: Path | None = None, *, search_workload: bool = False
) -> Callable[[], None]:
    """Default scenario: drive an already-running federation over ``scheme``.

    Shells out to ``deploy.run_scenario`` (P4-4) rather than coupling in-process,
    so capture spans the real cross-hospital break-glass flow on the fixed
    loopback ports the BPF filter pins. The federation must already be up
    (``deploy/run_local.py`` or Docker Compose) -- plain HTTP for ``plain``,
    TLS for ``tls`` (start it with the certs from :mod:`wire.tls`).
    ``search_workload`` adds the P5-3 searches (ADR-0070).
    """

    def _run() -> None:
        import sys

        cmd = [sys.executable, "-m", "deploy.run_scenario", "--scheme", scheme]
        if canaries_out is not None:
            cmd += ["--canaries-out", str(canaries_out)]
        if search_workload:
            cmd.append("--search-workload")
        subprocess.run(cmd, check=True)

    return _run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P4-6 federation traffic capture")
    parser.add_argument(
        "--mode",
        choices=("plain", "tls"),
        default="plain",
        help="capture-plain (default) or capture-tls",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="loopback interface to capture on (default: platform loopback)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output pcap path (default: wire/captures/<mode>.pcap)",
    )
    parser.add_argument(
        "--db-port",
        type=int,
        default=default_db_port(),
        help="Postgres port to include in the capture (claim-2 evidence; "
        "default: DATABASE_URL's port)",
    )
    parser.add_argument(
        "--search-workload",
        action="store_true",
        help="also run the P5-3 search workload (ADR-0070); default output "
        "wire/captures/<mode>-search.pcap",
    )
    args = parser.parse_args(argv)

    suffix = "-search" if args.search_workload else ""
    out = args.out or (CAPTURE_DIR / f"{args.mode}{suffix}.pcap")
    if args.interface is not None and not is_allowed_interface(args.interface):
        parser.error(f"refusing interface {args.interface!r}: {CAPTURE_RULE}")
    try:
        _require_dumpcap()
    except CaptureToolUnavailable as exc:
        parser.error(str(exc))

    scheme = "https" if args.mode == "tls" else "http"
    canaries = out.with_name(f"{out.stem}.canaries.json")
    capture_scenario(
        _run_scenario_via_subprocess(
            scheme, canaries, search_workload=args.search_workload
        ),
        output_path=out,
        interface=args.interface,
        db_port=args.db_port,
    )
    print(f"{args.mode} capture written to {out}")
    print(f"canary manifest written to {canaries} (never commit it)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
