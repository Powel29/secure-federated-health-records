"""Tests for the P4-6 capture harness (wire/capture.py).

The BPF filter and tool-availability guard are unit-testable without tshark; an
actual capture needs ``dumpcap`` and a running federation, so that test skips
cleanly when the binary is absent (the repo's Postgres-skip convention).
"""

from __future__ import annotations

import shutil

import pytest

from wire.capture import (
    CaptureToolUnavailable,
    _federation_bpf,
    _require_dumpcap,
    capture_scenario,
    default_loopback_interface,
)
from wire.tls import SERVICES


def test_bpf_filter_pins_only_federation_ports():
    bpf = _federation_bpf()
    for port in SERVICES.values():
        assert f"port {port}" in bpf
    # loopback-only intent: it is a tcp port filter, not a broad any-host capture
    assert bpf.startswith("tcp and (")


def test_default_loopback_interface_is_a_loopback_name():
    assert default_loopback_interface() in {"lo", "lo0", "\\Device\\NPF_Loopback"}


def test_require_dumpcap_raises_clearly_when_absent():
    if shutil.which("dumpcap") is not None:
        pytest.skip("dumpcap present; cannot test the absent-tool path here")
    with pytest.raises(CaptureToolUnavailable, match="dumpcap not found"):
        _require_dumpcap()


def test_capture_scenario_needs_dumpcap():
    """Without dumpcap, capture fails closed rather than pretending to record."""
    if shutil.which("dumpcap") is not None:
        pytest.skip("dumpcap present; the missing-tool path is not exercised")
    ran = []
    with pytest.raises(CaptureToolUnavailable):
        capture_scenario(lambda: ran.append(True), output_path=None)  # type: ignore[arg-type]
    assert ran == []  # scenario never started because capture could not begin
