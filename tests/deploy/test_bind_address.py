"""Review F16: services bind to loopback unless deployment says otherwise.

ARCHITECTURE.md §8 drops service authentication on the premise of "no public
exposure", so the default bind address must not be every interface.
"""

from __future__ import annotations

import re

import pytest

from deploy import entrypoint
from deploy.run_scenario import REPO_ROOT


@pytest.fixture()
def captured_host(monkeypatch):
    seen: dict[str, object] = {}

    def fake_run(app, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(entrypoint.uvicorn, "run", fake_run)
    monkeypatch.setenv("SERVICE_ROLE", "authority")
    monkeypatch.delenv("TLS_ENABLED", raising=False)
    return seen


def test_entrypoint_defaults_to_loopback(captured_host, monkeypatch):
    monkeypatch.delenv("HOST", raising=False)
    entrypoint.main()
    assert captured_host["host"] == "127.0.0.1"


def test_explicit_host_is_honoured(captured_host, monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")  # noqa: S104 -- testing the explicit override
    entrypoint.main()
    assert captured_host["host"] == "0.0.0.0"  # noqa: S104


def test_compose_publishes_ports_on_host_loopback_only():
    compose = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    mappings = re.findall(r'^\s*-\s*"([^"]*:\d+)"\s*$', compose, flags=re.MULTILINE)
    assert mappings, "no published ports found -- the check would be vacuous"
    for mapping in mappings:
        assert mapping.startswith("127.0.0.1:"), mapping
