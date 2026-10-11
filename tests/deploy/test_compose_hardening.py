"""The Compose deployment's hardening stays in place (review N12, N14, F1, F14).

These read the deployment files rather than starting containers, so they run
everywhere; each pins one property a later edit could silently undo.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from deploy import seed_portal
from deploy.config import env_flag

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))


def test_compose_store_never_uses_trust_auth(compose):
    """N12: any local process could otherwise connect as superuser."""
    text = (DEPLOY / "docker-compose.yml").read_text(encoding="utf-8")
    assert "HOST_AUTH_METHOD" not in text  # e.g. POSTGRES_HOST_AUTH_METHOD: trust
    env = compose["services"]["store"]["environment"]
    assert "POSTGRES_HOST_AUTH_METHOD" not in env
    assert ":?" in env["POSTGRES_PASSWORD"]  # Compose refuses to start without it


def test_every_published_port_is_loopback_only(compose):
    for name, service in compose["services"].items():
        for mapping in service.get("ports", []):
            assert str(mapping).startswith("127.0.0.1:"), f"{name} publishes {mapping}"


def test_image_runs_unprivileged_and_binds_loopback_by_default():
    """N14: no root by default, and no image-wide 0.0.0.0 bind."""
    dockerfile = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "\nUSER app" in dockerfile
    assert "ENV HOST" not in dockerfile


def test_no_service_can_turn_certificate_checks_off(compose):
    """N14: the lone TLS_VERIFY=false escape hatch is gone from Compose."""
    for name, service in compose["services"].items():
        assert "TLS_VERIFY" not in service.get("environment", {}), name


def test_facilities_get_trust_anchors_from_the_pki_job(compose):
    """F1: facilities start only after the PKI exists, and read it from a mount."""
    for facility in ("facility-a", "facility-b"):
        service = compose["services"][facility]
        assert service["depends_on"]["pki"]["condition"] == (
            "service_completed_successfully"
        )
        assert service["environment"]["FEDERATION_ROOT_CERT"] == "/trust/root.crt"
        assert "./pki/trust:/trust:ro" in service["volumes"]
        # Only certificates: the private-key file stays out of the container.
        assert not any("federation-pki.json" in v for v in service["volumes"])


def test_authorities_allowlist_their_authoring_callers(compose):
    """F14 interim: authoring keys go only to the named containers."""
    for authority in ("authority-med", "authority-net"):
        env = compose["services"][authority]["environment"]
        assert "AUTHORING_CALLERS" in env


@pytest.mark.parametrize(
    ("raw", "default", "expected"),
    [("", True, True), ("", False, False), ("YES", False, True), ("0", True, False)],
)
def test_env_flag_parses_one_way(monkeypatch, raw, default, expected):
    monkeypatch.setenv("SOME_FLAG", raw)
    assert env_flag("SOME_FLAG", default) is expected


def test_env_flag_rejects_a_typo(monkeypatch):
    monkeypatch.setenv("SOME_FLAG", "ture")
    with pytest.raises(ValueError, match="SOME_FLAG"):
        env_flag("SOME_FLAG")


def test_portal_takes_the_store_password_from_deploy_env(monkeypatch, tmp_path):
    """N12: the documented password-less portal DSN works against the store."""
    env_file = tmp_path / ".env"
    env_file.write_text("POSTGRES_PASSWORD=s3cret\n", encoding="utf-8")
    monkeypatch.setattr(seed_portal, "COMPOSE_ENV", env_file)
    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.setenv("PGPASSWORD", "")
    monkeypatch.delenv("PGPASSWORD")

    seed_portal._use_compose_store_password("postgresql://postgres@127.0.0.1:55433/ehr")
    import os

    assert os.environ["PGPASSWORD"] == "s3cret"
