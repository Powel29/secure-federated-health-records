"""The Compose deployment's hardening stays in place (N12, N14, F1, ADR-0066).

These read the deployment files rather than starting containers, so they run
everywhere; each pins one property a later edit could silently undo.
"""

from __future__ import annotations

import secrets
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


SERVICE_IDS = {
    "authority-med": "authority-med",
    "authority-net": "authority-net",
    "audit": "audit-service",
    "facility-a": "facility-a",
    "facility-b": "facility-b",
    "custodian": "custodian",
    "portal": "portal",
}


def test_every_service_mounts_only_its_own_signing_identity(compose):
    """ADR-0066: each container signs as itself and holds no other's key."""
    for name, service_id in SERVICE_IDS.items():
        service = compose["services"][name]
        env = service["environment"]
        assert env["SERVICE_KEY_FILE"] == "/identity/service.key", name
        assert env["SERVICE_CERT_FILE"] == "/identity/service.crt", name
        identity_mounts = [v for v in service["volumes"] if "pki/services" in v]
        assert identity_mounts == [f"./pki/services/{service_id}:/identity:ro"], name
        assert not any(v.startswith("./pki:") for v in service["volumes"]), name


def test_the_address_allowlist_is_gone(compose):
    """F14's interim allowlist is replaced by signed requests (ADR-0066)."""
    text = (DEPLOY / "docker-compose.yml").read_text(encoding="utf-8")
    assert "AUTHORING_CALLERS" not in text


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
    store_password = secrets.token_urlsafe(16)
    env_file = tmp_path / ".env"
    env_file.write_text(f"POSTGRES_PASSWORD={store_password}\n", encoding="utf-8")
    monkeypatch.setattr(seed_portal, "COMPOSE_ENV", env_file)
    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.setenv("PGPASSWORD", "")
    monkeypatch.delenv("PGPASSWORD")

    seed_portal._use_compose_store_password("postgresql://postgres@127.0.0.1:55433/ehr")
    import os

    assert os.environ["PGPASSWORD"] == store_password


def test_store_serves_tls_only_in_the_tls_profile(compose):
    """ADR-0071: the store wraps its entrypoint to serve TLS and refuse plaintext."""
    store = compose["services"]["store"]
    assert store["entrypoint"] == ["sh", "/store-entrypoint.sh"]
    assert store["environment"]["TLS_ENABLED"] == "${TLS_ENABLED:-false}"
    assert "./store-entrypoint.sh:/store-entrypoint.sh:ro" in store["volumes"]
    # Only the store's own key directory, never the whole certs tree (ADR-0047).
    assert "../wire/certs/store:/tls/store:ro" in store["volumes"]
    script = (DEPLOY / "store-entrypoint.sh").read_bytes()
    assert b"\r\n" not in script  # runs under sh in a Linux container
    text = script.decode("utf-8")
    assert "hostnossl all all all reject" in text
    assert "-c ssl=on" in text


def test_every_store_client_follows_the_tls_profile(compose):
    """Each service that dials the store gets the flag and the store's cert."""
    for name, service in compose["services"].items():
        env = service.get("environment", {})
        if "DATABASE_URL" not in env:
            continue
        assert "sslmode" not in env["DATABASE_URL"], name
        assert env.get("TLS_ENABLED") == "${TLS_ENABLED:-false}", name
        assert "../wire/certs/trust:/tls/trust:ro" in service.get("volumes", []), name
    # The migrate job applies the profile before connecting (deploy.migrate).
    assert compose["services"]["migrate"]["entrypoint"] == [
        "python",
        "-m",
        "deploy.migrate",
    ]
