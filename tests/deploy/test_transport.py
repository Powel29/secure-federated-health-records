"""TLS changes client URLs and validates the configured trust bundle."""

from pathlib import Path

import pytest

from deploy.config import STORE_SSLMODE, configure_transport

# Everything configure_transport may write into os.environ.
_WRITTEN = (
    "SSL_CERT_FILE",
    "SSL_CERTFILE",
    "SSL_KEYFILE",
    "PGSSLMODE",
    "PGSSLROOTCERT",
)


def _clean_env(monkeypatch) -> None:
    # setenv first so monkeypatch restores (deletes) what configure_transport
    # writes into os.environ; a bare delenv of an absent name is not undone.
    for name in _WRITTEN:
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.delenv("DATABASE_URL", raising=False)


def _tls_dir(tmp_path, *, store: bool = True):
    bundle = tmp_path / "trust" / "ca-bundle.crt"
    bundle.parent.mkdir()
    bundle.write_text("test trust bundle")
    if store:
        (tmp_path / "trust" / "store.crt").write_text("test store cert")
    return bundle


def test_tls_upgrades_all_endpoint_maps_and_uses_bundle(monkeypatch, tmp_path):
    bundle = _tls_dir(tmp_path)
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    _clean_env(monkeypatch)
    monkeypatch.setenv("AUDIT_SERVICE_URL", "http://audit:8020")
    monkeypatch.setenv("AUTHORITY_URLS", "med=http://med:8010,net=http://net:8011")
    configure_transport("audit")
    import os

    assert os.environ["AUDIT_SERVICE_URL"] == "https://audit:8020"
    assert os.environ["AUTHORITY_URLS"] == "med=https://med:8010,net=https://net:8011"
    assert Path(os.environ["SSL_CERT_FILE"]) == bundle
    assert Path(os.environ["SSL_CERTFILE"]) == tmp_path / "audit" / "audit.crt"


def test_tls_missing_trust_bundle_fails_before_starting(monkeypatch, tmp_path):
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    monkeypatch.setenv("SSL_CERT_FILE", "")
    monkeypatch.delenv("SSL_CERT_FILE")
    with pytest.raises(RuntimeError, match="TLS trust bundle missing"):
        configure_transport("audit")


def test_tls_profile_requires_verified_tls_to_the_store(monkeypatch, tmp_path):
    """ADR-0071: every store connection in the TLS profile is verify-full."""
    _tls_dir(tmp_path)
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    _clean_env(monkeypatch)
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres@127.0.0.1:55433/ehr")
    configure_transport("facility-a")
    import os

    assert os.environ["PGSSLMODE"] == STORE_SSLMODE == "verify-full"
    assert Path(os.environ["PGSSLROOTCERT"]) == tmp_path / "trust" / "store.crt"


def test_tls_profile_overrides_a_weaker_ambient_sslmode(monkeypatch, tmp_path):
    _tls_dir(tmp_path)
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    _clean_env(monkeypatch)
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres@127.0.0.1:55433/ehr")
    monkeypatch.setenv("PGSSLMODE", "disable")
    configure_transport()
    import os

    assert os.environ["PGSSLMODE"] == "verify-full"


@pytest.mark.parametrize("mode", ["disable", "prefer", "require", "verify-ca"])
def test_tls_profile_refuses_a_database_url_that_weakens_tls(
    monkeypatch, tmp_path, mode
):
    """A DSN's sslmode beats the environment in libpq, so it is refused."""
    _tls_dir(tmp_path)
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    _clean_env(monkeypatch)
    monkeypatch.setenv(
        "DATABASE_URL", f"postgresql://postgres@127.0.0.1:55433/ehr?sslmode={mode}"
    )
    with pytest.raises(RuntimeError, match=f"sslmode='{mode}'"):
        configure_transport()


def test_tls_profile_without_the_store_cert_fails_before_starting(
    monkeypatch, tmp_path
):
    _tls_dir(tmp_path, store=False)
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    _clean_env(monkeypatch)
    with pytest.raises(RuntimeError, match="store TLS certificate missing"):
        configure_transport()


def test_plain_profile_leaves_the_store_link_alone(monkeypatch, tmp_path):
    """capture-plain keeps a plaintext store link: claim 2 reads it (P5-5)."""
    monkeypatch.setenv("TLS_ENABLED", "false")
    _clean_env(monkeypatch)
    configure_transport("facility-a")
    import os

    assert "PGSSLMODE" not in os.environ
    assert "PGSSLROOTCERT" not in os.environ
