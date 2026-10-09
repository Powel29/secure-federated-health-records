"""TLS changes client URLs and validates the configured trust bundle."""

from pathlib import Path

import pytest

from deploy.config import configure_transport


def test_tls_upgrades_all_endpoint_maps_and_uses_bundle(monkeypatch, tmp_path):
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("test trust bundle")
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERTFILE", raising=False)
    monkeypatch.delenv("SSL_KEYFILE", raising=False)
    monkeypatch.setenv("AUDIT_SERVICE_URL", "http://audit:8020")
    monkeypatch.setenv("AUTHORITY_URLS", "med=http://med:8010,net=http://net:8011")
    configure_transport("audit")
    import os

    assert os.environ["AUDIT_SERVICE_URL"] == "https://audit:8020"
    assert os.environ["AUTHORITY_URLS"] == "med=https://med:8010,net=https://net:8011"
    assert Path(os.environ["SSL_CERT_FILE"]) == bundle
    assert Path(os.environ["SSL_CERTFILE"]) == tmp_path / "audit.crt"


def test_tls_missing_trust_bundle_fails_before_starting(monkeypatch, tmp_path):
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    with pytest.raises(RuntimeError, match="TLS trust bundle missing"):
        configure_transport("audit")
