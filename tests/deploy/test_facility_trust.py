"""A facility loads its break-glass trust anchors from config or does not start.

Review F1: the root and facility CAs used to arrive in the request body, so a
caller could bring their own. They now come from files bootstrap writes before
the facilities start.
"""

from __future__ import annotations

import pytest

from deploy import bootstrap
from deploy.asgi.facility import load_trust


def test_trust_bundle_round_trips_into_facility_trust(tmp_path, monkeypatch):
    _, pki = bootstrap.generate_federation_pki(["facility-a", "facility-b"])
    bootstrap.write_trust_bundle(tmp_path, pki)
    # Certificates only: no private key reaches the directory facilities mount.
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert "PRIVATE KEY" not in path.read_text(encoding="ascii")

    monkeypatch.setenv("FEDERATION_ROOT_CERT", str(tmp_path / "root.crt"))
    monkeypatch.setenv("FACILITY_CA_CERTS_DIR", str(tmp_path / "facility-cas"))
    monkeypatch.setenv("REVOKED_CLINICIAN_SERIALS", "12, 34")
    trust = load_trust()

    assert set(trust.facility_cas) == {"facility-a", "facility-b"}
    assert trust.revoked_serials == frozenset({12, 34})
    expected = bootstrap.facility_trust(pki)
    assert trust.root == expected.root


@pytest.mark.parametrize("missing", ["FEDERATION_ROOT_CERT", "FACILITY_CA_CERTS_DIR"])
def test_facility_refuses_to_start_without_trust_anchors(
    tmp_path, monkeypatch, missing
):
    _, pki = bootstrap.generate_federation_pki(["facility-a"])
    bootstrap.write_trust_bundle(tmp_path, pki)
    monkeypatch.setenv("FEDERATION_ROOT_CERT", str(tmp_path / "root.crt"))
    monkeypatch.setenv("FACILITY_CA_CERTS_DIR", str(tmp_path / "facility-cas"))
    monkeypatch.delenv(missing)
    with pytest.raises(RuntimeError, match="F1"):
        load_trust()


def test_facility_refuses_an_empty_ca_directory(tmp_path, monkeypatch):
    _, pki = bootstrap.generate_federation_pki(["facility-a"])
    bootstrap.write_trust_bundle(tmp_path, pki)
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("FEDERATION_ROOT_CERT", str(tmp_path / "root.crt"))
    monkeypatch.setenv("FACILITY_CA_CERTS_DIR", str(empty))
    with pytest.raises(RuntimeError, match="no facility CA certificates"):
        load_trust()


def test_saved_pki_reloads_with_a_working_root_key(tmp_path):
    """The Compose bootstrap job signs with the root the pki job generated."""
    root, pki = bootstrap.generate_federation_pki(["facility-a"])
    path = tmp_path / "federation-pki.json"
    bootstrap.save_federation_pki(path, root, pki)
    loaded_root, loaded_pki = bootstrap.load_federation_pki(path)
    assert loaded_pki == pki
    assert loaded_root.certificate == root.certificate
    assert loaded_root.public_key.public_numbers() == root.public_key.public_numbers()
