"""Threshold shares travel sealed to their recipient (review D6 step 2, ADR-0079).

Each test removes one property the control relies on -- a root-issued key
statement, the expected service kind, the recipient, record and index binding
-- and asserts the share is refused. The positive control in each case is the
same call with the property intact.
"""

from __future__ import annotations

import base64

import pytest
from breakglass.exceptions import SealedShareError
from breakglass.share_sealing import (
    SealedShare,
    ShareRecipient,
    ShareSealingKey,
    make_key_statement,
    open_sealed_share,
    seal_share,
    verify_key_statement,
)
from identity.root_anchor import generate_root_anchor

from tests.service_pki import ServicePKI

SHARE = (3, b"\x5a" * 33)


@pytest.fixture()
def pki():
    root = generate_root_anchor()
    return root, ServicePKI(root)


def _statement(services: ServicePKI, service_id: str, key: ShareSealingKey):
    identity = services.identity(service_id)
    return make_key_statement(
        key,
        service_id=identity.service_id,
        kind=identity.kind,
        signing_key=identity.signing_key,
        certificate_pem=identity.certificate_pem,
    )


class TestKeyStatement:
    def test_positive_control_facility_statement_verifies(self, pki):
        root, services = pki
        key = ShareSealingKey.generate()
        recipient = verify_key_statement(
            _statement(services, "facility-a", key),
            trusted_root=root.certificate,
            kind="facility",
        )
        assert recipient == ShareRecipient("facility-a", key.public_key)

    def test_statement_from_another_root_is_refused(self, pki):
        """A service certificate from a rogue root is not a federation service."""
        root, _services = pki
        rogue = ServicePKI(generate_root_anchor())
        statement = _statement(rogue, "facility-a", ShareSealingKey.generate())
        with pytest.raises(SealedShareError):
            verify_key_statement(
                statement, trusted_root=root.certificate, kind="facility"
            )

    def test_statement_of_another_kind_is_refused(self, pki):
        """The custodian's key cannot stand in for a facility gate's."""
        root, services = pki
        statement = _statement(services, "custodian", ShareSealingKey.generate())
        with pytest.raises(SealedShareError, match="not a facility"):
            verify_key_statement(
                statement, trusted_root=root.certificate, kind="facility"
            )

    def test_substituted_public_key_is_refused(self, pki):
        """An on-path attacker swapping in its own key breaks the signature."""
        root, services = pki
        statement = _statement(services, "facility-a", ShareSealingKey.generate())
        attacker = ShareSealingKey.generate()
        forged = statement.model_copy(update={"public_key": attacker.public_key})
        with pytest.raises(SealedShareError):
            verify_key_statement(forged, trusted_root=root.certificate, kind="facility")

    def test_statement_renamed_to_another_service_is_refused(self, pki):
        root, services = pki
        statement = _statement(services, "facility-a", ShareSealingKey.generate())
        renamed = statement.model_copy(update={"service_id": "facility-b"})
        with pytest.raises(SealedShareError):
            verify_key_statement(
                renamed, trusted_root=root.certificate, kind="facility"
            )


class TestSealedShare:
    def _sealed(self):
        key = ShareSealingKey.generate()
        sealed = seal_share(
            SHARE,
            record_id="rec-1",
            recipient=ShareRecipient("facility-a", key.public_key),
        )
        return key, sealed

    def test_positive_control_recipient_opens(self):
        key, sealed = self._sealed()
        assert (
            open_sealed_share(
                sealed, record_id="rec-1", service_id="facility-a", key=key
            )
            == SHARE
        )
        assert SHARE[1].hex() not in sealed.model_dump_json()

    def test_another_services_key_cannot_open(self):
        _key, sealed = self._sealed()
        with pytest.raises(SealedShareError):
            open_sealed_share(
                sealed,
                record_id="rec-1",
                service_id="facility-a",
                key=ShareSealingKey.generate(),
            )

    def test_redirected_to_another_service_does_not_open(self):
        """Recipient binding: the right key under another service id fails."""
        key, sealed = self._sealed()
        with pytest.raises(SealedShareError):
            open_sealed_share(
                sealed, record_id="rec-1", service_id="facility-b", key=key
            )

    def test_moved_to_another_record_does_not_open(self):
        key, sealed = self._sealed()
        with pytest.raises(SealedShareError):
            open_sealed_share(
                sealed, record_id="rec-2", service_id="facility-a", key=key
            )

    def test_changed_index_does_not_open(self):
        key, sealed = self._sealed()
        with pytest.raises(SealedShareError):
            open_sealed_share(
                sealed.model_copy(update={"x": 1}),
                record_id="rec-1",
                service_id="facility-a",
                key=key,
            )

    def test_tampered_ciphertext_does_not_open(self):
        key, sealed = self._sealed()
        raw = bytearray(base64.b64decode(sealed.ciphertext_b64))
        raw[0] ^= 1
        tampered = SealedShare(
            **{
                **sealed.model_dump(),
                "ciphertext_b64": base64.b64encode(bytes(raw)).decode(),
            }
        )
        with pytest.raises(SealedShareError):
            open_sealed_share(
                tampered, record_id="rec-1", service_id="facility-a", key=key
            )
