"""Service identities and signed test clients for the API suites (ADR-0066).

Every federation service now takes only signed requests, so a test talks to an
app through a :class:`~fastapi.testclient.TestClient` whose requests are signed
as some federation service -- usually ``bootstrap``, which every route that
seeding and scripts use allows. Negative tests sign as a kind a route refuses,
or do not sign at all.
"""

from __future__ import annotations

from typing import Any

from api.service_auth import ServiceIdentity, SignedRequestAuth
from crypto_core import certificate_to_pem, generate_ec_keypair
from fastapi.testclient import TestClient
from identity.certificates import issue_service_certificate
from identity.root_anchor import RootAnchor

BASE_URL = "http://testserver"

# service_id -> kind, as deploy/bootstrap issues them.
KINDS = {
    "authority-med": "authority",
    "authority-net": "authority",
    "audit-service": "audit",
    "facility-a": "facility",
    "facility-b": "facility",
    "custodian": "custodian",
    "portal": "portal",
    "bootstrap": "bootstrap",
}


class ServicePKI:
    """Root-issued service identities for one test federation, made on demand."""

    def __init__(self, root: RootAnchor) -> None:
        self.root = root
        self._identities: dict[str, ServiceIdentity] = {}

    def identity(self, service_id: str, kind: str | None = None) -> ServiceIdentity:
        if service_id not in self._identities:
            key, public_key = generate_ec_keypair()
            kind = kind or KINDS[service_id]
            certificate = issue_service_certificate(
                self.root, service_id, kind, public_key
            )
            self._identities[service_id] = ServiceIdentity(
                service_id=service_id,
                kind=kind,
                signing_key=key,
                certificate_pem=certificate_to_pem(certificate).decode("ascii"),
            )
        return self._identities[service_id]

    def auth(
        self, caller: str, recipient: str, base_url: str = BASE_URL
    ) -> SignedRequestAuth:
        return SignedRequestAuth(self.identity(caller), {base_url: recipient})

    def client(
        self,
        app: Any,
        recipient: str,
        *,
        caller: str = "bootstrap",
        base_url: str = BASE_URL,
        **kwargs: Any,
    ) -> TestClient:
        """A TestClient for ``app`` (service ``recipient``), signing as ``caller``."""
        client = TestClient(app, base_url=base_url, **kwargs)
        client.auth = self.auth(caller, recipient, base_url)
        return client
