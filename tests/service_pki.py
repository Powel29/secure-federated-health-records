"""Service identities and signed test clients for the API suites (ADR-0066).

Every federation service now takes only signed requests, so a test talks to an
app through a :class:`~fastapi.testclient.TestClient` whose requests are signed
as some federation service -- usually ``bootstrap``, which every route that
seeding and scripts use allows. Negative tests sign as a kind a route refuses,
or do not sign at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from api.authority_service import SubjectTrust
from api.service_auth import ServiceIdentity, SignedRequestAuth
from contracts import AttributeCredential
from crypto_core import certificate_to_pem, generate_ec_keypair
from crypto_core.types import ECPrivateKey
from cryptography.x509 import Certificate
from custodian import sign_key_release_possession
from fastapi.testclient import TestClient
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
    issue_patient_certificate,
    issue_service_certificate,
)
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


@dataclass(frozen=True)
class Person:
    """A patient or clinician certified by a test facility CA."""

    subject_id: str
    signing_key: ECPrivateKey
    certificate_pem: str


class PersonPKI:
    """One test facility CA under ``root`` that certifies people (ADR-0075)."""

    def __init__(self, root: RootAnchor, facility_id: str = "facility-a") -> None:
        self.root = root
        self.facility_id = facility_id
        self.ca_key, ca_public = generate_ec_keypair()
        self.ca_certificate: Certificate = issue_facility_ca_certificate(
            root, facility_id, ca_public
        )

    @property
    def trust(self) -> SubjectTrust:
        return SubjectTrust(
            root=self.root.certificate,
            facility_cas={self.facility_id: self.ca_certificate},
        )

    def clinician(self, clinician_id: str) -> Person:
        key, public_key = generate_ec_keypair()
        certificate = issue_clinician_certificate(
            self.ca_key, self.ca_certificate, clinician_id, public_key
        )
        return Person(clinician_id, key, certificate_to_pem(certificate).decode())

    def patient(self, patient_id: str) -> Person:
        key, public_key = generate_ec_keypair()
        certificate = issue_patient_certificate(
            self.ca_key, self.ca_certificate, patient_id, public_key
        )
        return Person(patient_id, key, certificate_to_pem(certificate).decode())


def release_body(
    credential: dict[str, Any] | AttributeCredential, person: Person
) -> dict[str, Any]:
    """A key-release request ``person`` signed for ``credential`` (ADR-0075)."""
    cred = (
        credential
        if isinstance(credential, AttributeCredential)
        else AttributeCredential.model_validate(credential)
    )
    possession = sign_key_release_possession(
        signing_key=person.signing_key, credential=cred
    )
    return {
        "credential": cred.model_dump(mode="json"),
        "possession": possession.model_dump(mode="json"),
        "subject_certificate_pem": person.certificate_pem,
    }
