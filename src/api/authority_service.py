"""Standalone Attribute Authority Service (P4-2, C14/C6, ARCHITECTURE.md §7).

Runs one federated attribute authority (e.g. ``authority-med``,
``authority-net``) as its own process, reachable over HTTP -- ARCHITECTURE.md
§7 bootstrap step 3: "Start the authority services; each generates attribute
key material and registers its public parameters with the anchor." A
facility node calls this service to issue or verify credentials and to
exchange a holder's valid credential for the attribute key material the
policy engine needs (``AttributeAuthority.get_attribute_key``), rather than
holding that key material itself.

Invariants:
- CONVENTIONS.md §2 rule 10: no cryptography in route handlers. Every
  signature, key mint, and credential check happens inside
  ``authority.issuance`` / ``authority.revocation``.
- The authority's private signing key never leaves this process; only its
  public key (``GET /public-key``) and, once bootstrap has registered one,
  its certificate (``GET /certificate``) are ever returned.
- Every route but health, public key and certificate read takes only a signed
  request from a federation service whose kind the route allows (ADR-0066).
  Authoring keys go to facilities, the custodian and bootstrap only.
- Ephemeral by design: ARCHITECTURE.md §7 reseeds the whole federation fresh
  on every bootstrap run, so this service generates its own signing keypair
  at startup rather than loading one from disk (ADR-0039). Issued
  credentials and minted attribute keys likewise live only for this
  process's lifetime.
"""

from __future__ import annotations

import base64
import datetime
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Annotated

from authority.exceptions import (
    CredentialExpiredError,
    CredentialNotYetValidError,
    CredentialRevokedError,
    CredentialStatusError,
    PossessionError,
    UnauthorizedAttributeError,
)
from authority.issuance import (
    DEFAULT_CREDENTIAL_VALID_DAYS,
    AttributeAuthority,
    generate_authority,
    issue_credential,
    issue_owner_credential,
    verify_credential,
)
from authority.possession import verify_key_release_possession
from breakglass import ConsumedRequestIds
from breakglass.exceptions import BreakglassError
from crypto_core import certificate_from_pem, certificate_public_key, public_key_to_pem
from crypto_core.exceptions import (
    CertificateExpiredError,
    InvalidSignatureError,
    KeyFormatError,
)
from cryptography.x509 import Certificate
from fastapi import Depends, FastAPI, HTTPException, Request, status
from identity import (
    PERSON_ROLES,
    ChainValidationError,
    SubjectCertificateError,
    validate_subject_certificate,
)

from api.authority_schemas import (
    AttributeKeyReleaseRequest,
    AttributeKeyResponse,
    AuthorAttributeKeyRequest,
    CertificateResponse,
    CredentialStatusRequest,
    CredentialStatusResponse,
    HealthResponse,
    IssueCredentialRequest,
    IssueCredentialResponse,
    PublicKeyResponse,
    RevokeCredentialResponse,
    SetCertificateRequest,
    VerifyCredentialRequest,
    VerifyCredentialResponse,
)
from api.service_auth import ServiceAuthConfig, install_service_auth


def get_authority(request: Request) -> AttributeAuthority:
    """Extract the wrapped AttributeAuthority from application state."""
    return request.app.state.authority


AuthorityDep = Annotated[AttributeAuthority, Depends(get_authority)]

_CREDENTIAL_ERRORS = (
    InvalidSignatureError,
    CredentialStatusError,
    CredentialRevokedError,
    CredentialNotYetValidError,
    CredentialExpiredError,
)


_ANY_SERVICE = frozenset({"facility", "custodian", "portal", "bootstrap"})

# Which kinds of federation service may call each route (ADR-0066). The
# authoring key is the same key ``/attribute-keys/release`` gates behind a
# credential (ADR-0026), so only the services that seal policies get it: the
# custodian and bootstrap at ingest, a facility at its expiry rotation
# (ADR-0069). This replaces the review F14 interim address allowlist.
AUTHORITY_PERMISSIONS: dict[tuple[str, str], frozenset[str]] = {
    ("PUT", "/certificate"): frozenset({"bootstrap"}),
    ("POST", "/credentials/issue"): frozenset({"bootstrap"}),
    ("POST", "/credentials/verify"): _ANY_SERVICE,
    ("POST", "/credentials/status"): _ANY_SERVICE,
    ("POST", "/credentials/{serial}/revoke"): frozenset({"bootstrap"}),
    ("POST", "/attribute-keys/release"): frozenset({"custodian", "bootstrap"}),
    ("POST", "/attribute-keys/author"): frozenset(
        {"custodian", "facility", "bootstrap"}
    ),
}
AUTHORITY_PUBLIC_ROUTES = frozenset(
    {("GET", "/health"), ("GET", "/public-key"), ("GET", "/certificate")}
)


@dataclass(frozen=True)
class SubjectTrust:
    """Where subjects' certificates must come from (ADR-0082).

    A key is released only to a request its credential's subject signed,
    under a key certified by one of these facility CAs.
    """

    root: Certificate
    facility_cas: Mapping[str, Certificate]
    revoked_serials: frozenset[int] = field(default_factory=frozenset)


_POSSESSION_ERRORS = (
    ChainValidationError,
    CertificateExpiredError,
    SubjectCertificateError,
    PossessionError,
    InvalidSignatureError,
    BreakglassError,  # envelope expired, wrong operation or recipient, replayed
)


def create_authority_app(
    authority_id: str,
    owned_attribute_names: frozenset[str],
    authority: AttributeAuthority | None = None,
    *,
    service_root: Certificate,
    subject_trust: SubjectTrust | None = None,
) -> FastAPI:
    """Create and configure the standalone Attribute Authority Service application.

    Args:
        authority_id: This authority's identifier (e.g. ``"authority-med"``).
        owned_attribute_names: The attribute names this authority may issue
            (its ADR-0019 namespace), e.g. ``frozenset({"role"})``.
        authority: Optional pre-built :class:`AttributeAuthority` (tests
            supply a fixed one). Defaults to a freshly generated one --
            ARCHITECTURE.md §7 step 3: "each generates attribute key
            material."
        service_root: The federation root callers' service certificates must
            chain to (ADR-0066). This service's id is ``authority_id``.
        subject_trust: The facility CAs subjects' certificates chain through.
            Without them no key is released (503): a release must prove the
            credential's subject is asking (ADR-0082).

    Returns:
        A configured FastAPI application.
    """
    auth = authority or generate_authority(authority_id, owned_attribute_names)
    # One-time ids of possession envelopes already used here (ADR-0082).
    release_replay = ConsumedRequestIds()

    app = FastAPI(
        title=f"Attribute Authority Service ({authority_id})",
        description="Federated Break-Glass EHR -- multi-authority attribute issuance",
        version="1.0.0",
    )
    app.state.authority = auth
    app.state.certificate_pem: str | None = None

    # --- Health & identity -----------------------------------------------

    @app.get("/health", response_model=HealthResponse)
    def health_check() -> HealthResponse:
        """Report readiness."""
        return HealthResponse(authority_id=authority_id)

    @app.get("/public-key", response_model=PublicKeyResponse)
    def public_key_endpoint(authority: AuthorityDep) -> PublicKeyResponse:
        """Publish this authority's public key for credential verification."""
        return PublicKeyResponse(
            public_key_pem=public_key_to_pem(authority.public_key).decode("ascii")
        )

    @app.get("/certificate", response_model=CertificateResponse)
    def get_certificate() -> CertificateResponse:
        """Return this authority's root-issued certificate, if registered yet."""
        return CertificateResponse(certificate_pem=app.state.certificate_pem)

    @app.put("/certificate", response_model=CertificateResponse)
    def set_certificate(payload: SetCertificateRequest) -> CertificateResponse:
        """Register this authority's root-signed certificate (bootstrap step 3).

        Called by the deployment bootstrap script (P4-3) after it fetches
        this authority's public key, has the root anchor sign a certificate
        for it, and hands the result back -- this service never holds the
        root's private key itself.
        """
        app.state.certificate_pem = payload.certificate_pem
        return CertificateResponse(certificate_pem=app.state.certificate_pem)

    # --- Credential issuance & verification (C6, §8 credential lifecycle) --

    @app.post(
        "/credentials/issue",
        response_model=IssueCredentialResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def issue(
        payload: IssueCredentialRequest, authority: AuthorityDep
    ) -> IssueCredentialResponse:
        """Issue a signed attribute credential (or an ADR-0016 owner credential)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        valid_from = payload.valid_from or now
        valid_until = payload.valid_until or (
            valid_from + datetime.timedelta(days=DEFAULT_CREDENTIAL_VALID_DAYS)
        )
        try:
            if payload.owner:
                credential = issue_owner_credential(
                    authority,
                    patient_id=payload.subject_id,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
            else:
                credential = issue_credential(
                    authority,
                    subject_id=payload.subject_id,
                    attribute=payload.attribute,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
        except UnauthorizedAttributeError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"cannot issue outside owned namespace: {exc}",
            ) from exc
        return IssueCredentialResponse(credential=credential)

    @app.post("/credentials/verify", response_model=VerifyCredentialResponse)
    def verify(
        payload: VerifyCredentialRequest, authority: AuthorityDep
    ) -> VerifyCredentialResponse:
        """Verify a credential's signature, status, validity window, and revocation."""
        try:
            verify_credential(
                payload.credential,
                authority.public_key,
                revocation_registry=authority.revocation_registry,
            )
        except _CREDENTIAL_ERRORS as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"credential invalid ({exc.__class__.__name__}): {exc}",
            ) from exc
        return VerifyCredentialResponse(valid=True)

    @app.post("/credentials/status", response_model=CredentialStatusResponse)
    def credential_status(
        payload: CredentialStatusRequest, authority: AuthorityDep
    ) -> CredentialStatusResponse:
        """Classify a credential's current lifecycle status (query only)."""
        return CredentialStatusResponse(
            status=authority.get_credential_status(payload.credential).value
        )

    @app.post("/credentials/{serial}/revoke", response_model=RevokeCredentialResponse)
    def revoke(
        serial: str, authority: AuthorityDep, reason: str = ""
    ) -> RevokeCredentialResponse:
        """Revoke a previously issued credential by its serial (P2-6)."""
        entry = authority.revoke_credential(serial, reason=reason)
        return RevokeCredentialResponse(
            serial=entry.serial, revoked_at=entry.revoked_at, reason=entry.reason
        )

    # --- Attribute key material (C6, §8: "the attribute key material the
    # --- policy engine seals leaf shares to") ------------------------------

    @app.post("/attribute-keys/release", response_model=AttributeKeyResponse)
    def release_attribute_key(
        payload: AttributeKeyReleaseRequest, authority: AuthorityDep
    ) -> AttributeKeyResponse:
        """Exchange a valid credential for its key, if its subject is asking.

        The request must carry a possession envelope its subject signed,
        under a certificate from a configured facility CA (ADR-0082, review
        F15): a copy of the credential alone releases nothing.
        """
        if subject_trust is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="no subject trust anchors configured; no key is released",
            )
        try:
            certificate = certificate_from_pem(
                payload.subject_certificate_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid subject certificate PEM: {exc}",
            ) from exc
        try:
            validate_subject_certificate(
                certificate,
                subject_id=payload.credential.subject_id,
                roles=PERSON_ROLES,
                facility_cas=subject_trust.facility_cas,
                trusted_root=subject_trust.root,
                revoked_serials=subject_trust.revoked_serials,
            )
            verify_key_release_possession(
                payload.credential,
                payload.possession,
                certificate_public_key(certificate),
                authority_id=authority_id,
                consumed_store=release_replay,
            )
        except _POSSESSION_ERRORS as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "subject did not prove possession "
                    f"({exc.__class__.__name__}): {exc}"
                ),
            ) from exc
        try:
            key = authority.get_attribute_key(payload.credential)
        except UnauthorizedAttributeError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"credential not honoured by this authority: {exc}",
            ) from exc
        except _CREDENTIAL_ERRORS as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"credential invalid ({exc.__class__.__name__}): {exc}",
            ) from exc
        return AttributeKeyResponse(
            name=payload.credential.attribute.name,
            value=payload.credential.attribute.value,
            key_b64=base64.b64encode(key).decode("ascii"),
        )

    @app.post("/attribute-keys/author", response_model=AttributeKeyResponse)
    def author_attribute_key(
        payload: AuthorAttributeKeyRequest, authority: AuthorityDep
    ) -> AttributeKeyResponse:
        """Mint (or fetch) the authoring-side key for an owned attribute leaf.

        The authoring key is the same key ``/attribute-keys/release`` gates
        behind a credential (ADR-0026), so only a signed request from a
        policy-sealing service kind reaches this (ADR-0066, replacing the
        review F14 interim address allowlist).
        """
        try:
            key = authority.attribute_key(payload.name, payload.value)
        except UnauthorizedAttributeError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"authority does not own this attribute namespace: {exc}",
            ) from exc
        return AttributeKeyResponse(
            name=payload.name,
            value=payload.value,
            key_b64=base64.b64encode(key).decode("ascii"),
        )

    install_service_auth(
        app,
        ServiceAuthConfig(
            service_id=authority_id,
            trusted_root=service_root,
            permissions=AUTHORITY_PERMISSIONS,
            public_routes=AUTHORITY_PUBLIC_ROUTES,
            replay=ConsumedRequestIds(),
        ),
    )
    return app
