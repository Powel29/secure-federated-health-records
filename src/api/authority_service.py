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
- Ephemeral by design: ARCHITECTURE.md §7 reseeds the whole federation fresh
  on every bootstrap run, so this service generates its own signing keypair
  at startup rather than loading one from disk (ADR-0039). Issued
  credentials and minted attribute keys likewise live only for this
  process's lifetime.
"""

from __future__ import annotations

import base64
import datetime
import ipaddress
import socket
from typing import Annotated

from authority.exceptions import (
    CredentialExpiredError,
    CredentialNotYetValidError,
    CredentialRevokedError,
    CredentialStatusError,
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
from crypto_core import public_key_to_pem
from crypto_core.exceptions import InvalidSignatureError
from fastapi import Depends, FastAPI, HTTPException, Request, status

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


# Who may call /attribute-keys/author until service authentication exists
# (review F14 interim; D5-a replaces this with signed request envelopes).
DEFAULT_AUTHORING_CALLERS = frozenset({"127.0.0.1", "::1"})


def _resolve_callers(callers: frozenset[str]) -> set[str]:
    """IP addresses for each allowlist entry; hostnames resolve at call time."""
    addresses: set[str] = set()
    for entry in callers:
        try:
            addresses.add(str(ipaddress.ip_address(entry)))
            continue
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(entry, None)
        except socket.gaierror:
            continue  # an unresolvable name allows nobody
        addresses.update(str(info[4][0]) for info in infos)
    return addresses


def create_authority_app(
    authority_id: str,
    owned_attribute_names: frozenset[str],
    authority: AttributeAuthority | None = None,
    *,
    authoring_callers: frozenset[str] = DEFAULT_AUTHORING_CALLERS,
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
        authoring_callers: Addresses or hostnames allowed to fetch authoring
            keys from ``/attribute-keys/author`` (review F14 interim).
            Defaults to loopback only.

    Returns:
        A configured FastAPI application.
    """
    auth = authority or generate_authority(authority_id, owned_attribute_names)

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
        """Exchange a valid credential for the attribute key it certifies."""
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
        payload: AuthorAttributeKeyRequest, authority: AuthorityDep, request: Request
    ) -> AttributeKeyResponse:
        """Mint (or fetch) the authoring-side key for an owned attribute leaf.

        The authoring key is the same key ``/attribute-keys/release`` gates
        behind a credential (ADR-0026), so only allowlisted authoring services
        may call this (review F14 interim). Those callers are trusted parties
        by construction; signed service requests (D5-a) replace the address
        check.
        """
        caller = request.client.host if request.client else None
        allowed = caller is not None and (
            caller in authoring_callers  # literal match: no DNS lookup
            or caller in _resolve_callers(authoring_callers)
        )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="caller is not an allowlisted authoring service",
            )
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

    return app
