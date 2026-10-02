"""Hospital Node REST API service (P4-1, C14).

Orchestrates facility node workflows:
- Read (under policy or patient consent gate)
- Consent (request issuance, grant submission, grant revocation)
- Revocation (cryptographic DEK rotation and policy rebuild)
- Break-glass (emergency assertion validation and 2-of-3 threshold gate)
- Search (federated discovery, encrypted index search, emergency search)
- Ingest (record encryption, owner-leaf addition, and indexing)

Invariants:
- CONVENTIONS.md §2 rule 10: No cryptography in api/. Route handlers only
  orchestrate domain calls and persist state; they do not compute ciphers.
- Parameterised queries / repository pattern only.
- Fail closed on unauthorized access, invalid signatures, or missing shares.
"""

from __future__ import annotations

import base64
import binascii
import logging
from datetime import timedelta
from typing import Annotated, Any, Callable
from uuid import uuid4

from audit.events import (
    ACCESS_VIA_CONSENT,
    ACCESS_VIA_POLICY,
    DENIED_BY_CONSENT,
    DENIED_BY_POLICY,
    DENIED_BY_REVOCATION_AUTHZ,
    EVENT_ACCESS_DENIED,
    EVENT_ACCESS_GRANTED,
    EVENT_FEDERATION_DISCOVERY,
    EVENT_FEDERATION_REWRAP,
    log_access_denied,
    log_access_granted,
    log_federation_discovery,
    log_federation_rewrap,
)
from breakglass import (
    ConsumedAssertionIds,
    validate_emergency_assertion,
)
from breakglass.emergency_key import Share
from breakglass.exceptions import (
    AssertionExpiredError,
    ClinicianMismatchError,
    FacilityMismatchError,
    InsufficientSharesError,
    ReplayedAssertionError,
)
from breakglass.gate import open_emergency_access
from consent.exceptions import (
    ConsentDeniedError,
    ConsentExpiredError,
    ConsentRevokedError,
    ConsentScopeError,
    ConsentSubjectError,
)
from consent.service import (
    create_consent_request,
    read_record_under_consent,
    revoke_consent_grant,
    verify_consent_grant,
)
from contracts.enums import LifecycleState
from crypto_core import (
    certificate_from_pem,
    private_key_from_pem,
    public_key_from_pem,
    sha256_digest,
)
from crypto_core.exceptions import InvalidSignatureError, KeyFormatError
from crypto_core.types import ECPrivateKey
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from lifecycle.exceptions import (
    EmergencySessionExpiredError,
    IllegalTransitionError,
    SessionNotFoundError,
)
from lifecycle.expiry import EmergencyExpiryManager
from policy.engine import unwrap_dek_via_policy
from policy.exceptions import PolicyCompileError, PolicyDeniedError
from records.exceptions import (
    RecordError,
    UnauthorizedRevocationError,
    UnwrappingError,
)
from records.ingest import ingest_record
from records.revocation import (
    check_revocation_authorization,
    revoke_record_access,
)
from records.service import decrypt_record
from search.service import search_records_with_emergency

from api.audit_client import AuditServiceError, append_entry
from api.repository import (
    InMemoryStorageRepository,
    PostgresStorageRepository,
    StorageRepository,
)
from api.schemas import (
    BreakglassUnlockRequest,
    BreakglassUnlockResponse,
    ConsentResponse,
    CreateConsentRequestPayload,
    DiscoveryResponse,
    EmergencySearchRequest,
    ErrorResponse,
    HealthResponse,
    IngestRecordRequest,
    IngestRecordResponse,
    ReadRecordRequest,
    ReadRecordResponse,
    RevokeConsentGrantPayload,
    RevokeRecordRequest,
    RevokeRecordResponse,
    SearchRecordsRequest,
    SearchRecordsResponse,
    SubmitConsentGrantPayload,
)

_logger = logging.getLogger(__name__)


def get_repo(request: Request) -> StorageRepository:
    """Extract StorageRepository from application state."""
    return request.app.state.repository


def get_consumed_store(request: Request) -> ConsumedAssertionIds:
    """Extract ConsumedAssertionIds store from application state."""
    return request.app.state.consumed_assertions


def get_audit_signing_key(request: Request) -> ECPrivateKey | None:
    """Extract optional audit signing key from application state."""
    return request.app.state.audit_key


RepoDep = Annotated[StorageRepository, Depends(get_repo)]
ConsumedDep = Annotated[ConsumedAssertionIds, Depends(get_consumed_store)]
AuditKeyDep = Annotated[ECPrivateKey | None, Depends(get_audit_signing_key)]


def get_audit_service_url(request: Request) -> str | None:
    """Extract optional standalone audit service URL from application state."""
    return getattr(request.app.state, "audit_service_url", None)


AuditUrlDep = Annotated[str | None, Depends(get_audit_service_url)]


def _log_event(
    audit_url: str | None,
    repo: StorageRepository,
    audit_key: ECPrivateKey | None,
    *,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    in_process_logger: Callable[..., Any] | None = None,
    **in_process_kwargs: object,
) -> None:
    """Log an event to the standalone Audit Service over HTTP or in-process fallback.

    Fails closed: if the audit service is unreachable or returns non-2xx,
    ``AuditServiceError`` propagates. Callers whose semantics require the log
    entry (log-before-release for discovery / break-glass rewrap) must let
    it bubble; a denial-path caller that only wants to record an already-
    refused attempt may catch it explicitly. Swallowing silently would
    contradict audit_client.py's own contract and defeat the audit chain.
    """
    if audit_url:
        append_entry(
            audit_url,
            event_type=event_type,
            event_data=event_data,
            actor_id=actor_id,
            correlation_id=correlation_id,
        )
    elif (
        in_process_logger and isinstance(repo, PostgresStorageRepository) and audit_key
    ):
        in_process_logger(
            repo._conn,
            actor_id=actor_id,
            correlation_id=correlation_id,
            signing_key=audit_key,
            **in_process_kwargs,
        )


def _effective_lifecycle_state(
    repo: StorageRepository,
    exp_manager: EmergencyExpiryManager | None,
    record_id: str,
) -> LifecycleState:
    """Current state, reconciling an expiry the store was never told about.

    The expiry timer signs ``EMERGENCY_OPEN -> EXPIRED -> GRANTED`` into the
    chain but does not write the store (ADR-0043, re-baseline persistence gap),
    so ``lifecycle_state`` stays ``emergency_open`` after the time-box ends and
    every later break-glass is refused as an illegal transition. If the store
    says open but the timer holds no session for the record, the window has
    ended (or the process restarted and lost it); record ``granted`` to match.
    A session that is registered -- even one past its deadline but not yet
    swept -- is left alone: the timer will expire it and this stays fail-closed.
    """
    state = repo.get_lifecycle_state(record_id) or LifecycleState.GRANTED
    if state is not LifecycleState.EMERGENCY_OPEN or exp_manager is None:
        return state
    try:
        exp_manager.get_active_emergency_key(record_id)
    except SessionNotFoundError:
        repo.upsert_lifecycle_state(
            record_id=record_id, state=LifecycleState.GRANTED, last_event_id=None
        )
        return LifecycleState.GRANTED
    except EmergencySessionExpiredError:
        return state
    return state


def _log_denial(
    audit_url: str | None,
    repo: StorageRepository,
    audit_key: ECPrivateKey | None,
    *,
    record_id: str,
    requester_id: str,
    denied_by: str,
    reason: str,
    actor_id: str,
    correlation_id: str,
) -> None:
    """Log a denied access attempt; tolerate audit outage without hiding the 403.

    The denial is already decided by the domain layer; the caller will raise
    the 403 either way. If the audit service is down, we surface a warning
    (so an operator can see the audit gap) rather than converting the client's
    denial into a confusing 500 — but a monitoring alert must still fire on
    the log record. Success-path loggers must NOT use this — they need
    log-before-release, i.e. propagate on failure.
    """
    try:
        _log_event(
            audit_url,
            repo,
            audit_key,
            event_type=EVENT_ACCESS_DENIED,
            event_data={
                "record_id": record_id,
                "requester_id": requester_id,
                "denied_by": denied_by,
                "reason": reason,
            },
            actor_id=actor_id,
            correlation_id=correlation_id,
            in_process_logger=log_access_denied,
            record_id=record_id,
            requester_id=requester_id,
            denied_by=denied_by,
            reason=reason,
        )
    except AuditServiceError as audit_exc:
        _logger.warning(
            "audit service unavailable while logging denial "
            "(record_id=%s, requester_id=%s, correlation_id=%s): %s",
            record_id,
            requester_id,
            correlation_id,
            audit_exc,
        )


def _log_granted(
    audit_url: str | None,
    repo: StorageRepository,
    audit_key: ECPrivateKey | None,
    *,
    record_id: str,
    requester_id: str,
    access_via: str,
    actor_id: str,
    correlation_id: str,
) -> None:
    """Log a successful read; log-before-release (propagate on audit outage).

    Unlike ``_log_denial``, this does NOT swallow ``AuditServiceError``: a read
    that cannot be logged must not return plaintext (ARCHITECTURE.md §5,
    logging-as-precondition). The error propagates to the 503 handler exactly
    like discovery / break-glass re-wrap.
    """
    _log_event(
        audit_url,
        repo,
        audit_key,
        event_type=EVENT_ACCESS_GRANTED,
        event_data={
            "record_id": record_id,
            "requester_id": requester_id,
            "access_via": access_via,
        },
        actor_id=actor_id,
        correlation_id=correlation_id,
        in_process_logger=log_access_granted,
        record_id=record_id,
        requester_id=requester_id,
        access_via=access_via,
    )


def _log_discovery(
    audit_url: str | None,
    repo: StorageRepository,
    audit_key: ECPrivateKey | None,
    *,
    patient_id: str,
    requester_id: str,
    record_ids: list[str],
    actor_id: str,
    correlation_id: str,
) -> None:
    _log_event(
        audit_url,
        repo,
        audit_key,
        event_type=EVENT_FEDERATION_DISCOVERY,
        event_data={
            "patient_id_hash": sha256_digest(patient_id.encode("utf-8")).hex(),
            "requester_id": requester_id,
            "record_count": len(record_ids),
            "record_ids": list(record_ids),
        },
        actor_id=actor_id,
        correlation_id=correlation_id,
        in_process_logger=log_federation_discovery,
        patient_id=patient_id,
        requester_id=requester_id,
        record_ids=record_ids,
    )


def _log_rewrap(
    audit_url: str | None,
    repo: StorageRepository,
    audit_key: ECPrivateKey | None,
    *,
    record_id: str,
    source_facility_id: str,
    target_actor_id: str,
    actor_id: str,
    correlation_id: str,
) -> None:
    _log_event(
        audit_url,
        repo,
        audit_key,
        event_type=EVENT_FEDERATION_REWRAP,
        event_data={
            "record_id": record_id,
            "source_facility_id": source_facility_id,
            "target_actor_id": target_actor_id,
        },
        actor_id=actor_id,
        correlation_id=correlation_id,
        in_process_logger=log_federation_rewrap,
        record_id=record_id,
        source_facility_id=source_facility_id,
        target_actor_id=target_actor_id,
    )


def _parse_attribute_keyring(
    raw_keyring: dict[str, str],
) -> dict[tuple[str, str, str], bytes]:
    """Parse a dict of 'auth_id:name:value' -> base64 string to AttributeKeyring."""
    parsed: dict[tuple[str, str, str], bytes] = {}
    for k, v in raw_keyring.items():
        parts = k.split(":", 2)
        if len(parts) != 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Invalid attribute key format {k!r}; "
                    "expected 'authority_id:name:value'"
                ),
            )
        try:
            parsed[(parts[0], parts[1], parts[2])] = base64.b64decode(v, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 encoding for key {k!r}: {exc}",
            ) from exc
    return parsed


def create_hospital_app(
    facility_id: str,
    repository: StorageRepository | None = None,
    expiry_manager: EmergencyExpiryManager | None = None,
    audit_signing_key_pem: str | None = None,
    audit_service_url: str | None = None,
) -> FastAPI:
    """Create and configure a FastAPI application for a hospital node.

    Args:
        facility_id: Identifier of this hospital node (e.g. 'facility-a').
        repository: Storage repository implementation. Defaults to in-memory.
        expiry_manager: Emergency expiry manager for tracking emergency sessions.
        audit_signing_key_pem: Optional ECDSA private key PEM for audit logging.
        audit_service_url: Optional base URL of standalone Audit Service over HTTP.

    Returns:
        Configured FastAPI application instance.
    """
    repo = repository or InMemoryStorageRepository()
    consumed_assertions = ConsumedAssertionIds()
    audit_key: ECPrivateKey | None = (
        private_key_from_pem(audit_signing_key_pem.encode("utf-8"))
        if audit_signing_key_pem
        else None
    )

    app = FastAPI(
        title=f"Hospital Node API ({facility_id})",
        description="Federated Break-Glass EHR Hospital Service",
        version="1.0.0",
    )

    app.state.facility_id = facility_id
    app.state.repository = repo
    app.state.consumed_assertions = consumed_assertions
    app.state.expiry_manager = expiry_manager
    app.state.audit_key = audit_key
    app.state.audit_service_url = audit_service_url

    @app.exception_handler(AuditServiceError)
    def _audit_unavailable_handler(  # noqa: ARG001
        request: Request, exc: AuditServiceError
    ) -> JSONResponse:
        """Log-before-release path lost the audit chain; fail closed with 503.

        Only success-path _log_* calls (discovery, break-glass rewrap) let
        this propagate. Denial-path logging swallows it inside _log_denial
        with a warning, so a real 403 is never masked by an audit outage.
        """
        _logger.error("audit service unavailable, refusing release path: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "detail": (
                    "audit service unavailable; refusing to release without a log "
                    "entry (log-before-release, ARCHITECTURE.md §5)"
                )
            },
        )

    # --- Health Check ---------------------------------------------------------

    @app.get("/health", response_model=HealthResponse)
    def health_check() -> HealthResponse:
        """Report facility node readiness."""
        return HealthResponse(facility_id=facility_id)

    # --- Read Endpoint --------------------------------------------------------

    @app.post(
        "/records/{record_id}/read",
        response_model=ReadRecordResponse,
        responses={
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
        },
    )
    def read_record(
        record_id: str,
        payload: ReadRecordRequest,
        repo: RepoDep,
        audit_key: AuditKeyDep,
        audit_url: AuditUrlDep,
    ) -> ReadRecordResponse:
        """Read and decrypt an encrypted health record under policy or consent."""
        record = repo.get_record(record_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Record {record_id!r} not found",
            )

        wrapping = repo.get_wrapping_for_record(record_id, wrapped_for=record.policy_id)
        if not wrapping:
            wrapping = repo.get_wrapping_for_record(record_id)
        if not wrapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"DEK wrapping for record {record_id!r} not found",
            )

        compiled_policy = repo.get_compiled_policy(record.policy_id)
        if not compiled_policy:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Compiled policy {record.policy_id!r} not loaded",
            )

        keyring = _parse_attribute_keyring(payload.holder_keyring)

        # 1. If a consent grant is provided, read under the consent gate
        if payload.grant is not None:
            if not payload.patient_public_key_pem:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="patient_public_key_pem required to verify consent grant",
                )
            try:
                patient_pub = public_key_from_pem(
                    payload.patient_public_key_pem.encode("utf-8")
                )
            except KeyFormatError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid patient public key PEM: {exc}",
                ) from exc

            access_via = ACCESS_VIA_CONSENT
            try:
                plaintext_bytes = read_record_under_consent(
                    record=record,
                    wrapping=wrapping,
                    compiled_policy=compiled_policy,
                    grant=payload.grant,
                    grantee_id=payload.requester_id,
                    patient_public_key=patient_pub,
                    holder_keyring=keyring,
                )
            except (
                ConsentDeniedError,
                ConsentRevokedError,
                ConsentExpiredError,
                ConsentScopeError,
                ConsentSubjectError,
            ) as exc:
                _log_denial(
                    audit_url,
                    repo,
                    audit_key,
                    record_id=record_id,
                    requester_id=payload.requester_id,
                    denied_by=DENIED_BY_CONSENT,
                    reason=str(exc),
                    actor_id=facility_id,
                    correlation_id=payload.correlation_id or str(uuid4()),
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Consent denied: {exc}",
                ) from exc
            except PolicyDeniedError as exc:
                _log_denial(
                    audit_url,
                    repo,
                    audit_key,
                    record_id=record_id,
                    requester_id=payload.requester_id,
                    denied_by=DENIED_BY_POLICY,
                    reason=str(exc),
                    actor_id=facility_id,
                    correlation_id=payload.correlation_id or str(uuid4()),
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Policy denied: {exc}",
                ) from exc
            except UnwrappingError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"DEK unwrapping failed: {exc}",
                ) from exc

        # 2. Otherwise, direct policy unwrap (e.g. owner access or in-network read)
        else:
            access_via = ACCESS_VIA_POLICY
            try:
                dek = unwrap_dek_via_policy(compiled_policy, keyring, wrapping)
                plaintext_bytes = decrypt_record(record, dek)
            except PolicyDeniedError as exc:
                _log_denial(
                    audit_url,
                    repo,
                    audit_key,
                    record_id=record_id,
                    requester_id=payload.requester_id,
                    denied_by=DENIED_BY_POLICY,
                    reason=str(exc),
                    actor_id=facility_id,
                    correlation_id=payload.correlation_id or str(uuid4()),
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Policy denied: {exc}",
                ) from exc
            except UnwrappingError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"DEK unwrapping failed: {exc}",
                ) from exc

        # Log-before-release: record the successful read before returning
        # plaintext. If the audit chain is unreachable this raises and the read
        # returns 503, not the record (ARCHITECTURE.md §5, logging-as-precondition).
        _log_granted(
            audit_url,
            repo,
            audit_key,
            record_id=record_id,
            requester_id=payload.requester_id,
            access_via=access_via,
            actor_id=facility_id,
            correlation_id=payload.correlation_id or str(uuid4()),
        )

        return ReadRecordResponse(
            record_id=record.record_id,
            patient_id=record.patient_id,
            facility_id=record.facility_id,
            content_type=record.content_type,
            plaintext_b64=base64.b64encode(plaintext_bytes).decode("ascii"),
            correlation_id=payload.correlation_id,
        )

    # --- Consent Endpoints ----------------------------------------------------

    @app.post("/consent/requests", response_model=ConsentResponse)
    def create_request(
        payload: CreateConsentRequestPayload,
        repo: RepoDep,
    ) -> ConsentResponse:
        """Create and sign a new ConsentRequest."""
        try:
            req_priv = private_key_from_pem(
                payload.requester_signing_key_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid requester signing key PEM: {exc}",
            ) from exc

        req = create_consent_request(
            patient_id=payload.patient_id,
            requester_id=payload.requester_id,
            scope=tuple(payload.scope),
            purpose=payload.purpose,
            requester_signing_key=req_priv,
            ttl=timedelta(days=payload.ttl_days),
        )
        repo.store_consent_request(req)
        return ConsentResponse(
            status="created",
            request=req,
            message="Consent request created and registered",
        )

    @app.post("/consent/grants", response_model=ConsentResponse)
    def submit_grant(
        payload: SubmitConsentGrantPayload,
        repo: RepoDep,
    ) -> ConsentResponse:
        """Submit and verify a patient-signed ConsentGrant."""
        try:
            patient_pub = public_key_from_pem(
                payload.patient_public_key_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid patient public key PEM: {exc}",
            ) from exc

        try:
            verify_consent_grant(payload.grant, patient_pub)
        except InvalidSignatureError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Consent grant signature verification failed: {exc}",
            ) from exc

        repo.store_consent_grant(payload.grant)
        return ConsentResponse(
            status="accepted",
            grant=payload.grant,
            message="Consent grant verified and stored",
        )

    @app.post("/consent/grants/revoke", response_model=ConsentResponse)
    def revoke_grant(
        payload: RevokeConsentGrantPayload,
        repo: RepoDep,
    ) -> ConsentResponse:
        """Revoke a previously issued ConsentGrant by patient signature."""
        try:
            patient_priv = private_key_from_pem(
                payload.patient_signing_key_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid patient signing key PEM: {exc}",
            ) from exc

        revoked_grant = revoke_consent_grant(
            prior_grant=payload.prior_grant,
            patient_signing_key=patient_priv,
        )
        repo.store_consent_grant(revoked_grant)
        return ConsentResponse(
            status="revoked",
            grant=revoked_grant,
            message="Consent grant revoked successfully",
        )

    # --- Revocation by Key Rotation Endpoint (P3-7, P3-12) -------------------

    @app.post("/records/{record_id}/revoke", response_model=RevokeRecordResponse)
    def revoke_record(
        record_id: str,
        payload: RevokeRecordRequest,
        repo: RepoDep,
        audit_key: AuditKeyDep,
        audit_url: AuditUrlDep,
    ) -> RevokeRecordResponse:
        """Cryptographically revoke record access via DEK rotation (P3-7, P3-12)."""
        record = repo.get_record(record_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Record {record_id!r} not found",
            )

        wrapping = repo.get_wrapping_for_record(record_id, wrapped_for=record.policy_id)
        if not wrapping:
            wrapping = repo.get_wrapping_for_record(record_id)
        if not wrapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"DEK wrapping for record {record_id!r} not found",
            )

        try:
            check_revocation_authorization(
                actor_id=payload.actor_id,
                record=record,
                owner_authority_id=payload.owner_authority_id,
            )
        except UnauthorizedRevocationError as exc:
            _log_denial(
                audit_url,
                repo,
                audit_key,
                record_id=record_id,
                requester_id=payload.actor_id,
                denied_by=DENIED_BY_REVOCATION_AUTHZ,
                reason=str(exc),
                actor_id=facility_id,
                correlation_id=payload.correlation_id or str(uuid4()),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unauthorized revocation: {exc}",
            ) from exc

        try:
            actor_priv = private_key_from_pem(
                payload.actor_signing_key_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid actor signing key PEM: {exc}",
            ) from exc

        try:
            old_dek = base64.b64decode(payload.old_dek_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 encoding for old_dek: {exc}",
            ) from exc

        keyring = _parse_attribute_keyring(payload.attribute_keyring)

        try:
            rev_result = revoke_record_access(
                current_record=record,
                current_wrapping=wrapping,
                old_dek=old_dek,
                new_clinical_policy=payload.new_clinical_policy,
                owner_authority_id=payload.owner_authority_id,
                attribute_keyring=keyring,
                actor_id=payload.actor_id,
                actor_signing_key=actor_priv,
                correlation_id=payload.correlation_id or str(uuid4()),
                reason_code=payload.reason_code,
                new_policy_id=payload.new_policy_id,
            )
        except (
            RecordError,
            PolicyDeniedError,
            PolicyCompileError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Revocation failed: {exc}",
            ) from exc

        repo.insert_record(rev_result.rotated_record)
        repo.insert_dek_wrapping(rev_result.rotated_wrapping)
        repo.store_compiled_policy(
            rev_result.rotated_record.policy_id, rev_result.compiled_policy
        )
        repo.upsert_lifecycle_state(
            record_id=record_id,
            state=LifecycleState.REVOKED,
            last_event_id=str(rev_result.transition_event.event_id),
        )
        repo.insert_transition_event(rev_result.transition_event)

        return RevokeRecordResponse(
            record_id=record_id,
            new_generation=rev_result.rotated_wrapping.generation,
            new_policy_id=rev_result.rotated_record.policy_id,
            transition_event=rev_result.transition_event,
        )

    # --- Break-Glass Emergency Endpoint (P3-5, P3-10, P3-11) ------------------

    @app.post(
        "/records/{record_id}/breakglass",
        response_model=BreakglassUnlockResponse,
    )
    def breakglass_unlock(
        record_id: str,
        payload: BreakglassUnlockRequest,
        repo: RepoDep,
        consumed_store: ConsumedDep,
        audit_key: AuditKeyDep,
        audit_url: AuditUrlDep,
    ) -> BreakglassUnlockResponse:
        """Execute 2-of-3 threshold emergency unlock for a record (P3-5)."""
        # 1. Five-point validation of EmergencyAssertion (P3-10, P3-11)
        try:
            cl_cert = certificate_from_pem(
                payload.clinician_certificate_pem.encode("utf-8")
            )
            ca_cert = (
                certificate_from_pem(
                    payload.facility_ca_certificate_pem.encode("utf-8")
                )
                if payload.facility_ca_certificate_pem
                else None
            )
            root_cert = (
                certificate_from_pem(
                    payload.trusted_root_certificate_pem.encode("utf-8")
                )
                if payload.trusted_root_certificate_pem
                else None
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Certificate parsing failed: {exc}",
            ) from exc

        try:
            validate_emergency_assertion(
                assertion=payload.assertion,
                clinician_certificate=cl_cert,
                facility_ca_certificate=ca_cert,
                trusted_root=root_cert,
                expected_facility_id=facility_id,
                consumed_store=consumed_store,
            )
        except (
            AssertionExpiredError,
            ClinicianMismatchError,
            FacilityMismatchError,
            InvalidSignatureError,
            ReplayedAssertionError,
        ) as exc:
            _log_denial(
                audit_url,
                repo,
                audit_key,
                record_id=record_id,
                requester_id=payload.assertion.clinician_id,
                denied_by="breakglass_assertion",
                reason=str(exc),
                actor_id=facility_id,
                correlation_id=payload.correlation_id or str(uuid4()),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Emergency assertion invalid ({exc.__class__.__name__}): {exc}",
            ) from exc

        # 2. Fetch record and emergency DEK wrapping
        record = repo.get_record(record_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Record {record_id!r} not found",
            )

        # An assertion opens the patient it names and nobody else
        # (ARCHITECTURE.md §8). Checked before any lifecycle change so a
        # mismatched assertion has no side effect on the record.
        if record.patient_id != payload.assertion.patient_id:
            reason = "assertion patient_id does not match the record's patient"
            _log_denial(
                audit_url,
                repo,
                audit_key,
                record_id=record_id,
                requester_id=payload.assertion.clinician_id,
                denied_by="breakglass_patient_binding",
                reason=reason,
                actor_id=facility_id,
                correlation_id=payload.correlation_id or str(uuid4()),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Emergency assertion not valid for this record: {reason}",
            )

        wrapping = repo.get_wrapping_for_record(record_id, wrapped_for="emergency")
        if not wrapping:
            wrapping = repo.get_wrapping_for_record(record_id)
        if not wrapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No DEK wrapping found for record {record_id!r}",
            )

        source_state = _effective_lifecycle_state(
            repo, app.state.expiry_manager, record_id
        )

        # 3. Parse shares and signing key
        try:
            lifecycle_priv = private_key_from_pem(
                payload.lifecycle_signing_key_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid lifecycle signing key PEM: {exc}",
            ) from exc

        shares_list: list[Share] = []
        for x, share_hex in payload.shares:
            try:
                shares_list.append((x, bytes.fromhex(share_hex)))
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid hex share for x={x}: {exc}",
                ) from exc

        # 4. Open emergency access via 2-of-3 threshold gate
        corr_id = payload.correlation_id or str(uuid4())
        try:
            unlock_result = open_emergency_access(
                shares_presented=shares_list,
                dek_wrapping=wrapping,
                transition_source_state=source_state,
                record_id=record_id,
                actor_id=payload.assertion.clinician_id,
                correlation_id=corr_id,
                reason_code=payload.assertion.reason_code,
                lifecycle_signing_key=lifecycle_priv,
                pre_rewrap_key=payload.pre_rewrap_key,
            )
        except InsufficientSharesError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Insufficient threshold shares: {exc}",
            ) from exc
        except (UnwrappingError, IllegalTransitionError) as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Emergency unlock rejected: {exc}",
            ) from exc

        # 5. Persist transition and log federation re-wrap
        repo.upsert_lifecycle_state(
            record_id=record_id,
            state=LifecycleState.EMERGENCY_OPEN,
            last_event_id=str(unlock_result.transition_event.event_id),
        )
        repo.insert_transition_event(unlock_result.transition_event)

        # Register session with expiry manager if baseline wrapping key supplied
        exp_manager = app.state.expiry_manager
        if exp_manager and payload.baseline_wrapping_key_b64:
            try:
                base_wrapping_key = base64.b64decode(
                    payload.baseline_wrapping_key_b64, validate=True
                )
            except (ValueError, binascii.Error) as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid base64 baseline_wrapping_key: {exc}",
                ) from exc
            try:
                baseline_wrapping = (
                    repo.get_wrapping_for_record(
                        record_id, wrapped_for=record.policy_id
                    )
                    or wrapping
                )
                exp_manager.register_session(
                    record_id=record_id,
                    actor_id=payload.assertion.clinician_id,
                    correlation_id=corr_id,
                    emergency_key=unlock_result.emergency_key,
                    baseline_wrapping_key=base_wrapping_key,
                    baseline_wrapping=baseline_wrapping,
                    emergency_wrapping=wrapping,
                    current_record=record,
                    duration_seconds=payload.emergency_duration_seconds,
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to register emergency session: {exc}",
                ) from exc

        _log_rewrap(
            audit_url,
            repo,
            audit_key,
            record_id=record_id,
            source_facility_id=record.facility_id,
            target_actor_id=payload.assertion.clinician_id,
            actor_id=facility_id,
            correlation_id=corr_id,
        )

        return BreakglassUnlockResponse(
            record_id=record_id,
            rewrapped_dek_b64=base64.b64encode(unlock_result.rewrapped_dek).decode(
                "ascii"
            ),
            transition_event=unlock_result.transition_event,
            correlation_id=corr_id,
        )

    # --- Search & Discovery Endpoints -----------------------------------------

    @app.get("/patients/{patient_id}/records", response_model=DiscoveryResponse)
    def discover_patient_records(
        patient_id: str,
        repo: RepoDep,
        audit_key: AuditKeyDep,
        audit_url: AuditUrlDep,
    ) -> DiscoveryResponse:
        """Federated discovery: find record IDs for a patient (C13)."""
        record_ids = repo.find_record_ids_by_patient(patient_id)
        _log_discovery(
            audit_url,
            repo,
            audit_key,
            patient_id=patient_id,
            requester_id=facility_id,
            record_ids=record_ids,
            actor_id=facility_id,
            correlation_id=str(uuid4()),
        )
        return DiscoveryResponse(
            patient_id=patient_id,
            record_ids=record_ids,
            record_count=len(record_ids),
        )

    @app.post("/search/records", response_model=SearchRecordsResponse)
    def search_coded_index(
        payload: SearchRecordsRequest,
        repo: RepoDep,
    ) -> SearchRecordsResponse:
        """Search coded index via equality check on token."""
        try:
            coded_term = base64.b64decode(payload.coded_term_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 token: {exc}",
            ) from exc

        matches = repo.find_records_by_search_term(coded_term)
        return SearchRecordsResponse(
            record_ids=matches,
            record_count=len(matches),
        )

    @app.post(
        "/records/{record_id}/emergency-search",
        response_model=SearchRecordsResponse,
    )
    def search_under_emergency(
        record_id: str,
        payload: EmergencySearchRequest,
        repo: RepoDep,
    ) -> SearchRecordsResponse:
        """Search encrypted index using active emergency session (P3-8)."""
        exp_manager = app.state.expiry_manager
        if not exp_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Emergency expiry manager not configured on this facility node",
            )

        # NOTE: CONVENTIONS.md §2 rule 10 forbids crypto in api/. The Postgres
        # path stays clean because search.service does the HKDF internally; the
        # in-memory fallback still calls derive_search_token from here so tests
        # without a DB run end-to-end. A repo-agnostic helper in search.service
        # would close this — cross-owner change, tracked separately.
        try:
            if isinstance(repo, PostgresStorageRepository):
                matches = search_records_with_emergency(
                    conn=repo._conn,
                    expiry_manager=exp_manager,
                    record_id=record_id,
                    search_term=payload.search_term,
                )
            else:
                em_key = exp_manager.get_active_emergency_key(record_id)
                from search.service import derive_search_token

                coded_term = derive_search_token(em_key, payload.search_term)
                matches = repo.find_records_by_search_term(coded_term)
        except (EmergencySessionExpiredError, SessionNotFoundError) as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Emergency search unavailable: {exc}",
            ) from exc

        return SearchRecordsResponse(
            record_ids=matches,
            record_count=len(matches),
        )

    # --- Ingest / Upload Endpoint (P3-14) --------------------------------------

    @app.post(
        "/records/ingest",
        response_model=IngestRecordResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def ingest_record_endpoint(
        payload: IngestRecordRequest,
        repo: RepoDep,
    ) -> IngestRecordResponse:
        """Ingest, encrypt, compile policy, wrap DEK, and index a record (P3-14)."""
        try:
            plaintext = base64.b64decode(payload.plaintext_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 plaintext: {exc}",
            ) from exc

        keyring = _parse_attribute_keyring(payload.attribute_keyring)
        try:
            em_key = (
                base64.b64decode(payload.emergency_key_b64, validate=True)
                if payload.emergency_key_b64
                else None
            )
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 emergency_key: {exc}",
            ) from exc

        try:
            result = ingest_record(
                plaintext=plaintext,
                patient_id=payload.patient_id,
                facility_id=facility_id,
                owner_authority_id=payload.owner_authority_id,
                clinical_policy=payload.clinical_policy,
                attribute_keyring=keyring,
                search_terms=payload.search_terms,
                emergency_key=em_key,
                content_type=payload.content_type,
                record_id=payload.record_id,
            )
        except (ValueError, PolicyCompileError, RecordError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Ingest failed: {exc}",
            ) from exc

        repo.insert_record(result.record)
        repo.insert_dek_wrapping(result.dek_wrapping)
        if result.emergency_dek_wrapping:
            repo.insert_dek_wrapping(result.emergency_dek_wrapping)
        repo.store_compiled_policy(result.record.policy_id, result.compiled_policy)
        repo.upsert_lifecycle_state(
            record_id=result.record.record_id,
            state=result.lifecycle_state,
        )
        for _term, token in result.search_tokens.items():
            repo.insert_search_term(result.record.record_id, token)

        return IngestRecordResponse(
            record_id=result.record.record_id,
            policy_id=result.record.policy_id,
            wrapping_id=result.dek_wrapping.wrapping_id,
            lifecycle_state=result.lifecycle_state,
            search_terms_indexed=len(result.search_tokens),
        )

    return app
