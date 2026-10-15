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
- Every route but ``/health`` takes only signed requests from a federation
  service whose kind the route allows (ADR-0066, ``api.service_auth``).
"""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Any, Callable
from uuid import uuid4

import httpx
from audit.events import (
    ACCESS_VIA_CONSENT,
    ACCESS_VIA_EMERGENCY_SEARCH,
    ACCESS_VIA_POLICY,
    DENIED_BY_BREAKGLASS_ASSERTION,
    DENIED_BY_BREAKGLASS_CHAIN,
    DENIED_BY_BREAKGLASS_GATE,
    DENIED_BY_BREAKGLASS_TRANSITION,
    DENIED_BY_CONSENT,
    DENIED_BY_DEK_UNWRAP,
    DENIED_BY_EMERGENCY_SEARCH,
    DENIED_BY_POLICY,
    DENIED_BY_RECORD_NOT_FOUND,
    DENIED_BY_REVOCATION_AUTHZ,
    EVENT_ACCESS_DENIED,
    EVENT_ACCESS_GRANTED,
    EVENT_FEDERATION_DISCOVERY,
    EVENT_FEDERATION_REWRAP,
    EVENT_RECORD_REVOKED,
    log_access_denied,
    log_access_granted,
    log_federation_discovery,
    log_federation_rewrap,
    patient_id_hash,
)
from breakglass import (
    ConsumedAssertionIds,
    ConsumedRequestIds,
    validate_emergency_assertion,
)
from breakglass.assertion import (
    ASSERTION_CLOCK_SKEW,
    MAX_ASSERTION_TTL,
    validate_clinical_context,
)
from breakglass.emergency_key import Share
from breakglass.exceptions import (
    AssertionExpiredError,
    AssertionLifetimeError,
    CertificateRevokedError,
    ClinicianMismatchError,
    FacilityMismatchError,
    InsufficientSharesError,
    ReplayedAssertionError,
)
from breakglass.gate import (
    EmergencyUnlockResult,
    join_emergency_access,
    open_emergency_access,
)
from consent.exceptions import (
    ConsentDeniedError,
    ConsentExpiredError,
    ConsentRevokedError,
    ConsentScopeError,
    ConsentSubjectError,
)
from consent.service import (
    read_record_under_consent,
    verify_consent_grant,
    verify_consent_request,
)
from contracts.enums import ConsentStatus, LifecycleState
from crypto_core import (
    certificate_from_pem,
    certificate_public_key,
    private_key_from_pem,
)
from crypto_core.exceptions import (
    CertificateExpiredError,
    InvalidSignatureError,
    KeyFormatError,
)
from crypto_core.types import ECPrivateKey, ECPublicKey
from cryptography.x509 import Certificate
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from identity import (
    PatientCertificateError,
    SubjectCertificateError,
    validate_clinician_certificate,
    validate_patient_certificate,
)
from identity.exceptions import ChainValidationError
from lifecycle.exceptions import (
    EmergencySessionExpiredError,
    IllegalTransitionError,
    MissingReasonCodeError,
    ReplayedEventError,
    SessionNotFoundError,
    StateConflictError,
    StateMismatchError,
)
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import (
    ConsumedEventIds,
    LifecycleStateMachine,
    verify_transition_event,
)
from policy.engine import decrypt_record_via_policy, policy_tree_of
from policy.exceptions import PolicyCompileError, PolicyDeniedError
from records.exceptions import (
    RecordError,
    UnauthorizedRevocationError,
    UnwrappingError,
)
from records.ingest import ingest_record
from records.labels import (
    LabelTrust,
    LabelVerificationError,
    disclosure_rules,
    verify_clinical_labels,
)
from records.revocation import (
    check_revocation_authorization,
    revoked_policy_tree,
)
from search.service import emergency_search_token
from shamir.exceptions import SecretSharingError

from api.audit_client import AuditServiceError, append_entry
from api.repository import (
    InMemoryStorageRepository,
    PostgresStorageRepository,
    RecordExistsError,
    RotationConflictError,
    StorageRepository,
)
from api.rotation import (
    FacilityRotator,
    RepositorySessionStore,
    RotationError,
    RotationPorts,
    recover_emergency_sessions,
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
    LifecycleStateResponse,
    ReadRecordRequest,
    ReadRecordResponse,
    RevokeRecordRequest,
    RevokeRecordResponse,
    SearchRecordsRequest,
    SearchRecordsResponse,
    SubmitConsentGrantPayload,
)
from api.service_auth import (
    ServiceAuthConfig,
    ServiceIdentity,
    SignedRequestAuth,
    install_service_auth,
)

_logger = logging.getLogger(__name__)

AUDIT_SERVICE_ID = "audit-service"

# Which kinds of federation service may call each route (ADR-0066). Every key
# path is also the custodian's or a bootstrap/demo script's; the portal calls
# only what it needs with no key material in the body.
_CUSTODIAN = frozenset({"custodian", "bootstrap"})
_PORTAL = frozenset({"portal", "bootstrap"})
FACILITY_PERMISSIONS: dict[tuple[str, str], frozenset[str]] = {
    ("POST", "/records/{record_id}/read"): _CUSTODIAN,
    ("POST", "/consent/requests"): _CUSTODIAN,
    # A revoked grant is the patient's signed REVOKED grant, submitted here
    # like any other decision; nobody sends the facility a key to sign one.
    ("POST", "/consent/grants"): _CUSTODIAN | _PORTAL,
    ("POST", "/records/{record_id}/revoke"): _CUSTODIAN,
    ("POST", "/records/{record_id}/breakglass"): _CUSTODIAN,
    ("GET", "/records/{record_id}/lifecycle"): _CUSTODIAN,
    ("GET", "/patients/{patient_id}/records"): _CUSTODIAN | _PORTAL,
    ("POST", "/search/records"): _CUSTODIAN,
    ("POST", "/records/{record_id}/emergency-search"): _PORTAL,
    ("POST", "/records/ingest"): _CUSTODIAN,
}
FACILITY_PUBLIC_ROUTES = frozenset({("GET", "/health")})


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

# ``sink(event_type, event_data, actor_id, correlation_id)``: an explicit
# in-memory audit destination for tests and standalone demos (review F19).
AuditSink = Callable[[str, dict[str, Any], str, str], None]


@dataclass(frozen=True)
class FacilityTrust:
    """Trust anchors for break-glass chain validation, from facility config (F1).

    The caller never chooses what the facility trusts: the federation root,
    the cross-certified facility CAs and the revoked clinician serials are
    loaded at startup (``deploy/asgi/facility.py``) or passed in by tests.
    """

    root: Certificate
    facility_cas: Mapping[str, Certificate]
    revoked_serials: frozenset[int] = field(default_factory=frozenset)

    def issuing_ca(self, leaf: Certificate) -> tuple[str, Certificate] | None:
        """``(facility_id, CA)`` of the configured CA that issued ``leaf``, if any.

        The facility id is the clinician's home facility once the chain
        verifies against that CA (ADR-0063).
        """
        for fid, ca in self.facility_cas.items():
            if ca.subject == leaf.issuer:
                return fid, ca
        return None


def _log_event(
    audit_url: str | None,
    repo: StorageRepository,
    audit_key: ECPrivateKey | None,
    *,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    sink: AuditSink | None = None,
    audit_auth: SignedRequestAuth | None = None,
    in_process_logger: Callable[..., Any] | None = None,
    **in_process_kwargs: object,
) -> None:
    """Log an event to the Audit Service, the in-process chain, or a test sink.

    Fails closed: if the audit service is unreachable or returns non-2xx,
    ``AuditServiceError`` propagates, and so it does when no audit destination
    is configured at all (review F19) -- a facility without an audit sink must
    not release anything. Callers whose semantics require the log entry
    (log-before-release) must let it bubble; a denial-path caller that only
    wants to record an already-refused attempt may catch it explicitly.
    """
    if audit_url:
        append_entry(
            audit_url,
            event_type=event_type,
            event_data=event_data,
            actor_id=actor_id,
            correlation_id=correlation_id,
            auth=audit_auth,
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
    elif sink is not None:
        sink(event_type, event_data, actor_id, correlation_id)
    else:
        raise AuditServiceError("no audit sink configured")


def _current_lifecycle_state(repo: StorageRepository, record_id: str) -> LifecycleState:
    """The record's stored state; a plain read with no side effects (review N1).

    The ADR-0044 reset that used to live here wrote ``granted`` whenever this
    process held no session, which raced other facilities and undid
    revocations. The expiry timer now mirrors its transitions into the store
    itself, so the stored state is authoritative.
    """
    return repo.get_lifecycle_state(record_id) or LifecycleState.GRANTED


def _log_denial(
    audit_url: str | None,
    repo: StorageRepository,
    audit_key: ECPrivateKey | None,
    *,
    sink: AuditSink | None = None,
    audit_auth: SignedRequestAuth | None = None,
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
            sink=sink,
            audit_auth=audit_auth,
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
    sink: AuditSink | None = None,
    audit_auth: SignedRequestAuth | None = None,
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
        sink=sink,
        audit_auth=audit_auth,
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
    sink: AuditSink | None = None,
    audit_auth: SignedRequestAuth | None = None,
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
        sink=sink,
        audit_auth=audit_auth,
        event_type=EVENT_FEDERATION_DISCOVERY,
        event_data={
            "patient_id_hash": patient_id_hash(patient_id),
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
    sink: AuditSink | None = None,
    audit_auth: SignedRequestAuth | None = None,
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
        sink=sink,
        audit_auth=audit_auth,
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


def _presents_no_key(payload: ReadRecordRequest) -> bool:
    """Whether a read request carries no attribute key at all (review F34).

    Such a requester can decrypt nothing, so the read is refused before the
    record, its wrapping or its policy is loaded.
    """
    return not payload.holder_keyring


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
    *,
    trust: FacilityTrust | None = None,
    audit_sink: AuditSink | None = None,
    identity: ServiceIdentity | None = None,
    rotation_ports: RotationPorts | None = None,
    service_root: Certificate | None = None,
) -> FastAPI:
    """Create and configure a FastAPI application for a hospital node.

    Args:
        facility_id: Identifier of this hospital node (e.g. 'facility-a').
        repository: Storage repository implementation. Defaults to in-memory.
        expiry_manager: Emergency expiry manager for tracking emergency sessions.
            Its timer transitions are mirrored into ``repository`` (review N1).
        audit_signing_key_pem: Optional ECDSA private key PEM for audit logging.
        audit_service_url: Optional base URL of standalone Audit Service over HTTP.
        trust: Break-glass trust anchors from configuration (review F1).
            Without them break-glass is refused with 503.
        audit_sink: Explicit in-memory audit destination for tests and
            standalone demos. With no audit destination at all, every
            log-before-release path fails closed with 503 (review F19).
        identity: This facility's service identity, which signs its calls to
            the audit service (ADR-0066). Required with ``audit_service_url``.
        rotation_ports: The authority and share-holder calls the forced
            rotation at expiry makes (ADR-0069). Without them break-glass is
            refused with 503: a session that cannot be rotated must not open.
        service_root: The federation root callers' service certificates must
            chain to; defaults to ``trust.root``. One of the two is required.

    Returns:
        Configured FastAPI application instance.

    Raises:
        ValueError: No federation root to authenticate callers against, or an
            audit service URL with no identity to sign appends with.
    """
    repo = repository or InMemoryStorageRepository()
    root = service_root or (trust.root if trust is not None else None)
    if root is None:
        raise ValueError(
            "a facility needs the federation root to authenticate its callers "
            "(ADR-0066): pass trust or service_root"
        )
    if audit_service_url and identity is None:
        raise ValueError("a facility that logs to the audit service must sign")
    audit_auth = (
        SignedRequestAuth(identity, {audit_service_url: AUDIT_SERVICE_ID})
        if audit_service_url and identity is not None
        else None
    )
    if expiry_manager is not None:
        expiry_manager.attach_state_writer(repo.transition_lifecycle_state)
        if rotation_ports is not None:
            expiry_manager.attach_rotator(FacilityRotator(repo, rotation_ports))
            # Open sessions survive a restart as rows with no key; the ones a
            # previous process left are closed with a rotation now (ADR-0073).
            expiry_manager.attach_session_store(
                RepositorySessionStore(repo, facility_id)
            )
            recover_emergency_sessions(repo, expiry_manager, facility_id)
    # Backed by the store so a facility restart does not re-open replay (F22).
    consumed_assertions = ConsumedAssertionIds(backend=repo)
    # Patient-signed revocations go through the state machine too, so their
    # event ids are one-time across restarts (ADR-0072).
    revocation_machine = LifecycleStateMachine(ConsumedEventIds(backend=repo))
    # Clinical labels are trusted only when their patient signature verifies
    # against these anchors; otherwise the strictest rules apply (ADR-0064).
    label_trust = (
        LabelTrust(
            facility_cas=trust.facility_cas,
            trusted_root=trust.root,
            revoked_serials=trust.revoked_serials,
        )
        if trust is not None
        else None
    )

    def patient_key(certificate_pem: str | None, patient_id: str) -> ECPublicKey:
        """``patient_id``'s key from a certificate a configured CA issued.

        Never a key the caller supplies (ADR-0064): a forger would sign with
        their own and send that.
        """
        if trust is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="consent verification needs configured trust anchors",
            )
        if not certificate_pem:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="patient_certificate_pem required to verify consent grant",
            )
        try:
            certificate = certificate_from_pem(certificate_pem.encode("utf-8"))
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid patient certificate PEM: {exc}",
            ) from exc
        try:
            validate_patient_certificate(
                certificate,
                patient_id=patient_id,
                facility_cas=trust.facility_cas,
                trusted_root=trust.root,
                revoked_serials=trust.revoked_serials,
            )
        except (
            ChainValidationError,
            CertificateExpiredError,
            PatientCertificateError,
        ) as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Patient certificate refused: {exc}",
            ) from exc
        return certificate_public_key(certificate)

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
        """Read and decrypt an encrypted health record under policy or consent.

        Object-level authorization runs before any storage access (review F34,
        ADR-0066): the caller is already an authenticated key agent, and a
        requester presenting no attribute key can open nothing, so it is
        refused before the record, its wrapping or its policy is loaded.
        """
        if _presents_no_key(payload):
            _log_denial(
                audit_url,
                repo,
                audit_key,
                sink=audit_sink,
                audit_auth=audit_auth,
                record_id=record_id,
                requester_id=payload.requester_id,
                denied_by=DENIED_BY_POLICY,
                reason="requester presented no attribute key",
                actor_id=facility_id,
                correlation_id=payload.correlation_id or str(uuid4()),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Policy denied: no attribute key presented for this record",
            )
        record = repo.get_record(record_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Record {record_id!r} not found",
            )

        wrapping = repo.get_wrapping_for_record(record_id, wrapped_for=record.policy_id)
        # Only patient-signed labels can relax this; unsigned or tampered
        # labels require consent (ADR-0064).
        rules = disclosure_rules(record, label_trust)
        if (
            rules.consent_for_read
            and payload.requester_id != record.patient_id
            and payload.grant is None
        ):
            _log_denial(
                audit_url,
                repo,
                audit_key,
                sink=audit_sink,
                audit_auth=audit_auth,
                record_id=record_id,
                requester_id=payload.requester_id,
                denied_by=DENIED_BY_CONSENT,
                reason="Patient-signed care-episode consent required",
                actor_id=facility_id,
                correlation_id=payload.correlation_id or str(uuid4()),
            )
            raise HTTPException(
                403,
                "A patient-signed care-episode grant is required; "
                "specialty alone is not a treating relationship",
            )
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
            patient_pub = patient_key(
                payload.patient_certificate_pem, record.patient_id
            )

            access_via = ACCESS_VIA_CONSENT
            try:
                # Revocation is terminal for this request, including after the
                # revocation artifact expires. Re-consent requires a new request.
                for decision in repo.list_consent_grants_by_patient(record.patient_id):
                    if (
                        decision.request_id == payload.grant.request_id
                        and decision.grantee_id == payload.requester_id
                        and decision.status == ConsentStatus.REVOKED
                    ):
                        try:
                            verify_consent_grant(decision, patient_pub)
                        except InvalidSignatureError:
                            # Not signed by this patient, so not a revocation of
                            # theirs: skip it rather than fail the read with 500.
                            _logger.error(
                                "stored revocation %s for record %s does not "
                                "verify; ignoring it",
                                decision.grant_id,
                                record_id,
                            )
                            continue
                        raise ConsentRevokedError(
                            "A stored patient revocation supersedes this grant"
                        )
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
                    sink=audit_sink,
                    audit_auth=audit_auth,
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
                    sink=audit_sink,
                    audit_auth=audit_auth,
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
                _log_denial(
                    audit_url,
                    repo,
                    audit_key,
                    sink=audit_sink,
                    audit_auth=audit_auth,
                    record_id=record_id,
                    requester_id=payload.requester_id,
                    denied_by=DENIED_BY_DEK_UNWRAP,
                    reason=str(exc),
                    actor_id=facility_id,
                    correlation_id=payload.correlation_id or str(uuid4()),
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"DEK unwrapping failed: {exc}",
                ) from exc

        # 2. Otherwise, direct policy unwrap (e.g. owner access or in-network read)
        else:
            access_via = ACCESS_VIA_POLICY
            try:
                plaintext_bytes = decrypt_record_via_policy(
                    compiled_policy, keyring, wrapping, record
                )
            except PolicyDeniedError as exc:
                _log_denial(
                    audit_url,
                    repo,
                    audit_key,
                    sink=audit_sink,
                    audit_auth=audit_auth,
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
                _log_denial(
                    audit_url,
                    repo,
                    audit_key,
                    sink=audit_sink,
                    audit_auth=audit_auth,
                    record_id=record_id,
                    requester_id=payload.requester_id,
                    denied_by=DENIED_BY_DEK_UNWRAP,
                    reason=str(exc),
                    actor_id=facility_id,
                    correlation_id=payload.correlation_id or str(uuid4()),
                )
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
            sink=audit_sink,
            audit_auth=audit_auth,
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
        """Register a ConsentRequest its clinician signed (ADR-0072).

        Verified against the clinician's certificate from a configured CA;
        the facility never holds the clinician's key.
        """
        req = payload.request
        if trust is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="consent verification needs configured trust anchors",
            )
        try:
            certificate = certificate_from_pem(
                payload.requester_certificate_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid requester certificate PEM: {exc}",
            ) from exc
        try:
            validate_clinician_certificate(
                certificate,
                clinician_id=req.requester_id,
                facility_cas=trust.facility_cas,
                trusted_root=trust.root,
                revoked_serials=trust.revoked_serials,
            )
            verify_consent_request(req, certificate_public_key(certificate))
        except (
            ChainValidationError,
            CertificateExpiredError,
            SubjectCertificateError,
            InvalidSignatureError,
            ConsentExpiredError,
        ) as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Consent request refused ({exc.__class__.__name__}): {exc}",
            ) from exc
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
        """Submit and verify a patient-signed ConsentGrant.

        A revocation arrives the same way: the patient's signed ``REVOKED``
        grant, signed in the custodian (ADR-0072). A revocation is final for
        its request: once one is stored, a ``GRANTED`` decision on the same
        request -- the earlier copy, still validly signed -- is refused here,
        as the read path already refuses it (review F13).
        """
        patient_pub = patient_key(
            payload.patient_certificate_pem, payload.grant.patient_id
        )

        try:
            verify_consent_grant(payload.grant, patient_pub)
        except InvalidSignatureError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Consent grant signature verification failed: {exc}",
            ) from exc

        revoked = payload.grant.status is ConsentStatus.REVOKED
        if not revoked and any(
            decision.request_id == payload.grant.request_id
            and decision.status is ConsentStatus.REVOKED
            for decision in repo.list_consent_grants_by_patient(
                payload.grant.patient_id
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"consent request {payload.grant.request_id} was revoked; "
                    "re-consent needs a new request"
                ),
            )
        repo.store_consent_grant(payload.grant)
        return ConsentResponse(
            status="revoked" if revoked else "accepted",
            grant=payload.grant,
            message=(
                "Consent grant revocation verified and stored"
                if revoked
                else "Consent grant verified and stored"
            ),
        )

    # --- Revocation by Key Rotation Endpoint (P3-7, P3-12, ADR-0072) ---------

    @app.post("/records/{record_id}/revoke", response_model=RevokeRecordResponse)
    def revoke_record(
        record_id: str,
        payload: RevokeRecordRequest,
        repo: RepoDep,
        audit_key: AuditKeyDep,
        audit_url: AuditUrlDep,
    ) -> RevokeRecordResponse:
        """A patient revokes access to their record by key rotation (ADR-0072).

        Order: verify the patient-signed ``GRANTED -> REVOKED`` against the
        patient's certificate (theirs, this record, from its current state,
        recent, never seen before) -> plan the rotation from the store under
        the revoked access tree -> log the revocation (log-before-commit) ->
        claim the state (compare-and-set) -> store the rotation and the event
        in one go, undoing the claim on failure -> hand the new emergency
        shares to their holders.

        The rotation is the expiry one (ADR-0069): new DEK and policy root,
        and a new emergency key, so break-glass on the revoked record still
        works with the holders' new shares and the old ones open nothing.
        """
        corr_id = payload.correlation_id or str(uuid4())
        event = payload.transition_event

        def deny(reason: str, code: int, detail: str) -> HTTPException:
            _log_denial(
                audit_url,
                repo,
                audit_key,
                sink=audit_sink,
                audit_auth=audit_auth,
                record_id=record_id,
                requester_id=event.actor_id,
                denied_by=DENIED_BY_REVOCATION_AUTHZ,
                reason=reason,
                actor_id=facility_id,
                correlation_id=corr_id,
            )
            return HTTPException(status_code=code, detail=detail)

        if rotation_ports is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "revocation re-keys the record and its break-glass path; "
                    "this facility has no rotation configured (ADR-0069)"
                ),
            )
        record = repo.get_record(record_id)
        if not record:
            raise deny(
                "record not found",
                status.HTTP_404_NOT_FOUND,
                f"Record {record_id!r} not found",
            )

        # 1. Only the record's patient revokes, under their own certified key.
        try:
            patient_pub = patient_key(
                payload.patient_certificate_pem, record.patient_id
            )
        except HTTPException as exc:
            raise deny(str(exc.detail), exc.status_code, str(exc.detail)) from exc
        compiled = repo.get_compiled_policy(record.policy_id)
        if compiled is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Compiled policy of record {record_id!r} not found",
            )
        try:
            new_tree = revoked_policy_tree(
                current_tree=policy_tree_of(compiled),
                new_clinical_policy=payload.new_clinical_policy,
                patient_id=record.patient_id,
            )
            check_revocation_authorization(
                actor_id=event.actor_id,
                record=record,
                owner_authority_id="",  # authorities do not sign revocations here
            )
        except UnauthorizedRevocationError as exc:
            raise deny(
                str(exc), status.HTTP_403_FORBIDDEN, f"Unauthorized revocation: {exc}"
            ) from exc

        source_state = _current_lifecycle_state(repo, record_id)
        if event.from_state is not source_state:
            reason = (
                f"revocation was signed from {event.from_state.value!r}; the "
                f"record is {source_state.value!r}"
            )
            raise deny(reason, status.HTTP_409_CONFLICT, reason)
        now = datetime.now(timezone.utc)
        if (
            event.record_id != record_id
            or event.to_state is not LifecycleState.REVOKED
            or event.issued_at < now - MAX_ASSERTION_TTL
            or event.issued_at > now + ASSERTION_CLOCK_SKEW
        ):
            reason = "transition event is not a recent revocation of this record"
            raise deny(reason, status.HTTP_400_BAD_REQUEST, reason)
        try:
            revocation_machine.apply_transition(source_state, event, patient_pub)
        except (
            InvalidSignatureError,
            IllegalTransitionError,
            MissingReasonCodeError,
            StateMismatchError,
            ReplayedEventError,
        ) as exc:
            raise deny(
                str(exc),
                status.HTTP_403_FORBIDDEN,
                f"Revocation refused ({exc.__class__.__name__}): {exc}",
            ) from exc

        # 2. Plan the rotation under the revoked tree (nothing stored yet).
        rotator = FacilityRotator(repo, rotation_ports)
        try:
            plan = rotator.plan_from_store(record_id, new_tree=new_tree)
        except (RotationError, httpx.HTTPError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"revocation could not re-key the record: {exc}",
            ) from exc
        except (PolicyCompileError, PolicyDeniedError, RecordError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"revocation could not re-key the record: {exc}",
            ) from exc

        # 3. Log-before-commit (review F10): an audit outage raises (503).
        _log_event(
            audit_url,
            repo,
            audit_key,
            sink=audit_sink,
            audit_auth=audit_auth,
            event_type=EVENT_RECORD_REVOKED,
            event_data={
                "record_id": record_id,
                "actor_id": event.actor_id,
                "event_id": str(event.event_id),
                "old_policy_id": record.policy_id,
                "new_policy_id": plan.record.policy_id,
                "new_generation": plan.baseline_wrapping.generation,
                "emergency_generation": plan.generation,
            },
            actor_id=facility_id,
            correlation_id=corr_id,
        )

        # 4. Claim the state; of two concurrent changes exactly one wins (N1).
        try:
            repo.transition_lifecycle_state(
                record_id,
                expected=source_state,
                new=LifecycleState.REVOKED,
                last_event_id=str(event.event_id),
            )
        except StateConflictError as exc:
            raise deny(
                str(exc), status.HTTP_409_CONFLICT, f"Revocation refused: {exc}"
            ) from exc

        # 5. Store the rotation (atomic, compare-and-set on the ciphertext).
        try:
            repo.apply_rotation(plan)
            repo.insert_transition_event(event)
        except Exception as exc:
            try:
                repo.transition_lifecycle_state(
                    record_id, expected=LifecycleState.REVOKED, new=source_state
                )
            except StateConflictError:
                _logger.error(
                    "could not roll back the revocation claim on record %s",
                    record_id,
                )
            if isinstance(exc, RotationConflictError):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Revocation refused: {exc}",
                ) from exc
            raise

        # 6. New shares to their holders. The revocation already holds; if a
        # holder is unreachable, break-glass on this record fails closed until
        # it is re-keyed, and the response says so.
        provisioned = True
        try:
            rotator.deposit(plan)
        except httpx.HTTPError as exc:
            provisioned = False
            _logger.error(
                "revocation of %s stored, but its new emergency shares were not "
                "delivered (%s); break-glass on it is closed until re-keyed",
                record_id,
                exc,
            )

        return RevokeRecordResponse(
            record_id=record_id,
            new_generation=plan.baseline_wrapping.generation,
            new_policy_id=plan.record.policy_id,
            transition_event=event,
            breakglass_provisioned=provisioned,
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
        """Execute 2-of-3 threshold emergency unlock for a record (P3-5).

        Order (review F7): parse and validate everything the caller sent,
        claim the lifecycle state with a compare-and-set, run the gate, log
        the re-wrap (log-before-release), register the expiry session, then
        record the signed event. Any failure after the claim undoes it, so a
        refused or failed unlock leaves the record as it was.

        A record that is already EMERGENCY_OPEN with a live session here is
        joined, not refused (ADR-0057): a second clinician, or the first one
        viewing it again, passes the same validation and threshold and the
        audit entry is still committed before the DEK is delivered, but no
        transition is signed and the window is not extended.
        """
        corr_id = payload.correlation_id or str(uuid4())
        clinician_id = payload.assertion.clinician_id

        def deny(denied_by: str, reason: str, code: int, detail: str) -> HTTPException:
            # Every refusal is audited with its own reason (review F8).
            _log_denial(
                audit_url,
                repo,
                audit_key,
                sink=audit_sink,
                audit_auth=audit_auth,
                record_id=record_id,
                requester_id=clinician_id,
                denied_by=denied_by,
                reason=reason,
                actor_id=facility_id,
                correlation_id=corr_id,
            )
            return HTTPException(status_code=code, detail=detail)

        exp_manager = app.state.expiry_manager
        if trust is None or exp_manager is None or rotation_ports is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "break-glass is not configured on this facility: it needs "
                    "configured trust anchors, an expiry manager and the "
                    "rotation that expiry runs (ADR-0069)"
                ),
            )

        # 1. Parse the caller's inputs before anything else (F7).
        try:
            cl_cert = certificate_from_pem(
                payload.clinician_certificate_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Certificate parsing failed: {exc}",
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
        # A caller may shorten the configured time-box, never extend it (F6).
        configured = exp_manager.default_duration_seconds
        duration = min(payload.emergency_duration_seconds or configured, configured)

        # 2. Validate the assertion against configured trust anchors (F1).
        issuer = trust.issuing_ca(cl_cert)
        if issuer is None:
            reason = "clinician certificate was not issued by a configured facility CA"
            raise deny(
                DENIED_BY_BREAKGLASS_CHAIN,
                reason,
                status.HTTP_403_FORBIDDEN,
                f"Emergency assertion refused: {reason}",
            )
        clinician_facility_id, ca_cert = issuer
        clinician_pub = certificate_public_key(cl_cert)
        try:
            validate_emergency_assertion(
                assertion=payload.assertion,
                clinician_certificate=cl_cert,
                facility_ca_certificate=ca_cert,
                trusted_root=trust.root,
                expected_facility_id=facility_id,
                consumed_store=consumed_store,
                revoked_serials=trust.revoked_serials,
            )
        except (
            ChainValidationError,
            CertificateExpiredError,
            CertificateRevokedError,
        ) as exc:
            raise deny(
                DENIED_BY_BREAKGLASS_CHAIN,
                str(exc),
                status.HTTP_403_FORBIDDEN,
                f"Clinician certificate refused ({exc.__class__.__name__}): {exc}",
            ) from exc
        except (
            AssertionExpiredError,
            AssertionLifetimeError,
            ClinicianMismatchError,
            FacilityMismatchError,
            InvalidSignatureError,
            ReplayedAssertionError,
        ) as exc:
            raise deny(
                DENIED_BY_BREAKGLASS_ASSERTION,
                str(exc),
                status.HTTP_400_BAD_REQUEST,
                f"Emergency assertion invalid ({exc.__class__.__name__}): {exc}",
            ) from exc

        # 3. Fetch record and emergency DEK wrapping
        record = repo.get_record(record_id)
        if not record:
            raise deny(
                DENIED_BY_RECORD_NOT_FOUND,
                "record not found",
                status.HTTP_404_NOT_FOUND,
                f"Record {record_id!r} not found",
            )

        # An assertion opens the patient it names and nobody else
        # (ARCHITECTURE.md §8). Checked before any lifecycle change so a
        # mismatched assertion has no side effect on the record.
        if record.patient_id != payload.assertion.patient_id:
            reason = "assertion patient_id does not match the record's patient"
            raise deny(
                "breakglass_patient_binding",
                reason,
                status.HTTP_403_FORBIDDEN,
                f"Emergency assertion not valid for this record: {reason}",
            )

        # Requirements come from patient-signed labels only; unsigned or
        # tampered labels get every requirement (ADR-0064).
        rules = disclosure_rules(record, label_trust)
        if not rules.labels_verified and record.clinical.signature is not None:
            _logger.error(
                "record %s labels do not verify; applying the strictest rules: %s",
                record_id,
                rules.reason,
            )
        if (
            rules.clinical_justification
            or rules.sensitive_justification
            or payload.assertion.clinical_context_digest
        ):
            try:
                validate_clinical_context(
                    payload.assertion,
                    record_id,
                    payload.justification,
                    payload.sensitive_justification,
                )
            except ValueError as exc:
                raise deny("clinical_context", str(exc), 403, str(exc)) from exc
            if rules.clinical_justification and len(payload.justification.strip()) < 20:
                raise deny(
                    "clinical_context",
                    "clinical necessity required",
                    403,
                    "Explain the immediate clinical need (at least 20 characters)",
                )
        if (
            rules.sensitive_justification
            and len(payload.sensitive_justification.strip()) < 20
        ):
            raise deny(
                "restricted_record",
                "explicit necessity required",
                403,
                "Restricted record: explicit clinical necessity is required",
            )
        wrapping = repo.get_wrapping_for_record(record_id, wrapped_for="emergency")
        if not wrapping:
            wrapping = repo.get_wrapping_for_record(record_id)
        if not wrapping:
            raise deny(
                DENIED_BY_RECORD_NOT_FOUND,
                "no DEK wrapping",
                status.HTTP_404_NOT_FOUND,
                f"No DEK wrapping found for record {record_id!r}",
            )

        def gate(
            call: Callable[[], EmergencyUnlockResult | bytes]
        ) -> EmergencyUnlockResult | bytes:
            """Run the threshold gate, turning each refusal into an audited deny."""
            try:
                return call()
            except InsufficientSharesError as exc:
                raise deny(
                    DENIED_BY_BREAKGLASS_GATE,
                    str(exc),
                    status.HTTP_400_BAD_REQUEST,
                    f"Insufficient threshold shares: {exc}",
                ) from exc
            except SecretSharingError as exc:
                raise deny(
                    DENIED_BY_BREAKGLASS_GATE,
                    str(exc),
                    status.HTTP_400_BAD_REQUEST,
                    f"Invalid threshold shares: {exc}",
                ) from exc
            except UnwrappingError as exc:
                raise deny(
                    DENIED_BY_BREAKGLASS_GATE,
                    str(exc),
                    status.HTTP_403_FORBIDDEN,
                    f"Emergency unlock rejected: {exc}",
                ) from exc
            except (
                IllegalTransitionError,
                MissingReasonCodeError,
                InvalidSignatureError,
            ) as exc:
                raise deny(
                    DENIED_BY_BREAKGLASS_TRANSITION,
                    str(exc),
                    status.HTTP_403_FORBIDDEN,
                    f"Emergency unlock rejected: {exc}",
                ) from exc

        # 4. Already open: join the live session (ADR-0057).
        source_state = _current_lifecycle_state(repo, record_id)
        if source_state is LifecycleState.EMERGENCY_OPEN:
            try:
                session_expires_at, opener_facility_id = exp_manager.join_window(
                    record_id
                )
            except (SessionNotFoundError, EmergencySessionExpiredError) as exc:
                # Sessions live at the record's own facility, and the custodian
                # and portal route every viewer there (ADR-0061), so this is
                # reached only by a request sent to the wrong node.
                reason = (
                    "record is already emergency_open and this facility holds "
                    f"no live session to join ({exc})"
                )
                raise deny(
                    DENIED_BY_BREAKGLASS_TRANSITION,
                    reason,
                    status.HTTP_409_CONFLICT,
                    reason,
                ) from exc
            # Only the opener's own facility joins: the care team on scene, not
            # any credentialed clinician in the federation (ADR-0063).
            if clinician_facility_id != opener_facility_id:
                reason = (
                    f"emergency session was opened by {opener_facility_id!r}; a "
                    f"clinician of {clinician_facility_id!r} cannot join it"
                )
                raise deny(
                    "breakglass_join_facility",
                    reason,
                    status.HTTP_403_FORBIDDEN,
                    f"Break-glass refused: {reason}",
                )
            rewrapped = gate(
                lambda: join_emergency_access(
                    shares_presented=shares_list,
                    dek_wrapping=wrapping,
                    record_id=record_id,
                    pre_rewrap_key=payload.pre_rewrap_key,
                )
            )
            # Log-before-release: an audit outage raises and nothing is sent.
            _log_rewrap(
                audit_url,
                repo,
                audit_key,
                sink=audit_sink,
                audit_auth=audit_auth,
                record_id=record_id,
                source_facility_id=record.facility_id,
                target_actor_id=clinician_id,
                actor_id=facility_id,
                correlation_id=corr_id,
            )
            return BreakglassUnlockResponse(
                record_id=record_id,
                rewrapped_dek_b64=base64.b64encode(rewrapped).decode("ascii"),
                transition_event=None,
                joined=True,
                correlation_id=corr_id,
                expires_at=session_expires_at,
                message="Joined the open emergency session; DEK re-wrapped",
            )

        if payload.join_only:
            reason = "no open emergency session to join for this record"
            raise deny(
                DENIED_BY_BREAKGLASS_TRANSITION,
                reason,
                status.HTTP_409_CONFLICT,
                reason,
            )

        # 4b. The transition the clinician signed (ADR-0068, D8-a): it must be
        # theirs, for this record, from its current state, with the
        # assertion's reason, recent -- all checked before any side effect.
        event = payload.transition_event
        if event is None:
            reason = "opening needs the clinician-signed transition event"
            raise deny(
                DENIED_BY_BREAKGLASS_TRANSITION,
                reason,
                status.HTTP_400_BAD_REQUEST,
                reason,
            )
        if event.from_state is not source_state:
            reason = (
                f"transition was signed from {event.from_state.value!r}; the "
                f"record is {source_state.value!r} (sign it again)"
            )
            raise deny(
                DENIED_BY_BREAKGLASS_TRANSITION,
                reason,
                status.HTTP_409_CONFLICT,
                reason,
            )
        now = exp_manager.now()
        if (
            event.record_id != record_id
            or event.to_state is not LifecycleState.EMERGENCY_OPEN
            or event.actor_id != clinician_id
            or event.reason_code is not payload.assertion.reason_code
            or event.issued_at < now - MAX_ASSERTION_TTL
            or event.issued_at > now + ASSERTION_CLOCK_SKEW
        ):
            reason = (
                "transition event is not this clinician's recent "
                "emergency_open of this record for the asserted reason"
            )
            raise deny(
                DENIED_BY_BREAKGLASS_TRANSITION,
                reason,
                status.HTTP_400_BAD_REQUEST,
                reason,
            )
        try:
            verify_transition_event(event, clinician_pub)
        except (
            InvalidSignatureError,
            IllegalTransitionError,
            MissingReasonCodeError,
        ) as exc:
            raise deny(
                DENIED_BY_BREAKGLASS_TRANSITION,
                str(exc),
                status.HTTP_400_BAD_REQUEST,
                "Transition event does not verify against the clinician's "
                f"certificate: {exc}",
            ) from exc

        # 5. Claim the state (N1, F7): of two concurrent opens exactly one wins.
        try:
            repo.transition_lifecycle_state(
                record_id, expected=source_state, new=LifecycleState.EMERGENCY_OPEN
            )
        except StateConflictError as exc:
            raise deny(
                DENIED_BY_BREAKGLASS_TRANSITION,
                str(exc),
                status.HTTP_409_CONFLICT,
                f"Break-glass refused: {exc}",
            ) from exc

        session_registered = False
        try:
            # 5b. Apply the event through the state machine, which consumes its
            # one-time id: a replayed event opens nothing (§8).
            try:
                exp_manager.state_machine.apply_transition(
                    source_state, event, clinician_pub
                )
            except ReplayedEventError as exc:
                raise deny(
                    DENIED_BY_BREAKGLASS_TRANSITION,
                    str(exc),
                    status.HTTP_400_BAD_REQUEST,
                    f"Transition event replayed: {exc}",
                ) from exc

            # 6. Open emergency access via 2-of-3 threshold gate
            unlock_result = gate(
                lambda: open_emergency_access(
                    shares_presented=shares_list,
                    dek_wrapping=wrapping,
                    transition_source_state=source_state,
                    record_id=record_id,
                    transition_event=event,
                    actor_public_key=clinician_pub,
                    pre_rewrap_key=payload.pre_rewrap_key,
                )
            )

            # 7. Log-before-release: an audit outage raises (503) and undoes
            # the claim below, so nothing is released without a chain entry.
            _log_rewrap(
                audit_url,
                repo,
                audit_key,
                sink=audit_sink,
                audit_auth=audit_auth,
                record_id=record_id,
                source_facility_id=record.facility_id,
                target_actor_id=clinician_id,
                actor_id=facility_id,
                correlation_id=corr_id,
            )

            # 8. Every unlock is time-boxed; there is no path that skips it.
            try:
                session = exp_manager.register_session(
                    record_id=record_id,
                    actor_id=clinician_id,
                    opener_facility_id=clinician_facility_id,
                    correlation_id=corr_id,
                    emergency_key=unlock_result.emergency_key,
                    emergency_wrapping=wrapping,
                    current_record=record,
                    return_state=source_state,
                    duration_seconds=duration,
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Failed to register emergency session: {exc}",
                ) from exc
            session_registered = True

            # 9. Record the signed event against the claimed state.
            repo.insert_transition_event(event)
            repo.transition_lifecycle_state(
                record_id,
                expected=LifecycleState.EMERGENCY_OPEN,
                new=LifecycleState.EMERGENCY_OPEN,
                last_event_id=str(event.event_id),
            )
        except Exception:
            if session_registered:
                exp_manager.unregister_session(record_id)
            try:
                repo.transition_lifecycle_state(
                    record_id, expected=LifecycleState.EMERGENCY_OPEN, new=source_state
                )
            except StateConflictError:
                _logger.error(
                    "could not roll back the break-glass claim on record %s", record_id
                )
            raise

        return BreakglassUnlockResponse(
            record_id=record_id,
            rewrapped_dek_b64=base64.b64encode(unlock_result.rewrapped_dek).decode(
                "ascii"
            ),
            transition_event=event,
            correlation_id=corr_id,
            expires_at=session.expires_at,
        )

    @app.get("/records/{record_id}/lifecycle", response_model=LifecycleStateResponse)
    def lifecycle_state(record_id: str, repo: RepoDep) -> LifecycleStateResponse:
        """The record's stored lifecycle state.

        The custodian signs the clinician's ``EMERGENCY_OPEN`` transition from
        it (ADR-0068). If the state moves before the transition arrives the
        open is refused with 409 and the custodian signs again.
        """
        state = repo.get_lifecycle_state(record_id)
        if state is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Record {record_id!r} not found",
            )
        return LifecycleStateResponse(record_id=record_id, state=state)

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
            sink=audit_sink,
            audit_auth=audit_auth,
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
        audit_key: AuditKeyDep,
        audit_url: AuditUrlDep,
    ) -> SearchRecordsResponse:
        """Search encrypted index using active emergency session (P3-8).

        Every search is audited with the requesting clinician (review F8):
        a refusal as a denial, a result as an access, logged before release.
        """
        corr_id = payload.correlation_id or str(uuid4())
        exp_manager = app.state.expiry_manager
        if not exp_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Emergency expiry manager not configured on this facility node",
            )

        # The token is derived in search.service, for either repository
        # (CONVENTIONS.md §2 rule 10, review F33).
        try:
            coded_term = emergency_search_token(
                exp_manager, record_id, payload.search_term
            )
            matches = repo.find_records_by_search_term(coded_term)
        except (EmergencySessionExpiredError, SessionNotFoundError) as exc:
            _log_denial(
                audit_url,
                repo,
                audit_key,
                sink=audit_sink,
                audit_auth=audit_auth,
                record_id=record_id,
                requester_id=payload.requester_id,
                denied_by=DENIED_BY_EMERGENCY_SEARCH,
                reason=str(exc),
                actor_id=facility_id,
                correlation_id=corr_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Emergency search unavailable: {exc}",
            ) from exc

        _log_granted(
            audit_url,
            repo,
            audit_key,
            sink=audit_sink,
            audit_auth=audit_auth,
            record_id=record_id,
            requester_id=payload.requester_id,
            access_via=ACCESS_VIA_EMERGENCY_SEARCH,
            actor_id=facility_id,
            correlation_id=corr_id,
        )
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
        """Ingest, encrypt, compile policy, wrap DEK, and index a record (P3-14).

        A ``record_id`` that already exists is refused with 409 (review F4):
        overwriting would orphan the emergency shares deposited for it.
        """
        if payload.record_id is not None and repo.get_record(payload.record_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Record {payload.record_id!r} already exists",
            )
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
                clinical=payload.clinical,
            )
        except (ValueError, PolicyCompileError, RecordError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Ingest failed: {exc}",
            ) from exc

        # Signed labels must verify before they are stored; unsigned labels are
        # stored as they are and get the strictest rules (ADR-0064).
        if result.record.clinical.signature is not None and label_trust is not None:
            try:
                verify_clinical_labels(result.record, label_trust)
            except LabelVerificationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Ingest refused: {exc}",
                ) from exc

        try:
            repo.insert_record(result.record)
        except RecordExistsError as exc:
            # A concurrent ingest won the primary key between the check and
            # the insert.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Record {result.record.record_id!r} already exists",
            ) from exc
        repo.insert_dek_wrapping(result.dek_wrapping)
        if result.emergency_dek_wrapping:
            repo.insert_dek_wrapping(result.emergency_dek_wrapping)
        repo.store_compiled_policy(result.record.policy_id, result.compiled_policy)
        repo.insert_lifecycle_state(
            record_id=result.record.record_id,
            state=result.lifecycle_state,
        )
        for _term, token in result.search_tokens.items():
            repo.insert_search_term(result.record.record_id, token)
        if result.sealed_search_terms is not None:
            repo.put_sealed_search_terms(
                result.record.record_id, result.sealed_search_terms
            )

        return IngestRecordResponse(
            record_id=result.record.record_id,
            policy_id=result.record.policy_id,
            wrapping_id=result.dek_wrapping.wrapping_id,
            lifecycle_state=result.lifecycle_state,
            search_terms_indexed=len(result.search_tokens),
        )

    install_service_auth(
        app,
        ServiceAuthConfig(
            service_id=facility_id,
            trusted_root=root,
            permissions=FACILITY_PERMISSIONS,
            public_routes=FACILITY_PUBLIC_ROUTES,
            # Backed by the store, so a restart does not reopen replay (F22).
            replay=ConsumedRequestIds(backend=repo),
        ),
    )
    return app
