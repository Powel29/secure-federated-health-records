"""Standalone Audit Service (P4-2, C10/C11, ARCHITECTURE.md §5 step 3, §7).

Runs the hash-chained audit log and break-glass share-3 custody as their own
process, separate from any facility node:

    "The audit service must be a separate process. If it shares memory with
    a facility node, 'the audit service releases its share only after
    committing' becomes an in-process function call that a reviewer can
    dismiss as a convention rather than an enforced precondition."
    (ARCHITECTURE.md §7)

This module is that enforced precondition, reachable only over HTTP. It does
not generate, split, or reconstruct any secret -- ``audit.share_custody`` and
``audit.share_registry`` already do that job; this module only exposes them.

Invariants:
- CONVENTIONS.md §2 rule 10: no cryptography in route handlers. Every hash,
  signature, and chain-link check happens inside ``audit.chain`` /
  ``audit.share_custody``.
- Every write takes only a signed request from a federation service whose
  kind the route allows (ADR-0066); chain reads and the public key are open.
- Share 3 is released only against an emergency assertion this service has
  validated itself, against its own configured trust anchors (ADR-0067).
- The signing key never leaves this process; only its public key
  (``GET /public-key``) is ever returned.
- Every request that appends to the chain is serialized behind one
  process-local lock (see ``_lock`` below), closing the concurrent-``seq``
  race ADR-0034 documents and explicitly defers to this task: "a liveness
  concern ... left as a documented limitation for P4-2 (the audit service
  process) to address if the demo topology needs it." Since this service is
  the sole writer of the chain, a single in-process lock is sufficient as
  long as it runs as one process with one worker (ADR-0039) -- a
  multi-worker deployment would need a real cross-process lock instead, and
  is out of scope for this project's demo topology.
"""

from __future__ import annotations

import threading
from typing import Annotated

import psycopg
from audit.chain import append_entry, create_genesis_entry, verify_full_chain
from audit.exceptions import (
    AuditCommitFailedError,
    ChainBreakError,
    EmptyChainError,
    TamperedEntryError,
)
from audit.share_custody import release_share_after_commit
from audit.share_registry import (
    ShareAlreadyHeldError,
    ShareGenerationError,
    ShareNotFoundError,
    ShareRegistry,
)
from breakglass import (
    ConsumedAssertionIds,
    ConsumedRequestIds,
    validate_emergency_assertion,
)
from breakglass.assertion import validate_clinical_context
from breakglass.emergency_key import Share
from breakglass.exceptions import (
    AssertionExpiredError,
    AssertionLifetimeError,
    CertificateRevokedError,
    ClinicianMismatchError,
    FacilityMismatchError,
    ReplayedAssertionError,
    SealedShareError,
)
from breakglass.share_sealing import (
    SealedShare,
    ShareRecipient,
    ShareSealingKey,
    make_key_statement,
    open_sealed_share,
    seal_share,
    verify_key_statement,
)
from contracts.enums import LifecycleState
from crypto_core import certificate_from_pem, generate_ec_keypair, public_key_to_pem
from crypto_core.exceptions import (
    CertificateExpiredError,
    InvalidSignatureError,
    KeyFormatError,
)
from crypto_core.types import ECPrivateKey, ECPublicKey
from cryptography.x509 import Certificate
from fastapi import Depends, FastAPI, HTTPException, Request, status
from identity.exceptions import ChainValidationError
from storage.repositories import (
    ConsumedIdTable,
    get_chain_head,
    get_lifecycle_state,
    insert_audit_entry,
)

from api.audit_schemas import (
    AppendEntryRequest,
    AppendEntryResponse,
    ChainHeadResponse,
    ChainVerifyResponse,
    HealthResponse,
    PublicKeyResponse,
    RegisterShareRequest,
    RegisterShareResponse,
    ReleaseShareRequest,
    ReleaseShareResponse,
    ReplaceShareRequest,
)
from api.hospital import FacilityTrust
from api.service_auth import (
    ServiceAuthConfig,
    ServiceIdentity,
    install_service_auth,
)
from api.share_transport import serve_share_key

AUDIT_SERVICE_ID = "audit-service"

# Which kinds of federation service may call each write (ADR-0066).
AUDIT_PERMISSIONS: dict[tuple[str, str], frozenset[str]] = {
    ("POST", "/entries"): frozenset({"facility", "portal", "custodian", "bootstrap"}),
    ("POST", "/breakglass/shares"): frozenset({"custodian", "bootstrap"}),
    ("PUT", "/breakglass/shares/{share_key}"): frozenset({"facility"}),
    ("POST", "/breakglass/release"): frozenset({"custodian", "bootstrap"}),
}
# Public integrity data: anyone may read and verify the chain.
AUDIT_PUBLIC_ROUTES = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/public-key"),
        ("GET", "/chain/head"),
        ("GET", "/chain/verify"),
    }
)


def get_conn(request: Request) -> psycopg.Connection:
    """Extract the shared-store connection from application state."""
    return request.app.state.conn


def get_shares(request: Request) -> ShareRegistry:
    """Extract the held-share registry from application state."""
    return request.app.state.shares


def get_lock(request: Request) -> threading.Lock:
    """Extract the append-serialization lock from application state."""
    return request.app.state.lock


ConnDep = Annotated[psycopg.Connection, Depends(get_conn)]
SharesDep = Annotated[ShareRegistry, Depends(get_shares)]
LockDep = Annotated[threading.Lock, Depends(get_lock)]


def create_audit_app(
    conn: psycopg.Connection,
    signing_key: ECPrivateKey | None = None,
    *,
    actor_id: str = "audit-service",
    bootstrap_genesis: bool = True,
    service_root: Certificate,
    trust: FacilityTrust | None = None,
    identity: ServiceIdentity,
    share_key: ShareSealingKey | None = None,
) -> FastAPI:
    """Create and configure the standalone Audit Service application.

    Args:
        conn: Open connection to the shared store. Switched to autocommit
            here so every request's writes are immediately durable and
            visible to every other process reading the store -- required
            by ARCHITECTURE.md §7's "if chain verification fails at boot,
            nothing else starts" and by the traffic-analysis module's
            requirement that a share never appear on the wire before its
            log-commit response (PROJECT.md §4A item 2).
        signing_key: This service's ECDSA-P256 signing key. Defaults to a
            freshly generated keypair -- ARCHITECTURE.md §7 step 4: "Start
            the audit service; it initialises the hash chain..."; the whole
            federation is bootstrapped fresh each run (ADR-0039), so nothing
            is lost by not persisting this across restarts.
        actor_id: Identity this service signs entries as.
        bootstrap_genesis: If the chain is empty, create and persist the
            genesis entry (ARCHITECTURE.md §7 step 4). If the chain is
            non-empty but fails verification, startup raises instead of
            silently continuing (§7 step 7).
        service_root: The federation root callers' service certificates must
            chain to (ADR-0066).
        trust: The root, facility CAs and revoked clinician serials this
            service validates emergency assertions against before releasing
            share 3 (ADR-0067). Without them every release is refused (503).
        identity: This service's root-issued identity (ADR-0066): its id is
            the recipient every envelope names, and its key signs the
            share-key statement senders seal share 3 to (ADR-0079).
        share_key: The key sealed shares are opened with; fresh by default.

    Returns:
        A configured FastAPI application. Its ``app.state.public_key`` is
        the corresponding ECDSA public key other processes need to verify
        this chain.

    Raises:
        Whatever ``audit.chain.verify_full_chain`` raises, if a pre-existing
        chain fails verification at startup -- deliberately: this is the
        hard boot precondition ARCHITECTURE.md §7 describes.
    """
    conn.autocommit = True
    service_id = identity.service_id
    sealing_key = share_key or ShareSealingKey.generate()
    key = signing_key if signing_key is not None else generate_ec_keypair()[0]
    public_key: ECPublicKey = key.public_key()

    lock = threading.Lock()
    if bootstrap_genesis:
        with lock:
            try:
                verify_full_chain(conn, public_key)
            except EmptyChainError:
                genesis = create_genesis_entry(signing_key=key, actor_id=actor_id)
                insert_audit_entry(conn, genesis)
            # Any other exception (ChainBreakError, TamperedEntryError,
            # InvalidSignatureError) propagates and aborts startup.

    app = FastAPI(
        title="Audit Service",
        description=(
            "Federated Break-Glass EHR -- hash-chained audit log and "
            "break-glass share-3 custody"
        ),
        version="1.0.0",
    )
    app.state.conn = conn
    app.state.signing_key = key
    app.state.public_key = public_key
    app.state.actor_id = actor_id
    app.state.shares = ShareRegistry()
    app.state.lock = lock
    # This holder's own consumed-assertion set, kept apart from the facility's
    # in the shared table (ADR-0067).
    release_assertions = ConsumedAssertionIds(
        backend=ConsumedIdTable(conn, kind_override="release_assertion")
    )

    # --- Health & identity -----------------------------------------------

    @app.get("/health", response_model=HealthResponse)
    def health_check() -> HealthResponse:
        """Report readiness and the current chain head position."""
        head = get_chain_head(conn)
        return HealthResponse(
            actor_id=actor_id, chain_head_seq=head.seq if head else None
        )

    @app.get("/public-key", response_model=PublicKeyResponse)
    def public_key_endpoint() -> PublicKeyResponse:
        """Publish this service's public key for chain verification elsewhere."""
        return PublicKeyResponse(
            public_key_pem=public_key_to_pem(public_key).decode("ascii")
        )

    # --- Chain read/verify -------------------------------------------------

    @app.get("/chain/head", response_model=ChainHeadResponse)
    def chain_head(conn: ConnDep) -> ChainHeadResponse:
        """Return the chain's current head entry."""
        return ChainHeadResponse(head=get_chain_head(conn))

    @app.get("/chain/verify", response_model=ChainVerifyResponse)
    def chain_verify(conn: ConnDep) -> ChainVerifyResponse:
        """Re-verify the whole persisted chain, genesis through head."""
        try:
            head = verify_full_chain(conn, public_key)
        except EmptyChainError:
            return ChainVerifyResponse(verified=False, head_seq=None)
        except (ChainBreakError, TamperedEntryError, InvalidSignatureError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"chain verification failed: {exc}",
            ) from exc
        except psycopg.Error as exc:
            # A store outage is not evidence of tampering (review F42).
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"chain verification unavailable: {exc}",
            ) from exc
        return ChainVerifyResponse(verified=True, head_seq=head.seq)

    # --- Append on a caller's behalf ---------------------------------------

    @app.post("/entries", response_model=AppendEntryResponse)
    def append_entry_endpoint(
        payload: AppendEntryRequest, conn: ConnDep, lock: LockDep
    ) -> AppendEntryResponse:
        """Sign and append one entry. The caller never touches the signing key."""
        with lock:
            try:
                entry = append_entry(
                    conn,
                    event_type=payload.event_type,
                    event_data=payload.event_data,
                    actor_id=payload.actor_id,
                    correlation_id=payload.correlation_id,
                    signing_key=key,
                )
            except ValueError as exc:
                # e.g. a float in event_data, which would later fail
                # verification after the jsonb round trip (review F31).
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
                ) from exc
        return AppendEntryResponse(entry=entry)

    # --- Break-glass share custody (P3-4, headline precondition) -----------

    def open_share(share_key: str, sealed: SealedShare) -> Share:
        """A deposited share, opened with this service's key (ADR-0079)."""
        try:
            return open_sealed_share(
                sealed, record_id=share_key, service_id=service_id, key=sealing_key
            )
        except SealedShareError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

    @app.post(
        "/breakglass/shares",
        response_model=RegisterShareResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def register_share(
        payload: RegisterShareRequest, shares: SharesDep
    ) -> RegisterShareResponse:
        """Hand this service custody of one break-glass share (share 3)."""
        share = open_share(payload.share_key, payload.sealed_share)
        try:
            shares.put(payload.share_key, share)
        except ShareAlreadyHeldError as exc:
            # Never overwrite a live record's share (review F4).
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
        return RegisterShareResponse(share_key=payload.share_key)

    @app.put("/breakglass/shares/{share_key}", response_model=RegisterShareResponse)
    def replace_share(
        share_key: str, payload: ReplaceShareRequest, conn: ConnDep, shares: SharesDep
    ) -> RegisterShareResponse:
        """Take the next generation's share from a record's rotation (ADR-0069).

        Only a facility may call this, only while the record is ``expired`` in
        the shared store -- the moment its forced rotation runs -- and only
        for the generation after the one held.
        """
        row = get_lifecycle_state(conn, share_key)
        if row is None or row["state"] != LifecycleState.EXPIRED.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="a share is replaced only during its record's expiry rotation",
            )
        share = open_share(share_key, payload.sealed_share)
        try:
            shares.replace(share_key, share, payload.generation)
        except ShareNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        except ShareGenerationError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
        return RegisterShareResponse(status="replaced", share_key=share_key)

    def check_assertion(payload: ReleaseShareRequest) -> None:
        """Validate the emergency assertion before any share moves (ADR-0067).

        The same five-point check a facility runs (ARCHITECTURE.md §8), against
        this service's own trust anchors, plus the record binding: the
        assertion's signed context digest must name this ``share_key``.
        """
        if trust is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="no trust anchors configured; share 3 is not released",
            )
        assertion = payload.assertion
        try:
            certificate = certificate_from_pem(
                payload.clinician_certificate_pem.encode("utf-8")
            )
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"clinician certificate does not parse: {exc}",
            ) from exc
        issuer = trust.issuing_ca(certificate)
        if issuer is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="clinician certificate was not issued by a federation CA",
            )
        if assertion.facility_id not in trust.facility_cas:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="assertion names a facility outside the federation",
            )
        if not assertion.clinical_context_digest:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="assertion is not bound to a record",
            )
        try:
            validate_clinical_context(
                assertion,
                payload.share_key,
                payload.justification,
                payload.sensitive_justification,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"assertion is not for this record: {exc}",
            ) from exc
        try:
            validate_emergency_assertion(
                assertion=assertion,
                clinician_certificate=certificate,
                facility_ca_certificate=issuer[1],
                trusted_root=trust.root,
                expected_facility_id=assertion.facility_id,
                consumed_store=release_assertions,
                revoked_serials=trust.revoked_serials,
            )
        except (
            ChainValidationError,
            CertificateExpiredError,
            CertificateRevokedError,
        ) as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"clinician certificate refused: {exc}",
            ) from exc
        except (
            AssertionExpiredError,
            AssertionLifetimeError,
            ClinicianMismatchError,
            FacilityMismatchError,
            InvalidSignatureError,
            ReplayedAssertionError,
        ) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"emergency assertion invalid ({exc.__class__.__name__}): {exc}",
            ) from exc

    @app.post("/breakglass/release", response_model=ReleaseShareResponse)
    def release_share(
        payload: ReleaseShareRequest,
        conn: ConnDep,
        shares: SharesDep,
        lock: LockDep,
    ) -> ReleaseShareResponse:
        """Commit a log entry, then release the held share -- never the reverse.

        This is ARCHITECTURE.md §5 step 3's "share 3" made an actual network
        boundary: the response body's ``entry`` is only ever populated
        because the commit already succeeded (fail-closed, P3-4). And nothing
        is committed or released until the emergency assertion validates here
        (ADR-0067).
        """
        check_assertion(payload)
        # Share 3 goes only to a root-certified facility's gate (ADR-0079).
        try:
            recipient = verify_key_statement(
                payload.recipient, trusted_root=service_root, kind="facility"
            )
        except SealedShareError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"share recipient refused: {exc}",
            ) from exc
        assertion = payload.assertion
        # The entry records what was validated, not what the caller said.
        event_data = {
            **payload.event_data,
            "record_id": payload.share_key,
            "assertion_id": str(assertion.assertion_id),
            "patient_id": assertion.patient_id,
            "clinician_id": assertion.clinician_id,
            "facility_id": assertion.facility_id,
            "reason_code": assertion.reason_code.value,
        }
        try:
            held_share = shares.get(payload.share_key)
        except ShareNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc

        with lock:
            try:
                share, entry = release_share_after_commit(
                    conn,
                    share=held_share,
                    event_type=payload.event_type,
                    event_data=event_data,
                    actor_id=payload.actor_id,
                    correlation_id=payload.correlation_id,
                    signing_key=key,
                )
            except AuditCommitFailedError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"log commit failed; share was not released: {exc}",
                ) from exc

        sealed = seal_share(share, record_id=payload.share_key, recipient=recipient)
        return ReleaseShareResponse(sealed_share=sealed, entry=entry)

    install_service_auth(
        app,
        ServiceAuthConfig(
            service_id=service_id,
            trusted_root=service_root,
            permissions=AUDIT_PERMISSIONS,
            public_routes=AUDIT_PUBLIC_ROUTES,
            replay=ConsumedRequestIds(backend=ConsumedIdTable(conn)),
        ),
    )
    app.state.share_key = sealing_key
    app.state.share_recipient = ShareRecipient(service_id, sealing_key.public_key)
    statement = make_key_statement(
        sealing_key,
        service_id=service_id,
        kind=identity.kind,
        signing_key=identity.signing_key,
        certificate_pem=identity.certificate_pem,
    )
    app.state.share_key_statement = statement
    serve_share_key(app, statement)
    return app
