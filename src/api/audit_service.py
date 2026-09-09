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
from audit.exceptions import AuditCommitFailedError, EmptyChainError
from audit.share_custody import release_share_after_commit
from audit.share_registry import ShareNotFoundError, ShareRegistry
from crypto_core import generate_ec_keypair, public_key_to_pem
from crypto_core.types import ECPrivateKey, ECPublicKey
from fastapi import Depends, FastAPI, HTTPException, Request, status
from storage.repositories import get_chain_head, insert_audit_entry

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
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"chain verification failed: {exc}",
            ) from exc
        return ChainVerifyResponse(verified=True, head_seq=head.seq)

    # --- Append on a caller's behalf ---------------------------------------

    @app.post("/entries", response_model=AppendEntryResponse)
    def append_entry_endpoint(
        payload: AppendEntryRequest, conn: ConnDep, lock: LockDep
    ) -> AppendEntryResponse:
        """Sign and append one entry. The caller never touches the signing key."""
        with lock:
            entry = append_entry(
                conn,
                event_type=payload.event_type,
                event_data=payload.event_data,
                actor_id=payload.actor_id,
                correlation_id=payload.correlation_id,
                signing_key=key,
            )
        return AppendEntryResponse(entry=entry)

    # --- Break-glass share custody (P3-4, headline precondition) -----------

    @app.post(
        "/breakglass/shares",
        response_model=RegisterShareResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def register_share(
        payload: RegisterShareRequest, shares: SharesDep
    ) -> RegisterShareResponse:
        """Hand this service custody of one break-glass share (share 3)."""
        try:
            share_bytes = bytes.fromhex(payload.share_hex)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid hex share: {exc}",
            ) from exc
        shares.put(payload.share_key, (payload.x, share_bytes))
        return RegisterShareResponse(share_key=payload.share_key)

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
        because the commit already succeeded (fail-closed, P3-4).
        """
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
                    event_data=payload.event_data,
                    actor_id=payload.actor_id,
                    correlation_id=payload.correlation_id,
                    signing_key=key,
                )
            except AuditCommitFailedError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"log commit failed; share was not released: {exc}",
                ) from exc

        x, share_bytes = share
        return ReleaseShareResponse(x=x, share_hex=share_bytes.hex(), entry=entry)

    return app
