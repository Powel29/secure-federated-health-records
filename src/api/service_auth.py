"""Signed service-to-service requests (ADR-0066, review D5-a, C14).

Every call one federation service makes to another carries two headers:

- ``X-Service-Certificate``: the caller's service certificate (base64 PEM),
  issued by the federation root with OU ``service:<kind>``
  (:func:`identity.issue_service_certificate`);
- ``X-Request-Envelope``: a signed :class:`~contracts.RequestEnvelope`
  (``breakglass.envelopes``) without its ``body`` field, base64url JSON.

The envelope's ``body`` is the raw HTTP request body, so the signature covers
exactly the bytes the callee receives, and the body itself is unchanged on the
wire (the traffic analyser in ``wire/`` still sees what it always saw). The
envelope also binds the caller id, the recipient service id and the operation
(``"<METHOD> <path>[?<query>]"``), carries a one-time ``request_id`` and a
timestamp.

The callee (:class:`ServiceAuthMiddleware`) checks, in order, before any route
code or storage runs: the certificate chains to its configured root and names
a service; the envelope's caller is that service; the envelope was signed for
this exact method, path and recipient, recently; the signature verifies; the
``request_id`` is unused. Then the route's permission table decides whether
that *kind* of service may call it at all. Only a handful of read-only public
routes (health, public keys, chain head/verify) skip this.

No cryptography is computed here (CONVENTIONS.md §2 rule 10): signing and
verification are ``breakglass.envelopes``, certificate checks are
``identity``. This module only moves headers and decides 401/403.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import json
import os
from collections.abc import Callable, Generator, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import anyio
import httpx
from breakglass.envelopes import (
    check_envelope_binding,
    create_request_envelope,
    verify_request_envelope,
)
from breakglass.exceptions import BreakglassError
from breakglass.replay import ConsumedRequestIds
from contracts import RequestEnvelope
from crypto_core import (
    certificate_from_pem,
    certificate_public_key,
    private_key_from_pem,
    public_key_to_pem,
)
from crypto_core.exceptions import CryptoError
from crypto_core.types import ECPrivateKey
from cryptography.x509 import Certificate
from fastapi import FastAPI, Request
from identity import service_name, validate_service_certificate
from pydantic import ValidationError
from starlette.routing import Match, Router
from starlette.types import ASGIApp, Message, Receive, Scope, Send

ENVELOPE_HEADER = "X-Request-Envelope"
CERTIFICATE_HEADER = "X-Service-Certificate"

# Routes FastAPI adds for its own schema and docs: public API descriptions,
# no data.
_SCHEMA_ROUTES = ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")

Route = tuple[
    str, str
]  # (METHOD, path template), e.g. ("POST", "/records/{record_id}/read")


class ServiceAuthError(RuntimeError):
    """A signed request could not be built (bad identity or unknown recipient)."""


class UnknownRecipientError(httpx.RequestError):
    """No configured service id for the URL a request was about to be sent to.

    An ``httpx.RequestError`` so callers that already treat a transport failure
    as "service unavailable" fail closed the same way: nothing unsigned leaves.
    """


# --- Caller side --------------------------------------------------------------


@dataclass(frozen=True)
class ServiceIdentity:
    """This process's service id, kind, request-signing key and certificate."""

    service_id: str
    kind: str
    signing_key: ECPrivateKey = field(repr=False)
    certificate_pem: str

    @classmethod
    def from_pem(cls, *, key_pem: bytes, certificate_pem: bytes) -> ServiceIdentity:
        """Load an identity, refusing a key that does not match the certificate.

        Raises:
            ServiceAuthError: The certificate is not a service certificate, or
                the key is not the one it certifies.
        """
        try:
            certificate = certificate_from_pem(certificate_pem)
            name = service_name(certificate)
            key = private_key_from_pem(key_pem)
        except CryptoError as exc:
            raise ServiceAuthError(f"invalid service identity: {exc}") from exc
        if public_key_to_pem(key.public_key()) != public_key_to_pem(
            certificate_public_key(certificate)
        ):
            raise ServiceAuthError("service key does not match its certificate")
        return cls(
            service_id=name.service_id,
            kind=name.kind,
            signing_key=key,
            certificate_pem=certificate_pem.decode("ascii"),
        )


def load_service_identity(env: Mapping[str, str] | None = None) -> ServiceIdentity:
    """This process's identity from ``SERVICE_KEY_FILE`` / ``SERVICE_CERT_FILE``.

    Raises:
        RuntimeError: Either variable is unset or names a missing file -- a
            service with no identity can neither call nor be called (ADR-0066).
    """
    env = os.environ if env is None else env
    key_file, cert_file = env.get("SERVICE_KEY_FILE"), env.get("SERVICE_CERT_FILE")
    if not key_file or not cert_file:
        raise RuntimeError(
            "SERVICE_KEY_FILE and SERVICE_CERT_FILE must be set: every service "
            "signs its requests with a root-issued identity (ADR-0066)"
        )
    key_path, cert_path = Path(key_file), Path(cert_file)
    if not key_path.is_file() or not cert_path.is_file():
        raise RuntimeError(f"service identity files not found: {key_path}, {cert_path}")
    return ServiceIdentity.from_pem(
        key_pem=key_path.read_bytes(), certificate_pem=cert_path.read_bytes()
    )


def load_trusted_root(env: Mapping[str, str] | None = None) -> Certificate:
    """The federation root named by ``FEDERATION_ROOT_CERT``.

    Raises:
        RuntimeError: Unset, or the file is missing.
    """
    env = os.environ if env is None else env
    root_file = env.get("FEDERATION_ROOT_CERT")
    if not root_file or not Path(root_file).is_file():
        raise RuntimeError(
            "FEDERATION_ROOT_CERT must name the federation root certificate: "
            "callers are authenticated against it (ADR-0066)"
        )
    return certificate_from_pem(Path(root_file).read_bytes())


def operation_of(method: str, path_and_query: str) -> str:
    """The operation string an envelope binds: ``"<METHOD> <path>[?<query>]"``."""
    return f"{method.upper()} {path_and_query}"


def encode_envelope_header(envelope: RequestEnvelope) -> str:
    """The envelope minus its body (the HTTP body is the body), base64url JSON."""
    fields = envelope.model_dump(mode="json", exclude={"body"})
    raw = json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_envelope_header(value: str, body: bytes) -> RequestEnvelope:
    """Rebuild the envelope from its header and the received HTTP body.

    Raises:
        ValueError / ValidationError: Not a well-formed envelope header.
    """
    raw = base64.urlsafe_b64decode(value.encode("ascii"))
    fields = json.loads(raw)
    if not isinstance(fields, dict) or "body" in fields:
        raise ValueError("malformed envelope header")
    return RequestEnvelope.model_validate({**fields, "body": body})


@dataclass(frozen=True)
class _Origin:
    scheme: str
    host: str
    port: int | None
    path: str

    @classmethod
    def of(cls, url: httpx.URL | str) -> _Origin:
        url = httpx.URL(url)
        return cls(
            scheme=url.scheme,
            host=url.host.lower(),
            port=url.port,
            path=url.path.rstrip("/"),
        )

    def covers(self, url: httpx.URL) -> bool:
        other = _Origin.of(url)
        if (other.scheme, other.host, other.port) != (
            self.scheme,
            self.host,
            self.port,
        ):
            return False
        return other.path == self.path or other.path.startswith(self.path + "/")


class SignedRequestAuth(httpx.Auth):
    """httpx auth flow that signs every request it sends (ADR-0066).

    ``recipients`` maps each configured base URL to the service id of the
    service listening there -- the same allowlist the caller already resolves
    endpoints from (CONVENTIONS.md §2 rule 8). A request to any other URL is
    refused before it is sent.
    """

    requires_request_body = True

    def __init__(
        self, identity: ServiceIdentity, recipients: Mapping[str, str]
    ) -> None:
        self._identity = identity
        self._recipients = sorted(
            ((_Origin.of(url), service_id) for url, service_id in recipients.items()),
            key=lambda pair: len(pair[0].path),
            reverse=True,
        )

    @property
    def identity(self) -> ServiceIdentity:
        return self._identity

    def recipient_for(self, url: httpx.URL) -> str:
        for origin, service_id in self._recipients:
            if origin.covers(url):
                return service_id
        raise UnknownRecipientError(
            f"no configured service for {url.copy_with(query=None)}"
        )

    def sign(self, request: httpx.Request) -> None:
        """Add the certificate and envelope headers to ``request`` in place."""
        recipient = self.recipient_for(request.url)
        envelope = create_request_envelope(
            caller_id=self._identity.service_id,
            recipient_id=recipient,
            operation=operation_of(
                request.method, request.url.raw_path.decode("ascii")
            ),
            body=request.content,
            signing_key=self._identity.signing_key,
        )
        request.headers[ENVELOPE_HEADER] = encode_envelope_header(envelope)
        request.headers[CERTIFICATE_HEADER] = base64.b64encode(
            self._identity.certificate_pem.encode("ascii")
        ).decode("ascii")

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        self.sign(request)
        yield request


def signed_client(
    identity: ServiceIdentity, recipients: Mapping[str, str], **kwargs: object
) -> httpx.Client:
    """An ``httpx.Client`` whose every request is signed as ``identity``."""
    return httpx.Client(auth=SignedRequestAuth(identity, recipients), **kwargs)


# --- Callee side --------------------------------------------------------------


@dataclass(frozen=True)
class CallerIdentity:
    """The authenticated service that sent the current request."""

    service_id: str
    kind: str


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@dataclass
class ServiceAuthConfig:
    """What a service checks on every request it receives.

    Attributes:
        service_id: This service's own id; every envelope must name it as
            recipient.
        trusted_root: The federation root, from configuration (never a request).
        permissions: ``(METHOD, path template) -> kinds allowed to call it``.
            A route with no entry is refused to every caller (fail closed).
        public_routes: Read-only routes any caller may use unauthenticated.
        replay: Consumed ``request_id`` store; pass one backed by the store
            where the service has one, so a restart does not reopen replay.
        clock: Current UTC time (tests).
    """

    service_id: str
    trusted_root: Certificate
    permissions: Mapping[Route, frozenset[str]]
    public_routes: frozenset[Route] = frozenset()
    replay: ConsumedRequestIds = field(default_factory=ConsumedRequestIds)
    clock: Callable[[], datetime.datetime] = _utcnow


class ServiceAuthFailure(Exception):
    """The request is not a valid signed request from a federation service."""


_AUTH_ERRORS = (
    CryptoError,
    BreakglassError,
    ValidationError,
    ValueError,
    binascii.Error,
    UnicodeError,
)


def authenticate_request(
    config: ServiceAuthConfig,
    *,
    method: str,
    path_and_query: str,
    headers: Mapping[str, str],
    body: bytes,
) -> CallerIdentity:
    """Authenticate one received request; consumes its ``request_id`` on success.

    Raises:
        ServiceAuthFailure: Any check failed. The message says which.
    """
    cert_value = headers.get(CERTIFICATE_HEADER.lower())
    envelope_value = headers.get(ENVELOPE_HEADER.lower())
    if not cert_value or not envelope_value:
        raise ServiceAuthFailure("request carries no service certificate or envelope")
    now = config.clock()
    try:
        certificate = certificate_from_pem(base64.b64decode(cert_value, validate=True))
        name = validate_service_certificate(
            certificate, trusted_root=config.trusted_root, at=now
        )
        envelope = decode_envelope_header(envelope_value, body)
        if envelope.caller_id != name.service_id:
            raise ServiceAuthFailure(
                f"envelope caller {envelope.caller_id!r} is not the certificate's "
                f"service {name.service_id!r}"
            )
        # No side effects: a mismatched envelope never burns its request_id.
        check_envelope_binding(
            envelope, expected_operation=operation_of(method, path_and_query), now=now
        )
        verify_request_envelope(
            envelope,
            certificate_public_key(certificate),
            config.service_id,
            consumed_store=config.replay,
        )
    except _AUTH_ERRORS as exc:
        raise ServiceAuthFailure(f"{exc.__class__.__name__}: {exc}") from exc
    return CallerIdentity(service_id=name.service_id, kind=name.kind)


def _route_template(router: Router, scope: Scope) -> str | None:
    for route in router.routes:
        match, _ = route.matches(scope)
        if match is Match.FULL:
            return getattr(route, "path", None)
    return None


def _path_and_query(scope: Scope) -> str:
    # uvicorn's raw_path has no query; Starlette's TestClient's does.
    raw = scope.get("raw_path") or scope["path"].encode("utf-8")
    path = raw.split(b"?", 1)[0].decode("latin-1")
    query = scope.get("query_string", b"").decode("latin-1")
    return f"{path}?{query}" if query else path


async def _send_json(send: Send, status_code: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class ServiceAuthMiddleware:
    """ASGI middleware enforcing :class:`ServiceAuthConfig` on every request."""

    def __init__(
        self, app: ASGIApp, *, config: ServiceAuthConfig, router: Router
    ) -> None:
        self.app = app
        self.config = config
        self.router = router

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope["method"]
        template = _route_template(self.router, scope)
        if template is not None and (method, template) in self.config.public_routes:
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = b"".join(chunks)
        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers", [])
        }
        try:
            # Off the event loop: the replay store may be a database write.
            caller = await anyio.to_thread.run_sync(
                lambda: authenticate_request(
                    self.config,
                    method=method,
                    path_and_query=_path_and_query(scope),
                    headers=headers,
                    body=body,
                )
            )
        except ServiceAuthFailure as exc:
            await _send_json(send, 401, f"service authentication failed: {exc}")
            return
        if template is not None:
            allowed = self.config.permissions.get((method, template), frozenset())
            if caller.kind not in allowed:
                await _send_json(
                    send,
                    403,
                    f"a {caller.kind} service ({caller.service_id}) may not call "
                    f"{method} {template}",
                )
                return

        sent = False

        async def replay_body() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        state = {**scope.get("state", {}), "caller": caller}
        await self.app({**scope, "state": state}, replay_body, send)


def install_service_auth(app: FastAPI, config: ServiceAuthConfig) -> None:
    """Require signed requests on every route of ``app`` (ADR-0066).

    Call after every route is declared. Every route must appear in exactly one
    of ``config.permissions`` or ``config.public_routes`` (FastAPI's own schema
    routes are public); an unlisted route, or a listed one that does not
    exist, is a configuration error raised here at startup.

    Raises:
        ValueError: The permission table and the app's routes disagree.
    """
    declared: set[Route] = set()
    for route in app.router.routes:
        path = getattr(route, "path", None)
        for method in getattr(route, "methods", None) or ():
            if method != "HEAD":
                declared.add((method, path))
    schema = {(m, p) for m, p in declared if p in _SCHEMA_ROUTES}
    listed = set(config.permissions) | set(config.public_routes)
    unlisted = declared - schema - listed
    unknown = listed - declared
    overlap = set(config.permissions) & set(config.public_routes)
    if unlisted or unknown or overlap:
        raise ValueError(
            f"service auth table mismatch: unlisted={sorted(unlisted)} "
            f"unknown={sorted(unknown)} both={sorted(overlap)}"
        )
    config.public_routes = frozenset(config.public_routes) | frozenset(schema)
    app.add_middleware(ServiceAuthMiddleware, config=config, router=app.router)
    app.state.service_auth = config


def add_public_route(app: FastAPI, method: str, path: str) -> None:
    """Mark a route added after :func:`install_service_auth` as public.

    For non-secret operational routes only (e.g. the deployment instance id).
    """
    config: ServiceAuthConfig = app.state.service_auth
    config.public_routes = frozenset(config.public_routes) | {(method, path)}


def caller_of(request: Request) -> CallerIdentity:
    """The authenticated caller of the current request.

    Raises:
        RuntimeError: The route is public or auth is not installed -- a route
            that needs a caller must not be public.
    """
    caller = getattr(request.state, "caller", None)
    if not isinstance(caller, CallerIdentity):
        raise RuntimeError("no authenticated caller on this request")
    return caller


def recipients(pairs: Iterable[tuple[str | None, str]]) -> dict[str, str]:
    """``{base_url: service_id}`` from ``(url, service_id)`` pairs, skipping unset."""
    return {url.rstrip("/"): service_id for url, service_id in pairs if url}
