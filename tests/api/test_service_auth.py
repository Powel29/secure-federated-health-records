"""Negative tests for signed service-to-service requests (ADR-0066).

A tiny app behind ``install_service_auth`` with one guarded route. Every test
first shows the legitimate signed request succeeding, then breaks exactly one
thing and expects a 401/403 with the route never reached.
"""

from __future__ import annotations

import datetime

import httpx
import pytest
from api.service_auth import (
    ENVELOPE_HEADER,
    ServiceAuthConfig,
    SignedRequestAuth,
    UnknownRecipientError,
    caller_of,
    decode_envelope_header,
    encode_envelope_header,
    install_service_auth,
)
from breakglass.envelopes import create_request_envelope
from crypto_core import certificate_to_pem, generate_ec_keypair
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from identity.certificates import issue_facility_ca_certificate
from identity.root_anchor import generate_root_anchor

from tests.service_pki import BASE_URL, ServicePKI


@pytest.fixture()
def services() -> ServicePKI:
    return ServicePKI(generate_root_anchor())


@pytest.fixture()
def app(services):
    app = FastAPI()
    reached: list[str] = []

    @app.get("/health")
    def health() -> dict:
        return {"ok": True}

    @app.post("/things/{thing_id}")
    def thing(thing_id: str, payload: dict, request: Request) -> dict:
        reached.append(thing_id)
        return {"caller": caller_of(request).service_id, "payload": payload}

    install_service_auth(
        app,
        ServiceAuthConfig(
            service_id="facility-a",
            trusted_root=services.root.certificate,
            permissions={("POST", "/things/{thing_id}"): frozenset({"custodian"})},
            public_routes=frozenset({("GET", "/health")}),
        ),
    )
    app.state.reached = reached
    return app


def _client(app, services, caller="custodian", recipient="facility-a"):
    return services.client(app, recipient, caller=caller)


def test_positive_control_a_signed_allowed_call_reaches_the_route(app, services):
    response = _client(app, services).post("/things/t1", json={"a": 1})
    assert response.status_code == 200, response.text
    assert response.json() == {"caller": "custodian", "payload": {"a": 1}}
    assert app.state.reached == ["t1"]


def test_public_route_needs_no_signature(app):
    assert TestClient(app).get("/health").status_code == 200


def test_unsigned_request_is_refused(app):
    response = TestClient(app).post("/things/t1", json={"a": 1})
    assert response.status_code == 401
    assert app.state.reached == []


def test_a_kind_the_route_does_not_allow_is_refused(app, services):
    response = _client(app, services, caller="portal").post("/things/t1", json={})
    assert response.status_code == 403
    assert app.state.reached == []


def test_envelope_for_another_recipient_is_refused(app, services):
    response = _client(app, services, recipient="facility-b").post(
        "/things/t1", json={}
    )
    assert response.status_code == 401
    assert "EnvelopeRecipientMismatchError" in response.json()["detail"]
    assert app.state.reached == []


def test_a_certificate_from_another_root_is_refused(app):
    rogue = ServicePKI(generate_root_anchor())
    response = rogue.client(app, "facility-a", caller="custodian").post(
        "/things/t1", json={}
    )
    assert response.status_code == 401
    assert app.state.reached == []


def test_a_ca_certificate_is_not_a_service_identity(app, services):
    """A facility CA chains to the root but is not a service certificate."""
    ca_key, ca_pub = generate_ec_keypair()
    ca_cert = issue_facility_ca_certificate(services.root, "custodian", ca_pub)
    envelope = create_request_envelope(
        caller_id="custodian",
        recipient_id="facility-a",
        operation="POST /things/t1",
        body=b"{}",
        signing_key=ca_key,
    )
    import base64

    response = TestClient(app).post(
        "/things/t1",
        content=b"{}",
        headers={
            "content-type": "application/json",
            ENVELOPE_HEADER: encode_envelope_header(envelope),
            "X-Service-Certificate": base64.b64encode(
                certificate_to_pem(ca_cert)
            ).decode(),
        },
    )
    assert response.status_code == 401
    assert app.state.reached == []


class _Tamper(httpx.Auth):
    """Sign normally, then change one thing the signature covers."""

    def __init__(self, inner: SignedRequestAuth, mutate) -> None:
        self.inner, self.mutate = inner, mutate

    def auth_flow(self, request):
        self.inner.sign(request)
        yield self.mutate(request)


def _tampered(app, services, mutate) -> TestClient:
    client = TestClient(app, base_url=BASE_URL)
    client.auth = _Tamper(services.auth("custodian", "facility-a"), mutate)
    return client


def test_a_changed_body_is_refused(app, services):
    def swap_body(request):
        return httpx.Request(
            request.method,
            request.url,
            headers={**request.headers, "content-length": "8"},
            content=b'{"a": 2}',
        )

    response = _tampered(app, services, swap_body).post("/things/t1", json={"a": 1})
    assert response.status_code == 401
    assert "InvalidSignatureError" in response.json()["detail"]
    assert app.state.reached == []


def test_an_envelope_for_another_path_is_refused(app, services):
    def retarget(request):
        return httpx.Request(
            request.method,
            request.url.copy_with(path="/things/t2"),
            headers=request.headers,
            content=request.content,
        )

    response = _tampered(app, services, retarget).post("/things/t1", json={})
    assert response.status_code == 401
    assert "EnvelopeOperationMismatchError" in response.json()["detail"]
    assert app.state.reached == []


def test_a_replayed_request_is_refused(app, services):
    sent: list[httpx.Request] = []

    def keep(request):
        sent.append(request)
        return request

    client = _tampered(app, services, keep)
    assert client.post("/things/t1", json={}).status_code == 200
    original = sent[0]
    replay = TestClient(app, base_url=BASE_URL).post(
        "/things/t1", content=original.content, headers=original.headers
    )
    assert replay.status_code == 401
    assert "ReplayedRequestError" in replay.json()["detail"]
    assert app.state.reached == ["t1"]


def test_an_old_envelope_is_refused(app, services):
    auth = services.auth("custodian", "facility-a")

    def backdate(request):
        envelope = decode_envelope_header(
            request.headers[ENVELOPE_HEADER], request.content
        )
        old = create_request_envelope(
            caller_id=envelope.caller_id,
            recipient_id=envelope.recipient_id,
            operation=envelope.operation,
            body=request.content,
            signing_key=auth.identity.signing_key,
            issued_at=datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5),
        )
        request.headers[ENVELOPE_HEADER] = encode_envelope_header(old)
        return request

    response = _tampered(app, services, backdate).post("/things/t1", json={})
    assert response.status_code == 401
    assert "EnvelopeExpiredError" in response.json()["detail"]


def test_an_unknown_recipient_is_never_sent(services):
    """The caller side refuses a URL outside its allowlist before sending."""
    transport_calls: list[httpx.Request] = []
    client = httpx.Client(
        auth=services.auth("custodian", "facility-a"),
        transport=httpx.MockTransport(
            lambda r: transport_calls.append(r) or httpx.Response(200)
        ),
    )
    with pytest.raises(UnknownRecipientError):
        client.post("http://elsewhere.test/things/t1", json={})
    assert transport_calls == []


def test_every_route_must_be_in_the_table(services):
    """A route nobody listed is a startup error, not an open endpoint."""
    app = FastAPI()

    @app.post("/forgotten")
    def forgotten() -> dict:
        return {}

    with pytest.raises(ValueError, match="unlisted"):
        install_service_auth(
            app,
            ServiceAuthConfig(
                service_id="facility-a",
                trusted_root=services.root.certificate,
                permissions={},
            ),
        )
