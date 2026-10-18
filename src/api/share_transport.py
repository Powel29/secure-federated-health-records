"""Moving threshold shares between services sealed (ADR-0079, review D6 step 2).

Each share holder and every facility serves ``GET /share-key``: its
share-sealing public key, signed by its service identity. A sender fetches the
recipient's statement from the URL in its own configuration, verifies it
against its own federation root, and sends only sealed shares. The sealing and
verification are :mod:`breakglass.share_sealing`; this module only fetches and
routes (CONVENTIONS.md §2 rule 10).
"""

from __future__ import annotations

from typing import Any

import httpx
from breakglass.emergency_key import Share
from breakglass.share_sealing import (
    ShareKeyStatement,
    ShareRecipient,
    seal_share,
    verify_key_statement,
)
from cryptography.x509 import Certificate
from fastapi import FastAPI

from api.service_auth import add_public_route

SHARE_KEY_PATH = "/share-key"


def serve_share_key(app: FastAPI, statement: ShareKeyStatement) -> None:
    """Publish ``statement`` at ``GET /share-key`` (public: it is a public key).

    Call after :func:`api.service_auth.install_service_auth`.
    """

    @app.get(SHARE_KEY_PATH, response_model=ShareKeyStatement)
    def share_key() -> ShareKeyStatement:
        return statement

    add_public_route(app, "GET", SHARE_KEY_PATH)


def fetch_share_key(http: httpx.Client, base_url: str) -> ShareKeyStatement:
    """The share-key statement the service at ``base_url`` publishes (unverified).

    Raises:
        httpx.HTTPError: The statement could not be fetched.
    """
    resp = http.get(f"{base_url.rstrip('/')}{SHARE_KEY_PATH}")
    resp.raise_for_status()
    return ShareKeyStatement.model_validate(resp.json())


def fetch_share_recipient(
    http: httpx.Client, base_url: str, *, kind: str, trusted_root: Certificate
) -> ShareRecipient:
    """The verified share-sealing key of the ``kind`` service at ``base_url``.

    Raises:
        httpx.HTTPError: The statement could not be fetched.
        breakglass.exceptions.SealedShareError: It does not verify against
            ``trusted_root`` as a ``kind`` service.
    """
    statement = fetch_share_key(http, base_url)
    return verify_key_statement(statement, trusted_root=trusted_root, kind=kind)


def sealed_json(
    share: Share, *, record_id: str, recipient: ShareRecipient
) -> dict[str, Any]:
    """``share`` sealed to ``recipient``, ready for a JSON body."""
    return seal_share(share, record_id=record_id, recipient=recipient).model_dump(
        mode="json"
    )
