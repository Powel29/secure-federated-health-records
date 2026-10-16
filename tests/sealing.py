"""Seal shares to, and open them at, an in-process service app (ADR-0079).

Every share now travels sealed to its recipient's share key. Tests that call a
service directly seal to the key the app holds (``app.state.share_recipient``)
instead of fetching and verifying ``GET /share-key``, which
``tests/security/test_share_sealing.py`` covers.
"""

from __future__ import annotations

from typing import Any

from breakglass.emergency_key import Share
from breakglass.share_sealing import (
    SealedShare,
    ShareSealingKey,
    make_key_statement,
    open_sealed_share,
    seal_share,
)


def _app(target: Any) -> Any:
    return getattr(target, "app", target)


def seal_for(target: Any, record_id: str, share: Share) -> dict[str, Any]:
    """``share`` sealed to the app behind ``target`` (an app or TestClient)."""
    recipient = _app(target).state.share_recipient
    return seal_share(share, record_id=record_id, recipient=recipient).model_dump(
        mode="json"
    )


def seal_all(target: Any, record_id: str, shares: list[Share]) -> list[dict[str, Any]]:
    return [seal_for(target, record_id, share) for share in shares]


def open_at(target: Any, record_id: str, sealed: dict[str, Any]) -> Share:
    """Open a share that was sealed to the app behind ``target``."""
    app = _app(target)
    return open_sealed_share(
        SealedShare.model_validate(sealed),
        record_id=record_id,
        service_id=app.state.share_recipient.service_id,
        key=app.state.share_key,
    )


def statement_of(target: Any) -> dict[str, Any]:
    """The app's published share-key statement (needs a service identity)."""
    return _app(target).state.share_key_statement.model_dump(mode="json")


def facility_statement(
    services: Any, service_id: str = "facility-a"
) -> tuple[Any, dict[str, Any]]:
    """A facility's share key and the statement it publishes, for audit tests."""
    identity = services.identity(service_id)
    key = ShareSealingKey.generate()
    statement = make_key_statement(
        key,
        service_id=identity.service_id,
        kind=identity.kind,
        signing_key=identity.signing_key,
        certificate_pem=identity.certificate_pem,
    )
    return key, statement.model_dump(mode="json")
