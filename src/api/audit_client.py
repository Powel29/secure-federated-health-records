"""Thin HTTP client for talking to the standalone Audit Service (P4-2, C14).

No cryptography here (CONVENTIONS.md §2 rule 10) -- every hash and signature
is computed by the Audit Service itself; this module only shapes HTTP calls
to it, so a caller (a facility node, the expiry timer, a seed script) never
needs to hold the audit signing key to get something logged.

Closes the seam ``lifecycle.expiry.EmergencyExpiryManager`` documents as
deferred to Phase 4:

    "Audit chain wiring (P3-3/P3-4) is deferred to Phase 4 API integration
    (P4-2); pass an ``audit_logger`` callback then. With ``audit_logger=None``,
    expiry events do NOT enter the hash chain -- documented limitation
    (ADR-0035)."

:func:`make_lifecycle_audit_logger` is that callback.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Callable

import httpx

DEFAULT_TIMEOUT_SECONDS = 5.0

# Highest seq each audit service has returned to this process (review F31).
# With a high-water file (``use_high_water_file``) it survives a restart;
# without one a restarted process starts trusting again from the next entry.
_last_seq: dict[str, int] = {}
_last_seq_lock = threading.Lock()
_high_water_file: Path | None = None


def use_high_water_file(path: Path) -> None:
    """Persist the highest seq seen per audit service in ``path`` (review F31).

    Loads any mark already in the file, so a restarted facility still refuses
    a chain shorter than the one it saw before the restart. The file lives on
    the facility's own disk, not in the shared store: every service reaches
    the store as the same role, so a mark kept there could be lowered by
    whoever truncated the chain.

    A fresh federation (new store, new chain) needs a fresh file; the
    launchers delete it when they reset the store.

    Raises:
        RuntimeError: The file exists but is not a JSON object of
            ``{audit_service_url: int}`` -- the facility must not start with a
            mark it cannot read (fail closed, CLAUDE.md).
    """
    global _high_water_file
    loaded: dict[str, int] = {}
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                f"unreadable audit high-water file {path}: {exc}"
            ) from exc
        if not isinstance(raw, dict) or not all(
            isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool)
            for k, v in raw.items()
        ):
            raise RuntimeError(f"malformed audit high-water file {path}")
        loaded = raw
    with _last_seq_lock:
        for url, seq in loaded.items():
            _last_seq[url] = max(seq, _last_seq.get(url, -1))
        _high_water_file = path


def _persist_locked() -> None:
    """Write ``_last_seq`` to the high-water file; caller holds the lock.

    Written to a temporary file and renamed, so a crash mid-write leaves the
    previous mark rather than a truncated file.
    """
    if _high_water_file is None:
        return
    tmp = _high_water_file.with_name(_high_water_file.name + ".tmp")
    try:
        tmp.write_text(json.dumps(_last_seq, sort_keys=True), encoding="utf-8")
        os.replace(tmp, _high_water_file)
    except OSError as exc:
        raise AuditServiceError(
            f"could not persist the audit high-water mark: {exc}"
        ) from exc


def _seq_before_send(audit_service_url: str) -> int:
    """The highest seq seen before this append was sent."""
    with _last_seq_lock:
        return _last_seq.get(audit_service_url, -1)


def _check_seq_advances(audit_service_url: str, seq: int, before: int) -> None:
    """Refuse an entry that is not after every entry seen before it was sent.

    Every entry already returned was committed before this append was sent, so
    this one must come after it; a lower seq means a truncated or replaced
    chain. Concurrent appends may return out of order, so the check is against
    ``before``, not the latest seq seen since. When a high-water file is in
    use, a raised mark is persisted before the entry is accepted.
    """
    with _last_seq_lock:
        if seq <= before:
            raise AuditServiceError(
                f"audit chain went backwards: seq {seq} after {before} "
                "(truncated or replaced chain)"
            )
        if seq > _last_seq.get(audit_service_url, -1):
            _last_seq[audit_service_url] = seq
            _persist_locked()


_DISABLE_VALUES = {"0", "false", "no"}


def _tls_verify() -> bool:
    """Whether to verify the audit service's TLS certificate.

    Verification is **on by default** and can only be disabled by *both* opting
    into the capture profile (``CAPTURE_TLS=true``) *and* explicitly setting
    ``TLS_VERIFY=false``. This double gate keeps the escape hatch scoped to the
    P4-6 ``capture-tls`` harness talking to :mod:`wire.tls`'s self-signed local
    certs -- a stray ``TLS_VERIFY=false`` in any normal deployment does nothing
    on its own, so this cannot silently become a fail-open path in production.
    """
    verify_off = os.environ.get("TLS_VERIFY", "true").strip().lower() in _DISABLE_VALUES
    capture_tls = os.environ.get("CAPTURE_TLS", "false").strip().lower() not in (
        {"", *_DISABLE_VALUES}
    )
    return not (verify_off and capture_tls)


class AuditServiceError(RuntimeError):
    """The Audit Service could not be reached, or refused the request."""


def append_entry(
    audit_service_url: str,
    *,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    auth: httpx.Auth | None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """POST one entry to the Audit Service's ``/entries`` endpoint.

    Args:
        audit_service_url: Base URL of the standalone Audit Service, e.g.
            ``"http://audit:8020"`` -- from the config allowlist
            (CONVENTIONS.md §2 rule 8), never from request-supplied data.
        event_type: e.g. ``"lifecycle_transition"``.
        event_data: Metadata only -- never key material (CONVENTIONS.md §2
            rule 3); this function does not enforce that, only forwards it.
        actor_id: The party responsible for the logged event.
        correlation_id: Groups this entry with the rest of its logical flow.
        auth: Signs the request as this process's service identity
            (``api.service_auth.SignedRequestAuth``, ADR-0066). Required: the
            audit service refuses unsigned appends, so ``None`` only fails.
        timeout: HTTP request timeout in seconds.

    Returns:
        The newly persisted ``AuditEntry`` as a plain dict (already
        base64/ISO-serialized JSON from the service response).

    Raises:
        AuditServiceError: The request failed, the service returned a
            non-2xx response, or the returned entry's seq is not after every
            seq this process saw before (review F31).

    Security property:
        Fails closed by propagating the error rather than swallowing it --
        a caller that needs this entry logged (e.g. the expiry timer, whose
        transition should be tamper-evident) finds out immediately if it
        was not.
    """
    before = _seq_before_send(audit_service_url)
    try:
        resp = httpx.post(
            f"{audit_service_url}/entries",
            json={
                "event_type": event_type,
                "event_data": event_data,
                "actor_id": actor_id,
                "correlation_id": correlation_id,
            },
            timeout=timeout,
            verify=_tls_verify(),
            auth=auth,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise AuditServiceError(
            f"audit service append failed for correlation_id={correlation_id!r}: {exc}"
        ) from exc
    entry = resp.json()["entry"]
    _check_seq_advances(audit_service_url, int(entry["seq"]), before)
    return entry


def make_lifecycle_audit_logger(
    audit_service_url: str,
    *,
    auth: httpx.Auth | None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Callable[[dict[str, Any]], None]:
    """Build the ``audit_logger`` callback ``EmergencyExpiryManager`` expects.

    The store mirror lives in the expiry manager (``state_writer``), which
    calls it after this logger as a compare-and-set and retries on failure
    (review N1, N2). A failed append here raises, so the manager retries.

    Args:
        audit_service_url: Base URL of the standalone Audit Service.
        auth: Signs each append as the facility (ADR-0066).
        timeout: Per-request HTTP timeout in seconds.

    Returns:
        A ``Callable[[dict[str, Any]], None]`` suitable for
        ``EmergencyExpiryManager(..., audit_logger=...)``. Each call logs one
        ``lifecycle_transition`` entry, using the transition's own
        ``actor_id`` (the timer service identity, not the facility) and its
        ``correlation_id`` -- both already present in the metadata dict
        ``lifecycle.expiry._transition_metadata`` builds.
    """

    def _log(entry: dict[str, Any]) -> None:
        append_entry(
            audit_service_url,
            event_type="lifecycle_transition",
            event_data=entry,
            actor_id=entry["actor_id"],
            correlation_id=entry["correlation_id"],
            auth=auth,
            timeout=timeout,
        )

    return _log
