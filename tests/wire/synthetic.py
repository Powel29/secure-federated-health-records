"""Synthetic federation traffic for the P5-5 check tests.

Builds :class:`wire.streams.Segment` lists that look like a capture of the
break-glass scenario, so every check can be driven both ways -- holding and
violated -- without tshark or a live federation.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field

from wire.canaries import Canary
from wire.checks import PG_COMMIT_COMPLETE, Capture
from wire.streams import Segment
from wire.tls import SERVICES

DB_PORT = 5432


def http_request(method: str, path: str, body: object | None = None) -> bytes:
    payload = json.dumps(body).encode() if body is not None else b""
    head = (
        f"{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n"
        f"content-type: application/json\r\ncontent-length: {len(payload)}\r\n\r\n"
    )
    return head.encode() + payload


def http_response(status: int, body: object) -> bytes:
    payload = json.dumps(body).encode()
    head = (
        f"HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\n"
        f"content-length: {len(payload)}\r\n\r\n"
    )
    return head.encode() + payload


@dataclass
class Wire:
    """Accumulates segments with monotonically increasing frames and times."""

    segments: list[Segment] = field(default_factory=list)
    _frame: int = 0
    _clock: float = 1000.0
    _next_stream: int = 0
    _seq: dict[tuple[int, int, int], int] = field(default_factory=dict)

    def send(
        self, stream: int, src: int, dst: int, payload: bytes, *, mss: int = 1400
    ) -> None:
        for i in range(0, len(payload), mss):
            self._frame += 1
            self._clock += 0.001
            key = (stream, src, dst)
            seq = self._seq.get(key, 1)
            chunk = payload[i : i + mss]
            self.segments.append(
                Segment(self._frame, self._clock, stream, src, dst, seq, chunk)
            )
            self._seq[key] = seq + len(chunk)

    def connection(self, server_port: int) -> tuple[int, int]:
        stream = self._next_stream
        self._next_stream += 1
        return stream, 50000 + stream

    def exchange(
        self, server: str, request: bytes, response: bytes, *, mss: int = 1400
    ) -> int:
        port = SERVICES[server]
        stream, client = self.connection(port)
        self.send(stream, client, port, request, mss=mss)
        self.send(stream, port, client, response, mss=mss)
        return stream


def make_canaries() -> dict[str, Canary]:
    return {
        "share1": Canary("share1", "share", secrets.token_bytes(33)),
        "share3": Canary("share3", "share", secrets.token_bytes(33)),
        "dek": Canary("dek", "dek", secrets.token_bytes(32)),
        "emergency_key": Canary(
            "emergency_key", "emergency_key", secrets.token_bytes(32)
        ),
        "attr": Canary("attr", "attribute_key", secrets.token_bytes(32)),
    }


def plain_scenario(
    canaries: dict[str, Canary],
    *,
    leak_keys: bool = True,
    commit_before_response: bool = True,
    share3_early: bool = False,
    include_db: bool = True,
    oversized_read: bool = False,
    searches: int = 2,
) -> Capture:
    """The break-glass scenario over plain HTTP.

    ``leak_keys`` reproduces today's design (keys and shares in bodies);
    the other flags each break one claim.
    """
    c = {name: can.value for name, can in canaries.items()}
    w = Wire()
    attr = {"key_b64": c["attr"].hex()} if leak_keys else {"ok": True}
    w.exchange(
        "authority-med",
        http_request("POST", "/attribute-keys/author", {"name": "role"}),
        http_response(200, attr),
    )
    w.exchange(
        "audit",
        http_request(
            "POST",
            "/breakglass/shares",
            {"share_key": "rec-001", "x": 3, "share_hex": c["share3"].hex()},
        ),
        http_response(201, {"share_key": "rec-001"}),
    )
    if share3_early:
        w.exchange(
            "facility-b",
            http_request("POST", "/records/rec-001/read", {"leak": c["share3"].hex()}),
            http_response(403, {"detail": "denied"}),
        )
    if oversized_read:
        w.exchange(
            "facility-b",
            http_request("POST", "/records/rec-001/read", {"pad": "x" * 20000}),
            http_response(403, {"detail": "denied"}),
        )

    # Audit service: INSERT (event_type as a text parameter) then COMMIT.
    db_stream, db_client = w.connection(DB_PORT)
    release_req = http_request(
        "POST",
        "/breakglass/release",
        {"share_key": "rec-001", "event_type": "breakglass_share_released"},
    )
    release_resp = http_response(
        200,
        {
            "x": 3,
            "share_hex": c["share3"].hex(),
            "entry": {"seq": 7, "entry_hash": "aGFzaA=="},
        },
    )
    audit_stream, audit_client = w.connection(SERVICES["audit"])
    w.send(audit_stream, audit_client, SERVICES["audit"], release_req)
    if include_db:
        w.send(
            db_stream, db_client, DB_PORT, b"B\x00\x00\x00\x20breakglass_share_released"
        )
        if commit_before_response:
            w.send(db_stream, DB_PORT, db_client, PG_COMMIT_COMPLETE)
    w.send(audit_stream, SERVICES["audit"], audit_client, release_resp)
    if include_db and not commit_before_response:
        w.send(db_stream, DB_PORT, db_client, PG_COMMIT_COMPLETE)

    unlock_body = {
        "shares": [[1, c["share1"].hex()], [3, c["share3"].hex()]],
        "certs": "C" * 6000,
    }
    w.exchange(
        "facility-b",
        http_request("POST", "/records/rec-001/breakglass", unlock_body),
        http_response(200, {"rewrapped_dek_b64": "opaque"}),
    )
    for _ in range(searches):
        w.exchange(
            "facility-b",
            http_request(
                "POST", "/records/rec-001/emergency-search", {"search_term": "cardiac"}
            ),
            http_response(200, {"record_ids": ["rec-001"], "record_count": 1}),
        )
    return Capture(
        "plain", w.segments, list(canaries.values()), dict(SERVICES), DB_PORT
    )


def tls_scenario(canaries: dict[str, Canary], *, leak: bytes | None = None) -> Capture:
    """The same scenario as opaque TLS records, sizes roughly preserved."""

    def record(size: int) -> bytes:
        return b"\x17\x03\x03" + secrets.token_bytes(size)

    w = Wire()
    w.exchange("authority-med", record(200), record(150))
    w.exchange("audit", record(300), record(120))
    w.exchange("audit", record(200), record(400))
    w.exchange("facility-b", record(6500) + (leak or b""), record(300))
    w.exchange("facility-b", record(250), record(180))
    return Capture("tls", w.segments, list(canaries.values()), dict(SERVICES), DB_PORT)
