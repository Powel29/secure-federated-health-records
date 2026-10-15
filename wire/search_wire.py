"""Search tokens and TLS record sizes as an on-path observer sees them (P5-3).

Two views :mod:`wire.analyze_search_leakage` adds to its HTTP view (ADR-0070):

- **The database link.** The facility derives a search token and looks it up
  in Postgres, over the same loopback the capture covers. The Postgres wire
  protocol carries the statement text (``Parse``), the token as a bind
  parameter (``Bind``) and the result row count (``CommandComplete``), so an
  observer of that link sees which token was asked for and whether it hit --
  under the TLS profile too, because only the federation's HTTP links use TLS.
- **TLS record sizes.** Over TLS the HTTP view is empty, but each request and
  response is still a run of application-data records whose lengths and times
  are visible. Paired with the token lookups by time, they give a per-search
  size and latency the observer can measure without a key.

When the store link is encrypted (the TLS profile since ADR-0071) the first
view is empty -- :func:`pg_link_status` says so -- and the TLS exchanges are
labelled from the workload's own search manifest instead
(:func:`label_tls_exchanges`): the labels say which exchange was which search,
while every size and time measured still comes off the wire.

Both are pure functions over reassembled flows (:mod:`wire.streams`), so they
run in tests without tshark. A flow with a lost segment is read only up to the
gap: parsing across it could invent messages that never crossed the wire.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from wire.streams import Flow, FlowKey

# The facility's token lookup (storage.repositories.find_records_by_search_term).
SEARCH_STATEMENT_MARKER = "FROM search_index WHERE coded_term"

_PG_SSL_REQUEST = 80877103
_PG_PROTOCOL_3 = 196608
_PG_FRONTEND_TYPES = frozenset(b"BCDEFHPQSXcdfp")
_PG_BACKEND_TYPES = frozenset(b"123ACDEGHIKNRSTVWZcdnstv")

_TLS_APPLICATION_DATA = 23
_TLS_RECORD_TYPES = frozenset({20, 21, 22, 23})


@dataclass(frozen=True)
class PgMessage:
    """One typed Postgres protocol message and when its first byte was seen."""

    kind: str
    body: bytes
    timestamp: float
    frame: int


@dataclass(frozen=True)
class TokenLookup:
    """One search-token query on the database link."""

    timestamp: float
    frame: int
    stream: int
    token_fingerprint: str
    token_bytes: int
    rows: int | None  # from the CommandComplete tag the server sent back


@dataclass(frozen=True)
class TlsRecord:
    stream: int
    src_port: int
    dst_port: int
    content_type: int
    length: int
    timestamp: float


def _usable(flow: Flow) -> bytes:
    """The flow's bytes up to its first gap (review N8)."""
    return flow.data[: min(flow.gaps)] if flow.gaps else flow.data


def _cstring(buf: bytes, pos: int) -> tuple[str, int]:
    end = buf.index(b"\x00", pos)
    return buf[pos:end].decode("utf-8", "replace"), end + 1


def pg_link_status(flows: dict[FlowKey, Flow], db_port: int) -> dict[str, int]:
    """How many store connections ran in the clear and how many over TLS.

    A connection is TLS when the client opened with an SSLRequest the server
    accepted (``S``), or -- for a pooled connection opened before the capture
    started -- when its first captured bytes are already TLS records. A plain
    startup, a refused SSLRequest (``N``) or Postgres messages are plaintext;
    anything else is counted as unknown rather than guessed.
    """
    status = {"connections": 0, "tls": 0, "plaintext": 0, "unknown": 0}
    for key, flow in flows.items():
        data = _usable(flow)
        if key.dst_port != db_port or len(data) < 8:
            continue
        status["connections"] += 1
        _length, code = struct.unpack("!II", data[:8])
        reverse = flows.get(FlowKey(key.stream, key.dst_port, key.src_port))
        answer = reverse.data[:1] if reverse else b""
        if code == _PG_SSL_REQUEST:
            status["tls" if answer == b"S" else "plaintext"] += 1
        elif code == _PG_PROTOCOL_3:
            status["plaintext"] += 1
        elif data[0] in _TLS_RECORD_TYPES and data[1] == 3:
            status["tls"] += 1
        elif data[0] in _PG_FRONTEND_TYPES:
            status["plaintext"] += 1
        else:
            status["unknown"] += 1
    return status


def pg_messages(flow: Flow, *, frontend: bool) -> list[PgMessage]:
    """Split one direction of a Postgres connection into typed messages.

    A frontend flow opens with an untyped startup packet; an SSLRequest means
    the rest is encrypted, so nothing after it is parsed. Parsing stops at the
    first message whose type or length is not plausible.
    """
    data = _usable(flow)
    pos = 0
    if frontend and len(data) >= 8:
        length, code = struct.unpack("!II", data[:8])
        if code == _PG_SSL_REQUEST:
            return []
        if code == _PG_PROTOCOL_3:
            pos = length
    allowed = _PG_FRONTEND_TYPES if frontend else _PG_BACKEND_TYPES
    messages: list[PgMessage] = []
    while pos + 5 <= len(data):
        kind = data[pos]
        (length,) = struct.unpack("!I", data[pos + 1 : pos + 5])
        if kind not in allowed or length < 4 or pos + 1 + length > len(data):
            break
        frame, timestamp = flow.locate(pos)
        messages.append(
            PgMessage(
                kind=chr(kind),
                body=data[pos + 5 : pos + 1 + length],
                timestamp=timestamp,
                frame=frame,
            )
        )
        pos += 1 + length
    return messages


def _bind_params(body: bytes) -> tuple[str, list[tuple[int, bytes | None]]]:
    """``(statement name, [(format, value), ...])`` from a Bind body."""
    _portal, pos = _cstring(body, 0)
    statement, pos = _cstring(body, pos)
    (n_formats,) = struct.unpack("!H", body[pos : pos + 2])
    pos += 2
    formats = list(struct.unpack(f"!{n_formats}H", body[pos : pos + 2 * n_formats]))
    pos += 2 * n_formats
    (n_params,) = struct.unpack("!H", body[pos : pos + 2])
    pos += 2
    params: list[tuple[int, bytes | None]] = []
    for i in range(n_params):
        (size,) = struct.unpack("!i", body[pos : pos + 4])
        pos += 4
        value = None if size < 0 else body[pos : pos + size]
        pos += max(size, 0)
        # One format code applies to all; none means text (protocol rule).
        fmt = formats[0] if n_formats == 1 else (formats[i] if formats else 0)
        params.append((fmt, value))
    return statement, params


def _token_value(fmt: int, value: bytes) -> bytes:
    """A bytea parameter as raw bytes, whether sent binary or as text hex."""
    if fmt == 0 and value.startswith(b"\\x"):
        return bytes.fromhex(value[2:].decode("ascii"))
    return value


def fingerprint(token: bytes) -> str:
    """A short stable label for a token; the report never carries the token."""
    return hashlib.sha256(token).hexdigest()[:12]


def _rows_from_tag(body: bytes) -> int | None:
    tag = body.rstrip(b"\x00").decode("ascii", "replace").split()
    if len(tag) == 2 and tag[0] == "SELECT" and tag[1].isdigit():
        return int(tag[1])
    return None


def search_token_lookups(flows: dict[FlowKey, Flow], db_port: int) -> list[TokenLookup]:
    """Every search-index lookup visible on the database link, in time order.

    The statement is recognised by its text, which the observer reads from
    ``Parse``; prepared statements (psycopg prepares after a few executions)
    are followed by name. Each lookup's row count is the next ``SELECT n``
    ``CommandComplete`` the server sends on the same connection.
    """
    lookups: list[TokenLookup] = []
    for key, flow in flows.items():
        if key.dst_port != db_port:
            continue
        reverse = flows.get(FlowKey(key.stream, key.dst_port, key.src_port))
        completions = [
            m
            for m in (pg_messages(reverse, frontend=False) if reverse else [])
            if m.kind == "C"
        ]
        statements: dict[str, str] = {}
        for msg in pg_messages(flow, frontend=True):
            if msg.kind == "P":
                name, pos = _cstring(msg.body, 0)
                statements[name], _ = _cstring(msg.body, pos)
                continue
            if msg.kind != "B":
                continue
            statement, params = _bind_params(msg.body)
            query = statements.get(statement, "")
            if SEARCH_STATEMENT_MARKER not in query or not params:
                continue
            fmt, value = params[0]
            if value is None:
                continue
            token = _token_value(fmt, value)
            done = next((c for c in completions if c.timestamp >= msg.timestamp), None)
            if done is not None:
                completions.remove(done)
            lookups.append(
                TokenLookup(
                    timestamp=msg.timestamp,
                    frame=msg.frame,
                    stream=key.stream,
                    token_fingerprint=fingerprint(token),
                    token_bytes=len(token),
                    rows=_rows_from_tag(done.body) if done else None,
                )
            )
    return sorted(lookups, key=lambda t: t.timestamp)


def tls_records(flow: Flow) -> list[TlsRecord]:
    """The TLS record headers of one flow direction (type, length, time)."""
    data = _usable(flow)
    pos = 0
    records: list[TlsRecord] = []
    while pos + 5 <= len(data):
        content_type = data[pos]
        major = data[pos + 1]
        (length,) = struct.unpack("!H", data[pos + 3 : pos + 5])
        if content_type not in _TLS_RECORD_TYPES or major != 3:
            break
        if pos + 5 + length > len(data):
            break
        _frame, timestamp = flow.locate(pos)
        records.append(
            TlsRecord(
                stream=flow.key.stream,
                src_port=flow.key.src_port,
                dst_port=flow.key.dst_port,
                content_type=content_type,
                length=length,
                timestamp=timestamp,
            )
        )
        pos += 5 + length
    return records


@dataclass(frozen=True)
class TlsMessage:
    """Consecutive application-data records one side sent before the other spoke.

    An HTTP/1.1 message over TLS is a short burst of records -- here the
    headers, then the body -- so the burst, not one record, is the unit an
    observer sizes. On a fresh TLS 1.3 connection the server's session
    tickets (also application-data records) can open the burst that carries
    the response, so the body is the burst's last record and latency is
    measured to ``last_timestamp``, never to the first record.
    """

    stream: int
    src_port: int
    dst_port: int
    timestamp: float
    record_lengths: tuple[int, ...]
    last_timestamp: float


def tls_messages(flows: dict[FlowKey, Flow]) -> list[TlsMessage]:
    """Every TLS application-data message in the capture, in time order."""
    by_stream: dict[int, list[TlsRecord]] = {}
    for flow in flows.values():
        by_stream.setdefault(flow.key.stream, []).extend(
            r for r in tls_records(flow) if r.content_type == _TLS_APPLICATION_DATA
        )
    messages: list[TlsMessage] = []
    for stream, records in by_stream.items():
        records.sort(key=lambda r: r.timestamp)
        run: list[TlsRecord] = []
        for rec in [*records, None]:
            if run and (rec is None or rec.src_port != run[0].src_port):
                messages.append(
                    TlsMessage(
                        stream=stream,
                        src_port=run[0].src_port,
                        dst_port=run[0].dst_port,
                        timestamp=run[0].timestamp,
                        record_lengths=tuple(r.length for r in run),
                        last_timestamp=run[-1].timestamp,
                    )
                )
                run = []
            if rec is not None:
                run.append(rec)
    return sorted(messages, key=lambda m: m.timestamp)


def tls_exchanges_for_lookups(
    flows: dict[FlowKey, Flow],
    lookups: list[TokenLookup],
    facility_ports: set[int],
) -> list[dict[str, object]]:
    """The TLS request and response around each token lookup, by time.

    The request is the last message sent to a facility before the lookup; the
    response is the facility's first message after it on the same connection.
    Their record lengths are what TLS leaves visible -- the last record of
    each is the HTTP body -- and the gap between their last records is the
    observer's latency measurement.
    """
    messages = tls_messages(flows)
    to_facility = [m for m in messages if m.dst_port in facility_ports]
    from_facility = [m for m in messages if m.src_port in facility_ports]
    exchanges: list[dict[str, object]] = []
    for lookup in lookups:
        request = next(
            (m for m in reversed(to_facility) if m.timestamp <= lookup.timestamp),
            None,
        )
        response = (
            next(
                (
                    m
                    for m in from_facility
                    if m.timestamp >= lookup.timestamp
                    and m.stream == request.stream
                    and m.dst_port == request.src_port
                ),
                None,
            )
            if request
            else None
        )
        exchanges.append(
            {
                "lookup_timestamp": lookup.timestamp,
                "request_timestamp": request.timestamp if request else None,
                "request_record_lengths": (
                    list(request.record_lengths) if request else None
                ),
                "response_timestamp": response.timestamp if response else None,
                "response_record_lengths": (
                    list(response.record_lengths) if response else None
                ),
                "latency_seconds": (
                    response.last_timestamp - request.last_timestamp
                    if request and response
                    else None
                ),
            }
        )
    return exchanges


def label_tls_exchanges(
    flows: dict[FlowKey, Flow],
    searches: list[dict[str, object]],
    facility_ports: set[int],
    *,
    lead: float = 0.001,
    slack: float = 0.05,
) -> list[dict[str, object]]:
    """Find each known search's TLS request and response in the capture.

    ``searches`` is the workload's manifest (``sent_at``/``answered_at`` from
    the client's clock, the capture's clock on loopback). The client stamps
    ``sent_at`` before it writes, so the request is the first message to a
    facility from ``lead`` seconds before that on; reaching further back
    picks up the previous request (the lifecycle poll before the refused
    search did exactly that). The response is the facility's first message
    back on the same connection by ``answered_at`` + ``slack``. A search with
    no matching exchange keeps ``None`` sizes rather than borrowing a
    neighbour's.
    """
    messages = tls_messages(flows)
    to_facility = [m for m in messages if m.dst_port in facility_ports]
    from_facility = [m for m in messages if m.src_port in facility_ports]
    labelled: list[dict[str, object]] = []
    for search in searches:
        start = float(search["sent_at"]) - lead  # type: ignore[arg-type]
        end = float(search["answered_at"]) + slack  # type: ignore[arg-type]
        request = next((m for m in to_facility if start <= m.timestamp <= end), None)
        response = (
            next(
                (
                    m
                    for m in from_facility
                    if request.timestamp <= m.timestamp <= end
                    and m.stream == request.stream
                    and m.dst_port == request.src_port
                ),
                None,
            )
            if request
            else None
        )
        labelled.append(
            {
                **search,
                "request_record_lengths": (
                    list(request.record_lengths) if request else None
                ),
                "response_record_lengths": (
                    list(response.record_lengths) if response else None
                ),
                "latency_seconds": (
                    response.last_timestamp - request.last_timestamp
                    if request and response
                    else None
                ),
            }
        )
    return labelled
