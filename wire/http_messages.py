"""Minimal HTTP/1.1 message splitter over reassembled flows (ADR-0045).

Claim 2 needs to know which request or response a byte belongs to and when
that message started. Parsing the reassembled stream ourselves keeps that
independent of tshark's HTTP dissector settings and makes it unit-testable.

Supports keep-alive connections carrying several messages, ``Content-Length``
bodies and ``Transfer-Encoding: chunked``. Anything it cannot parse ends the
walk for that flow -- the remaining bytes are still searched by the canary
check, so a parse failure can hide a message boundary, never a leak.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from wire.streams import Flow, FlowKey


@dataclass(frozen=True)
class HttpMessage:
    flow: FlowKey
    start: int  # offset of the start line in flow.data
    end: int  # offset one past the last body byte
    is_request: bool
    method: str
    path: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    frame: int
    timestamp: float

    def json(self) -> object | None:
        try:
            return json.loads(self.body)
        except ValueError:
            return None


def _dechunk(data: bytes, pos: int) -> tuple[bytes, int] | None:
    body = bytearray()
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return None
        try:
            size = int(data[pos:line_end].split(b";")[0], 16)
        except ValueError:
            return None
        pos = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n", pos)
            return (bytes(body), trailer_end + 2) if trailer_end != -1 else None
        if pos + size + 2 > len(data):
            return None
        body += data[pos : pos + size]
        pos += size + 2


def parse_flow(flow: Flow) -> list[HttpMessage]:
    """Split one flow into its HTTP messages, in order."""
    data = flow.data
    messages: list[HttpMessage] = []
    pos = 0
    while pos < len(data):
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end == -1:
            break
        lines = data[pos:head_end].decode("latin-1").split("\r\n")
        start_line = lines[0].split(" ", 2)
        if len(start_line) < 2:
            break
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

        is_request = not start_line[0].startswith("HTTP/")
        status: int | None = None
        if not is_request:
            try:
                status = int(start_line[1])
            except ValueError:
                break  # malformed status line: stop walking this flow (N15)
        body_start = head_end + 4
        if headers.get("transfer-encoding", "").lower() == "chunked":
            parsed = _dechunk(data, body_start)
            if parsed is None:
                break
            body, end = parsed
        else:
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                break
            end = body_start + length
            if end > len(data):
                break
            body = data[body_start:end]

        frame, ts = flow.locate(pos)
        messages.append(
            HttpMessage(
                flow=flow.key,
                start=pos,
                end=end,
                is_request=is_request,
                method=start_line[0] if is_request else "",
                path=start_line[1] if is_request else "",
                status=status,
                headers=headers,
                body=body,
                frame=frame,
                timestamp=ts,
            )
        )
        pos = end
    return messages


@dataclass(frozen=True)
class Exchange:
    request: HttpMessage
    response: HttpMessage | None


def pair_exchanges(flows: dict[FlowKey, Flow]) -> list[Exchange]:
    """Pair each request with the response on the reverse flow, by order.

    HTTP/1.1 without pipelining answers requests in order on a connection, so
    the n-th request on a stream pairs with the n-th response.
    """
    by_stream: dict[int, dict[str, list[HttpMessage]]] = {}
    for flow in flows.values():
        for msg in parse_flow(flow):
            kind = "req" if msg.is_request else "resp"
            by_stream.setdefault(flow.key.stream, {"req": [], "resp": []})[kind].append(
                msg
            )

    exchanges = []
    for messages in by_stream.values():
        requests = sorted(messages["req"], key=lambda m: m.start)
        responses = sorted(messages["resp"], key=lambda m: m.start)
        for i, req in enumerate(requests):
            exchanges.append(
                Exchange(req, responses[i] if i < len(responses) else None)
            )
    exchanges.sort(key=lambda e: (e.request.timestamp, e.request.frame))
    return exchanges
