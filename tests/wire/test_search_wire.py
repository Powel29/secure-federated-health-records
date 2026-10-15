"""Unit tests for the P5-3 database-link and TLS-size views (ADR-0070).

Postgres and TLS bytes are built by hand, so the parsers run without tshark;
each control is driven both ways (holding and violated).
"""

from __future__ import annotations

import struct

from wire.analyze_search_leakage import (
    _body_text,
    link_queries_to_lookups,
    summarize_search_leakage,
    summarize_token_leakage,
)
from wire.search_wire import (
    TokenLookup,
    fingerprint,
    search_token_lookups,
    tls_exchanges_for_lookups,
    tls_messages,
)
from wire.streams import Segment, reassemble

DB = 55433
CLIENT = 50000
SQL = "SELECT record_id FROM search_index WHERE coded_term = $1"
TOKEN_A = bytes(range(32))
TOKEN_B = bytes(range(32, 64))


def _msg(kind: bytes, body: bytes) -> bytes:
    return kind + struct.pack("!I", len(body) + 4) + body


def _startup() -> bytes:
    body = struct.pack("!I", 196608) + b"user\x00postgres\x00\x00"
    return struct.pack("!I", len(body) + 4) + body


def _parse(name: str, sql: str) -> bytes:
    return _msg(b"P", name.encode() + b"\x00" + sql.encode() + b"\x00\x00\x00")


def _bind(statement: str, token: bytes, *, text: bool = False) -> bytes:
    value = b"\\x" + token.hex().encode() if text else token
    body = (
        b"\x00"
        + statement.encode()
        + b"\x00"
        + struct.pack("!HH", 1, 0 if text else 1)
        + struct.pack("!H", 1)
        + struct.pack("!i", len(value))
        + value
        + struct.pack("!H", 0)
    )
    return _msg(b"B", body)


def _execute() -> bytes:
    return _msg(b"E", b"\x00\x00\x00\x00\x00") + _msg(b"S", b"")


def _complete(rows: int) -> bytes:
    return _msg(b"C", f"SELECT {rows}".encode() + b"\x00") + _msg(b"Z", b"I")


def _flows(client_chunks: list[tuple[float, bytes]], server_chunks):
    """One Postgres connection: ``(timestamp, bytes)`` chunks each way."""
    segments: list[Segment] = []
    frame = 1
    for direction, chunks in ((0, client_chunks), (1, server_chunks)):
        seq = 1
        for ts, payload in chunks:
            src, dst = (CLIENT, DB) if direction == 0 else (DB, CLIENT)
            segments.append(Segment(frame, ts, 3, src, dst, seq, payload))
            seq += len(payload)
            frame += 1
    return reassemble(segments)


class TestTokenLookups:
    def test_unnamed_and_prepared_lookups_are_both_read(self):
        """psycopg prepares after a few runs; the named statement must count."""
        flows = _flows(
            [
                (1.0, _startup()),
                (2.0, _parse("", SQL) + _bind("", TOKEN_A) + _execute()),
                (3.0, _parse("_pg3_0", SQL) + _bind("_pg3_0", TOKEN_B) + _execute()),
                (4.0, _bind("_pg3_0", TOKEN_A) + _execute()),
            ],
            [(2.1, _complete(1)), (3.1, _complete(0)), (4.1, _complete(1))],
        )
        lookups = search_token_lookups(flows, DB)
        assert [t.token_fingerprint for t in lookups] == [
            fingerprint(TOKEN_A),
            fingerprint(TOKEN_B),
            fingerprint(TOKEN_A),
        ]
        assert [t.rows for t in lookups] == [1, 0, 1]
        assert all(t.token_bytes == 32 for t in lookups)

    def test_text_format_bytea_is_decoded(self):
        flows = _flows(
            [(1.0, _startup()), (2.0, _parse("", SQL) + _bind("", TOKEN_A, text=True))],
            [],
        )
        [lookup] = search_token_lookups(flows, DB)
        assert lookup.token_fingerprint == fingerprint(TOKEN_A)
        assert lookup.rows is None

    def test_other_statements_are_not_lookups(self):
        flows = _flows(
            [
                (1.0, _startup()),
                (2.0, _parse("", "SELECT 1 FROM records WHERE x = $1")),
                (2.5, _bind("", TOKEN_A)),
            ],
            [],
        )
        assert search_token_lookups(flows, DB) == []

    def test_encrypted_database_link_shows_nothing(self):
        """After an SSLRequest the bytes are TLS; nothing may be parsed."""
        ssl_request = struct.pack("!II", 8, 80877103)
        flows = _flows([(1.0, ssl_request + _parse("", SQL) + _bind("", TOKEN_A))], [])
        assert search_token_lookups(flows, DB) == []

    def test_parsing_stops_at_a_lost_segment(self):
        """A gap must not be bridged into a lookup that never crossed (N8)."""
        first = _startup() + _parse("", SQL)
        bind = _bind("", TOKEN_A)
        segments = [
            Segment(1, 1.0, 3, CLIENT, DB, 1, first),
            # bytes first..first+10 are lost
            Segment(2, 2.0, 3, CLIENT, DB, 1 + len(first) + 10, bind),
        ]
        assert search_token_lookups(reassemble(segments), DB) == []


def _record(content_type: int, length: int) -> bytes:
    return bytes([content_type, 3, 3]) + struct.pack("!H", length) + b"\x00" * length


class TestTlsView:
    def _tls_flows(self):
        facility, client = 8002, 51000
        up = [
            (1.0, _record(23, 1535) + _record(23, 70)),  # request: headers, body
            (3.0, _record(23, 1535) + _record(23, 72)),
        ]
        down = [
            (1.5, _record(23, 142) + _record(23, 60)),  # hit
            (3.5, _record(23, 142) + _record(23, 51)),  # miss
        ]
        segments: list[Segment] = []
        frame = 1
        for src, dst, chunks in ((client, facility, up), (facility, client, down)):
            seq = 1
            for ts, payload in chunks:
                segments.append(Segment(frame, ts, 9, src, dst, seq, payload))
                seq += len(payload)
                frame += 1
        return reassemble(segments)

    def test_records_group_into_messages(self):
        messages = tls_messages(self._tls_flows())
        assert [m.record_lengths for m in messages] == [
            (1535, 70),
            (142, 60),
            (1535, 72),
            (142, 51),
        ]

    def test_exchange_sizes_follow_the_lookups(self):
        lookups = [
            TokenLookup(1.2, 1, 3, "a", 32, 1),
            TokenLookup(3.2, 2, 3, "b", 32, 0),
        ]
        exchanges = tls_exchanges_for_lookups(self._tls_flows(), lookups, {8002})
        assert [e["request_record_lengths"] for e in exchanges] == [
            [1535, 70],
            [1535, 72],
        ]
        assert [e["response_record_lengths"][-1] for e in exchanges] == [60, 51]
        assert exchanges[0]["latency_seconds"] == 0.5


def _query(ts: float, term: str, status: int = 200, count: int | None = 1):
    return {
        "timestamp": ts,
        "response_timestamp": ts + 0.1,
        "response_status": status,
        "search_term": term,
        "result_count": count,
    }


class TestTokenLeakage:
    def _run(self, tokens_after_expiry: dict[str, str]):
        queries = [
            _query(1.0, "cardiac"),
            _query(2.0, "cardiac"),
            _query(3.0, "pneumonia", count=0),
            _query(4.0, "cardiac", status=403, count=None),
            _query(5.0, "cardiac"),
        ]
        lookups = [
            TokenLookup(1.05, 1, 3, "tok-c", 32, 1),
            TokenLookup(2.05, 2, 3, "tok-c", 32, 1),
            TokenLookup(3.05, 3, 3, "tok-p", 32, 0),
            # a refused search makes no lookup
            TokenLookup(5.05, 5, 3, tokens_after_expiry["cardiac"], 32, 1),
        ]
        link_queries_to_lookups(queries, lookups)
        return queries, summarize_token_leakage(lookups, queries)

    def test_rekeyed_term_is_reported(self):
        queries, result = self._run({"cardiac": "tok-c2"})
        assert queries[3]["token_fingerprint"] is None
        assert result["epochs"] == 2
        assert result["same_term_same_token_within_epoch"] is True
        assert result["terms_rekeyed_across_epochs"] == ["cardiac"]
        assert result["token_frequency"] == {"tok-c": 2, "tok-p": 1, "tok-c2": 1}
        assert result["lookups_by_row_count"] == {"0": 1, "1": 3}

    def test_token_surviving_expiry_is_not_called_rekeyed(self):
        """Mutation: rotation skipped, the pre-expiry token still used."""
        _queries, result = self._run({"cardiac": "tok-c"})
        assert result["terms_searched_in_several_epochs"] == ["cardiac"]
        assert result["terms_rekeyed_across_epochs"] == []

    def test_unreadable_bodies_link_no_terms(self):
        lookups = [TokenLookup(1.0, 1, 3, "tok", 32, 1)]
        result = summarize_token_leakage(lookups, [])
        assert result["terms_linked_to_tokens"] is None
        assert result["distinct_tokens"] == 1


class TestBodyText:
    def test_tshark_hex_body_is_decoded(self):
        """tshark 4.6 reports file_data as colon hex; it is still readable."""
        hex_body = ":".join(f"{b:02x}" for b in b'{"search_term": "cardiac"}')

        class Http:
            file_data = hex_body

        assert _body_text(Http()) == '{"search_term": "cardiac"}'

    def test_term_frequency_counts_the_plaintext_term(self):
        events = []
        for frame, term in enumerate(["cardiac", "aspirin", "cardiac"], start=1):
            body = f'{{"search_term": "{term}"}}'
            events.append(
                {
                    "kind": "request",
                    "frame": frame,
                    "timestamp": float(frame),
                    "frame_bytes": 300,
                    "content_length": len(body),
                    "body": body,
                    "method": "POST",
                    "uri": "/records/rec-001/emergency-search",
                    "host": "h",
                }
            )
        result = summarize_search_leakage(events)
        assert result["term_frequency"] == {"cardiac": 2, "aspirin": 1}
