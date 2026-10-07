"""Unit tests for P5-5 stream reassembly, canary encodings and HTTP splitting.

A canary search that misses an encoding, or a reassembly that drops a split
secret, produces a false pass. Each encoding is therefore planted and found,
and near-misses are shown not to match.
"""

from __future__ import annotations

import base64
import secrets

import pytest

from wire.canaries import Canary, encodings, find_hits
from wire.http_messages import pair_exchanges, parse_flow
from wire.streams import FlowKey, Segment, reassemble

from .synthetic import Wire, http_request, http_response


def _flow_of(data: bytes, *, mss: int = 1400):
    w = Wire()
    w.send(0, 50000, 8001, data, mss=mss)
    return reassemble(w.segments)


class TestReassembly:
    def test_out_of_order_segments_are_stitched_in_sequence(self):
        segs = [
            Segment(2, 2.0, 0, 50000, 8001, 4, b"DEF"),
            Segment(1, 1.0, 0, 50000, 8001, 1, b"ABC"),
        ]
        flow = reassemble(segs)[FlowKey(0, 50000, 8001)]
        assert flow.data == b"ABCDEF"
        assert flow.locate(4) == (2, 2.0)

    def test_retransmission_does_not_duplicate_bytes(self):
        segs = [
            Segment(1, 1.0, 0, 50000, 8001, 1, b"ABC"),
            Segment(2, 2.0, 0, 50000, 8001, 1, b"ABC"),
            Segment(3, 3.0, 0, 50000, 8001, 4, b"DEF"),
        ]
        assert reassemble(segs)[FlowKey(0, 50000, 8001)].data == b"ABCDEF"

    def test_overlapping_segment_contributes_only_new_bytes(self):
        segs = [
            Segment(1, 1.0, 0, 50000, 8001, 1, b"ABCD"),
            Segment(2, 2.0, 0, 50000, 8001, 3, b"CDEF"),
        ]
        assert reassemble(segs)[FlowKey(0, 50000, 8001)].data == b"ABCDEF"

    def test_directions_are_separate_flows(self):
        segs = [
            Segment(1, 1.0, 0, 50000, 8001, 1, b"req"),
            Segment(2, 2.0, 0, 8001, 50000, 1, b"resp"),
        ]
        assert len(reassemble(segs)) == 2

    def test_locate_rejects_out_of_range(self):
        flow = reassemble([Segment(1, 1.0, 0, 1, 2, 1, b"x")])[FlowKey(0, 1, 2)]
        with pytest.raises(IndexError):
            flow.locate(5)


class TestCanaryEncodings:
    @pytest.fixture()
    def canary(self):
        return Canary("k", "attribute_key", secrets.token_bytes(32))

    @pytest.mark.parametrize("prefix_len", [0, 1, 2, 5])
    def test_base64_found_at_any_alignment_inside_a_larger_blob(
        self, canary, prefix_len
    ):
        blob = base64.b64encode(
            secrets.token_bytes(prefix_len) + canary.value + b"tail"
        )
        hits = find_hits(_flow_of(b'{"x": "' + blob + b'"}'), [canary])
        assert hits, f"missed base64 at prefix {prefix_len}"

    @pytest.mark.parametrize(
        "encode",
        [
            lambda v: v,
            lambda v: v.hex().encode(),
            lambda v: v.hex().upper().encode(),
            lambda v: base64.urlsafe_b64encode(v),
        ],
        ids=["raw", "hex", "hex_upper", "base64url"],
    )
    def test_each_encoding_found(self, canary, encode):
        assert find_hits(_flow_of(b"<<" + encode(canary.value) + b">>"), [canary])

    def test_secret_split_across_segments_is_found(self, canary):
        payload = b"A" * 1390 + canary.value.hex().encode() + b"B" * 50
        hits = find_hits(_flow_of(payload, mss=1400), [canary])
        assert hits, "reassembly failed: split secret missed"

    def test_pem_found_when_json_escapes_newlines(self):
        body = b"".join(
            base64.b64encode(secrets.token_bytes(48)) + b"\n" for _ in range(3)
        )
        pem = b"-----BEGIN PRIVATE KEY-----\n" + body + b"-----END PRIVATE KEY-----\n"
        canary = Canary("pk", "private_key", pem)
        escaped = pem.replace(b"\n", b"\\n")
        assert find_hits(_flow_of(b'{"k": "' + escaped + b'"}'), [canary])
        assert all(label.startswith("pem_line") for label, _ in encodings(canary))

    def test_near_miss_does_not_match(self, canary):
        tampered = bytes([canary.value[0] ^ 1]) + canary.value[1:]
        flow = _flow_of(tampered.hex().encode())
        assert [h for h in find_hits(flow, [canary]) if h.encoding == "hex"] == []

    def test_short_patterns_are_not_searched(self):
        assert encodings(Canary("tiny", "share", b"\x01\x02")) == []


class TestHttpSplitting:
    def test_keep_alive_carries_two_messages(self):
        data = http_request("GET", "/a") + http_request("POST", "/b", {"x": 1})
        flow = next(iter(_flow_of(data).values()))
        messages = parse_flow(flow)
        assert [m.path for m in messages] == ["/a", "/b"]
        assert messages[1].json() == {"x": 1}

    def test_chunked_body_is_decoded(self):
        data = (
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        )
        flow = next(iter(_flow_of(data).values()))
        assert parse_flow(flow)[0].body == b"hello world"

    def test_requests_pair_with_responses_in_order(self):
        w = Wire()
        w.exchange("audit", http_request("GET", "/x"), http_response(200, {"a": 1}))
        exchanges = pair_exchanges(reassemble(w.segments))
        assert exchanges[0].request.path == "/x"
        assert exchanges[0].response.json() == {"a": 1}

    def test_truncated_message_stops_the_walk(self):
        data = b"POST /a HTTP/1.1\r\ncontent-length: 50\r\n\r\nshort"
        flow = next(iter(_flow_of(data).values()))
        assert parse_flow(flow) == []
