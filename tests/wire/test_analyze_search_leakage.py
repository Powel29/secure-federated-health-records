"""Unit tests for the P5-3 search leakage summariser.

The measurement logic is exercised on flattened HTTP events so it runs
without tshark or a capture file.
"""

from __future__ import annotations

from types import SimpleNamespace

from wire.analyze_search_leakage import (
    extract_http_event,
    is_search_uri,
    record_id_from_uri,
    summarize_search_leakage,
)

URI = "/records/rec-001/emergency-search"


def _request(frame: int, ts: float, body: str = '{"search_term": "cardiac"}'):
    return {
        "kind": "request",
        "frame": frame,
        "timestamp": ts,
        "frame_bytes": 300,
        "content_length": len(body),
        "body": body,
        "method": "POST",
        "uri": URI,
        "host": "127.0.0.1:8001",
    }


def _response(frame: int, request_frame: int, count: int, length: int):
    return {
        "kind": "response",
        "frame": frame,
        "timestamp": None,
        "frame_bytes": 400,
        "content_length": length,
        "body": f'{{"record_ids": [], "record_count": {count}}}',
        "status": 200,
        "request_frame": request_frame,
        "uri": URI,
    }


class TestSummary:
    def test_responses_are_not_counted_as_queries(self):
        """Regression: a response echoes the request URI; it is not a query."""
        events = [
            _request(1, 10.0),
            _response(2, 1, count=1, length=50),
            _request(3, 14.0),
            _response(4, 3, count=1, length=50),
        ]
        result = summarize_search_leakage(events)
        assert result["query_volume"] == 2
        assert result["answered_queries"] == 2
        assert result["inter_query_seconds"] == [4.0]

    def test_access_pattern_is_keyed_by_record(self):
        result = summarize_search_leakage([_request(1, 1.0), _request(2, 2.0)])
        assert result["access_pattern_by_record"] == {"rec-001": 2}
        assert result["repeated_requests"] == {URI: 2}

    def test_response_size_grouped_by_hidden_result_count(self):
        events = [
            _request(1, 1.0),
            _response(2, 1, count=0, length=35),
            _request(3, 2.0),
            _response(4, 3, count=2, length=71),
        ]
        result = summarize_search_leakage(events)
        assert result["distinct_response_sizes"] == [35, 71]
        assert result["response_bytes_by_result_count"] == {"0": [35], "2": [71]}

    def test_plaintext_query_is_flagged(self):
        result = summarize_search_leakage([_request(1, 1.0)])
        assert result["queries_visible_in_clear"] == 1

    def test_unreadable_body_is_not_flagged(self):
        result = summarize_search_leakage([_request(1, 1.0, body="")])
        assert result["queries_visible_in_clear"] == 0

    def test_non_search_traffic_ignored(self):
        other = _request(1, 1.0)
        other["uri"] = "/records/rec-001/read"
        assert summarize_search_leakage([other])["query_volume"] == 0


class TestHelpers:
    def test_is_search_uri(self):
        assert is_search_uri(URI)
        assert is_search_uri("/search?x=1")
        assert not is_search_uri("/records/research-notes/read")

    def test_record_id_from_uri(self):
        assert record_id_from_uri(URI) == "rec-001"
        assert record_id_from_uri("/search") is None

    def test_extract_request_and_response(self):
        req = SimpleNamespace(
            number="7",
            sniff_timestamp="1.5",
            length="320",
            http=SimpleNamespace(
                request_method="POST",
                request_uri=URI,
                host="h",
                content_length_header="26",
                file_data='{"search_term": "x"}',
            ),
        )
        resp = SimpleNamespace(
            number="8",
            sniff_timestamp="1.6",
            length="400",
            http=SimpleNamespace(
                response_code="200",
                request_in="7",
                response_for_uri=URI,
                content_length_header="40",
            ),
        )
        assert extract_http_event(req)["kind"] == "request"
        parsed = extract_http_event(resp)
        assert parsed["kind"] == "response"
        assert parsed["request_frame"] == 7
        assert extract_http_event(SimpleNamespace(tcp=object())) is None
