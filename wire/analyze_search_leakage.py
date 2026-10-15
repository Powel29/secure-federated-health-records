"""P5-3 search leakage analysis from real PyShark captures.

Measures what a network observer learns from search traffic (PROJECT.md §4A
claim 3): access pattern, query volume, response-size leakage and timing,
plus whether the query itself crossed the wire in the clear.

Requests and responses are counted separately. A response carries the URI of
the request it answers (``http.response_for.uri``), so matching on URI alone
double-counts every query; here only ``http.request`` packets count as
queries, and each response is paired to its request by frame number.

This intentionally analyzes captured traffic rather than relying on
application arguments or source-code assumptions.

Beyond the HTTP view, the database link and the TLS record sizes are read
too (:mod:`wire.search_wire`, ADR-0070): the token each search looks up, its
row count, and -- over TLS, where the HTTP view is empty -- the size and
latency of each search exchange. Once the store link is encrypted too
(ADR-0071) the database view is empty; ``--searches`` then names which TLS
exchange was which search, so the sizes can still be measured against the
truth.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from itertools import pairwise
from pathlib import Path
from typing import Any

import pyshark

from wire.capture import default_db_port
from wire.search_wire import (
    TokenLookup,
    label_tls_exchanges,
    pg_link_status,
    search_token_lookups,
    tls_exchanges_for_lookups,
)
from wire.streams import read_segments, reassemble
from wire.tls import SERVICES

FACILITY_PORTS = {SERVICES["facility-a"], SERVICES["facility-b"]}

SEARCH_MARKERS = (
    "/search",
    "/emergency-search",
)

# /records/<record_id>/emergency-search -> record_id
_RECORD_URI = re.compile(r"/records/([^/?]+)/")

# JSON keys whose presence in a readable request body means the query (or its
# token) was visible to the observer.
_QUERY_BODY_KEYS = ("search_term", "token")

_HEX_BYTES = re.compile(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})*")


def _int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def is_search_uri(uri: str) -> bool:
    lowered = uri.lower().split("?", 1)[0]
    return any(lowered.endswith(marker) for marker in SEARCH_MARKERS)


def record_id_from_uri(uri: str) -> str | None:
    match = _RECORD_URI.search(uri)
    return match.group(1) if match else None


def _body_text(http: object) -> str | None:
    """Readable HTTP body, or None when the observer cannot see one.

    tshark 4.6 reports ``http.file_data`` as colon-separated hex bytes; older
    builds give the text. Without decoding the hex, every body read as
    unreadable and the plaintext query was never flagged.
    """
    body = getattr(http, "file_data", None)
    if not body:
        return None
    text = str(body)
    if _HEX_BYTES.fullmatch(text):
        return bytes.fromhex(text.replace(":", "")).decode("utf-8", "replace")
    return text


def extract_http_event(packet: object) -> dict[str, Any] | None:
    """Flatten one PyShark packet into a request/response event, or None."""
    if not hasattr(packet, "http"):
        return None
    http = packet.http
    frame = _int(getattr(packet, "number", None))
    common = {
        "frame": frame,
        "timestamp": _float(getattr(packet, "sniff_timestamp", None)),
        "frame_bytes": _int(getattr(packet, "length", None)) or 0,
        "content_length": _int(getattr(http, "content_length_header", None)),
        "body": _body_text(http),
    }
    if hasattr(http, "request_method"):
        return {
            "kind": "request",
            "method": str(http.request_method),
            "uri": str(getattr(http, "request_uri", "")),
            "host": str(getattr(http, "host", "")),
            **common,
        }
    if hasattr(http, "response_code"):
        return {
            "kind": "response",
            "status": _int(http.response_code),
            "request_frame": _int(getattr(http, "request_in", None)),
            "uri": str(getattr(http, "response_for_uri", "")),
            **common,
        }
    return None


def _search_term(body: str | None) -> str | None:
    """The plaintext query, when the observer can read the request body."""
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    term = parsed.get("search_term") if isinstance(parsed, dict) else None
    return term if isinstance(term, str) else None


def _result_count(body: str | None) -> int | None:
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    count = parsed.get("record_count") if isinstance(parsed, dict) else None
    return count if isinstance(count, int) else None


def summarize_search_leakage(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the leakage profile from flattened HTTP events.

    Pure function so the measurement logic is testable without tshark.
    """
    requests = [e for e in events if e["kind"] == "request" and is_search_uri(e["uri"])]
    responses_by_request = {
        e["request_frame"]: e
        for e in events
        if e["kind"] == "response" and e.get("request_frame") is not None
    }

    queries: list[dict[str, Any]] = []
    for req in requests:
        resp = responses_by_request.get(req["frame"])
        body = req["body"] or ""
        queries.append(
            {
                "timestamp": req["timestamp"],
                "method": req["method"],
                "uri": req["uri"],
                "record_id": record_id_from_uri(req["uri"]),
                "request_bytes": req["content_length"],
                "query_visible_in_clear": any(k in body for k in _QUERY_BODY_KEYS),
                "search_term": _search_term(req["body"]),
                "response_timestamp": resp["timestamp"] if resp else None,
                "response_status": resp["status"] if resp else None,
                "response_bytes": resp["content_length"] if resp else None,
                "result_count": _result_count(resp["body"]) if resp else None,
            }
        )

    uri_counter = Counter(q["uri"] for q in queries)
    record_counter = Counter(q["record_id"] or "<none>" for q in queries)
    timestamps = [q["timestamp"] for q in queries if q["timestamp"] is not None]

    # Response-size leakage: does the observable size vary with the hidden
    # result count?  Group sizes by count where the body was readable.
    sizes_by_count: dict[str, list[int]] = {}
    for q in queries:
        if q["result_count"] is not None and q["response_bytes"] is not None:
            sizes_by_count.setdefault(str(q["result_count"]), []).append(
                q["response_bytes"]
            )
    response_sizes = sorted(
        {q["response_bytes"] for q in queries if q["response_bytes"] is not None}
    )

    return {
        "query_volume": len(queries),
        "answered_queries": sum(1 for q in queries if q["response_status"]),
        "unique_observable_requests": len(uri_counter),
        "repeated_requests": {
            uri: count for uri, count in sorted(uri_counter.items()) if count > 1
        },
        "access_pattern_by_record": dict(sorted(record_counter.items())),
        "queries_visible_in_clear": sum(
            1 for q in queries if q["query_visible_in_clear"]
        ),
        # Every search shares one URI, so frequency shows in the term itself.
        "term_frequency": dict(
            Counter(q["search_term"] for q in queries if q["search_term"]).most_common()
        ),
        "distinct_response_sizes": response_sizes,
        "response_bytes_by_result_count": dict(sorted(sizes_by_count.items())),
        "inter_query_seconds": [
            timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))
        ],
        "queries": queries,
    }


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def link_queries_to_lookups(
    queries: list[dict[str, Any]], lookups: list[TokenLookup]
) -> None:
    """Attach to each HTTP query the token lookup made while it was in flight.

    A lookup belongs to the query whose request precedes it and whose response
    follows it. A refused search (403) makes no lookup: the facility has no
    live key to derive a token from.
    """
    for q in queries:
        start, end = q["timestamp"], q["response_timestamp"]
        match = (
            next((t for t in lookups if start <= t.timestamp <= end), None)
            if start is not None and end is not None
            else None
        )
        q["token_fingerprint"] = match.token_fingerprint if match else None
        q["db_rows"] = match.rows if match else None
        q["latency_seconds"] = (
            end - start if start is not None and end is not None else None
        )


def summarize_token_leakage(
    lookups: list[TokenLookup], queries: list[dict[str, Any]]
) -> dict[str, Any]:
    """Frequency, result and re-keying leakage on the database link.

    ``queries`` must already be linked (:func:`link_queries_to_lookups`). When
    the HTTP bodies were readable, each token is tied to its plaintext term,
    and the searches are split into epochs at every refused search: the
    expiry that refused it re-keyed the index (ADR-0069), so the same term
    must not map to the same token across epochs.
    """
    frequency = Counter(t.token_fingerprint for t in lookups)
    stamps = [t.timestamp for t in lookups]
    result: dict[str, Any] = {
        "token_lookups": len(lookups),
        "distinct_tokens": len(frequency),
        "token_frequency": dict(frequency.most_common()),
        "lookups_with_visible_row_count": sum(1 for t in lookups if t.rows is not None),
        "lookups_by_row_count": dict(
            sorted(Counter(str(t.rows) for t in lookups).items())
        ),
        "inter_lookup_seconds": [b - a for a, b in pairwise(stamps)],
    }

    epoch = 0
    term_epoch_tokens: dict[str, dict[int, list[str]]] = {}
    refused_searches = 0
    for q in queries:
        if q["response_status"] == 403:
            refused_searches += 1
            epoch += 1
            continue
        term, fp = q.get("search_term"), q.get("token_fingerprint")
        if term is None or fp is None:
            continue
        tokens = term_epoch_tokens.setdefault(term, {}).setdefault(epoch, [])
        if fp not in tokens:
            tokens.append(fp)
    if not term_epoch_tokens:
        result["terms_linked_to_tokens"] = None  # bodies unreadable (TLS)
        return result

    token_terms: dict[str, set[str]] = {}
    for term, epochs in term_epoch_tokens.items():
        for fps in epochs.values():
            for fp in fps:
                token_terms.setdefault(fp, set()).add(term)
    across = {
        term: [fps[0] for _, fps in sorted(epochs.items())]
        for term, epochs in term_epoch_tokens.items()
        if len(epochs) > 1
    }
    result.update(
        {
            "terms_linked_to_tokens": len(term_epoch_tokens),
            "refused_searches": refused_searches,
            "epochs": epoch + 1,
            "term_tokens_by_epoch": {
                term: {str(e): fps for e, fps in sorted(epochs.items())}
                for term, epochs in sorted(term_epoch_tokens.items())
            },
            "same_term_same_token_within_epoch": all(
                len(fps) == 1
                for epochs in term_epoch_tokens.values()
                for fps in epochs.values()
            ),
            "terms_searched_in_several_epochs": sorted(across),
            "terms_rekeyed_across_epochs": sorted(
                term for term, fps in across.items() if len(set(fps)) == len(fps)
            ),
            "tokens_shared_by_distinct_terms": sorted(
                fp for fp, terms in token_terms.items() if len(terms) > 1
            ),
        }
    )
    return result


def summarize_timing(queries: list[dict[str, Any]]) -> dict[str, Any]:
    """Latency of answered searches, split by whether they hit (HTTP view)."""
    timed = [q for q in queries if q.get("latency_seconds") is not None]
    hits = [q["latency_seconds"] for q in timed if (q.get("result_count") or 0) > 0]
    misses = [q["latency_seconds"] for q in timed if q.get("result_count") == 0]
    refused = [q["latency_seconds"] for q in timed if q["response_status"] == 403]
    return {
        "hit_latency_seconds": hits,
        "miss_latency_seconds": misses,
        "refused_latency_seconds": refused,
        "mean_hit_latency_seconds": _mean(hits),
        "mean_miss_latency_seconds": _mean(misses),
        "median_hit_latency_seconds": _median(hits),
        "median_miss_latency_seconds": _median(misses),
    }


def summarize_tls_exchanges(
    exchanges: list[dict[str, Any]], lookups: list[TokenLookup]
) -> dict[str, Any]:
    """Size and latency per search exchange as TLS leaves them visible.

    Grouped by the row count the database link showed for the same search,
    so a size that separates the groups is a hit/miss leak despite TLS.
    """
    response_body: dict[str, list[int]] = {}
    request_body: list[int] = []
    latency_by_rows: dict[str, list[float]] = {}
    for ex, lookup in zip(exchanges, lookups, strict=True):
        key = str(lookup.rows)
        if ex["response_record_lengths"]:
            response_body.setdefault(key, []).append(ex["response_record_lengths"][-1])
        if ex["request_record_lengths"]:
            request_body.append(ex["request_record_lengths"][-1])
        if ex["latency_seconds"] is not None:
            latency_by_rows.setdefault(key, []).append(float(ex["latency_seconds"]))
    return {
        "exchanges": exchanges,
        "response_body_record_bytes_by_db_rows": {
            k: sorted(set(v)) for k, v in sorted(response_body.items())
        },
        "request_body_record_bytes": request_body,
        "distinct_request_body_record_bytes": sorted(set(request_body)),
        "mean_latency_seconds_by_db_rows": {
            k: _mean(v) for k, v in sorted(latency_by_rows.items())
        },
        "median_latency_seconds_by_db_rows": {
            k: _median(v) for k, v in sorted(latency_by_rows.items())
        },
    }


def _outcome(search: dict[str, Any]) -> str:
    if search["status"] != 200:
        return "refused"
    return "hit" if (search["record_count"] or 0) > 0 else "miss"


def summarize_labelled_tls(labelled: list[dict[str, Any]]) -> dict[str, Any]:
    """What TLS sizes and times give away, checked against the known searches.

    Each figure is measured on the wire; the labels only say which exchange
    was which search. ``request_body_minus_term_length`` with one value means
    the request size gives the term's length exactly; the observer then sees
    term frequency only up to terms of equal length
    (``observable_request_size_frequency``).
    """
    matched = [x for x in labelled if x["request_record_lengths"]]
    response_body: dict[str, set[int]] = {}
    latency: dict[str, list[float]] = {}
    by_term: dict[str, set[int]] = {}
    overhead: set[int] = set()
    for x in matched:
        outcome = _outcome(x)
        if x["response_record_lengths"]:
            response_body.setdefault(outcome, set()).add(
                x["response_record_lengths"][-1]
            )
        if x["latency_seconds"] is not None:
            latency.setdefault(outcome, []).append(float(x["latency_seconds"]))
        body = x["request_record_lengths"][-1]
        by_term.setdefault(x["term"], set()).add(body)
        overhead.add(body - len(x["term"]))
    sizes_separate = all(
        not (response_body.get(a, set()) & response_body.get(b, set()))
        for a, b in (("hit", "miss"), ("hit", "refused"), ("miss", "refused"))
    )
    return {
        "labelled_searches": len(labelled),
        "matched_exchanges": len(matched),
        "exchanges": labelled,
        "response_body_record_bytes_by_outcome": {
            k: sorted(v) for k, v in sorted(response_body.items())
        },
        "outcomes_separable_by_response_size": sizes_separate,
        "request_body_record_bytes_by_term": {
            k: sorted(v) for k, v in sorted(by_term.items())
        },
        "request_body_minus_term_length": sorted(overhead),
        "observable_request_size_frequency": dict(
            sorted(
                Counter(
                    x["request_record_lengths"][-1]
                    for x in matched
                    if x["status"] == 200
                ).items()
            )
        ),
        "mean_latency_seconds_by_outcome": {
            k: _mean(v) for k, v in sorted(latency.items())
        },
        "median_latency_seconds_by_outcome": {
            k: _median(v) for k, v in sorted(latency.items())
        },
    }


def analyze_search_capture(
    path: Path, *, db_port: int, searches: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Analyze search-related traffic in one real PCAP.

    ``searches`` is the workload's manifest (ADR-0071); it only labels TLS
    exchanges and is never counted as an observation.
    """
    if not path.exists():
        raise FileNotFoundError(f"Capture not found: {path}")

    capture = pyshark.FileCapture(str(path), keep_packets=False, display_filter="tcp")

    events: list[dict[str, Any]] = []
    total_tcp_packets = 0
    total_bytes = 0
    tls_packets = 0
    try:
        for packet in capture:
            total_tcp_packets += 1
            total_bytes += _int(getattr(packet, "length", None)) or 0
            if hasattr(packet, "tls"):
                tls_packets += 1
            event = extract_http_event(packet)
            if event is not None:
                events.append(event)
    finally:
        capture.close()

    summary = summarize_search_leakage(events)
    flows = reassemble(read_segments(path))
    lookups = search_token_lookups(flows, db_port)
    link_queries_to_lookups(summary["queries"], lookups)
    tls_view = (
        summarize_tls_exchanges(
            tls_exchanges_for_lookups(flows, lookups, FACILITY_PORTS), lookups
        )
        if tls_packets and lookups
        else None
    )
    labelled_tls = (
        summarize_labelled_tls(label_tls_exchanges(flows, searches, FACILITY_PORTS))
        if tls_packets and searches
        else None
    )
    return {
        "capture": str(path),
        "total_tcp_packets": total_tcp_packets,
        "total_capture_bytes": total_bytes,
        "http_events": len(events),
        "tls_packets": tls_packets,
        # Over TLS without a key log the observer sees no URIs at all; the
        # profile above then under-reports, and that must be said, not hidden.
        "uris_observable": bool(events),
        "db_port": db_port,
        **summary,
        "database_link_connections": pg_link_status(flows, db_port),
        "database_link": summarize_token_leakage(lookups, summary["queries"]),
        "http_timing": summarize_timing(summary["queries"]),
        "tls_view": tls_view,
        "labelled_tls_view": labelled_tls,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze search leakage from real PyShark PCAP captures."
    )
    parser.add_argument(
        "--capture",
        type=Path,
        required=True,
        help="PCAP containing captured search traffic.",
    )
    parser.add_argument("--json", type=Path, help="Optional output JSON path.")
    parser.add_argument(
        "--db-port",
        type=int,
        default=default_db_port(),
        help="Postgres port whose link carries the token lookups "
        "(default: DATABASE_URL's port)",
    )
    parser.add_argument(
        "--searches",
        type=Path,
        default=None,
        help="the workload's search manifest (<mode>-search.searches.json) to "
        "label TLS exchanges when the store link is encrypted (ADR-0071)",
    )
    args = parser.parse_args()

    searches = (
        json.loads(args.searches.read_text(encoding="utf-8"))["searches"]
        if args.searches
        else None
    )
    result = analyze_search_capture(
        args.capture, db_port=args.db_port, searches=searches
    )

    print("P5-3 Search Leakage Analysis")
    print("=" * 40)
    print(f"Capture                  : {result['capture']}")
    print(f"URIs observable          : {result['uris_observable']}")
    print(f"Query volume             : {result['query_volume']}")
    print(f"Answered queries         : {result['answered_queries']}")
    print(f"Queries visible in clear : {result['queries_visible_in_clear']}")
    print(f"Total TCP packets        : {result['total_tcp_packets']}")
    print(f"TLS packets              : {result['tls_packets']}")

    print("\n[Access pattern by record]")
    for record_id, count in result["access_pattern_by_record"].items():
        print(f"  {record_id}: {count}")

    print("\n[Frequency leakage]")
    if result["repeated_requests"]:
        for uri, count in result["repeated_requests"].items():
            print(f"  {count}x {uri}")
    else:
        print("  No repeated observable search requests.")

    print("\n[Response-size leakage]")
    print(f"  distinct response sizes: {result['distinct_response_sizes']}")
    for count, sizes in result["response_bytes_by_result_count"].items():
        print(f"  result_count={count}: bytes={sizes}")

    print("\n[Timing leakage]")
    if result["inter_query_seconds"]:
        for delta in result["inter_query_seconds"]:
            print(f"  {delta:.6f} s")
    else:
        print("  Insufficient searches for timing comparison.")
    timing = result["http_timing"]
    print(f"  mean hit latency : {timing['mean_hit_latency_seconds']}")
    print(f"  mean miss latency: {timing['mean_miss_latency_seconds']}")
    print(
        f"  median hit / miss: {timing['median_hit_latency_seconds']} / "
        f"{timing['median_miss_latency_seconds']}"
    )

    db = result["database_link"]
    link = result["database_link_connections"]
    print("\n[Database link (token lookups)]")
    print(
        f"  connections: {link['connections']} "
        f"(tls {link['tls']}, plaintext {link['plaintext']})"
    )
    print(f"  lookups: {db['token_lookups']}, distinct: {db['distinct_tokens']}")
    print(f"  token frequency: {list(db['token_frequency'].values())}")
    print(f"  lookups by visible row count: {db['lookups_by_row_count']}")
    if db.get("terms_linked_to_tokens"):
        print(f"  epochs (split at refused searches): {db['epochs']}")
        print(
            "  same term -> same token within an epoch: "
            f"{db['same_term_same_token_within_epoch']}"
        )
        print(
            f"  re-keyed across epochs: {db['terms_rekeyed_across_epochs']} "
            f"of {db['terms_searched_in_several_epochs']}"
        )

    if result["tls_view"] is not None:
        tls_view = result["tls_view"]
        print("\n[TLS view (record sizes around each lookup)]")
        for rows, sizes in tls_view["response_body_record_bytes_by_db_rows"].items():
            print(f"  db rows={rows}: response body record bytes={sizes}")
        print(
            "  request body record bytes: "
            f"{tls_view['distinct_request_body_record_bytes']}"
        )
        for rows, mean in tls_view["mean_latency_seconds_by_db_rows"].items():
            median = tls_view["median_latency_seconds_by_db_rows"][rows]
            print(f"  db rows={rows}: latency mean={mean} median={median}")

    if result["labelled_tls_view"] is not None:
        lab = result["labelled_tls_view"]
        print("\n[TLS view (exchanges labelled by the search manifest)]")
        print(
            f"  matched {lab['matched_exchanges']} of "
            f"{lab['labelled_searches']} searches"
        )
        for outcome, sizes in lab["response_body_record_bytes_by_outcome"].items():
            print(f"  {outcome}: response body record bytes={sizes}")
        print(
            "  request body record - term length: "
            f"{lab['request_body_minus_term_length']}"
        )
        print(
            "  request size frequency seen: "
            f"{lab['observable_request_size_frequency']}"
        )
        for outcome, median in lab["median_latency_seconds_by_outcome"].items():
            print(f"  {outcome}: median latency={median}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nJSON report written to: {args.json}")

    labelled = result["labelled_tls_view"]
    if (
        result["query_volume"] == 0
        and not result["database_link"]["token_lookups"]
        and not (labelled and labelled["matched_exchanges"])
    ):
        print(
            "\nERROR: no search traffic was found in this capture. "
            "P5-3 evidence requires a capture containing real searches."
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
