"""The four P5-5 wire-level claims as automatic checks (PROJECT.md §4A, ADR-0045).

Each check takes the reassembled plain and TLS captures and returns a
:class:`ClaimResult`: pass/fail, how strong the evidence is, and the frames it
rests on. Nothing warns and carries on -- the entry point exits non-zero if any
claim fails.

1. **No plaintext on the wire.** Every secret the scenario handled is searched
   for in every encoding (:mod:`wire.canaries`), and JSON bodies are checked
   against a denylist of key-carrying fields (review F18). The *scope* is the
   open team decision D6:

   - ``all`` (default): neither capture may expose a secret. This fails today,
     because the plain profile carries keys, shares and plaintext in bodies --
     the review's point is that the analyser must say so.
   - ``tls`` (D6-b): only the TLS capture must be clean; the plain capture then
     serves as the positive control proving the detector fires.

2. **Commit-before-release.** In the plain capture, the audit service's
   Postgres ``COMMIT`` for the release entry crosses the wire before the
   ``/breakglass/release`` response that carries share 3, and share 3 never
   appears outside custody setup before that response.
3. **Search leakage.** The P5-3 profile, computed from the same capture.
4. **Break-glass is metadata, not content.** The break-glass URI is visible in
   plain mode; in TLS mode an observer can still pick out the exchange from
   ports and sizes alone (validated against the plain capture), yet no share,
   emergency key or DEK is readable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from wire.analyze_search_leakage import summarize_search_leakage
from wire.canaries import Canary, Hit, find_hits
from wire.http_messages import Exchange, HttpMessage, pair_exchanges
from wire.streams import Flow, FlowKey, Segment, reassemble, server_port

SECRET_CLASSES = frozenset(
    {"share", "attribute_key", "dek", "emergency_key", "phi", "private_key"}
)
BREAKGLASS_CLASSES = frozenset({"share", "emergency_key", "dek"})
POSITIVE_CONTROL_CLASSES = frozenset({"share", "attribute_key"})

# JSON fields that carry key material or plaintext (review F18).
DENYLISTED_JSON_KEYS = frozenset(
    {
        "plaintext_b64",
        "emergency_key_b64",
        "share_hex",
        "key_b64",
        "holder_keyring",
        "attribute_keyring",
        "old_dek_b64",
    }
)
DENYLISTED_JSON_SUFFIXES = ("_signing_key_pem",)

CLAIM1_SCOPES = ("all", "tls")

RELEASE_PATH = "/breakglass/release"
CUSTODY_PATH = "/breakglass/shares"
DEFAULT_DB_PORT = 5432
# Postgres CommandComplete for COMMIT: 'C', int32 length 11, "COMMIT\0".
PG_COMMIT_COMPLETE = b"C\x00\x00\x00\x0bCOMMIT\x00"


@dataclass
class Capture:
    """One reassembled capture plus the secrets of the run it recorded."""

    mode: str  # "plain" or "tls"
    segments: list[Segment]
    canaries: list[Canary]
    ports: dict[str, int]  # HTTP service name -> port
    db_port: int = DEFAULT_DB_PORT
    flows: dict[FlowKey, Flow] = field(init=False)
    hits: list[Hit] = field(init=False)
    exchanges: list[Exchange] = field(init=False)

    def __post_init__(self) -> None:
        self.flows = reassemble(self.segments)
        self.hits = find_hits(self.flows, self.canaries)
        http_flows = {
            k: f
            for k, f in self.flows.items()
            if server_port(k, self.service_ports) is not None
        }
        self.exchanges = pair_exchanges(http_flows)

    @property
    def service_ports(self) -> set[int]:
        return set(self.ports.values())


@dataclass
class ClaimResult:
    claim: str
    passed: bool
    strength: str  # "strong", "metadata-only" or "measurement"
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)


def _hit_summary(hits: list[Hit]) -> dict[str, list[str]]:
    by_canary: dict[str, set[str]] = {}
    for hit in hits:
        by_canary.setdefault(hit.canary, set()).add(hit.encoding)
    return {name: sorted(encs) for name, encs in sorted(by_canary.items())}


def _contains(msg: HttpMessage, hit: Hit) -> bool:
    return hit.flow == msg.flow and msg.start <= hit.offset < msg.end


def _denylisted_keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, inner in value.items():
            if key in DENYLISTED_JSON_KEYS or key.endswith(DENYLISTED_JSON_SUFFIXES):
                found.add(key)
            found |= _denylisted_keys(inner)
    elif isinstance(value, list):
        for inner in value:
            found |= _denylisted_keys(inner)
    return found


def denylisted_fields(capture: Capture) -> dict[str, list[str]]:
    """``"METHOD path [req|resp]" -> sorted denylisted keys`` seen in clear."""
    found: dict[str, set[str]] = {}
    for ex in capture.exchanges:
        for msg, side in ((ex.request, "req"), (ex.response, "resp")):
            if msg is None:
                continue
            keys = _denylisted_keys(msg.json())
            if keys:
                label = f"{ex.request.method} {ex.request.path} [{side}]"
                found.setdefault(label, set()).update(keys)
    return {label: sorted(keys) for label, keys in sorted(found.items())}


# ---------------------------------------------------------------------------
# Claim 1
# ---------------------------------------------------------------------------


def check_no_plaintext(plain: Capture, tls: Capture, scope: str = "all") -> ClaimResult:
    if scope not in CLAIM1_SCOPES:
        raise ValueError(f"claim-1 scope must be one of {CLAIM1_SCOPES}")

    plain_hits = [h for h in plain.hits if h.cls in SECRET_CLASSES]
    tls_hits = [h for h in tls.hits if h.cls in SECRET_CLASSES]
    plain_fields = denylisted_fields(plain)
    evidence: dict[str, Any] = {
        "scope": scope,
        "tls_hits": _hit_summary(tls_hits),
        "plain_hits": _hit_summary(plain_hits),
        "plain_denylisted_fields": plain_fields,
        "canaries_searched": {"plain": len(plain.canaries), "tls": len(tls.canaries)},
    }

    if tls_hits:
        return ClaimResult(
            "1-no-plaintext",
            False,
            "strong",
            f"{len(tls_hits)} secret occurrence(s) readable in the TLS capture",
            evidence,
        )

    if scope == "all":
        if plain_hits or plain_fields:
            return ClaimResult(
                "1-no-plaintext",
                False,
                "strong",
                f"plain profile exposes {len(_hit_summary(plain_hits))} secret(s) "
                f"and denylisted fields in {len(plain_fields)} message type(s); "
                "TLS capture is clean. Claim holds only if narrowed to TLS "
                "(decision D6) -- rerun with --claim1-scope tls once decided",
                evidence,
            )
        return ClaimResult(
            "1-no-plaintext",
            True,
            "strong",
            "no secret readable in either the plain or the TLS capture",
            evidence,
        )

    control = {h.cls for h in plain_hits} & POSITIVE_CONTROL_CLASSES
    evidence["positive_control_fired"] = control == POSITIVE_CONTROL_CLASSES
    if control != POSITIVE_CONTROL_CLASSES:
        missing = sorted(POSITIVE_CONTROL_CLASSES - control)
        return ClaimResult(
            "1-no-plaintext",
            False,
            "strong",
            f"positive control failed: detector found no {missing} in the plain "
            "capture, so a clean TLS result cannot be trusted",
            evidence,
        )
    return ClaimResult(
        "1-no-plaintext",
        True,
        "strong",
        f"scope tls (D6-b): no secret of {len(tls.canaries)} canaries readable "
        "under TLS; the same detector finds them in the plain capture",
        evidence,
    )


# ---------------------------------------------------------------------------
# Claim 2
# ---------------------------------------------------------------------------


def _db_commit_after(
    capture: Capture, marker: bytes, before_ts: float
) -> tuple[float, float] | None:
    """Timestamps of the release INSERT and the COMMIT that answers it.

    ``marker`` is the release entry's ``event_type``: psycopg sends it as a
    text parameter, so it is visible in the client-to-Postgres stream whether
    or not the statement has been prepared. The COMMIT is the first
    CommandComplete("COMMIT") from the server on the same connection after it.
    """
    for key, flow in capture.flows.items():
        if key.dst_port != capture.db_port:
            continue
        positions = []
        pos = flow.data.find(marker)
        while pos != -1:
            positions.append(flow.locate(pos)[1])
            pos = flow.data.find(marker, pos + 1)
        inserts = [ts for ts in positions if ts <= before_ts]
        if not inserts:
            continue
        insert_ts = inserts[-1]
        reverse = capture.flows.get(FlowKey(key.stream, key.dst_port, key.src_port))
        if reverse is None:
            continue
        pos = reverse.data.find(PG_COMMIT_COMPLETE)
        while pos != -1:
            commit_ts = reverse.locate(pos)[1]
            if commit_ts >= insert_ts:
                return insert_ts, commit_ts
            pos = reverse.data.find(PG_COMMIT_COMPLETE, pos + 1)
    return None


def check_commit_before_release(plain: Capture) -> ClaimResult:
    name = "2-commit-before-release"
    audit_port = plain.ports["audit"]
    release = next(
        (
            ex
            for ex in plain.exchanges
            if ex.request.path == RELEASE_PATH
            and ex.request.flow.dst_port == audit_port
        ),
        None,
    )
    if release is None or release.response is None:
        return ClaimResult(
            name, False, "strong", "no answered /breakglass/release exchange"
        )
    resp = release.response
    body = resp.json()
    entry = body.get("entry") if isinstance(body, dict) else None
    if resp.status != 200 or not isinstance(entry, dict):
        return ClaimResult(
            name,
            False,
            "strong",
            "release response carries no committed audit entry",
            {"status": resp.status},
        )

    custody = [ex.request for ex in plain.exchanges if ex.request.path == CUSTODY_PATH]
    share3 = [
        h
        for h in plain.hits
        if h.canary == "share3" and not any(_contains(req, h) for req in custody)
    ]
    if not share3:
        return ClaimResult(
            name, False, "strong", "share 3 never observed outside custody setup"
        )
    first = share3[0]
    if not _contains(resp, first):
        return ClaimResult(
            name,
            False,
            "strong",
            f"share 3 crossed the wire at frame {first.frame}, before the release "
            f"response at frame {resp.frame}",
            {"first_share3_frame": first.frame, "release_response_frame": resp.frame},
        )

    request_body = release.request.json()
    event_type = (
        request_body.get("event_type") if isinstance(request_body, dict) else None
    )
    if not isinstance(event_type, str) or not event_type:
        return ClaimResult(
            name, False, "strong", "release request names no event_type to trace"
        )
    db = _db_commit_after(plain, event_type.encode("utf-8"), resp.timestamp)
    evidence = {
        "release_response_frame": resp.frame,
        "release_entry_seq": entry.get("seq"),
        "first_share3_frame": first.frame,
        "db_port": plain.db_port,
    }
    if db is None:
        return ClaimResult(
            name,
            False,
            "strong",
            f"no Postgres INSERT+COMMIT for {event_type!r} before the release "
            f"response; capture must include the DB port ({plain.db_port}) "
            "unencrypted",
            evidence,
        )
    insert_ts, commit_ts = db
    evidence |= {"db_insert_ts": insert_ts, "db_commit_ts": commit_ts}
    if commit_ts > resp.timestamp:
        return ClaimResult(
            name,
            False,
            "strong",
            "release response left before the audit COMMIT was acknowledged",
            evidence,
        )
    lead_ms = (resp.timestamp - commit_ts) * 1000
    evidence["commit_lead_ms"] = lead_ms
    return ClaimResult(
        name,
        True,
        "strong",
        f"audit COMMIT acknowledged {lead_ms:.2f} ms before the release response; "
        "share 3 first appears inside that response",
        evidence,
    )


# ---------------------------------------------------------------------------
# Claim 3
# ---------------------------------------------------------------------------


def _events_from_exchanges(exchanges: list[Exchange]) -> list[dict[str, Any]]:
    events = []
    for ex in exchanges:
        req = ex.request
        events.append(
            {
                "kind": "request",
                "frame": req.frame,
                "timestamp": req.timestamp,
                "frame_bytes": 0,
                "content_length": len(req.body),
                "body": req.body.decode("utf-8", "replace") or None,
                "method": req.method,
                "uri": req.path,
                "host": req.headers.get("host", ""),
            }
        )
        if ex.response is not None:
            resp = ex.response
            events.append(
                {
                    "kind": "response",
                    "frame": resp.frame,
                    "timestamp": resp.timestamp,
                    "frame_bytes": 0,
                    "content_length": len(resp.body),
                    "body": resp.body.decode("utf-8", "replace") or None,
                    "status": resp.status,
                    "request_frame": req.frame,
                    "uri": req.path,
                }
            )
    return events


def search_leakage_rows(plain: Capture) -> list[dict[str, Any]]:
    """One CSV row per search, with the query hashed, never stored."""
    rows = []
    for ex in plain.exchanges:
        if not ex.request.path.endswith(("/search", "/emergency-search")):
            continue
        body = ex.request.json()
        query = ""
        if isinstance(body, dict):
            query = str(body.get("search_term") or body.get("token") or "")
        resp_body = ex.response.json() if ex.response else None
        rows.append(
            {
                "frame": ex.request.frame,
                "timestamp": ex.request.timestamp,
                "path": ex.request.path,
                "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "request_bytes": len(ex.request.body),
                "response_status": ex.response.status if ex.response else "",
                "response_bytes": len(ex.response.body) if ex.response else "",
                "result_count": (
                    resp_body.get("record_count") if isinstance(resp_body, dict) else ""
                ),
            }
        )
    return rows


def check_search_leakage(plain: Capture) -> ClaimResult:
    profile = summarize_search_leakage(_events_from_exchanges(plain.exchanges))
    rows = search_leakage_rows(plain)
    query_counts: dict[str, int] = {}
    for row in rows:
        query_counts[row["query_sha256"]] = query_counts.get(row["query_sha256"], 0) + 1
    evidence = {
        "profile": {k: v for k, v in profile.items() if k != "queries"},
        "repeated_query_hashes": {h: n for h, n in query_counts.items() if n > 1},
        "rows": rows,
    }
    if not rows:
        return ClaimResult(
            "3-search-leakage",
            False,
            "measurement",
            "no search traffic in the plain capture; leakage not measured",
            evidence,
        )
    return ClaimResult(
        "3-search-leakage",
        True,
        "measurement",
        f"{len(rows)} search(es) measured: access pattern, volume, response "
        "sizes, result counts and timing (leakage is a result, not a failure)",
        evidence,
    )


# ---------------------------------------------------------------------------
# Claim 4
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Burst:
    """Consecutive payload segments in one direction of one connection."""

    stream: int
    client_to_server: bool
    port: int
    size: int
    first_frame: int
    first_ts: float
    last_ts: float


def bursts(capture: Capture) -> list[Burst]:
    ports = capture.service_ports
    by_stream: dict[int, list[Segment]] = {}
    for seg in capture.segments:
        if seg.payload:
            by_stream.setdefault(seg.stream, []).append(seg)

    def close(stream: int, run: list[Segment]) -> Burst | None:
        first = run[0]
        port = server_port(FlowKey(stream, first.src_port, first.dst_port), ports)
        if port is None:
            return None
        return Burst(
            stream=stream,
            client_to_server=first.dst_port in ports,
            port=port,
            size=sum(len(s.payload) for s in run),
            first_frame=first.frame,
            first_ts=first.timestamp,
            last_ts=run[-1].timestamp,
        )

    result: list[Burst] = []
    for stream, segs in by_stream.items():
        segs.sort(key=lambda s: s.frame)
        run: list[Segment] = [segs[0]]
        for seg in segs[1:]:
            if seg.dst_port == run[0].dst_port:
                run.append(seg)
                continue
            burst = close(stream, run)
            if burst is not None:
                result.append(burst)
            run = [seg]
        burst = close(stream, run)
        if burst is not None:
            result.append(burst)
    result.sort(key=lambda b: (b.first_ts, b.first_frame))
    return result


def identify_breakglass(capture: Capture) -> Burst | None:
    """The unlock request, from ports and sizes alone.

    It carries an assertion, three certificates and the shares, so it is the
    largest client-to-facility-b burst in the scenario.
    """
    fb_port = capture.ports["facility-b"]
    requests = [b for b in bursts(capture) if b.client_to_server and b.port == fb_port]
    return max(requests, key=lambda b: b.size) if requests else None


def _breakglass_request(capture: Capture) -> HttpMessage | None:
    for ex in capture.exchanges:
        if ex.request.method == "POST" and ex.request.path.endswith("/breakglass"):
            return ex.request
    return None


def check_breakglass_metadata_only(
    plain: Capture, tls: Capture, scope: str = "all"
) -> ClaimResult:
    name = "4-breakglass-metadata-only"
    request = _breakglass_request(plain)
    if request is None:
        return ClaimResult(
            name, False, "strong", "no break-glass request visible in plain mode"
        )

    plain_pick = identify_breakglass(plain)
    validated = plain_pick is not None and plain_pick.first_frame == request.frame
    tls_pick = identify_breakglass(tls)

    content_hits = [h for h in tls.hits if h.cls in BREAKGLASS_CLASSES]
    if scope == "all":
        content_hits += [h for h in plain.hits if h.cls in BREAKGLASS_CLASSES]
    evidence = {
        "scope": scope,
        "plain_breakglass_uri": request.path,
        "metadata_pick_validated_on_plain": validated,
        "tls_unlock_burst": (
            {"frame": tls_pick.first_frame, "bytes": tls_pick.size}
            if tls_pick
            else None
        ),
        "breakglass_content_hits": _hit_summary(content_hits),
    }
    if not validated or tls_pick is None:
        return ClaimResult(
            name,
            False,
            "metadata-only",
            "the size/port heuristic does not pick the unlock request in plain "
            "mode, so the TLS identification cannot be trusted",
            evidence,
        )
    if content_hits:
        return ClaimResult(
            name,
            False,
            "strong",
            f"break-glass secrets readable ({len(_hit_summary(content_hits))} "
            f"canaries, scope {scope})",
            evidence,
        )
    return ClaimResult(
        name,
        True,
        "strong",
        f"break-glass visible as metadata ({request.path} in plain; a "
        f"{tls_pick.size}-byte unlock burst under TLS) with no share, emergency "
        "key or DEK readable",
        evidence,
    )


def run_all(plain: Capture, tls: Capture, scope: str = "all") -> list[ClaimResult]:
    return [
        check_no_plaintext(plain, tls, scope),
        check_commit_before_release(plain),
        check_search_leakage(plain),
        check_breakglass_metadata_only(plain, tls, scope),
    ]
