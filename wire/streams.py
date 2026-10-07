"""TCP stream reassembly for the P5-5 wire checks (ADR-0045).

A secret split across two TCP segments is invisible to a per-packet search,
which would turn a leak into a false pass. Every check therefore runs on
reassembled byte streams: one per (TCP stream, direction), in sequence order,
with an index that maps any byte offset back to the frame and timestamp that
carried it -- claim 2 needs to know *when* a value first crossed the wire.

Reassembly is a pure function over :class:`Segment` values so it is testable
without tshark; :func:`read_segments` is the only PyShark-dependent part.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Segment:
    """One TCP segment that carried payload."""

    frame: int
    timestamp: float
    stream: int
    src_port: int
    dst_port: int
    seq: int  # relative sequence number of the first payload byte
    payload: bytes


@dataclass(frozen=True)
class FlowKey:
    """One direction of one TCP connection."""

    stream: int
    src_port: int
    dst_port: int


@dataclass
class Flow:
    """The reassembled bytes of one direction of one TCP connection."""

    key: FlowKey
    data: bytes = b""
    # Parallel lists: offsets[i] is where the bytes of frames[i] start in data.
    offsets: list[int] = field(default_factory=list)
    frames: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)

    def locate(self, offset: int) -> tuple[int, float]:
        """Frame number and timestamp of the segment holding byte ``offset``."""
        if not self.offsets or offset < 0 or offset >= len(self.data):
            raise IndexError(f"offset {offset} outside flow {self.key}")
        i = bisect.bisect_right(self.offsets, offset) - 1
        return self.frames[i], self.timestamps[i]

    @property
    def start_timestamp(self) -> float:
        return self.timestamps[0]


def reassemble(segments: list[Segment]) -> dict[FlowKey, Flow]:
    """Group segments into flows and stitch each in sequence order.

    Retransmitted or overlapping segments contribute only bytes not already
    covered, so a retransmission never duplicates data. A gap (lost segment)
    is left as a gap: bytes are appended in order and the hole is simply
    absent, which can only hide a match, never invent one.
    """
    grouped: dict[FlowKey, list[Segment]] = defaultdict(list)
    for seg in segments:
        if seg.payload:
            grouped[FlowKey(seg.stream, seg.src_port, seg.dst_port)].append(seg)

    flows: dict[FlowKey, Flow] = {}
    for key, segs in grouped.items():
        segs.sort(key=lambda s: (s.seq, s.frame))
        flow = Flow(key=key)
        chunks: list[bytes] = []
        length = 0
        covered_to: int | None = None  # next expected sequence number
        for seg in segs:
            start, end = seg.seq, seg.seq + len(seg.payload)
            if covered_to is not None and end <= covered_to:
                continue  # pure retransmission
            skip = 0 if covered_to is None else max(0, covered_to - start)
            piece = seg.payload[skip:]
            flow.offsets.append(length)
            flow.frames.append(seg.frame)
            flow.timestamps.append(seg.timestamp)
            chunks.append(piece)
            length += len(piece)
            covered_to = end
        flow.data = b"".join(chunks)
        flows[key] = flow
    return flows


def server_port(key: FlowKey, service_ports: set[int]) -> int | None:
    """The federation service port this flow talks to, if any."""
    if key.dst_port in service_ports:
        return key.dst_port
    if key.src_port in service_ports:
        return key.src_port
    return None


def is_client_to_server(key: FlowKey, service_ports: set[int]) -> bool:
    return key.dst_port in service_ports


def read_segments(path: Path) -> list[Segment]:
    """Extract every payload-carrying TCP segment from a pcap via PyShark."""
    import pyshark  # deferred: only the live path needs tshark

    if not path.exists():
        raise FileNotFoundError(f"Capture not found: {path}")

    capture = pyshark.FileCapture(
        str(path), keep_packets=False, display_filter="tcp.len > 0"
    )
    segments: list[Segment] = []
    try:
        for packet in capture:
            tcp = packet.tcp
            raw = str(getattr(tcp, "payload", "")).replace(":", "")
            if not raw:
                continue
            segments.append(
                Segment(
                    frame=int(packet.number),
                    timestamp=float(packet.sniff_timestamp),
                    stream=int(tcp.stream),
                    src_port=int(tcp.srcport),
                    dst_port=int(tcp.dstport),
                    seq=int(tcp.seq),
                    payload=bytes.fromhex(raw),
                )
            )
    finally:
        capture.close()
    return segments
