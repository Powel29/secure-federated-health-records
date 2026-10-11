"""Canary search for the P5-5 "no plaintext on the wire" check (ADR-0045).

The scenario writes every secret it handled to a manifest
(``deploy.run_scenario --canaries-out``). Here each secret is expanded into
every form it could plausibly travel in over our HTTP/JSON APIs, and the
reassembled streams are searched for all of them:

- raw bytes
- hex, lower and upper case (shares travel as ``share_hex``)
- base64, standard and URL-safe, at all three byte alignments -- a secret
  embedded inside a larger base64 blob only matches if the search accounts
  for where it starts within a 3-byte group
- for PEM private keys, each full body line (JSON escapes the newlines, so
  the whole PEM never matches verbatim)

A search that misses an encoding produces a false pass, so the encodings are
unit-tested by planting each one.
"""

from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass
from pathlib import Path

from wire.streams import Flow, FlowKey

# Below this many encoded characters a match could be coincidence.
_MIN_PATTERN_LEN = 16


@dataclass(frozen=True)
class Canary:
    name: str
    cls: str  # "share", "attribute_key", "dek", "emergency_key", "phi", ...
    value: bytes


@dataclass(frozen=True)
class Hit:
    canary: str
    cls: str
    encoding: str
    flow: FlowKey
    offset: int
    frame: int
    timestamp: float


class UnsearchableCanaryError(ValueError):
    """A canary has no encoding long enough to search for (review N9)."""


def load_manifest(path: Path) -> list[Canary]:
    """Load a run's canaries; refuse one that could never be found.

    A canary whose every encoding is under the minimum pattern length would
    be silently skipped by :func:`find_hits` -- a false pass (review N9).
    """
    manifest = json.loads(path.read_text(encoding="utf-8"))
    canaries = [
        Canary(name=name, cls=entry["class"], value=bytes.fromhex(entry["hex"]))
        for name, entry in manifest["canaries"].items()
    ]
    unsearchable = [c.name for c in canaries if not encodings(c)]
    if unsearchable:
        raise UnsearchableCanaryError(
            f"canaries too short to search for: {unsearchable} "
            f"(every encoding is under {_MIN_PATTERN_LEN} characters)"
        )
    return canaries


def _b64_cores(value: bytes, *, urlsafe: bool) -> list[bytes]:
    """Base64 substrings fully determined by ``value`` at each alignment.

    With ``k`` unknown bytes before the secret, encoded character ``i`` covers
    bits ``[6i, 6i+6)``; it depends only on the secret when
    ``6i >= 8k`` and ``6i + 6 <= 8(k + n)``.
    """
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    n = len(value)
    cores = []
    for k in range(3):
        encoded = encode(b"\x00" * k + value + b"\x00" * 2)
        start = math.ceil(8 * k / 6)
        end = (8 * (k + n)) // 6
        cores.append(encoded[start:end])
    return cores


def _pem_lines(value: bytes) -> list[bytes]:
    lines = value.replace(b"\r", b"").split(b"\n")
    return [line for line in lines if line and not line.startswith(b"-----")]


def encodings(canary: Canary) -> list[tuple[str, bytes]]:
    """Every (encoding name, byte pattern) the canary is searched for."""
    value = canary.value
    if value.lstrip().startswith(b"-----BEGIN"):
        patterns = [(f"pem_line_{i}", line) for i, line in enumerate(_pem_lines(value))]
    else:
        patterns = [
            ("raw", value),
            ("hex", value.hex().encode("ascii")),
            ("hex_upper", value.hex().upper().encode("ascii")),
        ]
        for urlsafe, label in ((False, "base64"), (True, "base64url")):
            for k, core in enumerate(_b64_cores(value, urlsafe=urlsafe)):
                patterns.append((f"{label}_align{k}", core))

    seen: set[bytes] = set()
    unique = []
    for label, pattern in patterns:
        if len(pattern) >= _MIN_PATTERN_LEN and pattern not in seen:
            seen.add(pattern)
            unique.append((label, pattern))
    return unique


def find_hits(flows: dict[FlowKey, Flow], canaries: list[Canary]) -> list[Hit]:
    """Every occurrence of every canary encoding in every flow, in time order."""
    hits: list[Hit] = []
    for canary in canaries:
        for label, pattern in encodings(canary):
            for key, flow in flows.items():
                start = flow.data.find(pattern)
                while start != -1:
                    if flow.spans_gap(start, start + len(pattern)):
                        # Bytes either side of a lost segment (review N8).
                        start = flow.data.find(pattern, start + 1)
                        continue
                    frame, ts = flow.locate(start)
                    hits.append(
                        Hit(canary.name, canary.cls, label, key, start, frame, ts)
                    )
                    start = flow.data.find(pattern, start + 1)
    hits.sort(key=lambda h: (h.timestamp, h.frame, h.offset))
    return hits
