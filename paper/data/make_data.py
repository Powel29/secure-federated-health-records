"""Copy benchmark rows into pgfplots-ready CSVs for the paper (F7).

Reads bench/results/benchmark_summary.csv and bench/results/benchmark_results.csv
and writes paper/data/latency.csv and paper/data/expansion.csv. Values are
copied as the exact strings in the source files: no rounding, no unit change
(the source is already in milliseconds), nothing retyped.

    python paper/data/make_data.py
"""

from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "bench" / "results"
OUT = Path(__file__).resolve().parent


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_latency() -> int:
    rows = _rows(RESULTS / "benchmark_summary.csv")
    with (OUT / "latency.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["operation", "median_ms", "p95_ms", "n", "warmup"])
        for r in rows:
            if r["metric"] != "latency_ms":
                raise SystemExit(f"unexpected metric {r['metric']!r} in summary")
            w.writerow(
                [r["benchmark"], r["median_ms"], r["p95_ms"], r["iterations"], r["warmup"]]
            )
    return len(rows)


def write_expansion() -> int:
    rows = [
        r
        for r in _rows(RESULTS / "benchmark_results.csv")
        if r["benchmark"] == "ciphertext_expansion"
    ]
    with (OUT / "expansion.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["plaintext_bytes", "ciphertext_bytes", "expansion_percent"])
        for r in rows:
            w.writerow([r["plaintext_bytes"], r["ciphertext_bytes"], r["expansion_percent"]])
    return len(rows)


if __name__ == "__main__":
    print(f"latency.csv: {write_latency()} rows")
    print(f"expansion.csv: {write_expansion()} rows")
