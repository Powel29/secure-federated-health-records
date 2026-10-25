"""P5-2 benchmark harness.

One command regenerates every number, the environment record and the plots:

    python -m bench.run_benchmarks            # needs DATABASE_URL / Postgres
    python -m bench.run_benchmarks --no-db    # crypto-only subset

Each benchmark discards ``--warmup`` runs, then times ``--iterations`` runs and
reports median and p95 (benchmark-methodology skill). Raw per-run samples go to
``bench/results/raw/`` (gitignored); the summary, environment and plots are
committed.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import json
import os
import platform
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import matplotlib.pyplot as plt
import pandas as pd
import psycopg
from api.share_transport import fetch_share_recipient, sealed_json
from audit.chain import verify_full_chain
from breakglass.emergency_key import THRESHOLD, TOTAL_SHARES
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import (
    certificate_from_pem,
    generate_ec_keypair,
    public_key_from_pem,
)
from crypto_core.symmetric import generate_key
from lifecycle.state_machine import create_transition_event
from pre.elgamal import encapsulate_key, generate_keypair, generate_rekey, reencrypt
from records.ingest import ingest_record
from records.revocation import revoke_record_access
from records.service import encrypt_record, rewrap_dek, wrap_dek
from shamir.split import combine_shares, split_secret

from demo.driver import standalone_federation
from demo.seed_data import create_synthetic_dataset, seed_synthetic_data
from deploy.run_scenario import emergency_open

DEFAULT_ITERATIONS = 30
DEFAULT_WARMUP = 5
RESULTS_DIR = Path(__file__).resolve().parent / "results"
RAW_DIR = RESULTS_DIR / "raw"

Row = dict[str, Any]

# Per-run samples, keyed by benchmark name, for the raw CSV and the box plot.
SAMPLES: dict[str, list[float]] = {}

# Set from --warmup in main().
WARMUP = DEFAULT_WARMUP


def _p95(values: list[float]) -> float:
    if len(values) < 2:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[94]


def timed_call(
    func: Callable[[], object], iterations: int, name: str
) -> dict[str, float]:
    for _ in range(WARMUP):
        func()

    values = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        values.append((time.perf_counter() - start) * 1000)

    SAMPLES[name] = values
    return {
        "median_ms": statistics.median(values),
        "p95_ms": _p95(values),
        "mean_ms": statistics.mean(values),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def make_row(
    benchmark: str,
    result: dict[str, float],
    iterations: int,
    parameters: str = "",
    **extra: object,
) -> Row:
    return {
        "benchmark": benchmark,
        "metric": "latency_ms",
        "iterations": iterations,
        "warmup": WARMUP,
        "parameters": parameters,
        **result,
        **extra,
    }


def _ram_gb() -> float | None:
    """Total physical RAM without adding a dependency; None if unknown."""
    try:
        if sys.platform == "win32":

            class _MemStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = _MemStatus()
            status.dwLength = ctypes.sizeof(_MemStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
            return round(status.ullTotalPhys / 2**30, 1)
        pages = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        return round(pages / 2**30, 1)
    except (AttributeError, OSError, ValueError):
        return None


def environment(deployment_path: str) -> dict[str, object]:
    return {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "cpu": platform.processor() or platform.machine(),
        "cores": os.cpu_count(),
        "ram_gb": _ram_gb(),
        "python": sys.version.split()[0],
        "os": platform.platform(),
        "deployment_path": deployment_path,
    }


# ---------------------------------------------------------------------------
# 1. Threshold reconstruction
# ---------------------------------------------------------------------------


def benchmark_threshold(iterations: int) -> Row:
    secret = b"benchmark-secret-for-phase5-task2"

    # The deployed access structure (ADR-0089), not a hard-coded k and n.
    shares = split_secret(secret, k=THRESHOLD, n=TOTAL_SHARES)
    threshold_shares = shares[:THRESHOLD]

    def operation() -> None:
        recovered = combine_shares(threshold_shares, k=THRESHOLD)
        if recovered != secret:
            raise RuntimeError("Threshold reconstruction failed")

    return make_row(
        "threshold_reconstruction",
        timed_call(operation, iterations, "threshold_reconstruction"),
        iterations,
        f"Shamir k={THRESHOLD},n={TOTAL_SHARES}",
    )


# ---------------------------------------------------------------------------
# 2. Re-wrap cost
# ---------------------------------------------------------------------------


def benchmark_rewrap(iterations: int) -> Row:
    record, dek = encrypt_record(
        plaintext=b"benchmark health record " * 20,
        patient_id="patient-benchmark",
        facility_id="facility-a",
        policy_id="policy-benchmark",
    )

    old_key = generate_key(32)
    new_key = generate_key(32)

    wrapping = wrap_dek(
        dek=dek,
        record_id=record.record_id,
        wrapping_key=old_key,
        wrapped_for="facility-a",
    )

    def operation() -> None:
        result = rewrap_dek(
            wrapping=wrapping,
            old_wrapping_key=old_key,
            new_wrapping_key=new_key,
            new_wrapped_for="facility-b",
        )

        if result.wrapped_for != "facility-b":
            raise RuntimeError("Re-wrap failed")

    return make_row(
        "rewrap_cost",
        timed_call(operation, iterations, "rewrap_cost"),
        iterations,
        "AES-256-GCM unwrap + wrap",
    )


# ---------------------------------------------------------------------------
# 3. Revocation latency
# ---------------------------------------------------------------------------


def benchmark_revocation(iterations: int) -> Row:
    patient_id = "bench-revocation-patient"
    plaintext = b"benchmark clinical record"

    med, net = _make_authorities()

    clinical = _make_clinical_policy()
    keyring = {
        ("authority-med", "role", "physician"): med.attribute_key("role", "physician"),
        ("authority-net", "specialty", "cardiology"): net.attribute_key(
            "specialty", "cardiology"
        ),
        ("authority-net", "owner", patient_id): net.attribute_key("owner", patient_id),
    }

    def fresh_record() -> Any:
        return ingest_record(
            plaintext=plaintext,
            patient_id=patient_id,
            facility_id="facility-a",
            owner_authority_id="authority-net",
            clinical_policy=clinical,
            attribute_keyring=keyring,
            record_id="bench-revocation-record",
        )

    ingested = fresh_record()

    # The patient's custodian signs the event before the facility rotates
    # (review D6), so signing is setup here; verifying it is timed.
    signing_key, public_key = generate_ec_keypair()
    event = create_transition_event(
        record_id=ingested.record.record_id,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id=patient_id,
        signing_key=signing_key,
    )

    def operation() -> None:
        revoke_record_access(
            current_record=ingested.record,
            current_wrapping=ingested.dek_wrapping,
            current_compiled_policy=ingested.compiled_policy,
            new_clinical_policy=clinical,
            owner_authority_id="authority-net",
            attribute_keyring=keyring,
            transition_event=event,
            actor_public_key=public_key,
            correlation_id=f"bench-revocation-{time.perf_counter_ns()}",
        )

    return make_row(
        "revocation_latency",
        timed_call(operation, iterations, "revocation_latency"),
        iterations,
        "event verification + DEK unwrap and rotation + policy recompilation",
    )


def _make_authorities() -> tuple[Any, Any]:
    from authority.issuance import generate_authority

    med = generate_authority(
        "authority-med",
        frozenset({"role"}),
    )

    net = generate_authority(
        "authority-net",
        frozenset({"specialty", "owner"}),
    )

    return med, net


def _make_clinical_policy() -> Any:
    from contracts import Attribute
    from contracts.enums import PolicyNodeType
    from contracts.policy import PolicyTree

    return PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(
                    name="role",
                    value="physician",
                ),
                authority_id="authority-med",
            ),
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(
                    name="specialty",
                    value="cardiology",
                ),
                authority_id="authority-net",
            ),
        ),
    )


# ---------------------------------------------------------------------------
# 4. PRE component used by emergency re-wrap
# ---------------------------------------------------------------------------


def benchmark_pre(iterations: int) -> Row:
    sk_a, pk_a = generate_keypair()
    sk_b, _ = generate_keypair()

    ciphertext, _ = encapsulate_key(pk_a)
    c1, c2 = ciphertext

    rekey = generate_rekey(sk_a, sk_b)

    def operation() -> None:
        reencrypt(rekey, c1, c2)

    return make_row(
        "pre_reencryption_component",
        timed_call(operation, iterations, "pre_reencryption_component"),
        iterations,
        "ElGamal PRE",
    )


# ---------------------------------------------------------------------------
# 5. Ciphertext expansion
# ---------------------------------------------------------------------------


def benchmark_ciphertext_expansion() -> list[Row]:
    rows = []

    for size in [64, 256, 1024, 4096, 16384]:
        plaintext = b"A" * size

        record, _ = encrypt_record(
            plaintext=plaintext,
            patient_id="patient-benchmark",
            facility_id="facility-a",
            policy_id="policy-benchmark",
        )

        ciphertext_size = len(record.ciphertext)
        expansion = (ciphertext_size - size) / size * 100

        rows.append(
            {
                "benchmark": "ciphertext_expansion",
                "metric": "expansion_percent",
                "iterations": 1,
                "parameters": f"plaintext_bytes={size}",
                "mean_ms": "",
                "median_ms": "",
                "p95_ms": "",
                "min_ms": "",
                "max_ms": "",
                "plaintext_bytes": size,
                "ciphertext_bytes": ciphertext_size,
                "expansion_percent": expansion,
            }
        )

    return rows


# ---------------------------------------------------------------------------
# 6. DB-backed benchmarks
# ---------------------------------------------------------------------------


def run_db_benchmarks(iterations: int, database_url: str) -> list[Row]:
    rows = []

    print("\nStarting real federation benchmark setup...")

    with standalone_federation(
        database_url=database_url,
        default_duration=30.0,
    ) as federation:

        endpoints = federation["endpoints"]
        config = federation["config"]

        print("Seeding synthetic federation data...")

        # Every request is signed as bootstrap (ADR-0066).
        client: httpx.Client = federation["client"]
        seeded = seed_synthetic_data(
            endpoints=endpoints,
            config=config,
            dataset=create_synthetic_dataset(),
            client=client,
            database_url=database_url,
            verbose=False,
        )
        # Share 1 in clinician custody, so an expiry can rotate it (ADR-0069),
        # sealed to the custodian's verified share key (ADR-0079).
        root = certificate_from_pem(seeded["root_cert_pem"].encode("ascii"))
        custodian = fetch_share_recipient(
            client, endpoints.custodian, kind="custodian", trusted_root=root
        )
        for record_id, meta in seeded["records"].items():
            client.post(
                f"{endpoints.custodian}/records/{record_id}/shares",
                json={
                    "sealed_share": sealed_json(
                        meta["share1"], record_id=record_id, recipient=custodian
                    )
                },
            ).raise_for_status()

        # ---------------------------------------------------------------
        # Cross-facility latency
        # ---------------------------------------------------------------

        def discovery_operation() -> None:
            response = client.get(f"{endpoints.facility_b}/patients/pat-101/records")
            response.raise_for_status()

            if response.json()["record_count"] < 1:
                raise RuntimeError("Cross-facility discovery returned no records")

        result = timed_call(
            discovery_operation,
            iterations,
            "cross_facility_latency",
        )

        rows.append(
            make_row(
                "cross_facility_latency",
                result,
                iterations,
                "facility-b HTTP discovery for patient pat-101",
            )
        )

        # ---------------------------------------------------------------
        # Emergency search
        # ---------------------------------------------------------------
        #
        # The seeded emergency session is opened through the real
        # breakglass endpoint first. The resulting active session is then
        # measured through the real emergency-search endpoint.
        # ---------------------------------------------------------------

        record_info = seeded["records"]["rec-001"]
        clinician = seeded["clinicians"]["doc-201"]

        # rec-001 carries patient-signed "hospital" labels, so the facility
        # needs a clinical justification bound into the signed assertion
        # (ADR-0064), and the open transition signed by the clinician
        # (ADR-0068).
        justification = (
            "Unconscious patient requires urgent allergy and medication review."
        )
        assertion, transition_event = emergency_open(
            client,
            facility_url=endpoints.facility_b,
            record_id="rec-001",
            patient_id="pat-101",
            clinician_id="doc-201",
            facility_id="facility-b",
            clinician_key=clinician["private_key"],
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            justification=justification,
            ttl=dt.timedelta(minutes=5),
        )

        # Present a three-share unlock set (custodian x=1, audit x=3 and x=4;
        # ADR-0089) from the seeded shares, sealed to the facility's gate
        # (ADR-0079).
        gate = fetch_share_recipient(
            client, endpoints.facility_b, kind="facility", trusted_root=root
        )
        shares_payload = [
            sealed_json(record_info[name], record_id="rec-001", recipient=gate)
            for name in ("share1", "share3", "share4")
        ]

        unlock_payload = {
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": clinician["certificate_pem"],
            "sealed_shares": shares_payload,
            "pre_rewrap_key": clinician["pre_public_key"],
            "transition_event": transition_event.model_dump(mode="json"),
            "correlation_id": "bench-emergency-search",
            "justification": justification,
            "emergency_duration_seconds": 60.0,
        }

        unlock_response = client.post(
            f"{endpoints.facility_b}/records/rec-001/breakglass",
            json=unlock_payload,
        )
        unlock_response.raise_for_status()

        def emergency_search_operation() -> None:
            response = client.post(
                f"{endpoints.facility_b}/records/rec-001/emergency-search",
                json={
                    "search_term": "cardiac",
                    "requester_id": "doc-201",
                },
            )
            response.raise_for_status()

        result = timed_call(
            emergency_search_operation,
            iterations,
            "emergency_search_latency",
        )

        rows.append(
            make_row(
                "emergency_search_latency",
                result,
                iterations,
                "facility-b emergency-search endpoint",
            )
        )

        # ---------------------------------------------------------------
        # Audit verification
        # ---------------------------------------------------------------

        audit_app = federation.get("audit_app")

        if audit_app is not None:
            public_key = audit_app.state.signing_key.public_key()
        else:
            resp = client.get(f"{endpoints.audit}/public-key")
            resp.raise_for_status()
            public_key = public_key_from_pem(
                resp.json()["public_key_pem"].encode("ascii")
            )

        db_conn = psycopg.connect(database_url)

        try:

            def audit_operation() -> None:
                verify_full_chain(
                    db_conn,
                    public_key,
                )

            rows.append(
                make_row(
                    "audit_verification",
                    timed_call(
                        audit_operation,
                        iterations,
                        "audit_verification",
                    ),
                    iterations,
                    "verify_full_chain over persisted audit chain",
                )
            )

        finally:
            db_conn.close()

    return rows


# ---------------------------------------------------------------------------
# Results + plots
# ---------------------------------------------------------------------------


def write_results(rows: list[Row], env: dict[str, object]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    csv_path = RESULTS_DIR / "benchmark_results.csv"
    fieldnames = sorted({key for row in rows for key in row})
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Raw per-run samples: what the summary statistics were computed from.
    raw_path = RAW_DIR / "latency_samples.csv"
    with raw_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["benchmark", "run_index", "duration_ms"])
        for name, values in SAMPLES.items():
            for i, value in enumerate(values):
                writer.writerow([name, i, value])

    env_path = RESULTS_DIR / "environment.json"
    env_path.write_text(json.dumps(env, indent=2), encoding="utf-8")

    df = pd.DataFrame(rows)
    summary = df[df["metric"] == "latency_ms"].copy()
    summary_path = RESULTS_DIR / "benchmark_summary.csv"

    if not summary.empty:
        summary["warmup"] = summary["warmup"].astype(int)
        summary[
            [
                "benchmark",
                "metric",
                "iterations",
                "warmup",
                "parameters",
                "median_ms",
                "p95_ms",
                "mean_ms",
                "min_ms",
                "max_ms",
            ]
        ].to_csv(summary_path, index=False)

        # Box plot of the raw samples on a log axis: values span ~5 us to
        # ~20 ms, so a linear bar chart of means hides everything but HTTP.
        names = list(summary["benchmark"])
        plt.figure(figsize=(11, 6))
        plt.boxplot([SAMPLES[n] for n in names], labels=names, whis=(5, 95))
        plt.yscale("log")
        plt.ylabel("duration_ms (log scale)")
        plt.xlabel("benchmark")
        plt.title("P5-2 latency distribution (whiskers: p5-p95)")
        plt.xticks(rotation=35, ha="right")
        plt.grid(True, axis="y", alpha=0.3)
        plt.tight_layout()
        plt.savefig(RESULTS_DIR / "latency_summary.png", dpi=160)
        plt.close()

    expansion = df[df["benchmark"] == "ciphertext_expansion"].copy()
    if not expansion.empty:
        plt.figure(figsize=(9, 6))
        plt.plot(
            expansion["plaintext_bytes"],
            expansion["expansion_percent"].astype(float),
            marker="o",
        )
        plt.xscale("log", base=2)
        plt.xlabel("plaintext_bytes")
        plt.ylabel("expansion_percent")
        plt.title("P5-2 ciphertext expansion")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(RESULTS_DIR / "ciphertext_expansion.png", dpi=160)
        plt.close()

    print(f"\nResults written to: {csv_path}")
    print(f"Summary written to: {summary_path}")
    print(f"Raw samples written to: {raw_path}")
    print(f"Environment written to: {env_path}")
    print(f"Plots written to: {RESULTS_DIR}")


def _print_latency(row: Row) -> None:
    print(
        f"{row['benchmark']:35s}"
        f" median={row['median_ms']:.4f} ms"
        f" p95={row['p95_ms']:.4f} ms"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    global WARMUP

    parser = argparse.ArgumentParser(description="P5-2 reproducible benchmark harness")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP,
        help="Untimed runs discarded before each benchmark",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (defaults to $DATABASE_URL)",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Run only benchmarks that do not require PostgreSQL",
    )
    args = parser.parse_args()

    if args.iterations < 2:
        raise SystemExit("--iterations must be >= 2 to report a p95")
    if args.warmup < 0:
        raise SystemExit("--warmup must be >= 0")
    if not args.no_db and not args.database_url:
        raise SystemExit("Set DATABASE_URL or pass --database-url (or use --no-db)")
    WARMUP = args.warmup

    env = environment("local-processes" + ("" if args.no_db else "+postgres"))

    print("\n========================================")
    print("P5-2 BENCHMARK HARNESS")
    print("========================================")
    print(f"Iterations : {args.iterations} (+{args.warmup} warm-up)")
    for key, value in env.items():
        print(f"{key:15s}: {value}")

    rows: list[Row] = []

    print("\nRunning cryptographic benchmarks...")
    for benchmark in (
        benchmark_threshold,
        benchmark_rewrap,
        benchmark_revocation,
        benchmark_pre,
    ):
        row = benchmark(args.iterations)
        rows.append(row)
        _print_latency(row)

    print("\nRunning ciphertext expansion...")
    expansion_rows = benchmark_ciphertext_expansion()
    rows.extend(expansion_rows)
    for row in expansion_rows:
        print(
            f"ciphertext_expansion: {row['plaintext_bytes']} -> "
            f"{row['ciphertext_bytes']} bytes ({row['expansion_percent']:.2f}%)"
        )

    if not args.no_db:
        db_rows = run_db_benchmarks(args.iterations, args.database_url)
        rows.extend(db_rows)
        for row in db_rows:
            _print_latency(row)

    write_results(rows, env)

    print("\n========================================")
    print("BENCHMARK COMPLETE")
    print("========================================")


if __name__ == "__main__":
    main()
