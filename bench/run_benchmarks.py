from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import os
import platform
import statistics
import sys
import time
from pathlib import Path

import httpx
import pandas as pd
import matplotlib.pyplot as plt
import psycopg
from cryptography.hazmat.primitives.asymmetric import ec

from audit.chain import verify_full_chain
from contracts.enums import ReasonCode
from crypto_core import (
    certificate_to_pem,
    generate_ec_keypair,
    private_key_to_pem,
    public_key_from_pem,
)
from breakglass import create_emergency_assertion
from crypto_core.symmetric import generate_key
from pre.elgamal import generate_keypair, encapsulate_key, reencrypt, generate_rekey
from records.service import encrypt_record, wrap_dek, rewrap_dek
from records.revocation import revoke_record_access
from records.ingest import ingest_record
from policy import reconstruct_root_secret
from records.service import unwrap_dek
from shamir.split import split_secret, combine_shares
from search.service import search_records_with_emergency

from demo.driver import standalone_federation
from demo.seed_data import seed_synthetic_data, create_synthetic_dataset


DEFAULT_ITERATIONS = 30
RESULTS_DIR = Path("bench/results")


def timed_call(func, iterations: int):
    values = []

    for _ in range(iterations):
        start = time.perf_counter()
        func()
        values.append((time.perf_counter() - start) * 1000)

    return {
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def make_row(
    benchmark,
    result,
    iterations,
    parameters="",
    **extra,
):
    return {
        "benchmark": benchmark,
        "metric": "latency_ms",
        "iterations": iterations,
        "parameters": parameters,
        **result,
        **extra,
    }


# ---------------------------------------------------------------------------
# 1. Threshold reconstruction
# ---------------------------------------------------------------------------

def benchmark_threshold(iterations):
    secret = b"benchmark-secret-for-phase5-task2"

    shares = split_secret(secret, k=2, n=3)
    threshold_shares = shares[:2]

    def operation():
        recovered = combine_shares(threshold_shares, k=2)
        if recovered != secret:
            raise RuntimeError("Threshold reconstruction failed")

    return make_row(
        "threshold_reconstruction",
        timed_call(operation, iterations),
        iterations,
        "Shamir k=2,n=3",
    )


# ---------------------------------------------------------------------------
# 2. Re-wrap cost
# ---------------------------------------------------------------------------

def benchmark_rewrap(iterations):
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

    def operation():
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
        timed_call(operation, iterations),
        iterations,
        "AES-256-GCM unwrap + wrap",
    )


# ---------------------------------------------------------------------------
# 3. Revocation latency
# ---------------------------------------------------------------------------

def benchmark_revocation(iterations):
    patient_id = "bench-revocation-patient"
    plaintext = b"benchmark clinical record"

    med, net = _make_authorities()

    clinical = _make_clinical_policy()
    keyring = {
        ("authority-med", "role", "physician"):
            med.attribute_key("role", "physician"),
        ("authority-net", "specialty", "cardiology"):
            net.attribute_key("specialty", "cardiology"),
        ("authority-net", "owner", patient_id):
            net.attribute_key("owner", patient_id),
    }

    def fresh_record():
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

    old_root = reconstruct_root_secret(
        ingested.compiled_policy,
        keyring,
    )
    old_dek = unwrap_dek(
        ingested.dek_wrapping,
        old_root,
    )

    def operation():
        signing_key, _ = generate_ec_keypair()

        revoke_record_access(
            current_record=ingested.record,
            current_wrapping=ingested.dek_wrapping,
            old_dek=old_dek,
            new_clinical_policy=clinical,
            owner_authority_id="authority-net",
            attribute_keyring=keyring,
            actor_id=patient_id,
            actor_signing_key=signing_key,
            correlation_id=f"bench-revocation-{time.perf_counter_ns()}",
        )

    return make_row(
        "revocation_latency",
        timed_call(operation, iterations),
        iterations,
        "DEK rotation + policy recompilation + signed transition",
    )


def _make_authorities():
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


def _make_clinical_policy():
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

def benchmark_pre(iterations):
    sk_a, pk_a = generate_keypair()
    sk_b, _ = generate_keypair()

    ciphertext, _ = encapsulate_key(pk_a)
    c1, c2 = ciphertext

    rekey = generate_rekey(sk_a, sk_b)

    def operation():
        reencrypt(rekey, c1, c2)

    return make_row(
        "pre_reencryption_component",
        timed_call(operation, iterations),
        iterations,
        "ElGamal PRE",
    )


# ---------------------------------------------------------------------------
# 5. Ciphertext expansion
# ---------------------------------------------------------------------------

def benchmark_ciphertext_expansion():
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
        expansion = (
            (ciphertext_size - size) / size * 100
        )

        rows.append({
            "benchmark": "ciphertext_expansion",
            "metric": "expansion_percent",
            "iterations": 1,
            "parameters": f"plaintext_bytes={size}",
            "mean_ms": "",
            "median_ms": "",
            "min_ms": "",
            "max_ms": "",
            "plaintext_bytes": size,
            "ciphertext_bytes": ciphertext_size,
            "expansion_percent": expansion,
        })

    return rows


# ---------------------------------------------------------------------------
# 6. DB-backed benchmarks
# ---------------------------------------------------------------------------

def run_db_benchmarks(iterations, database_url):
    rows = []

    print("\nStarting real federation benchmark setup...")

    with standalone_federation(
        database_url=database_url,
        default_duration=30.0,
    ) as federation:

        endpoints = federation["endpoints"]
        config = federation["config"]
        expiry_manager_b = federation["expiry_manager_b"]
        
        print("Seeding synthetic federation data...")

        seeded = seed_synthetic_data(
            endpoints=endpoints,
            config=config,
            dataset=create_synthetic_dataset(),
            database_url=database_url,
            verbose=False,
        )

        client = httpx.Client(timeout=15.0)

        # ---------------------------------------------------------------
        # Cross-facility latency
        # ---------------------------------------------------------------

        def discovery_operation():
            response = client.get(
                f"{endpoints.facility_b}/patients/pat-101/records"
            )
            response.raise_for_status()

            if response.json()["record_count"] < 1:
                raise RuntimeError(
                    "Cross-facility discovery returned no records"
                )

        result = timed_call(
            discovery_operation,
            iterations,
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

        facility_ca = seeded["facility_cas"]["facility-b"]

        facility_ca_pem = certificate_to_pem(
            facility_ca[1]
        ).decode("ascii")

        assertion = create_emergency_assertion(
            patient_id="pat-101",
            clinician_id="doc-201",
            facility_id="facility-b",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=clinician["private_key"],
            ttl=dt.timedelta(minutes=5),
        )

        # Use the two locally available threshold shares.
        shares_payload = [
            (
                record_info["share1"][0],
                record_info["share1"][1].hex(),
            ),
            (
                record_info["share2"][0],
                record_info["share2"][1].hex(),
            ),
        ]

        k_physician = seeded["attribute_keys"]["authority-med:role:physician"]

        unlock_payload = {
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": clinician[
                "certificate_pem"
            ],
            "facility_ca_certificate_pem": facility_ca_pem,
            "trusted_root_certificate_pem": seeded[
                "root_cert_pem"
            ],
            "shares": shares_payload,
            "pre_rewrap_key": clinician["pre_public_key"],
            "lifecycle_signing_key_pem": clinician[
                "private_key_pem"
            ],
            "correlation_id": "bench-emergency-search",
            "baseline_wrapping_key_b64": base64.b64encode(k_physician).decode("ascii"),
            "emergency_duration_seconds": 60.0,
        }

        unlock_response = client.post(
            f"{endpoints.facility_b}/records/rec-001/breakglass",
            json=unlock_payload,
        )
        unlock_response.raise_for_status()

        def emergency_search_operation():
            response = client.post(
                f"{endpoints.facility_b}/records/rec-001/emergency-search",
                json={
                    "search_term": "cardiac",
                },
            )
            response.raise_for_status()

        result = timed_call(
            emergency_search_operation,
            iterations,
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

        client.close()

        db_conn = psycopg.connect(database_url)

        try:
            def audit_operation():
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

def write_results(rows):
    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    csv_path = RESULTS_DIR / "benchmark_results.csv"

    fieldnames = sorted({
        key
        for row in rows
        for key in row.keys()
    })

    with csv_path.open(
        "w",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)

    df = pd.DataFrame(rows)

    summary = (
        df[
            df["mean_ms"].notna()
            & (df["mean_ms"] != "")
        ]
        .copy()
    )

    summary_path = RESULTS_DIR / "benchmark_summary.csv"

    if not summary.empty:
        summary[
            [
                "benchmark",
                "metric",
                "iterations",
                "parameters",
                "mean_ms",
                "median_ms",
                "min_ms",
                "max_ms",
            ]
        ].to_csv(
            summary_path,
            index=False,
        )

    # Latency plot
    if not summary.empty:
        plt.figure(figsize=(11, 6))

        plt.bar(
            summary["benchmark"],
            summary["mean_ms"].astype(float),
        )

        plt.ylabel("Mean latency (ms)")
        plt.xlabel("Benchmark")
        plt.title("P5-2 Benchmark Latency")
        plt.xticks(
            rotation=35,
            ha="right",
        )
        plt.tight_layout()

        plt.savefig(
            RESULTS_DIR / "latency_summary.png",
            dpi=160,
        )

        plt.close()

    # Ciphertext expansion plot
    expansion = df[
        df["benchmark"] == "ciphertext_expansion"
    ].copy()

    if not expansion.empty:
        plt.figure(figsize=(9, 6))

        plt.plot(
            expansion["plaintext_bytes"],
            expansion["expansion_percent"].astype(float),
            marker="o",
        )

        plt.xlabel("Plaintext size (bytes)")
        plt.ylabel("Ciphertext expansion (%)")
        plt.title("P5-2 Ciphertext Expansion")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()

        plt.savefig(
            RESULTS_DIR / "ciphertext_expansion.png",
            dpi=160,
        )

        plt.close()

    print(f"\nResults written to: {csv_path}")

    if summary_path.exists():
        print(f"Summary written to: {summary_path}")

    print(
        f"Plots written to: {RESULTS_DIR}/"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="P5-2 reproducible benchmark harness"
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
    )

    parser.add_argument(
        "--database-url",
        default=os.environ.get(
            "DATABASE_URL",
            "postgresql://localhost/postgres",
        ),
    )

    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Run only benchmarks that do not require PostgreSQL",
    )

    args = parser.parse_args()

    if args.iterations < 1:
        raise SystemExit(
            "--iterations must be >= 1"
        )

    print("\n========================================")
    print("P5-2 BENCHMARK HARNESS")
    print("========================================")
    print(f"Iterations : {args.iterations}")
    print(f"Python     : {sys.version.split()[0]}")
    print(f"Platform   : {platform.platform()}")

    rows = []

    print("\nRunning cryptographic benchmarks...")

    benchmarks = [
        benchmark_threshold,
        benchmark_rewrap,
        benchmark_revocation,
        benchmark_pre,
    ]

    for benchmark in benchmarks:
        result = benchmark(args.iterations)
        rows.append(result)

        print(
            f"{result['benchmark']:35s}"
            f" mean={result['mean_ms']:.6f} ms"
            f" median={result['median_ms']:.6f} ms"
        )

    print("\nRunning ciphertext expansion...")

    expansion_rows = benchmark_ciphertext_expansion()

    rows.extend(expansion_rows)

    for row in expansion_rows:
        print(
            f"ciphertext_expansion:"
            f" {row['plaintext_bytes']} -> "
            f"{row['ciphertext_bytes']} bytes"
            f" ({row['expansion_percent']:.2f}%)"
        )

    if not args.no_db:
        db_rows = run_db_benchmarks(
            args.iterations,
            args.database_url,
        )

        rows.extend(db_rows)

        for row in db_rows:
            print(
                f"{row['benchmark']:35s}"
                f" mean={row['mean_ms']:.6f} ms"
                f" median={row['median_ms']:.6f} ms"
            )

    write_results(rows)

    print("\n========================================")
    print("BENCHMARK COMPLETE")
    print("========================================")


if __name__ == "__main__":
    main()
