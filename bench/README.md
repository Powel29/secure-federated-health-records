# Benchmarks (P5-2)

Every performance number in the paper comes from one command. Benchmarks never
run in CI (see the `benchmark-methodology` skill).

```bash
# Full run: crypto + real federation over HTTP + Postgres audit chain
DATABASE_URL=postgresql://... python -m bench.run_benchmarks

# Crypto-only subset, no Postgres needed
python -m bench.run_benchmarks --no-db
```

Options: `--iterations N` (default 30, minimum 2), `--warmup N` (default 5
untimed runs discarded before each benchmark).

## Outputs (`bench/results/`)

| File | Contents | Committed |
|---|---|---|
| `benchmark_summary.csv` | median, p95, mean, min, max per benchmark | yes |
| `benchmark_results.csv` | summary rows plus ciphertext-expansion rows | yes |
| `environment.json` | CPU, cores, RAM, Python, OS, deployment path | yes |
| `latency_summary.png` | box plot of raw samples, log y-axis | yes |
| `ciphertext_expansion.png` | expansion % against plaintext size | yes |
| `raw/latency_samples.csv` | every timed run (`benchmark, run_index, duration_ms`) | no (gitignored) |

Report median and p95 in the paper, never the mean alone.

## What is measured

| Benchmark | Path exercised |
|---|---|
| `threshold_reconstruction` | `shamir.combine_shares`, 2-of-3 |
| `rewrap_cost` | AES-256-GCM unwrap + wrap of one DEK |
| `revocation_latency` | `records.revocation.revoke_record_access` (DEK rotation, policy recompile, signed transition) |
| `pre_reencryption_component` | ElGamal PRE `reencrypt` only |
| `ciphertext_expansion` | record ciphertext size against plaintext size |
| `cross_facility_latency` | facility-b HTTP discovery (includes transport) |
| `emergency_search_latency` | facility-b `/emergency-search` over HTTP (includes transport) |
| `audit_verification` | `verify_full_chain` over the persisted chain |

Not yet covered (PROJECT.md D4): re-wrap cost against record count, and
scalability against number of patients and facilities.
