# ADR-0042: Traffic-capture harness and TLS capture profile (P4-6)

- **Status:** Proposed
- **Date:** 2026-09-10
- **Deciders:** Nandini (P4-6 owner) → all four for ratification
- **Task / source:** P4-6 (WORKFLOW.md); PROJECT.md §4A (required course module); ARCHITECTURE.md §2 C17
- **Affects:** new `wire/` subsystem (C17), `crypto_core.x509_certs`, `deploy/` (TLS serving), `src/api/audit_client.py`; feeds P5-5

## Context

PROJECT.md §4A's required course module (traffic analysis) needs packet captures
of the running federation in two profiles: `capture-plain` (services already
speak plain HTTP by default, P4-3/ADR-0039) and `capture-tls` (the encrypted
wire). P4-6's "Done when" is that *both modes produce a capture file per
scenario*. Producing captures is a new tool/subsystem and a deployment change,
so it warrants an ADR.

Three constraints shaped it: (1) CLAUDE.md forbids capturing anything but our own
synthetic federation on loopback / the Docker bridge; (2) CONVENTIONS.md §2
rule 1 forbids any module outside `crypto_core` importing `cryptography.hazmat`,
so TLS cert generation cannot live in `wire/` as raw hazmat; (3) the *analysis*
of captures (wire-level assertions) is P5-5, not P4-6.

## Decision

1. **`wire/` subsystem (C17).** `wire/capture.py` is the capture harness: it
   shells out to `dumpcap` (the Wireshark/tshark binary `pyshark` already wraps,
   pinned in `requirements.txt`), pins a BPF filter to the federation's loopback
   service ports, spans exactly a scenario run (default: `deploy.run_scenario`
   over http/https), and writes `wire/captures/{plain,tls}.pcap`. It fails closed
   with `CaptureToolUnavailable` if `dumpcap` is absent — never a fake capture.
2. **TLS certs via `crypto_core`.** `wire/tls.py` generates the throwaway,
   localhost-only server certs for the `capture-tls` profile, but every
   certificate/key primitive goes through a new
   `crypto_core.build_self_signed_tls_cert` (SAN-capable, bounded validity). No
   `hazmat` import lives in `wire/`.
3. **TLS serving in `deploy/`.** Compose/entrypoint gain `TLS_ENABLED` +
   `SSL_CERTFILE`/`SSL_KEYFILE` so the same services can be brought up over TLS
   for the tls capture; plain HTTP stays the default.
4. **Scoped TLS-verify escape hatch.** `audit_client._tls_verify()` disables
   certificate verification only when **both** `CAPTURE_TLS=true` and
   `TLS_VERIFY=false` are set — a double gate so the self-signed capture certs
   work without ever making a plain `TLS_VERIFY=false` a fail-open path in a
   normal deployment.
5. **Analysis stays P5-5.** `wire/analyze_traffic.py` is the seam to P5-5 (the
   graded wire-level assertion suite), not part of P4-6's deliverable; it reads
   the captures P4-6 produces. The full assertion set and its tests land under
   P5-5.

## Consequences

- P4-6's "Done when" is met: `python -m wire.capture --mode {plain,tls}` produces
  a capture per scenario, loopback-only, tool-gated.
- Certificate generation is unified under `crypto_core` — one audit surface, and
  the earlier direct-hazmat import in `wire/tls.py` is gone.
- **Honest downside — cannot be fully run in CI without tshark.** The capture and
  analysis paths need the `dumpcap`/`tshark` binary (and a live federation), so
  their tests skip cleanly when it is absent, exactly like the Postgres-gated
  suites. The `wire/tls.py` cert generation and the BPF/tool-guard logic *are*
  covered by real unit tests; the end-to-end capture is validated on a machine
  with Wireshark installed, not in the default CI run.
- The `capture-tls` profile adds a self-signed-cert trust exception. It is
  double-gated (see Decision 4) and localhost-only, but it is a real relaxation
  that must never leak into a non-capture run.

## Alternatives considered

- **Generate TLS certs with raw hazmat in `wire/tls.py`** (as first written) —
  rejected: violates CONVENTIONS.md §2 rule 1 and duplicates cert machinery
  outside the single `crypto_core` audit surface.
- **Capture the in-process standalone demo** — rejected: it binds ephemeral
  ports, which the port-pinned loopback BPF filter cannot target; driving the
  fixed-port deployed federation gives a deterministic, filterable capture.
- **A single `TLS_VERIFY=false` switch** — rejected: a lone verify-off flag in
  shared crypto-adjacent code is a latent fail-open path; the `CAPTURE_TLS`
  co-gate scopes it to the harness.
- **Fold the wire-level analysis into P4-6** — rejected: analysis is P5-5, the
  graded module; keeping it separate preserves its own gate, ADR, and tests.
