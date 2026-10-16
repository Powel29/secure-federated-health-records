# ADR-0078: Demo TLS certificates keep the `localhost` / `127.0.0.1` SANs

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal; owns `deploy/`) → Ojas (`wire/tls.py`) → all four
- **Task / source:** Review finding N14, last open row ("per-service SANs")
- **Affects:** `wire/tls.py` (unchanged), `deploy/README.md` assumption; ADR-0047, ADR-0071

## Context

`wire.tls.generate` gives every service certificate its own name plus
`localhost` and `127.0.0.1`. N14 pointed out that any service's TLS key can
then present itself as any other service to a client that connects by
`localhost`. The proposed fix was one SAN per certificate. Path A
(`run_local`), the host-run scenario, the captures and the benchmarks all
reach every service as `127.0.0.1:<port>`, so with one SAN per certificate
they could not verify any service without turning verification off, which
ADR-0047 removed.

## Decision

Keep the `localhost` / `127.0.0.1` SANs on the demo certificates and record
the residual risk. The certificates stay throwaway, generated per run, and
each container mounts only its own key (ADR-0047).

## Consequences

- An attacker who steals one service's TLS key *and* can bind a port on the
  host can impersonate another service to a host-side client. It cannot forge
  that client's requests (signed `RequestEnvelope`, ADR-0066), forge an audit
  release (the custodian verifies the entry signature, F31), or open a record
  (threshold gate). It could feed a host-side client false responses.
- Inside Compose, services reach each other by service name; a SAN-per-service
  certificate set for that path alone remains possible future hardening.

## Alternatives considered

- **One SAN per certificate (N14 as proposed)** — breaks every host-run path:
  scenario, captures, benchmarks and Path A.
- **A separate host-facing certificate per port** — doubles the certificate
  set and the trust bundle for a demo-only threat.
