# ADR-0054: Claim status comes from test runs; the wire analyser refuses evidence it cannot trust

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** Avaneeth (implementer) → Powel (claim registry, wire) → all four
- **Task / source:** Review N3, N4, N5, N6, N7, N8, N9, N15; amends ADR-0045 and ADR-0046
- **Affects:** `tests/security/claims.py`, `_claim_collector.py`, `mutations.py`, `test_claim_registry.py`, `test_p51_system_claims.py`; `wire/streams.py`, `canaries.py`, `capture.py`, `checks.py`, `analyze_traffic.py`, `http_messages.py`; `deploy/run_scenario.py`; Postgres skips in `tests/`

## Context

The claim table said "holds" for any system test without an xfail marker,
whether it passed, skipped or failed to import. The mutation runner counted a
crash as "caught". The analyser could pass on a stale pcap, a single TLS
handshake, a TLS run that never reached the unlock, a stream with a lost
segment, or a canary too short to search for, and never saw revocation.

## Decision

- **Claims:** status is computed from a run. "holds" needs every system test
  *passed*; skipped is `UNVERIFIED`, xfailed is "fails today", anything else
  is `BROKEN`. A non-zero collection exit voids the table. Every Postgres test
  uses the CI-aware skip.
- **Mutations:** a test must be green before mutating; only pytest exit 1
  counts as caught; exit 2–5 and a mutation that failed to apply are errors.
  C6 gains mutation C6b (the compare-and-set) because C6 holds through it.
- **Analyser:** capture deletes the old pcap and fails if dumpcap stops early
  or writes nothing; the manifest carries `run_id`/`started_at` and a pcap
  with no frame from that run is refused; TLS must appear on every service
  port the plain run used; claim 4 needs a TLS unlock burst at least as large
  as the plain request; a gap makes claim 1 inconclusive and no match spans a
  gap; an unsearchable canary is rejected; the scenario sends a revoke so
  claim 1 covers revocation; `--db-port` defaults to `DATABASE_URL`'s port;
  the search CSV labels queries `q1, q2, …` instead of reversible hashes.

## Consequences

- The committed captures (no run stamp) are now refused: P5-5 needs a fresh
  capture (exit plan E2), and claim 1 is expected to fail on the plain profile
  until D6 and F10.
- `python -m tests.security.claims` runs the claim tests, so it needs
  Postgres like the suite.

## Alternatives considered

- **Keep collection-only status with a "run it first" note** — the review's
  point is that the table must not be able to say "holds" on its own.
