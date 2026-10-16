# ADR-0045: P5-5 wire-level claim checks: canary search, DB-commit ordering, claim-1 scope switch

- **Status:** Proposed; claim-1 default scope set to `tls` by ADR-0073
- **Date:** 2026-10-07
- **Deciders:** Powel (implementer; P5-5 is listed for Nandini, handover to be confirmed) → all four for ratification; D6 remains a team decision
- **Task / source:** P5-5 (WORKFLOW.md); PROJECT.md §4A claims 1–4; review F18 and decision D6 (`docs/review/2026-10-07-fix-proposals.md`)
- **Affects:** `wire/` (new `streams.py`, `canaries.py`, `http_messages.py`, `checks.py`; reworked `analyze_traffic.py`; `capture.py`), `deploy/run_scenario.py` (cross-owner proposal, `--canaries-out`), `tests/wire/`; builds on ADR-0042

## Context

PROJECT.md §4A requires the traffic-analysis module to be analyser code that
asserts four wire-level claims automatically. The P4-6 analyser only counted
packets and URIs, used bare `assert` (stripped by `-O`) and printed "PASSED".
Review F18 adds that claim 1 is false on the plain profile today: plaintext,
the emergency key, attribute keys, shares and two private keys travel in
request and response bodies. Whether to fix the system (D6-a) or narrow the
claim to TLS (D6-b) is an open team decision. The analyser has to test the
claim either way and must not hide the current failure.

## Decision

1. **Canary manifest.** The scenario writes every secret it handled to a
   git-ignored `<mode>.canaries.json` beside the pcap
   (`deploy.run_scenario --canaries-out`, passed through by `wire.capture`).
   The analyser searches the captures for exactly those values.
2. **Search over reassembled streams, in every encoding.** TCP is reassembled
   per (stream, direction) before searching, so a secret split across
   segments is still found. Each secret is searched for raw, as hex in both
   cases, as standard and URL-safe base64 at all three alignments, and, for
   PEM keys, by body line (JSON escapes the newlines). JSON bodies are also
   checked against the review's denylist of key-carrying fields.
3. **Claim-1 scope switch.** `--claim1-scope all` (the default) requires both
   captures to be clean and **fails today**, as F18 asks. `--claim1-scope tls`
   is the D6-b reading: only TLS must be clean, and the plain capture becomes
   the positive control that must fire. The default changes only when D6 is
   decided.
4. **Claim 2 from the database wire.** The capture filter now includes the
   Postgres port. The check finds the release entry's `event_type` parameter
   on the audit service's Postgres connection, then the server's
   `CommandComplete("COMMIT")`. It asserts that commit precedes the
   `/breakglass/release` response, and that share 3 never appears outside
   custody setup before that response. If Postgres traffic is missing or
   encrypted, the check fails rather than falling back to weaker evidence.
5. **Claim 4 by metadata, validated.** An observer of the TLS capture can pick
   out the unlock request as the largest client→facility-b burst. The same
   rule is applied to the plain capture and must select the real
   `POST …/breakglass` request, or the claim fails. A TLS identification that
   cannot be checked against ground truth is not evidence.
6. **Claim 3 reuses P5-3.** The leakage profile comes from the same plain
   capture. A per-search CSV (`bench/results/p55_search_leakage.csv`, query
   hashed with SHA-256, never stored) records the measurement.
7. **Explicit failures.** Every check returns pass/fail with the frames it
   rests on. The entry point exits non-zero on any failure and writes
   `bench/results/p55_wire_checks.json`.

## Consequences

- P5-5's "Done when" (all four checks run and pass automatically) is met for
  claims 2–4 once captures exist. Claim 1 is met only under `--claim1-scope tls`
  until D6-a lands. That is the honest state, and the report says so.
- Every check has a negative test on synthetic traffic, so CI proves each one
  can fail. The live run needs tshark, dumpcap and a running federation, so its
  test skips without them (ADR-0042 convention).
- **Honest downsides.**
  - The canary manifest holds synthetic key material on disk. It is git-ignored
    and throwaway, but a careless `git add -f` would commit it.
  - The claim-2 check depends on psycopg sending the release entry's
    `event_type` as a text parameter, and on Postgres running without TLS on
    loopback. If either changes, the check fails closed and needs revisiting.
  - The claim-4 rule ("largest facility-b request") is tied to this scenario's
    shape. The plain-mode validation catches it when the rule breaks, but it is
    not a general break-glass detector.
  - The HTTP splitter handles Content-Length and chunked bodies only. A body
    it cannot parse is still searched by the canary check, so a parse failure
    can hide a message boundary but never a leak.
- Depends on the `deploy/` proposal (`--canaries-out`) being merged first.

## Alternatives considered

- **Assert claim 1 on TLS only, as the first plan did.** Rejected as the
  default. It would make the analyser pass while the plain profile carries
  private keys, which is exactly what F18 objects to. It is kept as an explicit
  scope for D6-b.
- **Claim 2 from response contents and a later `/chain/verify` read-back
  only.** Rejected. The share and its entry arrive in the same response, so
  that shows the entry exists, not that it was committed first. The Postgres
  `COMMIT` on the wire is the observable ordering.
- **Rely on tshark's HTTP dissector.** Rejected for the checks. Its output
  varies with reassembly preferences and cannot be unit-tested without the
  binary. Our own splitter over reassembled bytes can.
- **Committed fixture pcaps for the analyser tests (F18's suggestion).**
  Deferred. Reading a pcap needs tshark in CI. Synthetic segment-level traffic
  exercises the same logic, including deliberately violating cases, with no
  binary.
