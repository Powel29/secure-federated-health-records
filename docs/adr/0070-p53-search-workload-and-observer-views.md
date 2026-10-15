# ADR-0070: P5-3 search workload and the database-link / TLS-size observer views

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (proposal); Nandini (`search`, P5-3 owner) and Avaneeth (`deploy/run_scenario.py`) to review
- **Task / source:** WORKFLOW.md P5-3; PROJECT.md §4A claim 3; ADR-0027, ADR-0069
- **Affects:** `deploy/run_scenario.py` (`--search-workload`, `run_search_workload`), `wire/capture.py` (`--search-workload`), new `wire/search_wire.py`, `wire/analyze_search_leakage.py`, `tests/wire/test_search_wire.py`, `tests/deploy/test_end_to_end.py`, `bench/results/p53_search_leakage*.json`

## Context

The P4-6 capture held one emergency search, so P5-3 could report neither
frequency nor timing. Three more things only surfaced once real searches were
captured:

- Every emergency search has the same URI (`/records/<id>/emergency-search`),
  so counting repeats by URI measures nothing. The query is in the request
  body.
- The search token never crosses the HTTP wire. The facility derives it and
  looks it up in Postgres, and the facility↔Postgres link is plaintext in
  **both** capture profiles (only the federation's HTTP links use TLS). An
  observer of that link sees the token, its repetitions and the result count.
- tshark 4.6 reports `http.file_data` as colon-separated hex, so the old
  analyser read every body as unreadable and reported 0 plaintext queries on
  a capture where all of them were plaintext.

ADR-0069 also needs evidence on the wire: the same term must map to a
different token after expiry.

## Decision

1. **The workload is an opt-in flag on the existing scenario**
   (`python -m deploy.run_scenario --search-workload`, passed through by
   `python -m wire.capture --search-workload`, output
   `wire/captures/<mode>-search.pcap`). After step 9 it runs 10 searches under
   the scenario's session (repeats, hits and misses, 0.5 s apart). It then waits
   for expiry and the forced rotation (`granted`) and searches once more, which
   must be refused with 403. Last, it declares a second break-glass and runs 4
   more searches, 3 of them terms already searched in the first session. It
   stays loopback-only and uses synthetic data only.
2. **The second break-glass goes through the custodian.** After rotation only
   the custodian holds the new share 1. The workload gives the custodian the
   federation's public trust anchors (`PUT /trust`) and the scenario clinician's
   synthetic material (`POST /subjects/{id}/material`), both bootstrap-only
   routes. That is what the portal seed does when `SEED_DATA=true`.
3. **The analyser reads three observer views of one capture.**
   (a) HTTP: unchanged, plus the hex-body fix and `term_frequency`.
   (b) Database link (`wire/search_wire.py`): frontend `Parse`/`Bind` messages
   from the reassembled Postgres stream, recognised by the statement text,
   following psycopg's prepared statements by name, plus the server's
   `CommandComplete` row count.
   (c) TLS sizes: record headers from the same reassembled streams, grouped
   into messages (a burst of records from one side) and paired with the token
   lookups by time.
   Searches are split into epochs at each refused search, and the report says
   whether a term searched in several epochs kept its token.
4. **Reports carry token fingerprints** (first 12 hex digits of SHA-256),
   never the tokens.

## Consequences

- P5-3 has numbers from real plain and TLS captures; see
  `bench/results/p53_search_leakage.md`.
- New finding for the paper: **TLS on the federation's HTTP links does not
  hide search frequency or result counts.** The database link shows them,
  and the TLS record sizes separate hits from misses and leak the query's
  length.
  Closing the database link (Postgres `sslmode=verify-full`) is a deployment
  decision for Avaneeth and is not taken here; ADR-0071 proposes it.
- In the plain workload capture the custodian deposit puts a clinician signing
  key on the wire, the same as the existing scenario canaries. This capture is
  P5-3 evidence only; the P5-5 claims still run on `plain.pcap`/`tls.pcap`
  without the workload.
- The workload adds about 20 s to a run (it waits out the window), and the
  Postgres-gated e2e test about 21 s.
- The pairing is by time, so it assumes searches are sequential, which the
  workload guarantees. Concurrent traffic to the same facility could mispair
  a TLS exchange.

## Alternatives considered

- **A separate `wire/` driver.** It would need its own record, keys and
  session; the scenario already has them. Rejected as duplication.
- **A custodian endpoint that releases share 1 to the script.** That weakens
  custody (ADR-0043) to make a measurement easier. Rejected.
- **Decrypting TLS with `SSLKEYLOGFILE`.** That measures what the key holder
  sees, not what an observer sees. Rejected.
- **pyshark `tls.record.length` fields.** Frames holding several records
  come back as multi-valued fields that are easy to misread. Parsing the
  reassembled stream reuses `wire.streams` and its gap handling (review N8)
  and runs in tests without tshark.
