# ADR-0071: The TLS profile covers the facility-store link (Postgres verify-full)

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (proposal); Avaneeth (`deploy`, `storage`) to decide; Nandini (`wire`, P5-3) to review the analyser changes
- **Task / source:** WORKFLOW.md P5-3 follow-up; ADR-0070's finding
- **Affects:** `deploy/config.py` (`configure_store_tls`), `deploy/store-entrypoint.sh` (new), `deploy/migrate.py` (new), `deploy/docker-compose.yml` (`store`, `migrate`), `deploy/seed_portal.py` (transport before the first connection), `deploy/README.md`, `wire/tls.py` (`store` certificate, `trust/store.crt`), `wire/search_wire.py` (`pg_link_status`, `label_tls_exchanges`), `wire/analyze_search_leakage.py` (`--searches`), `deploy/run_scenario.py` / `wire/capture.py` (`--searches-out`), `.gitattributes`; ADR-0039, ADR-0047, ADR-0070

## Context

ADR-0070 measured that in the TLS profile the facility-store link was still
plaintext. An observer of it saw every search token, the token frequency
(5, 2, 2, 1, …) and each lookup's row count: the same frequency and hit/miss
leakage TLS was hiding on the HTTP side. That link is loopback or the Docker
bridge here, but in a real deployment it is the network between an
application server and its database.

## Decision

1. **In the TLS profile every Postgres client uses `sslmode=verify-full`.**
   `deploy.config.configure_transport` already runs first in every service,
   in bootstrap and in the scenario. It now also sets `PGSSLMODE=verify-full`
   and `PGSSLROOTCERT=<certs>/trust/store.crt`. libpq applies these to every
   `psycopg.connect`, so no connect call changes. A missing store certificate,
   or a `DATABASE_URL` with any other `sslmode` (it would override the
   environment), is refused before anything starts. `seed_portal` now runs
   `configure_transport` before its first connection. A new `deploy.migrate`
   runs `storage.migrate` under the same profile for the Compose `migrate` job.
2. **The store serves TLS only, and says so in `pg_hba`.**
   `deploy/store-entrypoint.sh` wraps the image's entrypoint. When
   `TLS_ENABLED` is on, it copies the store key into a private directory
   (bind-mount modes cannot be trusted on Windows hosts), sets `ssl=on` and
   TLS ≥ 1.3, and writes `hostssl … ; hostnossl … reject`. A client that
   forgets TLS fails instead of talking in the clear. When `TLS_ENABLED` is
   off it runs the image unchanged; any other value, or missing certificates,
   exits 2. Path A starts its throwaway store through the same script
   (`deploy/README.md`).
3. **The store certificate is trusted on its own.** `python -m wire.tls`
   issues a `store` certificate (SANs `store`, `localhost`, `127.0.0.1`) like
   the services' certificates. It goes in `trust/store.crt`, not the HTTP
   bundle, and `store` is not added to `SERVICES`, so captures and checks
   don't treat it as an HTTP service port.
4. **The plain profile is untouched.** P5-5 claim 2 (audit `COMMIT` before
   share release) reads the store link in the plain capture only, so it still
   holds.
5. **P5-3 still measures what TLS leaves.** With the store link encrypted
   there are no token lookups to pair TLS exchanges with. The workload
   therefore writes a ground-truth manifest (`--searches-out`, beside the
   canaries under `wire/captures/`). `--searches` uses it only to say which
   exchange was which search; every size and time is still measured on the
   wire. The analyser also reports how many store connections were TLS,
   including pooled connections opened before the capture started, whose
   first captured bytes are already TLS records.

## Consequences

- Measured (`bench/results/p53_search_leakage_tls.json`): store connections
  4/4 TLS, 0 readable token lookups. Without the store link the observer
  loses token identity, row counts and the token frequency histogram. On a
  live store: a plaintext client is rejected by `pg_hba`, a verify-full client
  negotiates TLSv1.3, and a client trusting the wrong root fails verification.
  The Compose stack came up healthy in the TLS profile with 6/6 store
  connections on TLSv1.3.
- **Still leaked over TLS, now the main residual:** response size separates
  hit (60 B), miss (51 B) and refused (112 B). The request body record is
  always the term length + 63 B, so term frequency is visible per term
  length (70 B ×9, 71 B ×3, …). Closing this needs padding, which is not
  decided here.
- Every TLS-profile run now needs `python -m wire.tls` to have produced
  `store.crt`. Certificates from before this change cause a clear refusal at
  startup, and a store started before regeneration must be restarted.
- `.gitattributes` gains `*.sh text eol=lf`. The entrypoint runs under `sh`
  in a Linux container, and this repository is checked out with
  `core.autocrlf=true` on Windows.
- Tests: `tests/deploy/test_transport.py` (verify-full set, weaker DSN
  refused, missing cert refused, plain profile untouched),
  `tests/deploy/test_compose_hardening.py` (store entrypoint, every store
  client gets the flag and trust mount), `tests/security/test_store_tls.py`
  (the TLS profile refuses the suite's plaintext Postgres after the same URL
  connects without it), `tests/wire/test_search_wire.py` (link status,
  labelled exchanges, ticket-safe latency).

## Alternatives considered

- **`sslmode=require`** — encrypts but does not check who answers, so a
  machine in the middle can still read the tokens. Rejected for
  `verify-full`.
- **TLS in both profiles** — the plain profile is the deliberately readable
  wire that P5-5's claims 0 and 2 are proven on (ADR-0039). Rejected.
- **`?sslmode=verify-full` in each `DATABASE_URL`** — it would have to be
  repeated across Compose, Path A, the portal and the tests, and one
  forgotten URL would silently fall back to plaintext. Setting the
  environment in one place, and refusing a DSN that contradicts it, is
  harder to get wrong.
- **Server-side `ssl=on` only** — Postgres would still accept a plaintext
  client. `hostnossl … reject` makes a misconfigured client fail.
- **Putting the store certificate in the HTTP bundle** — every HTTPS client
  would then trust a database certificate. A separate file keeps each trust
  anchor to its purpose (ADR-0047's least-mount spirit).
