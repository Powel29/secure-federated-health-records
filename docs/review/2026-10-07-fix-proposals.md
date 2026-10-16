# Fix proposals — whole-repo review

**To:** Powel, Nandini, Ojas, Avaneeth
**From:** Avaneeth (review run with Claude Code)
**Status:** draft for review. Nothing here is implemented by this document.

| Review | Range | What it covered |
|---|---|---|
| 1st, 2026-10-07 | whole repo at `3c42094` | Rule violations and bugs → decisions **D1–D11**, fixes **F1–F44** |
| 2nd, 2026-10-09 | `3c42094...4ddc201` (branch `full-deploy`, 106 files) | Status of every D/F item, plus new findings **N1–N16** from the Phase 5 and full-deploy code |
| Update, 2026-10-11 | `4ddc201...a40a5a7` (one code commit) | Status of the items that commit touched (N2, N11, N12, N14, N16, F20, F42), plus the list of fixes that need no decision |
| Fix batch, 2026-10-11 | `a40a5a7...443ca0f` (commit `443ca0f`) | Every fix in "Fixes that need no decisions" implemented (ADR-0048 to ADR-0054); status below |

Both reviews were four- or three-way parallel reviews (standards × spec),
and the main findings were re-checked by hand. Smells are left out; this
covers rule violations and bugs only. Status lines marked **Status at
`4ddc201`** come from the second review. Headings marked **FIXED**,
**PARTIAL** or **INTERIM FIX** carry a **Status at `443ca0f`** line naming
the change that fixed them; unmarked items are still open.

## How to review

- **Everyone:** §0 lists eleven design decisions (D1–D11). They need a team
  answer before the fixes that depend on them can start. Please each read §0
  before the next sync.
- **Each person:** the last section lists your fixes by name. Reply per ID
  with **approve**, **reject** or **change** (e.g. "F9 → option b").
- Items marked **⚑ needs D#** can't be coded until that decision is made.
  The `crypto-implementation` rule applies: where the architecture does not
  already specify a construction, this doc names the options and does **not**
  pick one silently.
- **Owner** comes from `WORKFLOW.md` and `git log`. Under CONVENTIONS §3,
  each fix goes to its owner as an issue or a proposal PR; nobody edits
  another person's module.
- **ADR** = needs a new ADR (or amends one) under the standing rule.
- Effort: S ≤ 2h, M ≈ half a day, L ≥ 1 day.

---

## 0. Design decisions needed first

**All eleven are still pending at `4ddc201`.** `docs/plans/phase5-exit-plan.md:55-62` lists D1–D8 as "⏳ Pending"; D9–D11 have no ADR.

| ID | Decision | Current state | Options | Recommendation |
|---|---|---|---|---|
| **D1** | Who checks the Emergency Assertion before share 3 is released? | Nobody. The audit service releases share 3 to any caller that knows the `share_key` (= record_id). The custodian asks for it *before* the facility has checked anything, and ADR-0044 accepts that order. | (a) The audit service checks it itself, against its own trust anchor, before commit-then-release. (b) The facility pre-checks it first and the custodian calls audit afterwards. | **(a)**. A share holder that releases without checking anything is the actual hole; ordering at the custodian doesn't fix that. Amend §8 to say "each share holder validates before release". Supersede ADR-0044's acceptance of the current ordering. |
| **D2** | Share 2 (home authority) | Generated at ingest and thrown away (`custodian_service.py:764`). Break-glass is effectively 2-of-2: custodian (share 1) + audit service (share 3). | (a) Deposit share 2 with the patient's home-authority service and gate its release the same way as share 3. The gate then accepts any 2 of {1,2,3}. (b) Amend §5 and the paper to say "2-of-2 custodian + audit; share 2 reserved". | **(a)** if time allows, since the paper claims 2-of-3 with a delegate fallback. Otherwise (b) and state it honestly. |
| **D3** | What does "forced rotation" on expiry (and on revocation) actually rotate? | Nothing. Expiry computes a rotated record and wrapping, then discards them; the custodian sends a random "baseline key". Old shares, the emergency wrapping and search tokens all keep working. Revocation rotates the DEK but crashes on Postgres and leaves the emergency wrapping on the old DEK. **Since `4ddc201`:** the expiry timer now *mirrors* `EXPIRED → GRANTED` into the store (ADR-0047) without persisting a rotated ciphertext, so the store claims a re-baseline that never happened. | (a) **Full**: new DEK, re-encrypt, re-author the policy root secret (needs authoring keys from the authorities), new emergency key with re-split and redistributed shares, re-index search. (b) **Emergency path only**: replace the emergency wrapping with a fresh emergency key and new shares, and re-key search tokens. The DEK is not rotated; state that as a limitation. | **(b) now, (a) as stretch.** Today *nothing* is rotated (F9). (b) is achievable at the facility (it holds the DEK during the session), kills old shares and tokens, and is honest. (a) needs a facility→authority authoring call (depends on D5). |
| **D4** | Trusted source of **patient** public keys | There isn't one. The caller sends the patient's public key in the request body (consent read, grant submit), so a self-signed grant passes. Revocation trusts a caller-supplied `actor_id`. Revoking a grant sends the patient's *private* key to the facility. | (a) The home facility CA issues each patient an X.509 cert at enrolment, validated against the configured root like clinicians. (b) A registry at the home authority that signs (patient_id → public key) bindings. | **(a)**. It reuses `identity` and the F1 trust anchor and adds no new construction. Unblocks F10, F13, F15. |
| **D5** | Service-to-service authentication | None. Every service is unauthenticated and listens on all interfaces; Compose publishes every port. `requester_id` / `subject_id` are whatever the caller types. `breakglass/envelopes.py` exists but nothing calls it. **Since `4ddc201`:** (b) is done. Services bind to `127.0.0.1` and Compose publishes on `127.0.0.1` (F16). Postgres is newly published with `trust` auth (N12). | (a) Every inter-service call carries a signed `RequestEnvelope` (the existing contract and `breakglass/envelopes.py`, currently unused), signed by a service key with a bootstrap-issued cert, with one-time `request_id`. (b) Network-only: bind to loopback / Compose internal network, and document "no exposure" as an assumption. | **(b) immediately (F16), then (a)**. (a) also satisfies §2 rule 9 for share requests and gives BOLA (F34) a caller identity. |
| **D6** | PROJECT §4A property 1 ("no PHI, DEKs, attribute keys or shares in the clear") vs. the current wire design | The facility decrypts and returns `plaintext_b64`. Ingest sends the plaintext and the full emergency key. Attribute keys, shares and two private keys travel in request/response bodies. The analyser checks none of this and prints "PASSED". **Since `4ddc201`:** the analyser now asserts property 1, with a `--claim1-scope plain\|tls` switch that leaves D6 open (ADR-0045). Never run on real captures. | (a) **Client-side crypto**: the custodian decrypts and encrypts. The facility returns ciphertext + wrapping, ingest sends ciphertext + wrappings, and shares are delivered wrapped to the recipient's key using the existing `encapsulate_key` + AES-GCM delivery pattern the gate already uses. (b) Narrow property 1 to the five federation services, exclude the custodian↔facility hop, and force TLS on it. | **(a)** is what the claim needs; it is large (L, three owners). **(b)** is the fallback if time runs out, written into the paper as scope. Either way the analyser (F18) must test whatever claim is kept. |
| **D7** | Where expiry returns a record that was REVOKED before break-glass | Expiry always ends at `GRANTED`, so REVOKED → break-glass → expiry silently un-revokes the record. ADR-0044's reset writes `granted` too. **Since `4ddc201`:** worse. The new state mirror writes `GRANTED` into the shared store unconditionally, so the un-revoke is persistent (N1). **Now urgent.** | (a) Add `EXPIRED → REVOKED` to `LEGAL_TRANSITIONS`; the session remembers `prior_state`. (b) Forbid break-glass on REVOKED records. | **(a)**. Break-glass on a revoked record is an intended legal transition today; it must not silently un-revoke. |
| **D8** | Who signs the break-glass `TransitionEvent` | A throwaway keypair minted per unlock (`custodian_service.py:926`). Its private key is sent to the facility, and nobody can verify the event afterwards. | (a) The custodian signs it **inside the custodian** with the clinician's key and sends only the signed event; the facility verifies it against the cert already validated by F1. (b) A facility service key signs as witness. | **(a)**. The clinician's key never leaves the custodian (ADR-0043), and the event becomes verifiable (today it is signed with a throwaway key). |
| **D9** | Fix for ambiguous signed payloads | Seven modules join fields with `0x1f`, with no length prefix and no type tag. `Identifier` allows `0x1f`, so one set of signed bytes can be read as different fields. The same clinician key signs assertions and transition events. | (a) A length-prefixed encoding with a per-type domain tag, in `crypto_core`. (b) Forbid `0x1f` in `Identifier` (a `contract:` PR). | **(a)**. It also fixes cross-type signature reuse. It is an encoding change, not a new primitive, but it touches five modules: one ADR, one coordinated PR. |
| **D10** | Credential revocation vs. one shared, never-rotated attribute key | One key per (name, value), shared by every holder and never rotated. Revoking a credential stops nothing already obtained, and `/attribute-keys/author` skips the credential check entirely. | (a) Document as a limitation (ADR-0026 trade). (b) Epoch-versioned attribute keys plus re-authoring affected records. | **(a)** for this project; (b) is future work. |
| **D11** | PRE claims (unidirectional, "without decryption") | Docstrings and ADR-0012 claim unidirectional re-encryption without decryption. In the code, `rk` can be inverted (bidirectional), the facility unwraps the DEK in plaintext and delivers it by KEM, and `reencrypt` is never called. | (a) Correct the docstrings and paper: it's a KEM-style delivery to the clinician, the scheme is bidirectional, and the gate decrypts. (b) Implement a unidirectional scheme. | **(a)**. A real unidirectional PRE needs pairings, which are out of scope (PROJECT §6). Don't change the construction. |

---

## Status at `4ddc201` (second review)

| ID | Status | Evidence | What remains |
|---|---|---|---|
| F1, F2, F3, F4, F6, F7, F8, F10, F11 | **OPEN** | Only 3 lines of `hospital.py` changed; C3, C6, C7 are strict xfails | Everything in its section below |
| F5 | **DIVERGED (not sound)** | `deploy/asgi/facility.py:61` gives the timer `state_writer=repo.upsert_lifecycle_state`. The ADR-0044 reset is still at `hospital.py:199-227`. | The proposal asked for writes through the CAS ending at `prior_state`, plus a sessions table and restart reconciliation. The actual write is unconditional and always ends at GRANTED. See N1, N2. |
| F9 | **OPEN** | Strict xfail `test_c4_pre_expiry_shares_do_not_restore_search`; ADR-0047 defers it | Everything; blocked on D3. Note the C4 test itself is vacuous (N6). |
| F12 | **PARTIAL (overclaimed by 638c2c6)** | `transition_lifecycle_state` at `storage/repositories.py:297` and `api/repository.py:383`; lock on `ConsumedEventIds`; unit tests | **No production caller.** `hospital.py:221,831,1006,1220` and the new state mirror all still upsert unconditionally. See N1. |
| F13 | **PARTIAL** | Postgres `store_consent_grant` is now an upsert by `grant_id` (persisted across processes) | The facility still never reads stored grants and still takes the patient key from the caller (`hospital.py:519`). |
| F14, F15, F17 | **OPEN** | — | Everything |
| F16 | **FIXED** | `entrypoint.py` defaults to `127.0.0.1`; Compose ports bound to `127.0.0.1:`; `tests/deploy/test_bind_address.py` | The Dockerfile's `ENV HOST=0.0.0.0` overrides the default for a plain `docker run` (N14) |
| F18 | **PARTIAL** | Canary matching in raw, hex and base64; key denylist (`wire/checks.py:48`); claim 2 checked through the Postgres COMMIT frame; non-zero exit; synthetic-fixture tests | System fix blocked on D6. Never run on real captures (exit-plan E4). Revocation not covered (N4). Stale-capture and empty-TLS false passes (N5). Gap handling fails open (N8). |
| F19, F20, F21 | **OPEN** | No `else` at `hospital.py:179-196`; `consumed_store=None` still defaults | Everything. F20 is now easier to trigger (N2). |
| F22 | **FIXED (facility only)** | Migration `0002_consumed_ids.sql`, `consume_id`, a Postgres backend for `replay.py`, wired in `facility.py`; C8 system test | The C8 test uses the in-memory repo; a Postgres variant is missing (N13). The audit and authority consumers wait on F2 and F15. |
| F23–F27, F29–F36 | **OPEN** | Sources untouched | Everything |
| F37 | **PARTIAL** | URL scheme follows `TLS_ENABLED` (`deploy/config.py`); the custodian is seeded on Compose | Chain verification still runs after the services start (`run_local` [7/7], `compose_bootstrap.py:129`); no tampered-genesis test |
| F38, F40, F41, F44 | **OPEN** | — | Everything |
| F39 | **FIXED** | `capture.is_allowed_interface` refuses before `dumpcap` runs; two tests | `br-*` also matches non-Docker bridges such as `br-lan` (N15) |
| F42 | **PARTIAL** | CI fails instead of skipping (`skip_or_fail_without_postgres`) | The other seven rows of the F42 table. Some tests still use a plain `pytest.skip` (N3). |
| F43 | **FIXED (diverged, sound)** | Versioned JSONB with a strict codec (`storage/policy_codec.py`), encrypted leaves only; `test_policy_and_consent_survive_a_new_process`, `test_stored_policy_still_requires_attribute_keys` | An HTTP-level `test_read_succeeds_after_facility_restart` |

**Totals:** 4 fixed, 7 partial or diverged, 33 open. No decisions made.

## Status at `a40a5a7` (update, 2026-10-11)

Only `a40a5a7` ("Harden Compose deploy per review") changed code since `4ddc201`. Every item not listed here is unchanged.

| ID | Status | Evidence | What remains |
|---|---|---|---|
| N11 | **FIXED (diverged, sound)** | `bootstrap.run_migrations(reset=True)` refuses any non-loopback / non-socket host in the DSN or `PGHOST`/`PGHOSTADDR`, before connecting (`deploy/bootstrap.py:99-135`); `tests/security/test_deployment_reset_guard.py`. A host check replaces the proposed name check, which a remote DB with the same name would pass (recorded in ADR-0047). | Nothing |
| N12 | **MOSTLY FIXED** | `POSTGRES_HOST_AUTH_METHOD: trust` removed; Compose refuses to start without `POSTGRES_PASSWORD` from the git-ignored `deploy/.env`; `.dockerignore` excludes `**/.env*` | The `portal-compose` entry in `.claude/launch.json` still uses a DSN with no password, so it fails against the new store. Bootstrap doesn't generate the password (it's a manual one-liner in `deploy/README.md`). The proposed test (Compose file has no `trust`) wasn't added. Services still connect as the `postgres` superuser (see F36). |
| N14 | **PARTIAL** | Each container mounts only `wire/certs/<service>/` plus `wire/certs/trust/`, so a compromised service holds only its own TLS key | All five table rows: no `USER` in the Dockerfile; `ENV HOST=0.0.0.0` (`deploy/Dockerfile:29`); `TLS_VERIFY` still wired (`bootstrap._http_verify`, `run_scenario.py:65`); every cert still has `localhost`/`127.0.0.1` SANs (`wire/tls.py:50-51`); four copies of env-flag parsing |
| N2 | **PARTIAL** | A `state_writer` failure is now logged at ERROR, not raised (`audit_client.py:146-161`), so it can't kill the monitor; `test_store_write_failure_after_audit_is_logged_not_raised` | A record can still get stuck in EXPIRED: the EXPIRED mirror succeeds, then the GRANTED append or mirror fails. ADR-0047 says the facility reconciles a stale `emergency_open`, but that is not true for `expired`, and that reconciliation is the unconditional ADR-0044 reset (N1, D7). The retry is not done. |
| F20 | **OPEN** | `expiry.py` untouched | An `audit_logger` HTTP error still ends `_loop`. Only the `state_writer` path is covered (N2). |
| F42 | **PARTIAL** (row 1) | Compose runs the portal with `DJANGO_DEBUG=0` and fixed `DJANGO_ALLOWED_HOSTS` | `portal/config/settings.py:21` still defaults DEBUG on. The other six rows are unchanged. |
| N16 | **PARTIAL** | ADR-0047 decider is now "Avaneeth (proposal); Ojas to review `deploy/` and `wire/`", still **Proposed**; tracker row updated | Owner reviews of 638c2c6 and 9721387; the `PROJECT.md` expiry paragraph (line 287) still has no heading |

---

## Status after the no-decision fix batch (2026-10-11, `443ca0f`)

All of "Fixes that need no decisions" below was implemented in commit
`443ca0f` on `full-deploy` (ADR-0051: across module owners, each owner reviews their
directories before merge). Full suite: 754 passed, 4 strict xfails (C3, C4,
C7, C9, all decision-blocked), 1 failure: the live-capture test, which now
correctly refuses the committed captures because they predate the run stamp
(N5) and must be re-recorded (exit-plan E2). Portal suite: 50 passed.

| ID | Status | What was done | What remains |
|---|---|---|---|
| F1 | **FIXED** (ADR-0048) | Root, facility CAs and revoked serials from facility config; issuer matched to a configured CA; chain/expiry/revocation errors are 403 + denial; trust fields in the request are 422; Compose `pki` job generates the PKI before facilities; facilities refuse to start without anchors | Static serial list, no CRL/OCSP |
| F4 | **FIXED** | Custodian ingests before depositing shares; facility returns 409 on a duplicate id; audit registry and custodian vault never overwrite a share (409); share deposit failure after ingest is 503 `breakglass_provisioned=false` | — |
| F6 | **FIXED** (ADR-0049) | Assertion lifetime ≤ 3 days, `issued_at` ≤ now + 30 s; requested window ≤ 3 days and capped at the configured duration; response returns the real `expires_at` | — |
| F7 | **FIXED** | Parse and validate first; compare-and-set claim; gate; log-before-release; session; event; every failure after the claim undoes it; break-glass needs an expiry manager and a baseline key | — |
| F8 | **FIXED** | Every break-glass refusal (chain, assertion, gate, transition, record not found, patient binding), read-path unwrap failures and emergency search (granted and denied, with `requester_id`) are audited | — |
| F12 | **FIXED** (via N1) | The compare-and-set is now used everywhere | — |
| F14 (interim) | **FIXED** (ADR-0052) | Address allowlist on `/attribute-keys/author`; C10 now holds for any caller outside it | D5-a; Compose host-run scenarios need the bridge gateway in `AUTHORING_CALLERS` |
| F17 | **FIXED** (ADR-0053) | Sign-up records a request only (no profile, no directory row); unissued logins reach no portal; existing subject ids refused | Issuance is still the P2-2 stub |
| F19 | **FIXED** | No audit destination → 503; `AUDIT_SERVICE_URL` required by the facility; tests pass an explicit sink | — |
| F20 | **FIXED** (with N2) | Session claimed as `expiring`, retried with backoff, resumes without re-signing; monitor survives every failure | — |
| F21 | **FIXED** | `consumed_store`, `revoked_serials`, `revocation_registry` are required keyword arguments | — |
| F22 (rest) | **FIXED** (via N13) | Postgres replay test across two facility processes | — |
| F24 / F25 / F26 / F27 | **FIXED** | `crypto_core.types` hints; invariant scans all of `src/`; `secrets` nonces + test; `repr=False` key fields + test; Shamir `x`/`y` range checks in `combine_shares` and the gate | — |
| F30 | **FIXED** | Comment now matches the values (requests 7 days, grants 30) | — |
| F31 | **FIXED** | Floats refused at append (422); custodian verifies each release entry's signature, flow and seq; facility clients refuse a backwards seq | The facility's high-water mark is in memory, not persisted |
| F33 | **FIXED** (listed calls) | Search token via `search.emergency_search_token`; patient hash via `audit.events.patient_id_hash`; read path via `policy.decrypt_record_via_policy`; custodian crypto in new `src/custodian/`; invariant forbids all of them in `api/` | Emergency provisioning is in `custodian`, not `breakglass.provision_emergency_path` (that is F9, D3) |
| F35 / F36 | **FIXED** | `psycopg.sql` composition; `portal_app` role owns the portal schema with no store privileges | — |
| F37 | **FIXED** | Audit verifies the chain at startup (already), writers depend on it, tampered-genesis test | — |
| F38 | **FIXED** | Portal demo runs Path A's processes on fixed ports by default (`run_local.start_federation`); `--in-process` kept for tests | Not run live here: the running Compose stack holds the ports |
| F39 (rest) / F40 | **FIXED** | Docker bridge names matched exactly; §7 now names `wire/captures/` | — |
| F41 | **FIXED** (ADR-0053) | Break-glass acts only on the session's logged-lookup patient; raw `patient_id` is 400 | — |
| F42 | **FIXED** (all rows) | DEBUG off by default; safe `next`; uploads download with `nosniff`; bad id 400; three-state link check; chain-verify DB errors 503; e2e PASS/FAIL/SKIP and 403-only denials | — |
| F43 (rest) | **FIXED** | HTTP-level read after a facility restart on Postgres | — |
| N1 | **FIXED** (ADR-0050) | Compare-and-set for break-glass, revoke, the timer mirror; insert-only ingest; ADR-0044 reset removed (stale `emergency_open` is 409); in-memory CAS keeps `last_event_id`; Postgres concurrency tests | Restart reconciliation is F5 (D7) |
| N2 | **FIXED** | See F20; stuck-in-EXPIRED case retried to GRANTED | Final state still GRANTED (D7) |
| N3 | **FIXED** (ADR-0054) | Status from a run; collection errors void the table; CI-aware skip everywhere; evidence doc regenerated | — |
| N4 | **FIXED** | Scenario sends a revoke; analyser expects `/records/rec-001/revoke`; test with `old_dek_b64` failing claim 1 | Claim 1 fails on plain until D6/F10, as expected |
| N5 | **FIXED** | Old pcap deleted, dumpcap early exit / empty file fails; run stamp; TLS on every port; TLS unlock burst ≥ plain request | Re-record the captures (E2) |
| N6 / N7 / N8 / N9 | **FIXED** | C4 asserts unconditionally; mutation exit codes and green baseline; gap tracking; unsearchable canaries rejected | — |
| N10 | **PARTIAL** | Benchmarks re-run on current code (Python 3.11 image) with `environment.json`; stale `p53_search_leakage.json` removed | Re-run the leakage analysis on a fresh capture (E2) |
| N11 | **FIXED** (`a40a5a7`) | — | — |
| N12 | **FIXED** | No-`trust` test; host-side portal reads the store password from `deploy/.env` | Password generation stays a documented manual step |
| N13 | **FIXED** | See F22 | — |
| N14 | **PARTIAL** | `USER app`; no `ENV HOST`; lone `TLS_VERIFY=false` path removed (only ADR-0042's double gate remains); one `env_flag` | Per-service SANs not changed: host-run TLS scenarios and captures reach services as `localhost`, so dropping that SAN breaks them; needs a decision |
| N15 | **FIXED** (all rows) | Malformed status line; exact bridge names; `--db-port` from `DATABASE_URL`; word-boundary finding match; `policy_codec` type checks + tests; query labels; live test scope `all`; exit-plan TLS row | — |
| N16 | **PARTIAL** | PROJECT.md expiry paragraph is now §5 caveat 6 | Owner reviews of 638c2c6, 9721387 and this batch (ADR-0051) |

## Status on `proposal/review-open-items` (2026-10-15)

On top of `40b13e9` (`proposal/c4-c7-c9-full-fixes`, which closed D1, D3,
D5, D8 and claims C3, C4, C7, C9). D4 was decided by ADR-0064 and D7 by
ADR-0058; this branch implements what they unblocked and takes D11-a.

| ID | Status | What was done | What remains |
|---|---|---|---|
| D11 / F32 | **FIXED** (ADR-0076, D11-a) | Docstrings, ARCHITECTURE §1/§2 C3, PROJECT §5 caveat 8 now say KEM delivery, facility sees the DEK, bidirectional toy PRE; a test shows `rk` inverts | Explainers 05/09 (user's working docs) |
| F10 | **FIXED** (ADR-0080) | Patient-signed `GRANTED -> REVOKED` checked against the patient certificate; owner leaf from the stored tree; facility recovers the DEK through the policy and re-keys with the ADR-0069 rotation (atomic, works on Postgres, new emergency key and shares); `record.revoked` logged before commit; no key or DEK in the body (422 if sent) | Home-authority revocation not wired |
| F13 | **FIXED** (ADR-0080) | `/consent/grants/revoke` (took the patient's private key) removed; a revocation is the signed REVOKED grant; a GRANTED decision on a revoked request is refused (409); consent requests arrive signed and are checked against the clinician certificate | — |
| F15 | **FIXED** (ADR-0082) | Release needs a one-time envelope the credential's subject signed, under a certificate from a configured facility CA; replay refused; mutation C10b | The custodian still holds every subject key (ADR-0043) |
| F5 | **FIXED** (ADR-0081) | Open sessions stored without keys; a restarted facility closes its own with a rotation recovered through the policy; holders accept any later generation | — |
| ADR-0069 residual (crash mid-rotation) | **FIXED** (ADR-0081) | Same recovery finishes it one generation on | — |
| F34 | **FIXED** (by `532e57a`) | BOLA covered by claim C9 (`test_c9_bola_...`) | — |
| N3 follow-up (BG-0001) | **FIXED** | Portal trace test reads the case number from the created case | — |

**Still open:** D2 (share 2), D6 (bodies vs. TLS), D9 (signed-payload
encoding), D10 (credential revocation vs. shared keys), N14 SANs, F31 high-
water mark persistence, static revoked-serial lists (no CRL), clinical labels
readable in the store, portal `TIME_ZONE`, self-registration (ADR-0021).

## Fixes that need no decisions (at `a40a5a7`)

*All implemented in `443ca0f` except the remainders of N10, N14 and N16; see the status table above.*

These items have no **⚑ needs D#** and are still open or partial. Each one can start now. **ADR** still means "write an ADR in the same PR", not "wait for the team".

**Quick (S), in suggested order**

| ID | Fix | Owner |
|---|---|---|
| N6 | Assert unconditionally in the C4 strict-xfail test | Powel |
| N9 | Generate canaries ≥ 16 chars; reject a manifest with an unsearchable canary | Powel |
| N8 | Count gaps per flow; a gap makes claim 1 inconclusive; don't join across gaps | Powel |
| N10 | Re-run benchmarks and leakage, commit with `environment.json` (or delete the stale files) | Nandini |
| N12 (rest) | Fix the `portal-compose` DSN; add the no-`trust` test | Avaneeth |
| N14 (rest) | `USER app`, drop `ENV HOST`, delete `TLS_VERIFY`, per-service SANs, one `env_flag` | Avaneeth |
| N15 | The eight small correctness rows | Powel, Avaneeth, Nandini |
| N7 | Mutation runner: green baseline first; only exit 1 counts as caught | Powel |
| N4 | Revoke step in the scenario; `/revoke` and `old_dek_b64` in the analyser | Powel + Avaneeth |
| N13 | Postgres variant of the C8 restart test | Powel + Avaneeth |
| N16 (rest) | Owner reviews of 638c2c6 / 9721387; heading for the PROJECT.md expiry paragraph | Powel, Avaneeth |
| F19 | `_log_event` raises without an audit sink; `AUDIT_SERVICE_URL` required | Avaneeth |
| F24 | Replace `hazmat` hints with `crypto_core.types`; invariant test scans all of `src/` | Ojas, Powel, Avaneeth |
| F25 | `secrets.token_bytes` for nonces; grep test | Powel |
| F26 | `field(repr=False)` on key fields; repr test | Powel, Avaneeth |
| F27 | Range-check Shamir `x` and `y` | Powel |
| F6 | Bound `emergency_duration_seconds`; assertion `max_ttl` and skew | Avaneeth, Ojas, Powel |
| F8 | Every refusal goes through `_log_denial`; audit emergency search | Avaneeth, Ojas |
| F4 | Reorder ingest before share deposit; 409 on duplicate `record_id`; no share overwrite | Ojas, Avaneeth |
| F14 (interim) | `AUTHORING_CALLERS` allowlist on `/attribute-keys/author` | Ojas |
| F21 | `consumed_store` / `revocation_registry` become required arguments | Powel, Ojas/Avaneeth |
| F42 (rest) | DEBUG default, open redirect, upload `nosniff`, `int()` 400, three-state links, narrow `except`, e2e skip counts | Mixed |
| F30 | Make the consent TTL comment and value agree (owner picks 7 days or 1 year) | Powel |
| F35 | `psycopg.sql` composition in `store_reader.py` | Ojas/Powel |
| F36 | `portal_app` role with no store-table privileges | Avaneeth |
| F31 | Reject non-integer floats; custodian verifies returned entries; facility keeps the last head | Ojas |
| F40 | Pick `bench/captures/` or amend §7 | Ojas |
| F41 | Server-side `LookupSession`; break-glass form posts the lookup id | Nandini |
| F43 (rest) | HTTP-level `test_read_succeeds_after_facility_restart` | Avaneeth |

**Larger (M/L)**

| ID | Fix | Owner |
|---|---|---|
| N3 | Claim status from a real run, not a collection; collection errors are errors; fix C2/C5 evidence | Powel |
| N5 | Delete stale pcaps, check dumpcap exit; tie pcap to manifest; full TLS preconditions | Powel |
| N1 (with F12) | Use the CAS for break-glass, revoke and the timer mirror; insert-only ingest; drop the ADR-0044 write | Avaneeth |
| N2 (rest, with F20) | Claim the session as `expiring`, retry with backoff, resume from the stored state | Powel + Avaneeth |
| F1 · ADR | Trust root and facility CAs from config; drop the PEM fields; chain errors → 403 + denial; revoked serials | Avaneeth, Ojas, Powel |
| F7 | Validate → CAS claim → gate → log → session → one DB transaction; roll back on failure. Needs N1's CAS. | Avaneeth |
| F17 | Require an ISSUED profile; bind `subject_id` at issuance; unique constraint | Nandini, Ojas |
| F37 (rest) | Audit verifies the chain at startup; others depend on it; tampered-genesis test | Ojas |
| F38 | Spawn portal-demo services as processes on fixed ports | Ojas, Avaneeth |
| F33 (part) | Move search-token, hashing and custodian crypto out of `api/`; extend `forbidden_calls`. Emergency provisioning waits for F9 (D3). | Avaneeth, Ojas, Nandini |

**Not on this list, because they wait on a decision:** F2 (D1), F3 (D2), F5 (D7), F9 (D3), F10 (D3, D4), F11 (D7, D8), F13 (D4), F14 proper (D5), F15 (D4), F18 system fix (D6), F23 (D9), F29 (after F23, so D9), F32 (D11), F34 (D5), F44 (D10).

---

## 1. Break-glass gate (the novelty claim)

### F1 — Facility trusts a root CA chosen by the caller · HIGH · Avaneeth (api) + Ojas (deploy) + Powel (breakglass) · ADR · M · **FIXED**
**Status at `443ca0f`:** **FIXED** (ADR-0048). The facility loads the root, facility CAs and revoked serials from config at startup (`load_trust` in `deploy/asgi/facility.py`, `FacilityTrust` in `hospital.py`) and matches the leaf's issuer to a configured CA. `BreakglassUnlockRequest` drops the PEM fields and forbids extras, so a caller still sending them gets 422. Chain, expiry and revocation errors are 403 with a denial logged. `validate_emergency_assertion` takes a required `revoked_serials`. The Compose `pki` job generates the trust anchors, and facilities refuse to start without them. Remaining: a static serial list, no CRL/OCSP.

**Problem.** [hospital.py:861-893](../../src/api/hospital.py) builds `ca_cert` and `root_cert` from
`facility_ca_certificate_pem` / `trusted_root_certificate_pem` in the request
body. An attacker mints their own root and CA plus a `CN=doc-201` leaf and passes
`validate_chain`. `ChainValidationError` / `CertificateExpiredError` are not in the
except list (`:893-899`), so they give a 500 and no denial is logged. No revocation check is made on the clinician cert.

**Fix.**
1. `deploy/asgi/facility.py`: load the trust material at startup. Use `FEDERATION_ROOT_CERT` (PEM path) and `FACILITY_CA_CERTS_DIR` (one PEM per facility, cross-certified per §7 step 2). Fail startup if either is missing.
2. `create_hospital_app(..., trusted_root: Certificate, facility_cas: Mapping[str, Certificate])`. In the handler, pick the intermediate by matching `cl_cert.issuer` to a configured CA subject. Unknown issuer → 403 + `_log_denial(denied_by="breakglass_assertion")`.
3. `api/schemas.py` `BreakglassUnlockRequest`: delete both PEM fields and set `model_config = ConfigDict(extra="forbid")`, so a caller still sending them gets 422 rather than being silently ignored.
4. Add `ChainValidationError`, `CertificateExpiredError` (and the revocation error from step 5) to the except tuple → 403 + denial logged. Use 403, not 400: these are authorization failures.
5. Revocation (Powel, `breakglass/assertion.py`): add a required `revoked_serials: frozenset[int]` argument (loaded from config like the root). Check it after the chain and raise `CertificateRevokedError`.
6. `custodian_service.py:933-936`: stop sending the PEMs.

**Tests (`tests/security/`).**
- `test_breakglass_rejects_assertion_chained_to_attacker_root`: forged root/CA/leaf with a valid signature → 403. Assert lifecycle state unchanged, no transition event, and one denial entry.
- `test_breakglass_rejects_expired_clinician_cert_with_403_and_denial`.
- `test_breakglass_rejects_revoked_clinician_cert`.
- `test_breakglass_request_with_trust_fields_is_rejected` → 422.

### F2 — Audit service releases share 3 to any caller · HIGH · Ojas (audit service) + Avaneeth (schemas) · ⚑ needs D1 · ADR · M
**Problem.** [audit_service.py:227-265](../../src/api/audit_service.py) releases a held share to anyone
who knows the `share_key` (= record_id), with no assertion, signature or
one-time ID. Together with share 1 (custodian), one process can open any
record. This breaks PROJECT §5's "no single shareholder" claim and CONVENTIONS §2
rule 9 (HARD).

**Fix (option D1-a).**
1. Share deposit (`/breakglass/shares`) stores `patient_id` and `home_facility_id` with the share (`audit/share_registry.py`). It refuses to overwrite an existing `share_key` → 409 (see F4).
2. `ReleaseShareRequest` replaces free-form `event_data`/`actor_id` with `assertion: EmergencyAssertion` + `clinician_certificate_pem`.
3. The audit service, at startup, loads the same root, facility CAs and revoked serials as F1. On release, **before** `release_share_after_commit`, it:
   - calls `validate_emergency_assertion(..., expected_facility_id=assertion.facility_id, consumed_store=<persistent store, F22>)`;
   - checks that `assertion.facility_id` is in its configured facility allowlist;
   - checks `assertion.patient_id == stored patient_id`.
4. The event data written to the chain is **derived from the verified assertion**, never from the caller.
5. Every refusal is appended as a denial entry, then 403.

**Residual (paper).** The custodian holds every clinician's signing key (ADR-0043), so it can still mint valid assertions. That is the custodial trust assumption. State it; it can't be closed without client-held keys.

**Tests.** `test_audit_share_not_released_without_valid_assertion` (no assertion / forged signature / wrong patient / replayed / revoked cert): no `share_hex` in the response and only a denial entry added. Also `test_single_share_holder_cannot_open_record` (existing exit criterion; extend it to call the HTTP service).

### F3 — Share 2 is generated and discarded · MED · Ojas (authority service) + Avaneeth · ⚑ needs D2 · ADR · M/L
**Problem.** `custodian_service.py:764` discards `_share2`, so the scheme is effectively 2-of-2.

**Fix (D2-a).**
- `authority_service.py` gets `/breakglass/shares` and `/breakglass/release`, with the same validation as F2. Its release logs through the audit service so the chain still records it.
- The custodian deposits share 2 at the patient's `owner_authority_id`.
- At break-glass, the custodian asks audit first and the home authority as fallback (§5 "or its federated delegate"). Two of the three shares are presented.

**(D2-b)** Instead: amend ARCHITECTURE §5, PROJECT §5 and the paper to say 2-of-2.

### F4 — Ingest with an existing `record_id` overwrites shares · HIGH · Ojas (custodian) + Avaneeth (ingest endpoint) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** The custodian ingests at the facility before depositing shares. A duplicate `record_id` is 409 (`RecordExistsError` from the unique violation). The audit `ShareRegistry.put` and the custodian vault refuse to overwrite a share (409). A deposit failure after ingest is 503 with `breakglass_provisioned=false`.

**Problem.** `custodian_service.py:753-771` deposits share 3 and share 1 **before** the facility ingest. A duplicate `record_id` makes the ingest 500, but the old shares are already replaced, and break-glass on that record is broken for good.

**Fix.**
1. Reorder: generate key → facility ingest → deposit share 3 → `vault.put_share`.
2. `hospital.py` ingest: catch the unique violation from `insert_record` → **409**. (Better: `repo.record_exists()` first, *and* rely on the PK.)
3. `vault.put_share` and the audit `register_share` refuse to overwrite (409). Replacement is only allowed through the authenticated re-key operation from F9/F10.
4. If share deposit fails after the ingest succeeded: return 503 with `breakglass_provisioned=false` and log it. Don't leave it silent.

**Test.** `test_ingest_with_existing_record_id_leaves_shares_intact`: break-glass on the original still works afterwards.

### F5 — ADR-0044 state reconciliation · HIGH · Avaneeth (api) + Powel (lifecycle) + Avaneeth (storage) · ⚑ needs D7 · ADR (supersede part of 0044) · M
**Status at `4ddc201`:** **DIVERGED (not sound).** The timer got `state_writer=repo.upsert_lifecycle_state` (`deploy/asgi/facility.py:61`): unconditional, always ends at GRANTED. The ADR-0044 reset is still at `hospital.py:199-227`. No sessions table or restart reconciliation. See N1, N2.

**Problem.** `_effective_lifecycle_state` ([hospital.py:199-227](../../src/api/hospital.py)) writes
`granted` (unsigned, `last_event_id=None`) whenever *this* process holds no session. Three consequences:
- It races with another facility's live session.
- It runs before the share check, so a request with bad shares still changes state.
- It always writes `granted`, which undoes a revocation.

**Fix.** Remove the cause rather than patching the symptom:
1. **Keep** ADR-0044's patient-binding check (it's correct). **Reject** the reconciliation half.
2. The expiry manager gets a `state_writer` callback, like `audit_logger`. It persists `EXPIRED` and then the session's `prior_state` with `last_event_id` through the CAS in F12, so the store is never stale.
3. New table `emergency_sessions(record_id PK, facility_id, opened_event_id, expires_at)` (storage migration; **no key material**). It is written at open and deleted at expiry.
4. On facility startup, reconcile **only rows where `facility_id` = self**. These are sessions whose keys were lost when the process restarted. The timer key signs `EMERGENCY_OPEN → EXPIRED → prior_state` with reason `expired_without_rotation`, and an audit entry is written. This fails closed: the record is no longer open.
5. `_effective_lifecycle_state` becomes a plain read.

**Tests.**
- `test_facility_b_breakglass_does_not_reset_facility_a_live_session` → 409.
- `test_bad_shares_do_not_change_lifecycle_state`.
- `test_expiry_after_breakglass_on_revoked_record_returns_to_revoked`.
- `test_restart_reconciles_only_own_sessions`.

### F6 — Time-box and assertion lifetime unbounded · MED · Avaneeth (schemas, api) + Ojas (custodian schemas) + Powel (assertion) · S · **FIXED**
**Status at `443ca0f`:** **FIXED** (ADR-0049). `validate_emergency_assertion` enforces `max_ttl` = 3 days and rejects an `issued_at` more than 30 s in the future (`AssertionLifetimeError`), before the assertion is consumed. `emergency_duration_seconds` is `gt=0, le=3 days` and capped at the facility's configured window. The response returns the real `expires_at`. Custodian TTLs are capped at 3 days.

**Problem.** `emergency_duration_seconds` (`schemas.py:195`, `custodian_schemas.py:207`) has no bound and overrides `EMERGENCY_DURATION_SECONDS`. A huge value raises `OverflowError` → 500 after state is written. Assertion `expires_at` has no maximum, and `issued_at` is not checked (`assertion.py:270`).

**Fix.**
- Schemas: `Field(default=None, gt=0, le=86_400)`.
- Facility: `effective = min(requested or configured, configured)`, so a caller can only **shorten** it. §7 says the time-box is configuration.
- `assertion.py`: add `max_ttl: timedelta` (config, default 300s) and `clock_skew` (30s). Reject when `expires_at - issued_at > max_ttl` or `issued_at > now + skew`.
- `custodian_schemas.assertion_ttl_seconds`: `le=300`.

**Tests.** `test_breakglass_duration_cannot_exceed_configured`, `test_assertion_with_ten_year_lifetime_rejected`, `test_future_dated_assertion_rejected`.

### F7 — Break-glass leaves side effects on failure; open requests race · MED · Avaneeth (api) · M · **FIXED**
**Status at `443ca0f`:** **FIXED.** The break-glass handler parses and validates everything first, claims the state with a compare-and-set, then runs the gate, logs, registers the session and writes the event. Any failure after the claim unregisters the session and rolls the state back. Break-glass needs an expiry manager and a baseline key (503 otherwise), and a second open is 409.

**Problem.** [hospital.py:1005-1057](../../src/api/hospital.py) persists `EMERGENCY_OPEN` + the transition event, then registers the session, then logs the rewrap. An audit outage (503) or a session failure therefore leaves the record open with no timer. A missing `baseline_wrapping_key_b64` or expiry manager silently skips the time-box. The read at `:954` and the write at `:1005` are not atomic.

**Fix.** New order: validate everything (including decoding the baseline key) → CAS-claim the state (F12) → gate → `_log_rewrap` (log-before-release) → `register_session` → persist state + event **in one DB transaction** → respond.
- Any failure after the claim rolls the claim back, and unregisters the session if one was registered.
- A missing expiry manager → **503 at startup**, not a silent skip. The baseline key is no longer a caller input (see F9).

**Tests.** `test_audit_outage_during_breakglass_leaves_state_unchanged`, `test_breakglass_without_expiry_manager_refused`, `test_concurrent_breakglass_one_wins` (two threads → one 200, one 409).

### F8 — Several denials are never audited · MED · Avaneeth (api) + Ojas (event types) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Every break-glass refusal (chain, assertion, gate, transition, record not found, patient binding), every read-path unwrap failure and every revoke refusal goes through `_log_denial`. Emergency search is audited when granted and when denied (`ACCESS_VIA_EMERGENCY_SEARCH`, required `requester_id`).

**Problem.** Not audited:
- `InsufficientSharesError`, `UnwrappingError`, `IllegalTransitionError` ([hospital.py:993-1002](../../src/api/hospital.py)).
- Record-not-found.
- The chain errors (F1).
- `UnwrappingError` on the read path (`:582`, `:610`).
- `/emergency-search` (`:1119`): no caller identity, no event.

**Fix.**
- Route every refusal through `_log_denial` with a distinct `denied_by` (`breakglass_gate`, `breakglass_transition`, `record_not_found`, `dek_unwrap`).
- `EmergencySearchRequest` gains `requester_id` + `correlation_id`. Log granted and denied searches (`access_via="emergency_search"`; Ojas adds the constant to `audit.events`). After D5 the identity comes from the envelope, not the body.

**Test.** Parametrised `test_every_breakglass_refusal_appends_one_denial`.

---

## 2. Revocation, expiry, lifecycle

### F9 — Expiry "forced rotation" is computed and thrown away · HIGH · Powel (lifecycle) + Avaneeth (api, storage) + Nandini (search re-key) + Ojas (custodian/audit share replace) · ⚑ needs D3 · ADR · L
**Status at `4ddc201`:** **OPEN.** Strict xfail `test_c4_pre_expiry_shares_do_not_restore_search`; ADR-0047 defers it. That test is itself vacuous (N6).

**Problem.**
- `ExpiryResult.rotated_record` / `rotated_wrapping` (`expiry.py:396-443`) are never persisted.
- The custodian sends a random `baseline_wrapping_key` (`custodian_service.py:946`), so even the computed rotation is useless.
- Old shares, the emergency wrapping and the search tokens all survive expiry. This breaks §5 step 7 and C12, and violates the exit criterion "a search token does not work once the emergency state has expired".

**Fix (D3-b).** The building block is shared with F10, so build it once.
1. New `breakglass.provision_emergency_path(dek, record_id) -> (emergency_wrapping, shares)`. It is the existing `generate_emergency_key` + `split_emergency_key` + `wrap_dek(wrapped_for="emergency")`, just moved out of `api/` (also fixes F33).
2. On expiry, the expiry manager calls back into the facility: provision a new emergency path for the session's DEK, then **replace** the emergency wrapping (storage: `replace_wrapping(record_id, wrapped_for, expected_generation)`, with UPDATE … WHERE generation = expected). Then:
   - **replace** share 3 at audit and share 1 at the custodian. This is an authenticated re-key operation (D5), the only path allowed to overwrite (F4);
   - re-key the search index under the new emergency key (Nandini's P3-9 re-key function).
3. Remove `baseline_wrapping_key_b64` from the API. It is not a real key.
4. Under (D3-a) a DEK rotation step is added later. Until then, the paper's limitation says expiry revokes the *emergency capability*, not the DEK.

**Tests.** `test_old_shares_do_not_open_record_after_expiry`, `test_search_token_dead_after_expiry` (exit criterion, HTTP-level), `test_second_breakglass_after_expiry_uses_new_shares`.

### F10 — Revoke endpoint: 500 on Postgres, spoofable authz, bypasses the state machine, no audit · HIGH · Avaneeth (api, storage, `records/revocation.py`*) + Powel (lifecycle) · ⚑ needs D4, D3 · ADR · L
\*`git log` shows `records/revocation.py` authored by Avaneeth; `WORKFLOW.md` lists P3-7 under Powel. Confirm the owner.

**Problem.**
1. `repo.insert_record` re-inserts the same PK ([hospital.py:825](../../src/api/hospital.py), [repositories.py:23](../../src/storage/repositories.py)) → UniqueViolation → 500. Nothing is persisted.
2. `actor_id` and `owner_authority_id` both come from the request (`revocation.py:121`), so anyone holding the DEK can authorize themselves.
3. `GRANTED → REVOKED` is hard-coded (`revocation.py:286`). The current state is never read, so EMERGENCY_OPEN→REVOKED and REVOKED→REVOKED get persisted.
4. No audit entry on success (§5 revocation step 4).
5. The emergency wrapping still wraps the *old* DEK, so break-glass on a revoked record unwraps a key that no longer matches the ciphertext.

**Fix.**
1. Storage: `rotate_record(conn, rec, new_policy_wrapping, expected_generation)`. One transaction: `UPDATE records SET ciphertext, nonce, policy_id, created_at … WHERE record_id = %s`, delete the superseded policy wrapping, insert the new one, `WHERE generation = expected` → 0 rows = 409.
2. Authorization: the request is a patient- or home-authority-signed revocation (`RequestEnvelope`, operation `record.revoke`). The facility verifies it against the patient cert (D4) or the authority key from config. **Delete** `actor_id` / `owner_authority_id` as trusted inputs; `owner_authority_id` comes from the record's stored owner leaf.
3. `revoke_record_access(..., current_state)` calls `validate_transition(current_state, REVOKED)`. The facility applies it through F11's helper.
4. Log-before-commit: append the `record.revoked` audit event (the payload already exists as `audit_payload`) before writing the store.
5. Call `provision_emergency_path` (F9) for the new DEK so break-glass on a revoked record works.

**Tests.**
- `test_revocation_persists_on_postgres` (real-DB test, not in-memory).
- `test_revoked_reader_cannot_decrypt_after_rewrap` over HTTP + Postgres.
- `test_revoke_by_non_owner_with_spoofed_actor_fails`.
- `test_revoke_from_emergency_open_rejected`.
- `test_breakglass_on_revoked_record_opens_rotated_ciphertext`.

### F11 — Transitions bypass the state machine; break-glass events are unverifiable · HIGH · Avaneeth (api) + Powel (breakglass gate, lifecycle) · ⚑ needs D7, D8 · ADR · M
**Problem.**
- `apply_transition` is only called inside `expiry.py`.
- Break-glass transitions are signed with a throwaway key (`custodian_service.py:926`), and nothing verifies them.
- Expiry always ends at `GRANTED`.

**Fix.**
1. New facility helper `_apply_and_persist(repo, record_id, event, signer_public_key)`:
   - reads the state with `SELECT … FOR UPDATE`;
   - runs `LifecycleStateMachine.apply_transition` (signature, legality, from-state, one-time id);
   - persists through F12's CAS;
   - is used by break-glass, revoke, expiry and the F5 restart reconciliation.
2. D8-a: `open_emergency_access` takes a **pre-signed** `TransitionEvent` instead of `lifecycle_signing_key`. The custodian builds and signs it with the clinician key internally, and the facility verifies it against the F1-validated cert. Remove `lifecycle_signing_key_pem` from the API (this also removes a private key from the wire, which F18 needs).
3. D7-a: add `(EXPIRED, REVOKED)` to `LEGAL_TRANSITIONS`. `EmergencySession.prior_state` drives the final transition.

**Tests.** `test_transition_event_with_invalid_signature_rejected` (exit criterion, at the HTTP level), `test_illegal_transition_rejected` (EMERGENCY_OPEN→REVOKED), `test_replayed_transition_event_rejected`.

### F12 — No compare-and-set on lifecycle state; `ConsumedEventIds` unlocked · MED · Avaneeth (storage) + Powel (lifecycle) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Via N1: every lifecycle write now goes through `transition_lifecycle_state` (compare-and-set).

**Status at `4ddc201`:** **PARTIAL (overclaimed by 638c2c6).** `transition_lifecycle_state` and the `ConsumedEventIds` lock exist with unit tests, but **nothing in production calls the CAS**. See N1.

**Problem.** `upsert_lifecycle_state` ([repositories.py:270](../../src/storage/repositories.py)) overwrites unconditionally, so two concurrent transitions can both succeed. `ConsumedEventIds` (`state_machine.py:232`) has no lock, unlike `breakglass/replay.py`.

**Fix.**
- `transition_lifecycle_state(conn, record_id, expected, new, last_event_id) -> None`: run `UPDATE lifecycle_state SET … WHERE record_id=%s AND state=%s`, and raise `StateConflictError` when rowcount is 0. The API maps that to 409.
- Keep `upsert` only for ingest (insert-only).
- Add `threading.Lock` to `ConsumedEventIds`, mirroring `_ConsumedIdStore`.

**Test.** `test_concurrent_transitions_from_same_state_exactly_one_succeeds` (Postgres).

### F13 — Consent revocation is enforced only by the portal · HIGH (HARD: CLAUDE.md / ADR-0014) · Avaneeth (api) + Powel (consent) + Ojas (portal text) · ⚑ needs D4 · M
**Status at `4ddc201`:** **PARTIAL.** Postgres `store_consent_grant` is now an upsert by `grant_id`. The facility still never reads stored grants and still takes the patient key from the caller.

**Problem.**
- The facility checks only the grant the caller presents ([hospital.py:517-543](../../src/api/hospital.py)).
- It verifies that grant with a **caller-supplied** patient public key.
- `grant.patient_id` is never compared with the record.
- Stored grants are never read back. Only `clinician/views.py:546` refuses a revoked grant.
- `test_phase3_consent_security.py:292` presents the REVOKED grant, so it can't catch a stale GRANTED one.
- The UI texts ("facility now refuses") are false.

**Fix.**
1. The facility looks up the **latest stored version** of `grant.grant_id` (`store_consent_grant` becomes an upsert by grant_id) and requires its status to be `GRANTED`. The presented copy must match it byte for byte.
2. The patient key comes from the patient cert (D4). Remove `patient_public_key_pem` from `ReadRecordRequest` and `SubmitConsentGrantPayload`.
3. `authorize_read` (consent, Powel) adds `grant.patient_id == record.patient_id` → `ConsentSubjectError`.
4. `submit_grant`/`revoke_grant`: the revocation is signed by the patient (D4); the facility no longer receives the patient **private** key (`revoke_grant` takes `patient_signing_key_pem` today: a private key on the wire, see F18).
5. Fix the test: after revocation, present the **old GRANTED** grant and expect 403.
6. Fix the UI texts only once the facility actually refuses.

**Tests.** `test_stale_granted_grant_refused_after_revocation`, `test_self_signed_grant_with_attacker_key_refused`, `test_grant_for_other_patient_refused`.

---

## 3. Key release and identity

### F14 — `/attribute-keys/author` hands out keys with no authentication · HIGH · Ojas (authority service) · ⚑ needs D5 (interim fix needs nothing) · ADR · S→M · **INTERIM FIX**
**Status at `443ca0f`:** **INTERIM FIX** (ADR-0052). `/attribute-keys/author` only answers callers listed in `AUTHORING_CALLERS` (default loopback; Compose: `custodian,bootstrap`). Host-run scenarios against Compose need the bridge gateway in the list (`deploy/README.md`). Remaining: the proper fix (D5-a).

**Problem.** [authority_service.py:247-262](../../src/api/authority_service.py) returns
`authority.attribute_key(name, value)`, the same key `/release` gates. One
unauthenticated POST for `owner:pat-101` reads every one of Alice's records.

**Fix.**
- **Interim:** an allowlist of authoring callers by bootstrap-issued service identity. Until D5-a exists, refuse unless the request comes from an address in `AUTHORING_CALLERS` (loopback / Compose service names). Ship with F16.
- **Proper (D5-a):** require a `RequestEnvelope` (operation `attribute_key.author`) signed by a facility or custodian service cert, plus a consumed `request_id`.
- **Document:** under ADR-0026 an *author* necessarily gets the holder key, so authoring callers are trusted parties. Say so in ADR-0039/0043.

**Test.** `test_author_endpoint_refuses_unauthenticated_caller`.

### F15 — Attribute key released for a credential without proof of possession · HIGH · Ojas (authority) · ⚑ needs D4 · ADR · M
**Problem.** `authority/issuance.py:197-224` releases a key to whoever presents a validly signed credential. Credentials are public signed data, so a copy is enough.

**Fix.** `/attribute-keys/release` takes a `RequestEnvelope` (existing contract and `create_request_envelope` / `verify_request_envelope`), where:
- `caller_id == credential.subject_id`;
- `recipient_id == authority_id`;
- `operation == "attribute_key.release"`;
- `body` = the canonical credential bytes.

The authority verifies the envelope against the subject's cert (clinician: existing PKI; patient: D4) and consumes the `request_id`. No new construction is involved.

**Test.** `test_copied_credential_without_subject_signature_gets_no_key`, `test_replayed_release_envelope_rejected`.

### F16 — Services listen on all interfaces; Compose publishes every port · HIGH · Ojas (deploy) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Fixed in `3c42094...4ddc201`: services bind to `127.0.0.1` by default and Compose publishes ports on `127.0.0.1` only. `443ca0f` dropped the Dockerfile's `ENV HOST=0.0.0.0` (N14).

**Status at `4ddc201`:** **FIXED.** `entrypoint.py` defaults to `127.0.0.1`; Compose ports bound to `127.0.0.1:`; `tests/deploy/test_bind_address.py`. The Dockerfile's `ENV HOST=0.0.0.0` still overrides it for a plain `docker run` (N14).

**Problem.** `deploy/entrypoint.py:44` defaults `HOST` to `0.0.0.0`; `run_local.py` never sets it; `docker-compose.yml` publishes 8010, 8011, 8020, 8001, 8002 and 8030 on every interface. §8 drops authentication *because* there is "no public exposure".

**Fix.**
- Default `HOST=127.0.0.1` in `entrypoint.py`. Compose sets `HOST=0.0.0.0` explicitly (needed inside the bridge).
- In Compose, **remove** `ports:` for audit, authority, facilities and custodian (bridge-internal only), or publish as `"127.0.0.1:8030:8030"` where host access is needed. The Docker-bridge capture is unaffected.

**Test.** A deploy smoke test asserting each service's bind address is loopback on Path A.

### F17 — Self-registration can claim an existing identity · HIGH · Nandini (accounts) + Ojas (portal_core) · M · **FIXED**
**Status at `443ca0f`:** **FIXED** (ADR-0053). Sign-up records a `RegistrationRequest` only (no profile, no directory row) and refuses an existing subject id. Portals require an issued profile (`is_issued` in `portal_core/access.py`). Remaining: issuance itself is still the P2-2 stub.

**Problem.** `accounts/views.py:53-63, 104-110` binds whatever `patient_id` or `clinician_id` the visitor types and logs them in at once. Nothing in the portal checks `RegistrationRequest.status`, so the first person to register `doc-201` acts as that clinician through the custodian. That breaks ADR-0014.

**Fix.**
1. `role_required` (`portal_core/access.py`) also requires an **ISSUED** status for the profile. Seeded accounts are created as ISSUED. Unissued users get a "pending approval" page, and **no custodian call** is made.
2. The `subject_id` is bound at **issuance** by the admin, not at sign-up. Sign-up records it only as *requested*.
3. Add a unique constraint on `Profile.subject_id`.

**Test.** `test_unissued_registration_cannot_reach_custodian` (assert the custodian client is never called), `test_registering_existing_subject_id_rejected`.

---

## 4. Required course module (Traffic Analysis, PROJECT §4A)

### F18 — Analyser asserts none of the four properties, and property 1 is currently false · HIGH (HARD: PROJECT §4A) · Ojas (wire, per WORKFLOW; `analyze_traffic.py` was authored by Nandini) + everyone (D6) · ⚑ needs D6 · ADR · L
**Status at `4ddc201`:** **PARTIAL.** Analyser asserts all four properties (canaries in raw, hex and base64, key denylist, claim 2 through the Postgres COMMIT frame, non-zero exit). The system fix is blocked on D6, and it has never been run on real captures. See N4, N5, N8, N9.

**Problem.** `wire/analyze_traffic.py` counts packets and URIs, uses bare `assert` (stripped by `-O`), and prints "PASSED". On the plain profile the following do cross the wire in the clear:
- `plaintext_b64` (read and ingest);
- `emergency_key_b64` (ingest);
- attribute keys (`holder_keyring`, `attribute_keyring`, `/author` responses);
- `share_hex`;
- `lifecycle_signing_key_pem` and `patient_signing_key_pem` (private keys).

**Fix — analyser** (independent of D6; it should **fail today**, which is the point):
- **P1, no secrets on the wire.**
  - The scenario seeds every record with a unique canary string, and writes the canaries plus the emergency keys, DEKs and shares it generated to a git-ignored sidecar `bench/captures/<run>.secrets.json`.
  - The analyser reassembles each TCP stream on the service ports and searches the raw payload for every secret in raw, hex and base64 form (all three base64 alignments).
  - It also flags a denylist of JSON keys: `plaintext_b64`, `emergency_key_b64`, `share_hex`, `key_b64`, `*_signing_key_pem`, `holder_keyring`, `attribute_keyring`, `old_dek_b64`.
- **P2, commit before release.** For each `/breakglass/release` exchange, find the audit service's Postgres `INSERT INTO audit_log` + `COMMIT` on the DB port (pyshark `pgsql` dissector). Assert its frame time is earlier than the HTTP response frame that carries the share. Capture must include the DB port.
- **P3, leakage measured.** Per search request, record the token (opaque bytes, hashed), request and response sizes, result count and timing. Write a CSV to `bench/results/`, and assert it is non-empty and covers every search in the scenario. Report repeated tokens as search-pattern leakage.
- **P4, break-glass visible as metadata only.** Assert the break-glass URIs are visible, and that the emergency key is absent per P1.
- Replace bare `assert` with explicit checks that print which property failed and exit non-zero. Add `tests/wire/test_analyzer.py` running against a small committed fixture pcap: one clean, one with a planted secret that must fail.

**Fix — system:** D6-a (client-side crypto, shares delivered wrapped to the recipient), or D6-b with the narrowed claim written into PROJECT §4A and the paper. F11 (no signing key on the wire) and F13 (no patient private key on the wire) remove the private keys under either option.

### F39 — Capture accepts any interface · LOW (CLAUDE.md capture rule) · Ojas · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** The interface check before `dumpcap` landed in `3c42094...4ddc201`. `443ca0f` matches Docker bridges exactly (`br-[0-9a-f]{12}`).

**Status at `4ddc201`:** **FIXED.** `capture.is_allowed_interface` refuses before `dumpcap` runs; two tests. `br-*` also matches non-Docker bridges (N15).

**Fix.** `wire/capture.py --interface` accepts only a loopback adapter (`lo`, `\Device\NPF_Loopback`, "Adapter for loopback traffic capture") or a Docker bridge (`docker0`, `br-*`). Anything else exits 2 with the rule quoted. Test the allowlist function.

### F40 — Capture path / `bench/` · LOW · Ojas · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** ARCHITECTURE §7 now names `wire/captures/`.

**Fix.** Write PCAPs to `bench/captures/` as §7 says (or amend §7 to `wire/captures/`). `bench/` being empty is a phase item (D4 deliverable), not a bug.

---

## 5. Fail-closed and audit plumbing

### F19 — `_log_event` silently does nothing without an audit sink · MED (HARD: §2 rule 6) · Avaneeth (api) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `_log_event` raises `AuditServiceError` (503) when no audit URL, logger or sink is configured. The facility requires `AUDIT_SERVICE_URL`. Tests pass an explicit `RecordingAuditSink`.

**Problem.** [hospital.py:179-196](../../src/api/hospital.py) falls through with no `else`. `AUDIT_SERVICE_URL` is optional in `facility.py`, so reads return plaintext with nothing logged.

**Fix.** Add `else: raise AuditServiceError("no audit sink configured")`. `facility.py`: make `AUDIT_SERVICE_URL` required (fail at startup). Tests that want no audit pass an explicit in-memory sink.

**Test.** `test_read_without_audit_sink_returns_503_not_plaintext`.

### F20 — One exception kills the expiry monitor for good · MED · Powel (lifecycle) · M · **FIXED**
**Status at `443ca0f`:** **FIXED.** The expiry manager claims a session as `expiring`, retries a failed expiry with backoff (1 s, doubling to 60 s) and resumes without re-signing. The monitor loop logs and survives every exception (`lifecycle/expiry.py`).

**Problem.** `check_and_expire_due` (`expiry.py:445`) catches only `SessionNotFoundError`. An `audit_logger` HTTP error ends `_loop`, and the session was already deleted at claim (`:357`), so it is never retried.

**Fix.**
- Claim by marking the session `expiring` instead of deleting it.
- On failure, put it back with a retry count and backoff, and log at ERROR with `record_id` only.
- `_loop` wraps each sweep in `try/except Exception` with a comment saying why swallowing is correct here: the loop must survive, and the failed item is retried.
- Access stays closed meanwhile, because `get_active_emergency_key` already refuses past `expires_at`.

**Test.** `test_monitor_survives_audit_outage_and_retries`.

### F21 — Optional arguments that skip security checks · MED (§2 rule 6) · Powel (assertion, envelopes) + Ojas/Avaneeth (credential lifecycle, P2-6) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `consumed_store`, `revoked_serials` and `revocation_registry` are required keyword arguments (`breakglass/assertion.py`, `breakglass/envelopes.py`, `authority/issuance.py`); `tests/security/test_required_security_args.py`.

**Problem.** `consumed_store=None` skips the replay check (`assertion.py:197`, `envelopes.py`). `revocation_registry=None` skips the revocation check (`verify_credential`).

**Fix.** Make them required keyword arguments with no default. Callers that don't care pass a fresh store or an empty registry explicitly.

**Test.** A signature test (`inspect.signature`) asserting there is no default.

### F22 — Replay stores are in memory only · MED · Powel (breakglass) + Avaneeth (storage migration) · M · **FIXED (facility)**
**Status at `443ca0f`:** **FIXED (facility).** The facility's persistent replay store landed in `3c42094...4ddc201`. `443ca0f` added the Postgres test across two facility processes (N13). Remaining: the audit and authority consumers, which come with F2 and F15.

**Status at `4ddc201`:** **FIXED (facility only).** Migration `0002_consumed_ids.sql` + Postgres backend wired in `facility.py`; C8 system test. The Postgres variant of the test is missing (N13); the audit and authority consumers wait on F2 and F15.

**Problem.** `ConsumedAssertionIds()` lives in the process (`hospital.py:425`). A restart reopens replay for any unexpired assertion.

**Fix.** New table `consumed_ids(kind text, id uuid, consumed_at timestamptz, PRIMARY KEY (kind, id))`. Add a `PostgresConsumedIds(kind)` with the same `consume()` interface: `INSERT … ON CONFLICT DO NOTHING`, and rowcount 0 → `ReplayedAssertionError`. The facility, the audit service (F2) and the authority (F15) all use it.

**Test.** `test_assertion_replay_rejected_across_app_restart`.

### F31 — Audit chain edge cases · LOW · Ojas (audit) + Ojas (custodian) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Audit append rejects floats (422). The custodian verifies each release entry's signature, correlation and seq (`verify_entry_signature`). Facility audit clients refuse a backwards seq. Remaining: the facility's high-water mark is in memory, not persisted.

**Problem.** A float like `1e20` changes form after a jsonb round-trip and raises a false `TamperedEntryError`. Deleting the last entries goes undetected, and the custodian never verifies the entry it gets back (`custodian_service.py:900`).

**Fix.**
- `_canonical_event` rejects non-integer floats (raise at append).
- The custodian verifies the returned entry's signature with the audit service public key (config), and checks `seq` against the last seq it saw.
- The facility persists the last chain head it observed and refuses to accept a lower `seq` (a lightweight external anchor).

**Test.** `test_float_event_data_rejected_at_append`, `test_truncated_chain_detected_by_custodian`.

---

## 6. Cryptographic hygiene (core modules)

### F23 — Ambiguous signed payloads; no domain separation · MED · Powel (crypto_core, breakglass, lifecycle, consent) + Ojas (audit, authority) · ⚑ needs D9 · ADR · M
**Problem.** Seven modules join fields with `_FIELD_SEPARATOR` (`0x1f`), and `Identifier` allows `0x1f`. In `consent/service.py:97`, grantee `"dr\x1frec-9"` with scope `("rec-1",)` produces the same signed bytes as grantee `"dr"` with scope `("rec-9","rec-1")`. The same clinician key signs assertions and transition events with no type tag.

**Fix (D9-a).**
- Add `crypto_core.encoding.canonical_fields(domain: str, fields: Sequence[bytes | Sequence[bytes]]) -> bytes`. It writes the domain tag, then each field as a 4-byte big-endian length + bytes; nested sequences are a count + length-prefixed items.
- Domain tags: `custos/v1/emergency-assertion`, `…/transition-event`, `…/consent-request`, `…/consent-grant`, `…/credential`, `…/request-envelope`, `…/audit-entry`.
- Replace every `_FIELD_SEPARATOR.join`, and delete the unused one in `gate.py`.
- Every signature changes, which is fine because every run is a fresh bootstrap (ADR-0039).

**Tests.** `test_grant_field_boundary_unambiguous` (the example above must produce different bytes), `test_assertion_signature_not_valid_as_transition_signature`.

### F24 — `hazmat` imported outside `crypto_core` · HARD (CLAUDE.md, §2 rule 1) · Ojas (audit ×3) + Powel (gate, expiry) + Avaneeth/Powel (revocation) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Type hints use `crypto_core.types` instead of `hazmat` in `audit/` (3 files), `breakglass/gate.py`, `lifecycle/expiry.py` and `records/revocation.py`. The invariant test scans all of `src/`.

**Problem.** [chain.py:31](../../src/audit/chain.py), `audit/events.py:55`, `audit/share_custody.py:27`, [gate.py:62](../../src/breakglass/gate.py), [expiry.py:47](../../src/lifecycle/expiry.py), [revocation.py:44](../../src/records/revocation.py).

**Fix.** Replace `ec.EllipticCurvePrivateKey` / `ec.EllipticCurvePublicKey` hints with `crypto_core.types.ECPrivateKey` / `ECPublicKey`. Extend the invariant test to scan **all of `src/`** except `crypto_core`, not just `api/`.

### F25 — Nonces from `os.urandom` · HARD, minor (§2 rule 2) · Powel · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `crypto_core/symmetric.py` draws nonces from `secrets.token_bytes`, with a grep test.

**Fix.** `crypto_core/symmetric.py:51` → `secrets.token_bytes(num_bytes)`. Add a grep-style test forbidding `os.urandom` / `random.` in `src/`.

### F26 — Keys printed by default `repr` · LOW (§2 rule 3) · Powel (gate, expiry) + Avaneeth (ingest, revocation) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Key fields of `EmergencyUnlockResult`, `EmergencySession`, `IngestResult` and `RevocationResult` are `field(repr=False)`; `tests/security/test_key_reprs.py`.

**Fix.** `field(repr=False)` on:
- `EmergencyUnlockResult.emergency_key` and `.rewrapped_dek`;
- `EmergencySession.emergency_key` and `.baseline_wrapping_key`;
- `IngestResult.root_secret` and `.search_tokens`;
- `RevocationResult.new_root_secret`.

**Test.** `test_result_reprs_contain_no_key_bytes` (assert the hex and base64 of each key are absent from `repr()`).

### F27 — Shamir share index not range-checked · LOW · Powel (shamir) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `combine_shares` checks `1 <= x < P` and `y < P` (`InvalidShareError`), and the gate range-checks `x` before counting. The docstring now says P is prime but not a safe prime.

**Problem.** `x` and `x+P` pass the duplicate check and the gate's `unique_by_x`, then raise a bare `ValueError`. `x=0` (where the secret sits) and `y ≥ P` are accepted. The docstring calls P a "safe prime".

**Fix.** In `combine_shares` (and the gate before counting), require `1 ≤ x < P` and `0 ≤ y < P`, else `InvalidShareError`. Fix the docstring ("prime", 257-bit).

**Test.** `test_share_index_aliasing_rejected`, `test_share_at_x_zero_rejected`.

### F29 — DEK wrapping AAD binds only `record_id` · LOW · Avaneeth (records) · S · ADR (construction parameter)
**Problem.** `records/service.py` `wrap_dek` binds only `record_id`, so an old-generation wrapping can be swapped back in (rollback).

**Fix.** AAD = `canonical_fields("custos/v1/dek-wrap", [record_id, wrapped_for, generation])` (after F23).

**Test.** `test_old_generation_wrapping_does_not_unwrap_as_current`.

### F30 — Consent TTL comment wrong · LOW · Powel · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** The comment now matches the values (requests 7 days, grants 30).

**Fix.** `consent/service.py:38`: the comment says one year and the value is 7 days. Make them agree, and decide which is intended.

### F32 — PRE docstrings overstate the scheme · LOW · Ojas (pre) + Powel (gate) · ⚑ needs D11 · S
**Fix (D11-a).** Correct the `pre/elgamal.py` docstring: `rk⁻¹ mod q` reverses it, so it is bidirectional; and a 256-bit group is well below 128-bit security. Note in `gate.py` and ADR-0012 that the facility unwraps the DEK and delivers it by KEM. Add both to the paper's limitations.

---

## 7. API-layer conventions

### F33 — Crypto in `api/`, and the invariant test misses it · MED (HARD: §2 rule 10) · Avaneeth (api) + Ojas (custodian) + Nandini (search) · M · **FIXED (listed calls)**
**Status at `443ca0f`:** **FIXED (listed calls).** Search token via `search.emergency_search_token`, patient hash via `audit.events.patient_id_hash`, read path via `policy.decrypt_record_via_policy`; custodian crypto moved to the new `src/custodian/`. The invariant forbids these calls in `api/`. Remaining: emergency provisioning moves to `breakglass.provision_emergency_path` with F9 (D3).

**Problem.** `generate_emergency_key`/`split_emergency_key` (`custodian_service.py:763`), `derive_search_token` ([hospital.py:1149](../../src/api/hospital.py)), `sha256_digest` (`:336`), and the custodian's `decrypt_record` / `open_delivery_package` / `create_emergency_assertion`. `test_no_crypto_invariant.py:36` doesn't list them.

**Fix.**
- Emergency provisioning → `breakglass.provision_emergency_path` (F9).
- The in-memory emergency-search branch → a repo-agnostic `search.service` helper (Nandini).
- Patient-id hashing → an `audit.events` helper.
- **Custodian**: it is a client-side key agent, not a route orchestrator. Move its crypto into a new `src/custodian/` module, with `api/custodian_service.py` as a thin router. Record the decision in ADR-0043.
- Extend `forbidden_calls` with every name above.

### F34 — No BOLA test; read does DB work before authorization · MED (HARD: CONVENTIONS §5) · Avaneeth (api) · ⚑ needs D5 · M
**Problem.** `read_record` (`hospital.py:491-512`) loads the record, wrapping and policy before any caller check, and `requester_id` is self-declared.

**Fix.** Once D5-a gives a verified caller identity:
- check caller ↔ patient before **any** repo call. Owner: `caller == record.patient_id` through an index lookup that doesn't load ciphertext; clinicians are allowed through to the crypto check, which §8 says is the backstop;
- denials happen before the DB work and are logged.

**Test (exit criterion).** `test_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db`: a spy repo asserts that `get_record` / `get_wrapping_for_record` are never called.

### F35 — f-string SQL in `store_reader.py` · LOW (HARD as written: §2 rule 7) · Ojas/Powel (portal_core) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `store_reader.py` composes SQL with `psycopg.sql`.

**Fix.** `portal_core/store_reader.py:52,60,76,222`: compose with `psycopg.sql.SQL(...).format(sql.Identifier(...))` / `sql.SQL(_AUDIT_COLUMNS)`. The values are constants today, so this is about rule compliance, not an exploit.

### F36 — Portal's default DB connection is the postgres superuser · MED · Avaneeth (PS-6) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `portal/sql/roles.sql` creates a `portal_app` role that owns the portal schema and has no store-table privileges; the portal uses it; `tests/security/test_portal_roles.py`.

**Problem.** `settings.py:76-84` / `run_portal_demo.py:~153`: `default` uses the DATABASE_URL user with `search_path=portal,public`, so Django can write the store tables. `portal_ro` limits only the `store` alias.

**Fix.**
- `portal/sql/roles.sql`: add `portal_app`, which owns the `portal` schema and has **no** privileges on store tables. `default` connects as `portal_app`, with `search_path=portal`.
- `run_portal_demo` creates the role.

**Test.** `test_portal_default_connection_cannot_write_store_tables`.

### F43 — Compiled policies live only in a class-level dict · MED · Avaneeth (api, storage) · M · **FIXED**
**Status at `443ca0f`:** **FIXED.** Policies were persisted in `3c42094...4ddc201` (`storage/policy_codec.py`). `443ca0f` added the HTTP-level read-after-facility-restart test on Postgres and tightened the codec (rejects a bool version, checks `authority_id`).

**Status at `4ddc201`:** **FIXED (diverged, sound).** Versioned JSONB with a strict codec (`storage/policy_codec.py`), encrypted leaves only; cross-process tests. An HTTP-level restart test is still missing.

**Problem.** `api/repository.py:276`: `_shared_*` dicts are shared by every facility in one process and lost on restart, after which reads return 500 (`hospital.py:509`).

**Fix.** New store table `compiled_policies(policy_id PK, compiled bytea)`. Encrypted leaf shares only, which is safe for an honest-but-curious store. The repo reads and writes it; per-instance caches only.

**Test.** `test_read_succeeds_after_facility_restart` (Postgres).

---

## 8. Deployment and portal

### F37 — Bootstrap order and Path B · MED · Ojas (deploy) · M · **FIXED**
**Status at `443ca0f`:** **FIXED.** The audit service verifies its chain at startup, and every service that writes to it waits for it to be healthy. Tampered-genesis test added.

**Status at `4ddc201`:** **PARTIAL.** URL scheme follows `TLS_ENABLED`; the custodian is seeded on Compose. Chain verification still runs after the services start; no tampered-genesis test.

**Problem.**
- Compose `bootstrap` defaults to `https://` while the services default to TLS off, so Path B `up` fails.
- The chain is verified after the services start, against §7 step 7 ("If chain verification fails at boot, nothing else starts").
- The custodian is never seeded on Paths A/B.

**Fix.**
- Derive the URL scheme from the same `TLS_ENABLED` variable.
- The audit service verifies the chain from genesis in its startup and exits non-zero on failure. The other services `depends_on: audit: condition: service_healthy`, and Path A waits on the audit `/health` before starting the facilities.
- Call the `seed_portal` custodian deposit from `run_local` / Compose bootstrap.

**Test.** A deploy smoke test with a tampered genesis → facilities never start.

### F38 — Portal demo runs audit in-process · MED · Ojas (deploy) + Avaneeth (demo driver) · M · **FIXED**
**Status at `443ca0f`:** **FIXED.** `deploy/run_portal_demo.py` runs Path A's services as separate processes on fixed ports by default (`run_local.start_federation`); `--in-process` keeps the old path for tests. Run live on 2026-10-11.

**Problem.** `run_portal_demo.py` runs audit and both facilities as threads (`demo/driver._LiveServer`) on random ports. §7 says audit **must** be a separate process, and the capture filter misses the random ports.

**Fix.** Spawn the services with `deploy/entrypoint.py` on the fixed ports from `run_local`. Keep threads only behind `--in-process` for tests.

### F41 — The ADR-0033 lookup can be skipped · LOW · Nandini (clinician portal) · S · **FIXED**
**Status at `443ca0f`:** **FIXED** (ADR-0053). Break-glass acts only on the patient identified in the session's logged lookup; a different `patient_id` is 400 (also checked in the live portal on 2026-10-11).

**Problem.** The break-glass view takes `patient_id` from GET/POST. No `patient.lookup` event is written, and a fresh correlation id is minted.

**Fix.** The lookup creates a server-side `LookupSession` (portal DB: selected `patient_id`, correlation id) and writes the `patient.lookup` event. The break-glass form posts the lookup id; a raw `patient_id` gets 400.

**Test.** `test_breakglass_without_lookup_refused`.

### F42 — Portal and test hygiene · LOW · Mixed · S each · **FIXED**
**Status at `443ca0f`:** **FIXED.** Row 1 partly in `a40a5a7`, the rest in `443ca0f`. DEBUG off and `ALLOWED_HOSTS` loopback by default; safe `next` redirect; uploads download with `nosniff`; bad ids are 400; three-state link check; chain-verify DB errors are 503; the e2e script reports PASS/FAIL/SKIP and counts only 403 as a denial.

**Status at `4ddc201`:** **PARTIAL.** CI now fails instead of skipping (`skip_or_fail_without_postgres`). The other seven rows remain; some tests still use a plain `pytest.skip` (N3).

| Issue | Fix | Owner |
|---|---|---|
| `settings.py:21` DEBUG defaults on with `ALLOWED_HOSTS=["*"]` | Default `"0"`; `run_portal_demo` sets `DJANGO_DEBUG=1` explicitly | Avaneeth (PS-6) / Nandini |
| Open redirect, `patient/views.py:130` (`POST next`) | `url_has_allowed_host_and_scheme(next, {request.get_host()})`, else `patient:home` | Ojas/Powel (patient views) |
| Raw upload served inline with the uploader's Content-Type (`patient/views.py:369`) | Allowlist inline types (pdf, png, jpeg, text/plain); otherwise `Content-Disposition: attachment`, and always `X-Content-Type-Options: nosniff` | same |
| `admin_audit/views.py:237`: bad `int()` → 500 | Validate → 400 | Ojas |
| `admin_audit/views.py:94`: `_links_intact` true by default | Three-state result: intact / broken / unverifiable (no consecutive entries) | Ojas |
| `audit_service.py:181`: broad `except Exception` → 409 | Catch only the unique violation; let other DB errors become 503 | Ojas |
| `tests/security/conftest.py:27`: skips when Postgres is down, even in CI | If `CI=true`, fail instead of skip | Ojas |
| `tests/e2e/portal_flows.py:56` counts a skip as a pass; `:271` accepts 503 as a denial | Separate PASS / SKIP / FAIL counts; a denial must be 403 | Powel |

### F44 — Credential revocation doesn't remove cryptographic access · MED · ⚑ needs D10 · S (if D10-a)
**Fix (D10-a).** A paper limitation plus an ADR-0026 note: one key per (name, value), shared and never rotated, so revoking a credential stops *future key release* (after F15) but not a key already obtained.

---

## 9. New findings from the second review (N1–N16)

Found in code merged between `3c42094` and `4ddc201`.

### N1 — Compare-and-set is never used, and the new state mirror overwrites any state · HIGH · Avaneeth (api, storage, deploy) · M · **FIXED**
**Status at `443ca0f`:** **FIXED** (ADR-0050). Break-glass, revoke and the timer mirror all use the compare-and-set. Ingest is insert-only (`insert_lifecycle_state`). The ADR-0044 reset is gone, so a stale `emergency_open` is 409. The in-memory CAS keeps `last_event_id`. Postgres concurrency tests added. Remaining: restart reconciliation (F5, D7).

**Problem.**
- `transition_lifecycle_state` has no production caller. Every write still goes through the unconditional `upsert_lifecycle_state`: `hospital.py:221` (ADR-0044 reset), `:831` (revoke), `:1006` (break-glass), `:1220` (ingest), plus the new timer mirror (`facility.py:61` → `audit_client.py:142-145`).
- **Concurrent break-glass:** two requests both read GRANTED and both write EMERGENCY_OPEN; neither gets a conflict.
- **Cross-facility:** A opens record X. B's ADR-0044 reset sees no local session, writes GRANTED, and B opens too. A's timer then mirrors EXPIRED → GRANTED while B's session is still live.
- **Revocation:** once F10 makes revoke work on Postgres, any expiry overwrites REVOKED with GRANTED (the D7 hole, now persistent).
- The in-memory CAS also drops `last_event_id` (`api/repository.py:234-246`), unlike the Postgres version.

**Fix.**
1. Break-glass (`:1006`) and revoke (`:831`): `repo.transition_lifecycle_state(record_id, expected=source_state, new=…, last_event_id=…)`. Map `StateConflictError` to **409**, with no further side effects (do it before `insert_transition_event`).
2. Timer mirror: pass a writer that uses the CAS with `expected = LifecycleState(entry["from_state"])`. On conflict, log at ERROR with the record_id and don't overwrite.
3. Delete the write in `_effective_lifecycle_state` (`:221`); its reconciliation is F5's job. Until F5 lands, a stale `emergency_open` with no session gets **409 with a clear reason** instead of a silent reset.
4. Keep `upsert` only for ingest. Make it insert-only (`ON CONFLICT DO NOTHING`, raise if a row exists).
5. In-memory CAS: store `last_event_id` too.

**Tests (Postgres).**
- `test_concurrent_breakglass_one_wins`: two threads, one 200 and one 409.
- `test_timer_mirror_does_not_overwrite_a_changed_state`: set REVOKED mid-session, expire, assert still REVOKED.
- `test_stale_emergency_open_returns_409_not_silent_reset`.

### N2 — A partly failed expiry leaves the record stuck in EXPIRED; a DB error kills the monitor · MED · Powel (lifecycle) + Avaneeth (audit_client) · M · **FIXED**
**Status at `443ca0f`:** **FIXED.** `a40a5a7` stopped a store-write failure from killing the monitor; `443ca0f` finished it with F20. A record stuck in EXPIRED is retried to GRANTED. Remaining: the final state is still GRANTED (D7).

**Status at `a40a5a7`:** **PARTIAL.** A `state_writer` error is logged, not raised, so it no longer kills the monitor. The stuck-in-EXPIRED case and the retry are still open.

**Problem.** `audit_client._log` mirrors after each append separately.
- If the EXPIRED append and its mirror succeed but the GRANTED append fails, the store holds `expired`. `_effective_lifecycle_state` only reconciles EMERGENCY_OPEN, EXPIRED → EMERGENCY_OPEN is illegal, and the session was already deleted (`expiry.py:375`). Every later break-glass on that record gets 403, with no retry.
- Any exception from `state_writer` now also ends the monitor thread (`expiry.py:491-494`), a new way to hit F20.
- `test_deployment_expiry_state` only checks ordering on mocks.

**Fix.** This is F20 plus one rule:
- Claim the session as `expiring` instead of deleting it, and retry on any failure (F20).
- On retry, the manager resumes from the stored state: if the store already says EXPIRED, only the second transition is replayed.
- `state_writer` errors are caught inside that retry, never in the loop thread.

**Test.** `test_expiry_retries_after_second_append_fails`: a fake audit that fails once on the GRANTED append; assert the record ends GRANTED (or `prior_state`), not EXPIRED, and the monitor is still alive.

### N3 — Claim registry says "holds" without running the tests · HIGH · Powel (tests/security) · M · **FIXED**
**Status at `443ca0f`:** **FIXED** (ADR-0054). Claim status comes from a real run (`_claim_collector.py`, `claims.py`); a skipped test shows as UNVERIFIED and collection errors void the table. `skip_or_fail_without_postgres` is used everywhere. The P5-1 evidence was regenerated.

**Problem.** ADR-0046 §2: a claim holds "only if every one of its system tests runs without `xfail`".
- `claim_status` (`tests/security/claims.py:140-147`) decides from **collection only**: no xfail marker = "holds". A skipped or erroring test still "holds".
- C2's only system test (`tests/api/test_audit_service.py:24-31`) uses a plain `pytest.skip`, so the F42 CI guard never applies. With no Postgres, C2 and C5 print "holds", and `docs/review/p5-1-evidence.md` repeats that.
- `claims.collect()` ignores pytest's exit code, so a module that fails to import silently drops its tests. If one of them was a claim's only xfail, the claim flips to "holds".

**Fix.**
1. Compute status from a **run**, not a collection. Have the existing `_claim_collector` plugin also record each test's outcome (`pytest_runtest_logreport`).
   - "holds" requires every system test to have **passed**.
   - skipped → `UNVERIFIED (skipped)`.
   - xfailed → "fails today: …".
   - any other result → `BROKEN`.
2. Treat a non-zero collection exit code as an error, not a smaller set.
3. Change `test_audit_service.py` (and any other DB test using a plain `pytest.skip`) to `skip_or_fail_without_postgres`.
4. Re-run and correct `p5-1-evidence.md` for C2 and C5.

**Test.** `test_skipped_system_test_is_not_reported_as_holding` (feed the status function a skipped outcome), `test_collection_error_is_an_error`.

### N4 — Property 1 never covers revocation · HIGH · Powel (wire) + Avaneeth (`run_scenario.py`) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** The scenario sends a revoke; the analyser expects `/records/rec-001/revoke` and catches `old_dek_b64` on the plain profile.

**Problem.** PROJECT §4A(1) requires no secrets in the clear "during normal read, revocation, or break-glass". `deploy/run_scenario.py` never calls revoke, and `wire/analyze_traffic.py:42-51` doesn't expect `/revoke`. The revoke API takes `old_dek_b64` (`hospital.py:792`) and is never captured.

**Fix.**
- Add a revoke step to the scenario on a separate seeded record, so it doesn't disturb the break-glass record.
- Add `/records/{id}/revoke` to `EXPECTED_HTTP_ENDPOINTS` and `old_dek_b64` to the key denylist (if not already there).
- Expect claim 1 to **fail** on the plain capture until D6 and F10 land. That is the honest result.

**Test.** A synthetic-fixture test in `tests/wire/test_checks.py`: a revoke exchange carrying `old_dek_b64` fails claim 1.

### N5 — Stale or empty captures pass claims 1 and 4 · HIGH · Powel (wire) · M · **FIXED**
**Status at `443ca0f`:** **FIXED.** Capture deletes the old pcap and fails on a dumpcap early exit or an empty file. The canary manifest carries `run_id` and `started_at`, and the analyser refuses a capture that doesn't match (`StaleCaptureError`). TLS is required on every port, and the TLS unlock burst must be at least the plain request's size. Remaining: re-record the captures (E2).

**Problem.**
- `wire/capture.py:141-168` never deletes an old pcap and ignores dumpcap's exit status, while the canary manifest is rewritten every run (`run_scenario.py:516`). A failed TLS capture leaves the old `tls.pcap` alongside new canaries: zero hits, so claim 1 (`--claim1-scope tls`) and claim 4 pass.
- The TLS precondition (`analyze_traffic.py:85-91`) only needs **one** TLS record on any service port.
- `identify_breakglass(tls)` (`checks.py:507-515`) returns the largest client → facility-b burst without validating it, so a TLS run that aborted before unlock still "passes" claim 4.

**Fix.**
1. `capture.py`: delete the target pcap before starting, and fail if dumpcap exits non-zero or the file is empty.
2. Tie pcap to manifest: the scenario writes a `run_id` and `started_at` into the manifest. The analyser refuses when the pcap's first frame is earlier than `started_at`.
3. TLS preconditions: require TLS flows to **every** service port that the plain capture shows, and a client → facility-b TLS burst at least as large as the plain unlock request. Otherwise claim 4 fails as "TLS run incomplete".

**Tests.**
- `test_stale_pcap_older_than_manifest_rejected`.
- `test_tls_capture_with_single_handshake_fails_preconditions`.
- `test_tls_breakglass_without_unlock_burst_fails_claim4`.

### N6 — C4's strict-xfail test can pass without checking anything · MED · Powel (tests/security) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** The C4 strict-xfail test asserts unconditionally.

**Problem.** `test_p51_system_claims.py:333` asserts only inside `if reopened.status_code == 200`. Any refusal, a 500 included, passes. Once F9 lands, strict mode turns it red, the marker is removed, and C4 reads "holds" without proving search is dead.

**Fix.**
```python
assert reopened.status_code in (200, 403), reopened.text
if reopened.status_code == 200:
    result = _search(client)
    assert result.status_code != 200 or RECORD not in result.json()["record_ids"]
```

**Test.** It is the test. Also scan the other claim tests for `if … status_code` guards.

### N7 — Mutation runner counts a crash as "caught" · MED · Powel (tests/security) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** The mutation runner requires a green baseline and counts only pytest exit 1 as caught (`_classify`). Mutation C6b was added because C6 now holds through the compare-and-set.

**Problem.** `tests/security/mutations.py:274-276`: any non-zero exit counts as red (caught). That includes:
- an `AttributeError` in `apply()` after a rename;
- a collection error;
- a usage error.

A test that is already red at baseline is never flagged (`:294`). (Skip detection is fine: `-ra` prints `SKIPPED [n]`.)

**Fix.**
- Run the baseline first and abort if it isn't green.
- Count a mutation as caught only when pytest exits **1** (tests failed). Exit 2–5 (interrupted / internal / usage / no tests) is `ERROR`.
- `apply()` errors are reported as `ERROR (mutation did not apply)`.

**Test.** `test_mutation_that_fails_to_apply_is_error_not_caught`.

### N8 — TCP reassembly bridges gaps silently · MED · Powel (wire) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Flows track gaps (`Flow.gaps`, `spans_gap`); a gap makes claim 1 inconclusive, and no match spans a gap.

**Problem.** `wire/streams.py:86-97, 187-221` joins the bytes on either side of a missing segment.
- The docstring says this "can only hide a match". For claim 1, a hidden match is a false pass.
- Joining can also create a match that never existed.
- A flow's `start_timestamp` comes from its lowest sequence number, not its earliest frame.

**Fix.**
- Record a `gaps` count per flow. Any service-port flow with gaps makes claim 1 **inconclusive (fail)**, with the flow named.
- Don't join across a gap: split it into separate chunks.
- Take `start_timestamp` from the minimum frame time.

**Test.** `test_flow_with_missing_segment_makes_claim1_inconclusive`.

### N9 — Short canaries are silently dropped · MED · Powel (wire) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** A manifest with an unsearchable canary is rejected (`UnsearchableCanaryError`).

**Problem.** `wire/canaries.py:31,101` drops patterns shorter than 16 chars. A canary left with no patterns is never searched and never reported.

**Fix.** The scenario controls canary generation, so generate them at ≥ 16 chars. At manifest load, **fail** if any canary has zero patterns. (JSON `\u` escaping only affects non-ASCII and the canaries are ASCII, so skip that.)

**Test.** `test_manifest_with_unsearchable_canary_is_rejected`.

### N10 — Committed benchmark results are stale · MED · Nandini (bench) · S · **PARTIAL**
**Status at `443ca0f`:** **PARTIAL.** Benchmarks re-run on current code (Python 3.11 image) and committed with `environment.json`; the stale `p53_search_leakage.json` was removed. Remaining: the leakage analysis on a fresh capture (E2).

**Problem.**
- `bench/results/p53_search_leakage.json` still shows the response double-counting fixed in 390651a (4 requests, empty-method rows).
- `benchmark_summary.csv` has no p95 and no warm-up.
- `environment.json`, which `bench/README.md` says is committed, is missing.

All of these files predate the fixes, so the paper's evidence doesn't match the code (benchmark-methodology skill).

**Fix.** Re-run `bench/run_benchmarks.py` and the leakage analysis on the current code. Commit the results together with `environment.json`, or delete the stale files until exit-plan E2 is re-run.

### N11 — `run_local` drops the schema of any database · MED · Avaneeth (deploy) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** Fixed in `a40a5a7`. `run_migrations(reset=True)` refuses any non-local database host.

**Status at `a40a5a7`:** **FIXED (diverged, sound).** A host guard instead of a name guard; `test_deployment_reset_guard.py`.

**Problem.** `deploy/run_local.py:159` calls `run_migrations(reset=True)`, which runs `DROP SCHEMA public CASCADE` (`migrate.py:58-67`) on whatever `DATABASE_URL` names, with no guard. ADR-0047 doesn't cover it.

**Fix.** Refuse to reset unless the database name is in `{"ehr_test", "ehr"}` **or** `--reset` is passed. One `if` before `run_migrations`. Add a line to ADR-0047.

**Test.** `test_run_local_refuses_to_reset_unknown_database`.

### N12 — Postgres is published to the host with `trust` auth · MED · Avaneeth (deploy) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `a40a5a7` removed `trust` auth and requires `POSTGRES_PASSWORD`. `443ca0f` added the no-`trust` test, and the host-side portal reads the password from `deploy/.env`. Remaining: password generation is still a documented manual step.

**Status at `a40a5a7`:** **MOSTLY FIXED.** `trust` removed and the password is required. Remaining: the `portal-compose` launch entry has no password, there's no no-`trust` test, and bootstrap doesn't generate the password.

**Problem.** `docker-compose.yml:22,29` publishes `127.0.0.1:55433` with `POSTGRES_HOST_AUTH_METHOD: trust`. It was not published before this branch. Any local process gets superuser without a password, and could:
- run `DELETE FROM consumed_ids`, which reopens replay and undoes F22;
- rewrite `lifecycle_state` or `audit_log`.

**Fix.**
- Bootstrap generates `POSTGRES_PASSWORD` into the gitignored `.env`, and Compose uses `scram-sha-256`. Services and the `portal-compose` launch entry read it from `.env`.
- Keep the loopback publish only for the host-side `seed_portal`. If that can run inside Compose, drop the publish entirely.

**Test.** Extend `tests/deploy/test_transport.py`: the Compose file has no `trust` auth method.

### N13 — The C8 restart test never touches Postgres · LOW · Powel + Avaneeth (storage) · S · **FIXED**
**Status at `443ca0f`:** **FIXED.** `test_c8_replayed_assertion_rejected_across_processes_on_postgres`.

**Problem.** `test_p51_system_claims.py:430-440` uses `InMemoryStorageRepository`, so the "restart" shares one Python object, and the durable `consume_id` path has only unit coverage (`phase5-exit-plan.md:111`).

**Fix.** Add a Postgres-backed variant: two app instances on the same DSN, replay across them → 409/400.

### N14 — Container and TLS hardening · LOW · Avaneeth (deploy) · S · **PARTIAL**
**Status at `443ca0f`:** **PARTIAL.** `a40a5a7` mounted only each service's own TLS key. `443ca0f` added `USER app`, dropped `ENV HOST`, removed the lone `TLS_VERIFY=false` path and merged the flag parsing into one `env_flag`. Remaining: per-service SANs, which need a decision because host-run TLS reaches the services as `localhost`.

**Status at `a40a5a7`:** **PARTIAL.** Per-service key mounts landed. All five rows below are still open.

| Issue | Fix |
|---|---|
| `deploy/Dockerfile` has no `USER`; services run as root | `RUN useradd -r app` + `USER app` |
| Dockerfile `ENV HOST=0.0.0.0` overrides the F16 loopback default | Remove it; Compose already sets `HOST` per service |
| `TLS_VERIFY=false` is still wired through `bootstrap._http_verify`, despite the commit saying "no verify=false" | Delete the path; with the generated CA bundle it isn't needed |
| Every service cert lists `localhost`/`127.0.0.1` as a SAN, so any service key can impersonate any other service on the host | Give each service cert only its own Compose hostname; host access goes through a single host-facing cert (portal) |
| Four copies of env-flag parsing (`bootstrap`, `seed_enabled`, `config.tls_enabled`, `entrypoint`) | One `env_flag(name)` in `deploy/config.py` |

### N15 — Small correctness fixes · LOW · as listed · S each · **FIXED**
**Status at `443ca0f`:** **FIXED.** Malformed status line handled; exact bridge names; `--db-port` from `DATABASE_URL`; word-boundary finding match; `policy_codec` type checks; query labels; live test scope `all`; exit-plan TLS row.

| Location | Problem | Fix | Owner |
|---|---|---|---|
| `wire/http_messages.py:252` | `int(start_line[1])` raises on a malformed status line | Catch `ValueError` and stop walking that flow (as the docstring promises) | Powel |
| `wire/capture.py:85` | `br-` prefix also admits `br-lan`, `br-ex` | Match `^br-[0-9a-f]{12}$` (the Docker bridge name format) | Powel |
| `wire/checks.py` `--db-port` | Defaults to 5432; this project's Postgres runs on 55432/55433, so claim 2 fails by default | Default from `DATABASE_URL`'s port | Powel |
| `tests/security/test_claim_registry.py:269` | Substring match: "F2" matches "F22", "D1" matches "D10" | Word-boundary regex `\bF2\b` | Powel |
| `storage/policy_codec.py` | `authority_id` not type-checked; `version: true` equals 1; no negative tests for the coordinate and nonce-length guards | `type(x) is int` / `isinstance(x, str)` checks + negative tests | Avaneeth |
| Search-leakage CSV | Unsalted SHA-256 of dictionary words ("cardiac") is reversible | Replace the hash with a per-run sequence id (`q1`, `q2`, …): same leakage analysis, nothing to reverse | Nandini |
| `tests/wire/test_live_capture.py:40` | Defaults to `tls` scope while D6 is open | Default to `plain`, which is what the paper must defend until D6 says otherwise | Powel |
| `docs/plans/phase5-exit-plan.md` step A2 | Still says `TLS_VERIFY=false`, contradicting ADR-0047 | Remove the step | Powel |

### N16 — Process · Powel, Avaneeth · S · **PARTIAL**
**Status at `443ca0f`:** **PARTIAL.** The PROJECT.md expiry paragraph is now §5 caveat 6. Remaining: owner reviews of 638c2c6, 9721387 and `443ca0f` (ADR-0051).

- **CONVENTIONS §3 (one owner):** 638c2c6 (Powel) edits `src/api` and `src/storage`; 9721387 (Avaneeth) edits `src/lifecycle`, `wire` and `tests/security`. The owners of those parts should review each and say so in the PR or the ADR tracker.
- **ADR-0047:** the decider is "Tejas request", who is not on the team. Name the deciding member and keep it **Proposed** until the team ratifies it. Commit 9721387's message says "ADR-0045" but adds 0047.
- **PROJECT.md:** the new expiry paragraph sits between §4B and §5A with no heading. Give it one.

---

## Suggested order

*Steps 1-5 and the no-decision parts of 7-10 are done in the 2026-10-11 batch (status table above). What is left is step 6 (the decisions) and the decision-blocked fixes.*

1. **Stop false evidence first:** N3, N6, N5, N8, N9, N10. Until these are fixed, the claim table and the analyser can say "holds" or "pass" for something that wasn't shown.
2. **Stop the state from being overwritten:** N1, then N2 (with F20).
3. **Quick hardening:** ~~N11~~ (done in `a40a5a7`), N12 (remaining items), N14 (remaining rows), N15, N7.
4. **Close coverage gaps:** N4, N13.
5. **Quick first-review fixes that need no decisions:** F19, F24, F25, F26, F27, F6, F8, F4, F14 (interim), F42 (remaining rows).
6. **Make the decisions:** D7 first (now urgent), then D1, D4, D5, D6, D8. One team sync, with ADRs written in the same PR as the code.
7. **Break-glass core:** F1 → F2 → F11 → F7 → F5. After this the novelty claim holds.
8. **Lifecycle:** F10 → F9 (shared `provision_emergency_path`) → F20.
9. **Course module:** finish F18 under D6 → F40.
10. **Remainder:** F13, F15, F17, F23, F29, F33, F34, F36, F37, F38, F41, F31, F32, F44, F3/D2.

---

## Per-person breakdown

### Everyone
- No decision from §0 has been made since the first review. **D7 is now urgent**: the state mirror makes the un-revoke persistent.
- Review the one-owner crossings in N16 for your own modules.

### Powel: wire analyser, claim registry, lifecycle
- **Lead:** N3 (claim status from real runs), N5 (stale or empty captures), N6 (C4 vacuous assert), N7 (mutation runner), N8 (reassembly gaps), N9 (canary length), N13 (Postgres C8 variant).
- **Shared:** N2 (retry in the expiry manager, with F20), N4 (analyser side), N15 rows for `wire/` and tests, N16 (638c2c6 review, plan step A2).
- **Still open from the first review:** F11, F20, F23, F25, F27 (lead) and your parts of F1, F5, F6, F9, F10, F12, F13, F21, F22, F24, F26, F30, F32.

### Nandini: benchmarks, search, accounts, clinician portal
- **Lead:** N10 (re-run and commit the benchmark and leakage results).
- **Shared:** N15 (leakage CSV hashing).
- **Still open from the first review:** F17, F41 (lead); your parts of F9, F33, F42.

### Ojas: audit, authority, PRE, custodian, admin portal
- No new findings in your modules. This branch didn't touch audit, authority, PRE or custodian code.
- **Still open from the first review:** F2, F3, F4, F14, F15, F31, F38, F40 (lead) and your parts of F1, F6, F8, F9, F13, F18, F21, F23, F24, F32, F33, F35, F42. F37 is partly done: the chain still isn't verified before the services start.

### Avaneeth: facility API, storage, deploy
- **Lead:** N1 (wire the CAS everywhere), N12 (remaining: `portal-compose` DSN, no-`trust` test), N14 (all five rows; only the key mounts landed). N11 is done (`a40a5a7`).
- **Shared:** N2 (`audit_client` mirror), N4 (revoke step in `run_scenario`), N13 (storage side), N15 (`policy_codec`), N16 (9721387 review, ADR-0047 decider).
- **Still open from the first review:** F1, F5, F7, F8, F10, F19, F29, F34, F36 (lead) and your parts of F4, F6, F9, F11, F12, F13, F21, F22, F24, F26, F33, F38, F42.
