# Phase 5 exit plan: requirements and plan to meet all four exit criteria

**Written:** 2026-10-07, after the gate check on `phase5` / `phase5-task1` / `phase5-task5`.
**Sources:** WORKFLOW.md Phase 5 exit criteria; review `docs/review/2026-10-07-fix-proposals.md`
(F = finding, D = decision); `docs/review/p5-1-evidence.md`; ADR-0045, ADR-0046.

> **Gate rule (WORKFLOW.md):** a phase ends when its exit criteria are
> demonstrated **from a clean clone on a machine that is not the author's**,
> not when it feels done.

## Status (updated 2026-10-08)

**Done** (on branches, awaiting owner review; nothing merged or pushed):

| Item | Branch / commit | Owner to review |
|---|---|---|
| bench README D4 scope note | `phase5` `49a3a64` | Nandini |
| `tests/api` `test_setup` emergency-wrapping fixture bug | `proposal/phase5-fixes` `d2303d1` | Avaneeth |
| F22 durable one-time ids (assertions, requests, transition events) + facility wiring → **C8 now holds** | `proposal/phase5-fixes` `638c2c6` | Avaneeth (storage, api), Ojas (deploy), Powel (breakglass, lifecycle) |
| F12 lock on `ConsumedEventIds` + compare-and-set primitive (handler wiring pending F11) | `proposal/phase5-fixes` `638c2c6` | Avaneeth, Powel |
| F16 services bind to loopback; Compose ports on `127.0.0.1` only | `proposal/phase5-fixes` `1c51636` | Ojas |
| F39 capture only on loopback / Docker bridge | `phase5-task5` `d127f0b` | Ojas |

**Pending decisions:** D1, D2, D3, D4, D5, D6, D7, D8, CS, plus two new
pending items:

- **F14 interim:** which addresses count as trusted authoring callers. An
  address allowlist breaks host-run scripts under Compose, so this is part of
  D5.
- **F40:** the capture path. Either move captures to `bench/captures/` or
  amend ARCHITECTURE §7.

Everything else in Part B waits on one of these.

## Where things stand

| # | Exit criterion | Today |
|---|---|---|
| E1 | The full negative security suite in `tests/security/` passes | ❌ 5/11 claims hold (C8 added 2026-10-08 on `proposal/phase5-fixes`); 6 strict-xfail against review findings |
| E2 | The benchmark harness produces every metric in PROJECT.md D4 | ⚠️ All 7 metrics are coded; the committed numbers are stale |
| E3 | Edge cases (clock skew, partial shares, replayed transition events) handled and tested | ⚠️ Partial shares done; replayed transition events done (durable + locked); clock skew pending decision CS |
| E4 | PyShark analysers run on both capture profiles and all four §4A claims pass | ❌ Analyser built, never run on real captures; claim 1 blocked on D6 |

---

## Part A: Requirements

### A1. Team decisions (one sync, ADRs in the same PR as the code)

Nothing in E1, E3 or E4 can close until these are made. The recommendations
are the review's unless noted.

| ID | Decision | Recommended | Blocks | Note | Status |
|---|---|---|---|---|---|
| **D1** | Who checks the Emergency Assertion before share 3 is released | (a) the audit service validates it itself | E1 C3 | | ⏳ Pending |
| **D2** | Share 2 is discarded, so break-glass is effectively 2-of-2 | (a) deposit with the home authority, or (b) amend the paper to "2-of-2 + reserved" | E1 C3 wording | (b) is honest and cheap | ⏳ Pending |
| **D3** | What expiry/revocation "forced rotation" rotates | (b) emergency path only: new emergency key, new shares, re-key search | E1 C4, C1 Postgres path | | ⏳ Pending |
| **D4** | Trusted source of patient public keys | (a) the home facility CA issues patient certs | F10 (C1 on Postgres), F13 | | ⏳ Pending |
| **D5** | Service-to-service authentication | (b) loopback/internal network now, then (a) signed `RequestEnvelope` | E1 **C9 needs D5-a** (D5-b gives no caller identity), C10 proper fix | If only D5-b fits, the team must decide whether to narrow C9; that is a claim change and needs an ADR | ⏳ Pending |
| **D6** | §4A property 1 vs. the current wire design | (a) client-side crypto (L, three owners), or (b) narrow property 1 to TLS and say so in PROJECT §4A and the paper | **E4 claim 1** | Fixes the analyser's `--claim1-scope` default | ⏳ Pending |
| **D7** | Expiry after a REVOKED → break-glass record | (a) add `EXPIRED → REVOKED`, session remembers `prior_state` | E1 C6 | | ⏳ Pending |
| **D8** | Who signs the break-glass `TransitionEvent` | (a) the custodian signs with the clinician key; the facility verifies | E1 **C7 needs D8-a** | | ⏳ Pending |
| **CS** | Clock-skew check on assertions (`issued_at > now + MAX_CLOCK_SKEW`) | Implement with a ~2-minute tolerance | **E3** | Powel's call (`breakglass` owner); the alternative is "out of scope", written down with a reason | ⏳ Pending |
| **F14-i** | Trusted authoring callers for `/attribute-keys/author` (interim) | Ojas decides the deployment trust boundary, then the allowlist ships with F16 | E1 C10 | An address allowlist breaks host-run `run_scenario` / `seed_data` under Compose (they appear from the bridge gateway) | ⏳ Pending |
| **F40** | Capture path | Move to `bench/captures/` or amend ARCHITECTURE §7 to `wire/captures/` | E4 hygiene | | ⏳ Pending |

### A2. The evidence machine (one, ideally not the author's)

E2 and E4 cannot be demonstrated without this. It is also where the
clean-clone gate check runs.

| Need | Detail | Check |
|---|---|---|
| Python 3.11 + `requirements.txt` | fresh venv from a clean clone | `pytest tests/` green |
| **Postgres 16, throwaway** | Docker per README (`localhost:55432/ehr_test`). Never a database with real data: the test fixtures drop the `public` schema | `DATABASE_URL` set; C2/C5 tests **run**, not skip |
| Docker Desktop | for Postgres and the Compose path | `docker ps` |
| **Wireshark** (dumpcap + tshark) on PATH | pyshark wraps tshark | `tshark -v`, `dumpcap -D` |
| **Npcap with loopback support** (Windows) | without it dumpcap captures nothing on `127.0.0.1` | trivial loopback capture shows packets |
| Federation on fixed ports | `deploy/run_local.py` (8001/8002/8010/8011/8020/8030) | `deploy.run_scenario` prints all 9 steps |
| TLS profile | certs from `wire.tls` (clients verify against the generated bundle; no `TLS_VERIFY=false`, ADR-0047, review N15) | `run_scenario --scheme https` succeeds |

### A3. Reviews, merges and ownership

| Item | Who | Why |
|---|---|---|
| Review the `phase5` fix commits to Nandini's P5-2/3/4 work | Nandini | Her code, my fixes |
| Review `proposal/scenario-canaries` (`deploy/run_scenario.py --canaries-out`) | Avaneeth | `deploy/` is his; P5-5 depends on it |
| Confirm the P5-5 handover; update the WORKFLOW owner | Nandini → Powel | P5-5 is listed as hers |
| Review `phase5-task1` (P5-1) | Ojas | P5-1 is his task, and it tests Powel's controls |
| Ratify ADR-0045 (P5-5 checks) and ADR-0046 (P5-1 evidence rules) | all four | Both are Proposed |
| ✅ Fixed the `test_setup` fixture that wrapped the root secret as "emergency" (`proposal/phase5-fixes`); Avaneeth to review | Avaneeth | `tests/api/conftest.py` |
| Merge order | — | `phase5` → `proposal/scenario-canaries` → `phase5-task5` → `phase5-task1` → `proposal/phase5-fixes` → `main` |

---

## Part B: Plan per criterion

### E1: the negative security suite passes

**Done when:** `python -m tests.security.claims` prints `holds` for C1–C11,
no `claim` test carries an `xfail` marker, CI (with `CI=true` and Postgres) is
green, and `python -m tests.security.mutations` shows every holding test red
under its mutation, C2/C5 included.

| Claim | Fix | Owner(s) | Needs | Size | Test that flips |
|---|---|---|---|---|---|
| C3 ⏳ | F2: the audit service validates the assertion, binds share to patient, one-time `request_id`; F4: no share overwrite | Ojas, Avaneeth | D1 (+ D2 wording) | M | `test_c3_audit_service_releases_no_share_without_a_valid_assertion` |
| C4 ⏳ | F9: expiry replaces the emergency wrapping and shares; search re-keyed | Powel, Avaneeth, Nandini, Ojas | D3 | L | `test_c4_pre_expiry_shares_do_not_restore_search`; also update `tests/api/test_breakglass.py::…reopens_after_the_timebox_expired`, which asserts today's behaviour |
| C6 ⏳ | F11 step 1: `_apply_and_persist` through `LifecycleStateMachine` for revoke, break-glass and expiry; F12 compare-and-set (**primitive + lock done**; wiring is part of F11) | Avaneeth, Powel | D7 | M | `test_c6_api_refuses_revocation_of_an_emergency_open_record` |
| C7 ⏳ | F11 step 2 / D8-a: pre-signed event from the custodian; remove `lifecycle_signing_key_pem` from the API | Avaneeth, Powel, Ojas | D8 | M | `test_c7_breakglass_event_verifies_against_the_clinicians_certificate` |
| C8 ✅ | F22: `consumed_ids` table + repository-backed stores for assertions, requests and transition events. **Done on `proposal/phase5-fixes`; marker removed; C8 holds.** Still to add: a Postgres variant of the restart test | Powel, Avaneeth | — | M | `test_c8_replayed_assertion_rejected_after_facility_restart` |
| C9 ⏳ | F34: caller ↔ patient check before any repo call; denial logged | Avaneeth | **D5-a** | M | `test_c9_bola_…_denied_before_crypto_or_db` |
| C10 ⏳ | F14: interim allowlist of authoring callers (ships with F16 — F16 is **done**), then a signed envelope under D5-a. Interim is now pending a trust-boundary decision (F14-i) | Ojas | D5, F14-i | S→M | `test_c10_attribute_key_not_released_without_a_valid_credential` |
| C1 | F10: revoke works on Postgres, authz from a verified identity, goes through the state machine, audited. **Add a Postgres variant** of `test_c1_…` (today only the in-memory path is tested) | Avaneeth, Powel | D4, D3 | L | new `test_c1_…_postgres` |
| C2, C5 | No fix expected. **Observe them running**: run the suite and `python -m tests.security.mutations C2 C5` with Postgres, then replace the "skipped" rows in `p5-1-evidence.md` | Ojas (or whoever has the evidence machine) | A2 | S | — |

Rule while fixing: when a fix lands, delete the `xfail` marker in the same PR.
Strict mode turns CI red until you do. Never weaken an assertion to make one
pass (ADR-0046).

### E2: benchmarks produce every D4 metric

**Done when:** one command on the evidence machine regenerates
`bench/results/` (summary, results, `environment.json`, plots, raw samples)
with all seven D4 metrics, and every number P6-3 cites traces to that run.

1. **Wait for the E1 fixes that change the timed paths** (F9 rotation, F11
   break-glass, F10 revoke). Benchmarking before them measures code that is
   about to change.
2. Run `DATABASE_URL=… python -m bench.run_benchmarks` (default 30 iterations,
   5 warm-up).
3. Commit `benchmark_summary.csv`, `benchmark_results.csv`,
   `environment.json` and both plots. Raw samples stay gitignored.
4. Paper wording (P6-3, Nandini):
   - `threshold_reconstruction` times `combine_shares` only.
   - Cross-facility and emergency-search times include HTTP.
   - Scalability curves were cut (a stated limitation).
5. *Optional, Nandini's call:* add a `breakglass_gate` benchmark timing
   `open_emergency_access` end to end, if the paper wants the full gate cost
   rather than the Shamir step.

Owner: Nandini (P5-2). Size: S once the machine exists.

### E3: edge cases handled and tested

**Done when:** each of the three named cases has a handling path and a
negative test, at module and system level, all passing.

| Case | State | Work | Owner | Size |
|---|---|---|---|---|
| Partial shares | ✅ Done: missing, empty, truncated and garbage shares, `tests/breakglass/test_gate.py` | — | — | — |
| Clock skew | ⏳ Pending decision CS (WORKFLOW P5-4 note) | Decide CS. If implemented: add `MAX_CLOCK_SKEW` and an `AssertionNotYetValidError` check in `validate_emergency_assertion`, a module negative test, and a system test through `/records/{id}/breakglass` expecting 400 and a logged denial. Update ARCHITECTURE §8's validation list and write the ADR. Also consider capping assertion lifetime (review F6) | Powel | S |
| Replayed transition events | ✅ Done on `proposal/phase5-fixes`: `ConsumedEventIds` is locked (F12) and takes a durable backend (F22); the deployed facility's expiry state machine uses the store. Tests: a concurrent-consume test (exactly one succeeds) and a restart-on-same-backend test. No API accepts a client-supplied transition event, so module level is where replay applies | — | — | — |

### E4: analysers pass on both capture profiles

**Done when:** on the evidence machine, `python -m wire.analyze_traffic` exits
0 against fresh `plain` and `tls` captures under the claim-1 scope D6 chose.
`bench/results/p55_wire_checks.json`, `p55_search_leakage.csv` and a
regenerated `p53_search_leakage.json` are committed.

1. **Decide D6.**
   - **D6-a:** implement client-side crypto (custodian decrypts and encrypts;
     shares delivered wrapped). Large, with Avaneeth, Ojas and Nandini all
     involved. Then run with the default `--claim1-scope all`.
   - **D6-b:** amend PROJECT §4A property 1 to the TLS reading and write the
     ADR. Change the analyser default to `tls` in that PR. The paper states
     the narrowed scope.
2. **Take private keys off the wire under either option** (F11 / D8-a removes
   `lifecycle_signing_key_pem`; F13 / D4 removes the patient private key).
   Under D6-b they would still cross TLS, and the review treats that as a fix,
   not a scope note.
3. **Capture hygiene** (Ojas, S): F39 (loopback-only interface allowlist) ✅ **done** on `phase5-task5`; F40 ⏳ **pending**
   (capture path: `bench/captures/` vs. `wire/captures/`, so amend
   ARCHITECTURE §7 or move).
4. **Merge** `proposal/scenario-canaries` and `phase5-task5` (A3).
5. **Capture**: run `python -m wire.capture --mode plain`, then restart the
   federation over TLS and run `python -m wire.capture --mode tls`. Postgres
   must be unencrypted on loopback so claim 2 can see the `COMMIT`.
6. **Analyse**: run `python -m wire.analyze_traffic` (plus `--claim1-scope tls`
   if D6-b).
7. **Triage any failure as a finding, not a tuning problem.**
   - Claim 2 fails: either the commit ordering is wrong, or the DB marker
     assumption in ADR-0045 broke. Investigate before touching the check.
   - Claim 4's validation fails: the size heuristic no longer fits the
     scenario. Revisit the rule with the plain-mode ground truth.
8. **Commit** the JSON/CSV outputs. Never commit the pcaps or `*.canaries.json`.

Owner: Powel (P5-5), with Ojas for F39/F40 and the D6-a owners if chosen.
Size: S for the run itself; D6-a is L.

---

## Part C: Order of work

```
Stage 0  Sync: decide D1 D2 D3 D4 D5 D6 D7 D8 + CS          (all four, ~1 meeting)
Stage 1  Merges + reviews (A3) | build the evidence machine (A2)
Stage 2  Fixes in parallel, by owner:
           Ojas      F2 (C3), F14 interim (C10), F16, F39/F40
           Avaneeth  F11/F12 (C6, C7), F34 (C9, after D5-a), F10 (C1-PG), F22 storage
           Powel     CS (E3), F22/F12 lifecycle+breakglass (C8), F9 lifecycle (C4), D8 gate change
           Nandini   F9 search re-key (C4); P5-2 prep; D6-a share if chosen
Stage 3  Evidence runs on the evidence machine:
           suite with Postgres + mutation check (E1) -> benchmarks (E2) -> captures + analyser (E4)
Stage 4  Clean clone on a non-author machine: rerun Stage 3 commands; gate review
```

**Critical path:** decisions D5 and D6, then F11 (it unblocks C6, C7 and the
private-key removal E4 needs), then F9 (C4). Everything in Stage 3 waits on
Stage 2, because the benchmarks and captures must measure the fixed system.

## Fallback if time runs short

These are team decisions. Each one changes a claim, needs an ADR and a stated
limitation in the paper, and must never be taken by quietly editing a test.

- **D6-b** instead of D6-a: claim 1 holds under TLS only.
- **D2-b**: the paper says "2-of-2 plus a reserved share".
- **D3-b**: only the emergency path rotates; the DEK is not rotated on expiry.
- **C9 under D5-b only**: no caller identity exists, so the BOLA claim cannot
  be made. Either do D5-a or drop or narrow the claim. Do not leave it implied.
- **CS out of scope**: record why in WORKFLOW P5-4.

## Risks

- **Decisions slip.** E1, E3 and E4 all queue behind one sync. Schedule it
  first.
- **Evidence machine setup** (Npcap loopback, Docker, Postgres) can eat a day.
  Do the trivial-capture check before anything else.
- **Fixes change timings and wire shapes.** Re-running E2 and E4 after late
  fixes is expected, not wasted work.
- **Ownership drift.** Several Phase 5 tasks were implemented by someone other
  than their listed owner (P5-1, P5-5). Keep the reviews in A3; nobody
  security-reviews their own work.
