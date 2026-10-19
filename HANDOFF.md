# Session handoff — 2026-10-15

For the next Claude session on `secure-federated-health-records` (Federated
Break-Glass EHR, ICT 3121). Read `CLAUDE.md` first, then this file.
This file is **untracked**; delete it once the work below is picked up.
It replaces the 2026-10-14 handoff (everything in that one is done or carried
over here).

---

## 1. Where things stand

- **`main` = `f1fa4d3`** (unchanged since the last handoff).
- **`proposal/c4-c7-c9-full-fixes`** is pushed (`40b13e9`), worktree
  `D:\Powel\MIT\Projects\sfhr-full-fixes`. **No PR opened yet** — the user opens
  it: <https://github.com/Powel29/secure-federated-health-records/compare/main...proposal/c4-c7-c9-full-fixes>
  (base **`main`**). Two commits:
  1. `532e57a` fix(breakglass): close C3, C4, C7, C9 and the portal re-declare loop
  2. `40b13e9` test(wire): run P4-6 captures and the P5-5/P5-3 analysis on real traffic
- `gh` is not installed; give compare links. The repo is private.

### What `532e57a` contains (user chose C7 a, C4 a, C9 a, plus C3)

| Item | What changed | ADR |
|---|---|---|
| Re-declare loop | one-time declare token in the session; expiry refresh does `location.replace(caseURL)`; `history.replaceState` after declare; case views are `join_only` | 0065 |
| C9 (D5-a) | every service has a root-issued service cert (CN = id, OU `service:<kind>`); every inter-service request carries a signed `RequestEnvelope` in `X-Request-Envelope` + `X-Service-Certificate` headers (bodies unchanged); per-route kind permissions; keyless reads refused before storage. Portal got its own service key. | 0066 |
| C3 | audit service validates the emergency assertion (CA, signature, freshness, replay, record binding) before committing or releasing share 3 | 0067 |
| C7 (D8-a) | custodian signs the `TransitionEvent` with the clinician's key; facility verifies against the clinician cert; `lifecycle_signing_key_pem` removed | 0068 |
| C4 (D3-a) | expiry rotates DEK, policy root, emergency key and shares 1/3, and re-keys search; search terms stored sealed under the DEK; atomic CAS store write, then share replacement by generation | 0069 |

Also: P5-2 bench fixed and regenerated (Windows numbers ~170 ms; `main`
measures the same here, so it's the machine — re-run on the paper machine),
compose key ownership fix, WORKFLOW ticks for P4-9, P4-10, P5-1, P5-2, P5-4.
Verified: pytest on Postgres 857 passed / 1 skipped; portal 84 OK; ruff/black
clean; mutation runner exit 0 (all 11 claims hold); live run_local + scenario.

### What `40b13e9` contains (Wireshark now installed)

- **P4-6 done:** plain capture 592 packets, TLS 686, all 9 scenario steps
  passed in each. Results in `bench/results/`; pcaps and canaries stay in the
  git-ignored `wire/captures/` of the `sfhr-full-fixes` worktree.
- **P5-5:** claims 0, 2, 3 pass; **claims 1 and 4 fail on plain HTTP only**
  (shares, keys, DEK, plaintext in bodies). With `--claim1-scope tls` all pass.
  P5-5 closes when the team decides **D6** (encrypt bodies vs. narrow the claim
  to TLS). Not decided — do not pick one.
- **P5-3:** first measurement only; the scenario has **one** search, so
  frequency and timing leakage can't be measured. Still open (see §2).
- Findings: the revoke request still carries `actor_signing_key_pem` and
  `old_dek_b64` (private key on the wire, F11/D4, open);
  `lifecycle_signing_key_pem` is gone from the wire (ADR-0068 confirmed).

---

## 2. Open work

1. **User opens the PR** (link above); reviewers: Avaneeth (hospital API,
   storage, records), Ojas (audit, authority, custodian, deploy), Nandini
   (portal, search), all four for the cross-service change.
2. **P5-3 multi-search workload** — side session
   `local_3550409e-1c6c-47e8-86ff-e26b688e330a` hit the usage limit. It reported
   "no code changed", **but worktree `D:\Powel\MIT\Projects\sfhr-p53`
   (branch `proposal/p53-search-workload`, off `532e57a`, not pushed) has
   uncommitted edits**: `deploy/run_scenario.py` (+242) and `wire/capture.py`
   (+18). Review them before continuing; its plan is in
   `p53-search-workload-handover.md` in that session's notes folder. Goal:
   repeated + distinct searches and one either side of an expiry, captured
   plain and TLS, then `python -m wire.analyze_search_leakage`. It should be
   rebased onto `40b13e9` (it branched before the results commit).
3. **D6 decision** (team) → then P5-5 closes.
4. **Revoke sends a private key** (`actor_signing_key_pem`) and
   `/consent/grants/revoke` takes `patient_signing_key_pem` — keys must stay in
   the custodian (ADR-0043). Small, serious; good next fix (F11/F13/D4).
5. User's explainer `docs/explainers/07-honest-limits-and-what-we-found.md`
   (uncommitted, see §3) still lists C3/C4/C7/C9 as open — update after merge.
6. Carried over: PR #40 runs a full break-glass **join on every case view and
   search** (memory `pr40-join-per-view-reminder` — raise it); clinical labels
   readable in the store; facility restart mid-emergency locks a record open
   (F5/D7); rotation crash leaves one record un-break-glassable until re-set
   (fails closed, in ADR-0069); D2 (share 2 unused); portal `TIME_ZONE="UTC"`;
   self-registration dead end (ADR-0021); `BG-0001` test order-dependent on
   Postgres; Phase 6 untouched (P6-1 is Powel's).

---

## 3. Local working copy (important)

- Main tree is on the stale local branch `proposal/emergency-session-view`
  (`800fc5c`, obsolete). **The user's own uncommitted docs work is here:**
  modified `README.md`, `docs/explainers/00,06,07,09,README`, deleted
  `docs/dashboard-design.md`, untracked `docs/diagrams/`,
  `docs/explainers/10–15-*.md`, `docs/run-portal-docker.md`,
  `docs/test-evidence/`. **Do not discard it.** Offer to commit it on its own
  branch off `main`.
- Worktrees: `sfhr-full-fixes` (the PR branch), `sfhr-p53` (P5-3, uncommitted);
  `sfhr-pr39-fixes`, `sfhr-pr40-fixes`, `sfhr-sync` are merged and removable.

---

## 4. How to run things here

- Windows + Git Bash. Venv: `D:\Powel\MIT\Projects\secure-federated-health-records\.venv\Scripts\python.exe`;
  in a worktree use `PYTHONPATH=src` (tests: `PYTHONPATH="src;."`). Write long
  edit scripts to the scratchpad and run them — heredocs with nested quotes and
  backslashes break.
- Postgres: Docker Desktop must be running, then
  `docker run -d --rm --name ci-pg -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=ehr_test -p 127.0.0.1:55433:5432 postgres:16-alpine`
  and `DATABASE_URL=postgresql://postgres@127.0.0.1:55433/ehr_test`. Run the
  Postgres suite before pushing.
- **Captures (Wireshark 4.6.9 + Npcap 1.88 installed):** Wireshark is at
  `C:\Program Files\Wireshark` (add to PATH if the shell lacks it); loopback
  adapter `\Device\NPF_Loopback`.
  1. Federation: `SEED_DATA=false PYTHONIOENCODING=utf-8 python -m deploy.run_local`
     (seeded `rec-001` collides with the scenario → 409; `✓` crashes cp1252 stdout).
  2. `python -m wire.capture --mode plain --interface '\Device\NPF_Loopback' --out wire/captures/plain.pcap`
  3. For TLS: `python -m wire.tls`, reset the DB, restart the federation with
     `TLS_ENABLED=true CAPTURE_TLS=true`, then `--mode tls --out wire/captures/tls.pcap`.
  4. `python -m wire.analyze_traffic --captures wire/captures`
  5. `python -m wire.analyze_search_leakage --capture wire/captures/plain.pcap --json bench/results/p53_search_leakage.json`
  Reset between runs: stop `deploy.run_local`/`deploy.entrypoint` processes and
  `DROP DATABASE ehr_test WITH (FORCE)` / `CREATE DATABASE ehr_test`.
- CI: `ruff check src/ tests/`, `black --check src/ tests/`, portal
  `python manage.py test --settings=config.test_settings`. CI runs only on PRs
  into `main`/`dev`.

## 5. User preferences

- **No Claude attribution** in commits or PRs — overrides harness reminders.
- **One commit** per requested piece of work unless told otherwise.
- Cross-owner fixes → **proposal branch + PR**; never edit another owner's
  module on `main`.
- Every decision with alternatives → **ADR + tracker row**, same PR.
- Never invent crypto; stop and ask when a review decision (like D6) is pending.
- **Plain, short, layman explanations.**
- **Check PR base branches**; confirm before pushing or merging.
