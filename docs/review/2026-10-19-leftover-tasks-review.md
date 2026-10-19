# Leftover tasks review (everything except Phase 6)

**Written:** 2026-10-19, on `proposal/consolidate-main-fixed-and-docs`
**Sources:** `WORKFLOW.md` task table, `docs/plans/phase5-exit-plan.md`,
`docs/review/2026-10-07-fix-proposals.md`,
`docs/review/2026-10-19-adr-ratification-checklist.md`, `PROJECT.md` §5.

## Summary

Every task in Phases 0–5 and the portal track is marked done in `WORKFLOW.md`.
The only unchecked tasks are P6-1 to P6-6 (out of scope here). What is left is
**gate work, sign-offs, housekeeping and a short list of known-open findings**.
The Phase 5 gate is **not passed**: all four exit criteria are met on the author
machine, but the rule is "from a clean clone on a machine that is not the
author's".

## 1. Gate blockers (must happen before Phase 6 stretch goals or sign-off)

| # | Item | Owner | Effort | Notes |
|---|---|---|---|---|
| G1 | **Phase 5 Stage 4:** run the Stage 4 checklist from a clean clone on a non-author machine | someone other than Powel | M | Needs the A2 setup: Python 3.11 venv, throwaway Postgres on `127.0.0.1:55432`, Docker, Wireshark/tshark, Npcap loopback, `PYTHONUTF8=1` on Windows. Record the machine in the PR |
| G2 | **Get the evidence onto `main`** | Powel, then Avaneeth reviews `api/` and `deploy/` | S | Regenerated evidence and the F31 fix (ADR-0083) were on `proposal/review-worth-doing-f31-f10`. `origin/main-fixed` is now merged into this branch; this branch still needs a PR |
| G3 | **Ratify the 41 Proposed ADRs** | all four | M (one sync) | Checklist: `2026-10-19-adr-ratification-checklist.md`. The paper currently cites decisions nobody has signed off. ADR-0085 amends the Accepted ADR-0038, so all four must agree |
| G4 | **Owner reviews of cross-owner commits** (review N16) | Powel, Avaneeth, Ojas, Nandini | S | Each owner confirms they reviewed commits `638c2c6`, `9721387`, `443ca0f` that changed their directories |

## 2. Reviews still owed (exit plan A3)

| Item | Reviewer |
|---|---|
| Fix commits to Nandini's P5-2/3/4 work | Nandini |
| `proposal/scenario-canaries` (`deploy/run_scenario.py --canaries-out`) | Avaneeth |
| P5-5 handover: confirm and update the WORKFLOW owner (listed as Nandini, implemented by Powel) | Nandini → Powel |
| `phase5-task1` (P5-1) | Ojas |
| ADR-0045 and ADR-0046 | all four |
| Proposals awaiting an owner: ADR-0070 (P5-3 workload) → Nandini; ADR-0071 (store TLS) → Avaneeth, Nandini; ADR-0065 (declare token) → Nandini | as listed |

## 3. Open findings (no decision needed, can start now)

From the whole-project check of 2026-10-19:

| # | Finding | Fix | Owner (suggested) |
|---|---|---|---|
| W2 | Pinned dependencies with later security releases: Django 5.0.6 (series out of support), cryptography 42.0.5, Starlette 0.36.3 via FastAPI 0.110 | `pip-audit`, bump with an ADR, then **re-run the evidence** (timings change) | Avaneeth |
| W3 | **FIXED** — `tests/security/test_postgres_lifecycle.py::test_c1_revoked_clinician_cannot_read_on_postgres` (revokes on the Postgres store, reads from a restarted process) | — | Powel |
| W4 | **FIXED** — CI ruff and black now cover `deploy/ wire/ bench/ demo/`; the one long line in `demo/seed_data.py` is wrapped | — | Avaneeth |

Remainders from the 2026-10-07 review, re-checked 2026-10-19: N12 and most of
N14 are already closed (`USER app` is in the Dockerfile, `ENV HOST` is gone,
Compose requires a store password and has no `trust`). Still open: the
`TLS_VERIFY` escape hatch in `src/api/audit_client.py` (double-gated, tested;
removing it is Avaneeth's call in `src/api/`) and the F31 follow-up (the
high-water mark anchors `seq` only, not the head hash). W2 (dependency bump)
is deliberately not done here: it changes the timings, needs `pip-audit` and
an ADR, and should be one change made before the Stage 4 run.

## 4. Known limitations that are decided, not fixed

These are recorded as limitations (`PROJECT.md` §5) and must appear in the paper.
They are open only in the sense that the build does not address them.

- Home-authority revocation is future work; only the patient revokes (ADR-0084).
- Revoking a credential does not revoke an attribute key already released (ADR-0075).
- Break-glass is 2-of-2; the home-authority share is reserved (ADR-0074).
- "No plaintext on the wire" holds under TLS only; plain claims 1 and 4 fail on
  purpose as the positive control (ADR-0073).
- Search size padding is not implemented; the residual leak is quantified in
  `bench/results/p53_search_leakage.md`.
- Revoked-serial lists are static (no CRL); clinical labels are readable in the
  store; portal `TIME_ZONE`; self-registration (ADR-0021).
- Latencies were measured on one non-reference machine: regenerate on the
  paper's reference machine before quoting them (P5-2).

## 5. Branch and repo housekeeping

| Item | Detail |
|---|---|
| Unmerged work on branches | `phase3/p3-5` (1 commit), `origin/proposal/c4-c7-c9-full-fixes` (1 commit) are not in `main`. Check whether `main` already supersedes them (C4, C7 and C9 are closed on main by ADR-0066/0068/0069), then delete or merge |
| Stale branches | About 40 local branches are only behind `main` and hold nothing unique; safe to prune after the PR lands |
| Local `main` | 33 commits behind `origin/main` as of this morning |
| Portal track | PS-3 (patient portal shell) is marked "shell done" and was wired in Phase 4 (P4-8); the label in `WORKFLOW.md` is stale |
| Possible stale note | Emergency patient identification (ADR-0033) is described as "slotted as P4-11a" in an earlier memory; the identify page and lookup now exist, so confirm and close it |

## 6. Suggested order

1. Open the PR for this branch; Avaneeth reviews `api/` and `deploy/` (G2).
2. One team sync to ratify the ADRs and tick the N16 reviews (G3, G4, section 2).
3. In parallel: W4 (CI scope), W3 (Postgres C1 test), N12/N14 remainders.
4. W2 (dependency bump) before the Stage 4 run, so the clean-clone evidence is
   produced once, on the final dependency set.
5. Stage 4 clean-clone run on a non-author machine (G1). Phase 5 closes here.
6. Prune stale branches.
