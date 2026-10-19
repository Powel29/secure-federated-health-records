# Explainers — the project in plain language

Written for the progress check. Each file explains one big idea with an
everyday analogy, a small picture, and "what to say if asked". Nothing here
adds a feature or changes a decision; every claim points back to the real
document (`PROJECT.md`, `ARCHITECTURE.md`, an ADR) or to code you can show.

## The 60-second pitch

> Hospitals keep health records encrypted. Normally the patient decides who can
> read them. But when a patient arrives unconscious at a hospital that has never
> seen them, nobody can ask. Most systems solve this with a "break-glass"
> button and a promise to log it later — a promise anyone with admin rights can
> quietly skip.
>
> We made the log a **precondition of the key**. The emergency key is split into
> three pieces held by three different parties, and the audit service only hands
> over its piece **after** it has written the log entry. No log entry, no key,
> no access. The emergency window then **closes by itself** and the record's key
> is changed, so the doctor's access really ends.
>
> Consent, revocation and emergency access are not three bolt-on features. They
> are four states of one **key-lifecycle state machine**, and every move between
> states is a signed event.

## Reading order (and time to read)

| # | File | One-line summary | Min |
|---|---|---|---|
| 0 | [00-quick-startup.md](00-quick-startup.md) | Commands to get the stack and portals running, plus fixes | 3 |
| 1 | [01-big-picture.md](01-big-picture.md) | The problem, the idea, the parts, who is who | 6 |
| 2 | [02-key-lifecycle-state-machine.md](02-key-lifecycle-state-machine.md) | Four states, signed transitions, revocation by changing the key | 6 |
| 3 | [03-break-glass-and-threshold-gate.md](03-break-glass-and-threshold-gate.md) | 2-of-3 shares, log-before-release, the emergency assertion, auto-expiry | 8 |
| 4 | [04-who-can-read-what.md](04-who-can-read-what.md) | Policy tree, consent gate, patient self-access, why portals never decide | 7 |
| 5 | [05-audit-chain-search-and-pre.md](05-audit-chain-search-and-pre.md) | Hash chain, emergency-only search, proxy re-encryption | 6 |
| 6 | [06-traffic-analysis-module.md](06-traffic-analysis-module.md) | The required course module: what we capture and what we assert | 4 |
| 7 | [07-honest-limits-and-what-we-found.md](07-honest-limits-and-what-we-found.md) | Caveats, the three bugs the stress test found, and what the deployment review fixed | 5 |
| 8 | [08-demo-script-and-viva-qa.md](08-demo-script-and-viva-qa.md) | A step-by-step demo and 20 likely questions with short answers | 10 |
| 9 | [09-technical-details.md](09-technical-details.md) | Parameters, protocol, ports, API, tables, tests, ADR index | 8 |
| 10 | [10-presentation-split.md](10-presentation-split.md) | Who speaks when, and the Phase 5 status slide | 4 |
| 11 | [11-independent-topics.md](11-independent-topics.md) | The final four topics each, rubric coverage and shared demo | 6 |
| 12 | [12-powel-topics-detailed.md](12-powel-topics-detailed.md) | Powel's topics in depth, with likely questions | 15 |
| 13 | [13-ojas-topics-detailed.md](13-ojas-topics-detailed.md) | Ojas's topics in depth | 15 |
| 14 | [14-avaneeth-topics-detailed.md](14-avaneeth-topics-detailed.md) | Avaneeth's topics in depth | 15 |
| 15 | [15-nandini-topics-detailed.md](15-nandini-topics-detailed.md) | Nandini's topics in depth | 15 |

## Where the project stands (verified 2026-10-09)

`main` now includes the whole Phase 5 merge (PR #37) and the full local
deployment (PR #38, ADR-0047). Numbers below were re-checked today:

| Item | Status |
|---|---|
| Test suite | 643 passed, 1 skipped (no `tshark`), 6 expected-fail with Postgres; 596 / 49 / 5 without it |
| Negative security claims (E1) | 5 of 11 hold (C1, C2, C5, C8, C11); 6 are strict expected-fail against review findings (C3, C4, C6, C7, C9, C10) |
| Docker Compose stack | Brought up healthy: Postgres, two authorities, audit, custodian, two facilities, portal |
| Portal end-to-end checks | 77 of 77 passed (`python -m tests.e2e.portal_flows`) |
| Cross-hospital scenario | all 9 steps passed (`python -m deploy.run_scenario`) |
| Benchmarks (E2) | all 7 metrics coded; committed numbers dated 2026-10-07/08, no `environment.json`: re-run before presenting |
| Edge cases (E3) | partial shares and replayed transition events done; clock skew is still an open decision (CS) |
| PyShark analysers (E4) | built (ADR-0045), claim 1 waits on decision D6; not yet run on real captures |
| ADRs | 47 (0045 to 0047 are Proposed) |

Phase 5 is **not** closed. Say that plainly; the open items are listed in
`docs/plans/phase5-exit-plan.md`.

## The plan for tomorrow

**Tonight (about 90 minutes)**

1. Read files 1–3 end to end. These are the heart of the project and the
   viva will come back to them (`PROJECT.md` §3: everyone must explain the
   whole state machine and the threshold gate, not just their own module).
2. Skim 4–7 once; read file 7 closely, because admitting limits before
   being asked is what earns trust.
3. Rehearse file 8's demo twice out loud with the real stack running.
   Restart it first (`python -m deploy.run_portal_demo`, or tear Compose down and
   bring it up again) so the merged fixes are live and no record is left in a
   stale state.

**Before you walk in**

- Stack is up, you are logged in as `house` in one tab and `david` in another.
- Know where we are: Phases 0–4 are marked done in `WORKFLOW.md`; **Phase 5 is
  in progress and merged to `main`** (security suite 5 of 11 claims green,
  benchmarks coded, analysers built, clock-skew decision open) and Phase 6
  (paper, rehearsal, fallback screenshots) is next. Say that plainly.

**If you have only 15 minutes:** read the pitch above, the "one-paragraph
version" at the top of files 2 and 3, and the Q&A in file 8.

## Who owns what (for "who did this part?")

Powel, Nandini, Ojas, Avaneeth — `WORKFLOW.md` §3 has the full task table.
Several Phase 3/4 tasks were built across owners (see ADR-0025 and the
portal tasks marked "built by Ojas"); say "the team built it" and be ready to
explain any module, because the viva tests whole-system understanding.
