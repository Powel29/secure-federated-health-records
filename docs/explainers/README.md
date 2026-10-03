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
| 7 | [07-honest-limits-and-what-we-found.md](07-honest-limits-and-what-we-found.md) | Caveats, plus the three bugs the stress test found and the fixes | 5 |
| 8 | [08-demo-script-and-viva-qa.md](08-demo-script-and-viva-qa.md) | A step-by-step demo and 20 likely questions with short answers | 10 |
| 9 | [09-technical-details.md](09-technical-details.md) | Parameters, protocol, ports, API, tables, tests, ADR index | 8 |

## The plan for tomorrow

**Tonight (about 90 minutes)**

1. Read files 1–3 end to end. These are the heart of the project and the
   viva will come back to them (`PROJECT.md` §3: everyone must explain the
   whole state machine and the threshold gate, not just their own module).
2. Skim 4–7 once; read file 7 closely, because admitting limits before
   being asked is what earns trust.
3. Rehearse file 8's demo twice out loud with the real stack running.
   Restart it first (`python -m deploy.run_portal_demo`) so the merged fixes
   are live and no record is left in a stale state.

**Before you walk in**

- Stack is up, you are logged in as `house` in one tab and `david` in another.
- Know where we are: Phases 0–4 are marked done in `WORKFLOW.md`; Phase 5
  (benchmarks, analysers over captures, edge cases) and Phase 6 (paper,
  rehearsal, fallback recording) are what remain. Say that plainly.

**If you have only 15 minutes:** read the pitch above, the "one-paragraph
version" at the top of files 2 and 3, and the Q&A in file 8.

## Who owns what (for "who did this part?")

Powel, Nandini, Ojas, Avaneeth — `WORKFLOW.md` §3 has the full task table.
Several Phase 3/4 tasks were built across owners (see ADR-0025 and the
portal tasks marked "built by Ojas"); say "the team built it" and be ready to
explain any module, because the viva tests whole-system understanding.
