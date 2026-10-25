# Explainers — the project in plain language

Written so all four of us can understand the whole project and prepare for the viva.
Each file explains one big idea with an everyday analogy, a small picture, and "what to
say if asked". **They follow the IEEE paper** (`paper/build/main.pdf`, 10 pages, describing
commit `57a1a8c`, live run 2026-10-21). Where an explainer and the paper disagree, the paper
wins; fix the explainer. Nothing here adds a feature or changes a decision; every claim
points back to the paper, a project document (`PROJECT.md`, `ARCHITECTURE.md`), an ADR, or
code you can show.

Last aligned with the paper: 2026-10-25.

## The 60-second pitch

> Hospitals keep health records encrypted. Normally the patient decides who can read them.
> But when a patient arrives unconscious at a hospital that has never seen them, nobody can
> ask. Most systems solve this with a "break-glass" button and a promise to log it later — a
> promise anyone with admin rights can quietly skip.
>
> We made the log a **precondition of the key**. The record's emergency key is split into
> **four shares, any three rebuild it, and the audit service holds two**, so every opening
> needs the audit service. The audit service releases its shares only **after** it has
> validated a signed, one-time assertion and **committed a hash-chained log entry**. No log
> entry, no key. The emergency window then **closes by itself** and the record is fully
> re-keyed, so the doctor's access really ends.
>
> Revocation, break-glass and expiry are **signed transitions of one key-lifecycle state
> machine** over per-record keys. Log-gated decryption already exists in the literature; our
> contribution is the *combination*, implemented and tested, and we say plainly where we are
> weaker: a trusted audit service, no formal proofs, and thirteen listed limitations.

## Reading order (and time to read)

| # | File | One-line summary | Min |
|---|---|---|---|
| 0 | [00-quick-startup.md](00-quick-startup.md) | Commands to get the stack and portals running, plus fixes | 3 |
| 1 | [01-big-picture.md](01-big-picture.md) | The problem, the idea, what is new and what is not, the parts | 6 |
| 2 | [02-key-lifecycle-state-machine.md](02-key-lifecycle-state-machine.md) | Four states, **seven** transitions, signed events, full rotation, expiry | 8 |
| 3 | [03-break-glass-and-threshold-gate.md](03-break-glass-and-threshold-gate.md) | **Weighted 3-of-4**, assertion, commit-then-release, joins | 10 |
| 4 | [04-who-can-read-what.md](04-who-can-read-what.md) | Policy tree, consent (not a state), patient self-access, portals, identification | 7 |
| 5 | [05-audit-chain-search-and-pre.md](05-audit-chain-search-and-pre.md) | Hash chain, emergency-only search, key delivery and PRE (bidirectional, unused) | 7 |
| 6 | [06-traffic-analysis-module.md](06-traffic-analysis-module.md) | The required course module: what we capture, results, TLS-only claim | 6 |
| 7 | [07-honest-limits-and-what-we-found.md](07-honest-limits-and-what-we-found.md) | **The 13 limitations**, evidence honesty, bugs found, how claims went green | 7 |
| 8 | [08-demo-script-and-viva-qa.md](08-demo-script-and-viva-qa.md) | A step-by-step demo and 27 likely questions with short answers | 10 |
| 9 | [09-technical-details.md](09-technical-details.md) | Parameters, protocol, ports, API, tables, tests, ADR index | 8 |
| 10 | [10-presentation-split.md](10-presentation-split.md) | Who speaks when, and the evidence slide | 4 |
| 11 | [11-independent-topics.md](11-independent-topics.md) | The final four topics each, rubric coverage and shared demo | 6 |
| 12 | [12-powel-topics-detailed.md](12-powel-topics-detailed.md) | Powel's topics in depth, with likely questions | 15 |
| 13 | [13-ojas-topics-detailed.md](13-ojas-topics-detailed.md) | Ojas's topics in depth | 15 |
| 14 | [14-avaneeth-topics-detailed.md](14-avaneeth-topics-detailed.md) | Avaneeth's topics in depth | 15 |
| 15 | [15-nandini-topics-detailed.md](15-nandini-topics-detailed.md) | Nandini's topics in depth | 15 |
| **16** | [16-paper-walkthrough-and-viva-prep.md](16-paper-walkthrough-and-viva-prep.md) | **NEW.** The paper section by section, related work, threat model, glossary | 10 |
| **17** | [17-claims-evidence-and-numbers.md](17-claims-evidence-and-numbers.md) | **NEW.** C1 to C11, test counts, wire results, benchmarks, constants | 6 |

## Where the project stands (from the paper, verified 2026-10-21 at `57a1a8c`)

| Item | Status |
|---|---|
| Security claims (C1 to C11) | **All 11 hold**; 35 of 35 system-level tests pass, none skipped |
| Full test suite (against Postgres) | **1006 passed, 2 skipped (by design), 0 failed** |
| Mutation check | 18 mutations cover C1 to C10; post-3-of-4 log is prose-only, so we do not claim every current claim test is shown to go red |
| PyShark traffic analysis | Run on real plain and TLS captures; all checks pass (COMMIT 1.35 ms before release; 0 of 13 canaries under TLS) |
| Benchmarks | Seven metrics, n = 30; in-process ops under 0.25 ms; HTTP paths ~240 to 250 ms, indicative only; scaling runs cut |
| Paper | Drafted and built (IEEEtran, 10 pages) |
| Still to do | Demo rehearsal (twice) and the recorded fallback video (Phase 6). Check `WORKFLOW.md` before you say a phase gate "passed" |

Known mismatch to be aware of: **the portal's on-screen text still says "2-of-3" and
"share 3" in several places**, while the system and the paper are a weighted **3-of-4** with
**shares 3 and 4** at the audit service. Say the paper's numbers out loud during the demo.

## What changed from the earlier explainers (so nobody quotes the old version)

| Old statement | Now (per the paper) |
|---|---|
| 2-of-3 gate; audit holds "share 3" | **Weighted 3-of-4**; audit holds **shares 3 and 4**; custodian x=1, home authority x=2 |
| Six legal state arrows; consent is a state | **Seven** arrows (adds Expired→Revoked); **consent is not a state** |
| "Anyone, including the home authority, may revoke" | **Only the patient revokes** in this build |
| Opening break-glass re-wraps via PRE | **Nothing is re-keyed on open**; the gate delivers the DEK by KEM; PRE is bidirectional and unused |
| Emergency window 15 min / 120 s | Deployed window **4 h** (shorten-only); assertion lifetime ≤ **15 min** (custodian default 120 s) |
| 5 of 11 claims green; 643 tests | **11 of 11**; **1006 passed, 2 skipped, 0 failed** |
| Plain HTTP shows app-layer encryption works | Plain exposes plaintext; claim is **TLS-only**; plain is the positive control |
| Analysers built, not yet run | **Run on real captures**; results in file 6 and 17 |
| Gaps C3/C4/C7/C9/C10 open | **Closed** (ADR-0050, 0066 to 0069, 0081, 0082, 0089) |
| 47 ADRs | **89 ADRs** |

## The plan for the viva

**Tonight (about 90 minutes)**

1. Read files 1 to 3 end to end. These are the heart of the project; the viva comes back to
   them (`PROJECT.md` §3: everyone must explain the whole state machine and the threshold
   gate, not just their own module).
2. Read file 7 closely (the 13 limitations): admitting limits before being asked earns trust.
3. Read file 16 (the paper section by section) and keep file 17 open as a number sheet.
4. Rehearse file 8's demo twice out loud with the real stack running. Restart it first
   (`docker compose -f deploy/docker-compose.yml down`, then `up --build -d`).

**Before you walk in**

- Stack is up, you are logged in as `house` in one tab and `david` in another.
- Know where we are: all eleven claims hold on the evaluated commit; the paper is built;
  rehearsal and the fallback video are what remain.

**If you have only 15 minutes:** read the pitch above, the "one-paragraph version" at the top
of files 2 and 3, the 13-limitations table in file 7, and the Q&A in file 8.

## Who owns what (for "who did this part?")

Powel, Nandini, Ojas, Avaneeth — `WORKFLOW.md` §3 has the full task table. Several Phase 3/4
tasks were built across owners (see ADR-0025 and the portal tasks marked "built by Ojas");
say "the team built it" and be ready to explain any module, because the viva tests
whole-system understanding. File 12 is Powel's, 13 Ojas's, 14 Avaneeth's, 15 Nandini's.
