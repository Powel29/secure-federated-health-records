# One-shot IEEE paper generation — plan and prompt

**Written:** 2026-10-21, on `proposal/consolidate-main-fixed-and-docs`
**Covers:** deliverable D3 (`PROJECT.md` §2)
**Skill:** `.claude/skills/ieee-paper/` (every drafting and verifying agent
reads it)
**Decision:** ADR-0087 (IEEEtran LaTeX, built locally with Tectonic)

## Readiness: what was fixed on 2026-10-21

| Item | Before | Now |
|---|---|---|
| `ieee-paper` skill | Named in `CLAUDE.md` but missing | `.claude/skills/ieee-paper/SKILL.md`: structure, claim-to-evidence rules, limitations, how numbers are quoted, the build |
| IEEE class | None | `paper/IEEEtran.cls` and `paper/IEEEtran.bst` V1.8b from CTAN |
| LaTeX build | No toolchain | **Tectonic 0.17.0** at `C:\Users\user\AppData\Local\Programs\tectonic\tectonic.exe` (hash checked against GitHub's digest) builds `paper/main.tex` directly. The `compile_latex` tool is kept for snippet checks and `explain_latex_error`. It can't do full builds cheaply: no IEEEtran, and every call would have to retype the class, about 180 KB |
| Claims table | `docs/test-evidence/claim-table.md` from 2026-10-09 said 5/11 | Live `python -m tests.security.claims --table` on `867d472`: **11/11 hold**. The doc is regenerated |
| Wire evidence (course module) | The saved `plain.pcap` had no Postgres traffic, so check 2 failed in the live test | Plain and TLS captures re-recorded (TLS against the TLS-only store). `wire.analyze_traffic`: **checks 0–4 pass**, audit COMMIT 4.62 ms before the release. `bench/results/p55_*` regenerated |
| Benchmarks | 2026-10-19 run, AMD 16-core, before the ADR-0086 dependency bump | Re-run on current code: Intel 12-core, Postgres in Docker Desktop. Crypto figures unchanged. HTTP is ~405 ms median against ~50 ms before, which is the DB path on this machine (~11 ms per new connection), not the code. Recorded in `WORKFLOW.md` P5-2 |
| Limitations count | `WORKFLOW.md` said "four caveats" | Points to `PROJECT.md` §5 (twelve) |

## Still needed before running the prompt

1. ~~Warm Tectonic's package cache~~: done on 2026-10-21. The smoke test
   `.claude/skills/ieee-paper/smoke/main.tex` (IEEEtran, TikZ, pgfplots,
   booktabs, BibTeX, Times via TeX Gyre Termes) builds in about 2.5 s with no
   errors. The first attempt failed after 34 minutes on network errors to
   Tectonic's bundle server; the retry succeeded. On another machine, the
   first build fetches packages again.
2. **Pick the benchmark run the paper quotes.** Either the fresh 2026-10-21
   run (the working tree) or the 2026-10-19 run (in git). The paper names its
   machine either way.
3. **P5-3 search leakage** (`bench/results/p53_*`) predates the ADR-0086 bump
   and wasn't re-captured. It needs the two `--search-workload` captures and an
   update to `p53_search_leakage.md`. Otherwise the paper quotes it with its
   date.
4. Docker Desktop running, for the live claims check in Stage 2.

## How it stays inside context

The orchestrator never reads source code or long docs. It only reads fact
sheets, `paper/notes/STATUS.md` and verifier reports. Every subagent gets a
self-contained brief, writes its full output under `paper/notes/`, and returns
**at most 200 words** plus the output path. `STATUS.md` is the tracker and the
resume point if context is compacted.

| Stage | Who | Output |
|---|---|---|
| 0. Setup | orchestrator | branch, skeleton, `STATUS.md` |
| 1. Extraction | 7 read-only subagents, in parallel | `paper/notes/facts-F*.md`, each fact with `file:line` |
| 2. Live check | 1 subagent | `facts-live.md`: claims table and suite totals at `HEAD` |
| 3. Drafting | 6 writer subagents, in parallel | `paper/sections/*.tex`, TikZ figures, `refs.bib` |
| 4. Build | orchestrator | Tectonic build of `paper/main.tex` → page count |
| 5. Verification | 5 adversarial subagents, in parallel | `paper/notes/verify-*.md` |
| 6. Fix loop | orchestrator + writers, at most 2 rounds | zero BLOCKERs |
| 7. Wrap-up | orchestrator | one commit, compare link |

---

## The prompt

Paste everything inside the block into a fresh Claude Code session at the
repo root.

````text
Produce deliverable D3 for this repository: a complete IEEE conference paper
(IEEEtran, two-column, 8–10 pages plus references) for the "Federated
Break-Glass EHR with a Unified Key-Lifecycle State Machine" project. Do it in
one run, with every claim verified against the repo. Use subagents so that
you, the orchestrator, never run out of context.

## Ground rules

1. Load the `ieee-paper` skill first. Its rules are binding on you and on
   every subagent. Subagents can't see this chat, so every brief tells the
   subagent to read `.claude/skills/ieee-paper/SKILL.md` first, and quotes
   the rules it depends on.
2. Read only CLAUDE.md and PROJECT.md §1–§6 yourself. Never read src/, tests/,
   ARCHITECTURE.md, ADRs or explainers. Subagents do that.
3. Every brief states: purpose, exact files to read, output file, format, and
   "return ≤200 words + the output path".
4. Claim-to-evidence: every technical sentence carries `% src: facts-Fx#N`.
   Each fact cites `path:line`, a pytest node id or a results-file row. If
   there's no source, the sentence doesn't go in. Code beats docs.
5. C1–C11 statuses come ONLY from the Stage 2 live run.
6. Limitations: every item in PROJECT.md §5 goes in Section X (count them,
   don't assume a number). The five the skill names go in the abstract.
   Nothing from PROJECT.md §6 is claimed, and the scalability curves are
   stated as cut.
7. Benchmarks: the numbers come from bench/results/benchmark_summary.csv as it
   stands in the working tree, with median and p95, the iteration/warm-up
   counts, and the machine from environment.json. Do not re-run the
   benchmarks.
8. ADRs marked Proposed are design choices of this build, not ratified
   decisions.
9. Citations: anchors and rivals from PROJECT.md §4, each verified with web
   search (DOI/arXiv). If it can't be confirmed, drop it. Never invent one.
10. Figures: TikZ/pgfplots only (ADR-0087), with plot data taken from the
    CSVs. No \includegraphics of the bench PNGs.
11. Builds: full builds use Tectonic,
    `/c/Users/user/AppData/Local/Programs/tectonic/tectonic.exe -X compile
    paper/main.tex --outdir paper/build --keep-logs`. Use the compile_latex
    tool only to try a single figure/table/snippet, and explain_latex_error
    for a log line you don't understand. Never send the whole paper to it.
12. Git: branch `paper/ieee-draft` from the current branch. ONE commit at the
    end. No AI attribution lines. No push. Give the compare link and say its
    base is the current branch, not main.
13. Ask me before downloading or installing anything.

## Stage 0 — Setup (you)

- Check that paper/IEEEtran.cls and paper/IEEEtran.bst exist and that the
  Tectonic binary runs (`tectonic.exe --version`). If either is missing,
  STOP and ask me.
- Check the toolchain by building the smoke test:
  `tectonic.exe -X compile .claude/skills/ieee-paper/smoke/main.tex
  -Z search-path=paper --outdir paper/build/smoke` (seconds when the cache is
  warm; run it in the background in case packages need fetching). If it fails
  on network errors, retry once. If it fails again, STOP and tell me
  (Stages 1–3 can still run; only the build waits).
- Create the branch and paper/main.tex: IEEEtran conference, the XeTeX font
  preamble from the ieee-paper skill (copy it from the smoke test), \input
  per section, \bibliographystyle{IEEEtran}, \bibliography{refs}. Also
  create paper/sections/, paper/notes/ and paper/refs.bib. paper/build/ is
  already git-ignored.
- Create paper/notes/STATUS.md: Stage | Item | Subagent | Output | Status
  (pending/running/done/blocked) | Open issues. Update it after every
  subagent returns. After a compaction, re-read it and carry on.

## Stage 1 — Extraction (7 read-only subagents, in parallel)

Each one writes paper/notes/facts-<id>.md as numbered facts
("N. statement — source"). Each sheet ends with "Contradictions found"
(docs vs code; code wins). The skills named for each agent are what it must
read alongside its files.

F1 lifecycle (skill: crypto-implementation) — ARCHITECTURE.md §2, §5;
   src/lifecycle/*; src/contracts/; ADR-0030, 0050, 0058, 0069, 0081;
   docs/explainers/02. Extract: exact state names; the full transition table
   (from → to, trigger, signer, crypto performed); illegal-transition
   handling; expiry and full rotation.
F2 breakglass (crypto-implementation) — ARCHITECTURE.md §5 (cross-facility
   break-glass), §8; src/breakglass/*, src/audit/*, src/shamir/*; ADR-0032–0035,
   0044, 0049, 0056, 0057, 0063, 0065–0068, 0074, 0079, 0082, 0083. Extract:
   assertion fields and validation, replay protection, the commit-then-release
   order, share holders (2-of-3 split, 2-of-2 in practice), time limits.
F3 crypto (crypto-implementation) — ARCHITECTURE.md §1, §3; src/crypto_core,
   src/policy, src/records, src/pre, src/search; ADR-0001, 0002, 0012, 0022,
   0023, 0026, 0027, 0036, 0076, 0077, 0080. Extract: primitives, sizes and
   parameters, the envelope layout, Shamir over a policy tree, search tokens,
   why Charm-Crypto was rejected.
F4 system — ARCHITECTURE.md §2, §4, §6, §7; ADR-0011, 0014, 0019, 0024,
   0028, 0043, 0047, 0053, 0064, 0071, 0072, 0084, 0085;
   docs/federation-topology.md. Extract: processes, ports, trust boundaries,
   what portals/Postgres may not do, PKI, TLS.
F5 security (negative-security-test) — docs/threat-model.md;
   tests/security/claims.py; docs/test-evidence/claim-table.md;
   docs/review/p5-1-evidence.md; tests/security/mutations.py. Extract: the
   adversary model, assets, trust assumptions, each claim → its module and
   system tests, and the mutation evidence (every claim's tests go red under
   a mutation).
F6 traffic — PROJECT.md §4A; ARCHITECTURE.md §7 (capture configuration);
   wire/*.py (not captures/ or certs/); tests/wire/*;
   bench/results/p55_wire_checks.json, p55_search_leakage.csv,
   p53_search_leakage*.json, p53_search_leakage.md; ADR-0042, 0045, 0054,
   0070, 0071, 0073. Extract: capture scope (loopback/Docker bridge only),
   each wire check and its result, and the measured leakage with numbers and
   the date of each file.
F7 context + evaluation (benchmark-methodology) — PROJECT.md §4, §4B;
   docs/novelty-research-handoff.md; bench/README.md;
   bench/results/benchmark_summary.csv, benchmark_results.csv,
   environment.json; the WORKFLOW.md P5-2 notes; docs/explainers/07. Write
   paper/notes/refs-verified.bib, each entry checked by web search, with
   unverifiable ones marked DROPPED.

## Stage 2 — Live check (1 subagent, after Stage 1)

Brief: start Postgres if needed (Docker Desktop, then `docker run -d --rm
--name ci-pg -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=ehr_test -p
127.0.0.1:55433:5432 postgres:16-alpine`; DATABASE_URL=
postgresql://postgres@127.0.0.1:55433/ehr_test; PYTHONUTF8=1; Wireshark on
PATH). Run `.venv/Scripts/python.exe -m tests.security.claims --table` and the
full `pytest tests -q -rfEsx`. Write paper/notes/facts-live.md with each
claim's status, the suite totals, every failure or skip and its reason, the
date and the `git rev-parse --short HEAD`. If the result differs from
docs/test-evidence/claim-table.md, say so. If Postgres can't be started, STOP
and report it. Don't fall back to the doc.

→ You: if blocked, ask me whether to wait, or to use claim-table.md labelled
with its date and sha. Don't choose for me.

## Stage 3 — Drafting (6 writers, in parallel)

Each brief contains: read the ieee-paper skill; your fact sheets (paths);
your section and page budget; `% src:` on every technical sentence; TikZ/
pgfplots only; write paper/sections/NN-name.tex (tables in
paper/tables/*.tex, generated from the CSV or fact data, never retyped).

W1 Abstract + IEEEkeywords + I Introduction + II Related Work (F7, F5) — 1.25 pp;
   merges refs-verified.bib into paper/refs.bib
W2 III Threat Model and Goals + IV System Overview (F4, F5) — 1 p; TikZ
   component and trust-boundary figure
W3 V Key-Lifecycle State Machine (F1, F3) — 1.5 pp; TikZ state diagram and the
   transition table
W4 VI Break-Glass Protocol (F2, F3) — 1.25 pp; TikZ message sequence, the
   2-of-3 gate, the hash chain
W5 VII Security Analysis (F5, live) + VIII Traffic Analysis (F6) — 1.5 pp; the
   C1–C11 table captioned with its date and sha; the wire-check table; PRE
   marked unproven
W6 IX Implementation and Evaluation (F3, F4, F7) + X Limitations + XI
   Conclusion — 1.5 pp; the benchmark table, plus pgfplots latency (median/p95)
   and ciphertext-expansion plots

## Stage 4 — Build (you)

Run the Tectonic build (rule 11). Read only the error lines, the undefined
references and the overfull boxes from paper/build/main.log (grep them; never
read the whole log). Fix errors, using `explain_latex_error` on unclear ones.
To isolate a broken figure, try it alone in `compile_latex` wrapped in a
small `article` document. Record the page count in STATUS.md. Over 10 pages:
send cuts back to the writers with a page budget for each.

## Stage 5 — Verification (5 fresh adversarial subagents, in parallel)

Each one reads the ieee-paper skill, the .tex, the fact sheets and the
sources, and writes paper/notes/verify-<name>.md: issues marked BLOCKER or
MINOR, each with the .tex file:line and a fix. Tell them to try to find
faults, not to approve the draft.

V1 evidence-trace — every `% src:` resolves; the fact matches the sentence;
   the fact's source really says it. An untagged technical sentence is a
   BLOCKER.
V2 code-truth — re-derive state names, transitions, share counts, key sizes,
   assertion fields and time limits from src/ and diff them against sections
   V–VI, the figures and the tables.
V3 honesty — every PROJECT.md §5 caveat present and not watered down; the
   abstract's limitations sentence; nothing from §6; claim statuses exactly
   as facts-live.md; Proposed ADRs not presented as settled; rivals fair;
   synthetic data stated.
V4 numbers + citations — every number matches its CSV/JSON row (benchmarks,
   wire checks, leakage, test counts); the machine is named; every \cite
   resolves and is real; no unused entries.
V5 format — build with Tectonic itself; zero errors; no undefined
   references or citations; no overfull hbox over 10pt; every \ref/\label resolves; IEEEkeywords present;
   8–10 pages; figures readable in one column.

## Stage 6 — Fix loop (at most 2 rounds)

Read only the verify-*.md summaries. Send BLOCKERs to a fresh writer for the
section (the issue list plus its fact sheets), rebuild, and re-run only the
verifiers that flagged something. Stop at zero BLOCKERs or after 2 rounds.
Anything left goes in STATUS.md and in your report. Do not hide it.

## Stage 7 — Wrap-up (you)

- One commit on paper/ieee-draft: `paper: IEEE draft of D3 with evidence
  notes`. No AI attribution.
- Report: the page count, the claim summary with its sha, the benchmark run
  quoted (date and machine), the MINORs and any BLOCKER left, and the compare
  link with its base branch.
````
