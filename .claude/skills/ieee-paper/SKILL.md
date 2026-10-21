---
name: ieee-paper
description: How to write, verify and build the IEEE-format paper (deliverable D3) for this federated EHR project — section structure, claim-to-evidence discipline, the security-claims table, the limitations that must appear in the abstract, how benchmark numbers are quoted, honest related work, and building IEEEtran LaTeX locally with Tectonic (compile_latex only for small snippet checks). Use this skill for anything under paper/, for any task that mentions the paper, report, write-up, abstract, related work, evaluation section, limitations or bibliography, and for any subagent that drafts or verifies a paper section.
---

# Writing the paper (D3)

The paper is graded for honesty as much as for prose. An examiner who finds one
claim the repository does not back will distrust the rest. So every sentence
that says something technical must be traceable to a file, a test or a results
row. Good writing comes second to that.

## Source of truth, in order

1. **Code** (`src/`, `wire/`, `deploy/`): what the system actually does.
2. **Live runs**: `python -m tests.security.claims --table`, the full `pytest`
   run, `bench/results/*`. These are evidence only when they come from a run
   on the commit the paper describes.
3. **`ARCHITECTURE.md`, `PROJECT.md`, ADRs**: intent and rationale.
4. **Explainers, diagrams, review notes**: summaries. Never cite them as
   evidence.

When two of these disagree, the higher one wins, and the disagreement is
recorded in the notes. A **Proposed** ADR is a design choice of this build, not
a ratified decision. Don't write "the team agreed" about one.

## Claim-to-evidence discipline

- Every technical sentence in a `.tex` file ends with a LaTeX comment that
  names its source: `% src: facts-F2#14`, where the fact sheet entry itself
  cites `path:line`, a pytest node id, or a results-file row. No tag means the
  sentence doesn't ship.
- A security property is stated as holding **only if** every system-level test
  for it ran and passed in a live claims run (`tests/security/claims.py`
  decides this; don't decide it yourself). If a claim shows as `fails today`,
  `UNVERIFIED (skipped)` or `BROKEN`, it goes in the table under that status,
  with its finding. It is never removed and never softened.
- `docs/test-evidence/claim-table.md` is a snapshot. Before the paper quotes
  it, check its date and commit against `HEAD`. If they differ, re-run the
  table.
- Proxy re-encryption gets no security proof. Say it is unproven
  (ADR-0076: bidirectional, and computing `rk` needs both secret keys).

## Required structure (IEEEtran conference, 8–10 pages + references)

| # | Section | Must contain |
|---|---|---|
| — | Abstract + IEEEkeywords | Problem, contribution, the main result, **and one or two sentences of limitations** (see below) |
| I | Introduction | The gap: consent, revocation, break-glass and audit are usually separate mechanisms and audit can be bypassed; our contributions as a list |
| II | Related Work | The two anchors and the two rivals from `PROJECT.md` §4, each with the honest delta |
| III | Threat Model and Goals | Adversaries, trust assumptions, assets (`docs/threat-model.md`), goals stated as C1–C11 |
| IV | System Overview | Components, trust boundaries, what portals/Postgres may **not** do (ADR-0014) |
| V | Key-Lifecycle State Machine | States, the transition table, the access structure (Shamir over a policy tree, ARCHITECTURE §3) |
| VI | Break-Glass Protocol | Emergency Assertion, replay protection, commit-then-release ("no log entry, no key"), time-boxed expiry by full rotation |
| VII | Security Analysis | The C1–C11 table from the live run, plus an argument per claim that names its tests |
| VIII | Traffic Analysis | The required course module (`PROJECT.md` §4A): PyShark-asserted wire properties, plain vs TLS, measured search leakage |
| IX | Implementation and Evaluation | Stack, LOC/test counts from a run, the benchmark table and plots |
| X | Limitations | **All** caveats in `PROJECT.md` §5, in its order, plus the cut scalability runs |
| XI | Conclusion | Future work taken from the caveats, nothing new |

## Limitations

`PROJECT.md` §5 is the list, and it grows. Count its items when you write;
don't trust a number written down somewhere else. Each item gets its own
sentence or short paragraph in Section X. The abstract has to name at least
these: revocation is forward-only, expiry is enforced by the server rather than
by cryptography, the construction is not full CP-ABE (not collusion-resistant),
break-glass is 2-of-2 in this build, and "no plaintext on the wire" holds under
TLS only.

Never claim out-of-scope work (`PROJECT.md` §6): ML anomaly detection, FHIR/HL7,
real CP-ABE, or scalability curves over #patients/#facilities. Those curves
were cut and get stated as a limitation. The paper uses no real patient data
and says the dataset is synthetic.

## Quoting benchmark numbers

Follow the `benchmark-methodology` skill for how numbers are produced. In the
paper:

- Quote **median and p95** from `bench/results/benchmark_summary.csv`, never the
  mean alone. Give the iteration and warm-up counts.
- Name the machine and deployment path from `bench/results/environment.json`
  next to the table. Say the HTTP figures (`cross_facility_latency`,
  `emergency_search_latency`) include transport and depend on the machine.
- Call `threshold_reconstruction` "Shamir combine (2-of-3)", not "break-glass
  latency". It times `combine_shares` alone.
- Ciphertext expansion comes from `benchmark_results.csv` rows, not from the
  PNG.
- Tables are generated from the CSV (a small script or exact copy), never
  retyped by hand.

## Related work and citations

- Every `\cite` must resolve to an entry in `paper/refs.bib` that has a DOI,
  an arXiv id or a publisher URL, checked against the real source. If you
  can't confirm a reference, drop it. Don't invent one.
- Present the rivals fairly. arXiv 2511.17464 already does
  revocation-as-key-rotation, so our delta is the *unification* with consent
  and break-glass, not the rotation itself.

## Building: Tectonic for the paper, `compile_latex` for snippets

**Full builds use Tectonic**, a local engine that reads files straight from
`paper/` (ADR-0087). It lives at
`C:\Users\user\AppData\Local\Programs\tectonic\tectonic.exe` (0.17.0). From the
repo root:

```bash
/c/Users/user/AppData/Local/Programs/tectonic/tectonic.exe -X compile paper/main.tex --outdir paper/build --keep-logs
```

- `IEEEtran.cls` and `IEEEtran.bst` (V1.8b, from CTAN
  `macros/latex/contrib/IEEEtran`, LPPL) are vendored in `paper/`, next to
  `main.tex`, so the build uses those copies and not whatever Tectonic's
  bundle ships. Never fake the class with `article`: then the page count and
  layout mean nothing.
- **Tectonic is XeTeX, so the preamble must set the Times fonts itself.**
  Otherwise IEEEtran's Times request falls back to Latin Modern. Put this
  right after `\documentclass[conference]{IEEEtran}` (Tectonic finds fonts by
  file name, not by system font name):

  ```latex
  \usepackage{amsmath}
  \usepackage{newtxmath}
  \usepackage{fontspec}
  \setmainfont{texgyretermes}[Extension=.otf, UprightFont=*-regular,
    BoldFont=*-bold, ItalicFont=*-italic, BoldItalicFont=*-bolditalic]
  ```

  You'll still get four or five `Font shape 'TU/ptm/...' undefined` warnings
  while the class loads. They're expected and harmless; any other font
  warning is not. `smoke/main.tex` in this skill folder is a working
  example (verified 2026-10-21). Build it with
  `tectonic.exe -X compile .claude/skills/ieee-paper/smoke/main.tex -Z search-path=paper --outdir paper/build/smoke`
  to check the toolchain on a new machine.
- Tectonic runs BibTeX and repeats passes by itself. Read
  `paper/build/main.log` for overfull boxes and undefined references. The page
  count is the `/Type /Page` count of `paper/build/main.pdf` (or what the log
  reports).
- The first build downloads TeX packages on demand and can take several
  minutes. Run it in the background. Later builds use the cache and take
  seconds.
- `paper/build/` is git-ignored. Never commit the PDF or logs.

**The `compile_latex` tool is for small checks only**: one figure, one table,
or one section wrapped in `article`, plus `explain_latex_error` for a log
line you don't understand. It takes source as text and can't read files, so
sending the whole paper means retyping the IEEEtran class into every call
(about 180 KB). Don't use it for full builds.
`scripts/flatten_tex.py` (with `--embed`, which minifies) is kept only for
the rare case where Tectonic is unavailable.

Paper source rules:

- Write each section as `paper/sections/NN-name.tex` and use `\input` from
  `paper/main.tex` (that works with Tectonic and on Overleaf).
- Draw every diagram in **TikZ** (the state diagram, the break-glass sequence,
  the 2-of-3 gate, the hash chain). Draw plots in **pgfplots**, with data
  taken from the CSV (`\addplot table` on a copy under `paper/data/`, or
  inline coordinates generated by a script), so plots can't drift from the
  results. Don't use the PNGs in `bench/results/`: they're the harness's
  quick-look plots.
- Fix every error, every undefined reference and every overfull `\hbox`
  wider than 10pt. Report the page count from the built PDF.

## Done when

- [ ] `tectonic -X compile paper/main.tex` builds with no errors, no
      undefined references and no overfull box over 10pt, and the PDF is
      8–10 pages plus references.
- [ ] Every technical sentence has a `% src:` tag, and each tag resolves to a
      source that says the same thing.
- [ ] The security table matches a claims run on the commit being described,
      with its date and short sha in the caption.
- [ ] All `PROJECT.md` §5 caveats are in Section X, and the five named above
      are in the abstract.
- [ ] Benchmark numbers match the CSV, with the machine named.
- [ ] Every citation is real and cited fairly, with no unused bib entries.
