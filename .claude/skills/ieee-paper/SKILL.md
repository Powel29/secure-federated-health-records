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
- Include a **security-properties table** in Section VII. For each primitive
  or construction, give: the property claimed, the security model, whether
  it's tested (which claim), and whether it's proven. Never claim IND-CPA,
  unidirectionality or collusion resistance for a construction nobody has
  analysed. Write "not proven", which for the hand-rolled PRE and the
  Shamir-over-policy-tree structure is the only honest entry.
- **Figures match the shipped code.** The state diagram and transition table
  are derived from `src/lifecycle/` and `src/contracts/`, not from a doc.
  When the code changes, the figure changes in the same PR.

## Required structure (IEEEtran conference, 8–10 pages + references)

| # | Section | Must contain |
|---|---|---|
| — | Abstract + IEEEkeywords | Problem, contribution, the main result, **and one or two sentences of limitations** (see below) |
| I | Introduction | The gap: consent, revocation and break-glass are usually separate mechanisms, and log-gated decryption (transparent decryption) has not been applied inside one EHR key lifecycle; our contributions as a list, worded as a combination (ADR-0088) |
| II | Related Work | Every group in the coverage table below, each with its honest delta; a comparison matrix whose "this work" row comes from the live evidence, not from the review |
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
break-glass is 2-of-2 in this build, "no plaintext on the wire" holds under
TLS only, and the audit service is trusted (no proofs of presence or extension).

Never claim out-of-scope work (`PROJECT.md` §6): ML anomaly detection, FHIR/HL7,
real CP-ABE, or scalability curves over #patients/#facilities. Those curves
were cut and get stated as a limitation. The paper uses no real patient data
and says the dataset is synthetic.

Say plainly that the federation is **simulated**: a few mock facilities with
cross-certified PKI, run as local processes. Don't imply real HIE or FHIR
interoperability. Overstating deployment reality is the easiest dishonesty to
fall into and the easiest to catch.

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

## Related work, novelty and citations

The novelty position is `PROJECT.md` §4 as restated by ADR-0088. In short:

- **Forbidden claim:** being first to make logging (or a log entry) a
  cryptographic precondition of decryption or break-glass. It's prior art:
  accountable and transparent decryption. Also never claim to be first to
  offer break-glass over encrypted records, or time-limited search.
- **The claim:** the combination, implemented. One signed key lifecycle for
  consent, revocation, break-glass and expiry, plus transparent-decryption-style
  log gating instantiated for federated break-glass (a mandatory audit share,
  released only after assertion validation and commit), plus emergency-scoped
  search, plus test and wire evidence. Present transparent decryption as the
  primitive we instantiate, and say plainly that our log is weaker (trusted
  hash chain, `PROJECT.md` §5 item 13).
- **Grant is not a rotation.** Grant adds a key wrapping; Revoke and expiry
  rotate. Don't write "every transition rotates the key".
- **2511.17464** is cited for signed, time-bounded, audited grants. Never cite
  it for revocation-as-key-rotation, which wasn't confirmed.

**Where references come from.** The lead list is
`docs/review/2026-10-21-novelty-publishability-review.md` (§2–§5, §8, and its
Sources list). Read its status note first: it marks which findings are out of
date (the 2-of-3 bypass, the assertion check, expiry shares, "5/11 claims").
Never repeat those as current. Its bibliography is **leads, not references**.
Some numbered sources point at the wrong paper (e.g. [12], [18], [33]), and
§8 lists unverified ones. For every entry you cite:

- Open the DOI, arXiv abstract, IACR ePrint page or publisher page, and check
  the authors, title, venue, year and pages there, not in the review.
- Check that the paper says what you cite it for. If you can't reach a
  primary source, drop the citation. Don't invent or "fix up" an entry.
- Record each check in `paper/notes/refs-verified.bib`, with a comment on
  where it was verified, or mark the entry `DROPPED`.

**Coverage.** The related-work section has to engage with at least these
groups, using whichever of their papers survive verification. Each group gets
one sentence on what it does and one on our delta:

| Group | Leads in the review |
|---|---|
| Accountable / transparent decryption | Kroll et al. 2018; Ryan 2017; Cheval, Moreira & Ryan, EuroS&P 2023; Larch, OSDI 2023; PORTEX, TIFS 2025 |
| Break-glass access control | Brucker & Petritsch, SACMAT 2009; Ferreira et al. 2006; Marinovic et al., Rumpole, SACMAT 2011 |
| Cryptographic break-glass | Brucker, Petritsch & Weber 2010; Zhang, Chow & Sun, AsiaCCS 2016; Scafuro, PKC 2019; de Oliveira et al. 2019/2020; Yang, Liu & Deng (LiBAC) |
| Encrypted PHR sharing | Li et al., TPDS 2013 (anchor) |
| Time-limited search / PRE in e-health | Yang & Ma, TIFS 2016 |
| Consent at the policy layer | arXiv 2603.07004 (anchor); arXiv 2511.17464 |

Present the rivals fairly. Quote Kroll et al.'s hospital-emergency
application yourself, before a reviewer does.

While drafting, if a sentence needs a reference you don't have verified yet,
write `\cite{TODO-topic}` instead of a plausible-looking entry. A verifier
treats any `TODO-` key left in the final draft as a BLOCKER. Quote sparingly
(paraphrase by default), and attribute precisely.

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
- [ ] All `PROJECT.md` §5 caveats are in Section X, and the six named above
      are in the abstract.
- [ ] Benchmark numbers match the CSV, with the machine named.
- [ ] Every citation is real and cited fairly, with no unused bib entries.
- [ ] No "first to" claim about log-gated decryption, break-glass or
      time-limited search; transparent decryption is cited as the primitive we
      instantiate (ADR-0088).
