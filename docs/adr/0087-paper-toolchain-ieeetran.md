# ADR-0087: The paper is IEEEtran LaTeX, built locally with Tectonic

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Powel
- **Task / source:** PROJECT.md §2 D3 ("IEEE-style"); `docs/plans/ieee-paper-oneshot-prompt.md`
- **Affects:** `paper/`, `.claude/skills/ieee-paper/`, `.gitignore`

## Context

D3 has to be an IEEE-style paper. The machine we write it on had no TeX
install. A `compile_latex` tool is connected to the agent sessions. It takes
the document as text inside the call, can't read `\input` files or images,
and has no IEEEtran class in its TeX Live (checked 2026-10-21).

To use it, the class would have to be embedded in every call. Even minified,
that's about 180 KB (around 55k tokens), retyped exactly on every build. One
wrong character breaks the build, and a generated paper is rebuilt many times.

Two more constraints: the paper's figures and plots must not drift from the
code and from `bench/results/`, and every claim must carry a source tag that
a verifier can check.

## Decision

- The paper is LaTeX with the IEEEtran conference class. Each section is its
  own file under `paper/sections/`, pulled in by `paper/main.tex` with
  `\input`.
- `IEEEtran.cls` (V1.8b) and `IEEEtran.bst` (1.14) come from Tectonic's
  bundle, which ships the current CTAN release (checked 2026-10-21: the
  smoke test's log reports `IEEEtran 2015/08/26 V1.8b`). They are not
  committed; `paper/IEEEtran.*` is git-ignored. (They were vendored in
  `paper/` at first; that added about 8,750 lines to review and nothing the
  bundle lacks, so they were removed.)
- Full builds run locally with **Tectonic 0.17.0**, taken from its official
  GitHub release, with its SHA-256 checked against the digest GitHub
  publishes. It sits at
  `C:\Users\user\AppData\Local\Programs\tectonic\tectonic.exe`.
  `tectonic -X compile paper/main.tex --outdir paper/build` reads the files
  directly and runs BibTeX by itself. `paper/build/` is git-ignored, and
  Tectonic will not create it, so the build command makes it first.
- The `compile_latex` tool stays for small checks (one figure, table or
  section) and for `explain_latex_error`.
- Diagrams are TikZ and plots are pgfplots, with plot data taken from the
  results CSVs.
- Each technical sentence carries a `% src: <fact id>` comment.

The same source builds unchanged on Overleaf.

## Consequences

- A full build costs no tokens and takes seconds once the package cache is
  warm. The page count reflects the real IEEE layout.
- Tectonic fetches TeX packages on demand from its bundle server. The first
  build on 2026-10-21 ran 34 minutes and then failed on DNS and connection
  resets to `relay.fullyjustified.net`. The retry succeeded, and warm builds
  now take about 2.5 s. So the first build needs a working network and should
  run in the background, and a cold cache on a new machine costs the same
  again.
- Tectonic is XeTeX, so IEEEtran's Times request falls back to Latin Modern
  unless the preamble loads `newtxmath` plus `fontspec` with TeX Gyre Termes
  (by file name). The skill carries that preamble and a smoke test that
  builds with it. Teammates building elsewhere need Tectonic too, or
  Overleaf.
- The binary is per machine and isn't in the repo. Its path is written in the
  skill.
- The SVG diagrams in `docs/diagrams/` aren't reused. They get redrawn in
  TikZ, which takes more effort but means no SVG→PDF converter is needed.
- The class version is whatever Tectonic's bundle pins. Today that is V1.8b,
  current since 2015; a future bundle could change it, and the smoke test's
  log shows which one a build used. The `compile_latex` fallback needs local
  copies downloaded into `paper/` (untracked).
- `% src:` comments make the source longer, but nothing strips them: LaTeX
  and Overleaf just ignore them.

## Alternatives considered

- **Build everything through `compile_latex`**, with the class embedded via
  `filecontents*` by `flatten_tex.py --embed`. It works in principle (tested
  with a stand-in class), but it costs about 55k tokens per build and breaks
  on any transcription error. The flattener is kept only as a fallback.
- **MiKTeX or TeX Live.** Gigabytes to install, with an installer that
  changes system settings. Tectonic is one 50 MB binary.
- **Word with the IEEE template.** It has no place for source tags a script
  can check, it diffs badly in git, and there is no headless build.
- **Markdown → pandoc.** pandoc isn't installed, and IEEE two-column layout
  through pandoc is fragile.
- **Overleaf only.** It can't be built or checked from inside the generation
  run.
- **`article` in two columns as an IEEE look-alike.** Then the page count and
  layout mean nothing.
