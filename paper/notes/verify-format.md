# V5 — format and build verification

**Summary: 2 BLOCKER, 15 MINOR.** The build is clean by the skill's mechanical rules: 0 errors, 0 undefined refs or citations, 0 multiply-defined labels, 0 overfull boxes, and the body is 9.5 pages. Both blockers are overlapping labels inside TikZ figures, which leave parts of Fig. 3 and Fig. 4 unreadable in print.

## Build stats (tectonic 0.17.0, `-X compile paper/main.tex --outdir paper/build/v5`, built at 57a1a8c plus the untracked paper/ tree)

- Errors (`^!`): 0
- Undefined references or citations: 0. Multiply-defined labels: 0.
- Overfull \hbox or \vbox: 0
- Underfull: 29 unique (27 \hbox, 9 of them at badness 10000; 2 \vbox while \output is active)
- Font: the 4 expected `TU/ptm/*` substitution warnings plus the summary line. No missing-character warnings.
- Bibliography: 21 entries printed, 0 missing keys. 1 bib entry is never cited (`blaze1998proxy`).
- Labels: all 26 referenced labels resolve (32 `\newlabel` entries in main.aux). 4 labels are never referenced and do no harm: sec:intro, sec:lifecycle-states, sec:lifecycle-signing, sec:lifecycle-access.
- PDF: 10 pages, US letter, IEEEtran conference, two columns.
- **Body ends on page 10, left column, about 55% down the column** (the last line of XI Conclusion, "…bility runs we cut."). REFERENCES starts directly below it in the same column. Body length is about 9.5 pages, inside the 8–10 limit.
- Structure: the abstract and IEEEkeywords are present. Sections I–XI appear in the required order with the required titles (Introduction; Related Work; Threat Model and Goals; System Overview; Key-Lifecycle State Machine; Break-Glass Protocol; Security Analysis; Traffic Analysis; Implementation and Evaluation; Limitations; Conclusion). `\bibliographystyle{IEEEtran}` is set. There is no `\includegraphics` and no PNG anywhere: every figure is TikZ or pgfplots.
- Figure fonts: every TikZ and pgfplots label is `\footnotesize`. None use `\tiny`, `\scriptsize`, `scale<0.8`, `\resizebox` or `\scalebox`. The tables use `\footnotesize`. No "??" appears in the PDF text.

## Issues

[BLOCKER] paper/figures/gate-chain.tex:39 — The (b) label "next entry" (`above=0pt of e2`) is drawn on top of the (a) box "KEM to clinician's ElGamal key" (line 25, at y=-1.8). On page 6 both read as "EnelGxtamenatlrykey". The (a) and (b) panels share vertical space: the panel (b) scope is at `yshift=-3.25cm`, but box `d` extends below y=-2.1. — Fix: increase the scope shift to `yshift=-3.75cm`, or lift column (a) by placing k/u/d at y = 0.3/-0.55/-1.4. Re-render and check that "next entry", "genesis" and the ElGamal box no longer intersect.

[BLOCKER] paper/figures/breakglass-sequence.tex:42-44 — The step-6 label "**6** log rewrap" (message at y=-8.75) is printed over the bottom line "unwrap DEK" of the facility action box. That box is anchored north-east at y=-7.3 and is five lines tall, so it extends below -8.75. On page 5 "6 log rewrap" is printed over "unwrap DEK" and neither can be read. — Fix: move steps 6–8 down by about 0.5 cm (6 at -9.3, its return at -9.6, 7 at -10.1, 8 at -10.55, `\ybot` at -10.85), or shorten the box text, for example "validate $A$; bind patient; set state; \textbf{gate} 3/4; unwrap".

[MINOR] paper/figures/breakglass-sequence.tex:13 — `lbl/.style={above, inner sep=1pt}` has no fill, so lifelines strike through message labels. Affected labels: "2 get gate share key" (Home and Audit lifelines), "signed key statement", "4 A, gate key", "sealed s3, s4 + e_n", "5 A, cert, 3 sealed shares, pk, event" and "7 KEM_pk(DEK)". — Fix: `lbl/.style={above, inner sep=1pt, fill=white}`. Keep the lifelines on the background layer.

[MINOR] paper/figures/gate-chain.tex:15-17 — The dashed "audit service" fit box around s3/s4 cuts through the (b) label "genesis", and its left `audit\\service` label crowds the (b) panel tag. The arrow from $K_E$ to "AES-GCM unwrap DEK" (line 27) ends on top of the word "unwrap". — Fix: the yshift from the blocker fix resolves the first problem. For the arrow, add 0.15 cm of vertical gap between k, u and d (for example y = 0, -0.95, -1.9) or reduce `minimum height`.

[MINOR] paper/sections/06-breakglass.tex:64,66 — `\texttt{src/audit/share\_custody.py:94--110}` and `\texttt{src/api/audit\_service.py:425--446}` print a literal double hyphen "94--110", because the typewriter font has no en-dash ligature. File:line citations in running prose also read as a code review rather than a paper. — Fix: write `\texttt{src/audit/share\_custody.py}, lines 94--110` with the `--` outside `\texttt`, or move file:line references to a footnote or artifact appendix.

[MINOR] paper/tables/secprops.tex:12 — The Table IV `p{}` columns are fully justified, which produces rivers such as "Shamir      3-of-4      over" and "Scheme  assumed;  code / not proven" (underfull badness 10000 at lines 25–27). — Fix: prefix each column with `>{\raggedright\arraybackslash}`, as tables/transitions.tex already does.

[MINOR] paper/sections/05-lifecycle.tex:86-103 — Badly stretched lines (badness 10000 ×3). On page 4 the line reads "Illegal   transitions   fail   closed   before   anything": long `\texttt` identifiers (create_transition_event, validate_transition, IllegalTransitionError) cannot hyphenate. — Fix: add `\setlength{\emergencystretch}{1.5em}` to the main.tex preamble, and/or let the identifiers break with `\usepackage[htt]{hyphenat}` or `\allowbreak` after underscores.

[MINOR] paper/sections/05-lifecycle.tex:120-135 — Stretched lines (badness 5607/10000/6691). — Fix: same as above.

[MINOR] paper/sections/06-breakglass.tex:14-42 — The line "An   Emergency   Assertion   A   carries   a   one-time" is stretched by `\texttt{assertion\_id}` (badness 10000). — Fix: same as above, or reword so the identifier does not fall at a line end.

[MINOR] paper/sections/06-breakglass.tex:94-106 — The opening lines of D. Hash Chain are stretched ("event   type   and   metadata,   actor,   correlation   iden-", badness 10000 ×2) by three `\texttt` field names. — Fix: same as above.

[MINOR] paper/sections/06-breakglass.tex:109-115 — The opening lines of E. Expiry by Full Rotation are stretched ("The   deployed   window   is   4 h,   which   a   caller", badness 10000 ×2). The log attributes this to `07-security-analysis:1, lines 109--1`, but the paragraph is in 06. — Fix: `\emergencystretch`, or merge the short first sentence into the next one.

[MINOR] paper/sections/07-security-analysis.tex:16,69,85 — Subsection titles use sentence case ("Per-claim arguments", "Are the tests decorative?", "What is proven"), while every other subsection uses title case ("Emergency Assertion and Replay", "Signed Transitions"). A question as a heading is also unusual for IEEE. — Fix: use "Per-Claim Arguments", "Mutation Testing of the Claim Tests" (or "Are the Tests Decorative?") and "What Is Proven".

[MINOR] paper/tables/wire.tex:8 and paper/tables/bench.tex:6 — Inside IEEEtran's small-caps table captions, `\texttt{99092d1}` and `\texttt{57a1a8c}` render as "99092D1" and "57A1A8C" on page 8, and `local-processes+postgres` renders as "LOCAL−PROCESSES+POSTGRES" on page 9. A git hash shown in the wrong case is a different identifier. Table III's caption renders its hash correctly. — Fix: in the generators (paper/data/make_wire.py and make_bench_table.py), emit `\textnormal{\texttt{…}}` or `{\upshape\ttfamily …}` and regenerate. Do not hand-edit the tables.

[MINOR] paper/tables/related.tex (generated by paper/data/make_related.py) — The Table I caption is a 10-line small-caps block that holds the column legend and footnotes a–c. It is hard to read and dwarfs the table. — Fix: keep the caption to one sentence, and move the legend and the a/b/c notes below the tabular as a `\footnotesize` note, the way tables/transitions.tex does.

[MINOR] paper/sections/05-lifecycle.tex:5-9 — Fig. 2 and Table II float to the top of page 4's left column, above the "V. Key-Lifecycle State Machine" heading, which lands about 75% down that column. The reader meets the state diagram before the section that introduces it. Fig. 3 on page 5 similarly precedes the VI heading. IEEEtran allows this, but it reads poorly. — Fix: move `\input{figures/states}` and `\input{tables/transitions}` after the first paragraph of §V.A, so they land at the top of the next column or page.

[MINOR] paper/sections/04-system-overview.tex:64 and paper/sections/05-lifecycle.tex:7 — Underfull \vbox while \output is active (badness 10000 and 1087). Page 3's left column visibly stretches the paragraph gaps around "Adversaries", "Trust assumptions" and "Goals". — Fix: it should disappear once the floats move as above. Otherwise add `\raggedbottom` to the preamble, or trim or extend §III by one or two lines.

[MINOR] paper/main.tex:38 — The last-page columns are unbalanced: the right column (refs [6]–[21]) ends about 25% above the left. — Fix: add `\IEEEtriggeratref{12}` (tune the number) before `\bibliographystyle{IEEEtran}`.

[MINOR] paper/refs.bib:303 — `blaze1998proxy` is never `\cite`d, so it is silently dropped. Proxy re-encryption is discussed (Table IV, Limitation 10) without citing it. — Fix: cite it where the bidirectional ElGamal PRE is introduced (§V.D or Table IV), or delete the entry.

[MINOR] (extraction only) — pdftotext drops math glyphs (`K_E`, `x`, `p`, `≤`, `→`) and garbles the en-dashes in the references when it decodes as Latin-1. The rendered PDF pages show every one of these glyphs correctly. This affects only text search and accessibility, not print. — Fix: none needed. Optionally add `\usepackage{mmap}`-style ToUnicode maps; fontspec already handles text fonts.

Not issues: the 4 `TU/ptm` font warnings are expected. The Fig. 4 float carries two labels (`fig:gate` and `fig:chain`), which is intentional and is referenced as Fig. 4a and Fig. 4b. The Fig. 5 and Fig. 6 pgfplots fit `\columnwidth` and use `\footnotesize` ticks and labels. The Fig. 1 trust-boundary diagram is readable; the `x=3,4` label sits tight against the dashed boundary but does not overlap it. The reference [9] URL is wrapped in `\url` and breaks cleanly. Page renders of the build are in paper/build/v5/p1.png–p10.png.

## Round 2

**Summary: 0 BLOCKER, 7 MINOR (5 still open, 2 new). Both blockers are RESOLVED, as are 8 other round-1 items; the five round-1 stretched-line entries are merged into one open item below.**

### Build stats (rebuilt into paper/build/v5 with `--keep-logs --keep-intermediates`; pages re-rendered to p1–p11.png)

- Errors: 0. Undefined references or citations: 0. Multiply-defined labels: 0. Overfull boxes: 0.
- Underfull: 14 unique \hbox (5 at badness 10000), down from 27; 4 \vbox while \output is active, up from 2.
- Font: only the 4 expected `TU/ptm` warnings plus the summary line.
- Labels: all referenced labels resolve. Bib: 0 missing keys and 0 uncited entries.
- PDF: **11 pages**. **The body ends on page 10, left column, at the bottom of the column** (the last line of XI Conclusion, "…and the scalability runs we cut."). REFERENCES starts at the top of page 10's right column and continues to page 11 (refs [20]–[21] only). Body length is about 9.5 pages, inside the 8–10 limit.
- Structure: unchanged and correct: abstract, IEEEkeywords, I–XI in order, `\bibliographystyle{IEEEtran}`, no `\includegraphics`. No "??" in the PDF.

### Prior issues

- RESOLVED (BLOCKER), figures/gate-chain.tex: panels (a) and (b) are now separate. "next entry", "genesis" and the "KEM to clinician's ElGamal key" box no longer intersect, and the dashed audit-service box no longer cuts "genesis". Checked on page 6.
- RESOLVED (BLOCKER), figures/breakglass-sequence.tex: "6 log rewrap" now sits below the facility box ("unseal shares; … unwrap DEK"). Checked on page 5.
- RESOLVED, breakglass-sequence.tex:13: labels have `fill=white`, and lifelines no longer strike through any message label (checked at zoom on steps 2–5).
- RESOLVED, 06-breakglass.tex:64,66: the file:line `--` citations are gone from the prose.
- RESOLVED, tables/secprops.tex: Table IV columns are ragged-right, with no rivers.
- RESOLVED, 07-security-analysis.tex:16,70,86: subsection titles are now title case.
- RESOLVED, tables/wire.tex and tables/bench.tex captions: `99092d1`, `57a1a8c` and `local-processes+postgres` print in lowercase typewriter (pages 8 and 9).
- RESOLVED, refs.bib: no uncited entries remain.
- RESOLVED (superseded), main.tex last-page balance: the references now span page 10 right and page 11, so the old imbalance is gone (see the new issue below).
- RESOLVED (n/a): the round-1 "extraction only" note stands as information.
- STILL OPEN [MINOR] sections/05-lifecycle.tex:87-105, 122-137; sections/06-breakglass.tex:14-43, 93-105 and 108-115 (the log attributes the last to `07-security-analysis:1`): `\emergencystretch=1em` reduced but did not remove the badness-10000 lines. Visible stretched lines remain: "An   Emergency   Assertion   A   carries   a   one-time" and "event   type   and   metadata" on page 6, and "The   deployed   window   is   4 h" on page 6, and the same pattern on pages 4 and 5. — Fix: raise to `\emergencystretch=2em`, or allow breaks in `\texttt` identifiers (`\usepackage[htt]{hyphenat}`), or reword the line ends.
- STILL OPEN [MINOR] sections/05-lifecycle.tex:8-9: Fig. 2 and Table II still sit above the "V. Key-Lifecycle State Machine" heading, which lands on line 68 of 84 on page 4's left column. — Fix: move the two `\input`s below §V's first paragraph.
- STILL OPEN [MINOR] tables/related.tex:5 (generated by paper/data/make_related.py): the Table I caption is still an 8-line small-caps legend with footnotes a–c. — Fix: as in round 1, keep a one-sentence caption and move the legend and notes below the tabular.
- STILL OPEN [MINOR] tables/wire.tex:16,18: Table V cells are still justified ("6  of  13  canaries  hit", "URI  visible;  4314 B"; badness 10000). — Fix: in make_wire.py, use `>{\raggedright\arraybackslash}p{…}` columns and regenerate.
- STILL OPEN [MINOR] sections/04-system-overview.tex:65: an underfull \vbox (badness 10000) is still reported. A vertical-stretch gap is visible above the Fig. 1 caption and IV heading area on page 3, though slight. — Fix: as round 1 (`\raggedbottom`, or move the floats).

### New issues

[MINOR] paper/main.tex:39-40 — Refs [20]–[21] spill onto page 11, which holds only those two entries, about 9 lines. An eleven-page PDF with a nearly empty last page looks unfinished, and a reader may count it as 11 pages. — Fix: add `\IEEEtriggeratref{12}` (or a nearby value) before `\bibliographystyle{IEEEtran}`, or trim about 10 lines of body text so the references fit on page 10 and the PDF returns to 10 pages.

[MINOR] paper/tables/related.tex:47, paper/sections/02-related-work.tex:32, paper/sections/03-threat-model.tex:6 — New underfull \vbox warnings while \output is active (badness 10000, 2951 and 4205), caused by Table I and the heading at the top of page 3. The paragraph gaps in page 2's columns stretch. — Fix: `\raggedbottom` in the preamble, or shorten the Table I caption, which also addresses the open item above.
