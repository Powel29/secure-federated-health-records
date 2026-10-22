# V1 evidence trace: verify-evidence

**Summary: 8 BLOCKER, 13 MINOR.** HEAD `57a1a8c`, working tree as of 2026-10-22. 289 `% src:` comments
(814 tag references once ranges are expanded). 349 distinct fact ids resolve. 24 tag strings do not.

## Issues

[BLOCKER] paper/sections/02-related-work.tex:7 — The dangling tag `facts-F8 matrix` points at the unnumbered "Related-work matrix" table, not at a numbered fact. — Fix: delete `facts-F8 matrix` and keep `% src: facts-F8#23`, which already covers the sentence.

[BLOCKER] paper/sections/10-limitations.tex:9,13,17,22,27,30,34,37,42,46,51,55,59,64,67,74,79 — 17 tags cite `PROJECT.md §5 item N` / `PROJECT.md §6` directly, outside the fact sheets. WRITER-RULES says not to cite sources outside the fact sheets. PROJECT.md:330-429 does say what items (1)–(13) say; I checked each one. However, items (7) (name lookup / temporary encounter id) and (12) rest on PROJECT.md alone. — Fix: append facts for PROJECT.md §5 items 1–13 and §6 to a fact sheet. Each fact should cite `PROJECT.md:<line>` plus code where it exists: item 7 → `portal/clinician/encounters.py`; item 12 → existing facts-F4#42. Then retag, e.g. `% src: facts-F5#57, facts-F2#87, facts-F4#41` for (1).

[BLOCKER] paper/sections/11-conclusion.tex:25 — The tag is malformed: `PROJECT.md §5 items 13, 8, 9, 4, 10, 11, 5, 12, 1`. The parser reads it as 8 bare numbers that resolve nowhere. — Fix: once the new PROJECT §5 facts exist, use `% src: facts-XX#a, …, facts-F3#19, facts-F7#35`.

[BLOCKER] paper/tables/related.tex:23-45 — The 18 rival rows (Kroll … Romel) carry no `% src:` tag. Only the "This work" row (line 47) has one. The cells do match the facts-F8 matrix: I checked all 18 rows, FED column dropped. — Fix: have `make_related.py` append a tag per row, e.g. Kroll `% src: facts-F8#1`, Ryan `#2`, Cheval `#3`, Larch `#4`, Li 2025 `#5`, Brucker 2009 `#6`, Ferreira `#7`, Marinovic `#8`, Brucker 2010 `#9`, Zhang `#10`, Scafuro `#11`, de Oliveira 2019 `#12`, 2020 `#13`, LiBAC `#14`, Li 2013 `#15`, Yang–Ma `#16`, Muslim `#17`, Romel `#18`.

[BLOCKER] paper/sections/04-system-overview.tex:49 — The caption says "Thin arrows carry no key material (… facility to audit: log append)". facts-F4#43 lists facility→audit as "append, share replacement". The code agrees: `src/api/audit_service.py:345-377`, a facility-only `PUT /breakglass/shares` takes sealed shares 3 and 4 at rotation, and `src/api/rotation.py:199-210` deposits shares to all three holders. So the facility→audit edge does carry (sealed) key material, and the rotation deposits facility→custodian and facility→authority are neither drawn nor listed as "not drawn". — Fix: change the caption to "facility to audit: log append and, at rotation, the new sealed shares 3 and 4". Also add "rotation share deposits (facility to custodian/authority)" to "Not drawn", or draw the facility→audit edge thick. Tag facts-F4#43, facts-F2#85.

[BLOCKER] paper/sections/11-conclusion.tex:3-5 — "consent, revocation, break-glass and expiry share one signed key lifecycle of four states". The tagged facts (F1#1, F1#11, F4#1) do not say consent is in the lifecycle. facts-F1#35 contradicts it: consent grants do not move lifecycle state, and `src/consent/service.py:1-8` makes consent a signed read-time predicate that does not wrap or re-wrap. — Fix: "We built a simulated federated EHR in which a record's consented baseline, patient revocation, break-glass and expiry are states of one signed key lifecycle." (the abstract's wording). Tag `facts-F1#1, facts-F1#11, facts-F1#35, facts-F4#1`.

[BLOCKER] paper/tables/related.tex:47 — The "This work" LC cell is `✓^b` ("patient consent and revocation in one lifecycle"). By facts-F1#35, consent is outside the state machine: no grant transition is emitted and the consent module never touches lifecycle state. Rival rows with comparable partial coverage (Li 2013, de Oliveira, Romel) get ∘. — Fix: set LC to `$\circ^{b}$` and keep footnote b. F8#23's novelty argument still holds, since no rival has LG ✓ together with LC ∘.

[BLOCKER] paper/sections/07-security-analysis.tex:37 — "The claim text predates the 3-of-4 split". Neither tagged fact (F2#36, F2#37) says this. It is true from git: the C3 text was added in `e79bcd3` (2026-10-07, `tests/security/claims.py:59-61`), and the split landed in `99092d1` (2026-10-21). — Fix: append to facts-F5 "C3's statement was written on 2026-10-07 (`git log -S"A single share, including the audit service" -- tests/security/claims.py` → e79bcd3), before ADR-0089 (`99092d1`)" and tag it. Otherwise drop the clause.

[MINOR] paper/sections/08-traffic-analysis.tex:53; paper/sections/09-evaluation.tex:29,51 — Tags point at Contradictions entries (`facts-F6#C8`, `facts-F7#C1`, `facts-F7#C6`), not at numbered facts. The content is correct (checked against `git log` and `WORKFLOW.md:550-551`). — Fix: promote each to a numbered fact ("p53 files built at 0b95f2b+branch, 2026-10-19, predate 99092d1"; "six uvicorn servers in threads of one process"; "same machine measured ~405 then ~247 ms on 2026-10-21") and retag.

[MINOR] paper/notes/facts-F2.md:132-145, paper/notes/facts-F8.md:127-138 — The "Contradictions found" entries are numbered 1–14 and 1–12, so they collide with fact numbers. A tag such as `facts-F2#5` or `facts-F8#3` is ambiguous between the two lists. (I resolved every tag to the numbered fact, which fits each sentence.) — Fix: renumber those entries `C1…`, as F3/F6/F7 already do.

[MINOR] paper/sections/07-security-analysis.tex:74, 08-traffic-analysis.tex:17, tables/secprops.tex:16-32, tables/claims.tex:4, tables/wire.tex:3, tables/bench.tex:13-19 — Some tags use ranges (`facts-F5#38-45`, `facts-live#1-13`) or carry parenthetical annotations (`facts-F7#26 (benchmark_summary.csv row …)`). The skill shows only comma-separated ids. All of them resolve once expanded. — Fix: list the ids explicitly. Move the annotations to a separate comment.

[MINOR] paper/figures/states.tex:17-35, tables/secprops.tex:16-32, tables/claims.tex:4, tables/wire.tex:3 — These tags sit on the line *before* the row or element they support, which reverses the "same line or the line after" rule. In claims.tex and wire.tex, one tag above the table also stands for every row. — Fix: put each tag at the end of its row (`\\ % src: …`) or after the caption, as bench.tex and transitions.tex do.

[MINOR] paper/sections/07-security-analysis.tex:75 — "43 rows, all red". The 2026-10-19 log (`docs/review/p5-1-evidence.md`, mutation log) has green mutation cells too, e.g. C1 row 1 "C1c: green". What holds is that every row went red under at least one mutation (facts-F5#46: "no decorative test"). That fact is also sourced only to a file under `docs/review/`. It is a generated run log, so I accept it as a self-description, but it is not a run on 57a1a8c. — Fix: "(2026-10-19, 43 rows, each red under at least one mutation)".

[MINOR] paper/sections/03-threat-model.tex:28 — "Four parties are trusted" is tagged only facts-F5#21. That fact names the audit service, the custodian and the absence of an on-path adversary. It does not name the timer or the PKI root, and gives no count. — Fix: tag `facts-F5#21, facts-F5#6, facts-F4#31` (timer, root), or tag the count where the four parties are listed.

[MINOR] paper/sections/00-abstract.tex:3 — "Health-record systems usually build … as separate mechanisms and often log emergency overrides only after the fact" generalises from the 18 surveyed papers (F8#7, #17, #23). F8#23 is about the compared works only. — Fix: "In the systems we compare, consent, revocation and break-glass are separate mechanisms, and emergency overrides are logged after the fact."

[MINOR] paper/sections/02-related-work.tex:58; paper/sections/01-introduction.tex:19 — Two sentences go further than the code. "We give a cryptographic realisation of that lifecycle" refers to Muslim's creation/activation/revocation/expiration. "a key lifecycle that also carries consent and revocation" has the same problem. In the code, consent creation and activation are a signed read-time predicate, not keys (facts-F1#35). F8#17's "our delta" is the fact-writer's own claim, with no code source. — Fix: "We realise its revocation and expiration cryptographically, by re-keying; consent itself stays a signed read-time predicate over the GRANTED baseline." For the intro: "…inside a key lifecycle whose baseline is the consented state and which also carries revocation".

[MINOR] paper/sections/09-evaluation.tex:71 — "a 66-byte share per holder". facts-F2#39 gives 66 B per x, and the audit service holds two (132 B). — Fix: "a 66-byte share per $x$ (two at the audit service)".

[MINOR] paper/sections/09-evaluation.tex:49-51 — "earlier runs of the harness gave about 15 to 405 ms" rests on facts-F7#25 alone. That fact cites WORKFLOW.md task notes, not a results file. — Fix: say "as recorded in the project's task log (not re-run)", or drop the range and keep facts-F7#C6's point that two runs on one machine differed (~405 vs ~247 ms).

[MINOR] paper/tables/wire.tex:8 — The caption's provenance ("run of 2026-10-21 at 99092d1; no capture, analyser or service code changed up to 57a1a8c") appears only in the facts-F6 preamble, not as a numbered fact. Also, the capture timestamp (db_commit_ts 1792588199.86 = 18:39:59 IST) is earlier than the time `99092d1` was committed (18:50). The run was on the tree that became 99092d1, not on the commit itself. I confirmed `git diff --stat 99092d1 57a1a8c -- src wire deploy tests` is empty. — Fix: add a numbered F6 fact with that provenance, and write "(captured 2026-10-21 on the tree committed as 99092d1; …)".

[MINOR] paper/sections/05-lifecycle.tex:64-65 — "a domain tag … followed by those fields". "Those fields" refers back to a list that includes the signature, but the signed bytes exclude it (`src/lifecycle/state_machine.py:72-101`). — Fix: "followed by every field except the signature, in a fixed order, …".

## Checked

- **Tag resolution:** All 289 `% src:` comments in sections/, tables/ and figures/ were parsed by script. That is 814 references after range expansion, against 541 parsed fact entries. 349 distinct fact ids resolve. The 24 unresolved strings are the PROJECT.md/F8-matrix/malformed tags above. 3 tags point at Contradictions entries.
- **Untagged content:** I split every file into tag-delimited chunks (302) and read them all. The only untagged technical content is the 18 related.tex rows. Everything else untagged is structural (section roadmap, `\label`, `\end`, legend `EmOpen = …`).
- **Sentence ↔ fact:** I compared every tagged sentence, caption and row with its facts. That gave the mismatches listed above. Every bench-table number was checked against `bench/results/benchmark_summary.csv` and `paper/data/*.csv`. The claims table was checked against `paper/notes/live-claims-raw.txt` (35 sys / 18 mod). The wire table was checked against `bench/results/p55_wire_checks.json`. The search-leakage numbers were checked against both p53 JSONs.
- **Fact ↔ source:** I opened the cited source for every fact used in Sections V–VIII and their figures and tables. That covers F1 #1–5, 9–37, 39–41, 45–61, 63–72; F2 #1–43, 45–67, 71–90 as used; F3 #3, 14, 17–19, 22, 24, 29–30, 32–38, 40–49, 51–56, 58; F5 #23, 26, 33, 35, 37–46, 49–50; F6 #1–6, 9–13, 18, 20, 24–53, 57–77, 90; facts-live #1–17. Most of these are code; the rest are JSON results, `docs/review/p5-1-evidence.md`, WORKFLOW.md and PROJECT.md. All of them support their facts. The only exceptions are the self-referential sources noted above.
- **Other sections:** I also traced about 45 facts outside V–VIII to source: F4 #1, 11, 14, 16, 22, 26, 27, 34, 41, 43; F5 #4–6, 8, 12–19; F7 #1, 3, 7–9, 14–16, 20–34, 38. I re-ran the file count and line count myself (97 files / 16,450 lines).
- **Not traced:** The F8 external papers (URLs/DOIs) were not fetched, since downloading is out of scope. Their cells and sentences were checked only against the F8 fact text.

## Round 2

**Summary (round 2): 0 BLOCKER, 3 MINOR** (all 8 prior BLOCKERs and 10 of 13 prior MINORs resolved; no new issues found).

Re-scan: 308 `% src:` comments, 858 references, 576 parsed fact entries (incl. facts-F9 1–17, C1–C3); **0 dangling tags, 0 tags on Contradictions entries**, no range or annotated tags in sections; every tag-delimited chunk re-read — no untagged technical sentence or row (related.tex now tags each rival row with its F8 fact, rows/ids checked one by one).

### Prior issues

- [BLOCKER] 02-related-work.tex:7 `facts-F8 matrix` — RESOLVED (now `facts-F8#23`).
- [BLOCKER] 10-limitations.tex PROJECT.md tags — RESOLVED (retagged to facts-F9#1–17; each F9 fact traced to PROJECT.md:330-461 and to its code/ADR corroboration, incl. item 7 → `portal/clinician/views.py:8-11`, `encounters.py` `TEMP-…`, ≥20-char confirmation; item 11 now states §5's DEK claim vs the capture, per F9#C2).
- [BLOCKER] 11-conclusion.tex:25 malformed tag — RESOLVED (`facts-F8#25, facts-F3#19, facts-F7#35`; F8#25 checked against PROJECT.md §5 items).
- [BLOCKER] tables/related.tex rival rows untagged — RESOLVED (rows 20–42 → F8#1…#18 in matrix order).
- [BLOCKER] 04-system-overview.tex:49 caption — RESOLVED (facility→audit now "log append and, at rotation, the new sealed shares 3,4"; rotation deposits listed as not drawn; tagged F4#43, F2#85).
- [BLOCKER] 11-conclusion.tex:3-6 consent in lifecycle — RESOLVED (consent now "a signed read-time check against its GRANTED baseline"; new F1#77 traced to `src/consent/service.py:1-8`).
- [BLOCKER] related.tex:44 LC ✓ — RESOLVED (now `$\circ^{b}$`, footnote "Revocation is a transition; consent is a read-time check").
- [BLOCKER] 07-security-analysis.tex:37 "predates" — RESOLVED (new F5#57; `git log -S` → e79bcd3 2026-10-07, `99092d1` 2026-10-21 18:50, re-checked).
- [MINOR] Contradiction-entry tags (08:53, 09:29, 09:51) — RESOLVED (F6#91, F7#40, F7#41; F6#91 checked against `bench/results/p53_search_leakage.md:31-33`).
- [MINOR] facts-F2.md / facts-F8.md Contradictions numbered 1…n — STILL OPEN: facts-F2.md:132-145 and facts-F8.md:127-138 still collide with fact numbers (e.g. `facts-F2#5`, `facts-F8#3` are ambiguous). — Fix: renumber them `C1…`.
- [MINOR] Range / annotated tags — RESOLVED (explicit ids; bench.tex annotations moved to their own comment lines).
- [MINOR] Tag placement before content — STILL OPEN for paper/figures/states.tex:17,24,27,30,33,35 (tags still precede the TikZ elements); RESOLVED for secprops (same-line), claims and wire (tag right after caption). — Fix: move each states.tex tag after the `\draw`/`\node` it supports.
- [MINOR] 07:76 "all red" — RESOLVED ("each red under some mutation").
- [MINOR] 03:28 "Four parties" — RESOLVED (adds F5#6, F4#31).
- [MINOR] 00-abstract.tex:3 generalisation — STILL OPEN (narrowed to "the systems we compare", but "emergency overrides are logged after the fact" still does not hold for all of them: de Oliveira 2020 and Li 2013 describe no break-glass logging (F8#13, F8#15) and Kroll/Ryan/Cheval log before release (F8#1–3); 01-introduction.tex:11 "usually separate mechanisms" has the same F8#23-only basis). — Fix: "…are separate mechanisms, and where emergency overrides are logged at all, the log is not a precondition of key release." and in the intro "In the works we compare, consent, revocation and break-glass are separate mechanisms."
- [MINOR] 02:58 / 01:19 consent overreach — RESOLVED (revocation/expiration only; consent stays a read-time check; F1#47, F1#77).
- [MINOR] 09:71 share size — RESOLVED ("a 66-byte share per $x$").
- [MINOR] 09:49-51 WORKFLOW-only numbers — RESOLVED (now "our task log, not re-run, records 405 then 247 ms", F7#41 traced to WORKFLOW.md:550-551).
- [MINOR] wire.tex:7 provenance — RESOLVED ("captured 2026-10-21 on the tree committed as 99092d1"; F6#93: timestamp, commit time, empty `git diff --stat 99092d1 57a1a8c -- src wire deploy tests` re-run).
- [MINOR] 05:64 "those fields" — RESOLVED ("every field but the signature").

### New and changed facts traced to source

F1#73 (`custodian_service.py:1324-1343` signs `state→REVOKED` from the stored state; `hospital.py:1126-1144` accepts if from_state matches; EXPIRED→REVOKED is legal) — supports 05:82-85 and the "Timer or Patient" row of transitions.tex / `[T]/[P]` in states.tex, which are now consistent. F1#74 (`hospital.py:1600-1607`), F1#75 (`hospital.py:1207-1215`, rollback CAS without an event), F1#76 (`expiry.py:478-492, 645-662`: recovered session re-signs, `expired_emitted=already_expired`), F1#77 — all verified. F2#46 (`share_release.py:107-111,132`: `expected_facility_id=assertion.facility_id`, federation-membership check), F2#91 (`messaging.py:47`, `share_release.py:112-116`, `hospital.py:1422-1435`), F2#92 (`custodian_service.py:1416-1421`), F2#93 (`hospital.py:1320-1364`: shares opened before assertion validation) — verified. F3#21 (`elgamal.py` `_is_subgroup_member(c1)` before exponentiation) — verified for 09:42-44. F5#57, F6#91–93, F7#39 (19,961 non-blank test lines, re-counted), F7#40, F7#41, F8#25, F9#1–17 — verified as above. No regression found: the new sentences in V–VI (patient revoke from EXPIRED, issue-time check on the facility clock, holder facility check = membership, custodian patient check, re-signed EXPIRED event on recovery) each match their facts and the code.

## Round 3

**Summary (round 3, five files only): 0 BLOCKER, 1 MINOR.** Scope: sections/00-abstract.tex, 01-introduction.tex, 02-related-work.tex, 11-conclusion.tex, tables/related.tex, plus facts-F1#78.

Re-scan: 868 tag references across the paper, 0 dangling, 0 Contradictions-entry tags. In the five files I re-read every tag-delimited chunk: every technical sentence and every related.tex row is tagged (rows → F8#1…#18 in order; "This work" row and footnote b → F1#35, F1#77, F1#78); the only untagged text is the section roadmap and `\end{…}`.

**F1#78 traced:** `src/consent/service.py:270` (grant signed by patient), `:307` (`verify` on the grant), `:413-440` (`authorize_read`: signature, status must be GRANTED, `[decided_at, expires_at]`, grantee); `src/api/hospital.py:812` (`if payload.grant is not None`), `:911-916` (else `decrypt_record_via_policy`), `:1004` (grant verified on submit); no lifecycle-state lookup in the read route `hospital.py:728-990`. Source supports the fact; abstract:5-6, intro:26-29, related:58-59, conclusion:1-7 and related.tex footnote b match it ("checked at read time when one is presented … separate from the lifecycle").

**Prior MINOR 3 (abstract/intro overgeneralisation):** intro — RESOLVED (lines 9-14 now "none of these schemes is described as gating key release on a log entry" and "in the works we compare … the log-gated schemes carry no patient revocation lifecycle", both matching F8#1-3, #9, #13, #14, #17, #18, #23). Abstract — mostly resolved; residual:

[MINOR] paper/sections/00-abstract.tex:3 — "the health-record break-glass schemes do not gate key release on a committed log entry" states as fact what the matrix marks "?" for three of them (Marinovic, Brucker et al. 2010, de Oliveira 2019 have LG = ? in tables/related.tex:29,31,34; F8#8, #9, #12 say only "no logging precondition"/unreachable abstract). — Fix: "…and the health-record break-glass schemes are not described as gating key release on a committed log entry" (the intro's wording).

Prior round-2 MINORs 1 (F2/F8 Contradictions numbering) and 2 (states.tex tag placement) are outside this round's file scope and were not re-checked.

## Round 4

**Summary (round 4): 0 BLOCKER, 0 MINOR in scope.** Scope: sections/05-lifecycle.tex, 06-breakglass.tex, figures/states.tex, tables/related.tex, tables/wire.tex; facts-F2/F8 renumbering; updated facts-F8 #7, #8, #10, #12, #16 and matrix rows.

Re-scan (whole paper): 876 tag references, 0 dangling, 0 tags on Contradictions entries, **0 numbering collisions**.

- Round-2 MINOR 1 (Contradictions numbering in facts-F2/F8) — RESOLVED: facts-F2.md:132ff and facts-F8.md Contradictions are now `C1…`; no `facts-F2#n` / `facts-F8#n` tag is ambiguous.
- Round-2 MINOR 2 (states.tex tag placement) — RESOLVED: every tag now follows its `\node`/`\draw` block (lines 22, 26, 29, 32, 34, 39) and the caption (46); tags unchanged in content (F1#1/9/11, #32/#37, #35, #30/#36, #33/#53, #39/#63/#64/#73, caption F1#11/35/36/46/47/73).
- 05 and 06 rewording: re-read every chunk against its facts. All sentences tagged; tags identical to round 2 (Fig./Table inputs moved to 05:35, no tag lost). Wording changes ("An illegal transition fails closed … first calls", hash-chain field list, `\allowbreak` in identifiers) do not change meaning; no strengthening found.
- related.tex: every row tagged (rows → F8#1…#18 in order). The legend and footnotes now sit below the tabular, each tagged (legend → facts-live#12; a → F2#59, F8#3; b → F1#11/35/77/78; c → F1#54). Matrix cells checked: de Oliveira 2019 row (line 26) = ✓ – ✓ ∘ ✓ – – –, which matches the F8 matrix and F8#12 (no audit logging, informal analysis, no implementation). Yang & Ma row (line 32) = ✓ – – ∘ ✓ ✓ ✓ ∘, which matches the matrix and F8#16 (standard-model proof, simulations).
- wire.tex: unchanged; caption tag after caption covers the table (F6#34-53, #90, #93); row values re-checked against p55_wire_checks.json in round 1.
- Updated facts F8#7, #8, #10, #16 only add provenance or detail ("content confirmed" via OpenAlex/publisher abstract); F8#8's added description does not change any sentence that cites it (related-work.tex:27-29 still says only "build break-glass into access-control models"). The external pages were not re-fetched by V1.
- Side effect on the round-3 residual MINOR (00-abstract.tex:3, outside this round's scope): de Oliveira 2019's LG is now ✗, so only Marinovic and Brucker et al. 2010 remain "?". The round-3 fix ("are not described as gating") still applies if the abstract has not been changed.
