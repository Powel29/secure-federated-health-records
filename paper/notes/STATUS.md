# D3 paper build — status

Branch `paper/ieee-draft`, cut from `proposal/breakglass-3-of-4` at `57a1a8c`.
Orchestrator reads only CLAUDE.md, PROJECT.md §1–§6 and the files below; all
source reading is done by subagents. After a compaction, re-read this file.

Toolchain (Stage 0, 2026-10-21): Tectonic 0.17.0 OK; smoke build OK, log reports
`IEEEtran 2015/08/26 V1.8b`.

PROJECT.md §5 has **13** caveats (counted 2026-10-21). Note: PROJECT.md §1 line
13–14 still says "every transition ... is a signed key-rotation event" — stale vs
§4 item 1 (Grant wraps; Revoke and expiry rotate). Do not repeat it.

| Stage | Item | Subagent | Output | Status | Open issues |
|---|---|---|---|---|---|
| 0 | Setup | orchestrator | paper/main.tex, refs.bib, notes/ | done | |
| 1 | F1 lifecycle | F1 | notes/facts-F1.md | done | 71 facts; 4 states, 7 legal pairs (state_machine.py:52-62); IllegalTransitionError before signing; rotation ONLY on revoke + expiry; break-glass open rotates nothing; **no Grant transition/wrapping in code** (skill + PROJECT §4 item 1 say "Grant adds a key wrapping") — writers must follow code; REVOKED→GRANTED legal but never produced; EXPIRED→REVOKED via ADR-0058 (Proposed) |
| 1 | F2 breakglass | F2 | notes/facts-F2.md | done | 88 facts; 3-of-4 over GF(2^256+297), x=1 custodian, 2 home auth, 3+4 audit; gate checks only 3 distinct x (audit-share necessity follows from distribution, not a gate check); assertion ≤15 min, ≤30 s future skew, window 4 h; commit share_custody.py:94-110 before release audit_service.py:425-446; truncation check compares seq only (no sig verify); audit restart → new signing key (code reading, not observed); ADR-0079 2.27 ms timing is pre-3-of-4, do not quote |
| 1 | F3 crypto | F3 | notes/facts-F3.md | done | 58 facts; Shamir prime 2^256+297 (257-bit, docs say 256); ElGamal 256-bit demo group; payload has no AAD; RSA-OAEP in docs not code; ADRs 0001/0012/0018 say "unidirectional" (code: bidirectional) |
| 1 | F4 system | F4 | notes/facts-F4.md | done | 43 facts; 2 facilities, 2 authorities, audit, custodian, Postgres, 1 Django portal, one machine; Proposed ADRs: 0047,0053,0064,0066,0067,0071,0072,0079,0084,0085,0089; federation services use postgres superuser (only portal role-restricted); HTTP TLS self-signed server-only, no version/cipher pinned; federation-topology.md stale (2-of-3) |
| 1 | F5 security | F5 | notes/facts-F5.md | done | 53 claim-tagged tests (18 module, 35 system); C9 no module test; 18 mutations cover C1–C10, C11 uses positive control; p5-1-evidence.md (10-19) predates 3-of-4; mutation runner counts pre-skipped tests as neither; claim-table.md records no sha; threat-model.md Draft, omits audit/custodian as trusted |
| 1 | F6 traffic | F6 | notes/facts-F6.md | done | 89 facts; p55 wire checks (2026-10-21 @99092d1, no wire/src/deploy/tests/wire change since) all pass; claim 1 TLS-only; COMMIT 1.35 ms before release; p55 has 1 search only — multi-search leakage from p53 (2026-10-19, pre-3-of-4) → paper must date them, not re-run; only ADR-0042 Accepted; plain capture shows no DEK (docs say DEKs cross) |
| 1 | F7 evaluation | F7 | notes/facts-F7.md, data/latency.csv, data/expansion.csv | done | results match HEAD 57a1a8c; n=30, warm-up 5, ms; env.json lacks commit/lib versions; "local-processes" is really uvicorn threads in-process; HTTP figures unstable (~405 vs 247 ms same day); expansion = constant 16 B tag only |
| 1 | F8 related work | F8 | notes/facts-F8.md, refs-verified.bib | done | 22 refs verified on primary pages; 2511.17464 HAS break-glass (2-physician co-signed, 2 h, on-chain log; key release via unimplemented HSM, not log-gated; revocation = flag flip) — must be stated; "PORTEX" name unconfirmed → cite Li et al. TIFS 20:620–635 "Accountable Decryption Made Formal and Practical", no break-glass motivation claim; Kroll et al. undated manuscript, no "2018"; caution flags on Zhang–Chow–Sun, Ferreira, Rumpole, Yang&Ma, Red Alert; DROPPED: PORTEX name, review [2],[12],[18],[33], Kroll–Felten–Boneh 2014, all §8 leads |
| 2 | Live claims + pytest | L1 | notes/facts-live.md | done | 2026-10-21 ~19:54 +0530 @57a1a8c: C1–C11 all holds (35/35 system tests); pytest 1006 passed, 2 skipped (dumpcap-missing tests, skip by design), 0 failed, 86.52 s; Py 3.11.9, TShark 4.6.9; claim-table.md has no sha, statuses agree; quote live claim wording |
| 3 | W1 abstract/intro/related | W1 | sections/00–02, tables/related.tex, refs.bib | done | abstract 201 words; ~1.7 pp (over 1.5 budget — trim related first); matrix 18 rows + this work, FED column dropped; added F8#23–24 |
| 3 | W2 threat model/overview | W2 | sections/03–04 | done | exactly 1 p; 4 adversaries + 4 trusted parties; C1–C11 wording from live run; added F4#44; \texttt was Latin Modern Mono (no setmonofont) |
| 3 | W3 lifecycle | W3 | sections/05, figures/states.tex, tables/transitions.tex | done | ~1.55 pp; table script checks rows against LEGAL_TRANSITIONS in src; added F1#72; defines sec:lifecycle-expiry |
| 3 | W4 break-glass | W4 | sections/06, figures/breakglass-sequence.tex, gate-chain.tex | done | ~2.5 columns; fig:gate+fig:chain share one figure; added F2#89–90 |
| 3 | W5 security/traffic | W5 | sections/07–08, tables/claims+secprops+wire | done | ~1.6 pp; claims table generated from live-claims-raw.txt (sha hard-coded from facts-live); secprops is table* written from facts; one tag points at facts-F6#C8 (contradiction entry); added F6#90 |
| 3 | W6 eval/limits/conclusion | W6 | sections/09–11, tables/bench.tex, figures/latency+expansion | done | ~1.75 pp before final trim (over 1.5); 13 §5 items in order + extras; item 11 omits "DEKs cross" (p55 plain showed no DEK, F6); added F7#38–39 (16,450 non-blank src lines); deployed revocation path not benchmarked |
| 4 | Build | orchestrator | build/main.pdf | done | round 0: 0 errors, 0 undefined refs/cites, 0 overfull; 10 pp total, body ends p10 left column, references start p10 (≈9.4 pp body); added setmonofont texgyrecursor |
| 5 | V1–V5 verify | V1–V5 | notes/verify-*.md | done | round 1: 13 BLOCKER total (V1 8, V2 2, V3 1, V4 0, V5 2) — see table below |
| 6 | Fix loop | X1–X6, Y1 | sections, tables, figures, facts-F9.md | done (2 rounds) | 0 BLOCKER left; MINORs listed below |
| 7 | Commit + report | orchestrator | one commit on paper/ieee-draft | done | |

## Stage 5 results (round 1)

| Verifier | Output | BLOCKER | MINOR | Notes |
|---|---|---|---|---|
| V3 honesty | notes/verify-honesty.md | 1 | 5 | blocker: 11-conclusion.tex:21 "any-two-of-three fallback" wording; items 1–7, 9–11 PASS |
| V4 numbers+citations | notes/verify-numbers.md | 0 | 5 | tables byte-identical on regeneration; all 22 cites resolve; blaze1998proxy unused (prune); 08:67 hit/miss medians unlabelled + different AMD host; Kroll PDF text not extractable — hospital claim rests on facts-F8 (human check §1.1); li2025 provenance comment points at wrong Crossref query |
| V5 format | notes/verify-format.md | 2 | 15 | blockers: gate-chain.tex:39 panel (b) label overlaps panel (a); breakglass-sequence.tex:42-44 "6 log rewrap" over "unwrap DEK"; build 0 err\/0 undef\/0 overfull, 29 underfull, 10 pp, body ends p10 left ~55% |
| V2 code truth | notes/verify-code.md | 2 | 11 | blockers: EXPIRED→REVOKED also patient-signed (custodian_service.py:1324-1343, hospital.py:1126-1144) — table\/figure\/05:81-83 say timer only; 05:77-79 issue time checked vs facility clock (≤15 min old, ≤30 s ahead, hospital.py:1600-1607), not vs assertion |
| V1 evidence | notes/verify-evidence.md | 8 | 13 | blockers: 02:7 "facts-F8 matrix" tag; 17 limitations tags cite PROJECT.md §5 not a fact sheet; malformed tag 11:25; related.tex 18 rival rows untagged; 04:49 caption "no key material" facility→audit wrong (sealed shares 3,4 at rotation); consent overclaim 11:3-5 + related "this work" ✓ (consent is read-time predicate outside state machine, F1#35); 07:37 unsupported |

## Stage 6 round 1 fixers

| Fixer | Files | Result |
|---|---|---|
| X2 | 03, 04 | V1 blocker 04:49 FIXED (caption: facility→audit carries sealed shares 3,4 at rotation); 03:28 tag FIXED; underfull vbox 04:64 left (float-dependent) |
| X5 | 07, 08, claims\/secprops\/wire tables | V1 blocker 07:37 FIXED (F5#57 git log -S → e79bcd3, 2026-10-07); share 3 wording, hit\/miss medians (11\/4, AMD host, F6#92), secprops ragged-right, subsection caps, F6#C8 → F6#91 FIXED; caption sha lowercase not visually checked |
| X3 | 05, transitions, states, facts-F1 | V2 blockers FIXED: EXPIRED→REVOKED "Timer or Patient" (custodian_service.py:1324-1343, custodian\/__init__.py:129-149, api\/hospital.py:1126-1144), script now checks signer vs F1#46; issue time vs facility clock (F1#74); 4 V2 MINORs FIXED (F1#73–76); orchestrator added \emergencystretch=1em to main.tex for stretched lines |
| X1 | 00, 01, 02, 11, related | 5 blockers + 4 minors FIXED: consent = read-time check vs GRANTED baseline (abstract, intro, conclusion, table LC → ∘; F1#77); related rows tagged F8#1–18; F8#23, F8#25 added; 2-of-3 wording removed; interim full build 11 pp (body ends p10, refs spill) |
| X6 | 09, 10, bench, facts-F9 (new) | V1 blocker FIXED: facts-F9.md (13 §5 items + §6 + cut scalability, PROJECT lines + code\/ADR), all limitations tags → F9; item 11 faithful + evidence; F7#40–41; bench caption lowercase sha |
| X4 | 06, sequence, gate-chain | V5 blockers FIXED (panel (b) yshift −4.15 cm; steps 5–8 moved; label fill=white), coordinates checked not rendered; "--" fixed; V2 minors FIXED (F2#91–93); underfull lines in 06 left |
| build r1 | orchestrator | 0 errors, 0 undefined, 0 overfull; 11 pp total; body ends p10 left column, references p10 right + p11 (body ≈9.5 pp) |

## Stage 5 re-verify (round 2)

| Verifier | Result |
|---|---|
| V3 honesty | 6/6 round-1 issues RESOLVED; 1 new BLOCKER: 00-abstract.tex:3 "emergency overrides are logged after the fact" contradicts our own related work (2511.17464 logs at request time; Kroll/transparent decryption gate on the log). Note: V3's suggested fix ("the log does not gate key release") is itself wrong for Kroll/TD — needs different wording |
| V2 code truth | 13/13 round-1 RESOLVED; consent IS patient-signed (consent/service.py:270,307,413; hospital.py:1004). New BLOCKER: "against its GRANTED baseline" (00:5, 01:34, 11:5-6) — check is vs ConsentGrant status+window, read path never reads lifecycle state (hospital.py:728-990). New MINOR: consent only checked when a grant is presented; key holders read via policy alone (hospital.py:812, 911-916); related.tex:12 footnote |
| V5 format | both overlap blockers RESOLVED (seen on renders); 0 BLOCKER; 7 MINOR (stretched lines §V–VI, Fig 2\/Table II above §V heading, Table I caption 8 lines, Table V justified, underfull vbox p2–3, p11 holds only refs [20]–[21]); 11 pp, body ends p10 left (≈9.5 pp) |
| V4 numbers | 0 BLOCKER; tables byte-identical; 21 cites = 21 entries; Kroll hospital paragraph now confirmed from PDF text; 1 MINOR open in notes: refs-verified.bib:67 li2025 provenance line |
| V1 evidence | 8/8 round-1 BLOCKERs RESOLVED; 0 BLOCKER; 3 MINOR (Contradictions numbering ambiguity in F2\/F8; states.tex tags before elements; abstract:3\/intro:11 "logged after the fact" overgeneralises — same as V3 blocker) |
| orchestrator | fixed refs-verified.bib li2025 provenance line → Crossref DOI url |
| Y1 (round 2) | 00, 01, 02, 11, related | consent wording FIXED (F1#78: grant status\/window\/signature when presented, separate from lifecycle); abstract\/intro gap statement FIXED; trimmed; build 10 pp |
| build r2 | orchestrator | 0 errors\/undef\/overfull; 10 pp; body ends p10 left column, refs p10 left–right |
| V2 round 3 | 0 BLOCKER, 0 MINOR — consent wording matches code |
| V3 round 3 | 0 BLOCKER, 0 MINOR — scoped gap claim; items 2, 6, 7, 8 PASS |
| V1 round 3 | 0 BLOCKER; 1 MINOR (abstract:3 "do not gate" → "are not described as gating") — applied by orchestrator |

## Final state (2026-10-22)

- Final Tectonic build: 0 errors, 0 undefined refs/cites, 0 multiply-defined labels, 0 overfull boxes; 16 underfull boxes; 4 expected TU/ptm font warnings.
- 10 pages: body ends in p10 left column (≈9.3 pp), references [1]–[21] on p10.
- Claims: C1–C11 all hold, live run 2026-10-21 @57a1a8c (35/35 system tests); pytest 1006 passed, 2 skipped, 0 failed.
- BLOCKERs left: none.
- MINORs left:
  - Stretched/underfull lines in §V–§VI (emergencystretch reduced, not removed).
  - Fig. 2 and Table II float above the §V heading.
  - Table I caption is 8 lines; Table V cells fully justified; underfull \vbox on p2–3.
  - Contradictions entries in facts-F2/F8 are numbered 1…n, so some tags (e.g. facts-F2#5) are ambiguous with numbered facts.
  - figures/states.tex tags sit before the TikZ elements they support.
  - Several F8 sources carry caution flags (Zhang–Chow–Sun, Ferreira, Rumpole, Yang & Ma, Red Alert): only partly verified on content.
  - Underfull \vbox at 04:64 (float-dependent).
- Not done here, needs the team: docs that are stale vs code (ARCHITECTURE §5/§7, federation-topology.md, threat-model.md, several ADRs saying 2-of-3 or "unidirectional", PROJECT.md §1 "every transition rotates", "Grant adds a key wrapping" in PROJECT §4/skill) — see "Contradictions found" in each fact sheet.

## Minor clean-up pass (2026-10-22)

- Contradictions entries in facts-F2/F8 renumbered C1… (tags now unambiguous).
- Layout: §V–§VI badness-10000 lines removed (\allowbreak on identifiers, light rewording, same tags); Fig. 2/Table II moved below §V's first paragraph; Table I caption one sentence, legend/notes below the tabular; Table V ragged-right; states.tex tags moved after their elements.
- References: zhang2016password, ferreira2006break, marinovic2011rumpole, yang2016timing, deoliveira2019redalert content CONFIRMED (OpenAlex publisher abstracts; Red Alert full text); caution notes replaced with `% verified:` lines. Matrix sharpened: de Oliveira 2019 LG/FP/IMP → ✗ (none described / informal analysis / none reported), Yang & Ma IMP → ~ (simulations only).
- Re-verified: V1 round 4 0/0; V5 round 3 0 BLOCKER, 2 MINOR.
- Build: 0 errors/undefined/overfull; 4 underfull \hbox (none at 10000), 2 underfull \vbox; 10 pages, references end p10.
- Left, by choice: the two \vbox stretches (gap above §VI-B on p6, smaller near §VII-C on p7). \raggedbottom removes them but leaves p6's left column ~3 lines short; kept the balanced columns.

## Reader-facing clean-up (2026-10-22)

- Removed every ADR reference from the paper text, tables and generators (03, 04, 05, 06, transitions, claims C11). The decisions are still described ("this build chooses …"), only the internal record numbers are gone; `% src:` tags unchanged. make_claims.py drops a trailing "(ADR-NNNN)" from claim statements by a documented deterministic rule.
- Table I note reformatted: footnotesize, labelled Columns / Marks / This work lines, one line per footnote a–c.
- Commit hash explained at first use (intro: "the evaluated version of our code, git commit 57a1a8c of the project repository"); later mentions say "the evaluated commit"; wire caption says the capture was at repository commit 99092d1 and the code is unchanged in 57a1a8c.
- Build: 0 errors/undefined/overfull, 6 underfull, 10 pages, references end p10, no "ADR" in the PDF text.

## Author block (2026-10-22)

- Four authors in two rows of two (Ojas Thakurela 240911282, Powel Lawrence Lewis 240911458; Avaneeth Gowda L 240911368, Nandini Taldar 240911356), each with School of Computer Engineering, MIT, Manipal, India. IEEEtran wraps after three per row, so a `\linebreakand` macro forces the 2×2 layout.
- The taller title block pushes references [16]–[21] onto page 11: 11 pages total, body still ends in p10's left column (within "8–10 pages plus references"). Build otherwise clean (0 errors/undefined/overfull, 6 underfull).
- Changed to all four authors in one row (2026-10-22): "School of Computer Engineering" breaks after "Computer" so four blocks fit the page width; the 2×2 macro is gone. Title block is shorter, so only references [20]–[21] now spill onto page 11 (11 pages; body ends p10). Build clean, 4 underfull.

## Trim to 10 pages (2026-10-22)

- Wording-only trims (no fact or tag changed) so references [20]–[21] fit on page 10 again:
  01 (gap sentence; search-token sentence), 02 (weaker-log sentence), 05 (return-to-claimed-state; monitor sentence),
  06 ("old shares open nothing"), 08 (DEK canary; "there is no padding"), 10 Further limits (scaling runs, formal model,
  truncation check "not signatures", payload AAD, ElGamal group), 11 conclusion (Assertion/commit clause, "prior art",
  "C1--C11 all hold", "under a millisecond", future-work list).
- Build: 10 pages, references end on p10; 0 errors/undefined/overfull; 5 underfull.
