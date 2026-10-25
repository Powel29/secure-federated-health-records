# Response to the IEEE manuscript review

Review: [`ieee-paper-review.md`](ieee-paper-review.md). Paper: `paper/` on branch
`paper/ieee-draft`. Each issue was checked against the paper text and, where it
makes a technical statement, against the code.

**Legend:** **Fixed**: changed in the paper. **Partly fixed**: the paper-level
part is done, and the rest needs code, experiments or a team decision.
**Not required**: already handled in the paper, or not a valid issue for this
paper (reason given).

## Summary

| Outcome | Issues |
|---|---|
| Fixed | 1, 3, 4, 5, 12, 13, 14, 16, 17, 19, 20, 22, 26, 27, 30 |
| Partly fixed | 2, 9, 10, 15, 18, 28, 29 |
| Not required | 6, 7, 8, 11, 21, 23, 24, 25 |

Build after the changes: Tectonic, 0 errors, 0 undefined references, 0 overfull
boxes. The body still ends on page 10. The PDF is now **11 pages** because the 17
rendered DOIs lengthen the reference list, which continues onto page 11. That
still meets "8–10 pages plus references". Abstract: 250 words.

## Issue by issue

| # | Outcome | Analysis and action |
|---:|---|---|
| 1 | **Fixed** | Valid. C1's tests exercise revocation through the facility endpoint, while §X item 9 says a holder who kept a shared attribute key still satisfies the rotated policy. §VII now scopes C1 to those service paths and points to item 9. The registry's claim wording is quoted verbatim and unchanged. Epoch-versioned attribute keys plus a retained-key test is code work, already listed as future work. |
| 2 | **Partly fixed** | Valid as a framing issue. §X now says the 256-bit ElGamal group has no production security level and must be replaced before any deployment. §IX, Table IV and §X already called it a demonstration parameter, and the abstract calls the system a prototype. Replacing the group is a cryptographic code change (ADR, module owner, re-test) and is not done here. |
| 3 | **Fixed** | Valid. The abstract, introduction, §VII and the conclusion now say that all 35 claim-tagged system tests pass, and that these are test outcomes, not proofs. §VII points to Table IV for what is proven. |
| 4 | **Fixed** | Valid. Checked in code: `src/consent/service.py:381-410`, `src/api/hospital.py:811-830, 911-920`. §V now states the rule. A presented grant needs the patient's valid signature, status GRANTED, a current window, the reader as grantee and the record in scope, or the read is refused. With no grant, the reader's attribute keys must satisfy the record policy. Emergency reads use break-glass. New fact `facts-F1#79`. |
| 5 | **Fixed** | Valid in one place. §III and the abstract already qualify the slogan. §VI's "no log entry, no key" now reads "with an honest audit service". |
| 6 | **Not required** | Accurate, but already disclosed: §X item 8, the abstract's "single point of availability", and §VI. Persisting shares and the signing identity across an audit restart is code work in the audit module, not a paper fix. |
| 7 | **Not required** | The failure case is already defined: share 2 replaces a lost share 1 after a custodian restart, because share 1 is kept in memory (§VI, §X item 8). §X also says what it does not cover. Redesigning holder roles is a design decision (ADR-0089), not a paper fix. |
| 8 | **Not required** | Already disclosed. §IX says the revocation row is an in-process library call, and that deployed revocation runs the full rotation, which no benchmark times. Adding end-to-end benchmarks is new evaluation work. The paper does not present 0.239 ms as deployed latency. |
| 9 | **Partly fixed** | The mixed revisions are real and were already disclosed. Provenance is now stated once, in a "Provenance and availability" paragraph in §IX: claims and suite at 57a1a8c, benchmarks committed in it, wire captures at 99092d1 with no capture, analyser or service code changed since, and multi-search leakage from 2026-10-19 runs before the 3-of-4 split. Re-running every evidence set at one commit is an experiment task, not done here. |
| 10 | **Partly fixed** | The provenance and availability paragraph is added. Pinned library versions, chain length and raw timings cannot be added without re-running, because `environment.json` does not record them. §IX already says so. |
| 11 | **Not required** | §VII already restricts the claim. It says the per-test mutation log predates the 3-of-4 split, and that "we do not claim that every current claim test is shown to go red". A fresh mutation report is a test-run task that can follow. |
| 12 | **Fixed** | Valid. In Table V the search-leakage result now reads "measured", not "pass". The note says leakage is measured, not asserted, and that the check only confirms search traffic was captured. Generated through `make_wire.py`. |
| 13 | **Fixed** | Valid. IEEEtran.bst 1.14 does not print `doi`. A new script, `paper/data/add_doi_notes.py`, renders each entry's own DOI as a note, so nothing is retyped: 17 entries. The arXiv entries [8] and [11] already print their arXiv identifiers. Kroll et al. (an undated manuscript) and Larch have no DOI. |
| 14 | **Fixed** | Valid. The introduction says "none of those we examined". Related work says "None of these is described as gating…". The abstract was already scoped to "the works we compare". The preprints [8] and [11] are printed with their arXiv identifiers. |
| 15 | **Partly fixed** | The availability statement is added. The repository is private (GitHub returned 404 on 2026-10-25), so the paper says so instead of giving a URL. Publishing the code or an archive is the team's decision. |
| 16 | **Fixed** | Valid. §VI now defines enc as a domain-tagged, length-prefixed field encoding. *event* is the event type plus its metadata as canonical JSON, and *t* is the UTC timestamp. The paper lists the signed fields: seq, both hashes, event, actor, correlation id and timestamp. From `src/audit/chain.py`, facts F2#71–73. |
| 17 | **Fixed** | Valid. §IV now says, early, that the emergency scenario assumes the patient can be identified, and points to §X item 7. |
| 18 | **Partly fixed** | Mostly handled already. §III models store, facility, authority and colluding clinicians separately, and lists the audit service, custodian, timer and PKI root as trusted parties with what each could do. Added: a compromised custodian can act as any persona. |
| 19 | **Fixed** | Valid. The abstract now expands CP-ABE and TLS, drops the tool name PyShark, and splits the limitations sentence into two. It stays within 250 words. |
| 20 | **Fixed** | Five index terms: electronic health records, break-glass access, transparent decryption, threshold secret sharing, key rotation. |
| 21 | **Not required** | "EHR" is a standard abbreviation and is expanded in the abstract's first use and in the index terms. A longer title is the team's call, and the review itself says "consider". |
| 22 | **Fixed** | Normalised to American spelling: modeled (×2), realize, unauthorized in §VII. The one remaining "unauthorised" is inside claim C9, which is quoted verbatim from the claim registry (§III, Table III). Changing it would misquote the registry. |
| 23 | **Not required** | "re-wrap" in C1 is the registry's verbatim wording, and §III already explains that in C1 it means a full rotation. The benchmark row reads "DEK re-wrap (one DEK)", and §IX says it covers one DEK, not a sweep. |
| 24 | **Not required** | IEEEtran places floats at the top of the page. Each figure is on the same page as its first citation, which is standard IEEE layout. Forcing positions would cost space and risk bad breaks. |
| 25 | **Not required** | The render was checked. Labels are `\footnotesize` and readable in one column, and the format verifier passed it. Widening it to `figure*` would cost about half a column. |
| 26 | **Fixed** | Table IV column renamed from "Proven" to "Proof status". |
| 27 | **Fixed** | §VIII now says the small sample showed no hit/miss timing difference, instead of "no signal". |
| 28 | **Partly fixed** | The code and data availability statement is added (see #15). Funding and conflicts of interest: none are recorded in the repository, so nothing was invented. The team must state them. **AI-use disclosure:** this draft was produced with AI assistance. IEEE policy asks authors to disclose AI-generated text, normally in the acknowledgments. The team should decide the wording and add it. It was not added for them. |
| 29 | **Partly fixed** | Wire caption shortened (provenance moved to §IX). The claims-table caption keeps its run date and commit, and the benchmark caption keeps the machine, because the project's paper rules require both next to those tables. |
| 30 | **Fixed** | Commit hashes removed from the introduction, §VII, §IX method and the conclusion, and from the Table V caption and Table I note. They remain once in §IX's provenance paragraph and in the claims-table caption, which the rules require. |

## Changes made

- `paper/sections/00-abstract.tex`: issues 3, 19, 20, plus trims to stay at 250 words.
- `01-introduction.tex`: 3, 14, 30. `02-related-work.tex`: 14, 22. `03-threat-model.tex`: 18, 22.
- `04-system-overview.tex`: 17. `05-lifecycle.tex`: 4. `06-breakglass.tex`: 5, 16.
- `07-security-analysis.tex`: 1, 3, 22, 30. `08-traffic-analysis.tex`: 27. `09-evaluation.tex`: 9, 10, 15, 30.
- `10-limitations.tex`: 2. `11-conclusion.tex`: 3.
- `paper/tables/secprops.tex`: 26. `paper/data/make_wire.py` → `tables/wire.tex`: 12, 29.
- `paper/data/add_doi_notes.py` (new) → `paper/refs.bib`: 13.
- `paper/notes/facts-F1.md` #79 (read decision rule) and `facts-F7.md` #42 (repository private). Every new sentence carries a `% src:` tag, and all tags resolve.

## Still open (needs the team, not a paper edit)

- Add the AI-use disclosure and any funding or conflict statements (#28).
- Decide whether to publish the code or an archive, and add its URL (#15).
- Code and experiment work the review recommends, already stated in the paper as limitations or future work:
  - epoch-versioned attribute keys (#1);
  - a production-strength KEM group (#2);
  - audit-service share persistence (#6);
  - end-to-end benchmarks (#8);
  - one-commit evidence rerun (#9);
  - pinned environment (#10);
  - final mutation report (#11).
