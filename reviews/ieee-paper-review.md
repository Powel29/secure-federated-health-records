# IEEE manuscript review

**Manuscript:** “Federated Break-Glass EHR with a Unified Key-Lifecycle State Machine”  
**Reviewed file:** [`../paper/build/main.pdf`](../paper/build/main.pdf)  
**Verdict:** Major revision before IEEE submission

This review covers the complete 10-page PDF, including six figures, six tables, equations, and 21 references. No target venue was provided, so venue-specific page, template, and disclosure requirements remain unverified. The PDF was also checked against [`../paper/refs.bib`](../paper/refs.bib) for bibliography metadata.

## 1. Summary

| Area | Score / 10 |
|---|---:|
| Language | 7 |
| Format | 7 |
| Technical soundness | 5 |
| References | 6 |

**Issue count:** 2 critical, 16 major, 12 minor. The added minor issue concerns repeated commit hashes and run dates. The abstract is approximately 245 words, near IEEE's general 250-word limit; the Index Terms list has seven entries, while IEEE's general conference guidance recommends 3–5 keywords. See [IEEE conference guidance](https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/structure-your-paper/).

## 2. Issue log

Locations use PDF page and section or table because PDF text has no stable line numbers. Quoted snippets are from the reviewed PDF.

| # | Severity | Location and category | Original text | Problem | Suggested fix |
|---:|---|---|---|---|---|
| 1 | **Critical** | pp. 3, 7, 9; security claim C1 | “A revoked user cannot decrypt after re-wrap”; “a revoked holder who kept a key still satisfies its leaves” | These statements conflict. Tests establish denial through tested service paths, while a retained attribute key can still satisfy the rotated policy. | Narrow C1 to the tested online path, or rotate/version attribute keys and test retained-key access to new ciphertext. |
| 2 | **Critical** | pp. 6, 8, 10; cryptography | “256-bit demonstration group” | Share sealing and DEK delivery use this group, yet its production security is neither established nor evaluated. | Use a standard reviewed KEM at an explicit security level and rerun tests; until then, describe the system consistently as a demonstration prototype. |
| 3 | Major | Abstract, pp. 7–8, Conclusion; interpretation | “all eleven security claims hold” | Passing 35 system tests establishes outcomes for tested cases, not universal security properties. Table IV marks several constructions “Not proven.” | Say “all 35 claim-tagged system tests passed” and separate observations from guarantees. |
| 4 | Major | pp. 1, 4, 10; consent | “checked at read time when one is presented” | The access decision when no grant is presented is unspecified, including how it differs for patient, clinician, and emergency reads. | Specify decisions for absent, invalid, expired, and revoked grants on each path. |
| 5 | Major | pp. 1, 6, 10; trust | “no log entry, no key” | A compromised audit service can release shares without a durable entry, as the paper acknowledges. | Qualify the guarantee with “provided the audit service is honest.” |
| 6 | Major | pp. 6, 9; availability | “an audit restart loses shares 3 and 4 of every record” | A routine restart appears to disable break-glass for existing records, with no tested recovery procedure. | Persist/recover shares and signing identity securely and test restart; otherwise foreground this deployment blocker. |
| 7 | Major | pp. 4, 6, 9; threshold design | “share 2 covers a lost share 1 only”; “It does not cover a custodian or audit outage” | The extra shareholder gives little operational redundancy because the custodian is also the clinician's key agent. | Define and measure the failure case it solves, or redesign holder roles. |
| 8 | Major | pp. 8–9; evaluation | “Revocation (library call)”; “the deployed facility instead revokes through the full expiry rotation, which no benchmark times” | The 0.239 ms result is not deployed revocation latency. End-to-end break-glass and rotation latency are absent too. | Benchmark these operations through the deployed service, storage, and audit path. |
| 9 | Major | pp. 7–8; evidence provenance | “capture … commit 99092d1”; “evaluated commit 57a1a8c”; “before the 3-of-4 change” | Security, wire, search, and benchmark evidence comes from different revisions. | Rerun the full evidence package at one final commit and record provenance once. |
| 10 | Major | pp. 8–9; reproducibility | “environment.json … records no commit or library versions”; “chain length was not recorded” | Dependency versions, workload size, chain size, and raw timings are missing. | Publish a pinned environment, commands, fixtures, record counts, chain length, and raw results. |
| 11 | Major | p. 7; test adequacy | “post-split run … is recorded only in prose”; “lacks seven of today's claim-tagged nodes” | Mutation evidence does not cover the final claim suite. | Generate a final-revision mutation report or restrict the claim to the older set. |
| 12 | Major | p. 8, Table V; wire checks | “Search leakage … pass*”; “it fails only if no search traffic is captured” | This confirms capture, not a security property. | Label the row “measurement” and reserve “pass” for a stated criterion. |
| 13 | Major | pp. 9–10; references | Entries [1]–[5], [7]–[11], [13]–[21] omit DOI fields | The bibliography source contains DOIs for these 19 works, but the rendered PDF omits them. | Render available DOI fields, following the target venue's style. |
| 14 | Major | pp. 1–2; novelty | “none of these schemes is described as gating key release on a log entry” | “None” can imply an exhaustive literature exclusion; [8] and [11] are preprints. | Consistently say “among the works examined” and mark preprints as such. |
| 15 | Major | pp. 1, 7–9; artifacts | “git commit 57a1a8c of the project repository” | A commit hash without a repository URL or archive does not let readers inspect the code and results. | Add a stable code/data availability statement with URL, revision, and access limits. |
| 16 | Major | p. 6, Fig. 4; equation | `h_i = SHA-256(enc(h_(i-1), event, t, actor))` | The paper does not define `enc` or clearly enumerate which entry fields are hashed and signed. | Define canonical encoding and list all hashed and signed fields. |
| 17 | Major | p. 9; clinical scope | “Unidentified patients get no history” | The emergency scenario assumes identification; the workflow impact is unevaluated. | Bound the use case to identified patients early and add an identification scenario if relevant. |
| 18 | Major | pp. 3, 9–10; security model | “fully dumped … never plaintext or an unwrapped key”; “One shared process is every user's key agent” | Store-only confidentiality may hold, but the custodian and facilities are much stronger compromise points. | State distinct claims for store, custodian, facility, audit, and collusion compromise. |
| 19 | Minor | p. 1; abstract | “CP-ABE”; “TLS”; “PyShark” | CP-ABE and TLS are not expanded; the final limitations sentence is dense. | Expand or remove abbreviations and shorten that sentence. |
| 20 | Minor | p. 1; Index Terms | Seven terms, ending “traffic analysis” | IEEE's general advice recommends 3–5 keywords. | Keep the five most useful terms, subject to venue rules. |
| 21 | Minor | p. 1; title | “EHR” | The abbreviation is not expanded in the title. | Consider “electronic health records” if the venue and title length permit. |
| 22 | Minor | pp. 2–3, 7; spelling | “modelled”; “unauthorised”; “realise”; “authorize”; “realized” | British and American spellings are mixed. | Choose one variant throughout; American spelling fits the existing “authorize” and “realized.” |
| 23 | Minor | pp. 3, 6, 8–9; terminology | “re-wrap is a full rotation”; “DEK re-wrap (one DEK)” | “Re-wrap” names both full rotation and a single-key benchmark. | Use “full record rotation” and “single-DEK wrapping,” respectively. |
| 24 | Minor | pp. 3–5; figure order | Figs. 1–3 appear above their first visible text citations | The rendered reading order presents figures before explanation. | Where practical, move the introductory citations ahead of the floats. |
| 25 | Minor | p. 3, Fig. 1; legibility | “store data, identify users, decide no access” | The diagram and arrow labels are crowded at column width. | Simplify labels, span both columns, or split architecture and share flow. |
| 26 | Minor | p. 8, Table IV; table semantics | Column “Proven” contains “Assumed” | “Assumed” is not a proof status. | Rename the column “Evidence status” or separate assumptions. |
| 27 | Minor | p. 8; timing | “66.1 ms over 11 hits and 66.7 ms over 4 misses” | The sample is small for a broad no-signal conclusion. | Say the small sample did not reveal a difference; provide dispersion if retained. |
| 28 | Minor | end matter; disclosures | No data/code availability, funding, conflict, or AI-use statement | Applicability depends on venue and actual circumstances. | Add applicable statements without inventing funding or AI use; check [IEEE AI guidance](https://open.ieee.org/author-guidelines-for-artificial-intelligence-ai-generated-text/). |
| 29 | Minor | pp. 4, 8–9; captions | “shipped in src/lifecycle/”; hashes and machine details in captions | Captions are long and code-centric. | Move paths, commit IDs, and setup details to text or an artifact statement. |
| 30 | Minor | Introduction, Sections VII–IX, captions; repetition | Repeated “57a1a8c,” “99092d1,” and run dates | Repeating provenance throughout interrupts the argument. | Keep each distinct run's date and revision **once** in a compact evaluation provenance table; retain dates in prose only where they explain a real revision difference. |

I found no clear spelling typo that warrants inventing a correction. Section, figure, table, and reference numbering is sequential.

## 3. Corrected snippets for the ten highest-priority issues

1. **C1:** “In the tested service paths, revocation blocked subsequent clinician reads after full record rotation. This result does not cover a user who retained a shared attribute key before revocation.”
2. **Prototype security:** “The prototype uses a 256-bit demonstration ElGamal group for share sealing and DEK delivery; this component has no established production security level and must be replaced before deployment.”
3. **Test summary:** “At commit `57a1a8c`, all 35 system tests tagged to C1–C11 passed; these tests exercise the listed cases but do not constitute proofs of the claims.”
4. **Consent behavior:** “For a normal read, the facility requires a valid patient-signed grant matching the record, reader, and time window; an absent, invalid, expired, or revoked grant denies that path. Emergency reads follow the separately audited break-glass path.” **Use only if this matches the implementation.**
5. **Log guarantee:** “If the audit service follows the protocol, it commits a hash-chained entry before releasing its shares; a compromised audit service is outside this guarantee.”
6. **Restart limitation:** “The current audit service does not persist its emergency shares and signing identity across restart, so a restart can make existing records unavailable for break-glass until recovery or re-keying.”
7. **Latency:** “The 0.239 ms median measures an in-process revocation library call; deployed revocation includes full rotation, persistence, and audit operations and was not timed.”
8. **Evidence provenance:** “Security tests were run at commit `57a1a8c`; the wire capture and search measurements came from earlier revisions. The final-revision integrated wire result remains to be measured.”
9. **Novelty:** “Among the works compared in Table I, we did not find a health-record break-glass design that both gates emergency-key release on a committed log entry and integrates patient revocation into the implemented key lifecycle.”
10. **Hash-chain definition:** “Each entry hashes a canonical, length-prefixed encoding of its predecessor hash, sequence number, event type, metadata, actor, correlation identifier, and timestamp; the entry signature covers [list the actual signed fields].” **Replace the bracketed text with actual implementation fields.**

## 4. Reference audit

All 21 numbered entries appear cited and first-use numbering is orderly. Article titles are quoted and publication titles italicized in the PDF. The main format issue is that 19 DOI fields in `refs.bib` are absent from the PDF. The DOI additions below come from that bibliography source; this review did not independently re-verify every publisher record. Follow the [IEEE Reference Guide](https://journals.ieeeauthorcenter.ieee.org/wp-content/uploads/sites/7/IEEE_Reference_Guide.pdf) for final styling.

| Ref. | Status | Concrete correction or verification |
|---:|---|---|
| [1] | Fix format | Append `doi: 10.1145/1542207.1542239`. |
| [2] | Fix format | Append `doi: 10.1109/CBMS.2006.95`. |
| [3] | Fix format | Append `doi: 10.1007/978-3-642-12368-9_18`. |
| [4] | Fix format | Append `doi: 10.1109/TPDS.2012.97`. |
| [5] | Fix format | Append `doi: 10.1007/978-3-319-71075-4_11`. |
| [6] | Needs verification | Undated manuscript, not a peer-reviewed proceedings entry in supplied metadata. Keep URL/access date; check for a published version. |
| [7] | Fix format | Append `doi: 10.1109/EuroSP57164.2023.00016`. |
| [8] | Needs verification | Mark as arXiv preprint; available DOI is `10.48550/arXiv.2603.07004`. Check for a published version. |
| [9] | Fix format | Append `doi: 10.1007/s12243-020-00759-2`. |
| [10] | Fix format | Append `doi: 10.1109/TII.2017.2751640`. |
| [11] | Needs verification | Mark as arXiv preprint; available DOI is `10.48550/arXiv.2511.17464`. Check for a published version. |
| [12] | OK | Complete proceedings metadata; no DOI supplied in bibliography source. |
| [13] | Fix format | Append `doi: 10.1109/TIFS.2024.3515808`. |
| [14] | Fix format | Append `doi: 10.1145/1998441.1998453`. |
| [15] | Fix format | Append `doi: 10.1145/2897845.2897869`. |
| [16] | Fix format | Append `doi: 10.1007/978-3-030-17259-6_2`. |
| [17] | Fix format | Append `doi: 10.1109/HealthCom46333.2019.9009598`. |
| [18] | Fix format | Append `doi: 10.1109/TIFS.2015.2509912`. |
| [19] | Fix format | Append `doi: 10.1145/359168.359176`; age is justified as a foundational source. |
| [20] | Fix format | Append `doi: 10.1109/SP.2007.11`; age is justified as foundational CP-ABE work. |
| [21] | Fix format | Append `doi: 10.1145/1180405.1180417`; age is justified as foundational searchable-encryption work. |

For each affected entry, the corrected IEEE form is its current author, title, venue, volume/issue, year, and page sequence followed by the DOI above. The bibliography source already contains the metadata; render it instead of retyping 19 otherwise sound entries.

## 5. IEEE checklist

| Requirement | Result |
|---|---|
| Title and author block | Pass |
| Conference-style two-column layout and numbered headings | Pass |
| One-paragraph abstract at or below 250 words | Pass, close to limit |
| Self-contained abstract with minimized abbreviations | **Fail** |
| Index Terms | Pass; count requires venue check |
| Clear problem and contribution statement | Pass |
| Methods, results, limitations, conclusion | Pass |
| Sequential figure/table numbering and caption placement | Pass |
| Figures readable and cited before visible placement | **Partial** |
| Equation symbols and canonical encoding fully defined | **Fail** |
| Numbered citations and matching reference entries | Pass |
| Rendered references include available DOIs | **Fail** |
| Reproducible final-revision evaluation | **Fail** |
| Claims bounded by tests and trust assumptions | **Fail** |
| Funding, conflicts, code/data, applicable AI disclosure | **Unverified** |
| Venue page limit and template rules | **Unverified** |
| Plagiarism/close-paraphrase comparison | **Not assessed**; comparison material or a dedicated tool is required |

## 6. Priority action plan

1. Resolve the C1 retained-key contradiction with a narrower claim or epoch-versioned attribute keys and a retained-key test.
2. Replace the demonstration ElGamal group in key-bearing paths; state the security level and retest.
3. Run security, wire, search, mutation, and latency evidence at one final commit.
4. Measure deployed break-glass, revocation, and expiry latency, including persistence and audit work.
5. Test and document audit-service restart and key recovery.
6. Specify the consent decision rule and separate store, facility, custodian, and audit compromise claims.
7. Publish a reproducibility package with repository URL, revision, pinned dependencies, fixtures, raw results, and workload sizes.
8. Make the abstract and conclusion report test outcomes precisely; attach trust assumptions to log-gating claims.
9. Restore DOI fields in rendered references and identify preprints clearly.
10. Keep commit/date provenance once in an evaluation table, apply venue rules, and do a final language and figure pass.
