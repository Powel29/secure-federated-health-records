> **Status note (2026-10-21, added when this file was filed).**
>
> **What this is.** An external literature review (web research run from
> `docs/novelty-research-handoff.md`), pasted in as received. It was written
> against the project as it stood around 2026-10-09: 650 tests, 5 of 11 claims
> holding. What it led to is in ADR-0088.
>
> **Still valid, and now acted on:**
> - "Logging as a cryptographic precondition" is prior art (accountable and
>   transparent decryption: Kroll et al.; Ryan 2017; Cheval, Moreira & Ryan,
>   EuroS&P 2023; Larch, OSDI 2023; PORTEX, TIFS 2025). `PROJECT.md` §4 is
>   rewritten as a combination claim (ADR-0088).
> - arXiv 2511.17464 is not shown to do revocation-as-key-rotation. It is
>   cited for signed, time-bounded, audited grants.
> - The audit chain is trusted and has no proofs of presence or extension, so
>   it is weaker than transparent decryption. This is now `PROJECT.md` §5
>   item 13.
> - Grant adds a key wrapping and is not a rotation. There is no formal model.
>
> **Out of date. Do not repeat these as current:**
> - *"2-of-3 lets clinician + home authority open a record without the audit
>   service."* Fixed, first by ADR-0074 (share 2 discarded), now by
>   ADR-0089: a weighted 3-of-4 split where the clinician's custodian holds
>   x=1, the home authority x=2 and the audit service x=3 and x=4. Shares 1
>   and 2 are only two points, so every unlock still needs an audit share.
> - *"The audit service does not verify the assertion."* Fixed by ADR-0067
>   (claim C3).
> - *"Expiry does not replace the emergency shares."* Fixed by ADR-0069 (C4).
> - *"5/11 claims hold, 650 tests."* On 2026-10-21: 11/11 hold; 951 passed,
>   2 skipped (`docs/test-evidence/claim-table.md`).
> - *N5, "PRE handoff".* Break-glass doesn't use re-encryption. The DEK is
>   delivered to the clinician's key by a KEM (ADR-0076).
> - *N6, "the wire shows response order, not durable commitment".* Wire check 2
>   reads Postgres's own `CommandComplete(COMMIT)` on the wire before the
>   release response. That is stronger than response order, but still not a
>   proof, and only on the plain profile.
> - The "This work" row of the §4 matrix, and minimum-work items 1–2, describe
>   the old state.
>
> **Bibliography is leads, not references.** Some numbered sources don't match
> their claims. [33] (cited for Yang & Ma) is an unrelated blockchain-EHR
> paper; [12] (cited for de Oliveira et al.) is "Sharing in the Rain"; [18]
> (cited for Zhang, Chow & Sun) is de Oliveira's ResearchGate page; [2] is
> Wikipedia. §8 lists further unverified leads. Check every entry against its
> DOI, arXiv id or publisher page before citing it (ieee-paper skill).

---

# Novelty and Publishability Review: "Federated Break-Glass EHR with a Unified Key-Lifecycle State Machine"

The problem framing is not fully unique and the headline mechanism (logging as a cryptographic precondition of decryption) has been published since 2014–2017 as "accountable/transparent decryption" (Kroll, Felten, Boneh's 2014 accountable-warrant-execution manuscript; Ryan, "Making Decryption Accountable", LNCS 10476, 2017); what survives is the health-specific combination — consent, revocation and break-glass as one key lifecycle with a log-gated threshold emergency key — which is publishable at a workshop, a regional LNCS venue or an applied journal, not at a top-tier conference.

## TL;DR

- **Problem (Q1):** The generic idea "access must be cryptographically conditioned on logging, not on a code path" is already published (Kroll et al.'s accountable cryptographic access control, which even lists hospital emergency access as an application; Ryan's "Making Decryption Accountable", 2017; transparent decryption, IEEE EuroS&P 2023). I found no paper that frames consent + revocation + break-glass for encrypted EHRs as one key-lifecycle problem with log-gated emergency release — that specific framing appears unclaimed, but it is a re-application, not a new problem.
- **Solution (Q2):** No atomic claim is "fully novel". N2 (logger as threshold shareholder) is partially anticipated; N1, N5 are novel only as combinations; N3, N4 are partially anticipated by time-bounded e-health search/PRE and time-bounded break-glass (2016–2020); N6 is the most original but lowest-weight. Worse, the current 2-of-3 design lets the clinician and home authority reconstruct the key *without* the audit service, so the headline claim does not hold even by design.
- **Publishability (Q3):** Realistic as-is: student/regional venue (e.g., ICISS). After fixing the access structure, closing the failing claims, adding a ProVerif/Tamarin model of commit-before-release and a positioning table against transparent decryption: realistic for a security workshop (WPES/CCSW/STM) or an applied journal (Computers & Security, JISA, IEEE Access); second-tier conference (ACSAC/ESORICS/AsiaCCS) is a stretch; top-tier is not realistic. Confidence: medium-high.

## 1. Executive verdict

- **Is the problem unique?** Partially. "Break-glass without a guaranteed audit trail is a backdoor; the guarantee should come from key material" is, almost verbatim, the motivation of Kroll et al., who argue that software access checks "ultimately rely on a code path" that can be bypassed, and that there is otherwise "no way to guarantee that access by key-holders is properly logged".\[1\] The health-specific "one key lifecycle" framing was not found in prior work.
- **Is the solution novel?** Only as a combination and an application. The core primitive (key shares released only after the request is in a log) is transparent/accountable decryption.\[2\]\[3\]
- **Is it publishable?** Yes, at modest tiers, if repositioned as "transparent decryption instantiated for EHR break-glass inside a unified key lifecycle, with an implementation and wire-level evidence" — and only after the design flaw in the 2-of-3 access structure is fixed.
- **Tier:** Regional/student LNCS venue now; workshop or applied journal after the minimum work below; second-tier conference only with a formal model and real CP-ABE/PRE.
- **Confidence:** Medium-high on the prior-art threats (primary sources opened); medium on "nobody has done the exact EHR combination" (absence of evidence from ~18 searches plus one subagent sweep, not exhaustive).

## 2. Verification of the three known references

| Reference | Exists? | What it actually claims | Overlap with you |
|---|---|---|---|
| Li, Yu, Zheng, Ren, Lou, "Scalable and Secure Sharing of Personal Health Records in Cloud Computing Using Attribute-Based Encryption," IEEE TPDS 24(1):131–143, 2013. DOI 10.1109/TPDS.2012.97 (Crossref record opened: https://api.crossref.org/works/10.1109/TPDS.2012.97; full text via https://www.academia.edu/8265412/Scalable_and_Secure_Sharing_of_Personal; conference version SecureComm 2010: https://www.cnsr.ictas.vt.edu/publication/Li_SecureComm10.pdf) | Yes (Crossref: 855 citations)\[4\] | Multi-authority ABE for PHRs split into public/personal domains, on-demand user/attribute revocation, and break-glass. Mechanism (§4.5): the patient builds an "emergency" attribute into the ciphertext, generates a KP-ABE emergency key skEM and "delegates it to the ED who keeps it in a database of patient directory. Upon emergency, a medical staff authenticates herself to the ED, requests and obtains the corresponding patient's skEM". Revocation after the emergency: patient computes a rekey rkEM, the ED and server update key and ciphertext.\[5\] | Same problem space (consent via ABE, revocation, break-glass in one framework, multiple attribute authorities). Their break-glass is a single trusted escrow (the ED) with no time-box, no automatic expiry and **no logging requirement at all** — the text never mentions audit for break-glass. Your delta (threshold emergency key, audit-gated release, forced rotation on expiry) is real but incremental. |
| Muslim & Grégoire, "An Extended Consent-Based Access Control Framework: Pre-Commit Validation and Emergency Access," arXiv 2603.07004 (Mar 2026), https://arxiv.org/abs/2603.07004 | Yes | XACML-based consent-based access control. "Pre-commit validation" = a Consent Conflict Analysis Module that detects modality conflicts/redundancies **before consent directives become active**. Emergency override driven by IoT physiological evidence, bounded by an Emergency Disclosure Control Function;\[6\] "each override is auditable".\[7\] | Your reading is correct: policy-layer, not cryptographic. "Pre-commit" refers to policy commit, not log commit — no overlap with commit-before-release. Useful to you twice: (a) as the clean "policy promise" baseline; (b) its intro states consent enforcement needs "explicit lifecycle semantics encompassing creation, activation, revocation, and expiration"\[7\] — so the *lifecycle* framing exists at policy level, and your N1 must be stated as the *cryptographic* realisation of it. It also cites a cryptographic CBAC via conditional PRE (Zhang et al.) and an Event-B consent-lifecycle model (Peyrone et al.)\[7\] — see Unverified leads. |
| Romel, Paul, Ruhan, Mim, Hoque, "A Patient-Centric Blockchain Framework for Secure Electronic Health Record Management: Decoupling Data Storage from Access Control," arXiv 2511.17464 (Nov 2025), https://arxiv.org/abs/2511.17464 | Yes | Encrypted FHIR resources off-chain; a public blockchain stores commitments and patient-signed, **time-bounded** EIP-712 permissions; keys distributed by public-key wrapping; formalised goals incl. "auditability of authorization events"; Solidity implementation, gas and latency benchmarks.\[8\] PRE and ABE are listed only as future enhancements.\[9\] | Your premise "it already does revocation as key rotation" is **not confirmed** by the abstract or the sections I read; what it clearly has is time-bounded, signed, on-chain-audited permissions with key wrapping. Overlap with you: key wrapping per grantee, signed authorization events, time-bounded access, audit. It has no break-glass in the abstract. Do not cite it for "revocation = rotation" unless you verify that in the full text; cite it for signed, time-bounded, audited grants. |

## 3. Claim-by-claim assessment (N1–N7)

| Claim | Rating | Closest prior work (link) | Year / venue | Delta (1–2 sentences) | Confidence |
|---|---|---|---|---|---|
| N1. Consent, revocation, break-glass as one key-lifecycle state machine; every transition a signed key-rotation event | Novel only as a combination | Li et al. TPDS (https://www.cnsr.ictas.vt.edu/publication/Li_SecureComm10.pdf); de Oliveira et al., Ann. Telecommun. (https://link.springer.com/article/10.1007/s12243-020-00759-2); Muslim & Grégoire (https://arxiv.org/abs/2603.07004) | 2013 TPDS; 2020 Annals of Telecommunications; 2026 arXiv | Li et al. already put grant, revocation (rekey) and break-glass in one ABE framework; de Oliveira et al. grant and revoke emergency access dynamically;\[10\] lifecycle semantics exist at policy level.\[11\]\[12\] Your delta is an explicit, signed, logged state machine whose transitions are key operations. Caution: "Grant" in your design adds a wrapping, it is not a rotation — calling every transition a rotation will be flagged. | Medium-high |
| N2. Logger is a threshold shareholder releasing its share only after a hash-chain commit | Partially anticipated | Kroll, Zimmerman, Wu, Nikolaenko, Felten, Boneh, "Accountable Cryptographic Access Control" (https://www.cs.yale.edu/homes/jf/kroll-paper.pdf); Ryan, "Making Decryption Accountable" (https://pure-oai.bham.ac.uk/ws/files/41623943/06_ryan_paper.pdf); Cheval, Moreira, Ryan, transparent decryption (https://arxiv.org/abs/2303.04500); Dauterman et al., Larch (https://arxiv.org/abs/2305.19241) | Kroll: 2018 manuscript (no primary venue confirmed; Fialka, ISC 2020, cites it as a CRYPTO 2018 workshop paper); Ryan: Security Protocols XXV, LNCS vol. 10476, pp. 93–98, 2017; Cheval et al.: IEEE EuroS&P 2023, pp. 107–121 (arXiv 2303.04500 is the extended version); Larch: USENIX OSDI 2023, pp. 81–98 | Transparent decryption already splits the key among trustees who decrypt "if (and only if)" the request is proven present in an append-only Merkle log; Kroll et al. use a threshold of decryption authorities with an auditor log and name hospital emergency access as an application;\[1\]\[2\]\[13\] Larch makes the log a split-secret holder so that no authentication happens without a log record.\[1\]\[3\]\[14\] Your delta: the logger itself is the shareholder, applied to EHR break-glass and bound to an EmergencyAssertion — but your log is trusted and a plain hash chain (no proofs of presence/extension), so it is cryptographically *weaker* than the prior art. | High |
| N3. Searchable encryption whose capability is derived from and scoped to a time-boxed emergency state | Partially anticipated | Yang & Ma, "Conjunctive Keyword Search with Designated Tester and Timing Enabled Proxy Re-Encryption Function for E-Health Clouds," IEEE TIFS 11(4):746–759 (DOI 10.1109/TIFS.2015.2509912; indexed at https://pmc.ncbi.nlm.nih.gov/articles/PMC7516898); temporary keyword search for health data (https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10912703/) | 2016 TIFS; 2024 journal (PMC) | Time-limited delegation of *both* search and decryption in e-health, where "the delegate could be automatically deprived of the access and search authority after a specified period", is published with proofs.\[15\]\[16\] Your delta is binding the search key to the emergency key via HKDF so it dies on rotation — technically simple and likely to be judged an engineering choice. | Medium-high |
| N4. Automatic emergency close-out via forced rotation with no admin action | Partially anticipated | de Oliveira et al. (https://link.springer.com/article/10.1007/s12243-020-00759-2); Yang & Ma TIFS 2016 | 2020; 2016 | de Oliveira et al. ensure "treatment teams will only access the patient's EMR for the period during which the patient is under their care", with a formal security analysis;\[10\] Yang & Ma revoke automatically after a time period.\[10\]\[15\] Your delta: expiry triggers re-encryption with a fresh DEK (forward security for the record), but enforcement still rests on a trusted timer, like token expiry. | Medium |
| N5. Cross-facility break-glass combining federated PKI cross-certification, threshold emergency key and PRE handoff | Novel only as a combination | Li et al. TPDS (multi-authority, ED escrow); de Oliveira et al. (multiple treatment teams "even from different institutions"); SSX-EHRs cross-domain PRE (https://link.springer.com/article/10.1186/s13635-025-00200-y) | 2013; 2020; 2025 EURASIP J. Info. Security | Each ingredient is standard; I found no paper combining all three for break-glass. Reviewers will value this little unless the composition yields a property none of the parts gives (e.g., out-of-network access without prior enrolment and without a single escrow). | Medium |
| N6. Wire-level traffic analysis as externally verifiable evidence of commit-before-release | Novel (methodological), low weight | No direct precedent found | — | I found no paper using passive captures to test release ordering of a log-gated key. But ordering on the wire shows response order, not durable commitment, and is not a proof; position it as an independent, code-agnostic test oracle, not as security evidence. | Medium (absence of evidence) |
| N7. Framing: break-glass as a key-lifecycle problem; logging as precondition, not promise | Partially anticipated | Kroll et al. (https://www.cs.yale.edu/homes/jf/kroll-paper.pdf); Ryan 2017; Li, Li, Wang, Duan, Wang, Ryan, "Accountable Decryption made Formal and Practical," IEEE Transactions on Information Forensics and Security, vol. 20, pp. 620–635, 2025, DOI 10.1109/TIFS.2024.3515808 (preprint IACR ePrint 2023/1519, https://eprint.iacr.org/2023/1519.pdf) | 2014–2025 | "Logging as a cryptographic precondition" is the stated thesis of accountable/transparent decryption, and the Li–Ryan TIFS 2025 paper explicitly motivates it by "break-glass scenarios". What is unclaimed in what I found is the EHR-specific unification of consent/revocation/break-glass as one key lifecycle. | Medium-high |

## 4. Related-work comparison matrix

Legend: ✓ yes; ~ partial/weak; ✗ no; ? not determinable from what was read.

| Scheme | Crypto enforcement (vs policy) | Break-glass | Revocation | Consent | Unified lifecycle | Logging gates key release | Threshold emergency key | Time-boxed search | Multi-authority / federated | PRE | Formal proof | Impl./benchmarks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Brucker & Petritsch, "Extending Access Control Models with Break-Glass," SACMAT 2009 (https://dl.acm.org/doi/10.1145/1542207.1542239) \[17\] | ✗ | ✓ | ~ | ~ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ? | ✓ |
| Li, Yu, Zheng, Ren, Lou, IEEE TPDS 2013 | ✓ | ✓ (ED escrow) | ✓ | ✓ | ~ | ✗ | ✗ | ✗ | ✓ | ✗ | ✓ | ✓ |
| Zhang, Chow, Sun, "Password-Controlled Encryption with Accountable Break-Glass Access," AsiaCCS 2016\[18\] | ✓ | ✓ | ? | ~ | ✗ | ✗ (KGC held accountable)\[18\] | ✗ | ✗ | ✗ | ✗ | ? | ? |
| Yang & Ma, timing-enabled PRE + keyword search, IEEE TIFS 2016 | ✓ | ✗ | ✓ (time-based) | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Yang, Liu, Deng, LiBAC, IEEE Trans. Industrial Informatics 14(8) | ✓ | ✓ | ? | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Scafuro, "Break-glass Encryption," PKC 2019\[19\] | ✓ | ✓ (detectable, once)\[20\] | ✗ | ✗ | ✗ | ~ (detectability) | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ (feasibility) |
| de Oliveira et al., break-glass CP-ABE, Ann. Telecommun. 2020\[21\] | ✓ | ✓ | ✓ (tokens) | ~ | ~ | ✗ | ✗ | ✗ | ~ (multi-institution teams) | ✗ | ✓ | ✓ |
| Kroll et al., Accountable Cryptographic Access Control | ✓ | ✓ (exceptional access) | ? | ✗ | ✗ | ✓ (auditor log)\[1\] | ✓ (threshold authorities)\[1\] | ✗ | ✓ | ✗ | ? | ✓ |
| Ryan 2017 / Cheval, Moreira, Ryan, IEEE EuroS&P 2023 (transparent decryption) | ✓ | ~ | ✗ | ✗ | ✗ | ✓ (Merkle log proofs)\[13\] | ✓ (trustees)\[2\] | ✗ | ✗ | ✗ | ✓ (ProVerif) | ~ |
| Li et al., PORTEX, IEEE TIFS 2025 (ePrint 2023/1519) | ✓ (TEE) | ~ (motivation) | ✗ | ✗ | ✗ | ✓ (TEE logs then releases)\[22\] | ~ (partial key)\[22\] | ✗ | ✗ | ✗ | ✓ | ✓ |
| Dauterman et al., Larch, USENIX OSDI 2023 (arXiv 2305.19241) | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ (log is secret holder) | ✓ (2-of-2 / t-of-n logs) | ✗ | ✗ | ✗ | ✓ | ✓ |
| Blockchain emergency PHR, MDPI Healthcare 9(2):206, 2021 (https://www.mdpi.com/2227-9032/9/2/206) \[23\] | ~ | ✓ | ? | ✓ | ✗ | ✗ (records, no share) | ✗ | ✗ | ~ | ✗ | ✗ | ✓ |
| Muslim & Grégoire, arXiv 2603.07004 (2026) | ✗ | ✓ | ✓ | ✓ | ~ (policy lifecycle) | ✗ | ✗ | ✗ | ✗ | ✗ | ~ (invariants) | ✓ (simulation) |
| Romel et al., arXiv 2511.17464 (2025) | ✓ | ✗ | ~ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ (future work) | ~ (formalised goals) | ✓ |
| **This work** | ✓ | ✓ | ✓ (forward-only) | ✓ | ✓ | ~ (trusted log; 2-of-3 bypass) | ✓ (2-of-3 Shamir) | ✓ | ✓ (cross-certified PKI, multi-AA) | ✓ (hand-rolled) | ✗ | ✓ (650 tests; 5/11 claims hold) |

Reading the matrix: your row is the only one with ✓ in the "unified lifecycle" column, but every other column is covered by someone, and in the column that carries your headline ("logging gates key release") the prior art is stronger than you are.

## 5. Biggest threats to novelty

**Threat 1 — Transparent / accountable decryption (Ryan, LNCS 10476, 2017; Cheval–Moreira–Ryan, IEEE EuroS&P 2023; Li et al., IEEE TIFS 2025 / ePrint 2023/1519).** A reviewer will write: "This is transparent decryption with a weaker log." In transparent decryption the decryption key is "distributed among a set of agents (called trustees); they use their key share only if the required transparency conditions have been satisfied", with the log untrusted because it supplies proofs of presence and extension, and the property has been verified in ProVerif.\[2\]\[3\]\[13\] *Positioning:* cite it as the primitive you instantiate; claim the EHR-specific contributions (EmergencyAssertion binding, lifecycle integration, auto-expiry with re-encryption, federation); and either adopt Merkle proofs of presence/extension or state explicitly that your audit service is trusted and why.

**Threat 2 — Kroll et al., "Accountable Cryptographic Access Control".** It mediates every access through "an approver and a threshold set of decryption authorities", logs "all accesses and their authorizations", and lists "Hospital patient records … exceptional access … for health emergencies" as an application.\[1\] It also states your exact motivation about code-path enforcement.\[1\] *Positioning:* it is generic exceptional access with an approver; you add patient-centric consent, revocation, time-boxed emergency state and searchable access. Put it in your related-work table and quote its hospital application yourself before a reviewer does.

**Threat 3 — Li et al. TPDS 2013 (and de Oliveira et al. 2020 as backup).** Your stated base already has consent, revocation and break-glass in one encrypted-PHR system, and de Oliveira et al. already have time-bounded, revocable break-glass across institutions with a formal analysis.\[10\]\[24\] *Positioning:* your delta over Li is replacing the single trusted ED escrow with a threshold whose release is gated on the log, and making expiry automatic; over de Oliveira, it is the log gate and the explicit lifecycle. Say this in one sentence in the introduction.

**Design flaw a reviewer will find immediately.** With 2-of-3 Shamir and shareholders {clinician agent, home authority, audit service}, shares 1+2 reconstruct the emergency key without share 3. "No log entry, no key" therefore holds only if the home authority never releases its share without a log receipt — which is a policy promise, the very thing you argue against. Fix: make the audit share mandatory (e.g., audit AND (clinician OR home authority), realised as a 2-of-2 between the audit service and a 1-of-2 inner share), or require the home authority to verify a signed chain head before releasing. Also note that the audit service does not yet verify the assertion before releasing share 3 — so today the logger logs, but does not authorise.

## 6. Publishability

**What survives the literature check:** (i) the EHR-specific unification of consent/revocation/break-glass as a single signed key lifecycle (combination novelty); (ii) a concrete, implemented instantiation of transparent decryption for federated break-glass with a threshold emergency key and forced-rotation close-out; (iii) the wire-level, code-independent test of release ordering. On its own this is a solid systems/application paper, not a cryptography paper.

**Venue tiers (typical constraints — always check the current CFP):**

| Tier | Realistic? | Example venues | Typical length / proofs |
|---|---|---|---|
| Top-tier security (IEEE S&P, ACM CCS, USENIX Security, NDSS) | No | — | ~13 pp + appendices; expect formal models and novel primitives or large-scale systems |
| Second-tier security conferences | Stretch, only after all minimum work + formal model | ACSAC, ESORICS, AsiaCCS, ACNS; SACMAT (best topical fit: access control, break-glass has a SACMAT lineage) | LNCS ~16–20 pp or ACM ~12 pp; proof sketch or symbolic verification expected for protocol claims |
| Security workshops | Realistic after fixes | ACM WPES, ACM CCSW, STM (ESORICS workshop), DPM (ESORICS workshop) | Short/long papers; formal model welcome but not mandatory |
| Applied / health-security journals | Realistic after fixes + scalability | Computers & Security (Elsevier), Journal of Information Security and Applications, International Journal of Information Security (Springer), IEEE JBHI (needs more health grounding) | No strict limit; reviewers expect thorough related-work comparison and evaluation |
| IEEE Access-style | Realistic | IEEE Access, MDPI Cryptography / Sensors | Accepts system papers; reviewer quality varies; weak for a CV signal |
| Student / regional | Realistic now | ICISS (India, Springer LNCS), SPACE, IEEE INDICON | Proofs not required; implementation valued |

**Expected reviewer objections (in order of severity):**
1. The headline property does not hold: 2-of-3 bypass of the logger, and audit service not verifying the assertion; 6 of 11 system-level claims failing.
2. Novelty: "this is transparent/accountable decryption applied to health"; missing citations to Kroll, Ryan, Cheval et al., Larch, PORTEX, Scafuro, Zhang–Chow–Sun.
3. No security definitions or proofs; the trusted audit service and trusted timer are not modelled.
4. Hand-rolled cryptography (PRE and Shamir); unidirectional ElGamal-style PRE needs a citation to a published scheme and its security notion (CPA vs CCA, collusion safety).
5. Non-collusion-resistant ABE substitute — reviewers will discount N-related federation claims built on it.
6. Single key custodian, synthetic data, no scalability curves, plain HTTP (fine for the traffic study, but justify it).

**Minimum work, ordered by impact per effort:**
1. **Fix the access structure** so the audit share is mandatory; re-run the negative tests. (Days; removes a fatal objection.)
2. **Close the two headline gaps**: audit service verifies the EmergencyAssertion (signature, freshness, binding, replay) before committing and releasing; expiry replaces emergency shares on the deployed path. Report "11/11 claims hold" or explicitly scope the paper to the claims that hold.
3. **Related-work section and the comparison matrix above**, with transparent decryption positioned as the primitive you instantiate. (Low effort, high reviewer impact.)
4. **Symbolic model of commit-before-release in ProVerif or Tamarin**: property "if any party learns the emergency key for record r, the log contains a committed entry for r bound to the assertion". The Cheval–Moreira–Ryan transparent-decryption ProVerif methodology is a direct template.\[3\] (1–3 weeks; turns a claim into a result.)
5. **Strengthen the log**: Merkle tree with proofs of presence/extension, or at least signed chain heads cross-checked by the home authority, so the logger is not a trusted party. Otherwise state the trust assumption up front.
6. **Replace hand-rolled PRE** with a published, implemented scheme (e.g., an Umbral-style threshold PRE as used in health-data prototypes)\[25\] or cite the exact construction you implement and its security notion; use a vetted Shamir implementation or test vectors.
7. **Scalability benchmarks**: latency of break-glass, rotation cost vs record size, and index rebuild vs number of patients/facilities.
8. **Real CP-ABE** (lowest priority per effort): keep the substitute for the workshop/regional version and list it as a limitation; replace it only if targeting a second-tier conference.

## 7. Suggested contribution statement and title

**Title options:**
- "No Log, No Key: Audit-Gated Break-Glass for Encrypted Health Records"
- "Transparent Decryption for Emergency Access: A Unified Key Lifecycle for Consent, Revocation and Break-Glass in Federated EHRs"

**Contribution statement (honest version):**
"We show how to make emergency (break-glass) access to encrypted health records *auditable by construction*. Building on accountable/transparent decryption, we (1) model consent, revocation, break-glass and expiry as a single signed key lifecycle over per-record data-encryption keys; (2) instantiate a threshold emergency key whose release requires a share held by the audit service, released only after the access is committed to a hash-chained log and bound to a signed, one-time emergency assertion; (3) scope emergency search capability to the same key so it expires with the emergency state; and (4) implement the design as a multi-process federation and evaluate it with a negative-security test suite and passive wire captures that independently check that the audit share never precedes the log-commit response. We state the trust assumptions (trusted timer, audit service, non-collusion-resistant policy layer) and leave formal verification of the full protocol to future work [or: verify commit-before-release in ProVerif]."

Do not claim "first to make logging a cryptographic precondition" — that claim is false. "First to integrate transparent-decryption-style log gating into a unified consent/revocation/break-glass key lifecycle for federated EHRs" is defensible on current evidence, with the caveat in Section 1.

## 8. Unverified leads and search log

**Prior work seen only via search-result landing pages (metadata confirmed, full text not opened by me):**
- Scafuro, "Break-glass Encryption," PKC 2019, LNCS 11443, pp. 34–62, DOI 10.1007/978-3-030-17259-6_2 — https://link.springer.com/chapter/10.1007/978-3-030-17259-6_2 \[20\]\[26\]
- Zhang, Chow, Sun, "Password-Controlled Encryption with Accountable Break-Glass Access," AsiaCCS 2016, pp. 235–246 — listed at https://meeting.xidian.edu.cn/conference/AsiaCCS2016/papers.html \[18\]\[27\]\[28\]
- Brucker & Petritsch, SACMAT 2009, DOI 10.1145/1542207.1542239 — https://dl.acm.org/doi/10.1145/1542207.1542239 \[17\]
- Brucker, Petritsch, Weber, "Attribute-Based Encryption with Break-Glass," 2010 — https://link.springer.com/chapter/10.1007/978-3-642-12368-9_18 (fetch was rate-limited)\[29\]
- Yang, Liu, Deng, "Lightweight Break-Glass Access Control System for Healthcare Internet-of-Things," IEEE TII — https://ieeexplore.ieee.org/document/8036213/ \[30\]\[31\]
- de Oliveira, Michalas, Groot, Marquering, Olabarriaga, "Red Alert: Break-Glass Protocol to Access Encrypted Medical Records in the Cloud," 2019 — https://ieeexplore.ieee.org/document/9009598/ \[12\]\[32\]
- Yang & Ma, IEEE TIFS 11(4) 2016, DOI 10.1109/TIFS.2015.2509912\[33\]
- "Emergency Medical Access Control System Based on Public Blockchain," J. Med. Syst. 2024 — https://pmc.ncbi.nlm.nih.gov/articles/PMC11413154/ \[34\]\[35\]
- "TPM-based adaptive access control scheme with break-glass support for healthcare systems," 2026 — https://www.sciencedirect.com/science/article/abs/pii/S2214212626001286 (authors not visible; reportedly returns a "break-glass key share"; check whether release is log-gated)\[36\]
- SSX-EHRs cross-domain PRE, 2025 — https://link.springer.com/article/10.1186/s13635-025-00200-y \[37\]

**Leads not verified at all (check before citing):**
- Zhang et al., cryptographic consent-based access control via conditional PRE (cited as [5] in arXiv 2603.07004).\[7\]
- Peyrone et al., Event-B model of the consent lifecycle (cited as [6] in arXiv 2603.07004)\[7\] — potential threat to N1/N7 at specification level.
- Kroll, Felten, Boneh, "Secure protocols for accountable warrant execution," 2014 manuscript;\[3\]\[38\]\[39\] and Kroll et al. "Accountable Cryptographic Access Control", for which no primary venue is confirmed (Fialka, ISC 2020, cites it as "In: Workshop, CRYPTO 2018"; ePrint 2024/1676 cites it as a 2018 preprint) — cite it as a "2018 manuscript".
- Frankle, Park, Shaar, Goldwasser, Weitzner, "Practical Accountability of Secret Processes," USENIX Security 2018\[3\] (ePrint 2018/697).\[40\]
- Fialka (accountable decryption via privacy-preserving smart contracts); Nuñez, Agudo, Lopez, "Escrowed decryption protocols for lawful interception," IET Inf. Sec. 2019; "Universally Composable Auditable Surveillance" (Springer, 2023);\[2\]\[41\]\[42\] self-incriminating proofs of decryption (ePrint 2024/794); Acsesor auditable custodial secret recovery (ePrint 2022/1729).\[3\]\[43\]\[44\]\[45\]
- Rajput et al. 2019 EACMS (Hyperledger emergency access); Madine et al. emergency PRE on blockchain;\[34\]\[46\] "Fully Decentralized Multi-Party Consent Management for Secure Sharing of Patient Health Records" (IEEE Access, threshold key split among institutions); Marinovic et al., "Rumpole," SACMAT 2011;\[10\]\[46\]\[47\]\[48\] Ferreira et al. 2006 break-the-glass model.
- Miao et al., time-controllable keyword search for mobile e-health.\[49\]

**Search log (web search, Oct 2026; databases reached via results: arXiv, IACR ePrint, Springer, ACM DL, IEEE Xplore, ScienceDirect, PubMed Central, Crossref, MDPI):**
1. Li Yu Zheng Ren Lou PHR ABE break-glass
2. Li et al. TPDS 2013 emergency department "temporary read keys"
3. accountable decryption Ryan transparency log
4. break-glass encrypted health records threshold secret sharing audit
5. "A break-glass protocol based on ciphertext-policy attribute-based encryption…"
6. Kroll Feigenbaum accountable warrant execution threshold decryption auditor
7. blockchain smart contract break-glass EHR secret sharing key release
8. time-controlled keyword search encrypted health records emergency
9. Brucker Petritsch break-glass SACMAT 2009
10. Scafuro Break-Glass Encryption PKC 2019
11. Yang Zheng password-based break-glass ABE
12. emergency access encrypted EHR proxy re-encryption cross-domain escrow
13. Red Alert break-glass QR Shamir
14. LiBAC lightweight break-glass
15. site:eprint.iacr.org emergency access threshold decryption audit log
16. Password-controlled encryption accountable break-glass AsiaCCS 2016
17. PAD privacy-preserving accountable decryption transparent log
18. Yang Ma timing-enabled PRE e-health TIFS
Plus one subagent sweep (six further searches) for log-then-release EHR schemes: none found where the log/blockchain itself holds a decryption share. Gaps to extend: DBLP/Google Scholar for "transparent decryption" + health; Tamarin/ProVerif break-glass models; NIST SP 800-57 key states applied to consent.

## Sources

1. [Accountable Cryptographic Access Control](https://www.cs.yale.edu/homes/jf/kroll-paper.pdf)
2. [Transparent decryption](https://en.wikipedia.org/wiki/Transparent_decryption)
3. [Automatic verification of transparency protocols (extended version)](https://arxiv.org/pdf/2303.04500)
4. <https://api.crossref.org/works/10.1109/TPDS.2012.97>
5. [Scalable and Secure Sharing of Personal](https://www.academia.edu/8265412/Scalable_and_Secure_Sharing_of_Personal)
6. [An Extended Consent-Based Access Control Framework: Pre-Commit Validation and Emergency Access](https://arxiv.org/abs/2603.07004)
7. [An Extended Consent-Based Access Control Framework: Pre-Commit Validation and Emergency Access](https://arxiv.org/pdf/2603.07004)
8. [A Patient-Centric Blockchain Framework for Secure Electronic Health Record Management: Decoupling Data Storage from Access Control](https://arxiv.org/abs/2511.17464)
9. [A Patient-Centric Blockchain Framework for Secure Electronic Health Record Management: Decoupling Data Storage from Access Control](https://arxiv.org/pdf/2511.17464)
10. [A break-glass protocol based on ciphertext-policy attribute-based encryption to access medical records in the cloud](https://link.springer.com/article/10.1007/s12243-020-00759-2)
11. <https://www.cnsr.ictas.vt.edu/publication/Li_SecureComm10.pdf>
12. [Sharing in the Rain: Secure and Efficient Data Sharing for the Cloud](https://www.researchgate.net/publication/307868740_Sharing_in_the_Rain_Secure_and_Efficient_Data_Sharing_for_the_Cloud)
13. <https://pure-oai.bham.ac.uk/ws/files/41623943/06_ryan_paper.pdf>
14. <https://arxiv.org/pdf/2305.19241>
15. [(PDF) A Study on Conjunctive Keyword Search with Designated Tester and Timing Enabled Proxy Re-Encryption Function for E-Health Clouds](https://www.academia.edu/36678588/A_Study_on_Conjunctive_Keyword_Search_with_Designated_Tester_and_Timing_Enabled_Proxy_Re_Encryption_Function_for_E_Health_Clouds)
16. [Public Key Encryption with Keyword Search in Cloud: A Survey - PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC7516898)
17. [Extending access control models with break-glass](https://dl.acm.org/doi/10.1145/1542207.1542239)
18. [(PDF) A break-glass protocol based on ciphertext-policy attribute-based encryption to access medical records in the cloud](https://www.researchgate.net/publication/339776253_A_break-glass_protocol_based_on_ciphertext-policy_attribute-based_encryption_to_access_medical_records_in_the_cloud)
19. [Break-glass Encryption Alessandra Scafuro(B) NCSU, Raleigh, USA](https://par.nsf.gov/servlets/purl/10098718)
20. [Break-glass Encryption](https://www.researchgate.net/publication/332261858_Break-glass_Encryption)
21. [A break-glass protocol based on ciphertext-policy attribute-based encryption to access medical records in the cloud - Trepo](https://trepo.tuni.fi/handle/10024/217224)
22. <https://eprint.iacr.org/2023/1519.pdf>
23. [A Blockchain-Based Secret-Data Sharing Framework for Personal Health Records in Emergency Condition](https://www.mdpi.com/2227-9032/9/2/206)
24. [Scalable and secure sharing of personal health records in cloud computing using attribute-based encryption](https://experts.arizona.edu/en/publications/scalable-and-secure-sharing-of-personal-health-records-in-cloud-c/)
25. [Patient-centric health data sovereignty: an approach using Proxy re-encryption⋆](https://arxiv.org/pdf/2307.01175)
26. [Break-glass Encryption](https://link.springer.com/chapter/10.1007/978-3-030-17259-6_2)
27. [An efficient attribute-based access control system with break-glass capability for cloud-assisted industrial control system](http://www.aimspress.com/article/doi/10.3934/mbe.2021179)
28. [ASIACCS'16](https://meeting.xidian.edu.cn/conference/AsiaCCS2016/papers.html)
29. [Attribute-Based Encryption with Break-Glass](https://link.springer.com/chapter/10.1007/978-3-642-12368-9_18)
30. [Lightweight Break-Glass Access Control System for Healthcare Internet-of-Things](https://ieeexplore.ieee.org/document/8036213/)
31. [(PDF) Securing Data in Internet of Things (IoT) using Cryptography and Steganography Techniques](https://www.academia.edu/43776831/Securing_Data_in_Internet_of_Things_IoT_using_Cryptography_and_Steganography_Techniques)
32. [Red Alert: Break-Glass Protocol to Access Encrypted Medical Records in the Cloud](https://repository.tudelft.nl/record/uuid:3d533b47-3a41-49c5-8600-43ae63b09129)
33. [Electronic Health Records Sharing Based on Consortium Blockchain - PubMed](https://pubmed.ncbi.nlm.nih.gov/39557726/)
34. [Emergency Medical Access Control System Based on Public Blockchain - PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC11413154/)
35. [Emergency Medical Access Control System Based on Public Blockchain](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11413154/)
36. [TPM-based adaptive access control scheme with break-glass support for healthcare systems - ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S2214212626001286)
37. [SSX-EHRs: secure and scalable cross-domain EHRs sharing with blockchain sharding and dynamic proxy re-encryption](https://link.springer.com/article/10.1186/s13635-025-00200-y)
38. [Secure protocols for accountable warrant execution Joshua A. Kroll](https://www.jkroll.com/papers/warrant_paper.pdf)
39. [Joshua A. Kroll 94 Spring Grove Avenue, San Anselmo, CA 94960](https://www.jkroll.com/jkroll-cv.pdf)
40. [AUDIT: Practical Accountability of Secret Processes Jonathan Frankle Sunoo Park](https://eprint.iacr.org/2018/697.pdf)
41. [Making Decryption Accountable (Transcript of Discussion)](https://www.researchgate.net/publication/321351558_Making_Decryption_Accountable_Transcript_of_Discussion)
42. [Universally Composable Auditable Surveillance](https://link.springer.com/chapter/10.1007/978-981-99-8724-5_14)
43. [Acsesor: A New Framework for Auditable Custodial Secret Storage and Recovery](https://eprint.iacr.org/2022/1729.pdf)
44. [Detecting Rogue Decryption in (Threshold) Encryption via Self ...](https://eprint.iacr.org/2024/794.pdf)
45. [(PDF) An Accountable Decryption System Based on Privacy-Preserving Smart Contracts](https://www.researchgate.net/publication/347146837_An_Accountable_Decryption_System_Based_on_Privacy-Preserving_Smart_Contracts)
46. [Security of Healthcare Data Using Blockchains: A Survey](https://arxiv.org/pdf/2103.12326)
47. [(PDF) Fully Decentralized Multi-Party Consent Management for Secure Sharing of Patient Health Records](https://www.researchgate.net/publication/346968648_Fully_Decentralized_Multi-Party_Consent_Management_for_Secure_Sharing_of_Patient_Health_Records)
48. [Generic support for RBAC break-glass policies in process-aware information systems](https://dl.acm.org/doi/10.1145/2480362.2480631)
49. [Time-Controllable Keyword Search Scheme With Efficient Revocation in Mobile E-Health Cloud](https://www.researchgate.net/publication/370876195_Time-Controllable_Keyword_Search_Scheme_with_Efficient_Revocation_in_Mobile_E-health_Cloud)
