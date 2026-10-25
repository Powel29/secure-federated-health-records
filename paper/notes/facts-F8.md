# F8 — Related work and citation verification (2026-10-21)

Every fact below was read on the primary page given at the end of the line
(DOI registry record, publisher page, arXiv, IACR ePrint, USENIX, or the
author-hosted PDF). BibTeX for each is in `paper/notes/refs-verified.bib`.
"Our delta" lines follow `PROJECT.md` §4 / ADR-0088 and do not claim any
property of this work beyond those documents; the "this work" matrix row is
left for facts-live.md / F1–F6.

Forbidden in the paper (ieee-paper skill): being first to make logging a
cryptographic precondition of decryption or break-glass; first to offer
break-glass over encrypted records; first to offer time-limited search.

## Facts

### Accountable / transparent decryption

1. **kroll2018accountable**: Every access to records is mediated by an approver and a threshold set of decryption authorities. An auditor logs all accesses and their authorizations, and the audit log is publicly verifiable. The auditor certifies that entries are present in its log, and the other parties do not let the protocol proceed without that certification. A prototype is specialised to law-enforcement access to communications metadata. The intro argues that software-only checks "ultimately rely on a code path" that can be bypassed. **Hospital-emergency application (§1.1, paraphrased):** in a hospital, the protocol supports exceptional access "not foreseen by a normal access policy for health emergencies", where an unpredictable set of staff may suddenly need records. It also guarantees an audit record so internal reviewers can check that the access was not abused (e.g. snooping on celebrity patients). — our delta: generic approver-mediated exceptional access, with no patient consent or revocation lifecycle, no time-boxed emergency state that expires by rotation, and no emergency-scoped search. Here the logger (audit service) is itself a mandatory shareholder of a per-record emergency key, and it checks a signed Emergency Assertion before commit. Our log is weaker: a trusted hash chain, not a publicly verifiable log. Caveat: the PDF is **undated and gives no venue**; "2018" is unverified. — https://www.cs.yale.edu/homes/jf/kroll-paper.pdf

2. **ryan2017accountable**: Defines accountable decryption: encryptors can later learn the circumstances of decryptions, and decryptors cannot suppress that evidence without detection. The protocol relies on a trusted hardware device. The device decrypts only after the request is entered in a log organised like certificate transparency. The log maintainer is untrusted and gives proofs of presence and proofs of extension (append-only). It is a short position paper (6 pp.) with no implementation reported. — our delta: we instantiate this idea (log entry before key material) for federated EHR break-glass, using a threshold share held by the logger instead of a trusted hardware device. Our log is trusted and gives no proofs of presence or extension (PROJECT.md §5 item 13). — https://link.springer.com/chapter/10.1007/978-3-319-71075-4_11 ; text: https://pure-oai.bham.ac.uk/ws/files/41623943/06_ryan_paper.pdf

3. **cheval2023transparency**: Adds new features to ProVerif and gives the first formal verification of transparent decryption and certificate transparency, with a detailed Merkle-tree model. In transparent decryption (§2.2), the decryption key is split among trustees, e.g. m-of-n threshold decryption. A request is recorded in a Merkle-tree log, and a trustee uses its share only if the log proofs (presence and append-only extension) verify. The trust assumption is that the trustees behave correctly. — our delta: this is **the primitive we instantiate**. Ours is weaker: trusted plain hash chain, no proofs, no formal model. Ours adds an EHR-specific signed Emergency Assertion bound to the record, integration into a consent/revocation/expiry key lifecycle, federation, and automatic expiry by rotation. Note: the paper's title is "Automatic verification of transparency protocols". — https://arxiv.org/abs/2303.04500 ; DOI 10.1109/EuroSP57164.2023.00016

4. **dauterman2023larch**: Larch is accountable authentication for FIDO2, TOTP and passwords. It splits the user's authentication secret between the client and a log service, so both must take part in every login. If the client obtains a valid credential, the log obtains a well-formed encrypted log record, even when the client is compromised. The log learns nothing about which relying party is used. Trust can be split across several log providers for availability, and the user can revoke all accounts through the log. Implemented; logins take about 74–150 ms. — our delta: same "log as secret-holder" pattern, but for authentication, not decryption of records, and with no break-glass, consent or health setting. We apply it to a per-record emergency key with a mandatory audit share. — https://www.usenix.org/conference/osdi23/presentation/dauterman ; https://arxiv.org/abs/2305.19241

5. **li2025accountable**: Formal definitions of accountable decryption (with possibility and impossibility results) and a TEE-assisted construction in a "trust, but verify" model, so decryptors can detect a compromised TEE. Implemented: about 5.5 ms decryption with 300,000 log entries, and malicious decryptors identified within about 69 ms. **Not confirmed:** the name "PORTEX" and a break-glass motivation (neither appears on the ePrint page, in the abstract or in the index records; the full text returned 403). — our delta: formal and TEE-based, while ours is threshold-share-based, informal, and specific to an EHR lifecycle. Cite it only for formal, practical accountable decryption. — https://eprint.iacr.org/2023/1519 ; DOI 10.1109/TIFS.2024.3515808 (Crossref: vol. 20, pp. 620–635, 2025)

### Break-glass access control (policy layer)

6. **brucker2009extending**: Argues that static access control fails in health care and disaster management, and that break-glass is usually bolted on ad hoc. Integrates break-glass at fine grain into standard access-control models and their enforcement architecture, which supports model-driven development. No encryption. — our delta: policy-layer and enforced by a code path. In ours, keys and the threshold gate decide access, not a policy decision point. — https://brucker.ch/abstract/brucker.ea-extending-2009.en.html ; DOI 10.1145/1542207.1542239

7. **ferreira2006break**: A break-the-glass (BTG) policy added to the access-control model of a hospital EMR used daily by more than 500 doctors. It overrides access control in emergencies and provides non-repudiation mechanisms for BTG use. (content confirmed: https://api.openalex.org/works/doi:10.1109/CBMS.2006.95 — publisher abstract via index, 2026-10-22; full text not opened; metadata is from Crossref.) — our delta: no cryptographic enforcement there; break-glass usage is recorded after the fact, not as a precondition of key release. — DOI 10.1109/CBMS.2006.95 (https://api.crossref.org/works?query.bibliographic=How+to+Break+Access+Control+in+a+Controlled+Manner+Ferreira)

8. **marinovic2011rumpole**: A flexible break-glass access-control model (SACMAT 2011) for human-centric domains such as health care. It establishes why access was denied, uses Belnap's four-valued logic to handle conflicting and missing information, and gives a declarative query language in which policy writers specify the override procedure. (content confirmed: https://api.openalex.org/works/doi:10.1145/1998441.1998453 — publisher abstract via index, 2026-10-22; full text not opened.) — our delta: policy model, not cryptographic. — DOI 10.1145/1998441.1998453

### Cryptographic break-glass

9. **brucker2010abe**: Notes that common ABE schemes lack break-glass. Integrates break-glass into end-to-end secure information sharing built on ABE, for disaster management and health care. — our delta: no logging precondition, and no consent/revocation/expiry lifecycle. We use a Shamir threshold gate with a mandatory audit share. — https://link.springer.com/chapter/10.1007/978-3-642-12368-9_18

10. **zhang2016password**: Password-controlled encryption. Two factors combine a user-chosen password with a key generation centre's (KGC) master key. A password holder, such as an emergency contact, can obtain the decryption key from the KGC without revealing the password. The KGC is held accountable if it abuses key generation. Pitched for medical records, with no key-escrow server or trusted hardware. (content confirmed: https://api.openalex.org/works/doi:10.1145/2897845.2897869 — publisher abstract via index, 2026-10-22; dl.acm.org returns 403 and the full text was not opened.) — our delta: there, accountability means detecting KGC abuse. Here, the logger's share is released only after a signed assertion is validated and the access is committed to the log. — DOI 10.1145/2897845.2897869

11. **scafuro2019breakglass**: Break-glass encryption for cloud storage. The ciphertext security can be violated exactly once, in an emergency, without a trusted party. Unauthorised breaking is detectable, and the user gets proof of it. Semantic security holds if the legitimate user invokes it. The construction uses hardware tokens and is a feasibility result that the author says is impractical. — our delta: we give detection by construction (log before share) for many records and many clinicians, in an implemented federation. We give no "exactly once" property and no formal proof. — https://link.springer.com/chapter/10.1007/978-3-030-17259-6_2

12. **deoliveira2019redalert**: A break-glass protocol that lets a healthcare team decrypt a patient's encrypted records in emergencies such as suspected acute stroke. Access is limited to the time needed for a task such as transfer to hospital, and access can be granted and withdrawn during treatment. Mechanism (full text): a CP-ABE emergency key plus Master-Authority-signed team access tokens with a default expiry; the MA revokes a team's token at the CSP when its task ends, without re-encrypting the EMR; teams may come from different institutions. Security is argued informally against malicious behaviours; no implementation or audit logging is reported. (content confirmed: https://pure.amsterdamumc.nl/ws/files/178264175/Red-alert-break-glass-protocol-to-access-encrypted-medical-records-in-the-cloud.pdf — version of record, 2026-10-22; abstract also at https://researchportal.tuni.fi/en/publications/red-alert-break-glass-protocol-to-access-encrypted-medical-record/) — our delta: no log gate, and no single signed consent/revocation lifecycle. — DOI 10.1109/HealthCom46333.2019.9009598

13. **deoliveira2020breakglass**: A CP-ABE break-glass protocol in which all treatment teams in an emergency, "even from different institutions", can decrypt relevant EMR parts and add data. Each team's access is limited to the period the patient is under its care. This uses signed access tokens with expiry, plus revocation messages from a trusted Master Authority to a trusted CSP, driven by check-in/check-out from attested devices. Data is not re-encrypted. The security analysis is game/simulation-based, with initial experiments. No audit or logging mechanism for break-glass is described. — our delta: our log gate (mandatory audit share released after assertion check and commit), the explicit signed lifecycle, and expiry enforced by DEK rotation rather than by a trusted CSP blocking access. — https://link.springer.com/article/10.1007/s12243-020-00759-2

14. **yang2018libac**: LiBAC offers two ways to open encrypted medical files in healthcare IoT. Normally, a worker's attributes must satisfy the file's policy. In an emergency, break-glass overrides the policy. Lightweight for IoT devices, proven secure in the standard model, with experiments. — our delta: no logging precondition and no lifecycle or federation. — DOI 10.1109/TII.2017.2751640

### Encrypted PHR sharing (anchor)

15. **li2013phr**: Patient-centric PHR sharing on semi-trusted servers using multi-authority ABE. Users are split into multiple security domains, with dynamic policy updates, efficient on-demand user/attribute revocation, and break-glass access in emergencies. Break-glass mechanism (read in the SecureComm 2010 version, §4.5): the patient delegates a trapdoor to an emergency department (ED). Staff authenticate to the ED and obtain it, and after recovery the patient re-keys via the ED and the server. No audit or logging is described for break-glass. — our delta: the single trusted ED escrow is replaced by a threshold whose release needs a logged, assertion-checked audit share, and expiry is automatic. — DOI 10.1109/TPDS.2012.97 ; abstract https://experts.arizona.edu/en/publications/scalable-and-secure-sharing-of-personal-health-records-in-cloud-c/ ; conference text https://www.cnsr.ictas.vt.edu/publication/Li_SecureComm10.pdf

### Time-limited search / PRE in e-health

16. **yang2016timing**: Re-dtPECK is time-dependent searchable encryption for e-health clouds. Patients can delegate search and decryption rights over their records for a controlled time period, with conjunctive keyword search, a designated tester, and resistance to keyword-guessing attacks; proven secure in the standard model, with simulations. (content confirmed: https://api.openalex.org/works/doi:10.1109/TIFS.2015.2509912 — publisher abstract via index, 2026-10-22; full text not opened; the metadata is from Crossref.) — our delta: time-limited delegated search is prior art. Ours only derives the emergency search capability from the emergency key, so it ends at the expiry rotation; that is an engineering choice, not a new primitive. — DOI 10.1109/TIFS.2015.2509912

### Consent at the policy layer

17. **muslim2026consent**: Extended XACML-based consent-based access control. "Pre-commit validation" checks a draft consent directive for conflicts and invariant violations before it becomes active. It adds immutable baseline-access invariants and break-the-glass access triggered by physiological evidence and bounded by an Emergency Disclosure Control Function. Each override is auditable and logged for post-hoc accountability. The intro says consent needs lifecycle semantics covering creation, activation, revocation and expiration. The paper says its enforcement is "logical rather than cryptographic". Evaluated by simulation. — our delta: we give a cryptographic realisation of that lifecycle (keys and the threshold gate decide). "Pre-commit" there means committing a policy, not a log entry. — https://arxiv.org/abs/2603.07004 ; body https://arxiv.org/html/2603.07004v1

18. **romel2025patient**: Encrypted FHIR resources off-chain. A public chain stores commitments and patient-signed (EIP-712), time-bounded permissions, and keys are distributed by public-key wrapping. Formal goals include "auditability of authorization events". Solidity implementation, about 78k gas per grant on L1, 0.7–1.4 s access for 1 MB. Revocation flips an on-chain flag and does not re-encrypt; re-keying is a separate optional workflow. **It also has emergency access (§5.8):** two registered emergency physicians co-sign an EIP-712 request, access expires after 2 hours, confirmation is due within 24 h, and grant and confirmation are emitted as on-chain events. Wrapped keys come from an HSM-backed institutional guardian that is design-only (§9.2). — our delta: cite it for signed, time-bounded, audited grants (never for revocation-as-rotation). Its emergency grant is logged on-chain, but the key release is not cryptographically gated on that log, because the guardian is a separate trusted service and is unimplemented. Ours gates release on a mandatory audit share. — https://arxiv.org/abs/2511.17464 ; body https://arxiv.org/html/2511.17464v1

### Foundational primitives

19. **shamir1979share**: (k, n) threshold secret sharing by polynomial interpolation. — our use: weighted 3-of-4 split of the emergency key. — DOI 10.1145/359168.359176
20. **bethencourt2007cpabe**: Ciphertext-policy ABE. — our use: contrast only; we substitute a secret-sharing access structure (not collusion-resistant CP-ABE). — DOI 10.1109/SP.2007.11
21. **blaze1998proxy**: Atomic proxy cryptography, where a proxy key and function translate ciphertexts from one key to another. — our use: background for PRE. Note: break-glass uses a KEM, not PRE (ADR-0076). — https://link.springer.com/chapter/10.1007/BFb0054122
22. **curtmola2006sse**: Searchable symmetric encryption, with improved definitions and efficient constructions. — our use: background for the encrypted search index. — DOI 10.1145/1180405.1180417

## Review findings marked out of date

From the status note of `docs/review/2026-10-21-novelty-publishability-review.md`. Never repeat these as current:

- "2-of-3 lets clinician + home authority open a record without the audit service." This was fixed by ADR-0074 and is now ADR-0089: a weighted 3-of-4 split with clinician custodian x=1, home authority x=2, and audit service x=3 and x=4, so every unlock needs an audit share.
- "The audit service does not verify the assertion." Fixed by ADR-0067 (claim C3).
- "Expiry does not replace the emergency shares." Fixed by ADR-0069 (C4).
- "5/11 claims hold, 650 tests." As of 2026-10-21, 11/11 hold, with 951 passed and 2 skipped (`docs/test-evidence/claim-table.md`). Re-check in facts-live.md.
- N5 "PRE handoff". Break-glass does not use re-encryption; the DEK is delivered by a KEM (ADR-0076).
- N6 "the wire shows response order, not durable commitment". Wire check 2 reads Postgres `CommandComplete(COMMIT)` on the wire before the release response. That is stronger than response order but not a proof, and it holds only on the plain profile.
- The "This work" row of the review's §4 matrix, and minimum-work items 1–2, describe the old state.
- Also from the skill: the review's bibliography is leads only. [2] is Wikipedia, and [12], [18] and [33] point at the wrong papers. §8 leads are unverified.

Still valid (status note): logging-as-precondition is prior art; 2511.17464 is not revocation-as-rotation; the audit chain is trusted with no presence or extension proofs (§5 item 13); Grant wraps and does not rotate; there is no formal model.

## Related-work matrix

Columns:
- **CE**: cryptographic enforcement (keys decide, not a policy check)
- **LG**: key or decryption release gated on a log entry
- **BG**: break-glass or emergency access
- **LC**: patient consent and revocation in one lifecycle
- **TB**: time-boxed or automatic expiry
- **ES**: emergency-scoped or time-limited search
- **FED**: multi-institution or multi-authority
- **FP**: formal proof or model, and log proofs
- **IMP**: implementation and evaluation

✓ yes · ~ partial · ✗ no · ? not determined from what was read. Cells come only from facts 1–18.

| Work | CE | LG | BG | LC | TB | ES | FED | FP | IMP |
|---|---|---|---|---|---|---|---|---|---|
| Kroll et al. (n.d.) | ✓ | ✓ auditor certifies log entries; threshold DAs | ~ exceptional access; hospital emergencies named | ✗ | ? | ✗ | ~ independent DAs | ~ properties; proofs deferred to an extended version; publicly verifiable log | ✓ prototype (LE metadata) |
| Ryan 2017 | ✓ | ✓ trusted HW decrypts after log proofs | ✗ | ✗ | ✗ | ✗ | ✗ | ~ untrusted log with presence/extension proofs; no proof in paper | ✗ |
| Cheval, Moreira, Ryan 2023 | ✓ | ✓ trustees iff Merkle proofs verify | ✗ | ✗ | ✗ | ✗ | ~ m-of-n trustees | ✓ ProVerif and Merkle log proofs | ~ models only |
| Larch (OSDI 2023) | ✓ (authentication) | ✓ log holds split secret | ✗ | ✗ | ✗ | ✗ | ~ multiple log providers | ? | ✓ |
| Li et al. TIFS 2025 | ✓ (TEE) | ✓ accountable decryption with log | ? not confirmed | ✗ | ✗ | ✗ | ✗ | ✓ formal definitions | ✓ |
| Brucker & Petritsch 2009 | ✗ | ✗ | ✓ | ✗ | ? | ✗ | ✗ | ? | ? |
| Ferreira et al. 2006 | ✗ | ✗ (non-repudiation after use) | ✓ | ✗ | ? | ✗ | ✗ | ? | ✓ deployed in a hospital EMR |
| Marinovic et al. 2011 | ✗ | ? | ✓ | ? | ? | ✗ | ? | ? | ? |
| Brucker, Petritsch, Weber 2010 | ✓ (ABE) | ? | ✓ | ? | ? | ✗ | ? | ? | ? |
| Zhang, Chow, Sun 2016 | ✓ | ✗ (KGC accountable for abuse) | ✓ | ? | ? | ✗ | ✗ | ? | ? |
| Scafuro 2019 | ✓ | ~ detectability, not a log | ✓ exactly once | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ feasibility, HW tokens |
| de Oliveira et al. 2019 | ✓ | ✗ none described (full text) | ✓ | ~ grant/withdraw | ✓ task duration | ✗ | ? | ✗ informal analysis only | ✗ none reported |
| de Oliveira et al. 2020 | ✓ (CP-ABE) | ✗ none described | ✓ | ~ tokens and revocation via trusted MA/CSP | ✓ period of care, no re-encryption | ✗ | ✓ different institutions | ✓ game/simulation | ✓ initial experiments |
| Yang, Liu, Deng 2018 (LiBAC) | ✓ (ABE) | ✗ | ✓ | ✗ | ? | ✗ | ✗ | ✓ standard model | ✓ |
| Li et al. TPDS 2013 | ✓ (MA-ABE) | ✗ | ✓ ED escrow | ~ patient-centric, on-demand revocation | ✗ manual restore | ✗ | ✓ multi-authority, multiple domains | ? | ✓ |
| Yang & Ma 2016 | ✓ | ✗ | ✗ | ~ delegation | ✓ time-limited delegation | ✓ time-limited (not emergency) | ✗ | ✓ (per abstract) | ~ simulations only |
| Muslim & Grégoire 2026 | ✗ ("logical rather than cryptographic") | ✗ (overrides logged after the fact) | ✓ | ~ lifecycle at policy layer | ? | ✗ | ✗ | ~ invariants | ✓ simulation |
| Romel et al. 2025 | ✓ (encryption and key wrapping) | ✗ (on-chain audit; guardian is a separate design-only service) | ✓ two-physician, 2 h | ~ signed grants; revocation is a flag | ✓ time-bounded grants | ✗ | ? | ~ formalised goals | ✓ Solidity, gas |
| **This work** | TO FILL FROM facts-live.md / F1–F6 | | | | | | | | |

## Contradictions found

Review vs primary sources:

C1. **arXiv 2511.17464 does have break-glass.** The review says "no break-glass in the abstract", and its matrix marks Break-glass ✗; PROJECT.md §4's rival description also omits it. The full text §5.8 implements a two-physician, co-signed EIP-712 emergency grant with a 2-hour expiry and on-chain events. The paper should acknowledge this. Our delta is that its key release goes through a separate, unimplemented HSM guardian and is not gated on the log.
C2. **"PORTEX" is not confirmed.** It is not on the IACR ePrint page, in the TIFS abstract, or in Crossref or S2. Nor is "explicitly motivates it by break-glass scenarios" (review N7, PROJECT.md §4: "Its motivation is break-glass"); it is absent from the abstract, and the full text returned 403. Use the real title, "Accountable Decryption Made Formal and Practical", and do not use the name or the break-glass motivation.
C3. **The Kroll et al. date is unsupported.** The Yale-hosted PDF is undated, has no venue, and its newest reference is 2016. The "2018 manuscript" in the review and PROJECT.md §4 cannot be confirmed from a primary page. Cite it as an undated manuscript. The author list in the review matches the PDF.
C4. **Kroll et al. gate on the log more strongly than the review's matrix says.** §2 says the auditor certifies the presence of log entries, and the other parties "do not allow the protocol to make progress without such certification". Treat it as full log-gated prior art, not only an auditor log.
C5. **The Cheval, Moreira & Ryan title.** The paper is "Automatic verification of transparency protocols". It verifies transparent decryption rather than introducing it; the primitive is attributed there to earlier work (e.g. Ryan 2017).
C6. **Ferreira et al. 2006 pages.** The University of Kent listing (seen via a search snippet) gives pp. 182–196. Crossref for DOI 10.1109/CBMS.2006.95 gives pp. 847–854, and Crossref is used.
C7. **LiBAC year and pages.** The review gives no year (only "IEEE TII 14(8)"). Crossref gives Aug. 2018, pp. 3610–3617.
C8. **Li et al. TPDS source.** The review quotes the ED-escrow mechanism while linking the SecureComm 2010 conference PDF. That is a different paper: authors Li, Yu, Ren, Lou (no Zheng), titled "Securing Personal Health Records in Cloud Computing: Patient-Centric and Fine-Grained Data Access Control in Multi-owner Settings", LNICST 50, pp. 89–106. The mechanism was confirmed there. The TPDS abstract confirms break-glass but its full text was not opened.
C9. **de Oliveira et al. 2020: corrections and confirmations.** The review's source [18] (attached to Zhang, Chow, Sun) and [12] (attached to de Oliveira) point at the wrong papers. The primary page confirms "different institutions", a game/simulation-based (not ProVerif) analysis, revocation by trusted MA/CSP token blocking without re-encryption, and no audit mechanism.
C10. **Larch.** The review's matrix row says "2-of-2 / t-of-n logs". Confirmed: a client-plus-log split secret, and trust split across multiple log providers for availability. A t-of-n threshold among logs was not specifically confirmed in what was read.
C11. **Muslim & Grégoire.** The arXiv abstract page does not mention audit, but the body (§5.1) does ("each override is auditable"). This is consistent with the review once the body is read.
C12. **Yang & Ma [33].** The review's link is an unrelated consortium-blockchain EHR paper. The DOI 10.1109/TIFS.2015.2509912 resolves (via Crossref) to the correct paper.

## Added by W1

23. Derived from the related-work matrix above: no row is marked ✓ for LG (release gated on a log entry) together with ✓ or ~ for LC (consent and revocation in one lifecycle). The LG ✓ rows (Kroll et al., Ryan, Cheval et al., Larch, Li et al. 2025) all have LC ✗; the LC ~ rows (de Oliveira 2019/2020, Li et al. 2013, Yang & Ma, Muslim & Grégoire, Romel et al.) have LG ✗ or ?. This matches ADR-0088's statement that "no prior work found applies it inside a consent/revocation/break-glass lifecycle for federated health records". — facts-F8 matrix rows; `docs/adr/0088-novelty-restated-as-combination.md:75-78` (Status: Proposed) (added by W1)
24. The novelty is stated as a combination, implemented (one signed key lifecycle; transparent-decryption-style log gating for federated break-glass with a mandatory audit share and an assertion check before commit; emergency-scoped search; test and wire evidence), and the paper never claims to be first to gate key release on logging. Where weaker: trusted plain hash chain with no proofs of presence or extension, and no formal model. — `docs/adr/0088-novelty-restated-as-combination.md:33-39` (Status: Proposed); `PROJECT.md:151-170` (added by W1)
25. Future work named in PROJECT.md §5: a Merkle log with proofs of presence and extension that the facility checks (item 13); a home authority that also logs, so break-glass does not depend on the audit service alone (item 8); epoch-versioned attribute keys (item 9); real CP-ABE (item 4); a unidirectional, decryption-free PRE, which needs pairings (item 10); client-side crypto in the key agent (item 11), each person's agent being their own device or enclave in a real deployment (item 5); keyed pseudonyms in the store and assertion (item 12); home-authority revocation, not wired in this build (item 1, ADR-0084). — PROJECT.md:335-429 (added by X1)
