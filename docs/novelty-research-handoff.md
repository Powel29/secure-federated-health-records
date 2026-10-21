# Handoff to Claude chat — deep novelty and publishability research

> **Done (2026-10-21).** The result is filed at
> `docs/review/2026-10-21-novelty-publishability-review.md`, and what it
> changed is ADR-0088. The beliefs stated below (e.g. that arXiv 2511.17464
> does revocation-as-key-rotation) are what we *asked* the reviewer to test.
> They aren't current positions.

> **How to use:** open a new Claude chat, turn on **Research** (web search),
> and paste everything below the line. It is self-contained; Claude chat has no
> access to our repo.

---

## Your task

You are acting as a skeptical senior reviewer and literature scout for an
applied-cryptography / security paper. Do a **deep online literature search**
and answer three questions with evidence:

1. **Is our problem statement unique?** Has anyone already framed the problem
   as "consent, revocation and emergency break-glass access to encrypted health
   records are one key-lifecycle problem, and audit logging should be a
   cryptographic precondition of emergency access rather than a policy promise"?
2. **Is our solution still novel as of today (October 2026)?** Check each
   atomic contribution below separately. A contribution can be fully novel,
   novel only as a combination, or already published.
3. **Can the final paper realistically be made publishable on novelty grounds?**
   If yes, at what tier of venue, with what reframing, and what is the minimum
   extra work a reviewer would demand. If no, say so plainly and tell us what
   the strongest honest contribution statement would be instead.

Be adversarial. We would much rather hear "this was done in 2019 by X" now than
from a reviewer. Do **not** fabricate citations: every prior work you name must
have a working link (DOI, arXiv, IACR ePrint, publisher page) that you actually
opened. If you suspect a relevant paper exists but cannot verify it, list it
under "unverified leads", separately.

---

## Project context

**Title (working):** Federated Break-Glass EHR with a Unified Key-Lifecycle
State Machine.

**Setting:** a one-semester, four-person Information Security lab project
(course ICT 3121) at an Indian university. The deliverables are a working
multi-process implementation, a live demo, benchmarks, a negative-security
test suite, and an IEEE-style paper written to a publishable standard. Faculty
said the paper is for internal assessment, but we want to know whether it can
go to a real venue.

This is a **security** project, not a health-informatics one. We model the
federation cryptographically and deliberately do **not** implement FHIR/HL7. An
ML anomaly-detection layer was also deliberately cut. Synthetic data only.

### The problem we claim

Existing systems for encrypted health records treat three things as separate
mechanisms:

- **consent / granting** access,
- **revocation**, and
- **emergency "break-glass"** access when the patient cannot consent
  (e.g. unconscious patient at an out-of-network hospital).

They also treat **audit logging as a policy-layer promise**: a server is
*supposed* to log a break-glass event, but nothing cryptographic stops access
if logging is skipped or fails. Our framing: break-glass without a guaranteed
audit trail is just a backdoor, and the guarantee should come from the key
material, not from the code path.

### Our solution, precisely

**1. One key-lifecycle state machine.** Every record is in one of four states:
`Granted`, `Revoked`, `Emergency-open`, `Expired`. There is a legal transition
table, and **every transition is a signed (ECDSA P-256) key-rotation event**
appended to the audit chain. Consent = wrap the record's data-encryption key
(DEK) to a policy; revocation = generate a new DEK, re-encrypt the record,
rebuild wrappings without the revoked party; break-glass = enter
`Emergency-open`; expiry = forced rotation back to baseline with no
administrator action.

**2. Logging as a cryptographic precondition of break-glass (headline claim).**
The emergency key is split with **2-of-3 Shamir secret sharing** over GF(p),
p a 256-bit prime. Shareholders: (1) the attending clinician's key agent, (2)
the patient's home authority or its federated delegate, (3) the **audit
service**. The audit service releases share 3 **only after** it has committed
a hash-chained entry `h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)` and
returns the new chain head with the share. If the log write fails, no share is
released and break-glass fails closed. "No log entry, no key, no access." No
single shareholder, including the audit service, can open a record alone.
Break-glass is triggered only by a signed, one-time, short-lived
`EmergencyAssertion` bound to patient, clinician and facility, with replay
protection.

**3. Emergency-only searchable encryption.** An encrypted inverted index over
record contents. Search tokens are derived via HKDF from the emergency key, so
the ability to search exists only while the record is `Emergency-open` and dies
when the time-box expires and the key is rotated.

**4. Cross-facility handoff.** An out-of-network clinician is validated through
a federated PKI with cross-certified facility CAs. The record key is re-wrapped
to them with a hand-rolled unidirectional ElGamal-style **proxy re-encryption**
so the proxy never sees plaintext.

**5. Multi-authority attribute-based access (CP-ABE substitute).** Policies are
AND/OR trees over attributes issued by independent authorities (e.g. medical
council issues `role:*`, hospital network issues `specialty:*`). AND nodes use
k-of-k Shamir splits, OR nodes copy the secret, leaves are encrypted to
attribute keys, root = DEK wrapping key. **Not collusion-resistant** (two users
can pool attribute keys); we say so. Real pairing-based CP-ABE was rejected for
install/schedule reasons and is future work.

**6. Traffic-analysis evidence (course requirement).** PyShark analysers
capture our own federation's inter-service traffic over **plain HTTP on
purpose** and assert automatically that: no PHI/keys/shares appear on the wire;
the audit share never appears before the log-commit response (an external,
code-independent check of commit-before-release); the searchable-encryption
leakage profile (access pattern, query volume, response size) is measured
rather than assumed; break-glass is visible as metadata but not content.

**Stack:** Python 3.11, pyca `cryptography` (AES-256-GCM, HKDF, ECDSA P-256,
X.509), hand-rolled Shamir and PRE, FastAPI services as separate processes
(store, two facilities, two attribute authorities, audit service, key
custodian), PostgreSQL as a semi-trusted ciphertext-only store, Django patient/
clinician/admin portals that identify users but never decide access.

### Prior work we already know about

- **Li, Yu, Zheng, Ren, Lou**, *Scalable and Secure Sharing of Personal Health
  Records in Cloud Computing Using Attribute-Based Encryption*, IEEE TPDS
  24(1):131–143, 2013. We extend this. Note: it already has some form of
  emergency/break-glass access — check exactly how, and how far our delta is
  from it.
- **arXiv 2603.07004** (2026), *An Extended Consent-Based Access Control
  Framework: Pre-Commit Validation and Emergency Access.* Our understanding:
  consent + emergency override at the XACML policy layer, not cryptographic.
  Verify this, and check whether its "pre-commit validation" overlaps with our
  commit-before-release idea.
- **arXiv 2511.17464** — our understanding is that it already does revocation
  as key rotation. We concede rotation itself is not ours; our claimed delta is
  unification with consent and break-glass. Verify what it actually claims.

Please confirm these three exist and summarise what they actually contribute.

### Honesty caveats we will state in the paper

1. Revocation is forward-only; already-decrypted plaintext cannot be retracted.
2. Emergency expiry is enforced by a trusted (simulated HSM) timer, not pure
   cryptography. We make subverting it tamper-evident (signed, logged
   rotation), not impossible.
3. The policy tree is not collusion-resistant CP-ABE.
4. In the demo, one shared Key Custodian process holds every synthetic
   person's keys (a real deployment would use per-user devices/enclaves). It
   holds only share 1, so the threshold property is unaffected.
5. Searchable encryption leaks access pattern and sizes; we measure it.
6. Synthetic data, simulated federation, simulated HSM; scalability curves
   vs. number of patients/facilities were not run.
7. No formal proofs yet. Evidence is a negative-security test suite (650
   tests) plus wire captures. Currently 5 of 11 system-level security claims
   hold end to end; 6 are known implementation gaps being fixed (e.g. the
   audit service does not yet verify the assertion before releasing share 3;
   expiry does not yet replace emergency shares on the deployed path).

---

## Atomic claims to test

Rate each **Novel / Novel only as a combination / Partially anticipated /
Already published**, name the closest prior work, and explain the delta in one
or two sentences.

- **N1.** Consent, revocation and break-glass modelled as one key-lifecycle
  state machine in which every transition is a signed key-rotation event.
- **N2.** Audit logging as a *cryptographic precondition* of emergency access:
  the logger is a threshold shareholder that releases its share only after a
  hash-chain commit.
- **N3.** Searchable encryption whose search capability is derived from, and
  scoped to, a time-boxed emergency state.
- **N4.** Automatic emergency close-out via forced rotation with no admin action.
- **N5.** Cross-facility break-glass combining federated PKI cross-certification,
  threshold emergency key, and PRE handoff.
- **N6.** Wire-level traffic analysis used as externally verifiable evidence of
  a commit-before-release property.
- **N7.** The problem framing itself (break-glass as a key-lifecycle problem;
  logging as precondition rather than promise).

---

## Search guidance

Search widely; do not stop at the first match. Cover 2008–2026, including
2025–2026 arXiv and IACR ePrint preprints.

**Sources:** IEEE Xplore, ACM DL, Springer, Elsevier/ScienceDirect, arXiv
(cs.CR), IACR ePrint, Google Scholar, Semantic Scholar, DBLP, PubMed (for
medical-informatics venues such as JAMIA, JBI, IEEE JBHI), USENIX, NDSS.

**Search themes (combine and vary terms):**

- break-glass / break-the-glass / emergency access + encrypted EHR / PHR,
  attribute-based encryption, threshold cryptography, secret sharing
- emergency access + proxy re-encryption; emergency key escrow for health data
- **accountable decryption**, **auditable decryption**, "decryption only after
  logging", accountable key escrow, transparency logs gating key release, key
  transparency, "log-then-decrypt", witness/notary-gated decryption
- **blockchain / smart-contract break-glass EHR** — these are likely the
  strongest rivals to N2, because an on-chain transaction can be a
  precondition of key release. Look hard here and explain whether a blockchain
  log gating a key is equivalent to our design or materially different
- time-bound / time-limited / temporary keyword search, revocable searchable
  encryption, searchable encryption with expiring trapdoors, emergency
  searchable encryption for health records
- key-lifecycle state machines (e.g. NIST SP 800-57 key states) applied to
  access control or consent; dynamic consent with cryptographic enforcement;
  revocable ABE with key update; consent-as-encryption
- federated / multi-authority ABE for cross-hospital access; cross-domain
  emergency access; health information exchange + encryption
- break-glass models in access control (policy-level work such as break-glass
  extensions to RBAC/XACML) — to establish what the "policy promise" baseline
  is that we argue against

Also check whether any **surveys** of break-glass or emergency access in
e-health (recent ones especially) already list a scheme like ours.

---

## Publishability assessment

Given the above, assess honestly:

- **Which contributions survive** the literature check, and is what survives
  enough for a paper on its own?
- **Venue tier:** for each realistic target (top-tier security conference,
  second-tier security conference, security workshop, applied/health security
  journal, IEEE Access–style journal, student/regional conference), say whether
  it is realistic, and name 2–3 specific venues per tier that fit the topic.
  Note typical page limits and whether they expect formal proofs.
- **What reviewers would attack:** e.g. no formal security definitions or
  proofs, hand-rolled crypto (Shamir, PRE), non-collusion-resistant ABE
  substitute, trusted timer, single custodian, synthetic evaluation, missing
  scalability results, the 6 failing system-level claims.
- **Minimum work to become publishable** at the best realistic tier, ordered by
  impact per effort. Consider: formal model and proof sketch of
  commit-before-release (e.g. game-based definition, or Tamarin/ProVerif
  model), a related-work comparison table, closing the failing claims,
  scalability benchmarks, replacing the ABE substitute with real CP-ABE.
- **Reframing:** if the novelty is mainly in the combination, propose a
  sharper contribution statement and title that a reviewer would accept.

---

## Output format

1. **Executive verdict** (5–8 lines): is the problem unique, is the solution
   novel, is it publishable, and at what tier. Give a confidence level.
2. **Verification of our three known references** (exists? what it really
   claims? overlap with us?).
3. **Claim-by-claim table** for N1–N7: rating, closest prior work (with link),
   year, venue, delta, confidence.
4. **Related-work comparison matrix:** rows = the 8–15 most relevant prior
   schemes; columns = cryptographic enforcement (vs policy), break-glass,
   revocation, consent, unified lifecycle, logging gates key release, threshold
   emergency key, time-boxed search, multi-authority/federated, PRE, formal
   proof, implementation/benchmarks. Put our system as the last row.
5. **Biggest threats to novelty** — the 3 papers a reviewer is most likely to
   cite against us, and how we should position against each.
6. **Publishability:** venue recommendations by tier, expected reviewer
   objections, and the prioritised minimum-work list.
7. **Suggested contribution statement and title** for the paper.
8. **Unverified leads** (could not confirm) and **search log** (main queries
   and databases you used), so we can repeat or extend the search.

Use full citations (authors, title, venue, year) plus a link for every source.
