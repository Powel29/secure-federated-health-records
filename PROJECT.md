# PROJECT.md

Federated Break-Glass EHR with a Unified Key-Lifecycle State Machine
Information Security lab project (ICT 3121) — 4-person team, one semester.

---

## 1. Scope

We are building a cryptographically-enforced access control system for encrypted
electronic health records in which consent, revocation, and emergency
"break-glass" access are not three separate mechanisms but **one key-lifecycle
state machine** — Granted, Revoked, Emergency-open, Expired — where every
transition between states is a signed key-rotation event.

The headline novelty is that tamper-evident logging becomes a **cryptographic
precondition** of emergency access rather than a policy promise: break-glass
requires reconstructing an emergency key from a 2-of-3 Shamir threshold gate
(attending clinician + patient's home authority or federated delegate + audit
service), and the audit service releases its share only after it has committed a
hash-chained log entry. No log entry, no key, no access. A second contribution is
**emergency-only searchable encryption**: the capability to search encrypted
records is unlocked by entry into the Emergency-open state and dies when that
state expires.

All of this runs across a **simulated federation** of mock healthcare facilities
and attribute authorities, so that a record follows the patient rather than the
institution. The demo scenario is an unconscious patient arriving at an
out-of-network clinic: the clinician breaks glass using federation-level
threshold shares, emergency search locates the record across the federation,
access is time-boxed, and the emergency state auto-closes via forced key
rotation with no administrator action required.

Deliverables are a working simulation with benchmark results and a publishable
paper, plus a live demo. This is a **security project, not a health-informatics
project**: we model the federation cryptographically and do not implement real
healthcare interoperability standards.

---

## 2. Deliverables

| # | Deliverable | Form | Notes |
|---|---|---|---|
| D1 | Working implementation | Python repo, runnable end-to-end | Multi-process: facility nodes, authority services, audit service |
| D2 | Live demo | Scripted walkthrough of the cross-facility break-glass scenario | Must run from a clean clone; fallback recording required |
| D3 | Paper | Publishable write-up, IEEE-style | Design, security analysis, evaluation, honest limitations |
| D4 | Benchmark results | Tables + plots generated from the harness | Backs the evaluation section of D3. Covers revocation latency, threshold reconstruction, emergency-search latency, re-wrap cost, audit verification, cross-facility latency, and ciphertext expansion. **Scalability curves vs. #patients/#facilities were cut** to fund the demo dashboard — state this as a limitation rather than implying the runs were done |
| D5 | Test suite | pytest, including negative security tests | The negative tests are evidence for D3's claims |

**Deadline model:** no fixed calendar deadline. The team's stated intent is to
finish early. Work is therefore organised into **gated phases** — a phase ends
when its exit criteria are met, not on a date. See `WORKFLOW.md`.

---

## 3. Grading criteria

**STATUS: UNCONFIRMED — must be resolved in Phase 0 (task T06).**

Until faculty confirm, the plan optimises against this assumed weighting, which
is the common shape for a lab project of this type:

- Working implementation and demo — heaviest weight
- Novelty and correctness of the security argument
- Written report quality
- Viva / individual understanding of the whole system, not just one's own module

Two consequences follow from that last point and are treated as requirements
regardless of what the rubric turns out to be:

1. Every team member must be able to explain the full state machine and the
   threshold gate, not only the module they wrote. The gate reviews in
   `WORKFLOW.md` exist partly to enforce this.
2. The demo must survive a clean clone on a machine that is not the author's.

**Open items to take to faculty (task T06):**

- What is the actual weighting between code, report, and viva?
- Do they want standards-based interoperability (FHIR/HL7) or a cryptographic
  federation model? *We have defaulted to the cryptographic federation model —
  it is our lane and the source of our novelty. If faculty want FHIR, the scope
  changes materially and this plan must be revised before Phase 2.*
- Is there an interim review or milestone submission we should target?
- Is submission to an actual venue expected, or is the paper for internal
  assessment only?

---

## 4. Novelty claim

Existing work treats consent, revocation, and break-glass as separate
mechanisms, and treats audit logging as a bypassable policy-layer promise. No
prior work unifies them under a single key-lifecycle state machine, makes
logging a cryptographic precondition of break-glass, or provides search that
exists only within a time-boxed emergency state.

**Anchors we extend:**

- Li, Yu, Zheng, Ren, Lou. *Scalable and Secure Sharing of Personal Health
  Records in Cloud Computing Using Attribute-Based Encryption.* IEEE TPDS
  24(1):131–143, 2013.
- *An Extended Consent-Based Access Control Framework: Pre-Commit Validation and
  Emergency Access.* arXiv 2603.07004, 2026.

**Nearest rivals, to be cited honestly rather than ignored:**

- arXiv 2603.07004 — consent plus emergency override, but at the XACML policy
  layer, not cryptographic.
- arXiv 2511.17464 — already does revocation-as-key-rotation. Our delta is the
  unification with consent and break-glass, not rotation itself.

---

## 4A. Required security module (course requirement)

The Information Security Lab requires every project to **implement and
demonstrate** at least one module from the faculty-supplied list. Mentioning it
in the abstract or documentation is explicitly not sufficient.

**Selected: Module 7 — Traffic Analysis (Wireshark, PyShark).**

One module, implemented deeply. The requirement is "at least one relevant
module," and a single module carrying real evidence is a better answer than two
implemented adequately — a thin second claim invites scrutiny it cannot survive
and dilutes the strong one. Module 4 (PCAP to XML / SQLite) was considered and
dropped: at our capture scale pandas does the same analysis work with less
setup, and the benchmark harness is already pandas-based.

**Why this module and not another.** Our system is a five-process federation
communicating over a network. Traffic analysis is the only module on the list
that interrogates our own system's security properties rather than adding an
unrelated exercise. Every other option is either irrelevant to a cryptographic
EHR (WiFi cracking, USB forensics, Windows forensics, reverse engineering) or
reduces to attacking a target we built ourselves, which demonstrates little.

**Design decision that makes this module meaningful.** Inter-service traffic is
captured over **plain HTTP**, deliberately, in the capture configuration. This
demonstrates that confidentiality comes from our application-layer encryption
rather than from transport security. A capture with TLS enabled is run
separately to show defence in depth. Capturing only TLS traffic and observing
that it is encrypted would prove nothing about our contribution.

**What the captures must establish** — each maps to a claim made elsewhere in
this document:

1. **No plaintext on the wire** — no PHI, DEKs, attribute keys, or threshold
   shares in the clear during normal read, revocation, or break-glass.
2. **Commit-before-release is externally verifiable** — the audit service's
   share never appears on the wire before the log-commit response containing the
   new chain head. This is our headline contribution, demonstrated by an
   observer that does not trust our code.
3. **Searchable-encryption leakage profile, measured** — access pattern, query
   volume, and response-size leakage quantified from captures rather than
   asserted. Leakage *will* be found; that is a result, not a failure, and every
   honest SSE paper reports one.
4. **Break-glass is observable as metadata but not as content** — an observer
   learns that an emergency occurred and cannot obtain the emergency key.

**Deliverable standard.** The module is delivered as **PyShark analyser code in
the repository that asserts these properties automatically**, not as Wireshark
screenshots. An analyser that fails when plaintext appears, or when a share
precedes a commit, is a test; a screenshot is an anecdote.

**Ethical and legal constraint.** Captures are taken only on our own synthetic
federation, on loopback or the Docker bridge network. No capture on campus,
shared, or third-party networks under any circumstances, including for practice.

---

## 4B. External security review — disposition

An external AI-generated security review was obtained and assessed. It is a
competent generic application-security audit, but it grades this project against
a **production deployment** rubric that §6 of this document explicitly
disclaims. Roughly a third of its findings apply. This section records what was
adopted and what was rejected, so neither is re-litigated later.

### Adopted

| Finding | Where it landed |
|---|---|
| Emergency assertion undefined | T48 — signed, bound, expiring assertion (`ARCHITECTURE.md` §8) |
| Break-glass replay | T49 — one-time IDs + consumed-ID store |
| Revocation not bound to record ownership | T50 |
| Object-level authorization missing | T51 |
| Credential lifecycle incomplete | T52 |
| Service identity unspecified | T53 — signed service requests, **not** mTLS |
| `capture-plain` could become default | T54 — refuses to start without `ENVIRONMENT=LAB_CAPTURE` |
| PRE properties overclaimed | T42 — security-properties table marking PRE unproven |
| Threat model conflates adversaries | T04 — four adversaries modelled separately |
| Audit/wire correlation | T46 — request IDs |

The first two are the most valuable: break-glass is our headline contribution
and its trigger was genuinely undefined. The credential-lifecycle gap was an
internal inconsistency — a project about unified revocation should not issue
credentials that never expire.

### Rejected, with reasons

- **"Ready for Demo: NO" and the 7.0/10 rating.** Scored against production
  criteria this project explicitly excludes (§6). Category error, not a finding.
- **mTLS for all service-to-service traffic.** Conflicts with `capture-plain`,
  which is the evidence base for our required course module (§4A) — a collision
  the review did not notice. Signed service requests achieve authenticated
  service identity without encrypting the traffic we must analyse.
- **Rate limiting, CORS, security headers, API versioning, session management,
  MFA, brute-force protection, generic error pages.** No browser client, no
  public exposure, no user population. These would consume an estimated 60–80
  hours from the cryptographic core, which is the graded contribution and the
  publishable one.
- **Monitoring, alerting, anomaly detection, detection-and-response.** The ML
  anomaly-detection layer was cut deliberately; the reasoning stands unchanged
  in §6. **Do not re-add it on the strength of this review.**
- **Database encryption at rest, file permissions, backups, retention policy.**
  Record contents are already encrypted by design, so DB-level encryption is
  redundant for the data that matters; the remainder is production-operations
  scope per §6.

### Standing principle

The review's most useful contribution is a sentence worth keeping:
cryptographic authorization is not a substitute for endpoint authorization. Its
main risk is scope inversion — turning a cryptographic-contribution project into
an API-hardening exercise. Nothing in the API envelope is publishable. Adopted
items were chosen because they *strengthen* the state machine, break-glass, and
revocation story rather than adding subsystems beside it.

---

## 5. Honesty caveats

These go in the abstract and the limitations section, not buried. Claiming more
than this is the fastest way to lose credibility in the viva.

1. **Revocation is forward-only.** Re-wrapping the DEK denies future reads. It
   cannot retract plaintext a user has already decrypted and kept.
2. **Emergency expiry is server/HSM-enforced, not pure cryptography.** A
   compromised server could decline to expire an emergency key. We reduce, but
   do not eliminate, this: expiry is implemented as a *signed, logged* forced
   rotation, so subverting it is tamper-evident rather than silent.
3. **No single shareholder can open a record alone** — including the audit
   service. This is a property we claim and test, not an assumption.
4. **Our access-structure construction is not full CP-ABE.** We implement
   multi-authority attribute-based access via Shamir secret sharing over a
   policy tree (see `ARCHITECTURE.md`). It delivers policy-satisfaction-based
   decryption without per-user pre-provisioning, but it is **not
   collusion-resistant** in the way pairing-based CP-ABE is: two users could in
   principle pool attribute keys to satisfy a policy neither satisfies alone.
   This must be stated explicitly in the paper. Real CP-ABE is a stretch goal.

---

## 6. Explicitly out of scope

Do not re-open these without a team decision recorded in this file.

- **ML / anomaly-detection layer.** Cut by prior decision. Training on synthetic
  data is circular, it is bypassable, it adds attack surface, and hard rules
  cover most of what it would catch. **Do not re-add it as a security control.**
- **Real HIE / FHIR / HL7 interoperability.** We simulate the federation with
  2–3 mock facilities and cross-certification. Standards-based interoperability
  would make this a health-informatics project, not a security one.
- **Real HSM hardware.** The HSM/KMS timer is simulated by a trusted service
  process. Its trust assumptions are documented in the threat model.
- **Production deployment concerns** — high availability, horizontal scaling,
  container orchestration, real cloud hosting.
- **Real patient data.** Synthetic records only. No PHI, ever, under any
  circumstances.
- **A user-facing clinical UI.** The demo is a scripted CLI walkthrough. A GUI is
  not a deliverable and must not consume time that belongs to the crypto core.

## 7. Stretch goals

Not started until the Phase 5 gate passes. These are the first things to cut.

- Verifiable search (proof of no silent omission of results).
- Consent-aware search result filtering.
- Real pairing-based multi-authority CP-ABE replacing the secret-sharing
  access structure.
