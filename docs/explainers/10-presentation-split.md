# 10. Progress check: who talks about what

Split by the **module and task ownership** in `WORKFLOW.md`, so each person
presents the work they built, and balanced to about 6 minutes each. The
"graph communities" column comes from the graphify knowledge graph of the repo
(346 files, 3,408 nodes, 166 communities, built 2026-10-07), so you can open
`graphify-out/graph.html` and show your own cluster on screen.

Every topic links to the explainer file that covers it in plain language.

## Order of the talk

| Slot | Speaker | Topic | ~Min |
|---|---|---|---|
| 1 | Powel | Problem, idea, state machine, threshold gate | 6 |
| 2 | Ojas | Trust, audit log, log-before-release, deployment | 6 |
| 3 | Avaneeth | Records, assertions, API, patient side | 6 |
| 4 | Nandini | Search, discovery, clinician flow, wire analysis, benchmarks | 6 |
| 5 | Powel | Phase 5 status and the decisions we need | 3 |

---

## Powel: the idea and the state machine

**Own modules:** `crypto_core`, `shamir`, `policy`, `lifecycle`, `consent`,
`breakglass` gate, revocation (P1-1 to P1-3, P2-3, P3-1, P3-2, P3-5, P3-7).

1. The problem and the one-line idea: log first, then key (file 1).
2. The four-state key-lifecycle machine and its legal transitions (file 2).
3. Shamir 2-of-3 and how the emergency key is rebuilt (file 3).
4. Revocation by full key rotation, and why it is not a database flag (file 2).
5. The policy tree as our CP-ABE substitute, and consent as a gate (file 4).
6. Honest limits: forward-only revocation, not collusion-resistant.

Graph communities to show: *State Machine Tests, Lifecycle States, Policy Engine,
Policy Tree, Policy Compilation, Emergency Unlock Gate, Revocation
Tests, Consent Gate Tests, Shamir Exceptions*.
Demo slot: consent granted but `house` refused by the policy tree.

## Ojas: trust, audit and deployment

**Own modules:** `identity`, `authority`, `pre`, `audit`, deployment, admin
portal, notifications, threat model, security suite (P0-4, P1-5, P2-1, P2-2,
P3-3, P3-4, P3-13, P4-2, P4-3, P4-9, P4-10, P5-1).

1. How an out-of-network doctor is trusted: root anchor, facility CAs,
   cross-certification (file 9 §2).
2. Attribute authorities and attribute keys (file 4).
3. **The headline:** the audit hash chain and commit-before-release of share 3
   (files 3 and 5).
4. Proxy re-encryption: handing the key to another hospital without any server
   seeing it (file 5).
5. The seven-process deployment, bootstrap order and ports (files 0 and 9 §6).
6. The threat model: four separate attackers (`docs/threat-model.md`).
7. The negative security suite: what is proven and what is still red.

Graph communities: *Certificate Authority Chain, Federation PKI Bootstrap,
Attribute Issuance, Audit Chain Verification, Audit Event Logging, Audit Service
Schemas, Anti-Replay Stores, PRE Delivery Package, Break-glass Security Tests,
Admin Store Reader*.
Demo slot: the auditor view, chain PASS, and the trace of one emergency.

## Avaneeth: records, assertions and the patient side

**Own modules:** `records`, `storage`, `api` (hospital node), assertion and
replay protection, ingest, patient portal (P0-6, P0-8, P1-4, P2-6, P3-10 to
P3-12, P3-14, P4-1, P4-4, P4-7).

1. Envelope encryption: one key per record, wrapped to the policy (file 9 §3).
2. The shared store and schema: ciphertext only, never plaintext (file 1).
3. The Emergency Assertion: signed, bound, short-lived, single-use, and the new
   patient-binding check (file 3, ADR-0032, ADR-0044).
4. Replay protection and durable one-time ids (Phase 5 fix F22).
5. The hospital node API: thin, no cryptography in route handlers (file 9 §7).
6. Credential lifecycle and who may revoke (P2-6, P3-12).
7. The patient portal and patient self-access through the `owner:` attribute
   (file 4, ADR-0016).

Graph communities: *Record Ingest Pipeline, Record Encryption Errors, Hospital
Node API, Facility Node App, Postgres Repository, In-Memory Repository, Assertion
Validation, Emergency Assertion Signing, Request Envelope, Patient Portal Views,
Patient Directory*.
Demo slot: David reads his own record, and approves/revokes a grant.

## Nandini: search, discovery, clinician flow, evidence

**Own modules:** `search`, `federation`, `demo`, `wire`, `bench`, clinician
portal and identification (P2-4, P2-5, P3-8, P3-9, P4-5, P4-6, P4-8, P4-8a,
P5-2 to P5-5).

1. Federated discovery: finding a patient's records without holding them (file 5).
2. Emergency-only searchable encryption, and tokens that die at expiry (file 5).
3. Time-boxed expiry: the timer signs the closing and the record is re-keyed
   (file 3, ADR-0035).
3a. Re-keying the index on rotation (P3-9).
4. Emergency identification by name + date of birth, and why it releases no key
   (file 4, ADR-0033).
5. The clinician portal and the live break-glass walkthrough (file 8).
6. The required course module: Wireshark/PyShark traffic analysis and its four
   assertions (file 6).
7. Benchmarks (seven D4 metrics), search-leakage analysis and edge cases.

Graph communities: *Federated Discovery, Demo Driver, Clinician Portal Tests,
Traffic Capture Tests, Portal Flow Benchmarks, Live Test Servers, Explainer Docs*.
Demo slot: the full break-glass: identify, discover, declare, search, expiry.

## Closing slot (Powel, 3 min): where we are

From `docs/plans/phase5-exit-plan.md`:

| Exit criterion | Today |
|---|---|
| E1 security suite passes | 5 of 11 claims hold (C1, C2, C5, C8, C11); 6 are expected-fail against review findings |
| E2 every D4 benchmark metric | all 7 coded; committed numbers dated 2026-10-07/08, re-run on the demo machine before quoting |
| E3 edge cases | partial shares and replayed events done; clock skew awaits a decision |
| E4 PyShark on both captures | analyser built and tested on synthetic captures; not yet run on real ones; claim 1 waits on D6 |

Already merged to `main`: the Phase 5 branches (PR #37) and the full local
deployment (PR #38). Checked 2026-10-09 from a fresh Compose stack: 643 tests
pass (6 expected-fail), portal end-to-end 77 of 77, scenario 9 of 9 steps.

Decisions waiting on the team: D1 to D8, clock skew (CS), the F14 interim
allowlist and the capture path (F40). Phase 6 (paper and rehearsal)
follows.

---

## Rules for all four

- **Know the whole system, not only your part.** The viva asks anyone to walk
  through an emergency end to end (`PROJECT.md` §3). Read files 1 to 3 even if
  your slot is elsewhere.
- **Say the limits yourself.** File 7 lists them; mention the ones in your area.
- **Hand-offs:** end each slot with one sentence pointing to the next speaker's
  topic ("that audit commit is what Ojas will show next").
- **Where ownership drifted** (portal tasks "built by Ojas, owner to review"),
  say "the team built it" and be ready to explain it anyway.

## Answer-routing for questions

| If asked about | Best answerer |
|---|---|
| State machine, revocation, Shamir, policy tree, consent | Powel |
| PKI, attributes, PRE, audit chain, deployment, threat model | Ojas |
| Records, store, assertion, replay, API, patient portal | Avaneeth |
| Search, expiry, discovery, identification, wire analysis, benchmarks | Nandini |
