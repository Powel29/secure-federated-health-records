# 10. Progress check: who talks about what

Split by the **module and task ownership** in `WORKFLOW.md`, so each person
presents the work they built, and balanced to about 6 minutes each. The
"graph communities" column comes from the graphify knowledge graph of the repo
(built 2026-10-07; rebuild it with `/graphify` if you want a fresh view), so you can open
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
3. Weighted Shamir 3-of-4 and how the emergency key is rebuilt: audit holds two shares, so every opening needs it (file 3).
4. Revocation (and expiry) by full key rotation, and why it is not a database flag (file 2).
5. The policy tree as our CP-ABE substitute, and consent as a read-time grant that is *not* a lifecycle state (file 4).
6. Honest limits: forward-only revocation, not collusion-resistant, trusted timer.

Graph communities to show: *State Machine Tests, Lifecycle States, Policy Engine,
Policy Tree, Policy Compilation, Emergency Unlock Gate, Revocation
Tests, Consent Gate Tests, Shamir Exceptions*.
Demo slot: consent granted but `house` refused by the policy tree.

## Ojas: trust, audit and deployment

**Own modules:** `identity`, `authority`, `pre`, `audit`, deployment, admin
portal, notifications, threat model, security suite (P0-4, P1-5, P2-1, P2-2,
P3-3, P3-4, P3-13, P4-2, P4-3, P4-9, P4-10, P5-1). The paper's **trusted-parties**
paragraph (audit service, custodian, timer, PKI root) is yours to explain.

1. How an out-of-network doctor is trusted: root anchor, facility CAs,
   cross-certification (file 9 §2).
2. Attribute authorities and attribute keys (file 4).
3. **The headline:** the audit hash chain and commit-before-release of shares 3
   and 4 (files 3 and 5); the 1.35 ms wire proof (file 6).
4. Key delivery: the facility unwraps the DEK and delivers it by KEM; the PRE is
   bidirectional and unused (file 5, limitation 10).
5. The deployment, bootstrap order and ports (files 0 and 9 §6).
6. The threat model: four separate adversaries plus four trusted parties (file 16).
7. The negative security suite: C1 to C11 all hold; what the mutation evidence does
   and does not show (file 17).

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
3. The Emergency Assertion: signed, bound, short-lived (≤ 15 min), single-use, validated
   independently by facility, audit service and home authority; plus the patient-binding
   check (file 3, ADR-0032, ADR-0044).
4. Replay protection and durable one-time ids (claim C8).
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
3. Time-boxed expiry: the timer signs the closing, runs a full rotation, and the record
   returns to the state it was claimed from (files 2 and 3, ADR-0035/0058/0069).
3a. Re-keying the index on rotation (P3-9).
4. Emergency identification by name + date of birth, and why it releases no key
   (file 4, ADR-0033).
5. The clinician portal and the live break-glass walkthrough (file 8).
6. The required course module: PyShark traffic analysis, run on real plain and TLS
   captures; the wire-checks table (file 6).
7. Benchmarks (seven metrics, n=30), ciphertext expansion, search-leakage numbers
   (files 6 and 17).

Graph communities: *Federated Discovery, Demo Driver, Clinician Portal Tests,
Traffic Capture Tests, Portal Flow Benchmarks, Live Test Servers, Explainer Docs*.
Demo slot: the full break-glass: identify, discover, declare, search, expiry.

## Closing slot (Powel, 3 min): where we are

Numbers are the paper's (commit `57a1a8c`, live run 2026-10-21):

| Evidence | Today |
|---|---|
| Security claims | **All 11 hold** (C1 to C11): 35 of 35 system-level tests pass, none skipped; 18 module-level tests |
| Full test suite (against Postgres) | **1006 passed, 2 skipped (by design), 0 failed** |
| Mutation check | 18 mutations cover C1 to C10, C11 uses a positive control; the post-3-of-4 run is in prose only, so we do not claim every current claim test is shown to go red |
| Benchmarks | Seven metrics, n = 30 after 5 warm-ups; in-process ops under 0.25 ms median; HTTP paths ~240 to 250 ms, indicative only |
| PyShark traffic analysis | Run on real plain and TLS captures; all checks pass; COMMIT 1.35 ms before release; 0 of 13 canaries under TLS |
| Paper | Drafted and built (10 pages, IEEEtran) |

What is not done: demo rehearsal (twice) and the recorded fallback video (Phase 6).
Say the 13 limitations yourselves (file 7); say that scaling runs were cut.

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
