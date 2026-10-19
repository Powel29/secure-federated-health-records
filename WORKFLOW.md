# WORKFLOW.md

Sequencing, ownership, and process. Scope is in `PROJECT.md`; the dependency map
this plan derives from is in `ARCHITECTURE.md` §4; code rules are in
`CONVENTIONS.md`.

**No calendar dates.** The team intends to finish early, so phases are **gated**:
a phase ends when its exit criteria are met, not on a date. Hour estimates exist
to balance workload across four people, not to predict a date.

**Ownership model (as directed):**

- **Powel** — initial setup, the hard cryptographic concepts, and break-glass.
- **Nandini** — everything search-related, plus the evaluation that measures it.
- **Ojas** — the trust machinery: audit chain, proxy re-encryption, services,
  security testing.
- **Avaneeth** — the data plane and the federation's identity layer.

---

## 1. Phased plan

### Phase 0 — Setup and architecture decisions
Freeze the interfaces so four people can build in parallel, and resolve the two
open faculty questions before they can invalidate work.

**Exit criteria:** repo scaffolded, CI green on an empty suite; `src/contracts/`
frozen and reviewed by all four; threat model written; faculty answers on
grading and FHIR-vs-crypto recorded in `PROJECT.md`; the crypto spike proves
AES-GCM, ECDSA, HKDF and a toy ElGamal PRE run in pure Python on **all four**
machines. The PostgreSQL schema exists (P0-8).

### Parallel track — Portal shells (ADR-0021)
Runs alongside Phases 1–4; **does not gate Phase 0** and must not consume the
crypto critical path. All three Django portals start now as shells; graded
features still complete on the Phase-4 schedule as their backends land. Governing
invariant: *a portal account alone grants zero access* — credentials are issued
by an authority (P2-2), never by a signup form.

**PS-1 · Django scaffold + portal tests in CI** *(done)* — Nandini — 3h
*What:* `portal/` Django project, Bootstrap base, DB config (portal schema +
read-only `store` alias), CI step running the portal tests on SQLite.
*Done when:* `manage.py check` clean and the portal test job is green. ✅

**PS-2 · Self-service registration (request-then-issue)** *(done)* — Nandini — 4h
*What:* Patient and clinician registration creating a login + PENDING request; the
`issue_credential` step is stubbed (authority issues, P2-2). Includes the
invariant test (*signup issues no credential*).
*Done when:* both flows create pending requests and no signup issues a credential. ✅

**PS-3 · Patient portal shell** *(shell done)* — Avaneeth (owns future wiring) — 4h
*What:* Patient pages (enrollment status, upload → ingest stub, access history).
*Done when:* pages render; upload reaches the `ingest_upload` stub. ✅ *(shell built
+ verified at the Django layer; future ingest wiring stays off Avaneeth's P2
critical path)*

**PS-4 · Clinician portal shell** *(done)* — Nandini — 4h
*What:* Clinician pages (credential status, request-access + break-glass → stubs).
*Done when:* pages render; actions reach their stubs with clear messages. ✅

**PS-5 · Admin/audit portal (read-only over store)** *(done)* — Ojas — 4h
*What:* Read the P0-8 store read-only (records, audit chain, lifecycle); list
pending registration requests; approve → `issue_credential` stub.
*Done when:* real store rows render read-only; approve reaches the issue stub. ✅
*(verified against live Postgres: seeded record + audit entry render read-only,
and a `portal_ro` write is denied by the database — the wall holds)*

**PS-6 · Two-role DB + Django schema wiring** *(done)* — Avaneeth — 2h
*What:* `portal` schema + `portal_ro` read-only role (`portal/sql/roles.sql`),
Django `DATABASES`/router so the ORM never writes the store.
*Done when:* Django writes only the `portal` schema; the `store` alias is SELECT-only. ✅

**PS-later (Phase 2–3)** — wire `issue_credential` → `authority` (P2-2); wire
`ingest_upload`/request-access/break-glass → their backends (P3-14, P3, P3-5).

**PS-future (stretch)** — Drive-style virtual department folders & heuristic
auto-sorting in the patient and clinician portals. Records organised into
departmental folders (Cardiology, Radiology, Pathology, General, Emergency)
mapped to attribute-policy scopes (`dept:cardiology`, `dept:radiology`,
`emergency:breakglass`). See `PROJECT.md` §7 and `portal/README.md`.

---

### Phase 1 — Crypto and data foundations
Build the primitives everything else calls, plus storage.

**Exit criteria:** `crypto_core` and `shamir` fully tested against known-answer
vectors; PRE round-trips a ciphertext; a record encrypts, stores, retrieves, and
decrypts; the `policy` stub returns deterministic fakes so downstream work is
never blocked.

### Phase 2 — Federation and policy
Make cross-institution access possible at all.

**Exit criteria:** an out-of-network clinician's certificate validates against
the root anchor via cross-certification; two independent authorities issue
attribute credentials; a clinician satisfying a policy tree reconstructs the DEK
and one who does not, fails; federated discovery locates a patient's records
from a facility that does not hold them.

### Phase 3 — State machine and the four contributions
The novelty. This phase makes or breaks the paper.

**Exit criteria:** all four states reachable and every illegal transition
rejected; every transition emits a verifiable signed event; **break-glass
requires a valid signed Emergency Assertion and a replayed assertion is
rejected**; revocation re-wraps
and the revoked user provably loses read access; **break-glass fails closed when
the audit service cannot commit its log entry**; emergency search works in
Emergency-open and is dead after expiry; expiry auto-closes via forced rotation
with no administrator action.

### Phase 4 — Integration and deployment
Make it one federated system rather than eight libraries.

**Exit criteria:** all five processes run and talk to each other under both
deployment paths (`ARCHITECTURE.md` §7); the full cross-facility break-glass
scenario runs end to end **from a clean clone on a machine that is not the
author's**.

### Phase 5 — Testing and hardening
Turn claims into evidence.

**Exit criteria:** the full negative security suite in `tests/security/` passes;
the benchmark harness produces every metric in `PROJECT.md` D4; edge cases
(clock skew, partial shares, replayed transition events) handled and tested;
**the PyShark analysers run against captures from both profiles and all four
wire-level assertions in `PROJECT.md` §4A pass.**

*Status (2026-10-19):* every criterion is met on the author machine. 11/11
claims hold and the mutation check exits 0 (`docs/review/p5-1-evidence.md`);
`bench.run_benchmarks` produces all seven D4 metrics; the three edge cases are
handled and tested; `wire.analyze_traffic` exits 0 on fresh plain and TLS
captures, with claim 1 scoped to TLS (ADR-0073). **The gate is not yet
passed:** it needs the same commands to succeed from a clean clone on a
non-author machine (`docs/plans/phase5-exit-plan.md`, Stage 4). Stretch goals
still wait for that.

### Phase 6 — Paper and demo
**Exit criteria:** full draft reviewed by all four; every claim traceable to a
passing test or a benchmark number; demo rehearsed twice with a fallback
recording captured; every member can explain the whole system, not only their
own module.

**Stretch goals** (`PROJECT.md` §7) may not start until the Phase 5 gate passes.
These include verifiable search, consent-aware filtering, real CP-ABE, and
Drive-style department virtual folders with auto-sorting (PS-future).

---

## 2. Build Order

Plain language, no dependency-tracing required.

### MUST BE DONE BEFORE ANYTHING ELSE CAN START

All five are Powel's, which is deliberate — setup and the foundational concepts
are one coherent block, and splitting them across people costs more in
coordination than it saves in hours.

1. **Interface contracts (`src/contracts/`).** The shared schemas — `Record`,
   `DEKWrapping`, `TransitionEvent`, `AuditEntry`, `AttributeCredential`,
   `Facility`, `PolicyTree`. *Why:* this is the single thing that lets four
   people write modules that call each other before those modules exist. Without
   it, everyone waits for everyone. Highest-leverage hours in the project.

2. **`crypto_core`.** AES-256-GCM, HKDF, ECDSA, SHA-256. *Why:* every module
   calls primitives through it and `CONVENTIONS.md` forbids bypassing it.
   Nothing real gets built until it exists.

3. **`shamir`.** *Why:* required in two independent places — the break-glass
   threshold gate and the policy tree's AND-nodes. It blocks both the headline
   contribution and cross-institution access simultaneously.

4. **The two faculty questions** (grading weights; crypto-federation vs FHIR).
   *Why:* a FHIR answer invalidates the entire federation design before Phase 2.
   Costs one conversation. Ask on day one.

5. **Crypto install spike on all four machines.** *Why:* discovering in Phase 3
   that a teammate cannot run the stack is a schedule catastrophe. Ten minutes
   of prevention. (Owned by Avaneeth so it runs *concurrently* with Powel's
   contract work rather than behind it.)

### CAN BE BUILT IN PARALLEL once the above is done

**Powel — hard concepts and break-glass**
- `policy`: the access structure engine (AND/OR tree over Shamir)
- `lifecycle`: states, legal transitions, signed transition events
- Consent / grant path
- **Emergency Assertion Protocol** and replay protection (the trigger for
  break-glass — without it, "clinician asserts an emergency" is undefined)
- `breakglass`: the 2-of-3 threshold gate
- Time-boxed emergency key, auto-close, forced rotation
- Paper: system design and state-machine formalism

**Nandini — search, end to end**
- `search`: encrypted inverted index over ciphertext
- Emergency-only search tokens (derived from the emergency key)
- Search-index re-keying when a DEK rotates
- Leakage-profile analysis for the index
- `federation`: patient-indexed discovery (the search that finds the record)
- PyShark analysers + measured leakage profile (**required course module**)
- Benchmark harness and all evaluation numbers
- Paper: implementation and evaluation

**Ojas — trust machinery**
- `audit`: hash chain, signing, full-chain verification
- Share custody: commit-before-release
- Audit events for denials and federation operations
- `pre`: proxy re-encryption (one-direction re-wrap to the emergency clinician)
- Audit and authority service processes
- Containerisation, both deployment paths, and the capture profiles
- Traffic capture harness (**required course module**)
- Negative security test suite
- Paper: security analysis and limitations

**Avaneeth — data plane and identity**
- `storage`: schema and repositories
- `records`: envelope encryption, DEK wrapping, **record ingest path**
- `identity`: root anchor, facility CAs, cross-certification
- Credential lifecycle: serial, validity window, revocation status
- `authority`: multi-authority attribute issuance
- Revocation-as-key-rotation (re-wrap)
- Facility node API, demo driver, seed data
- Paper: introduction, problem, gap, related work

**Real sequencing constraints inside the parallel work:**
- Powel's `shamir` gates his own `policy` **and** his `breakglass` — it is the
  first thing he writes after contracts.
- Avaneeth's `identity` gates his own `authority`, which gates Powel's `policy`.
  So Avaneeth's Phase 2 work is on Powel's critical path — it is not optional
  background work.
- Nandini's search tokens depend on Powel's emergency key existing. Until then
  she builds the index against a **fixed test key**, then swaps to the real
  derivation. She must not sit idle waiting for Phase 3.
- Ojas's `audit` share custody gates Powel's `breakglass`.

### CANNOT START UNTIL LATE, regardless of who is free
- Emergency-only search tokens — need the emergency key, which needs break-glass,
  which needs the state machine and the audit service.
- Benchmarks — need working modules to measure.
- The paper's evaluation section — needs benchmark numbers.

---

## 3. Task list

Every task below has the same shape:

**ID · Title** — Owner — estimated hours
*What:* what you're actually building, in plain words.
*Needs first:* which tasks must be done before this one can start.
*Done when:* how you know it's finished.

IDs are `P<phase>-<n>` — so `P3-5` is the fifth task of Phase 3. The old
T-numbers are noted in brackets for anyone mid-task; they will disappear once
everyone has switched over.

---

### Phase 0 — Setup and architecture decisions

**P0-1 · Set up the repo** *(was P0-1)* — Powel — 3h ✅
*What:* Create the project skeleton — folders, virtual environment, pinned dependency versions — so everyone starts from the same base.
*Needs first:* nothing.
*Done when:* `pip install -r requirements.txt` works on all four laptops and the folders match the layout in ARCHITECTURE §6.

**P0-2 · Freeze the shared data shapes** *(was P0-2)* — Powel — 7h ✅
*What:* Agree and lock the core data structures everyone shares — Record, key-wrapping, transition event, audit entry, credential, facility, policy tree, plus the emergency-assertion and request-envelope shapes. Once frozen, these only change by a PR all four approve.
*Needs first:* P0-1.
*Done when:* all the shapes are defined, type-hinted, and signed off by all four.

**P0-3 · Get answers from faculty** *(was P0-3)* — Powel — 2h ✅
*What:* Ask the two questions that could change the whole plan: how it's graded, and whether they want the cryptography approach or the FHIR/standards approach. *(Done — crypto lane confirmed, report = 10 marks.)*
*Needs first:* nothing.
*Done when:* answers are written into PROJECT §3. (Complete.)

**P0-4 · Write the threat model** *(was P0-4)* — Ojas — 8h ✅
*What:* Describe who the attackers are and what each could do — treating the shared store, a hacked hospital node, a rogue authority, and colluding doctors as four *separate* threats with different consequences.
*Needs first:* nothing.
*Done when:* `docs/threat-model.md` covers all four attacker types distinctly.

**P0-5 · Set up automated checks (CI)** *(was P0-5)* — Nandini — 4h ✅
*What:* Make every pull request automatically run the tests and style checks, so broken or messy code can't be merged.
*Needs first:* P0-1.
*Done when:* CI runs on every PR and blocks merging if anything fails.

**P0-6 · Crypto sanity check on every machine** *(was P0-6)* — Avaneeth — 5h ✅
*What:* Prove the core crypto tools (AES, signatures, key-derivation, a toy proxy re-encryption) actually run in plain Python on all four laptops — before anyone builds on them.
*Needs first:* nothing.
*Done when:* a throwaway test script runs cleanly on all four machines; findings noted in an ADR.

**P0-7 · Map out the pretend federation** *(was P0-7)* — Powel — 4h ✅
*What:* Decide the make-believe setup — two hospitals (matching ARCHITECTURE §7; reconciled from "three" per ADR-0019), two attribute authorities, one shared trust root — and which authority hands out which attributes.
*Needs first:* nothing.
*Done when:* a topology diagram and the attribute-ownership list are in `docs/` (`docs/federation-topology.md`, ADR-0019). ✅

**P0-8 · Build the database schema** *(was P0-8)* — Avaneeth — 8h ✅
*What:* Create the **PostgreSQL** database structure — all the tables the system needs. Postgres holds only ciphertext, wrapped keys, and coded index — it **stores** data but never **decides** access; keys and the threshold gate do that (ADR-0014).
*Needs first:* P0-2.
*Done when:* all tables exist per ARCHITECTURE §2, basic read/write is tested, and there's a migration script.


---

### Phase 1 — Crypto and data foundations

**P1-1 · Core crypto: encryption + hashing** *(was P1-1)* — Powel — 6h ✅
*What:* The central toolbox everyone else calls for AES-256-GCM encryption, key-derivation, and SHA-256. No other module is allowed to touch raw crypto directly.
*Needs first:* P0-2.
*Done when:* known-answer test vectors pass, a fresh nonce is used every time, and nothing else imports raw crypto.

**P1-2 · Core crypto: signatures** *(was P1-2)* — Powel — 5h ✅
*What:* Add signing and verifying (ECDSA) to the toolbox, plus saving/loading keys.
*Needs first:* P1-1.
*Done when:* sign-then-verify works and a tampered message fails verification.

**P1-3 · Secret sharing (Shamir)** *(was P1-3)* — Powel — 8h ✅
*What:* Split a secret into three shares where any two rebuild it and any one reveals nothing. Used by both break-glass and the policy engine.
*Needs first:* P0-2.
*Done when:* any 2 of 3 shares reconstruct the secret, 1 gives nothing, tested over many random secrets.

**P1-4 · Record encryption + key wrapping** *(was P1-4)* — Avaneeth — 8h ✅
*What:* Give each record its own encryption key, encrypt the record, and wrap that key for whoever's allowed to read it.
*Needs first:* P1-1, P0-8.
*Done when:* encrypt → store → retrieve → decrypt round-trips, with exactly one key per record.

**P1-5 · Proxy re-encryption** *(was P1-5)* — Ojas — 7h ✅
*What:* A tool to re-wrap a record's key to a new person (the emergency doctor) without ever decrypting it. One direction only — no hospital-to-hospital handoff, since everything lives in one store now.
*Needs first:* P1-1.
*Done when:* a key can be re-wrapped to a new recipient and the tool provably never sees plaintext.

**P1-6 · Policy engine stub** *(was P1-6)* — Powel — 2h ✅
*What:* A fake stand-in for the access-policy engine that returns predictable answers, so other people can build against it before the real one exists.
*Needs first:* P0-2.
*Done when:* other modules can call the real interface and get sensible fake results.


---

### Phase 2 — Federation and policy

**P2-1 · Identity and cross-certification** *(was P2-1)* — Ojas *(swapped from Avaneeth, ADR-0025)* — 12h ✅
*What:* Build the trust setup — a root authority, per-hospital certificate authorities, and cross-certification so an out-of-network doctor can be verified.
*Needs first:* P1-2, P0-8.
*Done when:* an out-of-network doctor's certificate validates back to the shared root, and a forged one is rejected. ✅ *(`src/identity/`: `root_anchor.py`, `certificates.py`, `chain.py`, `trust_registry.py`; see ADR-0024 for the single-root cross-certification design; negative tests in `tests/security/test_phase2_security.py`.)*

**P2-2 · Attribute issuing** *(was P2-2)* — Ojas *(swapped from Avaneeth, ADR-0025)* — 8h ✅
*What:* Let the authorities hand out signed "attribute" credentials (like role:doctor, specialty:cardiology) that the policy engine checks. **A patient's home authority also issues that patient their own `owner:<patient_id>` attribute** (ADR-0016), which is what lets a patient self-decrypt their records; it follows the same credential lifecycle (validity window, revocation status) as any other attribute.
*Needs first:* P2-1.
*Done when:* two independent authorities issue valid credentials and a forged credential is rejected; a patient's home authority can issue an `owner:<patient_id>` attribute credential. ✅ *(`src/authority/`: `issuance.py`, `certification.py`; live revocation registry deferred to P2-6 per the module's docstring; negative tests in `tests/security/test_phase2_security.py`.)*

**P2-3 · The real policy engine** *(was P2-3)* — Powel — 12h ✅
*What:* Replace the stub with the real thing: an AND/OR policy tree that lets someone unlock a record only if their attributes satisfy the policy. In standard terms this is the **Policy Decision Point (PDP)**; the check that enforces it in front of the record/key services is the **Policy Enforcement Point (PEP)**. This is our stand-in for full attribute-based encryption. **Policy-authoring convention (ADR-0016):** every record's tree is authored with a root-level `OR` whose branches are the clinical policy and an `owner:<patient_id>` leaf, so the patient can always reconstruct their own record via the same path. This is a convention on how trees are built, not a schema change — the `Attribute`/`PolicyTree` contracts already express it.
*Needs first:* P1-3, P2-2.
*Done when:* a doctor whose attributes satisfy the policy unlocks the record, one who doesn't is refused, a patient holding only their `owner` attribute unlocks their own record, and it drops in without changing any code that called the stub. ✅ *(`src/policy/engine.py`: Shamir over attribute keys per ADR-0026; `evaluate_policy` (PDP) kept from the stub, `reconstruct_root_secret`/`unwrap_dek_via_policy` (PEP) added; `author_policy_with_owner` stamps the ADR-0016 owner leaf; negative tests in `tests/security/test_phase2_policy.py`. Attribute-key material is issued by `authority` (`attribute_key` / `get_attribute_key`, completing P2-2's §8-C6 half) and consumed end-to-end in `tests/policy/test_authority_integration.py` — that `authority` edit is a cross-owner change flagged for Ojas's review per ADR-0026.)*

**P2-4 · Find a patient's records** *(was P2-4)* — Nandini — 8h ✅
*What:* Given a patient, locate their encrypted records in the shared store — without the store or the asking hospital learning what's inside.
*Needs first:* P0-8, P2-1.
*Done when:* one hospital can find a patient's records in the shared store by patient index, learning nothing about contents. ✅ *(`src/storage/repositories.py`: `find_record_ids_by_patient`; negative security tests in `tests/security/test_phase2_discovery.py`.)*

**P2-5 · Searchable encrypted index** *(was P2-5)* — Nandini — 12h ✅
*What:* Build the coded index that lets someone search records without the server ever seeing the search words or the contents. Built against a fixed test key until break-glass exists.
*Needs first:* P1-4.
*Done when:* the index is searchable but the server learns no plaintext words. ✅ *(`src/search/service.py`: `derive_search_token`, `index_search_term`, `search_records`; see ADR-0027; tests in `tests/search/test_service.py` and `tests/security/test_phase2_search.py`.)*

**P2-6 · Credential lifecycle** *(was P2-6)* — Avaneeth — 6h ✅
*What:* Give every credential a serial number, a validity window, and a status — so credentials can expire and be revoked. (A project about revocation shouldn't issue credentials that never expire.)
*Needs first:* P2-1, P2-2.
*Done when:* expired or revoked credentials are rejected at check time. ✅ *(`src/authority/`: `revocation.py`, `issuance.py`, `exceptions.py`; see ADR-0028; unit tests in `tests/authority/test_lifecycle.py` and negative security tests in `tests/security/test_phase2_lifecycle.py`.)*

---

### Phase 3 — The state machine and the core contributions

**P3-1 · The state machine** *(was P3-1)* — Powel — 12h ✅
*What:* The heart of the project — the four states (Granted, Revoked, Emergency-open, Expired) and the signed events for every legal move between them. Illegal moves are refused.
*Needs first:* P1-2, P1-4.
*Done when:* all four states work, illegal transitions are rejected, and every transition produces a verifiable signed event. ✅ *(`src/lifecycle/`: `state_machine.py`, `exceptions.py`; six legal transitions per ADR-0030, seven since ADR-0058; unit tests in `tests/lifecycle/test_state_machine.py`; negative security tests in `tests/security/test_phase3_security.py` cover illegal transitions, invalid signatures, field tampering, missing reason code, state mismatch, and event-id replay.)*

**P3-2 · Patient consent + granting access** *(was P3-2)* — Powel — 8h ✅
*What:* The full consent path. The patient issues a **signed, scoped, expiring grant** — naming the hospital, the clinician/role, the purpose, the records, and the time window — via a request-then-approve flow (hospital requests, patient approves or denies). Only the patient can create or revoke it. The grant then wraps the record's key to a policy so the approved doctor can read it. This makes "the patient grants access" a real, defined action, not an assumption.
*Needs first:* P3-1, P2-3.
*Done when:* a patient-issued grant is signed and scoped; an approved doctor reads within scope; an unauthorized one can't; and only the patient can revoke it. ✅ *(`src/consent/`: `service.py`, `exceptions.py`; consent is a read-time gate over the already-wrapped record per ADR-0031; revocation is a fresh patient-signed grant with `status=REVOKED`; unit tests in `tests/consent/test_consent.py`; end-to-end + negative security tests in `tests/security/test_phase3_consent_security.py` cover approved read, unauthorized doctor denied, out-of-scope denied, expired/denied/revoked denied, forged signature denied, non-patient revocation denied.)*

**P3-3 · The tamper-proof audit log** *(was P3-3)* — Ojas — 10h ✅
*What:* A hash-chained, signed log where each entry locks in the one before it, so tampering is detectable.
*Needs first:* P1-2, P0-8.
*Done when:* the full chain verifies and any tampered entry is caught. ✅
*(`src/audit/chain.py`: `create_genesis_entry`, `append_entry`, `verify_chain`,
`verify_full_chain` per the ARCHITECTURE §2 C10 formula; see ADR-0034 for the
canonical-encoding and full-entry-signing decisions; unit tests in
`tests/audit/test_chain.py`; negative tests in
`tests/security/test_phase3_audit_security.py` cover tampered event_data,
a broken prev_hash link, and a replayed chain position.)*

**P3-4 · Log-before-release (the headline)** *(was P3-4)* — Ojas — 8h ✅
*What:* Make the audit service hand over its emergency key-share *only after* it has committed the log entry. No log, no share — this is what makes logging a hard precondition of emergency access.
*Needs first:* P3-3, P1-3.
*Done when:* the share is released only after the log commits, and a failed log-write means no share (proven by a negative test). ✅
*(`src/audit/share_custody.py`: `release_share_after_commit` wraps
`audit.chain.append_entry` in a psycopg3 savepoint (`conn.transaction()`) and
only returns the caller's share once it has released; any failure raises
`AuditCommitFailedError` before the share is ever constructed as a return
value — see ADR-0034 for why a real cross-connection race was not used for
the negative test. Negative test:
`tests/security/test_phase3_audit_security.py::test_breakglass_share_not_released_when_log_commit_fails`;
positive control: `test_share_released_only_after_successful_commit`.)*

**P3-5 · Break-glass emergency access** *(was P3-5)* — Powel — 14h ✅
*What:* The emergency unlock. Three parties each hold a share (doctor, patient's home authority, audit service); any two rebuild the emergency key. One share alone is never enough — not even the audit service's. On unlock, the record key is re-wrapped to the emergency doctor without decrypting it in the open.
*Needs first:* P3-4, P3-1, P2-2, P1-5.
*Done when:* two shares unlock, one fails, the audit service alone can't open a record, and the doctor gets a usable key that was never exposed.

**P3-6 · Time-boxed access + auto-expiry** *(was P3-6)* — Powel — 10h ✅
*What:* Make emergency access expire on its own after a set time, closing via a forced key-rotation that needs no admin action. The timer length is adjustable (short for demos, realistic for the paper).
*Needs first:* P3-5.
*Done when:* emergency access expires with no admin action, and the expiry is itself a signed, logged event.

**P3-7 · Revocation by key-rotation** *(was P3-7)* — Powel *(taken from Avaneeth)* — 8h ✅
*What:* Taking access away — rotate the record's key and rebuild the wrappings so a revoked user can't read future versions.
*Needs first:* P3-1, P1-4.
*Done when:* after revocation the revoked user cannot decrypt (proven by a negative test).

**P3-8 · Emergency-only search** *(was P3-8)* — Nandini — 10h ✅
*What:* Wire search so it only works during emergency access — the search key is derived from the emergency key, so it dies when the emergency expires.
*Needs first:* P2-5, P3-6.
*Done when:* search works while emergency access is open and stops working once it expires (negative test).

**P3-9 · Re-key the search index on rotation** *(was P3-9)* — Nandini — 8h ✅
*What:* When a record's key rotates (revocation or expiry), rebuild its search index so old search keys stop working.
*Needs first:* P2-5, P3-7.
*Done when:* after rotation, stale search keys match nothing and no plaintext leaks during re-indexing.

**P3-9a · Post-merge cleanup: ingest negative tests + federation move + hazmat aliases** *(new)* — Nandini — 5h ✅
*What:* Consolidated code-only fixes on already-merged Phase-3 work:
- Add `tests/security/test_phase3_ingest_security.py` proving `records/ingest.py` fails closed on: missing owner leaf on the policy tree (ADR-0016 invariant), `search_terms` provided without an `emergency_key`, wrong `owner_authority_id`, and tampered-plaintext / cross-record-DEK-reuse attempts. Closes the biggest negative-test gap on the tree — P3-14 shipped with happy-path tests only.
- Move `find_record_ids_by_patient` from `src/storage/repositories.py` to a new `src/federation/discovery.py` so C13 lives in the module ARCHITECTURE.md §2 assigns it to; update call sites; re-export from `src/federation/__init__.py`.
- Add `src/crypto_core/types.py` exporting `ECPrivateKey` / `ECPublicKey` aliases, then swap the 7 non-`crypto_core` files off direct `cryptography.hazmat` imports: `src/breakglass/{assertion,envelopes}.py`, `src/consent/service.py`, `src/lifecycle/state_machine.py`, `src/authority/issuance.py`, `src/identity/{certificates,root_anchor}.py`. Enforces the CLAUDE.md "no direct hazmat outside `crypto_core`" rule without a carve-out ADR.
- Fix ADR mis-citation in `src/contracts/audit.py:31,42` (0014 → 0017).
*Needs first:* P3-1, P3-2, P3-10, P3-14 (all done). Independent of P3-8 and P3-9, so it can run in parallel with them or immediately after.
*Done when:* the new negative tests pass; no direct `cryptography.hazmat` imports outside `src/crypto_core/` (verified by grep); federated discovery lives under `src/federation/`; ruff, black, and full pytest are green.

**P3-10 · Emergency assertion** *(was P3-10)* — Avaneeth *(taken from Powel)* — 6h ✅
*What:* Define what "declaring an emergency" actually is — a signed statement binding the patient, doctor, hospital, time, reason, and an expiry. Break-glass won't start without a valid one.
*Needs first:* P3-1, P2-1.
*Done when:* unsigned or unbound assertions are rejected and break-glass refuses to proceed without one. ✅ *(`src/breakglass/`: `assertion.py`, `exceptions.py`; five-point validation sequence per ARCHITECTURE §8 and ADR-0032; unit tests in `tests/breakglass/test_assertion.py`; negative security tests in `tests/security/test_phase3_assertion_security.py` cover field tampering, untrusted cert, clinician mismatch, facility mismatch, expiry, and replay.)*

**P3-11 · Replay protection** *(was P3-11)* — Avaneeth *(taken from Powel)* — 3h ✅
*What:* Give emergency requests, share requests, and transition events one-time IDs so a captured request can't be replayed for repeat access.
*Needs first:* P3-10.
*Done when:* a replayed request is rejected, not re-run. ✅ *(`src/breakglass/`: `replay.py` (thread-safe `ConsumedAssertionIds`, `ConsumedRequestIds`), `envelopes.py` (signed `RequestEnvelope` creation and verification with recipient binding); ADR-0032; unit tests in `tests/breakglass/test_replay.py` and `tests/breakglass/test_envelopes.py`; negative security tests in `tests/security/test_phase3_assertion_security.py` cover replay rejection and the ordering invariant that forged messages cannot burn legitimate IDs.)*

**P3-12 · Check who's allowed to revoke** *(was P3-12)* — Avaneeth — 3h ✅
*What:* Make sure a revocation actually comes from the record's owner (patient) or its home authority — a valid signature from the wrong person isn't enough.
*Needs first:* P3-7.
*Done when:* a correctly-signed but unauthorized revocation is rejected. ✅ *(`records.revocation.check_revocation_authorization` enforces patient owner or home authority check at step 0 of `revoke_record_access`; `UnauthorizedRevocationError` in `records.exceptions`; ADR-0037; unit tests in `tests/records/test_revocation.py`; negative security tests in `tests/security/test_phase3_revocation_security.py` prove correctly-signed requests from unauthorized clinicians or foreign authorities fail closed).*

**P3-13 · Log denials and federation events** *(was P3-13)* — Ojas — 3h ✅
*What:* Record access-denials and federation actions (policy checks, discovery, re-wraps) in the audit chain — identifiers and hashes only, never key material. This is what makes the admin portal's denial view possible.
*Needs first:* P3-3.
*Done when:* denials and federation events appear in the chain with no sensitive data leaked. ✅ *(`src/audit/events.py`: `log_access_denied`, `log_federation_discovery` (hashed `patient_id` at the time; since ADR-0085 it logs `patient_id` like every other event, because a hash of an enumerable id hid nothing), `log_federation_rewrap` — fixed-shape wrappers over `audit.chain.append_entry`, deliberately not call-site edits into `policy`/`consent`/`authority`/`records`/`breakglass`/`federation` per one-owner-per-module and those modules' own "caller logs" design; ADR-0038; unit tests in `tests/audit/test_events.py`; negative security tests in `tests/security/test_phase3_denial_federation_audit_security.py` drive real denials from `policy`, `consent`, and `records.revocation`, and real federation discovery/re-wrap results, into the chain and prove no attribute key, DEK or signature is ever persisted (the raw-`patient_id` check was replaced by an exact-field-set check, ADR-0085) — plus a structural test that `append_entry` itself refuses raw key bytes in `event_data` before anything is written.)*

**P3-14 · Record upload path** *(was P3-14)* — Avaneeth — 4h ✅
*What:* The ingest flow — a submitted record gets its keys minted, gets encrypted, gets indexed, gets a policy attached, and gets logged. **The policy attached at ingest carries the `owner:<patient_id>` OR-leaf** (ADR-0016 convention from P2-3) so every record is patient-readable from the moment it is created — this must be baked in here, not retrofitted in Phase 4.
*Needs first:* P1-5, P2-5.
*Done when:* uploading a record produces an encrypted, indexed, policy-attached record (with the owner leaf present) and a log entry.

---

### Phase 4 — Integration and deployment

**P4-1 · Hospital node service (API)** *(was P4-1)* — Avaneeth — 10h ✅
*What:* The web service for a hospital — endpoints for read, grant, revoke, break-glass, and search. No crypto in the route handlers; it just orchestrates.
*Needs first:* P3-2, P3-7, P3-5.
*Done when:* all endpoints work and no cryptography lives in a route handler. ✅ *(`src/api/`: `hospital.py` FastAPI app factory `create_hospital_app`, `schemas.py`, `repository.py` StorageRepository Protocol with InMemory and Postgres adapters; endpoints for read, consent, revoke, break-glass, discovery, search, emergency search, and ingest; AST-based negative invariant tests in `tests/api/test_no_crypto_invariant.py` prove 0 direct crypto imports or cipher calls; 26 tests in `tests/api/`).*

**P4-2 · Audit + authority services** *(was P4-2)* — Ojas — 8h ✅
*What:* Run the audit service and the authorities as their own separate processes that the hospitals talk to over HTTP.
*Needs first:* P3-3, P2-2.
*Done when:* they run as separate processes and a hospital can talk to them. ✅ *(`src/api/audit_service.py`: standalone Audit Service — `GET /health`, `/public-key`, `/chain/head`, `/chain/verify`, `POST /entries`, and the break-glass share-custody pair `POST /breakglass/shares` / `POST /breakglass/release` that makes ARCHITECTURE.md §7's "log-before-release must be a real process boundary" concrete over HTTP; `src/audit/share_registry.py` backs it. `src/api/authority_service.py`: standalone Attribute Authority Service — issuance, verification, revocation, credential-status, and both the holder-facing (`/attribute-keys/release`) and authoring-side (`/attribute-keys/author`) attribute-key paths. `src/api/audit_client.py` closes the ADR-0035 seam by wiring `lifecycle.expiry.EmergencyExpiryManager`'s `audit_logger` callback to the standalone service over HTTP. Also resolves ADR-0034's documented concurrent-`seq` liveness gap with a process-local lock. See ADR-0039. Tests: `tests/api/test_audit_service.py`, `tests/api/test_authority_service.py`, `tests/api/test_audit_client.py`.)*

**P4-3 · Deployment + bootstrap** *(was P4-3)* — Ojas — 12h ✅
*What:* Two ways to run the whole federation — a local launcher script and Docker Compose — plus the startup sequence that brings everything up in the right order. Includes the plain-HTTP capture mode for traffic analysis.
*Needs first:* P4-1, P4-2.
*Done when:* both run methods work, startup happens in order, and the audit chain verifies at boot or nothing starts. ✅ *(`deploy/`: `bootstrap.py` (the reusable bootstrap-sequence library — PKI generation, authority registration, the audit-chain hard boot precondition), `run_local.py` (Path A, no Docker required), `compose_bootstrap.py` + `docker-compose.yml` + `Dockerfile` (Path B), `entrypoint.py` + `asgi/{facility,authority,audit}.py` (one shared entrypoint dispatching on `SERVICE_ROLE`, used identically by both paths). Inter-service traffic is plain HTTP by default, which is the `capture-plain` profile PROJECT.md §4A's traffic-analysis module needs — TLS (`capture-tls`) is P4-6's addition. See ADR-0039. Tests: `tests/deploy/test_bootstrap.py` (PKI/root-chaining and authority-registration round trip against real sockets, plus the audit-chain check, skips cleanly without Postgres).)*

**P4-4 · Full end-to-end run** *(was P4-4)* — Avaneeth — 10h ✅
*What:* Wire the whole cross-hospital break-glass story together so it runs start to finish across all the processes.
*Needs first:* P4-1, P4-2, P3-8.
*Done when:* the full scenario runs from a clean clone across all processes. ✅ *(`deploy/run_scenario.py`: standalone runner for the complete 9-step cross-hospital break-glass scenario start to finish across all 5 federation processes plus the shared store. `tests/deploy/test_end_to_end.py`: automated test suite running against real ephemeral OS sockets covering the 9-step scenario against in-memory stores, emergency expiry with forced key rotation, and the full scenario against real PostgreSQL container storage with schema migrations and foreign keys. Wired `src/api/hospital.py` route handlers (`_log_denial`, `_log_discovery`, `_log_rewrap`) to the standalone Audit Service over HTTP via `api.audit_client.append_entry` with fallback for isolated unit tests, closing the remaining audit delegation seam from ADR-0039. Extended `src/records/ingest.py` with automatic emergency DEK wrapping generation, keeping `src/api/` completely free of cipher primitives (zero AST violations). See ADR-0040. Tests: `tests/deploy/test_end_to_end.py` [3 passed], `tests/api/test_no_crypto_invariant.py` [2 passed], full suite `tests/` [488 passed]).*

**P4-5 · Demo driver + fake data** *(was P4-5)* — Nandini — 8h ✅
*What:* A one-command script that seeds realistic fake patient data and runs the demo scenario with readable output. No real patient data, ever.
*Needs first:* P4-4.
*Done when:* one command seeds and runs the scenario with clear output. ✅ *(`demo/seed_data.py`: realistic synthetic clinical dataset generator with 3 patient profiles [Alice Vance / STEMI, David Miller / Diabetes, Emma Hartwell / Polytrauma] and clinicians across Node A and Node B, establishing 2-of-3 Shamir splits, Share 3 audit escrow, blind HKDF search tokens, and ADR-0016 owner leaves; zero real PHI [PROJECT.md §5]. `demo/driver.py`: examiner-ready 8-Act demonstration runner formatted with ANSI styling, box headers, live visual countdown timer, dead-token post-expiry verification, genesis-to-head SHA-256 audit chain verification, and standalone in-process ephemeral socket server launcher. `demo/__main__.py` and `demo/run_demo.py`: unified CLI entrypoints [`python -m demo`, `python -m demo.run_demo`]. See ADR-0041. Tests: `tests/demo/test_demo.py` [5 passed], full suite `tests/` [493 passed]).*

**P4-6 · Traffic capture setup** *(was P4-6)* — Nandini — 6h ✅
*What:* The capture harness and the two modes (plain-HTTP and TLS) that record network traffic for the required traffic-analysis module.
*Needs first:* P4-3.
*Done when:* both modes produce a capture file per scenario.
*Done (2026-10-15):* both modes captured on Windows (Wireshark 4.6.9, Npcap 1.88, the Npcap loopback adapter) against `deploy/run_local.py` with Postgres on loopback: `plain.pcap` 592 packets, `tls.pcap` 686 packets, and all nine scenario steps passed in each. Since ADR-0066 every request also carries signed `X-Request-Envelope` / `X-Service-Certificate` headers; bodies are unchanged, so the analyser's checks apply as written. Two things the run needs on Windows: start the federation with `SEED_DATA=false` (the seeded `rec-001` collides with the scenario's own ingest, 409), and set `PYTHONIOENCODING=utf-8` (the scenario prints `✓`, which a redirected cp1252 stdout cannot encode). Pcaps and `*.canaries.json` stay in the git-ignored `wire/captures/`.

**P4-7 · Patient portal (web UI)** *(new — replaces dashboard)* — Avaneeth — 10h ✅ *(built by Ojas with the other portal tasks; Avaneeth to review)*
*What:* The patient's web page (Django + Bootstrap): see who has access to their records, approve or deny incoming access requests, revoke a grant, and view the history of who accessed what — including any break-glass. **Also view their own uploaded records:** the patient reads a record via the `owner:<patient_id>` attribute leaf on the record's policy tree (ADR-0016), served by the home authority; the decrypted PDF is streamed to the browser for that request only, never persisted or logged. This is the patient half of the three-portal UI that replaces the old terminal dashboard.
*Needs first:* P4-1, P3-2, P3-13; owner-attribute issuance in `authority` (ADR-0016).
*Done when:* a patient can approve/deny/revoke and see their access history in the browser; a patient can open and view their own record, decrypted through the policy path (not by portal login alone) and failing closed if the owner attribute is absent; the portal never decrypts on its own and never becomes the access authority (keys still gate access). ✅ *(`portal/patient/`: overview with alerts + break-glass banner, access control & consent (approve/deny/revoke signed by the Key Custodian as the patient and verified+stored by the facility), access history straight from the hash chain with break-glass rows badged, encrypted-records list and a one-request owner-leaf view (`Cache-Control: no-store`, never persisted) that fails closed with the facility's reason. The portal imports nothing from `src/` and holds no key — ADR-0043. **Patients can also upload their own records:** `patient:upload` hands the bytes to the custodian's `POST /subjects/{id}/records`, which mints and 2-of-3-splits the emergency key (share 3 to the audit service, share 1 to clinician custody), fetches the authoring keys for the chosen clinical preset (`portal_core/policies.py`) plus the owner key, and calls the facility's P3-14 `/records/ingest`; refused before any service call if the patient holds no owner credential. Tests: `portal/patient/tests.py` [15], incl. login-without-owner-attribute → 403 and no plaintext; `tests/api/test_custodian_service.py` covers upload → owner read → policy read → break-glass on the uploaded record.)*

**P4-8 · Clinician portal (web UI)** *(new — replaces dashboard)* — Nandini — 10h ✅ *(built by Ojas; Nandini to review)*
*What:* The clinician's web page: request access to a patient's records, see what's currently granted, run a search during an emergency, and declare break-glass with a justification. Shows the live countdown on active emergency access.
*Needs first:* P4-1, P3-5, P3-8.
*Done when:* a clinician can request, search-when-emergency, and declare break-glass from the browser; denied actions show clear reasons; the portal holds no keys. ✅ *(`portal/clinician/`: credentials read back from the custodian, consent requests (custodian-signed) and consent-gated reads, federated discovery, break-glass declaration bound to the identified `patient_id` under the lookup's correlation id, live countdown + three-share panel + chain segment on the session page, emergency search with the dead-token state after expiry; denials render the upstream reason verbatim. Tests: `portal/clinician/tests.py` [12].)*

**P4-8a · Emergency patient identification (name + DOB search)** *(new — ADR-0033)* — Nandini — 4h ✅ *(built by Ojas; Nandini to review)*
*What:* The identification step that produces the `patient_id` a break-glass declaration is bound to. Add a `PatientDirectory` model in the portal Postgres (given_name, family_name, date_of_birth, subject_id — subject_id is the same string as the crypto-side `patient_id`; no mapping table). Add a search view in the clinician portal: enter name and DOB, see candidate matches, select one, and the break-glass form on P4-8 receives the resolved `patient_id`. Ambiguous matches (multiple rows with the same name and DOB) are all shown — never auto-selected. Every lookup, hit or miss, is written to the audit chain as a `patient.lookup` event.
*Needs first:* P4-8 shell, P3-10 (assertion contract), P3-13 (audit event types — Ojas adds `patient.lookup`).
*Done when:* a clinician can search by name and DOB, pick from a candidate list, and the resolved `patient_id` is carried into a signed `EmergencyAssertion`; ambiguous matches show all candidates; PII lives only in the portal DB and never in the crypto store (ADR-0011 / ADR-0033); the search view holds no keys and grants no access on its own (a negative test proves that portal login without a valid assertion decrypts nothing); every lookup — including empty ones — appears in the audit chain. ✅ *(`accounts.PatientDirectory` (given_name, family_name, date_of_birth, subject_id = crypto `patient_id`), `clinician:identify` + `select_candidate` views; ambiguous matches all shown and never auto-selected (the seed adds a namesake `pat-777` to prove it); every lookup and every selection appended as `patient.lookup` (hashed query, candidate ids only) *before* results are shown — if the append fails the results are withheld (503). `audit.events.EVENT_PATIENT_LOOKUP` added. Negative tests: selection outside the candidate set is refused; a login without a signed assertion decrypts nothing.)*

**P4-9 · Admin / audit portal (web UI)** *(new — replaces dashboard)* — Ojas — 8h ✅
*What:* The oversight web page: browse the audit log by correlation ID, view the state of the federation and its services, and review completed break-glass cases. Read-only over the audit and state data.
*Needs first:* P4-2, P3-3, P3-13.
*Done when:* an admin can pull up a whole access flow by correlation ID and review break-glass cases in the browser; the portal is read-only and holds no keys. ✅ *(`portal/admin_audit/`: overview with chain length + genesis-to-head verification from the audit service, trace any flow by correlation id with per-link `prev_hash` check and the joined case/consent/notification rows, break-glass case review derived from the chain and the ledger (failed-closed attempts included), federation process health + store contents + trust topology, registrations (approval still reaches only the ADR-0021 stub). Read-only throughout; no POST changes access. Tests: `portal/admin_audit/tests.py` [5].)*

**P4-10 · Patient notifications** *(new)* — Ojas — 4h ✅
*What:* Alert the patient when their records are accessed under break-glass and when a grant is revoked. A notification event is emitted and surfaced in the patient portal (and logged in the audit chain).
*Needs first:* P3-5, P3-7, P3-13.
*Done when:* break-glass and revocation each produce a patient notification, visible in the patient portal and recorded in the audit log. ✅ *(`portal_core/notify.py` + `ledger.PatientNotification`: break-glass, revocation and incoming consent requests each create a notification row and append a `patient.notification` entry (identifiers only) to the chain; `audit_seq` is stored on the row, and a row the chain could not record is shown as "not yet in chain" rather than hidden. Surfaced as the alerts card on the patient overview with links to the access-history row. `audit.events.EVENT_PATIENT_NOTIFICATION` added. Tests in `portal/patient/tests.py` and `portal/clinician/tests.py`.)*


---

### Phase 5 — Testing and hardening

**P5-1 · Security test suite** *(was P5-1)* — Ojas — 15h ✅ *(Ojas to review)*
*What:* The eleven "attack fails" tests — each proves a security claim by showing the system refuses. These are the evidence for the paper. Includes the **patient-self-access fail-closed test** (ADR-0016): a logged-in patient is refused decryption when the `owner:<patient_id>` attribute is absent, proving portal login alone never releases a DEK.
*Needs first:* P4-4.
*Done when:* all eleven negative tests pass and each maps to a specific paper claim.
*Progress (2026-10-07):* implemented by Powel; Ojas (owner) to review (ADR-0046). All eleven claims are tagged (`@pytest.mark.claim`) with module- and system-level tests; `python -m tests.security.claims --table` prints the claim table and `python -m tests.security.mutations` shows each holding test going red with its control off. **Today: 5 hold (C1, C2, C5, C8, C11), 6 fail at system level** as strict xfails against review findings — C3 (F2/D1), C4 (F9/D3), C6 (F11/D7), C7 (D8), C9 (F34/D5), C10 (F14). C8 flipped 2026-10-08 with the F22 fix (durable consumed ids). P5-1 closes as those fixes land and the markers come off. Evidence and open items: `docs/review/p5-1-evidence.md` (C2/C5 mutation rows still need a Postgres run).
*Re-verified (2026-10-19):* claim table and mutation check re-run with Postgres; 11/11 hold, every C1–C10 test goes red under at least one of 18 mutations (C1c and C10b added since 2026-10-15), C11 has a positive control. `docs/review/p5-1-evidence.md` regenerated.
*Done (2026-10-15):* **all eleven claims hold at system level; no xfails remain.** C6 and C10 flipped with the review fixes before this; C3 (ADR-0067, the audit service validates the assertion), C4 (ADR-0069, full rotation at expiry), C7 (ADR-0068, clinician-signed transition) and C9 (ADR-0066, signed service requests, keyless reads refused before storage) flip here. `python -m tests.security.mutations` with Postgres exits 0: every claim-tagged test goes red under at least one mutation of its control, none decorative (new mutations C3b, C4b, C9a, C9b).

**P5-2 · Benchmark harness** *(was P5-2)* — Nandini — 12h ✅ *(Nandini to review)*
*What:* Measure and plot performance — timings, ciphertext expansion — reproducibly from one command.
*Needs first:* P4-4.
*Done when:* every benchmark number is produced and reproducible from one command.
*Done (2026-10-15):* `DATABASE_URL=... python -m bench.run_benchmarks` runs again: the break-glass step had broken on PR #40's justification rule; it now sends the justification bound into the signed assertion and the clinician-signed transition (ADR-0068), and signs every request (ADR-0066). `bench/results/` is regenerated. **Caveat for the paper:** this run is native Windows, where the HTTP benchmarks measure ~170 ms; `main`'s own code measures the same here, so that is the machine, not signing (the previous results, ~15 ms, came from WSL). Regenerate on the paper's reference machine before quoting latencies.
*Re-run (2026-10-19):* on current code (30 iterations, 5 warm-up, Postgres, Python 3.11), native Windows on a different machine (AMD, 16 cores; `environment.json`). The HTTP benchmarks now measure ~50 ms median (cross-facility 49 ms, emergency search 51 ms), so the earlier ~170 ms was that machine, as suspected. The reference-machine caveat above still applies.

**P5-3 · Search leakage analysis** *(was P5-3)* — Nandini — 6h ✅ *(Nandini to review)*
*What:* Measure exactly what the server can infer from search traffic (access patterns, frequency, volume) — from real captures, not argument.
*Needs first:* P3-8, P3-9, P5-5.
*Done when:* the measured leakage is quantified for the paper.
*Progress (2026-10-15):* first run on the P4-6 captures, `bench/results/p53_search_leakage.json`. Plain: the search URI and the matched record (`rec-001`) are visible, response size 43 bytes, the query keyword itself not in the clear. TLS: no search URI observable. **Not done:** the scenario issues a single search, so frequency and timing leakage cannot be measured; it needs a capture of a multi-search workload (repeated and distinct keywords, and one search either side of an expiry). ADR-0069 adds one fact to measure there: every expiry re-derives a record's whole search index under a new key, so tokens from different emergencies of the same record no longer match each other.
*Measured (2026-10-15, proposal by Powel for Nandini's review, ADR-0070):* `python -m wire.capture --mode {plain,tls} --search-workload` captures 16 searches across two emergency sessions with an expiry between them. `python -m wire.analyze_search_leakage` now also reads the database link and the TLS record sizes. Results are in `bench/results/p53_search_leakage{,_tls}.json`, written up in `bench/results/p53_search_leakage.md`. Plain: every query term in the clear; hit/miss responses 43 B / 34 B. TLS: hit/miss response body records still 60 B / 51 B, and the request record gives the term's length exactly. Both profiles: the facility↔Postgres link is plaintext, so the token frequency (5, 2, 2, 1, …), all 15 tokens and their row counts are visible. Re-keying holds: all 3 terms searched in both sessions got new tokens after expiry. No hit/miss timing signal at n = 15. Also fixed: tshark 4.6's hex `file_data` had made every body read as unreadable. Open: Postgres TLS and size padding are not implemented (deployment decision, Avaneeth).
*Store link (2026-10-15, proposal by Powel for Avaneeth's decision, ADR-0071):* the TLS profile now runs the store link under `sslmode=verify-full` (Compose and Path A, via `deploy/store-entrypoint.sh`); the plain profile is unchanged. A new TLS capture shows 4/4 store connections on TLS and 0 readable token lookups, so tokens, row counts and the token frequency histogram are gone from the wire. What remains over TLS, measured against the workload's search manifest: hit / miss / refused response bodies 60 / 51 / 112 B, and every request body is the term length + 63 B, so frequency is visible per term length (70 B ×9, 71 B ×3, …). Still open: size padding.
*Done (2026-10-19):* re-measured on fresh plain and TLS search-workload captures of current code; the leakage profile is unchanged (same sizes, same frequency histogram, all three re-searched terms re-keyed across the expiry), and `bench/results/p53_search_leakage{,_tls}.json` and `.md` are regenerated. The leakage is quantified, which is what "done" asks; size padding is not implemented and is reported as the residual leak (`p53_search_leakage.md`), not left as an open task.

**P5-4 · Edge cases** *(was P5-4)* — Nandini — 5h ✅
*What:* Handle the awkward cases — clock skew, missing shares, malformed input — and test them.
*Needs first:* P4-4.
*Done when:* each case is handled and tested.
*Open (2026-10-07):* missing and malformed shares are handled and tested (`tests/breakglass/test_gate.py::TestOpenEmergencyAccessEdgeCases`). **Clock skew is not.** `breakglass.validate_emergency_assertion` rejects an expired assertion but accepts one whose `issued_at` is in the future, so a fast clinician clock silently extends the assertion's effective lifetime. Proposed fix: reject `issued_at > now + MAX_CLOCK_SKEW` (about 2 minutes) with a negative test. That adds a check ARCHITECTURE.md §8 does not specify, so it needs an ADR, and Powel (`breakglass` owner) has deferred the decision. P5-4 — and the Phase 5 gate — stays open until it is either implemented or recorded as out of scope with a reason.
*Done (2026-10-15):* clock skew was closed by ADR-0049/0056: an assertion whose `issued_at` is more than `ASSERTION_CLOCK_SKEW` (30 s) ahead, or whose lifetime exceeds `MAX_ASSERTION_TTL`, is refused (`tests/security/test_phase3_assertion_security.py::...::test_future_dated_assertion_rejected` and the lifetime tests beside it). Service requests (ADR-0066) and clinician-signed transitions (ADR-0068) apply the same bounds (`tests/api/test_service_auth.py::test_an_old_envelope_is_refused`).

**P5-5 · Traffic analysis (PyShark)** *(was P5-5)* — Nandini — 13h ✅ *(Nandini to review)*
*What:* Code that reads the captured traffic and automatically checks the wire-level claims — no plaintext leaks, no share released before its log entry, break-glass visible only as metadata. This is the required course module, delivered as code not screenshots.
*Needs first:* P4-6, P4-4.
*Done when:* all four wire-level checks run and pass automatically.
*Progress (2026-10-07):* implemented by Powel (handover from Nandini to be confirmed), ADR-0045. `wire/checks.py` asserts all four claims over reassembled captures against the scenario's canary manifest; `python -m wire.analyze_traffic` exits non-zero on any failure. Negative tests in `tests/wire/test_checks.py` run in CI. **Not yet run on real captures** (needs Wireshark/Npcap, Postgres and the federation up). Claim 1 fails by default until decision D6 (review F18) is made; `--claim1-scope tls` is the D6-b reading. Depends on the `deploy/run_scenario.py --canaries-out` proposal (Avaneeth).
*Run on real captures (2026-10-15):* `python -m wire.analyze_traffic` over the P4-6 captures, report in `bench/results/p55_wire_checks.json`. Default scope (`all`): claims 0, 2 and 3 **pass** (the audit `COMMIT` is acknowledged 0.54 ms before the release response, and share 3 first appears inside it); claims 1 and 4 **fail**, only on the plain capture: shares, the emergency key, the DEK, attribute keys and record plaintext cross plain HTTP in bodies. With `--claim1-scope tls` (the D6-b reading) all five pass and none of the 10 canaries is readable under TLS. So P5-5 closes when D6 is decided, not before. Two findings from the run: the revoke request still carries `actor_signing_key_pem` and `old_dek_b64` (a private key on the wire, F11/D4, open), and `lifecycle_signing_key_pem` no longer appears anywhere on the wire (ADR-0068 confirmed).
*Decided (2026-10-15):* D6-b (ADR-0073): claim 1 is scoped to TLS and `--claim1-scope` defaults to `tls`. The revoke request now carries a signed event and the patient's certificate instead of `actor_signing_key_pem` and `old_dek_b64` (ADR-0072). Shares now travel sealed to their recipient on every profile (ADR-0079): a fresh plain capture from `deploy.run_local` shows no share anywhere, and claim 2 passes on the sealed share 3 (audit COMMIT 2.27 ms before the release response). The committed report predates all of this; re-record both captures (the TLS one needs the TLS store, ADR-0071).
*Done (2026-10-19):* both captures re-recorded on Path A (Npcap loopback; the TLS run against the TLS-only store, ADR-0071). `python -m wire.analyze_traffic` exits 0: claims 0–4 pass, the audit `COMMIT` is acknowledged 1.79 ms before the release response, no secret of 11 canaries is readable under TLS, and break-glass is visible only as a 4011-byte TLS burst. With `--claim1-scope all`, claims 1 and 4 fail on the plain capture only, as `PROJECT.md` §5 item 11 states. `bench/results/p55_wire_checks.json` and `p55_search_leakage.csv` are regenerated; `tests/wire/test_live_capture.py` passes on the new captures.

---

### Phase 6 — Paper and demo

**P6-1 · Paper: design + state machine** *(was P6-1)* — Powel — 7h
*What:* Write the system-design section — the state diagram, transition table, and protocol figures — matching the shipped code exactly.
*Needs first:* P4-4.
*Done when:* the figures match the code and the design reads clearly.

**P6-2 · Paper: design write-up** *(was P6-2)* — Nandini — 7h
*What:* Turn P6-1's formal design into readable prose for the paper's design section.
*Needs first:* P6-1.
*Done when:* the section reads as prose (not a spec dump) and Powel confirms it matches the design.

**P6-3 · Paper: implementation + results** *(was P6-3)* — Nandini — 18h
*What:* Write the implementation and evaluation sections — every performance number traceable to a benchmark run.
*Needs first:* P5-2.
*Done when:* every number traces to a real benchmark.

**P6-4 · Paper: security analysis** *(was P6-4)* — Ojas — 14h
*What:* Write the security analysis, threat model, limitations, and the security-properties table (with proxy re-encryption honestly marked unproven). Every claim maps to a passing test.
*Needs first:* P5-1.
*Done when:* every claim maps to a passing test and all four honesty caveats are stated up front.

**P6-5 · Paper: intro + related work** *(was P6-5)* — Avaneeth — 12h
*What:* Write the introduction, problem statement, the gap, and related work — citing both anchor papers and both rivals honestly.
*Needs first:* P4-4.
*Done when:* the gap statement holds up and rivals are cited fairly.

**P6-6 · Demo script + rehearsal** *(was P6-6)* — Avaneeth — 6h
*What:* Write and rehearse the demo, and capture a fallback recording in case the live run fails.
*Needs first:* P4-5, P4-3.
*Done when:* rehearsed twice on someone else's machine, with a recording captured.

---

### Workload and notes

Balanced by hours: **Avaneeth 118, Nandini 113, Powel 109, Ojas 103** (443h).
Verified by summing the table programmatically, not estimated (re-summed 2026-08-21
after the ADR-0014 portal additions and the ADR-0015 cuts; the earlier 434h figure
predated that reconciliation). P4-4 (end-to-end orchestration) is owned by
Avaneeth, who owns the demo driver.

The traffic-analysis module (P4-6, P5-5) added 17h. P6-1 is split between Powel and
Nandini — he supplies the state-machine formalism, she turns it into prose —
which was already flagged as sensible pairing, since writing the design section
well and knowing the design deeply are not always the same person.

If the total proves too heavy, cut in this order: stretch goals (`PROJECT.md`
§7) first, then P5-4 (edge cases) reduced in scope, then trim a portal
(P4-7/11/12) to a read-only minimum. *(The old "P1-7 two-pane dashboard"
fallback is gone — the dashboard was replaced by the three portals, ADR-0014.)*
**Never cut P5-5**, which is what satisfies the mandatory course module, and
never cut P5-1, which is the evidence base for the paper's security claims.


### Flagged risks in this assignment

- **Powel holds the entire critical path.** P0-2 → P1-1 → P1-3 → P2-3 → P3-1 → P3-5 →
  P3-6 → P4-4 is one unbroken chain, all owned by one person. If Powel is blocked
  or unavailable, the project stops. *Mitigation:* Powel ships P1-6 (the policy
  stub) early so nobody waits on P2-3, and the phase-gate cross-explanations
  (§5) exist partly so a second person can pick up `lifecycle` if needed. Nominate
  Ojas as the designated backup reader for `lifecycle` and `breakglass`.
- **P1-5 `pre` is the hardest task not owned by Powel.** If Ojas struggles with
  the ElGamal construction, pair on it early — it now feeds the break-glass
  re-wrap in P3-5 (PRE shrank to one direction under one shared store, ADR-0012).
- **Nandini's Phase 2 is thin and her Phase 5–6 is heavy** (P5-2, P5-3, P6-3 =
  36h). That is inherent to owning evaluation, which cannot start early. She has
  P2-4 and P2-5 to work on meanwhile; if she runs dry in Phase 3, the first thing
  to hand her is P5-4 (edge cases).
- **Nobody security-reviews their own work.** P5-1's negative tests are written
  by the person who built the audit gate they test — a real conflict of
  interest. Powel is the named reviewer for `tests/security/` specifically.
- **The course module must be code, not screenshots.** P5-5 is the deliverable
  that satisfies the mandatory module requirement, and the requirement is
  explicit that demonstration — not mention — is what counts. If P5-5 slips to
  screenshots-only, the project fails a stated course requirement regardless of
  how good the cryptography is. Treat it as non-negotiable, not as polish.
- **P5-5 depends on P4-6, which depends on deployment (P4-3).** The required course
  module therefore sits behind the deployment work. If deployment slips, the
  module slips with it — another reason P4-3 belongs in Phase 4, not Phase 6.
- **Skill fit is unverified.** These assignments balance hours, not aptitude,
  because individual skill levels were never specified. Swap freely; the
  vertical boundaries matter more than who holds them.

---

## 4. Git workflow

**Branches**
- `main` — protected, always demo-able. Never commit directly.
- `dev` — integration branch. All feature branches merge here first.
- Feature branches: `phase<N>/<module>/<short-desc>` — e.g.
  `phase3/audit/commit-before-release`, `phase1/shamir/gf-p-split`.

**Merging**
- Feature branch → `dev` via PR, reviewed by **one non-author**.
- `dev` → `main` only at a **phase gate**, performed only by **Powel**, after
  the phase's exit criteria are demonstrated.
- Squash-merge features into `dev`; plain merge commit for `dev` → `main` so
  phase boundaries stay visible in history.
- CI must be green. No merging around a red build to "unblock" someone.

**Avoiding collisions on the same files**
1. **Module ownership is the primary mechanism** — one owner per `src/`
   directory, only the owner edits it (`CONVENTIONS.md` §3). The four verticals
   map onto disjoint directories, so two people should almost never touch the
   same file.
2. **`src/contracts/` is the known exception.** Frozen after Phase 0; changes go
   through a `contract:` PR approved by all four and announced before merge.
3. **Rebase on `dev` before opening a PR.** Resolve conflicts on your branch,
   never in `dev`.
4. **One task per branch.** P3-1 and P3-6 are both Powel's and both touch
   `lifecycle`, but they are separate branches merged in dependency order.
5. Need a change in someone else's module? Open an issue. A one-line fix in
   someone else's file is how a two-hour merge conflict begins.

**Also**
- `.gitignore` covers `*.db`, `*.pem`, `*.key`, `deploy/pki/`, `__pycache__/`,
  `.env`, `bench/results/raw/`. **No key material in git, ever** — including
  test keys that "don't matter."
- Tag each phase gate: `phase-0-complete`, `phase-1-complete`, … Free, and it
  gives the paper a real development timeline.

---

## 5. Sync cadence

Gated rather than dated, matching the phase model.

**Twice-weekly standup — 20 minutes, hard stop.** Each person: what landed, what
is next, what is blocking. Blockers get an owner before the call ends. Anything
longer is a separate conversation between the two people who actually need it.

**Weekly integration session — 45 minutes.** Merge `dev`, run the full suite
together, walk any contract changes. Non-negotiable: **`dev` is green at the end
of this session.** Integration debt compounds faster than any other kind on a
project with this many cross-module dependencies.

**Phase gate review — 60–90 minutes, whenever the exit criteria are met.** Not
scheduled; triggered.
1. Demonstrate each exit criterion live. "Works on my machine" is not a
   demonstration — run from a clean clone.
2. Merge `dev` → `main`, tag the phase.
3. **Cross-explain:** each person explains someone *else's* module for two
   minutes. Cheapest possible viva insurance, and it surfaces integration
   misunderstandings while they are still cheap. Given that Powel owns the whole
   critical path, this is also the team's only real bus-factor mitigation.
4. Re-check the risk list; retire what is dead, add what is new.

**Ad-hoc pairing.** Any negative security test that fails in a surprising way
gets two people on it the same day. Those failures are usually design problems
wearing a test's clothing — and they are exactly what the paper is about.

**Written async check-in** in the team channel on any day without a standup: two
lines, what you did and what is blocking. Stops the twice-weekly cadence from
becoming a twice-weekly surprise.

---

## 6. Deployment procedure

Runtime topology, the two paths, and the bootstrap sequence are specified in
`ARCHITECTURE.md` §7. This section is the process around them.

**Who owns it:** Ojas (P4-3), because he already owns the audit and authority
services and the trust boundaries that the topology has to preserve.

**When it happens:** Phase 4, not Phase 6. Deployment discovered late is how
demos fail. The rule is that from the moment P4-3 lands, **every phase gate is
demonstrated on the deployed topology**, not on a developer's laptop with five
terminal tabs.

**Release procedure at each phase gate:**
1. Merge `dev` → `main`, tag `phase-N-complete`.
2. Bring the federation up from a clean clone on a machine belonging to someone
   who did not write the code being demonstrated.
3. Run the bootstrap health check — all five services ready, audit chain
   verifying from genesis.
4. Run the demo scenario end to end.
5. If any step fails, the gate does not pass. There is no partial credit at a
   gate; that is the entire point of having one.

**Demo-day checklist:**
- Clean clone, both deployment paths verified the day before.
- Time-box configuration set to demo length (~60s), not paper length (~15min).
- Fallback recording on the presenting machine **and** on a second device.
- Terminal font large enough to read from the back of the room.
- Every member able to answer a question about any module, not only their own.
