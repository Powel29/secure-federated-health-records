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
machines.

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

### Phase 6 — Paper and demo
**Exit criteria:** full draft reviewed by all four; every claim traceable to a
passing test or a benchmark number; demo rehearsed twice with a fallback
recording captured; every member can explain the whole system, not only their
own module.

**Stretch goals** (`PROJECT.md` §7) may not start until the Phase 5 gate passes.

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
- Four-pane observability dashboard (see the flag under the task table)
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
- `pre`: proxy re-encryption + cross-facility handoff
- Audit and authority service processes
- Containerisation, both deployment paths, and the capture profiles
- Traffic capture harness (**required course module**)
- Service-request signing (service identity across process boundaries)
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

## 3. Task table

Balanced by hours: **Powel 116, Avaneeth 112, Ojas 110, Nandini 109** (447h).
Verified by summing the table programmatically, not estimated.

The four-pane dashboard (T55, 16h) was funded by cutting T37 (scalability runs)
and moving T33 (end-to-end orchestration) to Avaneeth, who owns the demo driver.

**Flagged:** T55 is a Textual UI owned by the person holding the entire critical
path. It is the lowest-value work on the highest-value person, and it sits in
front of `shamir`, `policy`, `lifecycle`, and `breakglass`. If Phase 3 starts
slipping, T55 is the first thing to reassign — to Avaneeth, who already owns the
demo surface — or to cut back to the two-pane variant.

The traffic-analysis module (T45, T46) added 17h. T40 is split between Powel and
Nandini — he supplies the state-machine formalism, she turns it into prose —
which was already flagged as sensible pairing, since writing the design section
well and knowing the design deeply are not always the same person.

If the total proves too heavy, cut in this order: stretch goals (`PROJECT.md`
§7) first, then T39 (edge cases) reduced in scope, then T55 cut back to the
two-pane variant.
**Never cut T46**, which is what satisfies the mandatory course module, and
never cut T35, which is the evidence base for the paper's security claims.

| ID | Task | Owner | Phase | Depends on | Est. h | Definition of done |
|---|---|---|---|---|---|---|
| T01 | Repo scaffold, venv, pinned deps, folder structure | Powel | 0 | — | 3 | `pip install -r requirements.txt` works on all four machines; layout matches ARCHITECTURE §6 |
| T02 | **Freeze interface contracts** in `src/contracts/` (incl. `EmergencyAssertion`, `RequestEnvelope`) | Powel | 0 | T01 | 7 | All 7 schemas defined, type-hinted, approved by all four |
| T03 | Resolve faculty questions (grading, FHIR vs crypto) | Powel | 0 | — | 2 | Answers recorded in `PROJECT.md` §3; if FHIR, plan revised before Phase 2 |
| T04 | Threat model + trust assumptions, **four adversaries modelled separately** | Ojas | 0 | — | 8 | `docs/threat-model.md` treats semi-trusted storage, compromised facility node, malicious authority, and colluding clinicians as distinct adversaries with distinct consequences |
| T05 | CI: pytest + ruff + black on every PR | Nandini | 0 | T01 | 4 | CI green on empty suite; PRs blocked on failure |
| T06 | Crypto spike on all four machines | Avaneeth | 0 | — | 5 | Throwaway script runs green everywhere; findings in an ADR |
| T07 | Federation topology: 3 facilities, 2 authorities, 1 anchor | Avaneeth | 0 | — | 4 | Topology diagram + which authority owns which attributes, in `docs/` |
| T08 | `crypto_core`: AES-256-GCM, HKDF, SHA-256 | Powel | 1 | T02 | 6 | Known-answer vectors pass; nonce generated per encryption; no raw hazmat imports elsewhere |
| T09 | `crypto_core`: ECDSA keygen, sign, verify, serialisation | Powel | 1 | T08 | 5 | Round-trip tests; tampered payload fails verification |
| T10 | **`shamir`: 2-of-3 split/combine over GF(p)** | Powel | 1 | T02 | 8 | Any 2 of 3 reconstruct; any 1 yields nothing; property test over random secrets |
| T11 | `storage`: SQLite schema + repositories | Avaneeth | 1 | T02 | 8 | All tables per ARCHITECTURE §2 C4; CRUD tested; migration script |
| T12 | `records`: per-record DEK, envelope wrap/unwrap | Avaneeth | 1 | T08, T11 | 8 | Encrypt→store→retrieve→decrypt round-trip; one DEK per record enforced |
| T13 | `pre`: unidirectional ElGamal-style proxy re-encryption | Ojas | 1 | T08 | 12 | A→B re-encryption key transforms ciphertext; proxy provably never sees plaintext |
| T14 | `policy` **stub** returning deterministic fakes | Powel | 1 | T02 | 2 | Downstream modules can call the real interface before the engine exists |
| T15 | `identity`: root anchor, facility CAs, cross-certification | Avaneeth | 2 | T09, T11 | 12 | Out-of-network clinician cert validates via chain to shared anchor; forged cert rejected |
| T16 | `authority`: multi-authority attribute issuance | Avaneeth | 2 | T15 | 8 | Two independent authorities issue signed credentials; forged credential rejected |
| T17 | **`policy`: access structure engine (AND/OR tree over Shamir)** | Powel | 2 | T10, T16 | 12 | Satisfying credential set reconstructs root secret; non-satisfying set fails; replaces T14 stub with no caller changes |
| T18 | `federation`: patient-indexed discovery | Nandini | 2 | T11, T15 | 8 | Facility B locates a patient's records held at Facility A without learning contents |
| T19 | `search`: encrypted inverted index | Nandini | 2 | T12 | 12 | Index built over ciphertext; server learns no plaintext terms; built against a fixed test key until T24 lands |
| T20 | **`lifecycle`: state machine core + signed transition events** | Powel | 3 | T09, T12 | 12 | 4 states, transition table enforced, illegal transitions raise, events independently verifiable |
| T21 | Consent / grant path (→ Granted) | Powel | 3 | T20, T17 | 5 | Grant wraps DEK to a policy tree; authorised clinician reads, unauthorised does not |
| T22 | `audit`: hash-chained signed log + verification | Ojas | 3 | T09, T11 | 10 | `h_i = SHA-256(h_{i-1} ‖ event ‖ ts ‖ actor)`; full-chain verify; tampered entry detected |
| T23 | **Audit share custody: commit-before-release** | Ojas | 3 | T22, T10 | 8 | Share returned only after the chain head is committed; log-write failure ⇒ no share (negative test) |
| T24 | **`breakglass`: 2-of-3 threshold gate (→ Emergency-open)** | Powel | 3 | T23, T20, T16 | 12 | Any 2 shares reconstruct the emergency key; 1 share insufficient; the audit service alone cannot open a record |
| T25 | **Time-boxed key, auto-close, forced rotation (→ Expired →)** | Powel | 3 | T24 | 10 | Emergency state expires with no admin action; expiry is a signed, logged rotation; time-box configurable |
| T26 | Revocation-as-key-rotation (→ Revoked) | Avaneeth | 3 | T20, T12 | 8 | Revoke rotates the DEK and rebuilds wrappings; revoked user cannot decrypt (negative test) |
| T27 | **Emergency-only search tokens** | Nandini | 3 | T19, T25 | 10 | Token derives from the emergency key via HKDF; search works in Emergency-open, dead after expiry (negative test) |
| T28 | Search-index re-keying on DEK rotation | Nandini | 3 | T19, T26 | 8 | After revocation or forced rotation the index is re-keyed; stale tokens fail; no plaintext re-indexing leak |
| T29 | Cross-facility handoff via PRE | Ojas | 3 | T13, T18, T24 | 10 | Record key re-wrapped to an out-of-network clinician; proxy never decrypts |
| T30 | Facility node FastAPI service | Avaneeth | 4 | T21, T26, T29 | 10 | Endpoints for read, grant, revoke, break-glass, search; **no cryptography in route handlers** |
| T31 | Audit + authority FastAPI services | Ojas | 4 | T22, T16 | 8 | Run as separate processes; facility talks to them over HTTP |
| T32 | **Deployment: local supervisor + Docker Compose + bootstrap** | Ojas | 4 | T30, T31 | 12 | Both paths in ARCHITECTURE §7 work; bootstrap sequence runs in order; chain verifies at boot or nothing starts |
| T33 | End-to-end cross-facility break-glass orchestration | Avaneeth | 4 | T30, T31, T27 | 10 | Full scenario runs across all five processes from a clean clone |
| T34 | Demo driver + synthetic seed dataset | Avaneeth | 4 | T33 | 8 | One command seeds and runs the scenario with examiner-readable output; zero real PHI |
| T35 | Negative security test suite | Ojas | 5 | T33 | 15 | All 10 negative tests in CONVENTIONS §5 pass; each maps to a specific paper claim |
| T36 | Benchmark harness + pandas analysis + plots, incl. ciphertext expansion | Nandini | 5 | T33 | 12 | Every D4 metric produced, including per-record ciphertext expansion; results reproducible from one command |
| T38 | Search leakage-profile analysis, **measured from captures** | Nandini | 5 | T27, T28, T46 | 6 | Quantifies what the semi-trusted server learns (access pattern, frequency, volume) from real PCAPs, not from argument alone; goes straight into the paper |
| T45 | **Capture harness + `capture-plain` / `capture-tls` profiles** | Ojas | 4 | T32 | 6 | Both profiles run; PCAP produced per scenario from the bridge network and from loopback; captures land in `bench/captures/` |
| T46 | **PyShark analysers asserting wire-level properties**, correlated by request ID | Nandini | 5 | T45, T33 | 13 | Four assertions in `PROJECT.md` §4A automated as failing-on-violation checks: no plaintext PHI/DEK/share on the wire; share never precedes commit; break-glass metadata-only; leakage measured |
| T48 | **Emergency Assertion Protocol** — signed, bound, expiring | Powel | 3 | T20, T15 | 6 | Assertion is an ECDSA-signed struct binding patient, clinician, facility, timestamp, nonce, reason code, expiry; unsigned or unbound assertions rejected; break-glass will not proceed without one |
| T49 | **Replay protection** — nonce + consumed-request-ID store | Powel | 3 | T48 | 3 | Emergency assertions, share requests, and transition events each carry a one-time ID; a replayed request is rejected, not re-executed |
| T50 | Revocation authorization binding | Avaneeth | 3 | T26 | 3 | Revocation signer must prove record ownership (patient) or home-authority status; a validly-signed but unauthorised revocation is rejected |
| T51 | Object-level authorization middleware (BOLA) | Nandini | 4 | T30 | 4 | Caller authorised for the specific patient/record **before** any crypto or DB work; enumeration of patient IDs denied |
| T52 | Credential lifecycle — serial, validity, revocation status | Avaneeth | 2 | T15, T16 | 6 | Clinician and authority credentials carry issuer, subject, serial, valid_from, valid_until, status; expired and revoked credentials rejected at validation |
| T53 | Service-request signing (service identity without mTLS) | Ojas | 4 | T31, T09 | 4 | Every inter-service call signed with the caller's service key and verified by the callee; unsigned inter-service calls rejected |
| T54 | `capture-plain` guard | Nandini | 4 | T32 | 2 | Services refuse to start in plain-HTTP mode unless `ENVIRONMENT=LAB_CAPTURE` is explicitly set; refusal is logged loudly |
| T39 | Edge cases: clock skew, partial shares, malformed input | Nandini | 5 | T33 | 5 | Each handled and tested (replay moved to T49, where it belongs) |
| T55 | **Four-pane observability dashboard** (Textual) — built to `docs/dashboard-design.md` | Powel | 4 | T32, T56 | 16 | Patient / clinician / authority / audit panes + chain strip; read-only SQLite URIs; no `crypto_core` import; each pane's query actor-scoped and tested |
| T56 | Audit events for denials + federation operations | Ojas | 3 | T22 | 3 | `ACCESS_DENIED`, `POLICY_EVALUATED`, `DISCOVERY_QUERY`, `PRE_REWRAP` committed to the chain; identifiers and hashes only, never key material |
| T57 | Record ingest path (upload → encrypt → index → policy) | Avaneeth | 3 | T13, T19 | 4 | A submitted record mints DEK + K_idx, encrypts, builds index tokens over designated fields, attaches policy tree, logs `RECORD_INGESTED` |
| T40 | Paper: state-machine formalism + protocol figures | Powel | 6 | T33 | 7 | State diagram, transition table, protocol figures; matches shipped code exactly |
| T40b | Paper: system design section drafted from T40 formalism | Nandini | 6 | T40 | 7 | Design section reads as prose, not as a spec dump; Powel verifies it matches the formalism |
| T41 | Paper: implementation + evaluation + results | Nandini | 6 | T36 | 18 | Every number traceable to a benchmark run |
| T42 | Paper: security analysis + threat model + limitations + **security-properties table** | Ojas | 6 | T35 | 14 | Every claim maps to a passing negative test; all four caveats stated up front, not buried |
| T43 | Paper: intro, problem, gap, related work | Avaneeth | 6 | T33 | 12 | Both anchors and both rivals cited honestly; gap statement defensible under questioning |
| T44 | Demo script, rehearsal, fallback recording | Avaneeth | 6 | T34, T32 | 6 | Rehearsed twice on a non-author machine; recording captured |

### Flagged risks in this assignment

- **Powel holds the entire critical path.** T02 → T08 → T10 → T17 → T20 → T24 →
  T25 → T33 is one unbroken chain, all owned by one person. If Powel is blocked
  or unavailable, the project stops. *Mitigation:* Powel ships T14 (the policy
  stub) early so nobody waits on T17, and the phase-gate cross-explanations
  (§5) exist partly so a second person can pick up `lifecycle` if needed. Nominate
  Ojas as the designated backup reader for `lifecycle` and `breakglass`.
- **T13 `pre` is the hardest task not owned by Powel.** If Ojas struggles with
  the ElGamal construction, pair on it early rather than late — it gates T29,
  which gates the cross-facility half of the demo.
- **Nandini's Phase 2 is thin and her Phase 5–6 is heavy** (T36, T38, T41 =
  36h). That is inherent to owning evaluation, which cannot start early. She has
  T18 and T19 to work on meanwhile; if she runs dry in Phase 3, the first thing
  to hand her is T39 (edge cases).
- **Nobody security-reviews their own work.** T35's negative tests are written
  by the person who built the audit gate they test — a real conflict of
  interest. Powel is the named reviewer for `tests/security/` specifically.
- **The course module must be code, not screenshots.** T46 is the deliverable
  that satisfies the mandatory module requirement, and the requirement is
  explicit that demonstration — not mention — is what counts. If T46 slips to
  screenshots-only, the project fails a stated course requirement regardless of
  how good the cryptography is. Treat it as non-negotiable, not as polish.
- **T46 depends on T45, which depends on deployment (T32).** The required course
  module therefore sits behind the deployment work. If deployment slips, the
  module slips with it — another reason T32 belongs in Phase 4, not Phase 6.
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
4. **One task per branch.** T20 and T25 are both Powel's and both touch
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

**Who owns it:** Ojas (T32), because he already owns the audit and authority
services and the trust boundaries that the topology has to preserve.

**When it happens:** Phase 4, not Phase 6. Deployment discovered late is how
demos fail. The rule is that from the moment T32 lands, **every phase gate is
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
