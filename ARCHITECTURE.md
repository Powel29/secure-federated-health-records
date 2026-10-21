# ARCHITECTURE.md

System components, what depends on what, the tech stack, and how data moves.
Scope and deliverables live in `PROJECT.md`; sequencing and ownership live in
`WORKFLOW.md`.

---

## 1. Tech stack

Chosen under an explicit constraint: **keep it easy to install and run.** A
stack that takes two weeks to build is a schedule risk disguised as a
sophistication win.

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Team familiarity; every needed primitive available |
| Crypto primitives | `cryptography` (pyca) | AES-256-GCM, HKDF, ECDSA (P-256), RSA-OAEP, X.509. Pure wheels, no C build |
| Hashing | `hashlib` (stdlib) | SHA-256 for the audit chain |
| Randomness | `secrets` (stdlib) | Never `random` for anything security-relevant |
| Shamir SSS | **Hand-rolled**, GF(p) with p a 256-bit prime | ~80 lines, it is a course topic, and it removes a dependency |
| Proxy re-encryption | **Hand-rolled** ElGamal-style PRE (bidirectional, ADR-0076) | No maintained easy-install PRE library exists |
| Access structure | **Hand-rolled** policy tree over Shamir | Replaces CP-ABE — see §3 |
| Services | FastAPI + Uvicorn | Trivial to run several processes; gives us real network boundaries |
| Storage | **PostgreSQL** (one shared store) | Real concurrent multi-service access; holds only ciphertext, wrapped keys, and coded index — stores data, never decides access (ADR-0014) |
| Analysis | pandas + matplotlib | Benchmark tables and plots |
| Testing | pytest | Including the negative security suite |
| Style | black + ruff | See `CONVENTIONS.md` |

### Explicitly rejected

**Charm-Crypto.** It depends on the PBC and GMP C libraries, its Python 3
support is patchy, and teams routinely lose one to two weeks getting it to
build. Since multi-authority attribute-based access sits on our critical path,
that risk is unacceptable. See §3 for what we do instead.

---

## 2. Components

Each component maps to one directory under `src/` and has exactly one owner.

**C1 — `crypto_core`.** AES-256-GCM encrypt/decrypt, HKDF derivation, SHA-256
helpers, ECDSA keygen/sign/verify, key serialisation. Every other module calls
primitives *through here*, never directly.

**C2 — `shamir`.** Threshold secret sharing over a prime field. Split, combine,
share validation. Used by both the break-glass gate and the policy engine.

**C3 — `pre`.** ElGamal-style proxy re-encryption over a safe-prime group:
re-encryption key `rk = sk_a · sk_b⁻¹ mod q` and a ciphertext transform. The
scheme is **bidirectional** (`rk⁻¹` re-encrypts B to A) and computing `rk` needs
both secret keys (ADR-0076). The break-glass path uses only its KEM: the
facility unwraps the DEK and delivers it to the clinician's ElGamal key.

**C4 — `storage`.** PostgreSQL schema and repository objects. Tables: patients,
records, dek_wrappings, attributes, authorities, facilities, lifecycle_state,
transition_events, audit_log, search_index.

**C5 — `identity`.** The federated PKI. Root trust anchor, per-facility CAs,
cross-certification, certificate chain validation, clinician certificates. This
is what lets an out-of-network clinician be verified at all.

**C6 — `authority`.** Multi-authority attribute issuance. Each authority
(medical council, hospital network) issues signed attribute credentials plus the
attribute key material used by the policy engine.

**C7 — `policy`.** The access structure engine. Compiles an AND/OR policy tree
into a Shamir sharing layout over attribute keys, and reconstructs the DEK when a
presented credential set satisfies the tree. This is our ABE substitute.

**C8 — `records`.** Record encryption service. One DEK per record, AES-256-GCM,
envelope encryption of the DEK per authorised party, re-wrap on rotation.

**C9 — `lifecycle`.** The state machine. States Granted / Revoked /
Emergency-open / Expired, the legal transition table, signed transition event
generation and verification, and the rotation logic each transition triggers.
**This is the spine of the project.**

**C10 — `audit`.** Hash-chained signed log — `h_i = SHA-256(h_{i-1} ‖ event ‖
timestamp ‖ actor)` — append and full-chain verification. Runs as its own
process. Also custodian of two break-glass shares, 3 and 4 (see C11).

**C11 — `breakglass`.** The threshold gate. The emergency key is a weighted
Shamir **3-of-4** split (ADR-0089): share 1 to the attending clinician's
custody, share 2 to the patient's home authority (the issuer of the patient's
`owner` credential), and shares 3 and 4 to the audit service. Any three points
reconstruct, so break-glass needs the audit service plus either the custodian
or the home authority. Custodian + home authority (two points) cannot open a
record, and neither can the audit service alone. The audit service's shares
are released **only after** its log entry is committed and the new chain head
is returned. Reconstructs the time-boxed emergency key.

**C12 — `search`.** Encrypted inverted index over record contents, plus search
token derivation. Tokens derive from the emergency key, so search capability
exists only while the record is in Emergency-open and is dead once it expires.

**C13 — `federation`.** Patient-indexed discovery over the shared store. Records
live in **one semi-trusted encrypted store**, not scattered per facility.
Discovery answers "which encrypted records exist for this patient" by patient
index, so any facility can locate a patient's records without the store — or the
querying facility — learning contents (ADR-0011).

**C14 — `api`.** FastAPI applications: facility node, authority service, audit
service. Thin — request handling and orchestration only, no cryptography.

**C15 — `bench`.** Benchmark harness and pandas analysis.

**C16 — `ui`.** Three role-based web portals (Django + Bootstrap), replacing the
earlier terminal dashboard (ADR-0014):
- **Patient portal** — approve/deny access requests, revoke grants, view access
  history including break-glass, receive notifications.
- **Clinician portal** — request access, search during emergency, declare
  break-glass, see the live emergency countdown.
- **Admin/audit portal** — browse the audit log by correlation ID, view
  federation/service state, review break-glass cases (read-only).

The portals are a **front-end over the cryptographic core, not a replacement for
it**. They never hold keys and never decide access — the threshold gate, the
policy engine, and the key wrappings do. Django login identifies *who is asking*;
it does not authorise decryption. This boundary is the one thing that keeps the
portals from quietly becoming the "database decides access" model the project
argues against (ADR-0014).

*Future enhancement (stretch):* Drive-style virtual department folders
(Cardiology, Radiology, Pathology, General, Emergency) with heuristic
auto-sorting on upload, mapping each folder directly to attribute-policy scopes
(`dept:cardiology`, `dept:radiology`, `emergency:breakglass`). See `PROJECT.md`
§7 and `portal/README.md`.



**C17 — `wire`.** Traffic capture and analysis (the required course module; see
`PROJECT.md` §4A). Capture harness that records PCAPs per scenario from the
federation's own network, PyShark analysers that assert wire-level security
properties. Analysis is done in pandas alongside the benchmark harness — no
separate persistence layer. Depends on the deployed
topology (§7) existing, so it lands in Phase 4–5.

---

## 3. The access structure (our CP-ABE substitute)

Because full CP-ABE is off the table for install reasons, policy-based
decryption works like this:

A record's access policy is a tree, e.g.
`(role:physician AND specialty:cardiology) OR role:emergency-physician`.

- Each **leaf** is an attribute. Its share is encrypted to the attribute key
  issued by the authority that owns that attribute.
- Each **AND node** splits its parent's secret with a k-of-k Shamir sharing
  across its children.
- Each **OR node** gives each child the *same* secret — any one child suffices.
- The root secret is the wrapping key for the record's DEK.

A clinician holding attribute keys that satisfy the tree can reconstruct up the
tree to the root and unwrap the DEK. No per-clinician pre-provisioning is
required, and attributes come from multiple independent federated authorities —
which is the property we actually need for cross-institution access.

**The honest limitation**, which belongs in the paper: this is not
collusion-resistant. Two clinicians could pool attribute keys to satisfy a
policy neither satisfies alone. Pairing-based CP-ABE prevents this by binding
attribute keys to a per-user random value; we cannot without pairings. Stated as
a limitation, with real CP-ABE listed as future work.

---

## 4. Dependency map

Read as "X requires Y to exist first."

```
C1 crypto_core        <- nothing (foundation)
C2 shamir             <- nothing (pure math; independent of C1)
C4 storage            <- interface contracts only (T02)

C3 pre                <- C1
C5 identity           <- C1, C4
C8 records            <- C1, C4
C10 audit             <- C1, C4

C6 authority          <- C1, C5            (issuance needs certs to sign under)
C7 policy             <- C1, C2, C6        (needs attribute keys to share to)
C13 federation        <- C4, C5            (discovery needs cross-facility trust)

C9 lifecycle          <- C1, C4, C8        (transitions rotate real keys)
   consent/grant path <- C9, C7            (grant = wrap DEK to a policy)
   revocation path    <- C9, C8            (revoke = re-wrap DEK)

C11 breakglass        <- C2, C9, C10, C6   (shares, a state to enter, an
                                            audit service to gate on; share 2
                                            held by the home authority,
                                            ADR-0089)
C12 search            <- C1, C8, C11       (tokens derive from emergency key)
   cross-facility     <- C3, C5, C13       (PRE re-wrap to an out-of-network
   handoff                                  clinician at a discovered node)

C14 api               <- C5..C13           (exposes them; thin)
C16 demo              <- C14, C13, C11, C12
C15 bench             <- whichever module it measures
C17 wire              <- deployed topology (§7) + C16
                         (captures need real processes and a real scenario)
```

### Critical path

```
contracts (T02) -> crypto_core -> records -> lifecycle -> breakglass -> search -> demo
                              \-> shamir  ->  policy  --^
                                    identity -> authority ^
```

**Consequences that drive `WORKFLOW.md`:**

- **Interface contracts must be frozen before anything else.** They are what
  lets four people build in parallel against modules that do not exist yet.
- `crypto_core` and `shamir` block nearly everything and must land first.
- `lifecycle` is the single widest dependency — break-glass, revocation,
  expiry, and search all sit on it.
- `policy` is a single point of failure on the critical path; it ships as a
  stub in Phase 1 so downstream work is never blocked waiting for it.
- `search` is last of the core features because it depends on break-glass, which
  depends on the state machine *and* the audit service.

---

## 5. Data and request flow

### Normal read (in-network, Granted)

1. Clinician authenticates to their facility node; cert chain validated against
   the federation root anchor (C5).
2. Node fetches the record and its DEK wrappings (C4, C8).
3. Clinician presents attribute credentials; the policy engine attempts
   reconstruction of the root secret (C7).
4. On success the DEK is unwrapped, the record is AES-256-GCM decrypted (C1).
5. Access is appended to the audit chain (C10). *Normal reads are logged but not
   gated on logging — only break-glass is.*

### Revocation (Granted → Revoked)

1. The patient signs a revocation request, verified against their patient
   certificate (ADR-0064). In this build the facility accepts only the
   patient's signature: a revocation by the home authority would need each
   authority's verification key in facility configuration and is future
   work (ADR-0080, ADR-0084).
2. `lifecycle` validates the transition is legal, emits a **signed transition
   event** (C9).
3. Record's DEK is rotated: new DEK, record re-encrypted, wrappings rebuilt
   excluding the revoked party (C8).
4. Transition event and new chain head appended to the audit log (C10).
5. The revoked party retains nothing usable for future reads. Already-decrypted
   plaintext is not retractable — stated as a limitation.

### Cross-facility break-glass (the headline scenario)

0. **Identification.** Clinician looks up the patient in the clinician
   portal by name and date of birth against the portal's `PatientDirectory`
   (ADR-0033). An unconscious patient cannot give these, so the scenario
   assumes they are read from an ID card the patient carries; unidentified
   patients are a stated limitation (ADR-0059, `PROJECT.md` §5 item 7). PII lives only in the portal DB — never in the crypto store
   (ADR-0011). Ambiguous matches are shown as a list; the clinician
   selects one, and the resulting `patient_id` is carried into the signed
   assertion below. The lookup itself is a `patient.lookup` audit event
   whether or not a match is selected. Identification produces no key and
   grants no access; the checks that follow are the ones that decide that.
1. Unconscious patient at an out-of-network facility. Clinician signs an
   `EmergencyAssertion` bound to the `patient_id` from step 0 (see
   "The Emergency Assertion" below); their certificate is validated via
   cross-certification (C5).
2. Federated discovery locates the patient's records (C13).
3. Threshold collection begins (C11):
   - **Share 1** — attending clinician, released against a valid emergency
     assertion and a valid cross-certified identity.
   - **Share 2** — the patient's home authority (the authority that issued the
     patient's `owner` credential). Used only when share 1 is not available
     (for example, lost in a custodian restart): the custodian then asks the
     home authority before it asks the audit service. The home authority
     releases share 2 only after it has validated the emergency assertion
     itself, with the same five-point check and record binding as the audit
     service, against its own trust anchors and its own consumed-assertion
     store, and only sealed to a root-certified facility gate. It writes no
     log entry: share 2 opens nothing without shares 3 and 4 (ADR-0089).
   - **In transit** every share is sealed to its recipient's share key,
     published at `GET /share-key` and signed by the recipient's
     root-certified service identity; shares 3 and 4 (by the audit service)
     and share 2 (by the home authority) are sealed straight to the
     facility's gate, so the custodian forwarding them cannot read them
     (ADR-0079).
   - **Shares 3 and 4** — audit service. **The audit service computes and
     commits `h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)` first, and
     only then returns both shares along with the new chain head.** If the log
     write fails, no share is returned and break-glass fails closed. The entry
     records which share path was used (`custodian` or `home_authority`).
   - **Each holder takes only its own shares.** A deposit or replacement whose
     share indices are not exactly the holder's ({1}, {2} or {3, 4}) is
     refused, so a misrouted share cannot give two non-audit holders three
     points.

     Each share holder validates the emergency assertion itself before it
     releases anything: the audit service runs the same five-point check
     against its own trust anchors and requires the assertion's signed context
     digest to name this record (ADR-0067).
4. Shares 3 and 4 plus share 1 (or share 2) reconstruct the emergency key.
   Any 3 of the 4 points would; the custodian and the home authority hold
   only two between them, so every set of three contains a share only the
   audit service releases, and it releases 3 and 4 together, after its log
   commit. `lifecycle` records the
   Granted → Emergency-open transition, signed by the clinician's own key
   inside the custodian and verified against their certificate before any
   share is combined (C9, ADR-0068).
5. Cross-facility handoff: the facility unwraps the DEK and delivers it to
   the out-of-network clinician's ElGamal key with the `pre` KEM (C3). The
   facility sees the DEK; there is no decryption-free re-encryption here
   (ADR-0076).
6. **Emergency search** becomes available: tokens are derived from the emergency
   key via HKDF, so the capability exists only in this state (C12).
7. Time-box expires. `lifecycle` performs Emergency-open → Expired → forced
   rotation back to baseline with no administrator action (C9). The rotation
   replaces every key (ADR-0069): a new DEK and re-encrypted record, the same
   policy tree compiled under a new root secret, a new emergency key whose new
   shares go to the custodian and the audit service, and the search index
   re-derived under it from the record's term list (sealed under the DEK at
   ingest). It is stored before the record returns to baseline. Search tokens
   are dead because the key they derive from is gone, and the old shares open
   nothing.

### Trust boundaries

- The **shared store** is semi-trusted and central by design: it holds every
  ciphertext record, the wrapped keys, and the coded search index, and is
  assumed honest-but-curious. It is one place, but never one that can *read*
  anything — it holds no keys and never sees plaintext. A full compromise of the
  store yields only gibberish. This is the deliberate trade of a central store:
  one target, but one that holds nothing usable (ADR-0011).
- The **audit service** is trusted to hold one share and to commit before
  releasing — but it **cannot open a record alone**, which is a tested property.
- The **HSM/KMS timer** is simulated by a trusted process. Its subversion is a
  documented limitation, mitigated by making expiry a signed, logged rotation.

---

## 6. Repository layout

```
src/
  crypto_core/     C1   AES-GCM, HKDF, ECDSA, SHA-256 wrappers
  shamir/          C2   threshold secret sharing over GF(p)
  pre/             C3   proxy re-encryption
  storage/         C4   PostgreSQL schema + repositories (ADR-0014/0020)
  identity/        C5   root anchor, facility CAs, cross-certification
  authority/       C6   multi-authority attribute issuance
  policy/          C7   access structure / policy tree engine
  records/         C8   record + envelope encryption, re-wrap
  lifecycle/       C9   the state machine
  audit/           C10  hash-chained signed log + share custody
  breakglass/      C11  threshold gate (weighted 3-of-4 split, ADR-0089)
  search/          C12  encrypted index + emergency-only tokens
  federation/      C13  patient-indexed discovery
  api/             C14  FastAPI apps (facility, authority, audit)
  contracts/       ---  shared schemas, frozen in Phase 0
tests/             mirrors src/, plus tests/security/ for negative tests
bench/             C15  harness + analysis notebooks/scripts
demo/              C16  seed data + scripted walkthrough
wire/              C17  capture profiles + PyShark analysers (§4A module)
paper/             LaTeX source, figures
docs/              threat model, ADRs, dashboard build spec
```

`src/contracts/` is the one directory everybody touches. It is frozen after
Phase 0 and changes only through a contract-change PR reviewed by all four —
see `CONVENTIONS.md`.

---

## 7. Deployment

The system is a **federation**, so it cannot be demonstrated as one process. The
whole point — that break-glass requires shares held by parties who do not trust
each other — is only visible if those parties are genuinely separate processes
with a network boundary between them. A single-process demo would silently
undermine the paper's central claim.

### Runtime topology

Seven processes. The shared `store` holds the encrypted records; the five federation services each have their own signing key and a small local DB for keys and state; the `custodian` (ADR-0043) is the portals' key agent:

| Process | Port | Role | Holds |
|---|---|---|---|
| `store`      | 8000 | Shared semi-trusted encrypted record store | All ciphertext records, wrapped keys, coded search index — **never plaintext, never unwrapped keys** |
| `facility-a` | 8001 | Patient's home facility | Clinician certs + home-authority link; **holds no records** — reads them from `store` |
| `facility-b` | 8002 | Out-of-network facility (the demo entry point) | Clinician certs only; must discover the patient in `store`, then break-glass |
| `authority-med` | 8010 | Medical council attribute authority | Attribute keys for `role:*`; share 2 of records whose patients it issued an `owner` credential |
| `authority-net` | 8011 | Hospital network attribute authority | Attribute keys for `specialty:*`, `facility:*`; share 2 of records whose patients it issued an `owner` credential (ADR-0089) |
| `audit` | 8020 | Audit service — chain custodian + shares 3 and 4 | Hash-chained log, break-glass shares |
| `custodian` | 8030 | Key Custodian — every subject's key agent (ADR-0043) | Per-subject signing keys, certificates, PRE keypairs, issued credentials; clinician-custody share 1 per record. Signs and presents on request; **decides nothing** |

The three Django portals (C16) run beside these (`portal/manage.py runserver`,
port 8000, or all-in-one via `python -m deploy.run_portal_demo`) and hold no
keys: anything that needs one goes to the `custodian` by `subject_id` after
login; grant submission, discovery, emergency search and chain reads go to the
facilities and the audit service directly.

The `audit` service **must** be a separate process. If it shares memory with a
facility node, "the audit service releases its share only after committing"
becomes an in-process function call that a reviewer can dismiss as a
convention rather than an enforced precondition.

### Two deployment paths

**Path A — local processes (primary, for development).** A Python supervisor
script (`deploy/run_local.py`) launches all five uvicorn processes, waits for
health checks, and seeds the federation. No Docker required. This is what the
team uses day to day, and it honours the "keep it easy" constraint — a teammate
who cannot install Docker is not blocked.

**Path B — Docker Compose (for the demo and for reproducibility).** Five
services in one `docker-compose.yml`, one shared bridge network, a named volume
for the PostgreSQL data (ADR-0014). This is what runs on demo day and what an evaluator or a
paper reviewer can bring up from a clean clone with one command. It also removes
the "works on my machine" failure mode at the worst possible moment.

Both paths must work. Path A is the default; Path B is the safety net.

### Bootstrap sequence

Order matters — a facility cannot validate a clinician before the trust anchor
exists.

1. **Generate the root trust anchor** and its keypair.
2. **Issue facility CA certificates** signed by the anchor; **cross-certify** the
   facilities so `facility-b` can validate a clinician enrolled at `facility-a`.
3. **Start the authority services**; each generates attribute key material and
   registers its public parameters with the anchor.
4. **Start the audit service**; it initialises the hash chain with a genesis
   entry `h_0` and publishes its chain head.
5. **Start the facility nodes**; each loads the anchor, its own CA, and the
   authorities' public parameters.
6. **Seed synthetic data** — patients, records, policy trees, clinician
   certificates at both facilities.
7. **Health check**: every service reports ready, and the audit chain verifies
   from genesis. If chain verification fails at boot, nothing else starts.

### Configuration

- One `.env` per service, generated by the bootstrap script — never committed.
- Keys and certs land in `deploy/pki/`, which is `.gitignore`d in its entirety.
- Ports, timer durations, and the emergency time-box length are configuration,
  not constants in code. **The time-box must be adjustable**: hours (an
  emergency encounter; the facility default is 4 h) is realistic for the paper,
  60–120 seconds is what you need for a live demo that does not require the
  audience to wait. The emergency assertion that opens it is a separate,
  one-time token capped at 15 minutes (ADR-0056).
- No secrets in `docker-compose.yml`. Generated at bootstrap, mounted in.

### Demo-day requirements

- Runs from a **clean clone on a machine that is not the author's**. This is a
  phase exit criterion, not a nicety.
- One command up, one command to run the scenario, one command down.
- Output must be readable by an examiner watching over a shoulder: print the
  state transitions, the chain head after each append, which shares were
  collected and from whom, and the expiry countdown.
- **A recorded fallback video is mandatory.** Live demos fail. A recording is
  ten minutes of insurance against losing the largest chunk of the grade.

### Capture configuration (for the traffic-analysis module)

Traffic capture is a first-class deployment mode, not an afterthought. Two
profiles, selected by environment variable:

| Profile | Transport | Purpose |
|---|---|---|
| `capture-plain` | Plain HTTP between all five services | **Primary.** Demonstrates that confidentiality comes from application-layer encryption, not from TLS. This is the profile that produces the evidence in `PROJECT.md` §4A. |
| `capture-tls` | TLS between services | Secondary. Shows defence in depth and that we are not relying on the absence of transport security. |

Capture points:
- **Docker path:** capture on the Compose bridge network, which sees all
  inter-service traffic in one place.
- **Local path:** capture on loopback across the five service ports.

PCAPs are written to `wire/captures/` (beside the canary manifest each run
writes; review F40), which is `.gitignore`d — captures of a
seeded synthetic federation are still large and still regenerable. The analysers
and their assertions are committed; the raw captures are not.

**Constraint:** capture only our own federation. Never on campus, shared, or
third-party networks.

---

## 8. Application security model

Added after an external security review (disposition recorded in `PROJECT.md`
§4B). The governing principle:

> **Cryptographic authorization is not a substitute for endpoint
> authorization.** The policy engine decides whether a key can be
> *reconstructed*. It does not decide whether a request should have been
> *served*. Both checks are required, and the endpoint check runs first.

### The Emergency Assertion

Break-glass previously began with "the clinician asserts an emergency," which
left the trigger for our headline contribution undefined. An assertion is now a
signed structure:

```
EmergencyAssertion {
  assertion_id    # one-time UUID, consumed on use
  patient_id      # bound: this assertion opens this patient only
  clinician_id    # bound: subject of the presenting certificate
  facility_id     # bound: where the emergency is being declared
  reason_code     # constrained enum, not free text
  issued_at
  expires_at      # short — an assertion is not a standing permission
  nonce
  signature       # ECDSA, by the clinician's certificate key
}
```

Validation, in order, before any share is requested: signature verifies against
a currently-valid clinician certificate; `clinician_id` matches the certificate
subject; `facility_id` matches the receiving node; `expires_at` is in the
future; `assertion_id` has not been consumed. Once the record is loaded, and
before any state changes, its `patient_id` must equal the assertion's
(ADR-0044). Failure at any step is
fail-closed — no share request is made.

**How `patient_id` gets into the assertion.** The clinician resolves the
identifier upstream of signing via a name + DOB lookup in the clinician
portal (ADR-0033, step 0 of the break-glass sequence above). Identification
is not authorization: picking a candidate from the search results releases
no key, and the five validation checks and threshold gate below are the
things that actually decide access. PII (name, DOB) lives only in the
portal DB, never in the crypto store (ADR-0011), and that includes the audit
chain: a lookup entry records the candidates and the selection, nothing about
what was typed, not even a hash (ADR-0085). The chain is pseudonymous, not
anonymous: it names patients by `patient_id`, which links to a person only
through the portal DB, so `patient_id` must never be derived from PII.

### Replay protection

Emergency assertions, share requests, transition events and every
service-to-service request each carry a one-time ID. A consumed-ID store
rejects reuse. Without this, a captured break-glass request could be replayed
for repeated emergency sessions, which would defeat the time-boxing that the
state machine exists to enforce.

### Service identity and signed requests

Every federation process (facilities, the audit service, the authorities, the
custodian, the portal and the bootstrap job) holds a key and a certificate
signed directly by the federation root: CN = service id, OU =
`service:<kind>`. Every call between them carries that certificate and a
signed one-time `RequestEnvelope` binding caller, recipient, method, path,
body and time; the body itself travels unchanged. The callee checks all of it
before any route code runs, then allows the call only if the route permits the
caller's kind (ADR-0066, reversing the service-signing cut of ADR-0015). The
portal's key identifies the portal process; it is not a subject's key and
opens nothing, so ADR-0014 stands.

### Object-level authorization
Endpoints authorise the caller for the *specific* patient/record before doing
work: only a key agent may read, and a requester presenting no attribute key
is refused before the record, its wrapping or its policy is loaded
(ADR-0066). The cryptographic layer is the real backstop: an unauthorised
caller cannot decrypt regardless. This is verified by a **test** in the
security suite (P5-1, claim C9).


### Credential lifecycle

Clinician and authority credentials carry issuer, subject, serial,
`valid_from`, `valid_until`, and status. Expired or revoked credentials fail
validation. A system whose central claim is that revocation is part of a unified
key lifecycle cannot coherently issue credentials that never expire.

Revoking a credential stops the authority releasing its attribute key again; it
does not revoke a key already released. Attribute keys are one per value,
shared by every holder and never rotated, so a holder who kept one still
satisfies the leaves it names, including after record rotation. Stated as a
limitation (`PROJECT.md` §5 item 9, ADR-0075); epoch-versioned keys are future
work.


### Deliberately excluded

Rate limiting, CORS, security headers, session management, MFA, brute-force
lockout, API versioning, and operational monitoring. There is no browser client,
no public exposure, and no user population — these controls would protect
nothing here while consuming hours from the cryptographic core that constitutes
the project's contribution. Rationale recorded in `PROJECT.md` §4B.
