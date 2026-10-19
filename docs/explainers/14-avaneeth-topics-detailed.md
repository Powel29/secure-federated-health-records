# 14. Avaneeth's topics in detail

Your slot in `11-independent-topics.md`: about 6 minutes, four topics of about
1.5 minutes each, plus the rubric slides you own (ER diagram, literature table,
Phases 0 to 6 plan, screenshot set). Story order: **how a record is protected,
how an emergency is proven, how the patient controls access, and how the API stays
thin.**

Your concepts from file 11: AES-256-GCM, DEK, key wrapping, the crypto rules,
consent grants, who may revoke, the emergency assertion and replay protection.

---

## Topic 1. Record protection (AES, DEK, wrapping)

**One sentence.** Every record is encrypted with its own random key, and that key
is itself locked ("wrapped") so only authorised parties can unlock it; the
database stores only ciphertext.

**Analogy.** Each record is in its **own locked box** (the DEK is the box key).
The box key is then put in a **second lockbox** that only the right people can
open (wrapping). Stealing the warehouse gets you locked boxes and locked keys.

### AES-256-GCM (`src/crypto_core/symmetric.py`)

- **AES-256**: a block cipher with a 256-bit key.
- **GCM** adds **authentication**: the output ciphertext carries a tag. Any change
  to the ciphertext, the nonce, or the associated data makes decryption fail. So
  it gives confidentiality **and** tamper detection.
- **Nonce:** `aes_gcm_encrypt` **generates a fresh 12-byte random nonce itself and
  returns it**. The caller cannot pass one in (ADR-0022). Reusing a nonce under one
  key breaks GCM completely, so the API removes that mistake.
- **AAD (associated data):** extra data that is authenticated but not encrypted.
  Used to bind a ciphertext to its context.
- `aes_gcm_decrypt` raises `InvalidTagError` on any mismatch. It never returns
  partial plaintext. Key length is checked (32 bytes).
- Also in this file: `generate_key` (CSPRNG via `secrets`), `hkdf_derive`,
  `sha256_digest`. All crypto primitives live in `crypto_core` only.

### Envelope encryption (`src/records/service.py`)

| Function | What it does |
|---|---|
| `encrypt_record` | Make a fresh 32-byte **DEK**; AES-GCM encrypt the payload; return the `Record` (ciphertext, nonce, aad, ids) and the DEK |
| `decrypt_record` | Decrypt with the DEK; wrong key or tamper raises `DecryptionError` |
| `wrap_dek` | Encrypt the DEK under a **wrapping key** (policy root secret or emergency key) with **`record_id` as AAD**, and a `generation` counter |
| `unwrap_dek` | Reverse; failure raises `UnwrappingError` |
| `rewrap_dek` | Unwrap with the old key, wrap with the new, `generation + 1` |

**Why bind `record_id` as AAD?** A wrapped DEK copied from record A cannot be
substituted into record B: the tag would fail. This blocks cross-record swaps.

**Where the DEK is never stored in clear:** the store keeps `records` (ciphertext)
and `dek_wrappings` (wrapped DEKs). Tables: `src/storage/migrations/0001_initial.sql`
(authorities, facilities, patients, attributes, records, dek_wrappings,
lifecycle_state, transition_events, audit_log, search_index) and
`0002_consumed_ids.sql`. This is your ER diagram.

### Ingest (`src/records/ingest.py`, `ingest_record`)

Seven steps:
1. Fresh DEK, encrypt the plaintext.
2. Author the policy: `OR(clinical policy, owner:<patient_id>)`.
3. Fresh root secret; `compile_policy` over the attribute keyring.
4. Wrap the DEK under the root secret.
5. Derive search tokens for any search terms (from the emergency key).
6. Lifecycle starts at `GRANTED`.
7. Return everything as a frozen `IngestResult`. **It does not touch the database
   or the audit service**; the caller persists. That keeps it testable without
   Postgres.

### The crypto rules (CONVENTIONS.md §2)

Know the ones you can name: all primitives only through `crypto_core` (no direct
`hazmat` elsewhere); randomness only from the CSPRNG; no key material in logs or
audit entries; fresh nonce and key per use; fail closed; no cryptography inside
API route handlers. The last two are enforced by
`tests/api/test_no_crypto_invariant.py`, which parses every file in `src/api/`
with `ast` and fails if it imports `cryptography.hazmat` or calls
`aes_gcm_encrypt`, `aes_gcm_decrypt`, `hkdf_derive`, `split_secret`,
`combine_shares`, `encapsulate_key`, `decapsulate_key` or `reencrypt`.

**Say in 90 seconds.**
"One fresh 256-bit key per record, AES-256-GCM with a fresh random nonce and an
authentication tag, so any tampering fails. The key is wrapped under the policy
root secret with the record id as associated data, so wrappings cannot be swapped
between records. The store holds only ciphertext and wrapped keys. Ingest returns
everything as one object and persists nothing itself."

**Limit to admit.** The wrapping key is only as safe as who can reconstruct it
(that is Powel's policy tree). Python cannot zeroize memory (ADR-0035).

**Likely questions.**
- *Why a DEK per record rather than one key?* A compromise or a revocation affects
  one record, and rotation is cheap.
- *Why GCM, not CBC?* GCM authenticates; CBC alone does not detect tampering.
- *What if two records share a nonce?* Different DEKs make that harmless, and the
  nonce is random 96 bits anyway.

**Tests.** `tests/records/`, `tests/security/test_phase3_ingest_security.py`.

---

## Topic 2. Emergency Assertion, patient binding, replay protection

**One sentence.** To break the glass, a clinician signs a short-lived statement
naming the patient, themselves and the facility; the facility checks that
statement six ways and burns its one-time id so it cannot be used twice.

**Analogy.** A **signed, dated, numbered permission slip** for one named patient,
to one named building. The guard checks the signature, the ID card, the building,
the date, then **tears off the numbered stub** so the slip cannot be reused.

### What the assertion contains (`src/breakglass/assertion.py`)

`assertion_id` (UUID), `patient_id`, `clinician_id`, `facility_id`, `reason_code`,
`issued_at`, `expires_at` (default 15 minutes), a 16-byte `nonce`, and an ECDSA
signature over all of them joined with `0x1f`. Changing any field breaks the
signature.

### Validation: `validate_emergency_assertion`, in order

1. **Signature** verifies against the clinician certificate's public key.
2. **Certificate chain** reaches the trusted root via the facility CA
   (`validate_chain`, Ojas's code).
3. **Clinician binding:** `clinician_id` equals the certificate's common name
   (else `ClinicianMismatchError`).
4. **Facility binding:** `facility_id` equals the receiving facility
   (`FacilityMismatchError`).
5. **Expiry:** `expires_at` is in the future (`AssertionExpiredError`).
6. **Replay:** `assertion_id` is consumed (`ReplayedAssertionError`).

Order matters: signature first, so a tampered assertion is reported as tampered.
**Consumption is last**, so a forged assertion cannot burn a legitimate id.

### Patient binding (ADR-0044, the bug #1 fix)

In `src/api/hospital.py` (`breakglass_unlock`), after the assertion validates and
the record is fetched:

```
if record.patient_id != payload.assertion.patient_id:
    log denial ("breakglass_patient_binding")
    raise 403
```

An assertion opens **the patient it names and nobody else**. It is checked
**before** any lifecycle change, so a mismatch has no side effect. Before this fix
an assertion for patient X could open patient Y's record: found by the stress
test.

### Replay protection (`src/breakglass/replay.py`)

- `ConsumedAssertionIds` and `ConsumedRequestIds` share a base: a lock, an
  in-memory set, and an optional **durable backend**.
- `consume(id)` succeeds once; every later call raises. It never returns a boolean,
  so the caller cannot accidentally fail open.
- With the storage repository as backend (`consumed_ids` table, migration
  `0002`), the consumed set survives a restart (review fix **F22**). Test:
  `test_c8_replayed_assertion_rejected_after_facility_restart`.
- The lock stops two threads both passing the check for one id (review fix F12).

**Say in 90 seconds.**
"The assertion is signed by the clinician and names patient, clinician, facility,
reason, and a 15-minute expiry. The facility checks signature, certificate chain,
that the clinician matches the certificate name, that the facility is itself,
expiry, and replay. The one-time id is consumed last, and stored durably so a
restart does not reopen replay. We also found and fixed that an assertion for one
patient could open another's record; now it returns 403 and logs a denial."

**Limits to admit.**
- A signed assertion proves the clinician *claimed* an emergency. It does not prove
  there was one. The control is that it is signed, logged, time-boxed and
  reviewable, not that it is verified true.
- **Claim C7 (finding D8/F11):** the break-glass lifecycle event is signed with a
  caller-supplied lifecycle key, not the clinician's own key, so who opened it
  cannot be verified from the event alone. The assertion itself *is* signed by the
  clinician. Do not blur the two.
- Clock skew handling is an open team decision.

**Likely questions.**
- *Why 15 minutes?* A short window limits theft of a captured assertion; replay
  is separately blocked by the one-time id.
- *What if an attacker captures it before use?* They would also need the shares
  and a valid facility; that is why shares come from separate parties.
- *Why consume last?* So forgeries cannot burn real ids.

**Tests.** `tests/security/test_phase3_assertion_security.py` (claim C8),
`tests/api/test_breakglass.py`.

---

## Topic 3. Consent and the patient side

**One sentence.** Before the crypto path even starts, the patient's signed grant
must say yes; and only the patient or their home authority can revoke.

**Analogy.** A **signed permission letter** from the patient. The hospital front
desk checks the letter first (consent gate); then the vault still has its own lock
(policy tree). Both must pass: consent is **necessary, not sufficient**.

### Signed grants (`src/consent/service.py`)

- `create_consent_request`: a clinician (grantee) asks for access to records.
- `create_consent_grant`: the patient signs a decision (GRANTED or DENIED) with
  scope (list of record ids), grantee, and an expiry.
- Everything is ECDSA-signed over a `0x1f`-joined payload, the same construction as
  the assertion and the state machine.
- **`revoke_consent_grant`**: grants are immutable signed objects, so revocation is
  a **new patient-signed grant with status REVOKED** for the same request. Only the
  patient's key makes a valid one, so "patient-only revocation" is cryptographic,
  not a policy check.

### The read-time gate: `authorize_read`

Fail closed in order:
1. Patient signature verifies (`InvalidSignatureError`).
2. Status must be GRANTED; DENIED and REVOKED each have a named error
   (`ConsentDeniedError`, `ConsentRevokedError`) so the audit entry says what
   happened.
3. Inside the time window (`ConsentExpiredError`).
4. Reader equals grantee (`ConsentSubjectError`).
5. Record is in scope (`ConsentScopeError`).

`read_record_under_consent` then runs the **single decryption path**:
`authorize_read`, then `unwrap_dek_via_policy`, then AES-GCM decrypt (ADR-0016).
There is no side door to a DEK.

### Who may revoke the *record's* access (key rotation)

`check_revocation_authorization` in `src/records/revocation.py` allows only the
record's patient or the patient's home authority. A clinician with a valid key and
signature is still refused (`UnauthorizedRevocationError`). (This calls into
Powel's rotation.)

### The patient portal (`portal/patient/views.py`)

`decide` (approve or deny a request), `revoke`, `access`, `history`, `home` with
notifications, `records` / `record_view`, `upload`. The portal **identifies** the
patient but the signing is done by the Key Custodian on their behalf (ADR-0043).
**Patient self-access:** the policy tree always has an `owner:<patient_id>` leaf
(ADR-0016), so the patient reads their own record through the same key path as a
doctor, with the key held by the custodian.

**Say in 90 seconds.**
"Consent is a signed grant with scope, grantee and expiry. Before any crypto
starts, five checks: signature, status, time window, grantee, scope. Revoking is a
new signed grant, so only the patient can do it. Consent alone does not open a
record: the policy tree is the second lock. Live: `house` has consent but is
refused on `rec-002`; `david` reads his own record through the owner attribute."

**Limits to admit.**
- The Key Custodian is one shared process in the demo; real patients would hold
  their own keys.
- A rogue home authority could mint a patient's owner key (threat model C).
- Portal login alone releases nothing: if it ever did, the novelty would be gone
  (claim C11 holds).

**Likely questions.**
- *Why not store consent in the database?* A DB flag can be edited by an admin;
  a patient-signed grant cannot be forged.
- *Why separate revoke by key rotation and consent revoke?* Consent revoke stops
  the gate; rotation removes the cryptographic capability. Both exist.
- *Can the patient lose access to their own record?* No; the owner leaf is
  re-added at every rotation.

**Tests.** `tests/security/test_phase3_consent_security.py`,
`tests/consent/`.

---

## Topic 4. Thin API, normal read, portal boundary

**One sentence.** The hospital API only orchestrates (find, check, call a module,
log); all cryptography lives in modules, and portals and the database never decide
access.

**Analogy.** A **receptionist** who routes you but does not hold the vault keys,
cannot open the vault, and writes your visit in the log before letting you through.

### The normal read: `POST /records/{record_id}/read` (`src/api/hospital.py`)

1. Load record, wrapping, compiled policy (404 / 500 if missing).
2. Parse the caller's attribute keyring.
3. **If a consent grant is attached:** `read_record_under_consent`. Otherwise
   (owner access or in-network read): `unwrap_dek_via_policy` then `decrypt_record`.
4. On denial (consent or policy): **log the denial to the audit service**, return
   **403**. A failed audit write is tolerated for the denial so the 403 is never
   masked (`_log_denial`).
5. On success: **`_log_granted` before returning plaintext.** If the audit chain
   is unreachable the read returns 503, not the record (log-before-release again).

### Why "thin"

`tests/api/test_no_crypto_invariant.py` makes this a CI-enforced rule: no `hazmat`
imports and no direct cipher calls in `src/api/`. Handlers call `records.service`,
`policy.engine`, `consent.service`, `breakglass.*`.

### The Key Custodian (`src/api/custodian_service.py`, ADR-0043)

One process standing in for every subject's key agent (smartcard, enclave). It
holds signing keys, certificates, PRE keys, credentials; **signs on request and
returns the signed artifact, never a key**; calls federation endpoints on the
subject's behalf. Its endpoints come from configuration, never request data (rule
8). A portal account with no material at the custodian gets 404 and nothing
decrypts: "a portal account alone grants zero access."

### Portal boundary (ADR-0014 / 0021 / 0043)

- Portals identify users and display data.
- `portal/sql/roles.sql` creates `portal_ro` with **SELECT only** on the store
  tables. The boundary is a **Postgres permission**, not a convention.
- A portal login or database check must never release a key. Keys and the Shamir
  threshold gate decide.

**Say in 90 seconds.**
"The read path: find the record, check consent if present, rebuild the key through
the policy tree, decrypt, and log before returning. Denials are logged and return
403. The API calls modules; a test parses every file in `src/api/` and fails if a
handler touches a cipher. The portals use a read-only database role and a custodian
for keys, so a login alone releases nothing."

**Limits to admit (claim C9, finding F34/D5).** `read_record` loads the record,
wrapping and policy *before* any caller authorisation check, and `requester_id` is
self-declared in the request body. So an authenticated-but-unauthorised caller is
not denied before crypto and DB work. The cryptographic layer still refuses
(they lack the keys), but the endpoint check is missing. This is the one slide
where a reviewer will push; say it before they do.

**Likely questions.**
- *If the audit service is down, can I read?* No; the read returns 503. Denials are
  still returned as 403 with a warning.
- *Who can see the plaintext?* The caller only; the portal gets it via the
  custodian, and nothing is stored in clear.
- *Why not have the portal check permissions?* Then a bug in the portal opens
  records. Keys must be the gate.

**Tests.** `tests/api/test_no_crypto_invariant.py`, `tests/api/test_hospital.py`,
claim C9 (xfail today, honestly).

---

## Diagrams for your slides

1. **ER diagram (main).** Tables from `0001_initial.sql`: patients, records,
   dek_wrappings, lifecycle_state, transition_events, audit_log, search_index,
   authorities, facilities, attributes; plus `consumed_ids`. Mark `records` and
   `dek_wrappings` as "ciphertext only".
2. **Envelope diagram.** Plaintext, AES-GCM with DEK, ciphertext; DEK wrapped under
   the root secret (AAD = record id); root secret reconstructed through the policy
   tree.
3. **Assertion-validation flowchart.** Six checks in order, each with its error;
   consume last; a separate branch for the patient-binding 403.

## Your demo

As `david`: view the own record on the encrypted-records page (ciphertext, then
readable via the owner leaf); approve or deny a request; show a wrong-patient
break-glass refused with 403 and a denial in the chain.

## Rubric slides you own

- **ER diagram** (above).
- **Literature table and gap:** break-glass and EHR access control papers
  (see `PROJECT.md` §4 for the papers extended), what each lacks (log-as-
  precondition, unified lifecycle), where we fit.
- **Phases 0 to 6 plan:** from `WORKFLOW.md`; phases are gated by exit criteria, not
  dates. State the current phase honestly: Phases 0 to 4 done; Phase 5 merged to `main`
  but its gate is not passed (5 of 11 claims green, clock-skew decision open,
  analysers not yet run on real captures); Phase 6 paper and rehearsal next.
- **Screenshot set:** refused read, break-glass case page, chain PASS. Keep these
  as the fallback if a live step fails.

## Cross-cutting rules for you

- End your slot with a hand-off: "and the search that stops at expiry is
  Nandini's."
- State your limits unprompted: the C9 gap, the C7 signing key, custodian
  simplification.
- Ownership drift: you shipped P3-10/11/14 even though `WORKFLOW.md` lists some as
  Powel's. Say "the team built it" if asked, but you can explain them all.

## Answer-routing

| If asked about | You answer |
|---|---|
| AES-GCM, DEK, wrapping, ingest, crypto rules | Yes |
| Emergency assertion, patient binding, replay | Yes |
| Consent, who may revoke, patient portal | Yes |
| Thin API, normal read, custodian, read-only role | Yes |
| State machine, Shamir, policy tree, 2-of-3 gate | Powel |
| PKI, audit chain, PRE, deployment, threat model | Ojas |
| Search, expiry, discovery, wire analysis, benchmarks | Nandini |
