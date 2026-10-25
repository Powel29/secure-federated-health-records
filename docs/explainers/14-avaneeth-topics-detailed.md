# 14. Avaneeth's topics in detail

Your slot in `11-independent-topics.md`: about 6 minutes, four topics of about
1.5 minutes each, plus the rubric slides you own (ER diagram, literature table,
Phases 0 to 6 plan, screenshot set). Story order: **how a record is protected,
how an emergency is proven, how the patient controls access, and how the API stays
thin.**

Your concepts from file 11: AES-256-GCM, DEK, key wrapping, the crypto rules,
consent grants, who may revoke, the emergency assertion and replay protection.

> **Source of truth:** the IEEE paper (`paper/build/main.pdf`, commit `57a1a8c`).
> Yours: Section V-B/C (signed transitions, access structure), VI-A (Emergency
> Assertion and Replay), IV (what portals and Postgres may not do), C8, C9, C11 in
> Section VII, and Section IX's ciphertext-expansion figure. Files 16 and 17 map them.

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
(that is Powel's policy tree). Python cannot zeroize memory (ADR-0035). **The record
payload is encrypted without associated data; only the DEK wrapping binds record, policy
and generation** (paper "further limits"). Leaf ciphertexts in the policy tree also
carry no AAD.

**Cost (paper Section IX).** Ciphertext expansion is a **constant 16 bytes, the GCM
tag**: 25 % at 64 B, 6.25 % at 256 B, 1.56 % at 1 KiB, 0.39 % at 4 KiB, **under 0.1 %
at 16 KiB**. It excludes what is stored beside the payload: the 12-byte nonce, two
48-byte DEK wrappings, the compiled policy, a 66-byte share per x and the search index.

**Likely questions.**
- *Why a DEK per record rather than one key?* A compromise or a revocation affects
  one record, and rotation is cheap.
- *Why GCM, not CBC?* GCM authenticates; CBC alone does not detect tampering.
- *What if two records share a nonce?* Different DEKs make that harmless, and the
  nonce is random 96 bits anyway.

**Tests.** `tests/records/`, `tests/security/test_phase3_ingest_security.py`.

---

## Topic 2. Emergency Assertion, patient binding, replay protection

**One sentence.** To break the glass, a clinician's key agent signs a short-lived
statement naming the patient, the clinician, the facility and the record's justification;
the facility, the audit service and the home authority each check it independently, and
each burns its one-time id so it cannot be used twice.

**Analogy.** A **signed, dated, numbered permission slip** for one named patient, to one
named building. Three guards (facility, notary, home authority) each check the signature,
the ID card, the building and the date, then each **tears off its own numbered stub** so
the slip cannot be reused.

### What the assertion contains (`src/breakglass/assertion.py`)

`assertion_id` (UUID, one-time), `patient_id`, `clinician_id`, `facility_id`,
`reason_code` (closed enum of 13), `issued_at`, `expires_at`, a **nonce of at least 128
bits** (16 bytes drawn from `secrets`), an optional **`clinical_context_digest`**
(`SHA-256` over record id, justification and sensitive-label text, **which the share
holders require**), and an **ECDSA P-256 signature** over all other fields by the
clinician's key, **which never leaves the custodian**. The signed bytes are
domain-tagged and length-prefixed (ADR-0077). The maximum lifetime is **15 minutes**;
the custodian requests **120 s** by default and refuses more than 15 min.

### Validation: `validate_emergency_assertion`, in order (paper Section VI-A)

It fails closed at the **first failing check**:

1. **Signature** against the certificate's public key.
2. **Certificate chain** via a facility CA to the trusted root (`validate_chain`,
   Ojas's code).
3. **Clinician binding:** `clinician_id` equals the certificate's common name
   (`ClinicianMismatchError`).
4. **Certificate not revoked.**
5. **Facility binding:** at the facility, equals the receiving node
   (`FacilityMismatchError`); at the audit service and home authority, only that it is a
   federation member.
6. **Not expired** (strict `expires_at <= now` is expired).
7. **Lifetime <= 15 min** and `issued_at` at most **30 s** in the future (clock skew).
8. **Consumption** of `assertion_id` (`ReplayedAssertionError`).

Order matters: signature first, so a tampered assertion is reported as tampered.
**Consumption is last**, so an invalid assertion cannot burn a legitimate id, and the
consumed store is a **required argument** that cannot be omitted.

### Three independent validators

The **facility, the audit service and the home authority** each validate against **their
own trust anchors** and consume the id in **their own store** (durable at the facility
and the audit service, in memory at the authority). So a reused assertion gets **no
shares 3 and 4, even after an authority restart** (claim C8). The audit service and the
home authority run identical shared code (`src/api/share_release.py`). The transition
event and every signed service request also carry one-time ids.

### Patient binding (ADR-0044, the bug #1 fix)

In `src/api/hospital.py`, after the assertion validates and the record is fetched:

```
if record.patient_id != payload.assertion.patient_id:
    log denial ("breakglass_patient_binding")
    raise 403
```

An assertion opens **the patient it names and nobody else**. It is checked **before**
any lifecycle change, so a mismatch has no side effect. **Important nuance (paper):**
*no share holder checks that the record belongs to the assertion's patient*; **the
facility does**, as does the custodian when it can load the record. The facility also
checks the **clinical-context digest** (a mismatch is a 403 audited as
`clinical_context`) when the record's disclosure rules need a justification or the
assertion carries a digest. `facility_id` means the record's own facility (the custodian
routes the break-glass there), so the facility binding checks routing, not where the
clinician physically is.

### Replay protection (`src/breakglass/replay.py`)

- `ConsumedAssertionIds` and `ConsumedRequestIds` share a base: a lock, an in-memory set,
  and an optional **durable backend**.
- `consume(id)` succeeds once; every later call raises. It never returns a boolean, so
  the caller cannot accidentally fail open.
- With the storage repository as backend (`consumed_ids` table), the set survives a
  restart. Test: `test_c8_replayed_assertion_rejected_after_facility_restart`. Replay is
  also refused at the home authority and across processes on Postgres.
- The lock stops two threads both passing the check for one id.

**Say in 90 seconds.**
"The assertion is signed by the clinician's key, which never leaves the custodian, and
names patient, clinician, facility, a reason from a closed list, a lifetime of at most
fifteen minutes and a digest binding the record and justification. The facility, the
audit service and the home authority each check it against their own trust anchors in a
fixed order: signature, certificate chain, clinician name, revocation, facility, expiry,
lifetime and skew, and only then do they consume the one-time id, so a forgery cannot
burn a real one. The facility alone checks that the record belongs to the named patient:
we found and fixed that an assertion for one patient could open another's record."

**Limits to admit.**
- A signed assertion proves the clinician *claimed* an emergency, not that there was one.
  The control is that it is signed, logged, time-boxed and reviewable, not verified true.
- No share holder checks the patient binding; the facility (and the custodian) do.
- The home authority keeps its consumed ids in memory only.
- Closed since the first review: the break-glass transition event used to be signed with
  a caller-supplied key (claim C7, finding D8/F11). It is now **signed with the
  clinician's own key inside the custodian** and verified against the clinician's
  certificate (ADR-0068), so C7 holds. Do not blur the event signature with the
  assertion signature: they use different domain tags.

**Likely questions.**
- *Why 15 minutes?* A short window limits theft of a captured assertion; replay is
  separately blocked by the one-time id. The custodian asks for 120 s by default.
- *What if an attacker captures it before use?* They would also need the shares and a
  valid facility; shares come from separate parties, and sealed to the gate.
- *Why consume last?* So forgeries cannot burn real ids.
- *Why three validators?* Each holder must be able to refuse on its own trust anchors;
  a compromised facility cannot talk the audit service into releasing.

**Tests.** `tests/security/test_phase3_assertion_security.py` (claim C8),
`tests/api/test_breakglass.py`.

---

## Topic 3. Consent and the patient side

**One sentence.** When a patient-signed grant is presented, the facility checks it
(status, window, signature, grantee, scope) before the crypto path; consent is **not** a
lifecycle state; and in this build only the patient revokes.

**Analogy.** A **signed permission letter** from the patient. The hospital front
desk checks the letter first (consent gate); then the vault still has its own lock
(policy tree). Both must pass: consent is **necessary, not sufficient**.

### Signed grants (`src/consent/service.py`)

- `create_consent_request`: a clinician (grantee) asks for access to records.
- `create_consent_grant`: the patient signs a decision (GRANTED or DENIED) with
  scope (list of record ids), grantee, and an expiry.
- Everything is ECDSA-signed over a domain-tagged, length-prefixed payload (ADR-0077),
  the same construction as the assertion and the state machine.
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

`check_revocation_authorization` in `src/records/revocation.py` accepts the record's
patient or the patient's home authority; a clinician with a valid key and signature is
refused (`UnauthorizedRevocationError`). **But the deployed facility endpoint verifies a
patient-signed transition only**, so **in this build only the patient revokes**
(ADR-0084); home-authority revocation is future work, and a patient who cannot sign has
no path. (This calls into Powel's full rotation.)

**Consent is not a lifecycle state (paper Section V-A).** Grants do not move the
state, and the consent module does not wrap or re-wrap records. The portal's mirrored
consent rows are display data that no read path consults.

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
  (claim C11 holds: the custodian refuses a patient without an owner credential, and
  only the home authority issues that key).

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

**Claim C9 (was finding F34/D5, now closed by ADR-0066).** An authenticated but
unauthorised caller is denied **before any crypto or database work**. Every service
call carries a **root-issued service certificate and a signed one-time request
envelope** (age <= 120 s, 30 s skew, the operation `"<METHOD> <path>"` must match),
checked **before any route code runs**; key-bearing facility routes admit only the
custodian or bootstrap, a portal may not request an audit share, and an unsigned
request is refused. **C9 has no module-level test** (system tests only: 3). This is the
slide a reviewer will probe: say that C9 is evidenced at system level only.

**Other limits.** The federation services connect to Postgres as the `postgres`
superuser; only the portal is role-restricted. Local HTTP TLS is self-signed and
server-only.

**Likely questions.**
- *If the audit service is down, can I read?* No; the read returns 503. Denials are
  still returned as 403 with a warning.
- *Who can see the plaintext?* The caller only; the portal gets it via the
  custodian, and nothing is stored in clear.
- *Why not have the portal check permissions?* Then a bug in the portal opens
  records. Keys must be the gate.

**Tests.** `tests/api/test_no_crypto_invariant.py`, `tests/api/test_hospital.py`,
claim C9 (holds; system-level only).

---

## Diagrams for your slides

1. **ER diagram (main).** Tables from `0001_initial.sql`: patients, records,
   dek_wrappings, lifecycle_state, transition_events, audit_log, search_index,
   authorities, facilities, attributes; plus `consumed_ids`. Mark `records` and
   `dek_wrappings` as "ciphertext only".
2. **Envelope diagram.** Plaintext, AES-GCM with DEK, ciphertext; DEK wrapped under
   the root secret (AAD = record id); root secret reconstructed through the policy
   tree.
3. **Assertion-validation flowchart.** The eight ordered checks (signature, chain,
   clinician = CN, not revoked, facility, not expired, lifetime/skew, consume), each with
   its error; consume last; three validators (facility, audit, home authority); a
   separate branch for the patient-binding 403.

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
  dates. State the current phase honestly from `WORKFLOW.md`: the paper reports all 11
  claims holding on commit `57a1a8c` with PyShark checks run on real captures; Phase 6
  (paper, rehearsal twice, recorded fallback video) is what remains.
- **Screenshot set:** refused read, break-glass case page, chain PASS. Keep these
  as the fallback if a live step fails.

## Cross-cutting rules for you

- End your slot with a hand-off: "and the search that stops at expiry is
  Nandini's."
- State your limits unprompted: payload has no AAD, the assertion proves a claim not an
  emergency, C9 is system-level evidence only, the custodian simplification, only the
  patient can revoke.
- Ownership drift: you shipped P3-10/11/14 even though `WORKFLOW.md` lists some as
  Powel's. Say "the team built it" if asked, but you can explain them all.

## Answer-routing

| If asked about | You answer |
|---|---|
| AES-GCM, DEK, wrapping, ingest, crypto rules | Yes |
| Emergency assertion, patient binding, replay | Yes |
| Consent, who may revoke, patient portal | Yes |
| Thin API, normal read, custodian, read-only role | Yes |
| State machine, Shamir, policy tree, weighted 3-of-4 gate | Powel |
| PKI, audit chain, PRE, deployment, threat model | Ojas |
| Search, expiry, discovery, wire analysis, benchmarks | Nandini |
