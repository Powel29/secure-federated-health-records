# Fix proposals — whole-repo review (2026-10-07, HEAD `3c42094`)

**To:** Powel, Nandini, Ojas, Avaneeth
**From:** Avaneeth (review run with Claude Code)
**Status:** draft for review. Nothing here is implemented.

Every item comes from a four-way review of the whole repo (standards ×
spec, core modules × api/portal/deploy). Smells are left out; this covers
rule violations and bugs only.

## How to review

- **Everyone:** §0 lists eleven design decisions (D1–D11). They need a team
  answer before the fixes that depend on them can start. Please each read §0
  before the next sync.
- **Each person:** the last section lists your fixes by name. Reply per ID
  with **approve**, **reject** or **change** (e.g. "F9 → option b").
- Items marked **⚑ needs D#** can't be coded until that decision is made.
  The `crypto-implementation` rule applies: where the architecture does not
  already specify a construction, this doc names the options and does **not**
  pick one silently.
- **Owner** comes from `WORKFLOW.md` and `git log`. Under CONVENTIONS §3,
  each fix goes to its owner as an issue or a proposal PR; nobody edits
  another person's module.
- **ADR** = needs a new ADR (or amends one) under the standing rule.
- Effort: S ≤ 2h, M ≈ half a day, L ≥ 1 day.

---

## 0. Design decisions needed first

| ID | Decision | Current state | Options | Recommendation |
|---|---|---|---|---|
| **D1** | Who checks the Emergency Assertion before share 3 is released? | Nobody. The audit service releases share 3 to any caller that knows the `share_key` (= record_id). The custodian asks for it *before* the facility has checked anything, and ADR-0044 accepts that order. | (a) The audit service checks it itself, against its own trust anchor, before commit-then-release. (b) The facility pre-checks it first and the custodian calls audit afterwards. | **(a)**. A share holder that releases without checking anything is the actual hole; ordering at the custodian doesn't fix that. Amend §8 to say "each share holder validates before release". Supersede ADR-0044's acceptance of the current ordering. |
| **D2** | Share 2 (home authority) | Generated at ingest and thrown away (`custodian_service.py:764`). Break-glass is effectively 2-of-2: custodian (share 1) + audit service (share 3). | (a) Deposit share 2 with the patient's home-authority service and gate its release the same way as share 3. The gate then accepts any 2 of {1,2,3}. (b) Amend §5 and the paper to say "2-of-2 custodian + audit; share 2 reserved". | **(a)** if time allows, since the paper claims 2-of-3 with a delegate fallback. Otherwise (b) and state it honestly. |
| **D3** | What does "forced rotation" on expiry (and on revocation) actually rotate? | Nothing. Expiry computes a rotated record and wrapping, then discards them; the custodian sends a random "baseline key". Old shares, the emergency wrapping and search tokens all keep working. Revocation rotates the DEK but crashes on Postgres and leaves the emergency wrapping on the old DEK. | (a) **Full**: new DEK, re-encrypt, re-author the policy root secret (needs authoring keys from the authorities), new emergency key with re-split and redistributed shares, re-index search. (b) **Emergency path only**: replace the emergency wrapping with a fresh emergency key and new shares, and re-key search tokens. The DEK is not rotated; state that as a limitation. | **(b) now, (a) as stretch.** Today *nothing* is rotated (F9). (b) is achievable at the facility (it holds the DEK during the session), kills old shares and tokens, and is honest. (a) needs a facility→authority authoring call (depends on D5). |
| **D4** | Trusted source of **patient** public keys | There isn't one. The caller sends the patient's public key in the request body (consent read, grant submit), so a self-signed grant passes. Revocation trusts a caller-supplied `actor_id`. Revoking a grant sends the patient's *private* key to the facility. | (a) The home facility CA issues each patient an X.509 cert at enrolment, validated against the configured root like clinicians. (b) A registry at the home authority that signs (patient_id → public key) bindings. | **(a)**. It reuses `identity` and the F1 trust anchor and adds no new construction. Unblocks F10, F13, F15. |
| **D5** | Service-to-service authentication | None. Every service is unauthenticated and listens on all interfaces; Compose publishes every port. `requester_id` / `subject_id` are whatever the caller types. `breakglass/envelopes.py` exists but nothing calls it. | (a) Every inter-service call carries a signed `RequestEnvelope` (the existing contract and `breakglass/envelopes.py`, currently unused), signed by a service key with a bootstrap-issued cert, with one-time `request_id`. (b) Network-only: bind to loopback / Compose internal network, and document "no exposure" as an assumption. | **(b) immediately (F16), then (a)**. (a) also satisfies §2 rule 9 for share requests and gives BOLA (F34) a caller identity. |
| **D6** | PROJECT §4A property 1 ("no PHI, DEKs, attribute keys or shares in the clear") vs. the current wire design | The facility decrypts and returns `plaintext_b64`. Ingest sends the plaintext and the full emergency key. Attribute keys, shares and two private keys travel in request/response bodies. The analyser checks none of this and prints "PASSED". | (a) **Client-side crypto**: the custodian decrypts and encrypts. The facility returns ciphertext + wrapping, ingest sends ciphertext + wrappings, and shares are delivered wrapped to the recipient's key using the existing `encapsulate_key` + AES-GCM delivery pattern the gate already uses. (b) Narrow property 1 to the five federation services, exclude the custodian↔facility hop, and force TLS on it. | **(a)** is what the claim needs; it is large (L, three owners). **(b)** is the fallback if time runs out, written into the paper as scope. Either way the analyser (F18) must test whatever claim is kept. |
| **D7** | Where expiry returns a record that was REVOKED before break-glass | Expiry always ends at `GRANTED`, so REVOKED → break-glass → expiry silently un-revokes the record. ADR-0044's reset writes `granted` too. | (a) Add `EXPIRED → REVOKED` to `LEGAL_TRANSITIONS`; the session remembers `prior_state`. (b) Forbid break-glass on REVOKED records. | **(a)**. Break-glass on a revoked record is an intended legal transition today; it must not silently un-revoke. |
| **D8** | Who signs the break-glass `TransitionEvent` | A throwaway keypair minted per unlock (`custodian_service.py:926`). Its private key is sent to the facility, and nobody can verify the event afterwards. | (a) The custodian signs it **inside the custodian** with the clinician's key and sends only the signed event; the facility verifies it against the cert already validated by F1. (b) A facility service key signs as witness. | **(a)**. The clinician's key never leaves the custodian (ADR-0043), and the event becomes verifiable (today it is signed with a throwaway key). |
| **D9** | Fix for ambiguous signed payloads | Seven modules join fields with `0x1f`, with no length prefix and no type tag. `Identifier` allows `0x1f`, so one set of signed bytes can be read as different fields. The same clinician key signs assertions and transition events. | (a) A length-prefixed encoding with a per-type domain tag, in `crypto_core`. (b) Forbid `0x1f` in `Identifier` (a `contract:` PR). | **(a)**. It also fixes cross-type signature reuse. It is an encoding change, not a new primitive, but it touches five modules: one ADR, one coordinated PR. |
| **D10** | Credential revocation vs. one shared, never-rotated attribute key | One key per (name, value), shared by every holder and never rotated. Revoking a credential stops nothing already obtained, and `/attribute-keys/author` skips the credential check entirely. | (a) Document as a limitation (ADR-0026 trade). (b) Epoch-versioned attribute keys plus re-authoring affected records. | **(a)** for this project; (b) is future work. |
| **D11** | PRE claims (unidirectional, "without decryption") | Docstrings and ADR-0012 claim unidirectional re-encryption without decryption. In the code, `rk` can be inverted (bidirectional), the facility unwraps the DEK in plaintext and delivers it by KEM, and `reencrypt` is never called. | (a) Correct the docstrings and paper: it's a KEM-style delivery to the clinician, the scheme is bidirectional, and the gate decrypts. (b) Implement a unidirectional scheme. | **(a)**. A real unidirectional PRE needs pairings, which are out of scope (PROJECT §6). Don't change the construction. |

---

## 1. Break-glass gate (the novelty claim)

### F1 — Facility trusts a root CA chosen by the caller · HIGH · Avaneeth (api) + Ojas (deploy) + Powel (breakglass) · ADR · M
**Problem.** [hospital.py:861-893](../../src/api/hospital.py) builds `ca_cert` and `root_cert` from
`facility_ca_certificate_pem` / `trusted_root_certificate_pem` in the request
body. An attacker mints their own root and CA plus a `CN=doc-201` leaf and passes
`validate_chain`. `ChainValidationError` / `CertificateExpiredError` are not in the
except list (`:893-899`), so they give a 500 and no denial is logged. No revocation check is made on the clinician cert.

**Fix.**
1. `deploy/asgi/facility.py`: load the trust material at startup. Use `FEDERATION_ROOT_CERT` (PEM path) and `FACILITY_CA_CERTS_DIR` (one PEM per facility, cross-certified per §7 step 2). Fail startup if either is missing.
2. `create_hospital_app(..., trusted_root: Certificate, facility_cas: Mapping[str, Certificate])`. In the handler, pick the intermediate by matching `cl_cert.issuer` to a configured CA subject. Unknown issuer → 403 + `_log_denial(denied_by="breakglass_assertion")`.
3. `api/schemas.py` `BreakglassUnlockRequest`: delete both PEM fields and set `model_config = ConfigDict(extra="forbid")`, so a caller still sending them gets 422 rather than being silently ignored.
4. Add `ChainValidationError`, `CertificateExpiredError` (and the revocation error from step 5) to the except tuple → 403 + denial logged. Use 403, not 400: these are authorization failures.
5. Revocation (Powel, `breakglass/assertion.py`): add a required `revoked_serials: frozenset[int]` argument (loaded from config like the root). Check it after the chain and raise `CertificateRevokedError`.
6. `custodian_service.py:933-936`: stop sending the PEMs.

**Tests (`tests/security/`).**
- `test_breakglass_rejects_assertion_chained_to_attacker_root`: forged root/CA/leaf with a valid signature → 403. Assert lifecycle state unchanged, no transition event, and one denial entry.
- `test_breakglass_rejects_expired_clinician_cert_with_403_and_denial`.
- `test_breakglass_rejects_revoked_clinician_cert`.
- `test_breakglass_request_with_trust_fields_is_rejected` → 422.

### F2 — Audit service releases share 3 to any caller · HIGH · Ojas (audit service) + Avaneeth (schemas) · ⚑ needs D1 · ADR · M
**Problem.** [audit_service.py:227-265](../../src/api/audit_service.py) releases a held share to anyone
who knows the `share_key` (= record_id), with no assertion, signature or
one-time ID. Together with share 1 (custodian), one process can open any
record. This breaks PROJECT §5's "no single shareholder" claim and CONVENTIONS §2
rule 9 (HARD).

**Fix (option D1-a).**
1. Share deposit (`/breakglass/shares`) stores `patient_id` and `home_facility_id` with the share (`audit/share_registry.py`). It refuses to overwrite an existing `share_key` → 409 (see F4).
2. `ReleaseShareRequest` replaces free-form `event_data`/`actor_id` with `assertion: EmergencyAssertion` + `clinician_certificate_pem`.
3. The audit service, at startup, loads the same root, facility CAs and revoked serials as F1. On release, **before** `release_share_after_commit`, it:
   - calls `validate_emergency_assertion(..., expected_facility_id=assertion.facility_id, consumed_store=<persistent store, F22>)`;
   - checks that `assertion.facility_id` is in its configured facility allowlist;
   - checks `assertion.patient_id == stored patient_id`.
4. The event data written to the chain is **derived from the verified assertion**, never from the caller.
5. Every refusal is appended as a denial entry, then 403.

**Residual (paper).** The custodian holds every clinician's signing key (ADR-0043), so it can still mint valid assertions. That is the custodial trust assumption. State it; it can't be closed without client-held keys.

**Tests.** `test_audit_share_not_released_without_valid_assertion` (no assertion / forged signature / wrong patient / replayed / revoked cert): no `share_hex` in the response and only a denial entry added. Also `test_single_share_holder_cannot_open_record` (existing exit criterion; extend it to call the HTTP service).

### F3 — Share 2 is generated and discarded · MED · Ojas (authority service) + Avaneeth · ⚑ needs D2 · ADR · M/L
**Problem.** `custodian_service.py:764` discards `_share2`, so the scheme is effectively 2-of-2.

**Fix (D2-a).**
- `authority_service.py` gets `/breakglass/shares` and `/breakglass/release`, with the same validation as F2. Its release logs through the audit service so the chain still records it.
- The custodian deposits share 2 at the patient's `owner_authority_id`.
- At break-glass, the custodian asks audit first and the home authority as fallback (§5 "or its federated delegate"). Two of the three shares are presented.

**(D2-b)** Instead: amend ARCHITECTURE §5, PROJECT §5 and the paper to say 2-of-2.

### F4 — Ingest with an existing `record_id` overwrites shares · HIGH · Ojas (custodian) + Avaneeth (ingest endpoint) · S
**Problem.** `custodian_service.py:753-771` deposits share 3 and share 1 **before** the facility ingest. A duplicate `record_id` makes the ingest 500, but the old shares are already replaced, and break-glass on that record is broken for good.

**Fix.**
1. Reorder: generate key → facility ingest → deposit share 3 → `vault.put_share`.
2. `hospital.py` ingest: catch the unique violation from `insert_record` → **409**. (Better: `repo.record_exists()` first, *and* rely on the PK.)
3. `vault.put_share` and the audit `register_share` refuse to overwrite (409). Replacement is only allowed through the authenticated re-key operation from F9/F10.
4. If share deposit fails after the ingest succeeded: return 503 with `breakglass_provisioned=false` and log it. Don't leave it silent.

**Test.** `test_ingest_with_existing_record_id_leaves_shares_intact`: break-glass on the original still works afterwards.

### F5 — ADR-0044 state reconciliation · HIGH · Avaneeth (api) + Powel (lifecycle) + Avaneeth (storage) · ⚑ needs D7 · ADR (supersede part of 0044) · M
**Problem.** `_effective_lifecycle_state` ([hospital.py:199-227](../../src/api/hospital.py)) writes
`granted` (unsigned, `last_event_id=None`) whenever *this* process holds no session. Three consequences:
- It races with another facility's live session.
- It runs before the share check, so a request with bad shares still changes state.
- It always writes `granted`, which undoes a revocation.

**Fix.** Remove the cause rather than patching the symptom:
1. **Keep** ADR-0044's patient-binding check (it's correct). **Reject** the reconciliation half.
2. The expiry manager gets a `state_writer` callback, like `audit_logger`. It persists `EXPIRED` and then the session's `prior_state` with `last_event_id` through the CAS in F12, so the store is never stale.
3. New table `emergency_sessions(record_id PK, facility_id, opened_event_id, expires_at)` (storage migration; **no key material**). It is written at open and deleted at expiry.
4. On facility startup, reconcile **only rows where `facility_id` = self**. These are sessions whose keys were lost when the process restarted. The timer key signs `EMERGENCY_OPEN → EXPIRED → prior_state` with reason `expired_without_rotation`, and an audit entry is written. This fails closed: the record is no longer open.
5. `_effective_lifecycle_state` becomes a plain read.

**Tests.**
- `test_facility_b_breakglass_does_not_reset_facility_a_live_session` → 409.
- `test_bad_shares_do_not_change_lifecycle_state`.
- `test_expiry_after_breakglass_on_revoked_record_returns_to_revoked`.
- `test_restart_reconciles_only_own_sessions`.

### F6 — Time-box and assertion lifetime unbounded · MED · Avaneeth (schemas, api) + Ojas (custodian schemas) + Powel (assertion) · S
**Problem.** `emergency_duration_seconds` (`schemas.py:195`, `custodian_schemas.py:207`) has no bound and overrides `EMERGENCY_DURATION_SECONDS`. A huge value raises `OverflowError` → 500 after state is written. Assertion `expires_at` has no maximum, and `issued_at` is not checked (`assertion.py:270`).

**Fix.**
- Schemas: `Field(default=None, gt=0, le=86_400)`.
- Facility: `effective = min(requested or configured, configured)`, so a caller can only **shorten** it. §7 says the time-box is configuration.
- `assertion.py`: add `max_ttl: timedelta` (config, default 300s) and `clock_skew` (30s). Reject when `expires_at - issued_at > max_ttl` or `issued_at > now + skew`.
- `custodian_schemas.assertion_ttl_seconds`: `le=300`.

**Tests.** `test_breakglass_duration_cannot_exceed_configured`, `test_assertion_with_ten_year_lifetime_rejected`, `test_future_dated_assertion_rejected`.

### F7 — Break-glass leaves side effects on failure; open requests race · MED · Avaneeth (api) · M
**Problem.** [hospital.py:1005-1057](../../src/api/hospital.py) persists `EMERGENCY_OPEN` + the transition event, then registers the session, then logs the rewrap. An audit outage (503) or a session failure therefore leaves the record open with no timer. A missing `baseline_wrapping_key_b64` or expiry manager silently skips the time-box. The read at `:954` and the write at `:1005` are not atomic.

**Fix.** New order: validate everything (including decoding the baseline key) → CAS-claim the state (F12) → gate → `_log_rewrap` (log-before-release) → `register_session` → persist state + event **in one DB transaction** → respond.
- Any failure after the claim rolls the claim back, and unregisters the session if one was registered.
- A missing expiry manager → **503 at startup**, not a silent skip. The baseline key is no longer a caller input (see F9).

**Tests.** `test_audit_outage_during_breakglass_leaves_state_unchanged`, `test_breakglass_without_expiry_manager_refused`, `test_concurrent_breakglass_one_wins` (two threads → one 200, one 409).

### F8 — Several denials are never audited · MED · Avaneeth (api) + Ojas (event types) · S
**Problem.** Not audited:
- `InsufficientSharesError`, `UnwrappingError`, `IllegalTransitionError` ([hospital.py:993-1002](../../src/api/hospital.py)).
- Record-not-found.
- The chain errors (F1).
- `UnwrappingError` on the read path (`:582`, `:610`).
- `/emergency-search` (`:1119`): no caller identity, no event.

**Fix.**
- Route every refusal through `_log_denial` with a distinct `denied_by` (`breakglass_gate`, `breakglass_transition`, `record_not_found`, `dek_unwrap`).
- `EmergencySearchRequest` gains `requester_id` + `correlation_id`. Log granted and denied searches (`access_via="emergency_search"`; Ojas adds the constant to `audit.events`). After D5 the identity comes from the envelope, not the body.

**Test.** Parametrised `test_every_breakglass_refusal_appends_one_denial`.

---

## 2. Revocation, expiry, lifecycle

### F9 — Expiry "forced rotation" is computed and thrown away · HIGH · Powel (lifecycle) + Avaneeth (api, storage) + Nandini (search re-key) + Ojas (custodian/audit share replace) · ⚑ needs D3 · ADR · L
**Problem.**
- `ExpiryResult.rotated_record` / `rotated_wrapping` (`expiry.py:396-443`) are never persisted.
- The custodian sends a random `baseline_wrapping_key` (`custodian_service.py:946`), so even the computed rotation is useless.
- Old shares, the emergency wrapping and the search tokens all survive expiry. This breaks §5 step 7 and C12, and violates the exit criterion "a search token does not work once the emergency state has expired".

**Fix (D3-b).** The building block is shared with F10, so build it once.
1. New `breakglass.provision_emergency_path(dek, record_id) -> (emergency_wrapping, shares)`. It is the existing `generate_emergency_key` + `split_emergency_key` + `wrap_dek(wrapped_for="emergency")`, just moved out of `api/` (also fixes F33).
2. On expiry, the expiry manager calls back into the facility: provision a new emergency path for the session's DEK, then **replace** the emergency wrapping (storage: `replace_wrapping(record_id, wrapped_for, expected_generation)`, with UPDATE … WHERE generation = expected). Then:
   - **replace** share 3 at audit and share 1 at the custodian. This is an authenticated re-key operation (D5), the only path allowed to overwrite (F4);
   - re-key the search index under the new emergency key (Nandini's P3-9 re-key function).
3. Remove `baseline_wrapping_key_b64` from the API. It is not a real key.
4. Under (D3-a) a DEK rotation step is added later. Until then, the paper's limitation says expiry revokes the *emergency capability*, not the DEK.

**Tests.** `test_old_shares_do_not_open_record_after_expiry`, `test_search_token_dead_after_expiry` (exit criterion, HTTP-level), `test_second_breakglass_after_expiry_uses_new_shares`.

### F10 — Revoke endpoint: 500 on Postgres, spoofable authz, bypasses the state machine, no audit · HIGH · Avaneeth (api, storage, `records/revocation.py`*) + Powel (lifecycle) · ⚑ needs D4, D3 · ADR · L
\*`git log` shows `records/revocation.py` authored by Avaneeth; `WORKFLOW.md` lists P3-7 under Powel. Confirm the owner.

**Problem.**
1. `repo.insert_record` re-inserts the same PK ([hospital.py:825](../../src/api/hospital.py), [repositories.py:23](../../src/storage/repositories.py)) → UniqueViolation → 500. Nothing is persisted.
2. `actor_id` and `owner_authority_id` both come from the request (`revocation.py:121`), so anyone holding the DEK can authorize themselves.
3. `GRANTED → REVOKED` is hard-coded (`revocation.py:286`). The current state is never read, so EMERGENCY_OPEN→REVOKED and REVOKED→REVOKED get persisted.
4. No audit entry on success (§5 revocation step 4).
5. The emergency wrapping still wraps the *old* DEK, so break-glass on a revoked record unwraps a key that no longer matches the ciphertext.

**Fix.**
1. Storage: `rotate_record(conn, rec, new_policy_wrapping, expected_generation)`. One transaction: `UPDATE records SET ciphertext, nonce, policy_id, created_at … WHERE record_id = %s`, delete the superseded policy wrapping, insert the new one, `WHERE generation = expected` → 0 rows = 409.
2. Authorization: the request is a patient- or home-authority-signed revocation (`RequestEnvelope`, operation `record.revoke`). The facility verifies it against the patient cert (D4) or the authority key from config. **Delete** `actor_id` / `owner_authority_id` as trusted inputs; `owner_authority_id` comes from the record's stored owner leaf.
3. `revoke_record_access(..., current_state)` calls `validate_transition(current_state, REVOKED)`. The facility applies it through F11's helper.
4. Log-before-commit: append the `record.revoked` audit event (the payload already exists as `audit_payload`) before writing the store.
5. Call `provision_emergency_path` (F9) for the new DEK so break-glass on a revoked record works.

**Tests.**
- `test_revocation_persists_on_postgres` (real-DB test, not in-memory).
- `test_revoked_reader_cannot_decrypt_after_rewrap` over HTTP + Postgres.
- `test_revoke_by_non_owner_with_spoofed_actor_fails`.
- `test_revoke_from_emergency_open_rejected`.
- `test_breakglass_on_revoked_record_opens_rotated_ciphertext`.

### F11 — Transitions bypass the state machine; break-glass events are unverifiable · HIGH · Avaneeth (api) + Powel (breakglass gate, lifecycle) · ⚑ needs D7, D8 · ADR · M
**Problem.**
- `apply_transition` is only called inside `expiry.py`.
- Break-glass transitions are signed with a throwaway key (`custodian_service.py:926`), and nothing verifies them.
- Expiry always ends at `GRANTED`.

**Fix.**
1. New facility helper `_apply_and_persist(repo, record_id, event, signer_public_key)`:
   - reads the state with `SELECT … FOR UPDATE`;
   - runs `LifecycleStateMachine.apply_transition` (signature, legality, from-state, one-time id);
   - persists through F12's CAS;
   - is used by break-glass, revoke, expiry and the F5 restart reconciliation.
2. D8-a: `open_emergency_access` takes a **pre-signed** `TransitionEvent` instead of `lifecycle_signing_key`. The custodian builds and signs it with the clinician key internally, and the facility verifies it against the F1-validated cert. Remove `lifecycle_signing_key_pem` from the API (this also removes a private key from the wire, which F18 needs).
3. D7-a: add `(EXPIRED, REVOKED)` to `LEGAL_TRANSITIONS`. `EmergencySession.prior_state` drives the final transition.

**Tests.** `test_transition_event_with_invalid_signature_rejected` (exit criterion, at the HTTP level), `test_illegal_transition_rejected` (EMERGENCY_OPEN→REVOKED), `test_replayed_transition_event_rejected`.

### F12 — No compare-and-set on lifecycle state; `ConsumedEventIds` unlocked · MED · Avaneeth (storage) + Powel (lifecycle) · S
**Problem.** `upsert_lifecycle_state` ([repositories.py:270](../../src/storage/repositories.py)) overwrites unconditionally, so two concurrent transitions can both succeed. `ConsumedEventIds` (`state_machine.py:232`) has no lock, unlike `breakglass/replay.py`.

**Fix.**
- `transition_lifecycle_state(conn, record_id, expected, new, last_event_id) -> None`: run `UPDATE lifecycle_state SET … WHERE record_id=%s AND state=%s`, and raise `StateConflictError` when rowcount is 0. The API maps that to 409.
- Keep `upsert` only for ingest (insert-only).
- Add `threading.Lock` to `ConsumedEventIds`, mirroring `_ConsumedIdStore`.

**Test.** `test_concurrent_transitions_from_same_state_exactly_one_succeeds` (Postgres).

### F13 — Consent revocation is enforced only by the portal · HIGH (HARD: CLAUDE.md / ADR-0014) · Avaneeth (api) + Powel (consent) + Ojas (portal text) · ⚑ needs D4 · M
**Problem.**
- The facility checks only the grant the caller presents ([hospital.py:517-543](../../src/api/hospital.py)).
- It verifies that grant with a **caller-supplied** patient public key.
- `grant.patient_id` is never compared with the record.
- Stored grants are never read back. Only `clinician/views.py:546` refuses a revoked grant.
- `test_phase3_consent_security.py:292` presents the REVOKED grant, so it can't catch a stale GRANTED one.
- The UI texts ("facility now refuses") are false.

**Fix.**
1. The facility looks up the **latest stored version** of `grant.grant_id` (`store_consent_grant` becomes an upsert by grant_id) and requires its status to be `GRANTED`. The presented copy must match it byte for byte.
2. The patient key comes from the patient cert (D4). Remove `patient_public_key_pem` from `ReadRecordRequest` and `SubmitConsentGrantPayload`.
3. `authorize_read` (consent, Powel) adds `grant.patient_id == record.patient_id` → `ConsentSubjectError`.
4. `submit_grant`/`revoke_grant`: the revocation is signed by the patient (D4); the facility no longer receives the patient **private** key (`revoke_grant` takes `patient_signing_key_pem` today: a private key on the wire, see F18).
5. Fix the test: after revocation, present the **old GRANTED** grant and expect 403.
6. Fix the UI texts only once the facility actually refuses.

**Tests.** `test_stale_granted_grant_refused_after_revocation`, `test_self_signed_grant_with_attacker_key_refused`, `test_grant_for_other_patient_refused`.

---

## 3. Key release and identity

### F14 — `/attribute-keys/author` hands out keys with no authentication · HIGH · Ojas (authority service) · ⚑ needs D5 (interim fix needs nothing) · ADR · S→M
**Problem.** [authority_service.py:247-262](../../src/api/authority_service.py) returns
`authority.attribute_key(name, value)`, the same key `/release` gates. One
unauthenticated POST for `owner:pat-101` reads every one of Alice's records.

**Fix.**
- **Interim:** an allowlist of authoring callers by bootstrap-issued service identity. Until D5-a exists, refuse unless the request comes from an address in `AUTHORING_CALLERS` (loopback / Compose service names). Ship with F16.
- **Proper (D5-a):** require a `RequestEnvelope` (operation `attribute_key.author`) signed by a facility or custodian service cert, plus a consumed `request_id`.
- **Document:** under ADR-0026 an *author* necessarily gets the holder key, so authoring callers are trusted parties. Say so in ADR-0039/0043.

**Test.** `test_author_endpoint_refuses_unauthenticated_caller`.

### F15 — Attribute key released for a credential without proof of possession · HIGH · Ojas (authority) · ⚑ needs D4 · ADR · M
**Problem.** `authority/issuance.py:197-224` releases a key to whoever presents a validly signed credential. Credentials are public signed data, so a copy is enough.

**Fix.** `/attribute-keys/release` takes a `RequestEnvelope` (existing contract and `create_request_envelope` / `verify_request_envelope`), where:
- `caller_id == credential.subject_id`;
- `recipient_id == authority_id`;
- `operation == "attribute_key.release"`;
- `body` = the canonical credential bytes.

The authority verifies the envelope against the subject's cert (clinician: existing PKI; patient: D4) and consumes the `request_id`. No new construction is involved.

**Test.** `test_copied_credential_without_subject_signature_gets_no_key`, `test_replayed_release_envelope_rejected`.

### F16 — Services listen on all interfaces; Compose publishes every port · HIGH · Ojas (deploy) · S
**Problem.** `deploy/entrypoint.py:44` defaults `HOST` to `0.0.0.0`; `run_local.py` never sets it; `docker-compose.yml` publishes 8010, 8011, 8020, 8001, 8002 and 8030 on every interface. §8 drops authentication *because* there is "no public exposure".

**Fix.**
- Default `HOST=127.0.0.1` in `entrypoint.py`. Compose sets `HOST=0.0.0.0` explicitly (needed inside the bridge).
- In Compose, **remove** `ports:` for audit, authority, facilities and custodian (bridge-internal only), or publish as `"127.0.0.1:8030:8030"` where host access is needed. The Docker-bridge capture is unaffected.

**Test.** A deploy smoke test asserting each service's bind address is loopback on Path A.

### F17 — Self-registration can claim an existing identity · HIGH · Nandini (accounts) + Ojas (portal_core) · M
**Problem.** `accounts/views.py:53-63, 104-110` binds whatever `patient_id` or `clinician_id` the visitor types and logs them in at once. Nothing in the portal checks `RegistrationRequest.status`, so the first person to register `doc-201` acts as that clinician through the custodian. That breaks ADR-0014.

**Fix.**
1. `role_required` (`portal_core/access.py`) also requires an **ISSUED** status for the profile. Seeded accounts are created as ISSUED. Unissued users get a "pending approval" page, and **no custodian call** is made.
2. The `subject_id` is bound at **issuance** by the admin, not at sign-up. Sign-up records it only as *requested*.
3. Add a unique constraint on `Profile.subject_id`.

**Test.** `test_unissued_registration_cannot_reach_custodian` (assert the custodian client is never called), `test_registering_existing_subject_id_rejected`.

---

## 4. Required course module (Traffic Analysis, PROJECT §4A)

### F18 — Analyser asserts none of the four properties, and property 1 is currently false · HIGH (HARD: PROJECT §4A) · Ojas (wire, per WORKFLOW; `analyze_traffic.py` was authored by Nandini) + everyone (D6) · ⚑ needs D6 · ADR · L
**Problem.** `wire/analyze_traffic.py` counts packets and URIs, uses bare `assert` (stripped by `-O`), and prints "PASSED". On the plain profile the following do cross the wire in the clear:
- `plaintext_b64` (read and ingest);
- `emergency_key_b64` (ingest);
- attribute keys (`holder_keyring`, `attribute_keyring`, `/author` responses);
- `share_hex`;
- `lifecycle_signing_key_pem` and `patient_signing_key_pem` (private keys).

**Fix — analyser** (independent of D6; it should **fail today**, which is the point):
- **P1, no secrets on the wire.**
  - The scenario seeds every record with a unique canary string, and writes the canaries plus the emergency keys, DEKs and shares it generated to a git-ignored sidecar `bench/captures/<run>.secrets.json`.
  - The analyser reassembles each TCP stream on the service ports and searches the raw payload for every secret in raw, hex and base64 form (all three base64 alignments).
  - It also flags a denylist of JSON keys: `plaintext_b64`, `emergency_key_b64`, `share_hex`, `key_b64`, `*_signing_key_pem`, `holder_keyring`, `attribute_keyring`, `old_dek_b64`.
- **P2, commit before release.** For each `/breakglass/release` exchange, find the audit service's Postgres `INSERT INTO audit_log` + `COMMIT` on the DB port (pyshark `pgsql` dissector). Assert its frame time is earlier than the HTTP response frame that carries the share. Capture must include the DB port.
- **P3, leakage measured.** Per search request, record the token (opaque bytes, hashed), request and response sizes, result count and timing. Write a CSV to `bench/results/`, and assert it is non-empty and covers every search in the scenario. Report repeated tokens as search-pattern leakage.
- **P4, break-glass visible as metadata only.** Assert the break-glass URIs are visible, and that the emergency key is absent per P1.
- Replace bare `assert` with explicit checks that print which property failed and exit non-zero. Add `tests/wire/test_analyzer.py` running against a small committed fixture pcap: one clean, one with a planted secret that must fail.

**Fix — system:** D6-a (client-side crypto, shares delivered wrapped to the recipient), or D6-b with the narrowed claim written into PROJECT §4A and the paper. F11 (no signing key on the wire) and F13 (no patient private key on the wire) remove the private keys under either option.

### F39 — Capture accepts any interface · LOW (CLAUDE.md capture rule) · Ojas · S
**Fix.** `wire/capture.py --interface` accepts only a loopback adapter (`lo`, `\Device\NPF_Loopback`, "Adapter for loopback traffic capture") or a Docker bridge (`docker0`, `br-*`). Anything else exits 2 with the rule quoted. Test the allowlist function.

### F40 — Capture path / `bench/` · LOW · Ojas · S
**Fix.** Write PCAPs to `bench/captures/` as §7 says (or amend §7 to `wire/captures/`). `bench/` being empty is a phase item (D4 deliverable), not a bug.

---

## 5. Fail-closed and audit plumbing

### F19 — `_log_event` silently does nothing without an audit sink · MED (HARD: §2 rule 6) · Avaneeth (api) · S
**Problem.** [hospital.py:179-196](../../src/api/hospital.py) falls through with no `else`. `AUDIT_SERVICE_URL` is optional in `facility.py`, so reads return plaintext with nothing logged.

**Fix.** Add `else: raise AuditServiceError("no audit sink configured")`. `facility.py`: make `AUDIT_SERVICE_URL` required (fail at startup). Tests that want no audit pass an explicit in-memory sink.

**Test.** `test_read_without_audit_sink_returns_503_not_plaintext`.

### F20 — One exception kills the expiry monitor for good · MED · Powel (lifecycle) · M
**Problem.** `check_and_expire_due` (`expiry.py:445`) catches only `SessionNotFoundError`. An `audit_logger` HTTP error ends `_loop`, and the session was already deleted at claim (`:357`), so it is never retried.

**Fix.**
- Claim by marking the session `expiring` instead of deleting it.
- On failure, put it back with a retry count and backoff, and log at ERROR with `record_id` only.
- `_loop` wraps each sweep in `try/except Exception` with a comment saying why swallowing is correct here: the loop must survive, and the failed item is retried.
- Access stays closed meanwhile, because `get_active_emergency_key` already refuses past `expires_at`.

**Test.** `test_monitor_survives_audit_outage_and_retries`.

### F21 — Optional arguments that skip security checks · MED (§2 rule 6) · Powel (assertion, envelopes) + Ojas/Avaneeth (credential lifecycle, P2-6) · S
**Problem.** `consumed_store=None` skips the replay check (`assertion.py:197`, `envelopes.py`). `revocation_registry=None` skips the revocation check (`verify_credential`).

**Fix.** Make them required keyword arguments with no default. Callers that don't care pass a fresh store or an empty registry explicitly.

**Test.** A signature test (`inspect.signature`) asserting there is no default.

### F22 — Replay stores are in memory only · MED · Powel (breakglass) + Avaneeth (storage migration) · M
**Problem.** `ConsumedAssertionIds()` lives in the process (`hospital.py:425`). A restart reopens replay for any unexpired assertion.

**Fix.** New table `consumed_ids(kind text, id uuid, consumed_at timestamptz, PRIMARY KEY (kind, id))`. Add a `PostgresConsumedIds(kind)` with the same `consume()` interface: `INSERT … ON CONFLICT DO NOTHING`, and rowcount 0 → `ReplayedAssertionError`. The facility, the audit service (F2) and the authority (F15) all use it.

**Test.** `test_assertion_replay_rejected_across_app_restart`.

### F31 — Audit chain edge cases · LOW · Ojas (audit) + Ojas (custodian) · S
**Problem.** A float like `1e20` changes form after a jsonb round-trip and raises a false `TamperedEntryError`. Deleting the last entries goes undetected, and the custodian never verifies the entry it gets back (`custodian_service.py:900`).

**Fix.**
- `_canonical_event` rejects non-integer floats (raise at append).
- The custodian verifies the returned entry's signature with the audit service public key (config), and checks `seq` against the last seq it saw.
- The facility persists the last chain head it observed and refuses to accept a lower `seq` (a lightweight external anchor).

**Test.** `test_float_event_data_rejected_at_append`, `test_truncated_chain_detected_by_custodian`.

---

## 6. Cryptographic hygiene (core modules)

### F23 — Ambiguous signed payloads; no domain separation · MED · Powel (crypto_core, breakglass, lifecycle, consent) + Ojas (audit, authority) · ⚑ needs D9 · ADR · M
**Problem.** Seven modules join fields with `_FIELD_SEPARATOR` (`0x1f`), and `Identifier` allows `0x1f`. In `consent/service.py:97`, grantee `"dr\x1frec-9"` with scope `("rec-1",)` produces the same signed bytes as grantee `"dr"` with scope `("rec-9","rec-1")`. The same clinician key signs assertions and transition events with no type tag.

**Fix (D9-a).**
- Add `crypto_core.encoding.canonical_fields(domain: str, fields: Sequence[bytes | Sequence[bytes]]) -> bytes`. It writes the domain tag, then each field as a 4-byte big-endian length + bytes; nested sequences are a count + length-prefixed items.
- Domain tags: `custos/v1/emergency-assertion`, `…/transition-event`, `…/consent-request`, `…/consent-grant`, `…/credential`, `…/request-envelope`, `…/audit-entry`.
- Replace every `_FIELD_SEPARATOR.join`, and delete the unused one in `gate.py`.
- Every signature changes, which is fine because every run is a fresh bootstrap (ADR-0039).

**Tests.** `test_grant_field_boundary_unambiguous` (the example above must produce different bytes), `test_assertion_signature_not_valid_as_transition_signature`.

### F24 — `hazmat` imported outside `crypto_core` · HARD (CLAUDE.md, §2 rule 1) · Ojas (audit ×3) + Powel (gate, expiry) + Avaneeth/Powel (revocation) · S
**Problem.** [chain.py:31](../../src/audit/chain.py), `audit/events.py:55`, `audit/share_custody.py:27`, [gate.py:62](../../src/breakglass/gate.py), [expiry.py:47](../../src/lifecycle/expiry.py), [revocation.py:44](../../src/records/revocation.py).

**Fix.** Replace `ec.EllipticCurvePrivateKey` / `ec.EllipticCurvePublicKey` hints with `crypto_core.types.ECPrivateKey` / `ECPublicKey`. Extend the invariant test to scan **all of `src/`** except `crypto_core`, not just `api/`.

### F25 — Nonces from `os.urandom` · HARD, minor (§2 rule 2) · Powel · S
**Fix.** `crypto_core/symmetric.py:51` → `secrets.token_bytes(num_bytes)`. Add a grep-style test forbidding `os.urandom` / `random.` in `src/`.

### F26 — Keys printed by default `repr` · LOW (§2 rule 3) · Powel (gate, expiry) + Avaneeth (ingest, revocation) · S
**Fix.** `field(repr=False)` on:
- `EmergencyUnlockResult.emergency_key` and `.rewrapped_dek`;
- `EmergencySession.emergency_key` and `.baseline_wrapping_key`;
- `IngestResult.root_secret` and `.search_tokens`;
- `RevocationResult.new_root_secret`.

**Test.** `test_result_reprs_contain_no_key_bytes` (assert the hex and base64 of each key are absent from `repr()`).

### F27 — Shamir share index not range-checked · LOW · Powel (shamir) · S
**Problem.** `x` and `x+P` pass the duplicate check and the gate's `unique_by_x`, then raise a bare `ValueError`. `x=0` (where the secret sits) and `y ≥ P` are accepted. The docstring calls P a "safe prime".

**Fix.** In `combine_shares` (and the gate before counting), require `1 ≤ x < P` and `0 ≤ y < P`, else `InvalidShareError`. Fix the docstring ("prime", 257-bit).

**Test.** `test_share_index_aliasing_rejected`, `test_share_at_x_zero_rejected`.

### F29 — DEK wrapping AAD binds only `record_id` · LOW · Avaneeth (records) · S · ADR (construction parameter)
**Problem.** `records/service.py` `wrap_dek` binds only `record_id`, so an old-generation wrapping can be swapped back in (rollback).

**Fix.** AAD = `canonical_fields("custos/v1/dek-wrap", [record_id, wrapped_for, generation])` (after F23).

**Test.** `test_old_generation_wrapping_does_not_unwrap_as_current`.

### F30 — Consent TTL comment wrong · LOW · Powel · S
**Fix.** `consent/service.py:38`: the comment says one year and the value is 7 days. Make them agree, and decide which is intended.

### F32 — PRE docstrings overstate the scheme · LOW · Ojas (pre) + Powel (gate) · ⚑ needs D11 · S
**Fix (D11-a).** Correct the `pre/elgamal.py` docstring: `rk⁻¹ mod q` reverses it, so it is bidirectional; and a 256-bit group is well below 128-bit security. Note in `gate.py` and ADR-0012 that the facility unwraps the DEK and delivers it by KEM. Add both to the paper's limitations.

---

## 7. API-layer conventions

### F33 — Crypto in `api/`, and the invariant test misses it · MED (HARD: §2 rule 10) · Avaneeth (api) + Ojas (custodian) + Nandini (search) · M
**Problem.** `generate_emergency_key`/`split_emergency_key` (`custodian_service.py:763`), `derive_search_token` ([hospital.py:1149](../../src/api/hospital.py)), `sha256_digest` (`:336`), and the custodian's `decrypt_record` / `open_delivery_package` / `create_emergency_assertion`. `test_no_crypto_invariant.py:36` doesn't list them.

**Fix.**
- Emergency provisioning → `breakglass.provision_emergency_path` (F9).
- The in-memory emergency-search branch → a repo-agnostic `search.service` helper (Nandini).
- Patient-id hashing → an `audit.events` helper.
- **Custodian**: it is a client-side key agent, not a route orchestrator. Move its crypto into a new `src/custodian/` module, with `api/custodian_service.py` as a thin router. Record the decision in ADR-0043.
- Extend `forbidden_calls` with every name above.

### F34 — No BOLA test; read does DB work before authorization · MED (HARD: CONVENTIONS §5) · Avaneeth (api) · ⚑ needs D5 · M
**Problem.** `read_record` (`hospital.py:491-512`) loads the record, wrapping and policy before any caller check, and `requester_id` is self-declared.

**Fix.** Once D5-a gives a verified caller identity:
- check caller ↔ patient before **any** repo call. Owner: `caller == record.patient_id` through an index lookup that doesn't load ciphertext; clinicians are allowed through to the crypto check, which §8 says is the backstop;
- denials happen before the DB work and are logged.

**Test (exit criterion).** `test_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db`: a spy repo asserts that `get_record` / `get_wrapping_for_record` are never called.

### F35 — f-string SQL in `store_reader.py` · LOW (HARD as written: §2 rule 7) · Ojas/Powel (portal_core) · S
**Fix.** `portal_core/store_reader.py:52,60,76,222`: compose with `psycopg.sql.SQL(...).format(sql.Identifier(...))` / `sql.SQL(_AUDIT_COLUMNS)`. The values are constants today, so this is about rule compliance, not an exploit.

### F36 — Portal's default DB connection is the postgres superuser · MED · Avaneeth (PS-6) · S
**Problem.** `settings.py:76-84` / `run_portal_demo.py:~153`: `default` uses the DATABASE_URL user with `search_path=portal,public`, so Django can write the store tables. `portal_ro` limits only the `store` alias.

**Fix.**
- `portal/sql/roles.sql`: add `portal_app`, which owns the `portal` schema and has **no** privileges on store tables. `default` connects as `portal_app`, with `search_path=portal`.
- `run_portal_demo` creates the role.

**Test.** `test_portal_default_connection_cannot_write_store_tables`.

### F43 — Compiled policies live only in a class-level dict · MED · Avaneeth (api, storage) · M
**Problem.** `api/repository.py:276`: `_shared_*` dicts are shared by every facility in one process and lost on restart, after which reads return 500 (`hospital.py:509`).

**Fix.** New store table `compiled_policies(policy_id PK, compiled bytea)`. Encrypted leaf shares only, which is safe for an honest-but-curious store. The repo reads and writes it; per-instance caches only.

**Test.** `test_read_succeeds_after_facility_restart` (Postgres).

---

## 8. Deployment and portal

### F37 — Bootstrap order and Path B · MED · Ojas (deploy) · M
**Problem.**
- Compose `bootstrap` defaults to `https://` while the services default to TLS off, so Path B `up` fails.
- The chain is verified after the services start, against §7 step 7 ("If chain verification fails at boot, nothing else starts").
- The custodian is never seeded on Paths A/B.

**Fix.**
- Derive the URL scheme from the same `TLS_ENABLED` variable.
- The audit service verifies the chain from genesis in its startup and exits non-zero on failure. The other services `depends_on: audit: condition: service_healthy`, and Path A waits on the audit `/health` before starting the facilities.
- Call the `seed_portal` custodian deposit from `run_local` / Compose bootstrap.

**Test.** A deploy smoke test with a tampered genesis → facilities never start.

### F38 — Portal demo runs audit in-process · MED · Ojas (deploy) + Avaneeth (demo driver) · M
**Problem.** `run_portal_demo.py` runs audit and both facilities as threads (`demo/driver._LiveServer`) on random ports. §7 says audit **must** be a separate process, and the capture filter misses the random ports.

**Fix.** Spawn the services with `deploy/entrypoint.py` on the fixed ports from `run_local`. Keep threads only behind `--in-process` for tests.

### F41 — The ADR-0033 lookup can be skipped · LOW · Nandini (clinician portal) · S
**Problem.** The break-glass view takes `patient_id` from GET/POST. No `patient.lookup` event is written, and a fresh correlation id is minted.

**Fix.** The lookup creates a server-side `LookupSession` (portal DB: selected `patient_id`, correlation id) and writes the `patient.lookup` event. The break-glass form posts the lookup id; a raw `patient_id` gets 400.

**Test.** `test_breakglass_without_lookup_refused`.

### F42 — Portal and test hygiene · LOW · Mixed · S each
| Issue | Fix | Owner |
|---|---|---|
| `settings.py:21` DEBUG defaults on with `ALLOWED_HOSTS=["*"]` | Default `"0"`; `run_portal_demo` sets `DJANGO_DEBUG=1` explicitly | Avaneeth (PS-6) / Nandini |
| Open redirect, `patient/views.py:130` (`POST next`) | `url_has_allowed_host_and_scheme(next, {request.get_host()})`, else `patient:home` | Ojas/Powel (patient views) |
| Raw upload served inline with the uploader's Content-Type (`patient/views.py:369`) | Allowlist inline types (pdf, png, jpeg, text/plain); otherwise `Content-Disposition: attachment`, and always `X-Content-Type-Options: nosniff` | same |
| `admin_audit/views.py:237`: bad `int()` → 500 | Validate → 400 | Ojas |
| `admin_audit/views.py:94`: `_links_intact` true by default | Three-state result: intact / broken / unverifiable (no consecutive entries) | Ojas |
| `audit_service.py:181`: broad `except Exception` → 409 | Catch only the unique violation; let other DB errors become 503 | Ojas |
| `tests/security/conftest.py:27`: skips when Postgres is down, even in CI | If `CI=true`, fail instead of skip | Ojas |
| `tests/e2e/portal_flows.py:56` counts a skip as a pass; `:271` accepts 503 as a denial | Separate PASS / SKIP / FAIL counts; a denial must be 403 | Powel |

### F44 — Credential revocation doesn't remove cryptographic access · MED · ⚑ needs D10 · S (if D10-a)
**Fix (D10-a).** A paper limitation plus an ADR-0026 note: one key per (name, value), shared and never rotated, so revoking a credential stops *future key release* (after F15) but not a key already obtained.

---

## Suggested order

1. **Quick, no decisions needed:** F16, F19, F24, F25, F26, F27, F6, F8, F12, F4, F14 (interim), F42.
2. **Make the decisions:** D1, D4, D5, D6, D7, D8. One team sync, with ADRs written in the same PR as the code.
3. **Break-glass core:** F1 → F2 → F11 → F7 → F5. After this the novelty claim holds.
4. **Lifecycle:** F22 → F10 → F9 (shared `provision_emergency_path`) → F20.
5. **Course module:** F18 (the analyser first, so it fails, then the system fixes under D6) → F39 → F40.
6. **Remainder:** F13, F15, F17, F23, F29, F33, F34, F36, F37, F38, F41, F43, F31, F32, F44, F3/D2.

## Per-person breakdown

Owners are taken from `WORKFLOW.md` and `git log`. If something is listed
under the wrong person, say so and it moves. "Lead" means that person drives
the fix and coordinates the others on it.

### Everyone
- Answer **D1, D4, D5, D6, D7, D8** at the next sync. They block the
  break-glass core. D2, D3, D9, D10 and D11 can follow.
- **D6** changes the wire design across the custodian, the facility and the
  analyser, so it needs all four of you.
- **F44 / D10** is a team call on what the paper says about credential
  revocation.

### Powel: crypto core, break-glass, lifecycle, consent
- **Lead:** F11 (gate takes a pre-signed event; `EXPIRED → REVOKED`), F20 (expiry monitor survives errors), F23 (canonical encoding), F25 (`secrets` nonces), F27 (Shamir index checks).
- **Your part of shared fixes:**
  - F1: clinician-cert revocation check in `assertion.py`.
  - F5 / F9: expiry `state_writer` callback, `prior_state`, re-key on expiry.
  - F6: assertion max TTL and future-dating check.
  - F10: `validate_transition` in revocation (and `revocation.py` itself if it is yours; see F10).
  - F12: lock on `ConsumedEventIds`.
  - F13: `grant.patient_id` check in `authorize_read`.
  - F21: required `consumed_store`.
  - F22: Postgres consumed-id store.
  - F24 / F26: `gate.py` and `expiry.py` type hints and `repr=False`.
  - F30: consent TTL comment.
  - F32: gate docstring.
  - F35 / F42: `store_reader.py`, patient views, `portal_flows.py` (shared with Ojas).

### Nandini: search, accounts, clinician portal
- **Lead:** F17 (registration can't claim an identity; access requires an ISSUED status), F41 (break-glass requires a lookup session).
- **Your part of shared fixes:**
  - F9: re-key the search index when the emergency path is re-keyed.
  - F33: a repo-agnostic emergency-search helper in `search.service`, so `hospital.py` stops calling `derive_search_token`.
  - F18: you authored `analyze_traffic.py`; please pair with Ojas on the four property checks.
  - F42: DEBUG / `ALLOWED_HOSTS` default (shared with Avaneeth).

### Ojas: audit, authority, PRE, deploy, wire, custodian, admin portal
- **Lead:** F2 (audit service checks the assertion before releasing share 3), F3 (share 2 at the home authority, if D2-a), F4 (custodian ingest order), F14 (lock down `/author`), F15 (proof of possession for attribute keys), F16 (bind to loopback, stop publishing ports), F18 (the analyser and its four properties), F31 (chain edge cases), F37 (bootstrap order, Path B), F38 (portal demo in separate processes), F39 (capture interface allowlist), F40 (capture path).
- **Your part of shared fixes:**
  - F1: load root and facility CAs from bootstrap PKI in the deploy config.
  - F6: bounds in `custodian_schemas.py`.
  - F8: new event types in `audit.events`.
  - F9: authenticated share replacement at audit and custodian.
  - F13: correct the portal "facility now refuses" texts.
  - F21: required `revocation_registry` (shared with Avaneeth, P2-6).
  - F23: audit and authority payloads.
  - F24: three `hazmat` imports in `audit/`.
  - F32: PRE docstring.
  - F33: move custodian crypto into `src/custodian/`.
  - F35 / F42: `store_reader.py`, admin views, `audit_service.py` exception, CI skip→fail (some shared with Powel).

### Avaneeth: facility API, storage, records, identity lifecycle, demo, portal DB roles
- **Lead:** F1 (facility trust anchor), F5 (replace ADR-0044's reset), F7 (break-glass ordering and rollback), F8 (denial logging), F10 (revoke endpoint), F12 (compare-and-set on lifecycle state), F19 (no silent audit no-op), F29 (wrapping AAD), F34 (BOLA test), F36 (`portal_app` role), F43 (persist compiled policies).
- **Your part of shared fixes:**
  - F2: the `ReleaseShareRequest` schema.
  - F4: 409 on duplicate ingest.
  - F6: bounds in `schemas.py` and capping to the configured time-box.
  - F9: `replace_wrapping` in storage.
  - F11: the `_apply_and_persist` helper.
  - F13: the facility reads stored grants.
  - F21: required `revocation_registry` (P2-6).
  - F22: the `consumed_ids` migration.
  - F24 / F26: `revocation.py` and `ingest.py`.
  - F33: the api-side cleanup.
  - F38: the demo driver.
  - F42: settings defaults.
- **Confirm:** ownership of `records/revocation.py`. `git log` shows you as the author, while `WORKFLOW.md` lists P3-7 under Powel.
