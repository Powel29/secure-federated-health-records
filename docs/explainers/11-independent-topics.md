# 11. Topics for each speaker

Order: Powel, Ojas, Avaneeth, Nandini (about 6 minutes each, 4 topics of about
1.5 minutes), then a shared live demo (about 4 minutes).

## Topic split

| # | Powel | Ojas | Avaneeth | Nandini |
|---|---|---|---|---|
| 1 | Key-lifecycle state machine | Identity and credentials | Record protection (AES, DEK, wrapping) | Federated discovery and identification |
| 2 | Revocation by key rotation | Audit hash chain and commit-before-release | Emergency Assertion, patient binding, replay protection | Emergency-only searchable encryption |
| 3 | Access structure: policy tree and Shamir | Proxy re-encryption and key delivery | Consent and the patient side | Time-boxed expiry and forced re-key |
| 4 | Break-glass gate (weighted 3-of-4) | Deployment, threat model, admin/audit portal | Thin API, normal read, portal boundary | Traffic analysis |

## Who explains the major concepts

| Concept | Explained by | Code |
|---|---|---|
| AES-256-GCM | Avaneeth | `src/crypto_core/symmetric.py`: `aes_gcm_encrypt`, `aes_gcm_decrypt` |
| DEK | Avaneeth | `src/records/service.py`: `encrypt_record`, `decrypt_record` |
| Key wrapping (envelope encryption) | Avaneeth | `src/records/service.py`: `wrap_dek`, `unwrap_dek`, `rewrap_dek` |
| Crypto rules | Avaneeth | `CONVENTIONS.md` §2, `tests/api/test_no_crypto_invariant.py` |
| Consent grants | Avaneeth | `src/consent/service.py` |
| Who may revoke | Avaneeth | `src/records/revocation.py`: `check_revocation_authorization` |
| Emergency Assertion and replay | Avaneeth | `src/breakglass/assertion.py` |
| SHA-256 and the hash chain | Ojas | `src/audit/chain.py` |
| ECDSA signatures and X.509 | Ojas | `src/crypto_core/asymmetric.py`, `src/identity/certificates.py` |
| Proxy re-encryption | Ojas | `src/pre/elgamal.py` |
| Credential lifecycle | Ojas | `src/authority/issuance.py` |
| Shamir secret sharing | Powel | `src/shamir/split.py` |
| Policy tree | Powel | `src/policy/engine.py` |
| Weighted 3-of-4 threshold, emergency key | Powel | `src/breakglass/emergency_key.py`, `gate.py` |
| Key rotation, forward secrecy | Powel | `src/records/revocation.py`: `revoke_record_access` |
| HKDF and search tokens | Nandini | `src/search/service.py`: `derive_search_token` |
| Time-boxed expiry | Nandini | `src/lifecycle/expiry.py` |

---

## Powel

1. **Key-lifecycle state machine.** Granted, Revoked, Emergency_Open, Expired; legal
   arrows; illegal arrows rejected; each move is a signed event with a single-use id.
   *Code:* `src/lifecycle/state_machine.py`: `validate_transition`,
   `create_transition_event`, `verify_transition_event`,
   `LifecycleStateMachine.apply_transition`.
2. **Revocation by key rotation.** Decrypt, new key, re-encrypt, rebuild wrappings
   without the revoked party; expiry runs the same full rotation. Limit: forward-only
   and patient-only.
   *Code:* `src/records/revocation.py`: `revoke_record_access`.
3. **Access structure.** Policy tree (AND needs every child, OR needs any one) over
   Shamir sharing. Limit: not collusion-resistant.
   *Code:* `src/shamir/split.py`: `split_secret`, `combine_shares`;
   `src/policy/engine.py`: `compile_policy`, `reconstruct_root_secret`,
   `unwrap_dek_via_policy`.
4. **Break-glass gate.** Emergency key split weighted 3-of-4: custodian x=1, home
   authority x=2, audit service x=3 and 4; any three distinct x rebuild it, so every
   opening includes an audit share; the gate refuses fewer than three.
   *Code:* `src/breakglass/emergency_key.py`: `generate_emergency_key`,
   `split_emergency_key`; `src/breakglass/gate.py`: `open_emergency_access`.

**Diagrams:** UML state diagram (main; **seven** arrows), policy tree for `rec-002`, 3-of-4 diagram.

**Demo:** as `david`, `house` refused on `rec-002` and `cameron` succeeds, then
revoke and the read fails. In a terminal: `python -m tests.security.claims --table`
and `python -m tests.security.mutations`.

**Rubric slides:** objectives and scope; test-case table (11 claims, all hold);
bugs-found-and-fixed; deck assembly and timekeeping.

---

## Ojas

1. **Identity and credentials.** Root, facility CAs, cross-certification; ECDSA and
   X.509; attribute authorities and attribute keys; credential expiry and revocation.
   *Code:* `src/identity/root_anchor.py`: `generate_root_anchor`;
   `src/identity/certificates.py`: `issue_clinician_certificate`;
   `src/identity/chain.py`: `validate_chain`; `src/authority/issuance.py`:
   `issue_credential`, `verify_credential`, `attribute_key`.
2. **Audit hash chain and commit-before-release.**
   `h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)`; the audit service writes the
   entry first, then returns its piece; denials and federation events are logged.
   *Code:* `src/audit/chain.py`: `compute_entry_hash`, `append_entry`,
   `verify_full_chain`; `src/audit/share_registry.py`: `ShareRegistry`;
   `src/api/audit_service.py`: `POST /breakglass/release`.
3. **Proxy re-encryption and key delivery.** Re-encrypt a ciphertext for another
   party without seeing plaintext; the doctor opens the delivery package.
   *Code:* `src/pre/elgamal.py`: `generate_rekey`, `reencrypt`, `encapsulate_key`,
   `decapsulate_key`; `src/pre/delivery.py`: `open_delivery_package`.
4. **Deployment, threat model, admin/audit portal.** Seven processes, bootstrap
   order, four attackers, read-only auditor view.
   *Code:* `deploy/bootstrap.py`, `deploy/run_portal_demo.py`,
   `docs/threat-model.md`, `portal/admin_audit/views.py`: `trace`, `federation`.

**Diagrams:** block diagram of the seven processes (main), commit-then-release
sequence diagram, hash-chain picture.

**Demo:** as `auditor`, chain PASS, hash links in a trace, a
`breakglass_share_released` entry with its sequence number.

**Rubric slides:** block diagram; implementation status (modules, GitHub, merged
PRs, CI, ADR log, ticked `WORKFLOW.md`).

---

## Avaneeth

1. **Record protection.** DEK per record; AES-256-GCM with fresh nonce and tag; DEK
   wrapped, never stored in the clear; store holds ciphertext only; ingest and
   upload; the crypto rules.
   *Code:* `src/crypto_core/symmetric.py`: `aes_gcm_encrypt`, `aes_gcm_decrypt`;
   `src/records/service.py`: `encrypt_record`, `wrap_dek`, `unwrap_dek`;
   `src/records/ingest.py`: `ingest_record`; `src/storage/migrations/`.
2. **Emergency Assertion, patient binding, replay protection.** Signed, bound to
   patient, clinician and facility; short expiry; one-time ids in a durable
   consumed-id store; patient-binding check (ADR-0044).
   *Code:* `src/breakglass/assertion.py`: `create_emergency_assertion`,
   `validate_emergency_assertion`; `src/lifecycle/state_machine.py`:
   `ConsumedEventIds`.
3. **Consent and the patient side.** Signed grants (scope, expiry, grantee); consent
   gate before the crypto path; who may revoke; portal approve, deny, revoke,
   notifications; patient self-access through the `owner:` attribute (ADR-0016).
   *Code:* `src/consent/service.py`: `create_consent_request`,
   `create_consent_grant`, `revoke_consent_grant`, `authorize_read`;
   `src/records/revocation.py`: `check_revocation_authorization`;
   `portal/patient/views.py`: `decide`, `revoke`.
4. **Thin API, normal read, portal boundary.** Read path: certificate, policy tree,
   unwrap, decrypt, log. No cryptography in route handlers; portals identify, never
   decide; Key Custodian; read-only database role (ADR-0014/0043).
   *Code:* `src/api/hospital.py`: `create_hospital_app`, the read endpoint;
   `src/api/custodian_service.py`; `tests/api/test_no_crypto_invariant.py`;
   `portal/sql/roles.sql`.

**Diagrams:** ER diagram (main), envelope diagram, assertion-validation flowchart.

**Demo:** as `david`, view own record on the encrypted-records page; approve or deny
a request; wrong-patient break-glass refused with 403.

**Rubric slides:** ER diagram; literature table; Phases 0 to 6 plan; screenshot set.

---

## Nandini

1. **Federated discovery and identification.** Patient-indexed shared store;
   identification by family name + date of birth; ambiguous matches listed; lookups
   logged; the synthetic federation.
   *Code:* `src/federation/discovery.py`: `find_record_ids_by_patient`;
   `portal/clinician/views.py`: `identify`; `demo/seed_data.py`:
   `create_synthetic_dataset`; `demo/driver.py`.
2. **Emergency-only searchable encryption.** HKDF search tokens derived from the
   session key; index re-keyed on rotation; leakage measured.
   *Code:* `src/search/service.py`: `derive_search_token`, `index_search_term`,
   `search_records_with_emergency`, `rekey_search_index`.
3. **Time-boxed expiry and forced re-key.** A timer signs Emergency_Open to Expired,
   re-keys the record, signs Expired to Granted; search tokens go dead.
   *Code:* `src/lifecycle/expiry.py`: `EmergencyExpiryManager.expire_session`.
4. **Traffic analysis.** Plain HTTP captured on loopback; PyShark analysers assert
   four wire properties; TLS profile; measured search leakage.
   Status: analyser built (ADR-0045) and **run on real plain and TLS captures**; all checks pass.
   *Code:* `wire/capture.py`, `wire/tls.py`, `wire/analyze_traffic.py`,
   `wire/analyze_search_leakage.py`; `bench/results/p53_search_leakage.json`.

**Diagrams:** data-flow diagram level 1 (main), search-token and expiry timeline.

**Rubric slides:** data-flow diagram; benchmark charts with baseline and analysis;
edge-case results; capture and analyser status.
*Code:* `bench/run_benchmarks.py`,
`tests/breakglass/test_gate.py::TestOpenEmergencyAccessEdgeCases`.

---

## Shared live demo (about 4 minutes, operator: Nandini)

Setup before the session: restart the stack, run one break-glass on another record
and let it expire.

| Step | On screen |
|---|---|
| 1 | `house`: Identify patient, `Miller`, DOB `11/20/1965`, one match |
| 2 | Run federated discovery, pick `rec-002`, choose a reason code |
| 3 | Declare: case page with the three share cards (share 1 presented, share 2 not requested, shares 3 and 4 released after seq N) and a countdown |
| 4 | Emergency search "glucose": TOKEN LIVE |
| 5 | Window ends: TOKEN DEAD, case reads expired |

The presentation is live. If a step fails, show that step's screenshot slide.

## Rubric coverage (10 marks)

| Parameter (marks) | Slide | Covered by |
|---|---|---|
| 1. Problem and objectives (1) | Problem, 4 measurable objectives, scope | Powel |
| 1. Literature and gap | Literature table | Avaneeth |
| 2. Design (2) | One diagram each | All four |
| 2. Plan | Phases 0 to 6 | Avaneeth |
| 3. Implementation (4) | Own code and the live demo | All four |
| 3. Status | Modules, GitHub, CI, ADR log | Ojas |
| 4. Testing (2) | Test-case table | Powel |
| 4. Results and baseline | Benchmark charts, baseline, analysis | Nandini |
| 4. Bugs discussed | Bugs found by our own driver (3) and by per-container runs (1), fixed and tested | Powel |
| 4. Screenshots | Refused read, break-glass case, chain PASS | Avaneeth |
| 5. Presentation (1) | Order, timing, Q&A | All four; Powel keeps time |
