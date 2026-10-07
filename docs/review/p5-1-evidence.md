# P5-1 evidence: claim status and mutation log (2026-10-07)

Generated on `phase5-task1` from:

```bash
python -m tests.security.claims --table
python -m tests.security.mutations
```

Re-run both commands rather than editing this file by hand. ADR-0046 sets the
rules. A claim **holds** only if every system-level test for it runs without
`xfail`. Tests that fail today keep their full assertion and are marked
`xfail(strict=True)` with the review finding that blocks them.

## Summary

| Claim | Status today | Blocking finding |
|---|---|---|
| C1 revoked user cannot decrypt after re-wrap | holds (in-memory store) | Postgres revoke path not covered here (F10) |
| C2 break-glass fails closed when audit cannot commit | holds, **Postgres-backed, not observed locally** | — |
| C3 one share cannot open a record | fails | F2 / D1 |
| C4 search does not survive expiry | fails | F9 / D3 |
| C5 tampered audit entry detected | holds, **Postgres-backed, not observed locally** | — |
| C6 illegal transition rejected | fails | F11 / D7 |
| C7 bad transition signature rejected | fails | D8 / F11 |
| C8 replayed assertion rejected | holds (2026-10-08, F22 fix on `proposal/phase5-fixes`) | — |
| C9 BOLA denied before crypto/DB | fails | F34 / D5 |
| C10 expired/revoked credential releases no key | fails | F14 |
| C11 patient login alone releases no DEK | holds | — |

Each `xfail` was also run with `--runxfail` to confirm it fails on the
security assertion itself, not on setup:

- C3: the share is released.
- C4: the old shares re-open the record and search matches again.
- C6: the API returns 200.
- C7: `InvalidSignatureError` under the clinician's key.
- C9: the repository is touched before authorization.
- C10: `/attribute-keys/author` returns 200.

## Claim table

| Claim | Statement | Status | Module tests | System tests |
|---|---|---|---|---|
| C1 | A revoked user cannot decrypt after re-wrap | holds | `tests/security/test_phase3_revocation_security.py::TestRevokedClinicianCannotReconstruct::test_sec_revoked_user_cannot_decrypt_after_rotation`<br>`tests/security/test_phase3_revocation_security.py::TestOldDekCannotDecryptRotated::test_sec_old_dek_cannot_decrypt_rotated_record_ciphertext` | `tests/security/test_p51_system_claims.py::test_c1_revoked_clinician_cannot_read_after_revoke_endpoint` |
| C2 | Break-glass fails closed when the audit service cannot commit | holds | `tests/security/test_phase3_audit_security.py::test_breakglass_share_not_released_when_log_commit_fails` | `tests/api/test_audit_service.py::test_release_share_fails_closed_on_commit_failure` |
| C3 | A single share, including the audit service's, cannot open a record | fails today: F2/D1 | `tests/security/test_phase3_breakglass_security.py::…::test_single_facility_share_rejected`<br>`…::test_single_authority_share_rejected`<br>`…::test_audit_share_alone_rejected` | `tests/api/test_breakglass.py::…::test_breakglass_single_share_fails`<br>`tests/security/test_p51_system_claims.py::test_c3_audit_service_releases_no_share_without_a_valid_assertion` (xfail) |
| C4 | Search capability does not survive the emergency's expiry | fails today: F9/D3 | `tests/security/test_phase2_search.py::test_sec_emergency_search_stops_after_expiry` | `tests/security/test_p51_system_claims.py::test_c4_emergency_search_refused_after_expiry`<br>`…::test_c4_pre_expiry_shares_do_not_restore_search` (xfail) |
| C5 | A tampered audit entry is detected by chain verification | holds | `tests/security/test_phase3_audit_security.py::test_tampered_event_data_detected_by_chain_verification`<br>`…::test_broken_prev_hash_link_detected`<br>`…::test_replayed_entry_in_chain_position_detected` | `tests/security/test_p51_system_claims.py::test_c5_tampered_db_row_fails_the_chain_verify_endpoint` |
| C6 | An illegal state transition is rejected | fails today: F11/D7 | `tests/security/test_phase3_security.py::test_sec_illegal_state_transition_is_rejected` | `tests/security/test_p51_system_claims.py::test_c6_api_refuses_revocation_of_an_emergency_open_record` (xfail) |
| C7 | A transition event with an invalid signature is rejected | fails today: D8/F11 | `tests/security/test_phase3_security.py::test_sec_transition_event_with_invalid_signature_is_rejected` | `tests/security/test_p51_system_claims.py::test_c7_breakglass_event_verifies_against_the_clinicians_certificate` (xfail) |
| C8 | A replayed emergency assertion is rejected, not re-executed | holds | `tests/security/test_phase3_assertion_security.py::TestAssertionReplay::test_replay_rejected` | `tests/api/test_breakglass.py::…::test_breakglass_replayed_assertion_fails`<br>`tests/security/test_p51_system_claims.py::test_c8_replayed_assertion_rejected_after_facility_restart` |
| C9 | An authenticated but unauthorised caller is denied before any crypto or DB work (BOLA) | fails today: F34/D5 | none | `tests/security/test_p51_system_claims.py::test_c9_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db` (xfail) |
| C10 | An expired or revoked credential fails validation and releases no key | fails today: F14 | `tests/security/test_phase2_lifecycle.py::test_sec_revoked_credential_fails_validation_and_key_release`<br>`…::test_sec_expired_credential_fails_validation_and_key_release` | `tests/api/test_authority_service.py::test_revoked_credential_fails_verification_and_key_release`<br>`…::test_expired_credential_release_fails_closed`<br>`tests/security/test_p51_system_claims.py::test_c10_attribute_key_not_released_without_a_valid_credential` (xfail) |
| C11 | A patient login alone never releases a DEK (ADR-0016) | holds | `tests/security/test_phase2_lifecycle.py::test_sec_revoked_owner_credential_denies_patient_self_access`<br>`tests/security/test_phase2_policy.py::test_sec_patient_without_owner_attribute_cannot_unwrap` | `tests/api/test_custodian_service.py::test_patient_without_owner_credential_is_refused` |

## Mutation log

Each mutation disables one control at its point of use, by monkeypatching at
pytest start-up, never by editing source. A test passes the check if at least
one of its claim's mutations turns it red. Baseline means no mutation.

| Claim | Test | Baseline | Mutations |
|---|---|---|---|
| C1 | `test_c1_revoked_clinician_cannot_read_after_revoke_endpoint` | green | C1a red, C1b red |
| C1 | `test_sec_revoked_user_cannot_decrypt_after_rotation` | green | C1a red, C1b green |
| C1 | `test_sec_old_dek_cannot_decrypt_rotated_record_ciphertext` | green | C1a green, C1b red |
| C2 | `test_release_share_fails_closed_on_commit_failure` | skipped (no Postgres) | C2a skipped |
| C2 | `test_breakglass_share_not_released_when_log_commit_fails` | skipped (no Postgres) | C2a skipped |
| C3 | `test_breakglass_single_share_fails` (API) | green | C3a red |
| C3 | `test_single_facility_share_rejected` | green | C3a red |
| C3 | `test_single_authority_share_rejected` | green | C3a red |
| C3 | `test_audit_share_alone_rejected` | green | C3a red |
| C4 | `test_c4_emergency_search_refused_after_expiry` | green | C4a red |
| C4 | `test_sec_emergency_search_stops_after_expiry` | green | C4a red |
| C5 | all four C5 tests | skipped (no Postgres) | C5a / C5b skipped |
| C6 | `test_sec_illegal_state_transition_is_rejected` | green | C6a red |
| C7 | `test_sec_transition_event_with_invalid_signature_is_rejected` | green | C7a red |
| C8 | `test_breakglass_replayed_assertion_fails` (API) | green | C8a red |
| C8 | `test_replay_rejected` | green | C8a red |
| C8 | `test_c8_replayed_assertion_rejected_after_facility_restart` (added 2026-10-08) | green | C8a red |
| C10 | both API credential tests, both module credential tests | green | C10a red |

Mutations:

- C1a: the new tree still admits the revoked party.
- C1b: rotation does not re-encrypt.
- C2a: the share is released despite a failed commit.
- C3a: the gate threshold is lowered to 1.
- C4a: the emergency key outlives its session.
- C5a: entry signatures are not checked.
- C5b: prev_hash/seq links are not checked.
- C6a: LEGAL_TRANSITIONS is not enforced.
- C7a: the transition signature is not checked.
- C8a: consumed assertion ids are forgotten.
- C10a: credential validation is skipped.

Two claims are not mutated:

- **C9:** no holding test yet.
- **C11:** the control is the absence of the owner key. There is no switch to
  flip, so its tests carry a positive control instead.

**Open:** the C2 and C5 rows have not been observed going red. They need
Postgres. Re-run `python -m tests.security.mutations C2 C5` with
`DATABASE_URL` pointing at a throwaway test database (the fixtures drop the
`public` schema) and replace those rows.

## Findings made while writing the suite

- **Hardened:** the expired-credential test (C10) and the
  patient-without-owner-key test (C11) had no positive control. Both now first
  show the same fixture succeeding legitimately.
- **Untagged as C2 evidence:**
  `tests/api/test_custodian_service.py::test_breakglass_fails_closed_when_audit_cannot_commit`.
  It drives a fake audit service, so it tests the custodian's error
  propagation, not the audit commit gate.
- **Fixture bug in `tests/api/conftest.py` (Avaneeth):** `test_setup` inserts a
  second `"emergency"` wrapping of the policy **root secret**, and the
  repository returns the last one. So break-glass in the API tests hands the
  clinician the root secret, not the DEK. The P5-1 system tests use their own
  fixture seeded with `ingest_record`'s `emergency_dek_wrapping`. The shared
  fixture should be fixed by its owner.
