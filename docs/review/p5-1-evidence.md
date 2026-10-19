# P5-1 evidence: claim status and mutation log (regenerated 2026-10-19)

Regenerated on `proposal/review-worth-doing-f31-f10` (on top of `main` at
`0b95f2b`) with Postgres (`DATABASE_URL` set, `CI=true`) from:

```bash
python -m tests.security.claims --table
python -m tests.security.mutations
```

Re-run both commands rather than editing this file by hand. ADR-0046 sets the
rules, amended by ADR-0054: a claim **holds** only if every system-level test
for it *ran and passed* in the run that produced this table (review N3); a
skipped test shows as UNVERIFIED. No test is marked `xfail`.

## Summary

| Claim | Status | Notes |
|---|---|---|
| C1 revoked user cannot decrypt after re-wrap | holds | The system test uses the in-memory store. Revocation on Postgres (ADR-0080) is exercised by the capture scenario (`deploy.run_scenario`, review N4), which completed on Postgres on 2026-10-19; a Postgres-backed C1 system test is still missing (exit plan E1) |
| C2 break-glass fails closed when audit cannot commit | holds, observed on Postgres | -- |
| C3 one share cannot open a record | holds | ADR-0067: the audit service validates the assertion, bound to the record, before it commits or releases share 3 |
| C4 search does not survive expiry | holds, also across a restart and a crash mid-rotation on Postgres | ADR-0069, ADR-0081 |
| C5 tampered audit entry detected | holds, observed on Postgres | -- |
| C6 illegal transition rejected | holds | N1, ADR-0058 |
| C7 bad transition signature rejected | holds | ADR-0068 |
| C8 replayed assertion rejected | holds, across two facility processes on Postgres (N13) | -- |
| C9 BOLA denied before crypto/DB | holds | ADR-0066 |
| C10 expired/revoked credential releases no key | holds, including a copied credential without the subject's signature | ADR-0082 (proof of possession) |
| C11 patient login alone releases no DEK | holds | -- |

## Claim table

| Claim | Statement | Status | Module tests | System tests |
|---|---|---|---|---|
| C1 | A revoked user cannot decrypt after re-wrap | holds | `tests/security/test_phase3_revocation_security.py::TestRevokedClinicianCannotReconstruct::test_sec_revoked_user_cannot_decrypt_after_rotation`<br>`tests/security/test_phase3_revocation_security.py::TestOldDekCannotDecryptRotated::test_sec_old_dek_cannot_decrypt_rotated_record_ciphertext` | `tests/security/test_p51_system_claims.py::test_c1_revoked_clinician_cannot_read_after_revoke_endpoint` |
| C2 | Break-glass fails closed when the audit service cannot commit | holds | `tests/security/test_phase3_audit_security.py::test_breakglass_share_not_released_when_log_commit_fails` | `tests/api/test_audit_service.py::test_release_share_fails_closed_on_commit_failure` |
| C3 | A single share, including the audit service's, cannot open a record | holds | `tests/security/test_phase3_breakglass_security.py::TestSingleShareRejected::test_single_facility_share_rejected`<br>`tests/security/test_phase3_breakglass_security.py::TestSingleShareRejected::test_single_authority_share_rejected`<br>`tests/security/test_phase3_breakglass_security.py::TestAuditShareAloneCannotOpen::test_audit_share_alone_rejected` | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_assertion_for_another_record_is_refused`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_assertion_not_signed_by_the_certificate_key_is_refused`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_clinician_from_an_untrusted_ca_is_refused`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_a_replayed_assertion_is_refused`<br>`tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_breakglass_single_share_fails`<br>`tests/security/test_p51_system_claims.py::test_c3_audit_service_releases_no_share_without_a_valid_assertion` |
| C4 | Search capability does not survive the emergency's expiry | holds | `tests/security/test_phase2_search.py::test_sec_emergency_search_stops_after_expiry` | `tests/security/test_p51_system_claims.py::test_c4_emergency_search_refused_after_expiry`<br>`tests/security/test_p51_system_claims.py::test_c4_pre_expiry_shares_do_not_restore_search`<br>`tests/security/test_restart_recovery.py::test_restart_mid_window_closes_the_record_with_a_rotation[memory]`<br>`tests/security/test_restart_recovery.py::test_restart_mid_window_closes_the_record_with_a_rotation[postgres]`<br>`tests/security/test_restart_recovery.py::test_crash_between_store_and_share_deposit_is_finished_at_restart[memory]`<br>`tests/security/test_restart_recovery.py::test_crash_between_store_and_share_deposit_is_finished_at_restart[postgres]` |
| C5 | A tampered audit entry is detected by chain verification | holds | `tests/security/test_phase3_audit_security.py::test_tampered_event_data_detected_by_chain_verification`<br>`tests/security/test_phase3_audit_security.py::test_broken_prev_hash_link_detected`<br>`tests/security/test_phase3_audit_security.py::test_replayed_entry_in_chain_position_detected` | `tests/security/test_p51_system_claims.py::test_c5_tampered_db_row_fails_the_chain_verify_endpoint` |
| C6 | An illegal state transition is rejected | holds | `tests/security/test_phase3_security.py::test_sec_illegal_state_transition_is_rejected` | `tests/security/test_p51_system_claims.py::test_c6_api_refuses_revocation_of_an_emergency_open_record` |
| C7 | A transition event with an invalid signature is rejected | holds | `tests/security/test_phase3_security.py::test_sec_transition_event_with_invalid_signature_is_rejected` | `tests/security/test_p51_system_claims.py::test_c7_breakglass_event_verifies_against_the_clinicians_certificate`<br>`tests/security/test_p51_system_claims.py::test_c7_an_event_not_signed_by_the_clinician_opens_nothing` |
| C8 | A replayed emergency assertion is rejected, not re-executed | holds | `tests/security/test_phase3_assertion_security.py::TestAssertionReplay::test_replay_rejected` | `tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_breakglass_replayed_assertion_fails`<br>`tests/security/test_p51_system_claims.py::test_c8_replayed_assertion_rejected_after_facility_restart`<br>`tests/security/test_postgres_lifecycle.py::test_c8_replayed_assertion_rejected_across_processes_on_postgres` |
| C9 | An authenticated but unauthorised caller is denied before any crypto or DB work (BOLA) | holds | none | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_a_portal_may_not_request_share_3`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_an_unsigned_request_is_refused`<br>`tests/security/test_p51_system_claims.py::test_c9_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db` |
| C10 | An expired or revoked credential fails validation and releases no key | holds | `tests/security/test_phase2_lifecycle.py::test_sec_revoked_credential_fails_validation_and_key_release`<br>`tests/security/test_phase2_lifecycle.py::test_sec_expired_credential_fails_validation_and_key_release` | `tests/api/test_authority_service.py::test_revoked_credential_fails_verification_and_key_release`<br>`tests/api/test_authority_service.py::test_expired_credential_release_fails_closed`<br>`tests/api/test_authority_service.py::test_copied_credential_without_subject_signature_gets_no_key`<br>`tests/security/test_p51_system_claims.py::test_c10_attribute_key_not_released_without_a_valid_credential` |
| C11 | A patient login alone never releases a DEK (ADR-0016) | holds | `tests/security/test_phase2_lifecycle.py::test_sec_revoked_owner_credential_denies_patient_self_access`<br>`tests/security/test_phase2_policy.py::test_sec_patient_without_owner_attribute_cannot_unwrap` | `tests/api/test_custodian_service.py::test_patient_without_owner_credential_is_refused` |

## Mutation log

Each mutation disables one control at its point of use, by monkeypatching at
pytest start-up, never by editing source. A test passes the check if at least
one of its claim's mutations turns it red. Baseline means no mutation. The
run below exited 0: every baseline was green, no test is decorative and no
mutation failed to apply.

| Claim | Test | Baseline | Mutations (red = caught) |
|---|---|---|---|
| C1 | `tests/security/test_p51_system_claims.py::test_c1_revoked_clinician_cannot_read_after_revoke_endpoint` | green | C1a: red, C1b: red, C1c: green |
| C1 | `tests/security/test_phase3_revocation_security.py::TestRevokedClinicianCannotReconstruct::test_sec_revoked_user_cannot_decrypt_after_rotation` | green | C1a: red, C1b: green, C1c: green |
| C1 | `tests/security/test_phase3_revocation_security.py::TestOldDekCannotDecryptRotated::test_sec_old_dek_cannot_decrypt_rotated_record_ciphertext` | green | C1a: green, C1b: green, C1c: red |
| C2 | `tests/api/test_audit_service.py::test_release_share_fails_closed_on_commit_failure` | green | C2a: red |
| C2 | `tests/security/test_phase3_audit_security.py::test_breakglass_share_not_released_when_log_commit_fails` | green | C2a: red |
| C3 | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_assertion_for_another_record_is_refused` | green | C3a: green, C3b: red |
| C3 | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_assertion_not_signed_by_the_certificate_key_is_refused` | green | C3a: green, C3b: red |
| C3 | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_clinician_from_an_untrusted_ca_is_refused` | green | C3a: green, C3b: red |
| C3 | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_a_replayed_assertion_is_refused` | green | C3a: green, C3b: red |
| C3 | `tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_breakglass_single_share_fails` | green | C3a: red, C3b: green |
| C3 | `tests/security/test_p51_system_claims.py::test_c3_audit_service_releases_no_share_without_a_valid_assertion` | green | C3a: green, C3b: red |
| C3 | `tests/security/test_phase3_breakglass_security.py::TestSingleShareRejected::test_single_facility_share_rejected` | green | C3a: red, C3b: green |
| C3 | `tests/security/test_phase3_breakglass_security.py::TestSingleShareRejected::test_single_authority_share_rejected` | green | C3a: red, C3b: green |
| C3 | `tests/security/test_phase3_breakglass_security.py::TestAuditShareAloneCannotOpen::test_audit_share_alone_rejected` | green | C3a: red, C3b: green |
| C4 | `tests/security/test_p51_system_claims.py::test_c4_emergency_search_refused_after_expiry` | green | C4a: red, C4b: green |
| C4 | `tests/security/test_p51_system_claims.py::test_c4_pre_expiry_shares_do_not_restore_search` | green | C4a: green, C4b: red |
| C4 | `tests/security/test_phase2_search.py::test_sec_emergency_search_stops_after_expiry` | green | C4a: red, C4b: green |
| C4 | `tests/security/test_restart_recovery.py::test_restart_mid_window_closes_the_record_with_a_rotation[memory]` | green | C4a: green, C4b: red |
| C4 | `tests/security/test_restart_recovery.py::test_restart_mid_window_closes_the_record_with_a_rotation[postgres]` | green | C4a: green, C4b: red |
| C4 | `tests/security/test_restart_recovery.py::test_crash_between_store_and_share_deposit_is_finished_at_restart[memory]` | green | C4a: green, C4b: red |
| C4 | `tests/security/test_restart_recovery.py::test_crash_between_store_and_share_deposit_is_finished_at_restart[postgres]` | green | C4a: green, C4b: red |
| C5 | `tests/security/test_p51_system_claims.py::test_c5_tampered_db_row_fails_the_chain_verify_endpoint` | green | C5a: green, C5b: red |
| C5 | `tests/security/test_phase3_audit_security.py::test_tampered_event_data_detected_by_chain_verification` | green | C5a: red, C5b: green |
| C5 | `tests/security/test_phase3_audit_security.py::test_broken_prev_hash_link_detected` | green | C5a: green, C5b: red |
| C5 | `tests/security/test_phase3_audit_security.py::test_replayed_entry_in_chain_position_detected` | green | C5a: green, C5b: red |
| C6 | `tests/security/test_p51_system_claims.py::test_c6_api_refuses_revocation_of_an_emergency_open_record` | green | C6a: red, C6b: green |
| C6 | `tests/security/test_phase3_security.py::test_sec_illegal_state_transition_is_rejected` | green | C6a: red, C6b: green |
| C7 | `tests/security/test_p51_system_claims.py::test_c7_breakglass_event_verifies_against_the_clinicians_certificate` | green | C7a: red |
| C7 | `tests/security/test_p51_system_claims.py::test_c7_an_event_not_signed_by_the_clinician_opens_nothing` | green | C7a: red |
| C7 | `tests/security/test_phase3_security.py::test_sec_transition_event_with_invalid_signature_is_rejected` | green | C7a: red |
| C8 | `tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_breakglass_replayed_assertion_fails` | green | C8a: red |
| C8 | `tests/security/test_p51_system_claims.py::test_c8_replayed_assertion_rejected_after_facility_restart` | green | C8a: red |
| C8 | `tests/security/test_phase3_assertion_security.py::TestAssertionReplay::test_replay_rejected` | green | C8a: red |
| C8 | `tests/security/test_postgres_lifecycle.py::test_c8_replayed_assertion_rejected_across_processes_on_postgres` | green | C8a: red |
| C9 | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_a_portal_may_not_request_share_3` | green | C9a: red, C9b: green |
| C9 | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_an_unsigned_request_is_refused` | green | C9a: red, C9b: green |
| C9 | `tests/security/test_p51_system_claims.py::test_c9_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db` | green | C9a: red, C9b: red |
| C10 | `tests/api/test_authority_service.py::test_revoked_credential_fails_verification_and_key_release` | green | C10a: red, C10b: green |
| C10 | `tests/api/test_authority_service.py::test_expired_credential_release_fails_closed` | green | C10a: red, C10b: green |
| C10 | `tests/api/test_authority_service.py::test_copied_credential_without_subject_signature_gets_no_key` | green | C10a: green, C10b: red |
| C10 | `tests/security/test_p51_system_claims.py::test_c10_attribute_key_not_released_without_a_valid_credential` | green | C10a: red, C10b: red |
| C10 | `tests/security/test_phase2_lifecycle.py::test_sec_revoked_credential_fails_validation_and_key_release` | green | C10a: red, C10b: green |
| C10 | `tests/security/test_phase2_lifecycle.py::test_sec_expired_credential_fails_validation_and_key_release` | green | C10a: red, C10b: green |

Mutations:

- C1a: new tree still admits the revoked party.
- C1b: rotation does not re-encrypt the record.
- C1c: library revocation keeps the old ciphertext.
- C2a: share released despite a failed commit.
- C3a: gate threshold lowered to one share.
- C3b: audit service releases without validating the assertion.
- C4a: emergency key outlives its session.
- C4b: expiry re-baselines without rotating.
- C5a: entry signatures not checked.
- C5b: prev_hash/seq links not checked.
- C6a: LEGAL_TRANSITIONS not enforced.
- C6b: state compare-and-set overwrites any state.
- C7a: transition signature not checked.
- C8a: consumed assertion ids forgotten.
- C9a: service authentication lets any caller in.
- C9b: read loads the record before the key check.
- C10a: credential validation skipped.
- C10b: key released without proof of possession.

One claim is not mutated:

- **C11:** the control is the absence of the owner key. There is no switch to
  flip, so its tests carry a positive control instead.

## Findings made while writing the suite

- **Hardened:** the expired-credential test (C10) and the
  patient-without-owner-key test (C11) had no positive control. Both now first
  show the same fixture succeeding legitimately.
- **Untagged as C2 evidence:**
  `tests/api/test_custodian_service.py::test_breakglass_fails_closed_when_audit_cannot_commit`.
  It drives a fake audit service, so it tests the custodian's error
  propagation, not the audit commit gate.
- **Fixture bug in `tests/api/conftest.py` (Avaneeth), since fixed:**
  `test_setup` used to insert a second `"emergency"` wrapping of the policy
  **root secret**, so break-glass in the API tests handed the clinician the
  root secret, not the DEK. It now inserts `ingest_record`'s
  `emergency_dek_wrapping`, the record's DEK under the emergency key.
