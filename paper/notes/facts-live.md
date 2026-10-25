# facts-live — live claims run and full test suite

Stage 2 live-check subagent. The only source the paper may use for the status
of claims C1–C11 and for test-suite totals. Cite as `% src: facts-live#N`.

## Run metadata

- Date/time: claims run 2026-10-21 19:53:47–19:53:57 +0530; full suite run 1
  19:54:11–19:55:41 +0530; run 2 (totals) ended 19:57:26 +0530.
- Commit: `57a1a8c` (`git rev-parse --short HEAD`), branch `paper/ieee-draft`.
- Working tree: `git status --short` shows only untracked `paper/data/`,
  `paper/main.tex`, `paper/notes/`, `paper/refs.bib` (no `src/` or `tests/` changes).
- Python: 3.11.9 (`.venv/Scripts/python.exe`), Windows 11.
- tshark: `TShark (Wireshark) 4.6.9 (v4.6.9-0-g2d548b197c75).` (`C:\Program Files\Wireshark` prepended to PATH).
- Database: `DATABASE_URL=postgresql://postgres@127.0.0.1:55433/ehr_test`
  (host 127.0.0.1, port 55433), Docker container `ci-pg`, image
  `postgres:16-alpine` (already running and `pg_isready`; no image pulled). `CI` not set.
- Env: `PYTHONUTF8=1`.
- Raw output: `paper/notes/live-claims-raw.txt`, `paper/notes/live-pytest-raw.txt`.

## Claims (live claims run 2026-10-21 @57a1a8c)

Command: `.venv/Scripts/python.exe -m tests.security.claims --table` (exit 0, 9.8 s).
`--table` prints the status, not per-node counts. By `claim_status`
(`tests/security/claims.py:175-201`), "holds" is returned only when every
system-level test of the claim has outcome `passed` (any skip → UNVERIFIED,
any xfail → fails today, anything else → BROKEN). So for each claim below,
system tests passed = the number listed, skipped = 0, failed = 0. Module-level
outcomes are not shown by `--table` and do not affect status.

1. C1: status `holds` — 2 system-level tests passed, 0 skipped, 0 failed/xfailed (2 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
2. C2: status `holds` — 1 system-level tests passed, 0 skipped, 0 failed/xfailed (1 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
3. C3: status `holds` — 10 system-level tests passed, 0 skipped, 0 failed/xfailed (4 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
4. C4: status `holds` — 6 system-level tests passed, 0 skipped, 0 failed/xfailed (1 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
5. C5: status `holds` — 1 system-level tests passed, 0 skipped, 0 failed/xfailed (3 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
6. C6: status `holds` — 1 system-level tests passed, 0 skipped, 0 failed/xfailed (1 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
7. C7: status `holds` — 2 system-level tests passed, 0 skipped, 0 failed/xfailed (1 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
8. C8: status `holds` — 4 system-level tests passed, 0 skipped, 0 failed/xfailed (1 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
9. C9: status `holds` — 3 system-level tests passed, 0 skipped, 0 failed/xfailed (0 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
10. C10: status `holds` — 4 system-level tests passed, 0 skipped, 0 failed/xfailed (2 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
11. C11: status `holds` — 1 system-level tests passed, 0 skipped, 0 failed/xfailed (2 module-level tests tagged, outcomes not reported). — live claims run 2026-10-21 @57a1a8c
12. All 11 claims hold at system level on this run; 35 system-level claim nodes passed in total (C4's two restart tests each run as `[memory]` and `[postgres]`, so the Postgres-backed C4 variants and the Postgres C1/C8 tests did run, not skip). No claim is `fails today`, `UNVERIFIED (skipped)` or `BROKEN`. — live claims run 2026-10-21 @57a1a8c
13. The claims table as printed (verbatim):

```
| Claim | Statement | Status | Module tests | System tests |
|---|---|---|---|---|
| C1 | A revoked user cannot decrypt after re-wrap | holds | `tests/security/test_phase3_revocation_security.py::TestRevokedClinicianCannotReconstruct::test_sec_revoked_user_cannot_decrypt_after_rotation`<br>`tests/security/test_phase3_revocation_security.py::TestOldDekCannotDecryptRotated::test_sec_old_dek_cannot_decrypt_rotated_record_ciphertext` | `tests/security/test_p51_system_claims.py::test_c1_revoked_clinician_cannot_read_after_revoke_endpoint`<br>`tests/security/test_postgres_lifecycle.py::test_c1_revoked_clinician_cannot_read_on_postgres` |
| C2 | Break-glass fails closed when the audit service cannot commit | holds | `tests/security/test_phase3_audit_security.py::test_breakglass_share_not_released_when_log_commit_fails` | `tests/api/test_audit_service.py::test_release_share_fails_closed_on_commit_failure` |
| C3 | A single share, including the audit service's, cannot open a record | holds | `tests/security/test_phase3_breakglass_security.py::TestSingleShareRejected::test_single_facility_share_rejected`<br>`tests/security/test_phase3_breakglass_security.py::TestSingleShareRejected::test_single_authority_share_rejected`<br>`tests/security/test_phase3_breakglass_security.py::TestNoPairWithoutTheAuditServiceOpens::test_custodian_and_home_authority_together_rejected`<br>`tests/security/test_phase3_breakglass_security.py::TestAuditShareAloneCannotOpen::test_audit_share_alone_rejected` | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_assertion_for_another_record_is_refused`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_assertion_not_signed_by_the_certificate_key_is_refused`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_clinician_from_an_untrusted_ca_is_refused`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_a_replayed_assertion_is_refused`<br>`tests/api/test_authority_share_custody.py::TestReleaseNeedsAValidAssertion::test_assertion_for_another_record_releases_nothing`<br>`tests/api/test_authority_share_custody.py::TestReleaseNeedsAValidAssertion::test_assertion_not_signed_by_the_certificate_key_releases_nothing`<br>`tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_breakglass_single_share_fails`<br>`tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_custodian_and_home_authority_shares_alone_open_nothing`<br>`tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_audit_service_shares_alone_open_nothing`<br>`tests/security/test_p51_system_claims.py::test_c3_audit_service_releases_no_share_without_a_valid_assertion` |
| C4 | Search capability does not survive the emergency's expiry | holds | `tests/security/test_phase2_search.py::test_sec_emergency_search_stops_after_expiry` | `tests/security/test_p51_system_claims.py::test_c4_emergency_search_refused_after_expiry`<br>`tests/security/test_p51_system_claims.py::test_c4_pre_expiry_shares_do_not_restore_search`<br>`tests/security/test_restart_recovery.py::test_restart_mid_window_closes_the_record_with_a_rotation[memory]`<br>`tests/security/test_restart_recovery.py::test_restart_mid_window_closes_the_record_with_a_rotation[postgres]`<br>`tests/security/test_restart_recovery.py::test_crash_between_store_and_share_deposit_is_finished_at_restart[memory]`<br>`tests/security/test_restart_recovery.py::test_crash_between_store_and_share_deposit_is_finished_at_restart[postgres]` |
| C5 | A tampered audit entry is detected by chain verification | holds | `tests/security/test_phase3_audit_security.py::test_tampered_event_data_detected_by_chain_verification`<br>`tests/security/test_phase3_audit_security.py::test_broken_prev_hash_link_detected`<br>`tests/security/test_phase3_audit_security.py::test_replayed_entry_in_chain_position_detected` | `tests/security/test_p51_system_claims.py::test_c5_tampered_db_row_fails_the_chain_verify_endpoint` |
| C6 | An illegal state transition is rejected | holds | `tests/security/test_phase3_security.py::test_sec_illegal_state_transition_is_rejected` | `tests/security/test_p51_system_claims.py::test_c6_api_refuses_revocation_of_an_emergency_open_record` |
| C7 | A transition event with an invalid signature is rejected | holds | `tests/security/test_phase3_security.py::test_sec_transition_event_with_invalid_signature_is_rejected` | `tests/security/test_p51_system_claims.py::test_c7_breakglass_event_verifies_against_the_clinicians_certificate`<br>`tests/security/test_p51_system_claims.py::test_c7_an_event_not_signed_by_the_clinician_opens_nothing` |
| C8 | A replayed emergency assertion is rejected, not re-executed | holds | `tests/security/test_phase3_assertion_security.py::TestAssertionReplay::test_replay_rejected` | `tests/api/test_authority_share_custody.py::TestReleaseNeedsAValidAssertion::test_a_replayed_assertion_releases_nothing`<br>`tests/api/test_breakglass.py::TestHospitalBreakglassEndpoint::test_breakglass_replayed_assertion_fails`<br>`tests/security/test_p51_system_claims.py::test_c8_replayed_assertion_rejected_after_facility_restart`<br>`tests/security/test_postgres_lifecycle.py::test_c8_replayed_assertion_rejected_across_processes_on_postgres` |
| C9 | An authenticated but unauthorised caller is denied before any crypto or DB work (BOLA) | holds | none | `tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_a_portal_may_not_request_share_3`<br>`tests/api/test_audit_service.py::TestReleaseNeedsAValidAssertion::test_an_unsigned_request_is_refused`<br>`tests/security/test_p51_system_claims.py::test_c9_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db` |
| C10 | An expired or revoked credential fails validation and releases no key | holds | `tests/security/test_phase2_lifecycle.py::test_sec_revoked_credential_fails_validation_and_key_release`<br>`tests/security/test_phase2_lifecycle.py::test_sec_expired_credential_fails_validation_and_key_release` | `tests/api/test_authority_service.py::test_revoked_credential_fails_verification_and_key_release`<br>`tests/api/test_authority_service.py::test_expired_credential_release_fails_closed`<br>`tests/api/test_authority_service.py::test_copied_credential_without_subject_signature_gets_no_key`<br>`tests/security/test_p51_system_claims.py::test_c10_attribute_key_not_released_without_a_valid_credential` |
| C11 | A patient login alone never releases a DEK (ADR-0016) | holds | `tests/security/test_phase2_lifecycle.py::test_sec_revoked_owner_credential_denies_patient_self_access`<br>`tests/security/test_phase2_policy.py::test_sec_patient_without_owner_attribute_cannot_unwrap` | `tests/api/test_custodian_service.py::test_patient_without_owner_credential_is_refused` |
```

— live claims run 2026-10-21 @57a1a8c

## Full suite (pytest, 2026-10-21 @57a1a8c, against Postgres)

14. Totals: **1006 passed, 0 failed, 0 errors, 2 skipped, 0 xfailed, 0 xpassed, 0 deselected** (1008 tests), 3 warnings, 86.52 s (run 2: `pytest tests -o addopts="" -q -rfEsx`). Run 1 (`pytest tests -q -rfEsx`, exactly as specified) also exited 0 with the same two skips and 1006 passes counted from the progress dots, in ~90 s wall clock. — `paper/notes/live-pytest-raw.txt`
15. SKIPPED `tests/wire/test_capture.py::test_require_dumpcap_raises_clearly_when_absent` — reason "dumpcap present; cannot test the absent-tool path here" (`tests/wire/test_capture.py:40`). Environmental, by design: it tests the missing-tool path.
16. SKIPPED `tests/wire/test_capture.py::test_capture_scenario_needs_dumpcap` — reason "dumpcap present; the missing-tool path is not exercised" (`tests/wire/test_capture.py:48`). Environmental, by design.
17. No test failed, errored, xfailed or xpassed; no test is deselected. No claim-tagged test was skipped. — `paper/notes/live-pytest-raw.txt`

## Comparison with docs/test-evidence/claim-table.md

- Snapshot: dated 2026-10-21, run on branch `proposal/breakglass-3-of-4`;
  records **no commit sha**. Last changed in commit `99092d1`
  (2026-10-21 18:50 +0530). This run: `57a1a8c`, 2026-10-21 19:53 +0530.
  Per facts-F5#53, `99092d1..57a1a8c` has no `src/`, `tests/`, `wire/` or `deploy/` changes.
- Claim statuses: **no differences** — the snapshot lists all of C1–C11 as
  "Holds"; this run prints `holds` for all eleven.
- Suite totals: **no differences** — snapshot "1006 passed, 2 skipped, 0 failed,
  0 expected-fail (1008 collected)", same two `test_capture.py` skips.
- Wording: the snapshot's "What it proves" and "System-level evidence" columns
  are hand-written paraphrases (e.g. C1 "after the key is rotated", C11 "never
  releases a key"); the live table prints the `claims.py` statements
  ("after re-wrap", "never releases a DEK (ADR-0016)"). The paper should quote
  the live wording.

## Anomalies

- The specified command `pytest tests -q -rfEsx` prints no totals line because
  `pyproject.toml` addopts already contains `-q` (`-ra -q`), making it `-qq`.
  Totals were taken from a second identical run with `-o addopts=""`; both runs
  green with the same skips, so no flakiness observed across two full runs.
- Warnings (not failures): `StarletteDeprecationWarning` (httpx with
  `starlette.testclient`) from `fastapi/testclient.py`; two websockets
  `DeprecationWarning`s from uvicorn in `tests/demo/test_demo.py::test_seed_synthetic_data_integration`.
  Third-party deprecations; no effect on claims.
- `--table` does not report per-node outcomes or module-level results; the
  per-claim counts above are derived from the `holds` definition. Mutation
  testing (`tests.security.mutations`) was not run here; claims that tests
  are non-decorative still rest on facts-F5 §D.
- Not covered by this run: the 85 Django portal tests and the Docker live
  end-to-end checks (outside `tests/`).
