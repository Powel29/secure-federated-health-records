# facts-F1: key-lifecycle state machine (extracted from code; branch paper/ieee-draft, HEAD 57a1a8c)

Scope: src/lifecycle/, src/contracts/, and the src/api, src/custodian and deploy/ call sites that emit or apply lifecycle transitions. Test node ids show that a test exists. F1 did not run them, so they are not live-run evidence.

## States and contract

1. The lifecycle has exactly four states, defined as `LifecycleState(str, Enum)`: `GRANTED = "granted"`, `REVOKED = "revoked"`, `EMERGENCY_OPEN = "emergency_open"`, `EXPIRED = "expired"`. — src/contracts/enums.py:14-20
2. `ReasonCode` is a closed enum of 13 clinical reasons (e.g. `CARDIAC_ARREST`, `STROKE`, `OTHER_LIFE_THREATENING`) and is never free text. — src/contracts/enums.py:23-43
3. A transition is carried by the frozen contract `TransitionEvent` with these fields: `event_id: UUID`, `record_id`, `from_state`, `to_state`, `actor_id`, `reason_code: ReasonCode | None`, `issued_at: AwareDatetime`, `nonce: bytes`, `signature: bytes`. — src/contracts/lifecycle.py:18-41; docs/adr/0030-lifecycle-state-machine.md (Status: Accepted)
4. The `TransitionEvent` contract rejects a nonce shorter than 16 bytes (128 bits) and an empty signature. — src/contracts/lifecycle.py:43-59; src/contracts/base.py:61
5. Every contract model is `frozen=True` and `extra="forbid"`, so a signed event cannot be mutated after signing and an unknown field is rejected. — src/contracts/base.py:64-82
6. `TransitionEvent` has no `expiry_ts` field. The contract says emergency time-boxing is carried elsewhere. — src/contracts/lifecycle.py:26-30
7. `DEKWrapping` carries `wrapping_id, record_id, wrapped_for, wrapped_dek, nonce (12-byte GCM), generation (int >= 0), created_at`. `generation` is the rotation counter: a re-wrap produces a higher generation. — src/contracts/records.py:49-80
8. `Record` carries ciphertext only (AES-256-GCM, 12-byte nonce) plus `record_id, patient_id, facility_id, policy_id, content_type, aad, created_at, clinical`. — src/contracts/records.py:16-46
9. A record enters the lifecycle in `GRANTED` at ingest. Ingest also creates its first emergency wrapping at generation 0. — src/records/ingest.py:220-235
10. The state machine stores no per-record state. The caller passes `current_state` on every `apply_transition`, and the machine keeps only a consumed-event-id store. — src/lifecycle/state_machine.py:10-14, 291-308

## Legal transitions

11. `LEGAL_TRANSITIONS` is a frozenset of exactly seven `(from, to)` pairs: GRANTED→REVOKED, GRANTED→EMERGENCY_OPEN, REVOKED→GRANTED, REVOKED→EMERGENCY_OPEN, EMERGENCY_OPEN→EXPIRED, EXPIRED→GRANTED, EXPIRED→REVOKED. — src/lifecycle/state_machine.py:52-62
12. ADR-0030 introduced six of these pairs. ADR-0058 added EXPIRED→REVOKED so that expiry restores a revocation. — src/lifecycle/state_machine.py:46-51; docs/adr/0030-lifecycle-state-machine.md (Status: Accepted); docs/adr/0058-expiry-restores-pre-emergency-state.md (Status: Proposed)
13. The code comment says any extension, for example EMERGENCY_OPEN→REVOKED for premature termination, needs an ADR. The machine has no premature-termination transition. — src/lifecycle/state_machine.py:48-51; docs/adr/0030-lifecycle-state-machine.md (Status: Accepted)
14. `EMERGENCY_OPEN` can be entered only from `GRANTED` or `REVOKED`. Such a transition must carry a `reason_code`, or `MissingReasonCodeError` is raised. — src/lifecycle/state_machine.py:64-69, 127-130
15. Self-transitions are illegal (no `(s, s)` pair is in the set). — src/lifecycle/state_machine.py:52-62; tests/security/test_phase3_security.py::test_sec_self_transition_is_rejected
16. GRANTED→EXPIRED is illegal. — tests/security/test_phase3_expiry_security.py::TestIllegalExpiryTransitionsFailClosed::test_granted_to_expired_directly_rejected

## Illegal-transition handling (fail closed)

17. `validate_transition` raises `IllegalTransitionError("<from> -> <to> is not a legal transition")` for any pair not in `LEGAL_TRANSITIONS`. — src/lifecycle/state_machine.py:123-126
18. `IllegalTransitionError` subclasses `LifecycleError`, which subclasses `crypto_core.exceptions.CryptoError`. — src/lifecycle/exceptions.py:5-13
19. `create_transition_event` runs `validate_transition` before generating the id, the nonce or the signature, so an illegal transition never yields a signed artifact. — src/lifecycle/state_machine.py:161-167
20. `verify_transition_event` checks the ECDSA signature first and only then re-runs `validate_transition`. A tampered `to_state` therefore surfaces as `InvalidSignatureError`, not as an illegal transition. — src/lifecycle/state_machine.py:217-232; docs/adr/0030-lifecycle-state-machine.md (Status: Accepted)
21. `apply_transition` runs in this order: (1) signature and legality, (2) `event.from_state == current_state`, else `StateMismatchError`, (3) consume `event_id`, else `ReplayedEventError`. It then returns `event.to_state`. — src/lifecycle/state_machine.py:310-350
22. `event_id` is consumed only after the signature is verified, so a forged event cannot burn a legitimate id. — src/lifecycle/state_machine.py:323-325, 343-349; tests/security/test_phase3_security.py::test_sec_consumed_id_check_runs_after_signature_check
23. `ConsumedEventIds.consume` raises `ReplayedEventError` on the second use of an id. It is lock-guarded and can take a durable backend (`consume_once`). — src/lifecycle/state_machine.py:248-281
24. In the deployed facility, the expiry manager's state machine and the revocation state machine both use `ConsumedEventIds(backend=repo)`, so consumed ids survive a restart. — deploy/asgi/facility.py:153-155; src/api/hospital.py:616
25. Separately from the state machine, the store does its own compare-and-set: `transition_lifecycle_state(record_id, expected, new, last_event_id)` raises `StateConflictError` if the stored state is not `expected`. — src/api/repository.py:319-333 (in-memory), 537-549 (Postgres); src/lifecycle/exceptions.py:16-22; docs/adr/0050-lifecycle-state-compare-and-set.md (Status: Proposed)
26. Negative tests exist for an illegal pair, field tampering and a replayed event id. — tests/security/test_phase3_security.py::test_sec_illegal_state_transition_is_rejected; ::test_sec_field_tampering_breaks_signature; ::test_sec_replayed_event_id_is_rejected

## Signature format

27. The signed bytes are `encode_fields("ehr/transition-event/v1", [...])`: a domain tag, then these length-prefixed fields in order: event_id (str), record_id, from_state.value, to_state.value, actor_id, reason_code.value (or empty bytes), issued_at as UTC ISO-8601, nonce. — src/lifecycle/state_machine.py:39, 72-101; src/crypto_core/encoding.py:21-28
28. Signatures are ECDSA on P-256 with SHA-256, computed through `crypto_core.sign`/`verify`. — src/lifecycle/state_machine.py:27, 182, 227; src/crypto_core/asymmetric.py:1, 32-33
29. `event_id` comes from `uuid4()` and the nonce from `secrets.token_bytes(16)`. — src/lifecycle/state_machine.py:44, 168-169

## Who signs each transition (call sites)

30. GRANTED/REVOKED→EMERGENCY_OPEN is signed with the clinician's own key inside the custodian, as `actor_id = clinician_id`, with the assertion's `reason_code`. — src/custodian/__init__.py:100-126
31. The facility verifies that event against the clinician's certificate key. It also requires the event to match this record, `to_state = EMERGENCY_OPEN`, `actor_id = clinician_id`, `reason_code` = the assertion's reason code, and an `issued_at` within `MAX_ASSERTION_TTL` (15 min) / `ASSERTION_CLOCK_SKEW` (30 s). — src/api/hospital.py:1580-1632; src/breakglass/assertion.py:61-62
32. GRANTED→REVOKED is signed with the patient's own key inside the custodian (`actor_id = patient_id`). The facility verifies it against the patient's certificate through `revocation_machine.apply_transition`. — src/custodian/__init__.py:129-151; src/api/hospital.py:1100-1104, 1143-1156
33. EMERGENCY_OPEN→EXPIRED and EXPIRED→{GRANTED|REVOKED} are signed by the timer-service key. Its `actor_id` defaults to `"system:hsm-timer"`. It is never the clinician's or the audit service's key. — src/lifecycle/expiry.py:24-30, 238, 646-684 (corrected by X3, round 1: EXPIRED→REVOKED can also be patient-signed, see fact 73)
34. In deployment the timer key is a fresh ECDSA key pair per facility process, with `actor_id = "system:hsm-timer:<facility_id>"`. — deploy/asgi/facility.py:143-150; docs/adr/0081-restart-and-crash-recovery.md (Status: Proposed)
35. No code in src/ or deploy/ creates a REVOKED→GRANTED event. The pair is legal, but nothing emits it. Consent grants do not move lifecycle state. The consent module "does *not* wrap or re-wrap records". — src/lifecycle/state_machine.py:56; src/consent/service.py:1-8 (grep of src/, deploy/ for `to_state=LifecycleState.GRANTED` / `REVOKED, LifecycleState.GRANTED` outside src/lifecycle finds none)

## Crypto performed per transition

36. Break-glass open (→EMERGENCY_OPEN) performs no rotation. The gate reconstructs the emergency key from 3 of 4 shares, unwraps the DEK from the emergency wrapping and re-wraps it to the clinician's key with the PRE KEM. Nothing is re-keyed in the store. — src/api/hospital.py:1663-1674; src/breakglass/gate.py:253; src/breakglass/emergency_key.py:29-37, 71
37. Revocation (GRANTED→REVOKED) runs a full rotation through `plan_rotation_via_policy` with `new_tree` = the revoked access tree. It produces a new DEK and re-encrypted record, a new policy root under the new tree, and a new emergency key, shares and search index. — src/api/hospital.py:1061-1063, 1111-1116, 1158-1161; src/api/rotation.py:150-190; src/lifecycle/rotation.py:163-217
38. Revocation fails with 503 if the facility has no rotation ports configured. — src/api/hospital.py:1084-1091
39. Expiry runs a full rotation between the two signed timer transitions: EMERGENCY_OPEN→EXPIRED, then rotator, then EXPIRED→return_state. — src/lifecycle/expiry.py:645-686; docs/adr/0069-full-rotation-at-expiry.md (Status: Proposed)
40. A full rotation (`_plan_from_dek`) does the following: decrypts with the old DEK; re-encrypts under a fresh DEK with a new `policy_id = "pol-<uuid4>"`; recompiles the tree under a fresh 32-byte root secret and wraps the new DEK under it at baseline generation+1; generates a fresh emergency key, splits it, and wraps the new DEK under it (`wrapped_for="emergency"`) at emergency generation+1; re-derives search tokens under the new emergency key; and reseals the term list under the new DEK. — src/lifecycle/rotation.py:59-60, 220-291
41. The emergency key is split as weighted Shamir 3-of-4: x=1 to the clinician custodian, x=2 to the home authority, x=3 and x=4 to the audit service. — src/breakglass/emergency_key.py:29-37, 71; src/lifecycle/rotation.py:15-17
42. After a rotation the facility deposits the new shares as follows: share 1 to the custodian, share 2 to the patient's home (owner) authority, shares 3 and 4 to the audit service, each tagged with the new generation. — src/api/rotation.py:192-212, 380-406
43. At expiry, rotation order is store first (`apply_rotation`), then share deposit. Each step is recorded on the session, so a retry does not repeat it. — src/api/rotation.py:133-138
44. If the expiry manager has no rotator, `RotationNotConfiguredError` is raised and the record never returns to baseline (fail closed). — src/lifecycle/expiry.py:664-669; src/lifecycle/exceptions.py:89-94
45. The rotation plan is computed once and kept on the session (`rotation_plan`), so a retry finishes the same rotation instead of minting a second emergency key. — src/lifecycle/expiry.py:145-150; src/api/rotation.py:110-131

## Transition table (derived from code)

46. Transition table:

| From → To | Trigger / event | Signed by | Crypto performed | Logged | Source |
|---|---|---|---|---|---|
| GRANTED → REVOKED | Patient revocation (`POST` revoke route) | Patient key, in custodian (`actor_id=patient_id`) | Full rotation under the revoked tree: new DEK, new policy root, new emergency key + 3-of-4 shares, new search index | Yes. Audit entry `EVENT_RECORD_REVOKED` (with event_id) before commit; event stored in transition_events | src/custodian/__init__.py:129-151; src/api/hospital.py:1143-1210 |
| GRANTED → EMERGENCY_OPEN | Break-glass unlock; needs `reason_code` | Clinician key, in custodian (`actor_id=clinician_id`) | No rotation. 3-of-4 reconstruct, unwrap DEK, PRE re-wrap to clinician | Yes. Re-wrap audit entry before session registration; event stored | src/custodian/__init__.py:100-126; src/api/hospital.py:1619-1718 |
| REVOKED → EMERGENCY_OPEN | Same as above, from REVOKED | Clinician key | Same as above (no rotation) | Same as above | src/lifecycle/state_machine.py:57; src/api/hospital.py:1589-1701 |
| REVOKED → GRANTED | Legal in the table, but **no emitter** in src/ or deploy/ | n/a | None implemented | n/a | src/lifecycle/state_machine.py:56 |
| EMERGENCY_OPEN → EXPIRED | Timer: `now >= expires_at` (sweep / monitor / `expire_session`) | Timer key (`system:hsm-timer[:<facility>]`) | None in the event itself; the rotation follows it | Yes, via `audit_logger` (`lifecycle_transition`) when configured (deploy configures it) | src/lifecycle/expiry.py:645-661; src/api/audit_client.py:236-245; deploy/asgi/facility.py:152 |
| EXPIRED → GRANTED | Timer, after the rotation is stored and shares are deposited; `return_state=GRANTED` | Timer key | Full rotation precedes it (new DEK, root, emergency key + shares, search index) | Yes (as above) | src/lifecycle/expiry.py:663-686 |
| EXPIRED → REVOKED | Timer, after the rotation; `return_state=REVOKED`. **Or** a patient revocation while the record is stored as EXPIRED (fact 73) (corrected by X3, round 1) | Timer key; or Patient key, in custodian (`actor_id=patient_id`) | Full rotation precedes it (timer); full rotation under the revoked tree (patient, as GRANTED → REVOKED) | Yes (as above / as GRANTED → REVOKED) | src/lifecycle/expiry.py:672-686; src/api/custodian_service.py:1324-1343; src/api/hospital.py:1126-1144; docs/adr/0058-expiry-restores-pre-emergency-state.md (Status: Proposed) |

47. Not every transition rotates keys. Rotation happens on revocation and at expiry only. Break-glass open does not rotate, and no grant (REVOKED→GRANTED) path exists in code. — rows of fact 46

## Expiry

48. The time-box is set at `register_session`: `expires_at = now + duration`. `duration` defaults to the manager's `default_duration_seconds` (module default 60 s). — src/lifecycle/expiry.py:93, 403-413
49. The deployed facility sets the default from env `EMERGENCY_DURATION_SECONDS`, which defaults to 14400 s (4 h). — deploy/asgi/facility.py:59, 109-113, 151
50. A caller may shorten the configured time-box but not extend it: `duration = min(requested or configured, configured)`. — src/api/hospital.py:1339-1341
51. Only one emergency session per record may be active at a time. A second `register_session` raises `ValueError` (HTTP 409 at the API). — src/lifecycle/expiry.py:422-428; src/api/hospital.py:1704-1708
52. `register_session` accepts `return_state` only as GRANTED or REVOKED, and the facility passes the state the record was claimed from. — src/lifecycle/expiry.py:398-402; src/api/hospital.py:1701
53. Expiry is inclusive: `is_expired` is `now >= expires_at`. — src/lifecycle/expiry.py:155-157
54. Expiry is enforced by the server, not by cryptography. `get_active_emergency_key` / `join_window` raise `EmergencySessionExpiredError` once `now >= expires_at` or while the session is being expired, even before the sweep runs. — src/lifecycle/expiry.py:502-541; src/lifecycle/exceptions.py:58-66
55. No admin action is needed. A daemon monitor thread calls `check_and_expire_due` every 0.5 s (default), and the deployed facility starts it. — src/lifecycle/expiry.py:740-769; deploy/asgi/facility.py:157; tests/lifecycle/test_expiry.py::test_background_monitor_expires_without_admin_action
56. A manual `expire_session` before `expires_at` without `force=True` raises `SessionNotExpiredError`. The sweep passes `force=True` only for sessions already due. — src/lifecycle/expiry.py:597-602, 714-726
57. A session is claimed (`expiring = True`) before work starts, so concurrent expirers cannot double-rotate. — src/lifecycle/expiry.py:603-607
58. On failure the session is unclaimed, `attempts` is incremented, and a retry is scheduled with backoff 1 s × 2^(attempts-1), capped at 60 s. Access stays closed meanwhile. — src/lifecycle/expiry.py:96-97, 611-620; docs/adr/0050-lifecycle-state-compare-and-set.md (Status: Proposed)
59. A retry resumes without re-signing: each timer event is created and applied once (`expired_event`, `rebaselined_event`). An event already appended to audit is not appended again (`audited_event_ids`). — src/lifecycle/expiry.py:139-144, 646-686, 808-811
60. Each timer transition is written to audit first and then mirrored into the store by the `state_writer` compare-and-set. A `StateConflictError` there is logged and never overwritten. — src/lifecycle/expiry.py:800-825; src/api/hospital.py:603
61. The audit metadata per timer transition contains only event_id, record_id, from_state, to_state, actor_id, issued_at and correlation_id. It contains no key material. — src/lifecycle/expiry.py:781-798
62. After expiry the session's emergency-key reference is overwritten with 32 zero bytes. This is best effort, since Python cannot guarantee zeroization. — src/lifecycle/expiry.py:86-91, 622-625
63. The record returns to baseline (the second signed transition) only after the rotator returns, that is, after the rotation is stored and the new shares are deposited. — src/lifecycle/expiry.py:663-686; src/api/rotation.py:133-138
64. Expiry restores the pre-emergency state, so an emergency cannot undo a revocation. — src/lifecycle/expiry.py:128-130, 672-676; tests/security/test_phase3_expiry_security.py::TestEmergencyCannotUndoRevocation::test_revoked_record_returns_to_revoked_after_expiry; docs/adr/0058-expiry-restores-pre-emergency-state.md (Status: Proposed)
65. A test exists showing that after expiry the old shares do not restore search. — tests/security/test_p51_system_claims.py::test_c4_pre_expiry_shares_do_not_restore_search; docs/adr/0069-full-rotation-at-expiry.md (Status: Proposed)

## Crash / restart

66. When a session opens, a row of identifiers is saved: record_id, facility_id, return_state, actor_id, correlation_id, opener_facility_id, opened_at, expires_at. The row holds no key. If the save fails, the session is not registered. — src/lifecycle/expiry.py:178-187, 429-436; src/api/rotation.py:252-264; docs/adr/0081-restart-and-crash-recovery.md (Status: Proposed)
67. At startup a facility reads only its own rows. For each record still `emergency_open` or `expired`, it calls `recover_session`. Other rows are dropped. — src/api/rotation.py:270-315; src/api/hospital.py:606-611
68. A recovered session has no emergency key (zero bytes), `duration_seconds=0` and `expires_at=now`, so nobody can join it and the next sweep expires it. — src/lifecycle/expiry.py:439-500
69. For a recovered session the rotator recovers the DEK through the record's policy (`plan_rotation_via_policy`), which is the same path revocation uses. — src/api/rotation.py:110-115; src/lifecycle/rotation.py:163-217
70. If the store already shows `expired`, the EMERGENCY_OPEN→EXPIRED event is not emitted again (`expired_emitted=already_expired`). — src/lifecycle/expiry.py:466-468, 491, 659-661; src/api/rotation.py:307
71. A break-glass open that fails after claiming the state unregisters the session and compare-and-sets the state back to the source state. — src/api/hospital.py:1719-1730; src/lifecycle/expiry.py:333-346

## Contradictions found

Code wins in every case below.

- C1. **"Every transition is a rotation" claims.** ARCHITECTURE.md §2 C9 (ARCHITECTURE.md:75-77) says lifecycle holds "the rotation logic each transition triggers". The explainer (docs/explainers/02-key-lifecycle-state-machine.md:5-6) says every move "also changes the real encryption keys". Code: break-glass open performs no rotation (fact 36), and only revocation and expiry rotate (fact 47).
- C2. **The ieee-paper skill says "Grant adds a key wrapping".** Code has no grant transition emitter: REVOKED→GRANTED is legal but never created (fact 35). Consent "does *not* wrap or re-wrap records" (src/consent/service.py:7). The only paths into GRANTED are ingest (initial state) and EXPIRED→GRANTED after a rotation. The paper should not describe a grant operation that adds a wrapping unless another sheet finds one.
- C3. **ADR-0030 (Accepted)** says the set is "six pairs, not more" and lists EXPIRED→REVOKED as rejected (docs/adr/0030-lifecycle-state-machine.md:28-39, 119-124). Code has seven pairs including EXPIRED→REVOKED, added by ADR-0058, which is still **Proposed** (src/lifecycle/state_machine.py:52-62).
- C4. **ADR-0030's honesty caveat** says the consumed-id store is in-memory and does not survive a restart (docs/adr/0030-lifecycle-state-machine.md:107-109). The state_machine.py module docstring (lines 12-13) says the same. Code supports a durable backend, and deploy uses it (fact 24).
- C5. **ADR-0050 (Proposed)** says "Expiry still ends at `GRANTED`" (docs/adr/0050-lifecycle-state-compare-and-set.md:51-52). This is stale: code returns to GRANTED or REVOKED (fact 64).
- C6. **ADR-0069 (Proposed)** describes a "2-of-3" emergency split, share 1 to the custodian, share 3 to audit, share 2 "generated and discarded" (docs/adr/0069-full-rotation-at-expiry.md:27, 32, 71). Code uses weighted 3-of-4 and deposits share 2 to the home authority and shares 3 and 4 to audit (facts 41-42; ADR-0089).
- C7. **ARCHITECTURE.md §5 step 7** (ARCHITECTURE.md:323-324) says the new shares "go to the custodian and the audit service". Code also deposits share 2 to the home authority (fact 42). ARCHITECTURE.md:338 (trust boundaries) says the audit service is trusted "to hold one share". Code gives it two (x=3, 4).
- C8. **ARCHITECTURE.md §5 Revocation step 3** (ARCHITECTURE.md:251-252) describes only a new DEK, a re-encrypted record and rebuilt wrappings. Code's revocation also replaces the emergency key and shares and the search index (fact 37).
- C9. **The explainer** lists only five legal arrows (missing REVOKED→GRANTED and EXPIRED→REVOKED) and says expiry is "Emergency-open→Expired→Granted" (docs/explainers/02-key-lifecycle-state-machine.md:28-29, 63). Code has seven pairs and returns to the pre-emergency state. The explainer also names `src/records/revocation.py` as the place where revocation rotates. In fact the API revoke route rotates via `FacilityRotator.plan_from_store` → `plan_rotation_via_policy` and imports only `check_revocation_authorization` and `revoked_policy_tree` from records.revocation (src/api/hospital.py:149-152, 1158-1161).
- C10. **Stale docstrings in code** (code behaviour wins over the comments): the expiry.py module and class docstrings say audit wiring is a "Phase 4 seam" with `audit_logger=None` (src/lifecycle/expiry.py:32-36, 227-230). Deploy wires `make_lifecycle_audit_logger` (deploy/asgi/facility.py:152). The contracts/lifecycle.py docstring says time-boxing is carried by "the emergency key lifetime and EmergencyAssertion.expires_at" (src/contracts/lifecycle.py:29-30). Enforcement is actually `EmergencySession.expires_at` in the expiry manager (fact 54).
- C11. **ADR numbering:** docs/adr/0081-restart-and-crash-recovery.md is headed "ADR-0074" (line 1).

## Added by writers

72. The transition-event signature uses its own domain tag (`ehr/transition-event/v1`) so that a clinician's transition signature never verifies as their emergency assertion. — src/lifecycle/state_machine.py:36-38 (added by W3)
73. A patient revocation is signed from whatever state the facility reports: the custodian reads the record's stored state and signs `state → REVOKED` (`sign_revocation_transition` takes any `from_state`; only the legal set limits it), and the facility revoke route accepts the event if `from_state` equals the stored state and `to_state = REVOKED`, then rotates. So a record stored as EXPIRED (mid-expiry, or while a failed expiry waits on backoff) can be revoked by the patient, signed with the patient's key. — src/api/custodian_service.py:1324-1343; src/custodian/__init__.py:129-149; src/api/hospital.py:1126-1144, 1158-1210 (added by X3, round 1)
74. The facility checks the break-glass event's `issued_at` against its own clock (`exp_manager.now()`), not against the assertion: it must be no older than `MAX_ASSERTION_TTL` (15 min) and no more than `ASSERTION_CLOCK_SKEW` (30 s) in the future. Record, `to_state`, `actor_id = clinician_id` and `reason_code` = the assertion's reason code are compared as equalities. — src/api/hospital.py:1600-1607; src/breakglass/assertion.py:61-62 (added by X3, round 1)
75. A failed claim is undone without a signed event: if storing a revocation fails after the state was claimed, or a break-glass open fails after its claim, the facility compare-and-sets the stored state back to the source state; no transition event is created for the undo. — src/api/hospital.py:1207-1215, 1719-1730 (added by X3, round 1)
76. After a restart, a recovered session has no stored EMERGENCY_OPEN→EXPIRED event, so the sweep signs a new one with a new event id; if the store already shows `expired` it is not emitted (logged) again. Within one process a retry reuses the already-signed event. — src/lifecycle/expiry.py:478-492, 645-662 (added by X3, round 1)
77. Consent is a signed read-time predicate (ADR-0031): the consent module signs and verifies `ConsentRequest` / `ConsentGrant` objects and provides one `authorize_read` predicate that a caller runs before the crypto path over records already policy-wrapped at ingest; it does not wrap or re-wrap records and emits no lifecycle transition. Revocation, break-glass and expiry are the signed transitions over the per-record DEK. — src/consent/service.py:1-8; fact 35 (added by X1)
78. The read-time consent check is against the grant itself, not the record's lifecycle state: `authorize_read` verifies the patient's signature on the `ConsentGrant`, requires `grant.status` to be `ConsentStatus.GRANTED` (DENIED/REVOKED/other refused) and the read time to lie in `[decided_at, expires_at]`, and checks grantee and scope; the grant signature is also verified when the grant is submitted. The facility read route (`hospital.py:728-990`) does no lifecycle-state lookup. The consent gate runs only when the caller presents a grant (`if payload.grant is not None`); otherwise the facility reads through the policy keys alone (`decrypt_record_via_policy`). — src/consent/service.py:270, 307, 413-440; src/api/hospital.py:812, 911-916, 1004 (added by Y1)
