# Security claims: what is proven today

**All 11 claims hold at system level.** No claim is an expected-fail. A claim
that fails is kept at full strength as a strict expected-fail until its fix
lands (ADR-0046); none do on this run.

Run: 2026-10-21 on branch `proposal/breakglass-3-of-4` (ADR-0089, the
weighted 3-of-4 split), Postgres 16, Python 3.11, with
`python -m tests.security.claims --table` (it runs every claim-tagged test;
a claim holds only if all its system tests *passed*).

| Claim | What it proves | System-level evidence | Result | Fixed by |
|---|---|---|---|---|
| C1 | A revoked user cannot decrypt after the key is rotated | revoked clinician cannot read after the revoke endpoint, in memory and on Postgres | Holds | - |
| C2 | No committed log entry, no key (fails closed) | share 3 not released when the log commit fails | Holds | - |
| C3 | One share alone, even the audit service's, opens nothing | a single share, the audit service's two shares, and custodian + home authority together all fail at the hospital gate; the audit service and the home authority each release nothing without a valid assertion (wrong record, bad signature, untrusted CA, replay) | Holds | ADR-0067, ADR-0089 |
| C4 | Search capability does not survive the emergency | search refused after expiry; pre-expiry shares restore nothing; restart and crash mid-window close the record with a rotation | Holds | ADR-0069, ADR-0081 |
| C5 | A tampered audit entry is detected | edited row fails the chain verification endpoint | Holds | - |
| C6 | An illegal state change is rejected | API refuses revoking an emergency-open record | Holds | ADR-0050 |
| C7 | An event with an invalid signature is rejected | break-glass event verifies against the clinician's certificate; an event not signed by the clinician opens nothing | Holds | ADR-0068 |
| C8 | A replayed emergency assertion is refused | replay rejected at the endpoint, after a facility restart, and across processes on Postgres | Holds | - |
| C9 | Unauthorised caller denied before any crypto or database work | BOLA caller denied before crypto or DB; a portal may not request share 3; unsigned requests refused | Holds | ADR-0066 |
| C10 | Expired or revoked credential releases no key | revoked, expired and copied (unsigned-subject) credentials get no attribute key | Holds | ADR-0052, ADR-0082 |
| C11 | A patient login alone never releases a key | patient without the owner credential is refused by the custodian | Holds | - |

The test node ids behind each row are printed by the command above. Each
claim's tests are shown to be real by `python -m tests.security.mutations`
(every one of the 50 claim-tagged tests goes red under at least one mutation of
its control, last run 2026-10-21, see `WORKFLOW.md` P5-1).

Full suite on 2026-10-21 against Postgres: **1006 passed, 2 skipped, 0 failed,
0 expected-fail** (1008 collected). The two skips are the missing-tool paths in
`tests/wire/test_capture.py`, which can't run while dumpcap is installed. The
live wire test (`tests/wire/test_live_capture.py`) ran against captures
re-recorded that day on the 3-of-4 code and passed.

## Test pyramid (pytest counts, collected 2026-10-21)

| Layer | Directories | Tests |
|---|---|---|
| Module tests | contracts, crypto_core, shamir, policy, lifecycle, records, pre, search, breakglass, identity, authority, audit, consent | 338 |
| Security (attack fails) | security | 278 |
| API and storage integration | api, storage | 233 |
| Wire (traffic analysis) | wire | 107 |
| Deploy and demo smoke | deploy, demo | 52 |
| **Total** | | **1008** |

Not in these counts: the 85 Django portal tests (all passed on 2026-10-21),
and the live end-to-end checks against the Docker stack (77 portal checks plus
the 9-step break-glass scenario, last recorded 2026-10-09, not re-run). The
9-step scenario itself did run twice on 2026-10-21 through the local
federation (plain and TLS captures).
