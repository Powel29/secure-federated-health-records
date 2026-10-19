# Security claims: what is proven today

5 of 11 claims hold at system level. 6 are known gaps, each kept at full strength as a strict expected-fail until its fix lands.

| Claim | What it proves | Evidence | Result | Open finding |
|---|---|---|---|---|
| C1 | A revoked user cannot decrypt after the key is rotated | revoked clinician cannot read after the revoke endpoint | Holds | - |
| C2 | No committed log entry, no key (fails closed) | share 3 not released when the log commit fails | Holds | - |
| C3 | One share alone, even the audit service's, opens nothing | single-share tests hold; system test is expected-fail | Known gap | Audit service releases share 3 without checking the assertion |
| C4 | Search capability does not survive the emergency | module test holds; system test is expected-fail | Known gap | Expiry does not replace the emergency shares, so old ones still work |
| C5 | A tampered audit entry is detected | edited row fails chain verification endpoint | Holds | - |
| C6 | An illegal state change is rejected | module test holds; system test is expected-fail | Known gap | Revoke handler can overwrite an emergency-open record |
| C7 | An event with an invalid signature is rejected | module test holds; system test is expected-fail | Known gap | Break-glass event is signed with a throwaway key |
| C8 | A replayed emergency assertion is refused | replay rejected, also after a facility restart | Holds | - |
| C9 | Unauthorised caller denied before any crypto or database work | system test is expected-fail | Known gap | Record is loaded before the caller is checked |
| C10 | Expired or revoked credential releases no key | module tests hold; system test is expected-fail | Known gap | Attribute-key endpoint checks no credential |
| C11 | A patient login alone never releases a key | patient without owner attribute is refused | Holds | - |

Full suite on 2026-10-09 against Postgres: 643 passed, 1 skipped, 6 expected-fail (650 collected).

## Test pyramid (pytest counts)

| Layer | Tests |
|---|---|
| Module tests | 314 |
| Security (attack fails) | 153 |
| API and storage integration | 92 |
| Wire (traffic analysis) | 71 |
| Deploy and demo smoke | 20 |
| Live end to end | 77 + 9 |

Also outside pytest: 38 Django portal tests.
