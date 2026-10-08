# 3. Break-glass and the threshold gate (the headline)

**One-paragraph version.** To open an emergency, the system must rebuild an
emergency key from any **2 of 3** pieces held by different parties. The audit
service's piece is released **only after** it has committed a log entry and
returned the new chain head. The doctor must also present a signed, short-lived,
single-use **Emergency Assertion**. When the time-box ends the access closes by
itself and the record is re-keyed.

## Shamir secret sharing in one minute

Pick a secret. Draw a random line through it; give three people three points on
the line. Any **two** points define the line and so reveal the secret. **One**
point reveals nothing at all. That is 2-of-3 Shamir sharing, done with
arithmetic in a large prime field (`src/shamir`, about 80 lines, hand-rolled).

## The three share holders

| Share | Holder | Notes |
|---|---|---|
| 1 | Attending clinician (held by the Key Custodian) | Released only against a valid assertion and certificate |
| 2 | Patient's home authority, or a federated delegate | **Not requested in the demo**; the threshold is met by 1 + 3 |
| 3 | Audit service | Released only after it commits the log entry |

No single holder can open a record, **including the audit service**. That is a
claim we state and test, not an assumption.

## The flow, step by step

```
Clinician            Portal / Custodian         Audit service         Facility
   |  1. identify patient (name+DOB)                 |                   |
   |-------------------->|                           |                   |
   |  2. sign Emergency Assertion (bound to patient)  |                   |
   |                     |  3. "release share 3"      |                   |
   |                     |-------------------------->|                   |
   |                     |        4. WRITE log entry, new chain head      |
   |                     |        5. only now: return share 3             |
   |                     |<--------------------------|                   |
   |                     |  6. assertion + shares 1 and 3 ---------------->|
   |                     |                           |  7. validate, rebuild key,
   |                     |                           |     state -> Emergency-open,
   |                     |                           |     re-wrap DEK to clinician (PRE)
   |<---- record + search + countdown ------------------------------------|
   ...                                                  8. timer ends: Expired,
                                                           re-key, back to Granted
```

Step 4 before step 5 is the whole point. If the log write fails, step 5 never
happens and the break-glass fails closed.

## The Emergency Assertion

A signed structure, not a button press (`ARCHITECTURE.md` §8, ADR-0032):

- `assertion_id` (single use), `patient_id`, `clinician_id`, `facility_id`,
  `reason_code` (a fixed list, not free text), `issued_at`, `expires_at`
  (short, 120 s in the demo), `nonce`, and an ECDSA `signature`.

It is validated **before any share is requested**:

1. signature verifies against a currently valid clinician certificate,
2. the certificate chains to the federation root (cross-certification),
3. `clinician_id` matches the certificate subject,
4. `facility_id` matches the receiving node,
5. not expired,
6. not already used (replay protection),
7. **and the record belongs to the patient named in the assertion** (added
   after our stress test, see file 7 and ADR-0044).

## Auto-expiry (no admin needed)

A timer standing in for a hardware security module (ADR-0003, ADR-0035) signs
`Emergency-open → Expired`, mints a fresh key and re-encrypts the record, then
signs `Expired → Granted`. Emergency search tokens die with the old key.
**Honest limit:** a compromised timer could refuse to expire. We make that
tamper-evident because expiry is a signed, logged event, rather than claiming
it is impossible.

## Where to point in the code

`src/breakglass/` (gate, assertions), `src/audit/share_registry.py` (share 3
held back until commit), `src/api/hospital.py` (break-glass endpoint),
`src/lifecycle/expiry.py`. Negative tests: `tests/security/
test_phase3_breakglass_security.py`, `test_phase3_assertion_security.py`.

## Questions you will likely get

- *"What if the audit service is down?"* Break-glass fails closed. That is the
  intended trade: availability of emergency access depends on the log working.
- *"Can the audit service alone open a record?"* No, one share reveals nothing.
- *"Can a doctor reuse an assertion?"* No, the id is single-use and short-lived.
- *"What stops a doctor naming the wrong patient?"* The patient is bound into the
  signed assertion, and the facility now checks it against the record.
