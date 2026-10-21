# 3. Break-glass and the threshold gate (the headline)

**One-paragraph version.** To open an emergency, the system must rebuild an
emergency key from **3 of 4** pieces (ADR-0089). The audit service holds two of
them, the clinician's custodian one, and the patient's home authority one, so
every opening needs the audit service. The audit service's pieces are released
**only after** it has committed a log entry and returned the new chain head. The doctor must also present a signed, short-lived,
single-use **Emergency Assertion**. When the time-box ends the access closes by
itself and the record is re-keyed.

## Shamir secret sharing in one minute

Pick a secret. Draw a random curve through it (a parabola) and mark four
points on it. Any **three** points pin the curve down and so reveal the secret;
**two** reveal nothing at all. That is 3-of-4 Shamir sharing, done with
arithmetic in a large prime field (`src/shamir`, about 80 lines, hand-rolled).
Giving one holder two of the points is how it is weighted.

## The three share holders

| Share | Holder | Notes |
|---|---|---|
| 1 | Attending clinician (held by the Key Custodian) | Used normally |
| 2 | Patient's home authority (issued the `owner` credential) | Backup: asked only if share 1 is lost, e.g. after a custodian restart. Checks the assertion itself before releasing |
| 3 and 4 | Audit service | Released together, only after it commits the log entry |

No single holder can open a record, **including the audit service** (its two
points are one short). The custodian and the home authority together cannot
either: two points. That is a claim we state and test, not an assumption.

## The flow, step by step

```
Clinician            Portal / Custodian         Audit service         Facility
   |  1. identify patient (name+DOB)                 |                   |
   |-------------------->|                           |                   |
   |  2. sign Emergency Assertion (bound to patient)  |                   |
   |                     |  3. "release shares 3+4"   |                   |
   |                     |-------------------------->|                   |
   |                     |        4. WRITE log entry, new chain head      |
   |                     |        5. only now: return shares 3 and 4      |
   |                     |<--------------------------|                   |
   |                     |  6. assertion + shares 1, 3, 4 --------------->|
   |                     |                           |  7. validate, rebuild key,
   |                     |                           |     state -> Emergency-open,
   |                     |                           |     re-wrap DEK to clinician (PRE)
   |<---- record + search + countdown ------------------------------------|
   ...                                                  8. timer ends: Expired,
                                                           re-key, back to Granted
```

Step 4 before step 5 is the whole point. If the log write fails, step 5 never
happens and the break-glass fails closed. If share 1 is missing, the custodian
asks the home authority for share 2 *before* step 3, so a refusal there costs
no audit release.

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

`src/breakglass/` (gate, assertions, `emergency_key.py` for the holder map),
`src/audit/share_registry.py` (shares 3 and 4 held back until commit),
`src/api/authority_service.py` (share 2), `src/api/hospital.py` (break-glass endpoint),
`src/lifecycle/expiry.py`. Negative tests: `tests/security/
test_phase3_breakglass_security.py`, `test_phase3_assertion_security.py`.

## Questions you will likely get

- *"What if the audit service is down?"* Break-glass fails closed. That is the
  intended trade: availability of emergency access depends on the log working.
- *"Can the audit service alone open a record?"* No, its two shares are one
  short of three.
- *"Can the custodian and home authority open it without the audit service?"*
  No, they hold two points between them.
- *"Can a doctor reuse an assertion?"* No, the id is single-use and short-lived.
- *"What stops a doctor naming the wrong patient?"* The patient is bound into the
  signed assertion, and the facility now checks it against the record.
