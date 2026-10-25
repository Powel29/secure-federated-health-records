# 3. Break-glass and the weighted 3-of-4 gate (the headline)

*Paper: Section VI (Break-Glass Protocol) and its sequence, gate and hash-chain figures. Decision: ADR-0089
(supersedes the older 2-of-3 design in ADR-0074).*

**One-paragraph version.** To open an emergency, a gate at the record's facility
rebuilds the record's 256-bit **emergency key `K_E`** from **three of four**
Shamir shares. The custodian holds one, the patient's home authority holds one,
and the **audit service holds two**, so **every set of three shares includes an
audit share**. The audit service releases its two shares **only after** it has
validated a signed, one-time **Emergency Assertion** and **committed a
hash-chained log entry**. The gate then unwraps the DEK and delivers it to the
clinician. Opening rotates **no key**. When the window ends, the record is fully
re-keyed.

## Shamir secret sharing in one minute

Pick a secret. Draw a random polynomial through it and mark points on it. With a
threshold of 3, a degree-2 polynomial (a parabola) is fixed by **any three
points**, which reveal the secret; **two points reveal nothing at all**. Our field
is GF(p) with **p = 2^256 + 297** (a 257-bit prime). The secret is length-prefixed
(4 bytes), zero-padded and cut into 32-byte blocks, each with its own random
polynomial and a 33-byte share element (`src/shamir`, hand-rolled).

**Weighting** is Shamir's own device: giving one holder two of the four points.
No new construction.

## The four shares

| Share x | Holder | Notes |
|---|---|---|
| **1** | Key Custodian (the clinician's key agent) | Kept in process memory |
| **2** | The patient's **home authority** (issued the `owner` credential; `authority-net` here) | Used only if share 1 is missing. Validates the assertion itself before releasing |
| **3 and 4** | **Audit service** | Released **together**, in one response, only after the log entry is committed |

Why this shape (the arithmetic is the whole argument):

| Who | Points | Result |
|---|---|---|
| Any single holder | at most 2 | nothing, **including the audit service** (claim C3) |
| Custodian + home authority | 2 | nothing, **no audit entry, no key** |
| Audit + custodian | 3 | opens |
| Audit + home authority | 3 | opens |

So **every qualifying set contains an audit share.** Important honesty point: the
**gate checks no share holder**, only that three shares with *distinct x* are
present. That every qualifying set contains an audit share *follows from share
placement*, not from a gate check. (The text of claim C3 was written before the
3-of-4 split.) Also, a holder accepts only its own x-set ({1}, {2}, {3,4}), so a
misrouted share cannot give a custodian-plus-home-authority pair three points.

**Shares are not authenticated:** a well-formed wrong share yields a wrong key,
which the AES-GCM unwrap downstream detects. Fail closed.

## The Emergency Assertion (ADR-0032, ARCHITECTURE §8)

A signed structure, not a button press. Fields: a one-time `assertion_id`;
`patient_id`, `clinician_id`, `facility_id`; a `reason_code` from a closed
enumeration; `issued_at`, `expires_at`; a **nonce of at least 128 bits**; an
optional digest `clinical_context_digest = SHA-256(record id, justification,
sensitive-label)` binding the record and justification text (the **share holders
require it**); and an **ECDSA P-256 signature** over all other fields by the
clinician's key, **which never leaves the custodian**.

Validation fails closed at the **first failing check, in this order**:

1. signature
2. certificate chain via a facility CA to the trusted root
3. clinician identifier = certificate CN
4. certificate not revoked
5. facility identifier (at the share holders: only that it is a federation member)
6. not expired
7. lifetime ≤ **15 min** and `issued_at` at most **30 s** in the future
8. **then** consumption of `assertion_id`

**Consumption runs last**, so an invalid assertion cannot burn a legitimate id,
and the consumed store is a required argument that cannot be omitted.

**Three parties validate it independently**: the facility, the audit service and
the home authority each check against **their own trust anchors** and keep **their
own consumed-id store** (durable at the facility and the audit service, in memory
at the authority). So a reused assertion gets no shares 3 and 4, even after an
authority restart (claim C8).

Who checks the patient? **No share holder checks that the record belongs to the
assertion's patient; the facility does**, as does the custodian when it can load
the record (ADR-0044, the stress-test fix). The custodian requests a 120 s
assertion by default and refuses more than 15 min.

## The flow, step by step

```
Clinician/Portal   Custodian           Home authority   Audit service      Facility (gate)
      | 1. declare: patient, record,      |                  |                 |
      |    reason, justification          |                  |                 |
      |------------>| 2. sign assertion   |                  |                 |
      |             |    + transition event (clinician key)  |                 |
      |             | 3. share 1 in memory?                  |                 |
      |             |    else ask home authority for share 2 (it validates A)  |
      |             |--------------------->|                 |                 |
      |             | 4. "release shares 3 and 4" + A  ----->|                 |
      |             |                      |  5. validate A (chain, replay,    |
      |             |                      |     facility member, digest)      |
      |             |                      |  6. COMMIT hash-chained entry     |
      |             |                      |  7. ONLY NOW seal shares 3,4 to   |
      |             |<-------------------- |     the gate; return with entry   |
      |             | 8. check entry signature, correlation id, rising seq     |
      |             | 9. A + event + sealed shares ---------------------------->|
      |             |                                  10. validate A, patient binding,
      |             |                                      check/verify event, CAS state,
      |             |                                      combine 3 shares -> K_E,
      |             |                                      unwrap DEK, log re-wrap,
      |<------------------ DEK delivered by KEM to the clinician's key ---------|
```

**Step 6 before step 7 is the whole point.** The audit service validates `A`,
builds the log event from it, appends the entry **inside one transaction**, and
only then seals shares 3 and 4 and returns them with the signed entry. A failed
commit raises before the return and yields **HTTP 503 with no share**: *no log
entry, no key* (claim C2). On the wire, the **COMMIT reaches the network 1.35 ms
before the response** (file 6).

Then: the custodian checks the entry's signature, correlation id and rising
sequence number; the facility **logs the re-wrap before delivering the DEK**.

If share 1 is missing, the custodian asks the home authority for share 2
**before** asking the audit service, so a refusal there costs no audit release.
The audit entry records the `unlock_path` (`custodian` or `home_authority`).

**Shares travel sealed** (ADR-0079): a KEM to the gate's ElGamal key, whose signed
statement the holders verify, with record, x and recipient as associated data. The
ElGamal group is a **256-bit demonstration parameter**.

**Delivery:** the gate unwraps the DEK and delivers it by a KEM to the clinician's
ElGamal key. **The facility sees the plaintext DEK meanwhile.** The PRE
re-encryption key is bidirectional and **unused** in break-glass (file 5).

**Joining an open case (ADR-0057/0063):** another clinician from the *opening*
facility may join a live session. It runs the same validation and the same 3-share
gate, signs no transition and does **not** extend the window. Every join needs a
fresh audit release, so **the audit service commits an entry for every viewer**.

## Auto-expiry

At the deployed window (4 h, shorten-only) a monitor signs
Emergency_Open→Expired, runs a **full rotation** (new DEK, policy root and `K_E`,
with a fresh 3-of-4 split to the same holders), and signs the return to the prior
state. **Old shares open nothing** (claim C4). Details in file 2.

## Honest limits for this topic (say them first)

- **The audit service is trusted.** Tampering with stored entries is detected
  (C5), but a compromised audit service could release shares 3 and 4 without a
  durable entry, or show different chains to different parties. So *no log entry,
  no key* holds **against everyone except the audit service** (limit 13).
- **The audit service is a single point of availability** (limit 8). The home
  authority's share 2 covers **only a lost share 1**. It does **not** cover a
  custodian outage (the custodian is also the clinician's key agent), nor an
  audit outage, nor an **audit restart**, which loses shares 3 and 4 for every
  record until re-keyed. *By code reading, not observed:* a restarted audit
  service also gets a new signing key and would refuse a non-empty chain.
- **The custodian is one shared process** (limit 5). The threshold is not
  weakened (it holds share 1 only; the audit service still commits first).
- **The facility sees the plaintext DEK** during delivery.
- A signed assertion proves the clinician *claimed* an emergency, not that one
  existed. The control is that it is signed, logged, time-boxed and reviewable.

## Where to point in the code

`src/breakglass/` (`gate.py`, `assertion.py`, `emergency_key.py` for the holder
map and THRESHOLD=3/TOTAL_SHARES=4, `share_sealing.py`, `replay.py`);
`src/audit/share_custody.py` (commit-then-release);
`src/api/share_release.py` (the validation both holders run);
`src/api/audit_service.py` (`POST /breakglass/release`);
`src/api/authority_service.py` (share 2); `src/api/hospital.py` (unlock).
Negative tests: `tests/security/` for C2, C3, C7, C8.

## Questions you will likely get

- *"What if the audit service is down?"* Break-glass fails closed: every
  qualifying set needs an audit share. That is the intended trade, and also
  limit 8.
- *"Can the audit service alone open a record?"* No: two points, one short of
  three (C3, tested).
- *"Can the custodian and home authority open it without the audit service?"* No:
  two points between them (tested).
- *"Why 3-of-4 and not 2-of-3?"* The older 2-of-3 never deposited share 2; a home
  authority holding it would have let shares 1+2 open a record with no audit
  entry. Weighting the audit service (two points) makes the audit commit
  unconditional while giving a fallback for a lost share 1 (ADR-0089).
- *"Can a doctor reuse an assertion?"* No: single-use id, ≤ 15 min, consumed at
  three parties (C8).
- *"What stops a doctor naming the wrong patient?"* The facility checks the record
  against the assertion's patient (ADR-0044).
- *"Is this really novel?"* Log-gated release is prior art; the combination with
  the lifecycle and emergency search is ours (file 1).
