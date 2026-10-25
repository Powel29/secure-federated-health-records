# 2. The key-lifecycle state machine (the spine)

*Paper: Section V (Key-Lifecycle State Machine), the transitions table and the state figure.*

**One-paragraph version.** Every record is always in exactly one of four states.
Moving between states is only possible along **seven legal arrows**, and every
move is a **signed, replay-protected event** checked by one state machine in
`src/lifecycle/`. Revocation and expiry also perform a **full key rotation**:
"Revoked" does not mean a database column says no, it means the old keys were
thrown away and replaced. Opening break-glass changes state but **rotates
nothing**.

## The four states

| State | Meaning |
|---|---|
| **Granted** | Baseline. A record enters it at ingest (which also creates its first emergency wrapping of the DEK at generation 0). *Not* the result of a grant operation. |
| **Revoked** | The patient revoked. The record was fully re-keyed. |
| **Emergency_Open** | A break-glass session is live, time-boxed. |
| **Expired** | The emergency window ended; the record is being (or has been) re-keyed. |

## The seven legal transitions (the paper's transitions table)

| From | To | Trigger | Signer | Key operation |
|---|---|---|---|---|
| Granted | Revoked | Patient revokes | Patient | **Full rotation** |
| Granted | Emergency_Open | Break-glass; reason code required | Clinician | **None** |
| Revoked | Emergency_Open | Same | Clinician | **None** |
| Revoked | Granted | Legal, but **no code emits it** | — | None implemented |
| Emergency_Open | Expired | Timer: `now >= expires_at` | Timer | None; rotation follows |
| Expired | Granted | Timer, once the rotation is stored and shares deposited | Timer | Full rotation before it |
| Expired | Revoked | Timer, if it was Revoked before; or the patient revokes | Timer or Patient | Full rotation |

```
   Granted --revoke (full rotation)--> Revoked
      |                                   |
      +--break-glass (no rotation)--+     |
                                    v     v
                              Emergency_Open
                                    |
                                    | timer, now >= expires_at
                                    v
                                 Expired
                                    |
                                    | timer: full rotation, then return to
                                    v the state it was claimed from
                            Granted  or  Revoked
```

Facts to know cold:

- **Self-transitions and Granted→Expired are illegal.** There is **no
  premature-termination edge** out of Emergency_Open (an administrator cannot cut
  a window short).
- **Six of the seven pairs come from the original design; Expired→Revoked is a
  later addition** and a design choice of this build (ADR-0058: an expired
  emergency returns to the state it was claimed from, so it can never undo a
  revocation).
- Emergency_Open can be entered **only from Granted or Revoked**, and the event
  must carry a **reason code from a closed enumeration** (13 clinical reasons,
  never free text).
- Anything outside the seven pairs raises `IllegalTransitionError` **before
  anything is signed**: no event id, nonce or signature is produced (claim C6).

## What "signed event" means

A transition is a frozen `TransitionEvent`: event id, record id, from-state,
to-state, actor id, optional reason code, issue time, nonce (>= 16 bytes) and
signature. Unknown fields are rejected.

- **Signed bytes:** a domain tag `ehr/transition-event/v1` followed by every field
  but the signature, in a fixed order, **each length-prefixed** (ADR-0077). The
  domain tag stops a clinician's transition signature from verifying as their
  emergency assertion.
- **Algorithm:** ECDSA on P-256 with SHA-256. Event id from `uuid4`, nonce from
  `secrets`.
- **Who signs:** revocation is signed with the **patient's** key, break-glass with
  the **clinician's** key, both *inside the custodian*. Expiry-side transitions are
  signed by a **timer-service key**, never the clinician's or the audit
  service's. Each facility process makes a fresh timer key.
- **Facility check on break-glass:** verify against the clinician's certificate;
  require record, actor and reason code to match the assertion; require an issue
  time under 15 min old (30 s skew) on its own clock (ADR-0068).

## Applying an event (the order is the security)

`apply_transition` does, in this order:

1. **Verify the signature** (so a tampered to-state shows up as an invalid
   signature, and a forged event cannot burn a legitimate id).
2. **Re-check legality.**
3. **Require the event's from-state to equal the current state** (a valid old
   event cannot be applied to a record that has moved on).
4. **Consume the event id**, raising `ReplayedEventError` on reuse.

The deployed facility backs the consumed-id store **durably**, so ids survive a
restart, and the record store adds its own **compare-and-set** on the stored
state (ADR-0050).

## Full rotation: what it actually does

Revocation and expiry both do this (one code path, ADR-0036/0069/0080):

1. Decrypt the record with the old DEK.
2. Re-encrypt under a **fresh DEK** and a new policy identifier.
3. Recompile the policy tree under a **fresh 32-byte root secret**.
4. Generate and Shamir-split a **fresh emergency key**.
5. Wrap the new DEK under both, at **generation + 1**.
6. **Re-derive the search tokens** under the new emergency key.

| | Database flag | Our way |
|---|---|---|
| What changes | `status = 'REVOKED'` | New keys; record re-encrypted; wrappings rebuilt |
| Old copy of a key | Opens every future version | Opens nothing new |
| Who must be trusted | Whoever runs the database | The math, plus the audit/timer limits below |

**Honest limit 1:** revocation is **forward-only**. It cannot retract plaintext
already decrypted and kept. Also, **only the patient can revoke** in this build
(ADR-0084): home-authority revocation is not wired, and a patient who cannot sign
has no revocation path.

**Honest limit 9:** revoking a *credential* does not revoke a *released key*.
Attribute keys are shared by all holders of an attribute and never rotated, so a
revoked holder who kept a key still satisfies its leaves (ADR-0075).

## Expiry (the timer)

- Opening break-glass registers a session with `expires_at = now + d`. The
  **deployed default is d = 4 h** (`EMERGENCY_DURATION_SECONDS=14400`); a caller
  **may shorten but not extend** it; **one session per record** at a time. (The
  library default is 60 s; that is what tests and short demos use.)
- **Expiry is enforced by the server, not by cryptography.** Once
  `now >= expires_at`, the expiry manager refuses to hand out the emergency key or
  admit a new join, **even before the sweep runs**.
- A background monitor checks for due sessions every **0.5 s**; no administrator
  acts.
- **The sweep:** (1) claim the session so concurrent expirers cannot rotate twice;
  (2) sign Emergency_Open→Expired with the timer key; (3) run the full rotation;
  (4) **only after the rotation is stored and the new shares are deposited**, sign
  the return to Granted or Revoked.
- Each timer transition is written to the **audit log first** (identifiers, no key
  material), then mirrored into the store by compare-and-set.
- **Failure:** a failed attempt retries with backoff **capped at 60 s** while
  access stays closed, reusing the already-signed events and the first rotation
  plan, so it neither re-signs nor mints a second emergency key.
- **Crash or restart (ADR-0081):** when a session opens, a row of identifiers
  (**no key**) is persisted; if that write fails the session is not registered. At
  startup a facility reloads its rows for records still Emergency_Open or Expired
  as sessions with no emergency key and `expires_at = now`, so nobody can join them
  and the next sweep expires them with a fresh full rotation. Until then the record
  stays closed.

**Honest limit 2:** expiry is **server-enforced, not cryptographic**. A trusted
timer process (a simulated HSM) could decline to expire a key. Because expiry is a
forced rotation between two timer-signed, audited transitions, that is
**tamper-evident, not prevented**.

## Where to point in the code

`src/lifecycle/state_machine.py` (legal set, signed events, apply order),
`src/lifecycle/expiry.py` (the manager, monitor, retry, recovery),
`src/records/revocation.py` and `src/lifecycle/rotation.py` (rotation). Tests:
`tests/security/` (claims C1, C4, C6, C7).

## If asked

*"Why a state machine and not three features?"* Because the hard bugs live at the
seams: a revoke that does not apply during an emergency, an emergency that never
closes. One machine with one transition table has no seams to forget.

*"Is consent part of the machine?"* No. A grant is a patient-signed artifact
checked at read time. It does not move lifecycle state and the consent module
never wraps or re-wraps records.

*"Why can Revoked go to Granted if nothing emits it?"* It is legal in the table
(kept for a future re-grant), but no code in the repository produces it; say so.
