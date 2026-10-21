# 2. The key-lifecycle state machine (the spine)

**One-paragraph version.** Every record is always in exactly one of four
states. Moving between states is only possible along a short list of legal
arrows, and every move is a **signed event** that also changes the real
encryption keys. "Revoked" does not mean a database column says no; it means
the old key was thrown away and replaced.

## The four states

| State | Meaning |
|---|---|
| **Granted** | Normal. Authorised parties can read through the policy tree. |
| **Revoked** | A party's access was removed. The record's key was replaced. |
| **Emergency-open** | A break-glass session is live, time-boxed. |
| **Expired** | The emergency window ended. The record is about to be re-keyed. |

```
              revoke                       break-glass
   Granted ------------> Revoked        Granted / Revoked
      ^                                      |
      |                                      v
      |   forced re-key               Emergency-open
      +------------------ Expired <----------+
         (Expired -> Granted)        (time-box ends)
```

Legal arrows (ADR-0030): Granted→Revoked, Granted→Emergency-open,
Revoked→Emergency-open, Emergency-open→Expired, Expired→Granted.
**Anything else is rejected**, for example Emergency-open→Emergency-open.
That last one matters: it is why a second break-glass on a record that is
already open is refused.

## What "signed event" means

Each arrow produces a `TransitionEvent`: record id, from-state, to-state, who,
when, and an ECDSA signature. The event id is single-use, so replaying a
captured event is rejected. The events enter the audit chain, so anyone can
check afterwards what happened and who authorised it.

## Why this is more than a status column

Compare two ways to "revoke Dr. Menon":

| | Database flag | Our way |
|---|---|---|
| What changes | `status = 'REVOKED'` | New random key; record re-encrypted; wrappings rebuilt without Menon |
| If Menon kept an old copy of the key | Still opens every future version | Opens nothing new |
| Who must be trusted | Whoever runs the database | Nobody; the math enforces it |

This is revocation-by-rotation (ADR-0036): decrypt with the old key, mint a
fresh key, re-encrypt, re-wrap, sign the transition, log it.

**Honest limit:** rotation stops *future* reads. It cannot take back text a
person already decrypted and saved. Say so before you are asked.

## How the other features hang off the states

- **Consent** (patient says yes) is a gate in front of the Granted read path.
- **Revocation** is Granted→Revoked plus a key rotation.
- **Break-glass** is →Emergency-open, which only happens through the 3-of-4
  threshold gate (file 3).
- **Expiry** is Emergency-open→Expired→Granted, executed by a timer that signs
  both moves and re-keys the record in between. No administrator action.
- **Search** is allowed only while the record is Emergency-open (file 5).

## Where to point in the code

`src/lifecycle/state_machine.py` (legal-transition table, signed events),
`src/lifecycle/expiry.py` (the timer), `src/records/revocation.py`
(rotation on revoke). Tests: `tests/security/test_phase2_lifecycle.py` and
`test_phase3_revocation_security.py` prove illegal moves and revoked reads fail.

## If asked

*"Why a state machine and not three features?"* Because the hard bugs live at
the seams: a revoke that does not apply during an emergency, an emergency that
never closes, a consent that outlives a revoke. One machine with one transition
table has no seams to forget.
