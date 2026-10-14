# 1. The big picture

**One-paragraph version.** Health records are stored encrypted in one shared
store that cannot read them. Who may decrypt is decided by keys, not by a
database flag or a login. A hospital that has never met a patient can still
open an emergency record, but only by assembling a key from three separate
parties, one of whom (the audit service) refuses to take part until the access
is already written in a tamper-evident log. The access then expires on its own.

## The problem, as a story

Alice is brought unconscious to Eastbrook Hospital. Her records are at Northvale.
Dr. Rao at Eastbrook has never treated her and nobody can ask her for consent.
The ID card in her wallet gives her name and date of birth; that is how he
finds out who she is. (A patient with no ID cannot be looked up: a stated
limitation, ADR-0059.)

Three things go wrong in a normal system:

1. **Trust.** Eastbrook and Northvale are different organisations. How does one know
   Rao is really a doctor?
2. **The emergency override.** The usual answer is a break-glass button.
   But then "we log it afterwards" is only a policy. Someone with admin rights
   can open records and delete the log line.
3. **It never closes.** Once opened, who guarantees access ends in 15 minutes?

## Our idea in one picture

```
            Patient's record (encrypted, in the shared store)
                        |
          needs a key to open  <---- who may build that key?
                        |
   +--------------------+----------------------+
   |                    |                      |
 normal read         consent              EMERGENCY
 (right attributes)  (patient said yes)   (2 of 3 shares)
   |                    |                      |
   +--------- all are states of ONE key-lifecycle state machine ---------+
        Granted  <->  Revoked        Emergency-open  ->  Expired  -> Granted
              every arrow = a signed, logged key change
```

The two claims that are new (`PROJECT.md` §4):

- **Logging is a cryptographic precondition of break-glass.** Not a promise.
- **Search exists only during an emergency.** The ability to search encrypted
  records is derived from the emergency key, so it dies when the key does.

## The parts, with everyday comparisons

| Part | What it is | Comparison |
|---|---|---|
| Shared **store** (PostgreSQL) | Holds ciphertext, wrapped keys, search index | A warehouse of locked boxes. The warehouse keeper has no keys |
| **Facilities** (A and B) | Hospital servers: validate doctors, serve reads, run the break-glass endpoint | Hospital front desks |
| **Authorities** (medical council, hospital network) | Issue attribute credentials ("role: physician", "specialty: cardiology") | Licensing bodies |
| **Audit service** | Writes the hash-chained log; holds share 3 | A notary who stamps before handing over the paper |
| **Identity / PKI** | Root anchor + facility CAs + cross-certification | A chain of ID cards that lets Eastbrook trust a Northvale badge |
| **Key Custodian** | One process that holds every demo persona's keys and signs for them after portal login | A bank-vault concierge. Signs for you, decides nothing |
| **Three portals** (patient, clinician, admin) | Websites that show data and identify users | Windows, never doors |

## The two rules that protect the idea

1. **Portals and the database never decide access.** Keys and the Shamir
   threshold do (ADR-0014). If a login ever released a key, the project would be
   an ordinary "database decides" system.
2. **Fail closed.** A missing share, a bad signature, a wrong chain head: the
   system refuses. It never falls back to something weaker.

## What we deliberately did NOT build

No real healthcare standards (FHIR/HL7) — faculty confirmed the crypto
federation model is what they want (`PROJECT.md` §3, ADR-0010). No machine
learning anomaly detection. No real hardware security module (a trusted timer
process stands in, ADR-0003). Only synthetic data, ever.

## If asked "what is the contribution, honestly?"

Rotating keys on revoke is not new (another paper already does it). The
contribution is **unifying consent, revocation and emergency access in one
state machine**, making the **audit log a precondition of emergency access**,
and **emergency-only searchable encryption**, all demonstrated across a
simulated multi-facility federation.
