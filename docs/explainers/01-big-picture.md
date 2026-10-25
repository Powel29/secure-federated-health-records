# 1. The big picture

> **Source of truth:** the IEEE paper in `paper/` (built PDF: `paper/build/main.pdf`),
> evaluated commit `57a1a8c`, live run of 2026-10-21. If this file and the paper
> ever disagree, the paper wins; fix this file.

**One-paragraph version.** Health records are stored encrypted in one shared
store that cannot read them. Each record has its own data-encryption key (DEK).
A hospital that has never met the patient can still open an emergency record,
but only by rebuilding a per-record *emergency key* from **three of four Shamir
shares**. Two of the four belong to the audit service, so **every unlock needs
the audit service**, and the audit service releases its two shares only after it
has validated a signed, one-time Emergency Assertion and **committed a
hash-chained log entry**. Revocation and expiry then change the record's keys
(a full rotation), so access really ends.

## The problem, as a story

Alice is brought unconscious to Eastbrook Hospital. Her records are at
Northvale. Dr. Rao at Eastbrook has never treated her and nobody can ask her for
consent. The ID card in her wallet gives her name and date of birth; that is how
he finds out who she is. (A patient with no ID cannot be looked up: limitation 7
in the paper, ADR-0059.)

Three things go wrong in a normal system:

1. **Trust.** Eastbrook and Northvale are different organisations. How does one
   know Rao is really a doctor?
2. **The emergency override.** The usual answer is a break-glass button plus a
   log written afterwards. "We log it afterwards" is only a policy. Someone with
   admin rights can open records and delete the log line.
3. **It never closes.** Once opened, who guarantees access ends, and that a
   copied key stops working?

## Our idea in one picture

```
            Patient's record (encrypted, in the shared store)
                        |
          needs a key to open  <---- who may build that key?
                        |
   +--------------------+----------------------+
   |                                           |
 normal read                              EMERGENCY
 (right attributes; a patient-signed      (3 of 4 shares, two of them
  consent grant is checked if presented)   held by the audit service)
   |                                           |
   +---- revoke / break-glass / expiry are SIGNED, LOGGED transitions ----+
        of ONE key-lifecycle state machine over per-record keys

   Granted -> Revoked        Granted / Revoked -> Emergency_Open -> Expired
        ^                                                              |
        +---------------- back to the state it was claimed from -------+
```

Careful wording (the paper is strict about this): **consent is *not* a state.**
It is a patient-signed grant checked at read time when one is presented (status,
time window, signature). It is separate from the lifecycle state and it does not
move it. What the state machine covers is **revocation, break-glass and expiry**.

## What is new, and what is not (say this before you are asked)

Log-gated decryption is **prior art**: accountable and transparent decryption
(Ryan 2017; Kroll et al.; Cheval, Moreira & Ryan 2023). Break-glass for health
records is also prior art, at the policy layer and with keys. In the works we
compare (the related-work table in the paper), the log-gated schemes have **no patient revocation
lifecycle**, and the health-record break-glass schemes are **not described as
gating key release on a committed log entry**.

**Our claim is the combination, implemented and tested, not any of its parts:**

1. **One signed, logged key lifecycle.** Revocation, break-glass and expiry are
   signed transitions over per-record DEKs. Revocation and expiry rotate the
   DEK, the policy root, the emergency key with its shares, and the search index.
   **Opening break-glass rotates nothing.**
2. **Transparent-decryption-style log gating for federated break-glass.** The
   audit service releases its two shares only after validating the assertion and
   committing the entry.
3. **Emergency-scoped search.** Search tokens derive from the emergency key, so
   search works only during a live emergency, and old tokens stop matching after
   the expiry rotation.
4. **Evidence.** Negative security tests back eleven claims C1 to C11, all of
   which hold in a live run; PyShark checks see the audit commit on the wire
   before the shares.

**We are weaker than the transparent-decryption literature in two ways:** our
log is a plain hash chain held by a trusted audit service (no proofs of presence
or extension), and we give no formal model.

## The parts, with everyday comparisons

The federation is **simulated on one machine** (local processes or Docker
Compose containers on one bridge) with **synthetic data**: two facilities, two
attribute authorities, an audit service, a key custodian, a PostgreSQL store, and
one Django process serving three portals, under one self-signed PKI root that
cross-certifies the facilities.

| Part | What it is | Comparison |
|---|---|---|
| Shared **store** (PostgreSQL) | Ciphertext, wrapped keys, coded search index, log | A warehouse of locked boxes. The keeper has no keys |
| **Facilities** (A and B) | Run the policy engine and the threshold gate. **Hold no records** (they read ciphertext from the store) | Hospital front desks |
| **Authorities** (`authority-med`, `authority-net`) | Issue attribute credentials and keys. A patient's *home authority* (always `authority-net` here) holds **share x=2** | Licensing bodies |
| **Audit service** | Hash chain; holds **shares x=3 and x=4** | A notary who stamps before handing over the paper |
| **Key Custodian** | One shared process acting as every persona's key agent; holds their signing keys, PRE keys, credentials and **share x=1** | A bank-vault concierge. Signs for you, decides nothing |
| **Three portals** (patient, clinician, admin) | Websites that show data and identify users; hold no subject keys | Windows, never doors |
| **PKI root** | One self-signed root, cross-certifies facilities; a single point of trust | The government that issues passports |

## The two rules that protect the idea

1. **Portals and Postgres store data and identify users; they never decide
   access.** Keys and the Shamir threshold do (ADR-0014). The portal's database
   roles cannot write store tables, and its mirrored consent state is display
   data that no read path consults.
2. **Fail closed.** A missing share, a bad signature, a wrong chain head: the
   system refuses. It never degrades to something weaker.

## What we deliberately did NOT build

No FHIR/HL7 or health-information exchange (ADR-0010). No ML anomaly detection.
No real HSM (a trusted timer process stands in, ADR-0003). No real CP-ABE (a
Shamir-over-policy-tree substitute, ADR-0001/0002). No scaling runs over numbers
of patients or facilities (cut). Rate limiting, MFA and session threats are out
of scope. Only synthetic data, ever.

## If asked "what is the contribution, honestly?"

"Log-gated key release is published. Rotating keys on revoke is not new. What we
built and tested is the *combination*: revocation, break-glass and expiry as
signed transitions of one lifecycle over per-record keys, with the emergency key
released only through a committed audit entry, and emergency search that dies
with the window. We are weaker than the literature on log strength and we have
no formal model; the paper says so in its abstract."

See file 16 for the paper section by section and file 17 for every number.
