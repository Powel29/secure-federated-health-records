# ADR-0057: A second break-glass on an open record joins the session instead of 409

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** Avaneeth → Powel (`breakglass`, `lifecycle`), Nandini (clinician portal) → all four
- **Task / source:** Clinical review 2026-10-12 (issues 1 and 2)
- **Affects:** `breakglass/gate.py` (`join_emergency_access`), `lifecycle/expiry.py` (`active_session_expires_at`), `api/hospital.py` (break-glass endpoint), `api/schemas.py` and `api/custodian_schemas.py` (`transition_event` optional, `joined`), `api/custodian_service.py`, `portal/clinician/views.py` and `case.html` ("View record again", replaced by ADR-0062)

## Context

The facility refused any break-glass on a record already `EMERGENCY_OPEN`
until its window expired. Two clinical failures followed: the portal shows the
decrypted record on one response only, so a clinician who navigated away was
locked out of the record they had just opened; and a second clinician on the
same resuscitation (anaesthetist, ICU) could not open it at all.

## Decision

When the record is `EMERGENCY_OPEN` and this facility holds its live session,
a valid break-glass request **joins** it:

- the assertion is validated exactly as before (signature, chain, binding,
  lifetime, one-time id, patient binding);
- the same 2-of-3 threshold is required, so the audit service still commits
  its entry before releasing share 3, for every viewer;
- the facility logs the re-wrap before release and delivers the DEK by PRE;
- no transition is signed, no session is registered, and the window is not
  extended — the response carries the existing `expires_at` and
  `joined: true`.

The clinician portal adds "View record again" to an open case (since ADR-0062 the
record loads whenever the open case is viewed, through the same join); it reuses the
case's correlation id so each view lands in the case's chain segment. A second
clinician goes through identify → declare as usual and gets their own case.

## Consequences

- One lifecycle state per record is kept; extra viewers add audited accesses,
  not transitions.
- Since ADR-0063, only clinicians of the opener's facility may join.
- Sessions live at the record's own facility. The custodian routes every
  break-glass there, and the portal passes the discovered record's facility
  (ADR-0061), so a clinician at another facility joins too; 409 remains only
  for a request sent to a node that does not hold the session.
- Two simultaneous first opens can now both return 200 (one opens, one joins)
  as well as 200/409; the invariant tested is that exactly one transition and
  one session exist.

## Alternatives considered

- **One session per clinician** — each with its own expiry and rotation;
  several rotations of one record race each other.
- **Keep 409 and state it as a limitation** — leaves the lock-out in the demo.
