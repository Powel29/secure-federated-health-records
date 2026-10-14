# ADR-0063: Only the opener's facility may join an open emergency session

- **Status:** Proposed
- **Date:** 2026-10-14
- **Deciders:** Avaneeth → Powel (`breakglass`, `lifecycle`) → all four
- **Task / source:** Follow-up to ADR-0057 and ADR-0061
- **Affects:** `api/hospital.py` (`FacilityTrust.issuing_ca`, break-glass join path), `lifecycle/expiry.py` (`EmergencySession.opener_facility_id`, `join_window` replaces `active_session_expires_at`), `tests/api/test_breakglass.py`, `tests/security/test_clinical_workflow.py`; amends ADR-0057 and ADR-0061 §1 ("a viewer anywhere joins")

## Context

ADR-0057 lets a second break-glass on an `EMERGENCY_OPEN` record join the live
session. Its motivation was the care team on scene, such as the anaesthetist or
ICU, but the join path checked nothing about who joins. ADR-0061 routes every
break-glass to the record's own facility, and the custodian writes that facility
into the assertion. So `assertion.facility_id` now names the node that receives
the request, not the clinician's facility, and the facility binding no longer
ties a clinician to a hospital. As a result, any clinician with a certificate from
any facility CA in the federation could join any open session while it lasted.

## Decision

The facility takes the clinician's home facility from the configured facility
CA that issued their certificate (`issuing_ca` now returns the facility id with
the CA). The chain is verified, so the caller cannot choose this value.
When a session opens, the opener's facility is stored on the
`EmergencySession`. A join from a clinician of any other facility is refused
with 403 and audited as `breakglass_join_facility`. The refusal comes before the
threshold gate, so no share is used, nothing is re-wrapped and no DEK is
released. A session registered without an opener facility cannot be joined.

## Consequences

- An open emergency is joinable only by its facility's own staff. A clinician
  elsewhere who needs the record must wait for the window to end and open their
  own break-glass, or use a consent grant.
- The opener's facility is kept in process memory with the session, like the
  rest of the session state. It is lost on restart along with the session.
- This does not prove the joiner is on the same team, only at the same facility.
  Facility is the finest unit of membership the PKI encodes.
- Downside: a genuine cross-facility team, such as a transfer in progress or a
  retrieval team from another hospital, is refused while the session is open.
  This includes the record's own home facility: if a visiting ER at
  facility-b opens a facility-a record, facility-a's clinicians cannot join
  until the window ends.
- Not addressed here: the custodian still sets `assertion.facility_id` to the
  record's facility, so `validate_emergency_assertion`'s facility binding checks
  routing, not location. Its docstring still describes "the facility where the
  emergency is being declared".

## Alternatives considered

- **Restore `facility_id` as the clinician's facility and route separately
  (option A).** This fixes the meaning of the binding, but it changes the
  assertion contract and the ADR-0061 routing, and it still does not limit who
  can join.
- **Bind joins to the opening clinician only.** Too strict: it defeats
  ADR-0057's purpose of letting the second clinician on a resuscitation in.
- **Carry the facility in the assertion or the request.** Rejected because the
  caller controls it. The issuing CA is verified.
