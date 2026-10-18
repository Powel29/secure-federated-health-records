# ADR-0067: The audit service validates the emergency assertion before releasing share 3

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (decision, review D1-a); Ojas (audit service, custodian) to review
- **Task / source:** review D1 / F2 (claim C3); supersedes ADR-0044's acceptance of the release ordering
- **Affects:** `api/audit_service.py`, `api/audit_schemas.py` (`ReleaseShareRequest`), `api/custodian_service.py`, `deploy/asgi/audit.py`, Compose (audit mounts the trust bundle), storage migration 0005 (`release_assertion` kind), demo/scenario/bench release calls; ARCHITECTURE.md §5 step 3

## Context

The audit service released share 3 to any caller that named the record id.
With share 1 in the custodian, one actor holding both could open any record:
"no single shareholder" (C3) held in the gate but not through the service.
ADR-0044 had accepted that the custodian asks for share 3 before the facility
checks anything.

## Decision

`POST /breakglass/release` now carries the clinician's `EmergencyAssertion`,
their certificate and the justification texts, and the audit service, before it
commits or releases anything:

1. validates the certificate chain against its own configured root and
   facility CAs (never a caller's), and the revoked serials;
2. requires the assertion's facility to be a federation facility;
3. requires a clinical context digest and checks it binds **this record**
   (`validate_clinical_context` against `share_key` and the texts);
4. runs the same five-point check facilities run
   (`validate_emergency_assertion`: signature, chain, clinician and facility
   binding, expiry, lifetime) and consumes the assertion id in its **own**
   replay set (`consumed_ids` kind `release_assertion`, so the facility's own
   consumption under `assertion` is unaffected);
5. writes the audit entry from the validated assertion (record, assertion,
   patient, clinician, facility, reason), overriding whatever the caller put in
   `event_data`. Justification texts are checked against the signed digest and
   never logged.

Each share holder now validates before release, as ARCHITECTURE.md §5 says.

## Consequences

- C3 holds through the service (`test_c3_audit_service_releases_no_share_...`),
  with mutation C3b (validation skipped) turning its tests red.
- The audit service needs the trust bundle (`FEDERATION_ROOT_CERT`,
  `FACILITY_CA_CERTS_DIR`); without it every release is a 503.
- **Residual:** the audit service cannot check that the assertion's patient
  owns the record (it holds no record metadata beyond the store row); the
  facility checks that before the gate. Share 2 is still generated and
  discarded (D2 open), so break-glass is 2-of-2 between the custodian and the
  audit service.

## Alternatives considered

- **D1-b: the facility checks first and the custodian calls audit after** --
  leaves a share holder that releases without checking anything, which is the
  hole itself.
- **The audit service asks the facility whether to release** -- couples the
  two separate trust domains the threshold exists to keep apart.
