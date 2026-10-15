# ADR-0072: Revocation and consent send no private key or DEK; revocation re-keys with the expiry rotation

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (proposal; owns `lifecycle`, `consent`); Avaneeth (`api`, `records`, `identity`, `storage`), Ojas (custodian, audit share custody) to review
- **Task / source:** review F10, F13, D4 (decided by ADR-0064); handoff 2026-10-15 item 4; wire finding in `40b13e9` (`actor_signing_key_pem`, `old_dek_b64` on the wire)
- **Affects:** `api/hospital.py` (`/records/{id}/revoke`, `/consent/requests`, `/consent/grants`; `/consent/grants/revoke` removed); `api/schemas.py` (`RevokeRecordRequest`, `CreateConsentRequestPayload`, `RevokeConsentGrantPayload` removed); `api/custodian_service.py` (`POST /subjects/{id}/records/{record_id}/revoke`), `api/custodian_schemas.py`; `custodian.sign_revocation_transition`; `lifecycle/rotation.py` (`plan_rotation_via_policy`); `api/rotation.py` (`plan_from_store`, `deposit`); `records/revocation.py` (`revoked_policy_tree`); `identity/subjects.py` (`validate_clinician_certificate`, `validate_subject_certificate`); share holders in `api/audit_service.py`, `api/custodian_service.py`, `audit/share_registry.py`; `audit.events.EVENT_RECORD_REVOKED`; `deploy/run_scenario.py`; tests

## Context

Keys must stay in the custodian (ADR-0043), but three facility routes took a
private key in the request body: revoke (`actor_signing_key_pem`, plus the
old DEK as `old_dek_b64`), consent request (`requester_signing_key_pem`) and
consent revoke (`patient_signing_key_pem`). The P4-6 capture showed the
revoke key on the wire. Revocation also had the F10 defects: on Postgres it
answered 501 and stored nothing, `actor_id` and `owner_authority_id` came
from the caller, nothing was audited, and the emergency wrapping kept the old
DEK, so break-glass on a revoked record would open nothing.

ADR-0064 gave patients certificates (D4-a) and ADR-0068 showed the pattern:
the custodian signs the transition with the person's key and the facility
verifies it against their certificate.

## Decision

1. **Revocation is a patient-signed `GRANTED -> REVOKED`.** The custodian
   signs it with the patient's key (`custodian.sign_revocation_transition`)
   and sends the event, the patient's certificate and the clinical branch
   that stays. The facility checks the certificate (configured CA, role
   `patient`, CN = the record's patient), that the event is this record's,
   from its current state, recent (the assertion window), signed by that key
   and never seen before (the store-backed one-time ids of the state
   machine). Only the patient revokes here; a home-authority revocation
   would need an authority key in facility configuration and is not wired.
2. **The facility re-keys the record with the expiry rotation** (ADR-0069):
   it recovers the old DEK through the record's own policy with the
   authoring keys of its leaves (the keys it already fetches for every
   rotation, ADR-0026), compiles the revoked tree -- the owner leaf taken
   from the stored tree, never the caller -- under a fresh root, mints a new
   emergency key and shares, re-derives the search index, logs
   `record.revoked`, claims the state with a compare-and-set, stores the
   rotation atomically and hands the new shares to the custodian and the
   audit service. Revocation now works on Postgres, and break-glass on a
   revoked record opens it with the holders' new shares.
3. **Share holders accept a rotation while the record is `expired` or
   `revoked`**, and only for a later generation than the one they hold.
4. **Consent requests arrive signed.** The facility verifies a
   `ConsentRequest` against the requester's clinician certificate
   (`identity.validate_clinician_certificate`). A revocation is the
   patient's signed `REVOKED` grant, submitted to `/consent/grants` like any
   decision; `/consent/grants/revoke` is removed. Once a request is revoked,
   a `GRANTED` decision on it is refused (409), matching the read path.
5. All three request models forbid extra fields, so a caller still sending a
   key gets a 422 rather than having it silently ignored.

## Consequences

- No private key or DEK is sent by revocation or consent. The holder keyring
  on reads and the authoring keyring at ingest still carry attribute keys in
  bodies; that is D6.
- If a share holder is unreachable after the store commit, the revocation
  holds and the response says `breakglass_provisioned: false`; break-glass on
  that record fails closed until it is re-keyed.
- A facility can now replace shares of any revoked record, not only during
  an expiry. It gains no disclosure from that: it already fetches authoring
  keys and can open any record whose policy it re-authors.
- A failed revocation burns its event id; the custodian signs a fresh one on
  retry.
- `records.revocation.revoke_record_access` stays as the P3-7 library call
  its unit tests exercise; the facility no longer uses it.

## Alternatives considered

- **Keep `old_dek_b64`, drop only the private key.** Leaves a DEK on the wire
  and the caller choosing what it claims the DEK is.
- **Have the custodian compute the rotation and send the re-encrypted
  record.** Sends a DEK and plaintext-derived material to the facility anyway,
  and duplicates the facility's rotation.
- **Refuse revocation on Postgres until a dedicated `rotate_record` exists**
  (the F10 sketch). ADR-0069's atomic `apply_rotation` already is one.
