# ADR-0072: No private key or DEK in a facility request; the custodian signs revocations

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal; owns `api/` facility, `records/`) → Ojas (custodian) → all four
- **Task / source:** Review decision D6, first step (`docs/review/2026-10-07-fix-proposals.md`); rest of F10
- **Affects:** `src/api/hospital.py`, `src/api/schemas.py`, `src/api/custodian_service.py`, `src/api/custodian_schemas.py`, `src/custodian/__init__.py`, `src/records/revocation.py`, `deploy/run_scenario.py`, `bench/run_benchmarks.py`; extends ADR-0068 to revocation

## Context

The P5-5 analyser found nine secrets on the plain profile
(`bench/results/p55_wire_checks.json`). The worst were not data but keys:
`POST /records/{id}/revoke` took the actor's **private signing key**
(`actor_signing_key_pem`) and the caller's copy of the old DEK (`old_dek_b64`),
and two unused facility routes, `POST /consent/requests` and
`POST /consent/grants/revoke`, took the requester's or patient's private key.
The revoke route also trusted a caller-supplied `actor_id`. ADR-0068 already
fixed the same pattern for break-glass by signing in the custodian.

## Decision

1. **Revocation is signed where the key lives.** The custodian gets
   `POST /subjects/{subject_id}/revoke` (portal-callable). It signs the
   patient's `GRANTED -> REVOKED` `TransitionEvent` with the patient's key
   (`custodian.sign_revocation_transition`), fetches the authoring keys for the
   new policy and the owner leaf, and calls the facility.
2. **The facility verifies, it does not sign.** `RevokeRecordRequest` carries
   `transition_event` and `actor_certificate_pem` instead of `actor_id`,
   `actor_signing_key_pem`, `old_dek_b64` and `reason_code`. The facility
   validates the certificate as the record's patient's (ADR-0064), requires a
   recent event (the break-glass window: 15 minutes, 30 s skew), consumes its
   one-time id, then calls `records.revocation.revoke_record_access`, which
   checks the event is `GRANTED -> REVOKED` for this record, checks P3-12,
   verifies the signature, and only then rotates.
3. **No caller DEK.** `revoke_record_access` takes the record's current
   compiled policy and unwraps the old DEK itself with the supplied keyring
   (the owner leaf satisfies it). A caller can rotate a record only by proving
   it can open it now.
4. **The two key-taking consent routes are removed.** Consent requests and
   revocations are already signed by the custodian and submitted through
   `POST /consent/grants`.
5. A schema test (`test_no_facility_request_takes_a_private_key_or_dek`) fails
   if any facility request model gains a `private`, `signing_key` or
   `old_dek` field.

## Consequences

- No facility route accepts a private key or a DEK; the plain capture loses the
  `actor_signing_key_pem` and `old_dek_b64` hits. The authoring keyring still
  crosses the wire (ADR-0073 scopes that to TLS).
- **Home-authority revocation is refused over HTTP.** P3-12 still allows the
  home authority, and `records.revocation` still accepts its signature, but
  the authority has no certified signing identity a facility can verify, so
  the facility answers 403 rather than trust an unverifiable event. Adding one
  (an authority certificate under the root) is follow-up work.
- Revocation persistence on Postgres is still 501 (F10, unchanged).
- Bench `revocation_latency` now times event verification and the DEK unwrap
  instead of signing; the committed number is stale until re-run (N10).

## Alternatives considered

- **Keep the private key in the request, rely on TLS** — rejected: a facility
  that holds a patient's signing key can forge that patient's consent; TLS
  does not change who receives the key.
- **Send the DEK, signed by the patient** — rejected: the DEK would still
  cross the wire, and the facility can already unwrap it through the policy.
- **Accept the home authority's service certificate (ADR-0066)** — rejected
  for now: a service certificate names a service kind, not an authority id, so
  it cannot prove *which* authority signed.
