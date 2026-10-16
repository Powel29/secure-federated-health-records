# ADR-0079: Threshold shares travel sealed to their recipient's signed share key

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal; key binding and scope chosen by Avaneeth) → Powel (breakglass, wire), Ojas (audit, custodian) → all four
- **Task / source:** Review decision D6, step 2; left open by ADR-0073
- **Affects:** new `src/breakglass/share_sealing.py`, `src/api/share_transport.py`; `src/api/audit_service.py`, `audit_schemas.py`, `custodian_service.py`, `custodian_schemas.py`, `hospital.py`, `schemas.py`, `rotation.py`; `deploy/asgi/{audit,facility}.py`, `deploy/run_scenario.py`, `deploy/seed_portal.py`, `demo/driver.py`, `demo/seed_data.py`, `bench/run_benchmarks.py`; `wire/checks.py`; amends ADR-0073 and PROJECT §4A claim 1

## Context

Shares crossed the plain wire in five places: the ingest and seed deposits
(to the audit service and the custodian), the rotation re-deposits
(ADR-0069), the audit service's release response, and the unlock request to
the facility. The custodian also received share 3 in the clear while holding
share 1, so a compromised custodian held both shares of a 2-of-2 gate
(ADR-0074). No service had an encryption key; each had only the ECDSA
request-signing identity of ADR-0066. ADR-0073 left this open because no
document said how such a key is bound to a service.

## Decision

1. **Share-key statement.** The audit service, the custodian and every
   facility generate an ElGamal key pair at startup (the existing `pre`
   group) and serve `GET /share-key`: the public key, the service's
   certificate and an ECDSA signature by its service key over
   `encode_fields("ehr/share-sealing-key/v1", [service_id, kind, key])`
   (ADR-0077). A sender trusts the key only after checking the certificate
   against its own configured root, that it names that service id and the
   expected kind, and the signature. The route is public: it is a public key.
2. **Sealed share.** `pre.encapsulate_key` (the KEM the gate already uses for
   the DEK delivery) gives a fresh AES-256-GCM key; the share is encrypted
   with AAD `encode_fields("ehr/sealed-share/v1", [record_id, x, recipient_id])`.
   Only the index `x` is in the clear.
3. **All five flows.** Deposits are sealed to the holder (audit, custodian);
   rotation re-deposits likewise. The custodian fetches the record facility's
   statement and passes it in the release request; the audit service verifies
   it (kind `facility`, else 403 before anything is committed) and seals
   share 3 **to the facility's gate**, so the custodian forwards it without
   being able to read it. The custodian seals share 1 to the same gate. The
   facility opens both with its own key; a share sealed elsewhere is a 400 and
   an audited denial.
4. **Analyser.** A share readable in the plain capture fails claim 1 in either
   scope; the plain positive control is now the attribute keys. Claim 2 times
   the sealed share 3's bytes (a new `share3_sealed` canary in the scenario
   manifest) against the audit COMMIT.

## Consequences

- On a live plain capture (2026-10-15, `deploy.run_local` on loopback) no
  share appears anywhere, and claim 2 passes on the sealed share: the audit
  COMMIT was acknowledged 2.27 ms before the release response.
- The custodian no longer holds shares 1 and 3 together in the clear. It
  still holds share 1, and the facility still sees both shares during the
  unlock: the facility gate is where they are combined.
- Sealing inherits the `pre` group: a 256-bit safe prime (ADR-0018). That is a
  demonstration parameter, not a production one, and the paper must say so;
  ECDH on P-256 through `crypto_core` would be the production choice.
- Share keys are per process and not persisted: a restarted service publishes
  a new key, and senders fetch it per call. A share in flight to a service
  that restarts is refused and the operation is retried.
- `create_audit_app` now takes the service identity it already loaded;
  facilities need one to publish their key (all deployment paths have it).
- The release request is not bound to the assertion's facility: the
  custodian picks the gate. A wrong pick only means a facility that cannot
  open the record's emergency wrapping gets the shares; it is audited there.

## Alternatives considered

- **Key in a custom X.509 extension of the service certificate** — no extra
  route, but changes the identity code and the Compose `pki` job.
- **Keys distributed in bootstrap configuration** — simplest code, but trust
  rests on config files rather than the PKI.
- **Wrap only the break-glass path** — smaller, but shares would still show
  in plain deposits and claim 1 could not demand their absence.
