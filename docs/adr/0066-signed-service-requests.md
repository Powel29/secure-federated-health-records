# ADR-0066: Every service-to-service call is a signed one-time request from a root-certified service

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (decision, review D5-a); Ojas (audit, authority, custodian, deploy), Avaneeth (`api`, `identity`), Nandini (portal) to review
- **Task / source:** review D5 / F34 (claim C9), F14; `docs/review/2026-10-07-fix-proposals.md`
- **Affects:** new `api/service_auth.py`, `identity/services.py`, `identity.issue_service_certificate`, `breakglass.envelopes.check_envelope_binding`; every app factory (`create_hospital_app`, `create_audit_app`, `create_authority_app`, `create_custodian_app`); `api/audit_client.py`; `deploy/` (bootstrap, Compose, run_local, ASGI factories); `portal/portal_core/services.py` and settings; demo, scenario and bench scripts; storage migration 0005; reverses part of ADR-0015/ADR-0017; amends ADR-0014; replaces the F14 interim allowlist

## Context

No service authenticated its caller. Every endpoint was reachable by anything
that could open a socket, and `requester_id`, `subject_id` and `actor_id` were
whatever the caller typed. The only interim control was F14's address allowlist
for authoring keys, which does not hold on Path A where every process shares
loopback. `breakglass/envelopes.py` and the frozen `RequestEnvelope` contract
existed but nothing used them. ADR-0015 had cut service signing as redundant
with the PKI; the review showed the PKI identified clinicians, not services.

## Decision

1. **Service certificates.** Bootstrap issues every process -- `facility-a`,
   `facility-b`, `audit-service`, `authority-med`, `authority-net`,
   `custodian`, `portal`, `bootstrap` -- an ECDSA key and a certificate signed
   directly by the federation root, CN = service id, OU = `service:<kind>`
   (`facility`, `audit`, `authority`, `custodian`, `portal`, `bootstrap`). A
   CA certificate or one without that OU is not a service identity.
2. **Signed requests.** Every request carries `X-Service-Certificate` and
   `X-Request-Envelope`: the existing `RequestEnvelope` contract, signed by the
   existing `breakglass.envelopes.create_request_envelope`, minus its `body`
   field. The envelope's body is the raw HTTP body, so the signature covers
   exactly the received bytes and **the body itself is unchanged on the wire**
   (the `wire/` analyser still sees and checks what it always did). The
   envelope binds caller, recipient service id, operation
   (`"<METHOD> <path>[?<query>]"`), a one-time `request_id`, a nonce and
   `issued_at`.
3. **Checks, in order, before any route code runs** (`ServiceAuthMiddleware`):
   the certificate chains to the configured root and is a service certificate;
   the envelope's caller is that certificate's CN; the envelope was signed for
   this exact operation, within 120 s (30 s skew); the signature verifies; the
   recipient is this service; the `request_id` is unused (consumed last, so a
   forged envelope burns nothing). Failure is 401.
4. **Per-route permissions by kind.** Each service declares
   `(METHOD, path template) -> allowed kinds`; a route missing from the table,
   or a table entry with no route, is a startup error. A kind not allowed is
   403. Only read-only public routes skip authentication: `/health`, public
   keys, an authority's certificate read, the audit chain head and verify, and
   the deployment instance id.
5. **Replay stores.** Facilities and the audit service consume `request_id`s in
   the shared store (`consumed_ids`, kind `request`); authorities and the
   custodian in memory, bounded by the 120 s window.
6. **Object-level authorization before storage (F34).** A read whose requester
   presents no attribute key is refused before the record, wrapping or policy
   is loaded; only a key agent (custodian) or bootstrap may call reads at all.
7. **The portal gets a service key** (user decision). It identifies the portal
   process only: it is not a subject's key, opens no record and decides no
   access, so ADR-0014's rule -- portals store data and identify users, keys
   and the threshold gate decide -- stands. The portal imports
   `api.service_auth` from `src/` so its signing goes through `crypto_core`.
8. **F14's address allowlist is removed**: authoring keys go to a signed
   request from a facility, the custodian or bootstrap.

## Consequences

- Claim C9 holds at the system level
  (`tests/security/test_p51_system_claims.py::test_c9_bola_...`), with
  mutations C9a (auth lets anyone in) and C9b (read loads before the key
  check) each turning it red.
- Every caller must sign: deploy writes `deploy/pki/services/<id>/` (git-ignored)
  and each Compose container mounts only its own directory. Scripts sign as
  `bootstrap`; tests use `tests/service_pki.py`.
- **Residual risks, stated plainly:**
  - The custodian still asserts which subject it acts for (ADR-0043); a
    compromised custodian is every subject. Service identity narrows *which
    process* may assert that, not what it asserts.
  - No service-certificate revocation list: a stolen service key works until
    the deployment is re-bootstrapped (certificates last one year; every run
    re-issues them, ADR-0039).
  - Authorities' and the custodian's replay stores are in memory: after a
    restart a captured request could be replayed for up to 120 s.
  - TLS stays optional (ADR-0042); the envelope gives integrity and
    authenticity, not confidentiality.
- About 1 KB of headers per request; latency numbers in `bench/results/` were
  regenerated with signing on.

## Alternatives considered

- **Envelope as the HTTP body** (body base64-wrapped inside) -- double-encodes
  every secret in transit, so the wire analyser's canary and field checks
  would silently stop seeing them. Rejected.
- **Mutual TLS** -- also authenticates services, but ties identity to the
  optional TLS profile and leaves the plain capture profile unauthenticated.
- **Network isolation only (D5-b)** -- already in place (F16); it does not stop
  a process inside the network from claiming any identity.
- **Route everything through the custodian** (portal keeps no key at all) --
  rewires most portal flows and turns the custodian into a proxy for public
  operations such as discovery.
