# ADR-0047: Shared facility state and reproducible local deployment

- **Status:** Proposed
- **Date:** 2026-10-09
- **Deciders:** Avaneeth (proposal); Ojas to review the `deploy/` and `wire/` parts; team ratification pending
- **Task / source:** Full local/demo deployment review
- **Affects:** storage, API repository, deployment, TLS harness; ADR-0039/0043

## Context

The PostgreSQL adapter stored compiled policies and consent in class dictionaries.
Separate facility processes therefore returned HTTP 500 for cross-facility reads,
although the in-process tests passed. Compose also mistook registry rows for a
completed bootstrap, and TLS listeners retained HTTP client URLs.

## Decision

Store compiled policies as versioned JSON containing only the existing encrypted
leaf shares and tree layout. Store signed consent artifacts using their existing
contract JSON encoding. Do not introduce new crypto or change frozen contracts.

Record bootstrap completion only after seeding and chain verification succeed.
On rerun, compare per-process instance IDs and verify the chain again. Reject
partial initialization or changed processes with an explicit full-demo recreation
instruction. Keys remain ephemeral, as specified by ADR-0039; this change does not
claim persistent key custody or safe independent service restarts.

Compose includes the portal after successful bootstrap and publishes ports only
on loopback. TLS configuration upgrades all federation URLs and trusts a bundle
of generated local server certificates without disabling verification. Exclude
generated keys, certificates and local state from Docker build contexts.

Mirror timer lifecycle states into the store only after their audit append
succeeds, so portal status follows automatic expiry. This does not persist the
timer's rotated ciphertext: the caller still supplies a throwaway baseline key
(ADR-0043/0044), and persisting that result would lock out routine readers. The
cryptographic re-baseline persistence work remains separate from this deployment
fix. The live checker waits for the second session it deliberately reopens before
classifying an emergency-open record as stuck.

### Review follow-ups (2026-10-09)

- **Schema reset guard.** `deploy.bootstrap.run_migrations(reset=True)` refuses,
  before connecting, any target host (DSN `host`/`hostaddr` or `PGHOST`/`PGHOSTADDR`)
  that is not loopback or a local socket. Rejected: an expected-database-name check,
  which a remote store with the same name would pass.
- **Store password.** The Compose store requires `POSTGRES_PASSWORD` from the
  git-ignored `deploy/.env`; trust authentication is removed. The port stays
  published on loopback for host-side `psql`, the GUI and the separate-portal path.
  Rejected: unpublishing the port, which breaks those documented paths.
- **Portal settings.** Compose runs the portal with `DJANGO_DEBUG=0` and
  `DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost`; `runserver --insecure` keeps serving
  the static CSS. It is still the development server, which suits a loopback demo.
- **Per-service TLS keys.** `wire.tls` writes `certs/<service>/` per service and
  `certs/trust/ca-bundle.crt`. Each container mounts only its own key directory and
  the bundle. Directory mounts, not file mounts, because Docker turns a missing
  file mount into an empty directory when TLS certificates were never generated.
  The certificate SANs already include the Compose hostnames.
- **Store mirror failure.** If the store write after a committed expiry audit entry
  fails, it is logged at ERROR and not raised, because raising stops the expiry
  monitor thread (review F20). Access is already closed past `expires_at`, and the
  facility reconciles the stale `emergency_open` on its next state read (ADR-0044).
  Rejected: retrying inline, which would block the monitor sweep.

## Consequences

Cross-facility reads use the same encrypted policy and signed consent state.
Restarting the portal preserves its schema. Recreate the whole federation for
fresh key-service state; this intentionally discards synthetic demo records.
The browser portal remains HTTP on loopback; the optional TLS profile protects
federation traffic. The custodian assumes trusted local callers. This is a local
demonstration, not an authenticated internet-facing deployment.

## Alternatives considered

- Share a Python cache: cannot work across containers and conceals the bug in tests.
- Persist every private key and timer: expands this task into durable key custody
  and crash recovery, outside the requested local/demo scope.
- Disable TLS verification: unnecessary when generated certificates can be trusted
  explicitly; it would hide configuration errors.
