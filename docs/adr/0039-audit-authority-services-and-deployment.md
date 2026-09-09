# ADR-0039: Audit/authority services as standalone processes; shared-entrypoint deployment

- **Status:** Proposed
- **Date:** 2026-09-09
- **Deciders:** Ojas (P4-2/P4-3 owner) → all four for ratification
- **Task / source:** P4-2, P4-3 (WORKFLOW.md); ARCHITECTURE.md §5 step 3, §7;
  ADR-0034 (documented liveness gap explicitly deferred here); ADR-0035
  (documented Phase 4 audit-wiring seam explicitly deferred here)
- **Affects:** `src/api/audit_service.py`, `src/api/audit_schemas.py`,
  `src/api/audit_client.py`, `src/api/authority_service.py`,
  `src/api/authority_schemas.py`, `src/audit/share_registry.py`,
  `src/audit/__init__.py`, `deploy/` (new directory: `bootstrap.py`,
  `run_local.py`, `compose_bootstrap.py`, `entrypoint.py`, `asgi/`,
  `Dockerfile`, `docker-compose.yml`), `pyproject.toml` (ruff
  per-file-ignores), `tests/api/test_audit_service.py`,
  `tests/api/test_authority_service.py`, `tests/api/test_audit_client.py`,
  `tests/deploy/test_bootstrap.py`

## Context

P4-2 asks for the audit service and the two attribute authorities to run as
their own processes that a hospital node can talk to over HTTP. P4-3 asks
for both deployment paths (local supervisor, Docker Compose) and the
seven-step bootstrap sequence, ending in a hard precondition: if the audit
chain fails verification at boot, nothing else starts.

Two things already in the codebase point directly at this task rather than
leaving it open-ended:

- ADR-0034 (P3-4) flags a concurrent-`seq` race in `audit.chain.append_entry`
  as "a liveness concern... left as a documented limitation for P4-2 (the
  audit service process) to address if the demo topology needs it."
- `lifecycle.expiry.EmergencyExpiryManager` accepts an `audit_logger`
  callback and says outright: "End-to-end wiring to
  `audit.share_custody.release_share_after_commit` and
  `audit.chain.append_entry` happens at Phase 4 API integration (P4-2).
  Passing `audit_logger=None` here means expiry events do not enter the
  hash chain — documented limitation (ADR-0035)."

Both are addressed by this ADR's decisions, not deferred further.

## Decision

### 1. The audit service and each authority are separate FastAPI processes, ephemeral by design

`api.audit_service.create_audit_app` and `api.authority_service.create_authority_app`
each wrap the existing, already-tested modules (`audit.chain`,
`audit.share_custody`, `authority.issuance`) behind HTTP, generating their
own signing keypair at startup rather than loading one from disk.

This is deliberate, not a shortcut: ARCHITECTURE.md §7's bootstrap sequence
already regenerates the root anchor and every facility CA certificate fresh
on every run, and the whole federation is reseeded each time (`demo/`, not
yet built). A persisted authority signing key would be a false durability
guarantee anyway, because `AttributeAuthority`'s per-attribute key material
(`_attribute_keys`, minted lazily) is already in-memory-only and was never
in this task's scope to make durable — persisting just the signing key
while the keys it certifies vanish on restart would be worse than being
honest that the whole process is ephemeral.

**Consequence, made explicit and tested** (`test_second_boot_against_same_chain_does_not_duplicate_genesis`):
restarting the audit service against a *fresh* Postgres (new bootstrap run)
works exactly like a first boot. Restarting the *process only*, against a
Postgres that still holds a prior chain, only succeeds if the same signing
key is reloaded — with a freshly generated one (the default), chain
verification at startup correctly fails and the process refuses to start,
per ARCHITECTURE.md §7's own hard precondition. This is fail-closed, not
broken; a deployment that needs the audit service to restart independently
of its database would need to persist its key, which is out of this task's
scope.

### 2. Break-glass share release becomes a real network call, not an in-process one

ARCHITECTURE.md §7 states the governing constraint plainly: "If \[the audit
service\] shares memory with a facility node, 'the audit service releases
its share only after committing' becomes an in-process function call that a
reviewer can dismiss as a convention rather than an enforced precondition."

`api.audit_service` exposes `POST /breakglass/shares` (hand the service
custody of one share) and `POST /breakglass/release` (the log-before-release
gate, now reachable only over HTTP). `audit.share_registry.ShareRegistry` is
the new, deliberately dumb, in-memory store those two endpoints share — it
does not consume a share on release (see its own docstring for why: a
record's share is a standing custody item, not a one-time token; rotation,
not release, is what should retire it). PROJECT.md §4A item 2 needs exactly
this: "the audit service's share never appears on the wire before the
log-commit response containing the new chain head" is now a claim a PyShark
capture can actually check (P5-5), because the share and the chain head
travel in the same HTTP response body, which only exists once
`audit.share_custody.release_share_after_commit` has already returned.

### 3. ADR-0034's concurrent-`seq` gap: closed with one process-local lock

`api.audit_service` wraps every chain-appending endpoint
(`POST /entries`, `POST /breakglass/release`) in one `threading.Lock`. Since
this service is the chain's sole writer (by design — no other process ever
calls `audit.chain.append_entry` against the shared store), a single
in-process lock is sufficient *as long as the service runs as one process
with one worker*, which is what both deployment paths in this ADR do
(`uvicorn.run(..., workers=1)` is the implicit default; neither
`deploy/run_local.py` nor `docker-compose.yml` overrides it).

**Honesty caveat, inherited from ADR-0034 and narrowed, not removed:** a
future multi-worker or multi-replica audit service would reintroduce the
exact race ADR-0034 described, since a `threading.Lock` does not cross
process boundaries. That configuration is out of this project's demo
topology and is not attempted here.

### 4. The lifecycle audit-logger seam: closed via an HTTP client, not a shared key

`api.audit_client.make_lifecycle_audit_logger` builds the
`Callable[[dict], None]` `EmergencyExpiryManager.__init__` already accepts,
POSTing each expiry transition to the audit service's `/entries` endpoint.
`deploy/asgi/facility.py` wires it in whenever `AUDIT_SERVICE_URL` is
configured. This was the only reasonable way to close ADR-0035's gap
without giving a facility process the audit service's private signing key
(which `api/hospital.py`'s existing denial-logging path already does, as a
pre-existing P4-1 simplification this task does not touch — see
"Alternatives considered" below) or editing `lifecycle/expiry.py` itself,
which this task does not own.

### 5. One shared entrypoint, two deployment paths

`deploy/entrypoint.py` dispatches on a `SERVICE_ROLE` environment variable
to one of three `deploy/asgi/*.py` factory modules. `deploy/run_local.py`
(Path A) spawns it as a local subprocess per service; `deploy/Dockerfile`'s
`ENTRYPOINT` runs the identical module inside a container (Path B). There is
exactly one way a service process starts, regardless of which path launched
it — the two paths differ only in *how* the entrypoint is invoked, never in
what it does once running.

The bootstrap-sequence logic itself (`deploy/bootstrap.py`: PKI generation,
authority registration, the audit-chain hard precondition) is a plain
library with no process-management code in it, called by two thin drivers:
`run_local.py` for Path A (against `127.0.0.1:<port>`) and
`compose_bootstrap.py` for Path B (against Compose service hostnames, run as
a one-shot `bootstrap` service gated on every other service's
`depends_on: condition: service_healthy`). This is what makes
`tests/deploy/test_bootstrap.py` possible without Docker: the library
functions are tested directly against real (non-Docker) uvicorn servers, and
only the two drivers are Docker/subprocess-specific and untested by this
PR's own suite (they are exercised by actually running each path, per
ARCHITECTURE.md §7's own demo-day requirement).

### 6. Facility nodes hold no PKI material of their own

`api.hospital.create_hospital_app` (P4-1, Avaneeth's) already takes
certificates and keys as *request* data rather than server-held
configuration, so `deploy/asgi/facility.py` has nothing to bootstrap beyond
a database connection and a fresh emergency-timer identity. This ADR does
not change that design; it only confirms it is compatible with the
deployment topology as built.

## Consequences

**What this makes work.** A hospital node genuinely *can* talk to the audit
and authority services over HTTP now (P4-2's exit criterion) — verified by
`tests/api/test_audit_service.py`, `tests/api/test_authority_service.py`,
and, against a real socket (not just FastAPI's in-process `TestClient`), by
`tests/deploy/test_bootstrap.py`. Both deployment paths bring up all five
service processes plus the shared store, run the bootstrap sequence, and
refuse to proceed if the audit chain does not verify (P4-3's exit
criterion).

**What this leaves undone, on purpose.** `api/hospital.py`'s own denial and
federation-discovery logging (`log_access_denied`, `log_federation_discovery`,
`log_federation_rewrap`) still takes the audit signing key directly as a
per-facility parameter and calls `audit.chain.append_entry` in-process — a
pre-existing P4-1 design this task does not touch, since `src/api/hospital.py`
is not this task's module to edit (CONVENTIONS.md §3: one owner per `src/`
directory). Wiring those call sites to the standalone audit service the same
way `audit_client.py` wires the expiry timer is real follow-up work, most
naturally done alongside P4-4 (the end-to-end run, Avaneeth's), which already
owns the seam between facility orchestration and the rest of the federation.

**What is still a documented limitation, not a claimed control.**
`authority_service`'s `POST /attribute-keys/author` and
`POST /breakglass/shares` accept sensitive material (a mint request, a raw
share) with no caller authentication beyond what the rest of this project
already relies on — consistent with ARCHITECTURE.md §8's "Deliberately
excluded" list (no session/auth infrastructure anywhere in this project),
but worth restating here because these two endpoints are new and more
obviously an attack surface than most.

## Alternatives considered

- **Persist authority/audit signing keys to disk across restarts.**
  Rejected — see Decision 1. Would have added real complexity (key-file
  handling, `.gitignore`-sensitive paths, a "first run vs. restart" branch
  in every service factory) to solve a problem the project's own bootstrap
  model does not have: the demo never restarts one service against
  yesterday's database.
- **A cross-process lock (Postgres advisory lock, `SELECT ... FOR UPDATE`)
  instead of a Python `threading.Lock` for the audit chain's `seq`
  assignment.** Rejected for this task: correct for a multi-worker audit
  service, but this project's demo topology never runs one, and the simpler
  in-process lock is the smallest change that actually closes ADR-0034's gap
  for the topology that exists. Flagged as the natural next step if a future
  phase ever needs multiple audit-service replicas.
- **Editing `src/api/hospital.py` to call the standalone audit service for
  denial/federation logging, in this same PR.** Rejected — see "What this
  leaves undone." Would have meant editing Avaneeth's P4-1 module and its
  existing tests outside this task's ownership boundary, for a property
  (denial-log completeness) that is not one of P4-2's or P4-3's own exit
  criteria.
- **A single combined "authority" service process serving both
  `authority-med` and `authority-net`.** Rejected — ARCHITECTURE.md §7's
  topology table lists them as two independent processes on two ports
  precisely so that neither authority is a single point of failure for the
  other's namespace; `create_authority_app` takes an `authority_id` and
  owned-namespace set specifically so one factory module serves either role
  from environment configuration alone.
