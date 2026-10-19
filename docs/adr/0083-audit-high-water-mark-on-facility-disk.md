# ADR-0083: The facility keeps its audit high-water mark on its own disk

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** Ojas (proposal) → Avaneeth (`api/`, `deploy/` owner) to review
- **Task / source:** review F31 remainder (`docs/review/2026-10-07-fix-proposals.md`, "Still open")
- **Affects:** `api/audit_client.py` (`use_high_water_file`), `deploy/asgi/facility.py` (`AUDIT_HIGH_WATER_FILE`, required), `deploy/docker-compose.yml`, `deploy/Dockerfile`, `deploy/run_local.py`; `tests/security/test_audit_high_water.py`

## Context

Review F31 made every facility refuse an audit entry whose `seq` is not after
every `seq` it had already been given, so a truncated or replaced chain is
caught by the next append. The mark lived in process memory, so a restarted
facility trusted the chain again from whatever `seq` it was given next. The
gap is exactly the case that matters: an audit service cut back while the
facility was down.

All services reach the shared store as the same Postgres role (`postgres`,
see review F36 for the portal's separate role), so a table in that store
would be writable by whoever could truncate `audit_log`.

## Decision

The facility persists `{audit_service_url: highest seq}` to a JSON file named
by `AUDIT_HIGH_WATER_FILE`, on its own disk, and loads it at startup. The
variable is required: a facility without it refuses to start (fail closed,
like `AUDIT_SERVICE_URL` in review F19). A raised mark is written (temp file
+ rename) before the entry is accepted; if the write fails the append raises
`AuditServiceError`, so the caller gets 503 rather than an entry beyond the
mark on disk. A file that is not a JSON object of integers stops startup.

- Compose: `/var/lib/ehr/audit-high-water.json` in the container's own
  filesystem (no volume). It survives `docker compose restart` and goes away
  with `down`, together with the volume-less store.
- Path A: `deploy/pki/state/<facility>-audit-high-water.json` (git-ignored),
  deleted by `run_local` right after it resets the store.

## Consequences

- A facility restart no longer reopens the truncation window F31 left.
- The mark and the store must be reset together. Resetting only the store
  (a new chain at seq 0) makes every append from that facility fail until
  the file is deleted, which is fail-closed but needs the operator to know
  why; the error says "went backwards". Recreating only the facility
  container (e.g. `up` after an image change while the store keeps running)
  drops the mark, which is the old behaviour, not a new hole.
- This is a lightweight external anchor, not a proof: it catches truncation
  below what this facility has seen, not entries the audit service never
  returned to it, and an attacker who controls the facility's disk can lower
  the mark. The custodian's own check on release entries is unchanged.
- Code that builds the facility app directly (in-process demo, tests) still
  gets the in-memory mark unless it calls `use_high_water_file`.

## Alternatives considered

- **A table in the shared store** — rejected: the same role that can delete
  `audit_log` rows can lower the mark, so it adds nothing against the
  threat F31 names. It would become reasonable once services have separate
  store roles.
- **Optional variable, in-memory when unset** — rejected: a missing setting
  would silently restore the old behaviour; the project rule is fail closed.
- **Anchor the chain head hash, not just `seq`** — stronger (catches a
  replaced chain of equal length), but the facility does not get the full
  entry hash from every path today; left as future work.
