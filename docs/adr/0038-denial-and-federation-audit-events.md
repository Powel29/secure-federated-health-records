# ADR-0038: Denial and federation audit events as fixed-shape helpers, not call-site edits

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-09-06
- **Deciders:** Ojas (P3-13 owner) → all four for ratification
- **Task / source:** P3-13 (WORKFLOW.md); ARCHITECTURE §2 C10, §5 steps 0/3/5
- **Affects:** `src/audit/events.py` (new), `src/audit/__init__.py`,
  `tests/audit/test_events.py`,
  `tests/security/test_phase3_denial_federation_audit_security.py`

## Context

P3-13 asks for two things: (1) access denials, and (2) federation actions
(policy checks, discovery, re-wraps) to appear in the audit chain, with only
identifiers and hashes — never key material. `audit.chain.append_entry`
already accepts an arbitrary `event_type` string and `event_data` dict
(ADR-0034), so nothing prevents any caller from logging these events today.
Three things were not yet decided: *who* calls it, *what shape* the events
take, and *how* the "no sensitive data" requirement is actually enforced
rather than just documented.

The obvious-looking option — go into `policy/engine.py`, `consent/service.py`,
`authority/issuance.py`, `records/revocation.py`, `breakglass/gate.py`, and
`federation/discovery.py`, and insert an `audit.append_entry(...)` call at
each raise site / return point — was rejected. Every one of those modules is
owned by someone else (CLAUDE.md: "one owner per `src/` module... do not
edit it yourself, even for a one-line fix"), and, independently of
ownership, every one of them already documents the opposite design on
purpose: `breakglass/gate.py`'s module docstring says `open_emergency_access`
"does not audit-log itself... the caller uses [`correlation_id`] to tie its
own audit entry to this unlock", and `records/revocation.py` returns a
`RevocationResult.audit_payload` dict with the comment "the caller persists
these to storage and emits an audit entry." Editing those modules to call
`audit` directly would both violate ownership and reverse a design decision
those modules' owners already made and documented.

## Decision

### 1. `audit.events` is a caller-side helper module, not a hook into other modules

`src/audit/events.py` adds `log_access_denied`, `log_federation_discovery`,
and `log_federation_rewrap` — thin, fixed-shape wrappers around
`audit.chain.append_entry`. They live entirely inside `audit` (Ojas's
module) and import nothing from `policy`, `consent`, `authority`, `records`,
`breakglass`, or `federation`. A caller that already has a denial exception
in hand, or a discovery/re-wrap result in hand, calls the matching
`log_*` function. Wiring these calls into the actual production call sites
inside `policy`/`consent`/`records`/`breakglass`/`federation` is deferred to
the Phase 4 API/orchestration layer (P4-1, P4-2) that already owns calling
into all of those modules — exactly the "caller persists + audit-logs"
seam those modules were built expecting. `tests/security/
test_phase3_denial_federation_audit_security.py` proves the seam actually
works today by driving each real denial/federation function, catching its
result, and logging it — without touching the module that produced it.

### 2. Fixed event-data shapes, not free-form dicts per caller

Three event types, three fixed schemas:

- `access_denied`: `record_id`, `requester_id`, `denied_by` (one of
  `DENIED_BY_POLICY` / `DENIED_BY_CONSENT` / `DENIED_BY_CREDENTIAL` /
  `DENIED_BY_REVOCATION_AUTHZ`, or free text), `reason` (the caught
  exception's message).
- `federation.discovery`: `patient_id_hash`, `requester_id`, `record_count`,
  `record_ids`.
- `federation.rewrap`: `record_id`, `source_facility_id`, `target_actor_id`.

Fixing the shape (rather than letting each future caller invent its own
dict) is what makes the admin/audit portal's denial view (P4-9) a query
over a known schema instead of an ad hoc scan of free-form JSON.

### 3. `patient_id` is hashed, not stored raw, in federation discovery events

`event_data["patient_id_hash"] = sha256_digest(patient_id.encode()).hex()`.
Alternatives considered:

- **Store `patient_id` raw.** Rejected: ADR-0011 keeps PII out of the crypto
  store, and `records.revocation.RevocationResult.audit_payload` already
  established the precedent of omitting `patient_id` from audit metadata,
  carrying only `record_id`. Discovery has no `record_id` to key off of
  *before* the query runs, so it needs something to correlate repeated
  lookups for the same patient — a hash gives that without becoming a
  plaintext index of patient identities inside the tamper-evident,
  effectively-permanent chain.
- **Omit patient identity entirely, log only `record_count` and
  `requester_id`.** Rejected: it would make the admin denial view unable to
  answer "how many times was this patient looked up," which is exactly the
  kind of question ARCHITECTURE §5 step 0 wants answered ("the lookup itself
  is a `patient.lookup` audit event whether or not a match is selected").
  A hash is a reasonable middle ground: it does not name the patient, but two
  entries with the same `patient_id_hash` are provably about the same
  patient.

### 4. No new runtime "reject key material" guard is added

`share_custody.release_share_after_commit`'s docstring already explains why:
"this function does not enforce [no key material in event_data] beyond
documenting it, since it has no way to tell a hash from a secret" — both are
just bytes (or hex strings) to the function. What already *does* fail closed
structurally is `chain._canonical_event`'s `json.dumps(event_data, ...)`
call: raw `bytes` (which every key, share, and DEK in this codebase is) is
not JSON-serializable, so passing one directly in `event_data` raises
`TypeError` before `compute_entry_hash` runs and before
`repo.insert_audit_entry` is ever called — no partial entry, no chain
mutation. `tests/security/test_phase3_denial_federation_audit_security.py::
test_sec_raw_key_bytes_in_event_data_are_rejected_before_persisting` proves
this holds for these new event types specifically, rather than inventing a
redundant bytes-scanning guard on top of a check that already exists.

## Consequences

**What this makes work.** Any current or future caller (tests today; the
Phase 4 API layer once it exists) can log a denial or federation event with
three lines of code and a documented, minimal-leakage shape. The admin/audit
portal (P4-9) has a fixed schema to query for its denial view.

**What this does not do.** It does not make production denials in
`policy`/`consent`/`authority`/`records` or federation actions in
`federation`/`breakglass` actually appear in the chain during a live run
today — nothing in those modules calls `audit.events` yet, by design (see
Decision 1). That wiring is explicitly P4-1/P4-2's job. This is consistent
with every other Phase-3 module on this dependency chain (`gate.py`,
`revocation.py`) already shipping "caller logs" as a documented seam rather
than a violation waiting to be fixed.

## Alternatives considered

- **Edit the six other modules' raise sites directly.** Rejected — see
  Context: violates one-owner-per-module and reverses those modules'
  documented design.
- **A cross-module event-bus / callback registered at import time**, so
  `policy`/`consent`/etc. could emit without importing `audit` or being
  edited by Ojas. Rejected as over-engineering for this task: no such
  mechanism exists anywhere else in the codebase (grepped — confirmed), it
  would itself be a new contract needing four-person sign-off, and Phase 4's
  API layer already needs to call every one of these modules directly to
  orchestrate a request; adding audit logging at the same call site is no
  extra wiring once that layer exists.
