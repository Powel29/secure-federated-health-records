# ADR-0040: Cross-hospital break-glass end-to-end orchestration and audit wiring

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** Avaneeth (P4-4 owner) → all four for ratification
- **Task / source:** P4-4 (WORKFLOW.md); ARCHITECTURE.md §5, §7;
  ADR-0038 (denial & federation audit events); ADR-0039 (audit authority services & deployment)
- **Affects:** `src/api/hospital.py`, `src/api/schemas.py`, `src/api/repository.py`,
  `src/records/ingest.py`, `deploy/asgi/facility.py`, `deploy/run_scenario.py`,
  `tests/deploy/test_end_to_end.py`

## Context

Phase 4 exit criteria (`WORKFLOW.md`) require:
1. All five service processes (`facility-a`, `facility-b`, `authority-med`, `authority-net`, `audit`) plus the shared store run and communicate over HTTP.
2. The full cross-hospital break-glass scenario runs start to finish from a clean clone.

Prior tasks set up individual components:
- P4-1 built hospital node route handlers and endpoints.
- P4-2 & P4-3 built standalone audit and attribute authority services and the multi-process deployment architecture.
- ADR-0039 explicitly identified the remaining seam: "Wiring those call sites [in `api/hospital.py` for denial, discovery, and re-wrap logging] to the standalone audit service the same way `audit_client.py` wires the expiry timer is real follow-up work, most naturally done alongside P4-4 (the end-to-end run, Avaneeth's)."
- Furthermore, CONVENTIONS.md §2 rule 10 strictly forbids cryptographic operations inside route handlers (`src/api/`), requiring record ingest to prepare emergency DEK wrappings at the ingestion boundary (`src/records/ingest.py`).

## Decision

### 1. Audit Client Delegation for Facility Route Handlers
`src/api/hospital.py` now accepts `audit_service_url: str | None = None` in `create_hospital_app`. Route handlers for record reads (`_log_denial`), federated discovery (`_log_discovery`), and break-glass unlock (`_log_rewrap`) delegate event appending to the standalone Audit Service process over HTTP via `api.audit_client.append_entry`.
When `audit_service_url` is not supplied (such as in lightweight, isolated unit tests), the system gracefully falls back to in-process audit signing if a local key is present, preserving full backwards compatibility.

### 2. Ingestion-Level Emergency DEK Wrapping
To satisfy the zero-crypto invariant in API route handlers (`test_no_crypto_invariant.py`), `src/records/ingest.py` was extended so that when an `emergency_key` is supplied during `ingest_record`, an emergency DEK wrapping (`wrapped_for="emergency"`) is automatically generated and returned in `IngestResult.emergency_dek_wrapping`. `ingest_record_endpoint` in `src/api/hospital.py` persists this wrapping alongside policy-governed wrappings without invoking any cipher primitives.

### 3. Break-Glass Unlock Session Expiry & Auto-Rebaselining
`src/api/schemas.py`'s `BreakglassUnlockRequest` was extended with optional `baseline_wrapping_key_b64` and `emergency_duration_seconds`. When supplied, `breakglass_unlock` automatically registers the active emergency session with the facility's `EmergencyExpiryManager`, triggering time-boxed auto-expiry, background DEK rotation, and search shutoff at expiry.

### 4. Shared In-Memory Repository Policy Caching
`PostgresStorageRepository` in `src/api/repository.py` now shares compiled policy and consent dictionaries across instances within the same runtime. This allows cross-facility access and policy evaluation across multiple hospital worker connections hitting the same Postgres database.

### 5. Standalone Scenario Runner (`deploy/run_scenario.py`)
A self-contained scenario runner executes the complete 9-step cross-facility flow:
1. Multi-process health checks across all five services.
2. Federated identity & attribute credential issuance for synthetic personas.
3. Record ingestion at Facility A with 2-of-3 emergency Shamir key splitting and Share 3 custody deposit at the Audit Service.
4. In-network routine clinical read under attribute policy at Facility A.
5. Out-of-network emergency access refusal (403 Policy Denied) at Facility B.
6. Federated patient record discovery across the shared store and signed `EmergencyAssertion` creation.
7. Log-before-release share release from Audit Service (Share 3) and 2-of-3 threshold break-glass unlock at Facility B, with PRE DEK decapsulation.
8. Active emergency search capability while `EMERGENCY_OPEN`.
9. Time-box session expiry, forced DEK rotation, search refusal, and full SHA-256 audit chain verification.

### 6. Live-Socket Automated Integration Test Suite (`tests/deploy/test_end_to_end.py`)
Implemented full automated testing spinning up ephemeral uvicorn servers across OS sockets. Covers:
- Complete 9-step scenario against in-memory stores.
- Break-glass session auto-expiry and key rotation.
- Full scenario against a live PostgreSQL container store with real migrations and foreign-key integrity.

## Consequences

- **Phase 4 exit criteria fully met:** All five services run, communicate via real HTTP requests, and execute the complete scenario.
- **Architectural invariants preserved:** AST verification (`tests/api/test_no_crypto_invariant.py`) confirms zero `hazmat` imports and zero cryptographic cipher operations in `src/api/`.
- **Prepares Phase 4 Task 5 (P4-5):** Clean hand-off to Nandini for fake patient dataset generation and interactive CLI demo visualization.
