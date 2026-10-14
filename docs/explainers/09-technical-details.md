# 9. Technical details

The "how it is actually built" companion to the plain-language files. Use it
when a question goes below the analogy. Every item points at the source of
truth (`ARCHITECTURE.md`, an ADR, or a file you can open).

## 1. Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.11+ | |
| Crypto primitives | `cryptography` (pyca) | only imported inside `crypto_core` |
| Services | FastAPI + Uvicorn | one process per federation role |
| Storage | PostgreSQL, psycopg3, raw parameterised SQL (ADR-0020) | one shared store; also shares encrypted policy layouts and signed consent between facility processes (ADR-0047) |
| Portals | Django + Bootstrap | their own `portal` schema, plus a read-only window on the store |
| Contracts | Pydantic v2 (ADR-0007), nine frozen schemas (ADR-0008) | `src/contracts/` |
| Tests | pytest (Postgres suites skip without `DATABASE_URL`; known-false claims are strict xfails, ADR-0046) + Django test runner | |
| Style | black + ruff, line length 88 | CI runs lint, format, test on every PR |

Rejected: Charm-Crypto (C build chain, ADR-0001).

## 2. Cryptographic parameters

| Item | Value | Where |
|---|---|---|
| Symmetric encryption | AES-256-GCM, 96-bit nonce generated per encryption, never supplied by the caller (ADR-0022) | `crypto_core/symmetric.py` |
| Signatures | ECDSA, P-256 | `crypto_core` |
| Key derivation | HKDF (SHA-256) via `hkdf_derive` | `crypto_core/symmetric.py` |
| Hash chain | SHA-256 | `audit/chain.py` |
| Shamir field | prime P = 2^256 + 297, shares as (x, y) | `shamir/finite_field.py` |
| Proxy re-encryption | ElGamal-style, unidirectional, prime-order subgroup with generator 4; subgroup membership validated on every input (ADR-0023) | `pre/elgamal.py` |
| Certificates | X.509, single root, cross-certified facility CAs (ADR-0024) | `identity/` |

The seven rules in `CONVENTIONS.md` §2 are correctness requirements: all
primitives through `crypto_core`, `secrets` never `random`, never log keys or
shares, no hardcoded keys, no nonce reuse, fail closed, parameterised SQL.
Endpoints come from a config allowlist, security-sensitive requests carry a
one-time id, and **no cryptography in `api/`** (an AST test enforces this:
`tests/api/test_no_crypto_invariant.py`).

## 3. How a record is protected (envelope encryption)

```
plaintext --AES-256-GCM(DEK)--> ciphertext        (stored in `records`)
DEK --wrapped under--> root secret of the policy tree        (`dek_wrappings`)
DEK --wrapped under--> emergency key (wrapped_for="emergency")
root secret --Shamir over the policy tree--> per-attribute shares,
             each encrypted under that attribute's key
```

- Policy tree per record: `OR(clinical_policy, owner:<patient_id>)` (ADR-0016).
- AND node: k-of-k Shamir; OR node: every child gets the same secret.
- Revocation: full DEK rotation (new DEK, new root secret, re-encrypt, rebuild
  wrappings, signed `Granted → Revoked`, ADR-0036).

## 4. State machine

`src/lifecycle/state_machine.py`. States `granted`, `revoked`, `emergency_open`,
`expired`. Legal transitions (ADR-0030):

```
granted -> revoked          granted -> emergency_open     revoked -> emergency_open
emergency_open -> expired   expired -> granted
```

Each move builds a signed `TransitionEvent`; `event_id` is single-use (consumed
store). The store keeps current state in `lifecycle_state` and history in
`transition_events`. Expiry (`lifecycle/expiry.py`, ADR-0035) is a simulated
HSM timer under a dedicated identity `system:hsm-timer`: sign
`emergency_open → expired`, rotate DEK, sign `expired → granted`. A daemon
monitor thread sweeps due sessions. The facility reconciles a stale
`emergency_open` in the store when the timer holds no session (ADR-0044). In the
deployment, each timer transition is mirrored into the store only after its
audit append succeeds; a failed mirror is logged, not raised, so the monitor
thread keeps running (ADR-0047). The rotated ciphertext itself is not persisted
(throwaway re-baseline key, ADR-0043/0044).

## 5. Break-glass protocol

1. **Assertion** (`breakglass/`, ADR-0032): fields `assertion_id, patient_id,
   clinician_id, facility_id, reason_code (enum), issued_at, expires_at, nonce,
   signature`. Portal assertion TTL is 120 s.
2. **Share 3 release** (`audit_service`, `POST /breakglass/release`): the audit
   service appends a `breakglass_share_released` entry, then returns share 3
   with `entry.seq`. Registry in `audit/share_registry.py`; shares deposited via
   `POST /breakglass/shares`.
3. **Unlock** (`POST /records/{id}/breakglass` at the facility): validate
   assertion (signature, chain, clinician, facility, expiry, replay), check
   `record.patient_id == assertion.patient_id` (ADR-0044), parse shares,
   `open_emergency_access` (2-of-3 combine, signed transition, PRE re-wrap for
   the clinician), persist state, register the expiry session, log
   `federation.rewrap`.
4. **Search** (`POST /records/{id}/emergency-search`): tokens derived from the
   emergency key by HKDF, valid only while a session is live.

Share holders: 1 = clinician custody (Key Custodian), 2 = home authority
(unused in the demo), 3 = audit service. Demo threshold is met by 1 + 3.

## 6. Processes and ports

| Process | Port | Role |
|---|---|---|
| store | (Postgres) | ciphertext, wrapped keys, coded index. Never plaintext |
| facility-a / facility-b | 8001 / 8002 | facility nodes (`api/hospital.py`) |
| authority-med / authority-net | 8010 / 8011 | attribute authorities (`api/authority_service.py`) |
| audit | 8020 | hash chain + share 3 (`api/audit_service.py`) |
| custodian | 8030 | subjects' key agent (`api/custodian_service.py`, ADR-0043) |
| portals | 8000 | Django: `/patient/`, `/clinician/`, `/oversight/` |

`run_portal_demo` starts the federation processes in-process on **ephemeral
ports** and prints them; the table gives the fixed ports used by
`deploy.run_local` and Docker Compose. All service URLs come from config
(`CUSTODIAN_URL`, `AUDIT_SERVICE_URL`, `FACILITY_URLS`, `AUTHORITY_URLS`).

Docker Compose (ADR-0047) also runs the portal on 8000 once bootstrap
succeeds, publishes every port on `127.0.0.1` only, and exposes its store on
`55433` with a password from the git-ignored `deploy/.env` (no trust auth).
The portal runs with `DEBUG` off and fixed `ALLOWED_HOSTS`.

**TLS profile.** `TLS_ENABLED=true` upgrades every federation URL to HTTPS.
`python -m wire.tls` writes `wire/certs/<service>/` per service and a trust
bundle `wire/certs/trust/ca-bundle.crt`; clients verify against the bundle,
never with verification off. Each container mounts only its own key directory.
The browser portal stays HTTP on loopback.

**Bootstrap and restarts.** Bootstrap writes `deployment_bootstrap` (live
service instance ids) only after seeding and chain verification succeed. A
rerun re-checks those ids and the chain, and refuses a partial bootstrap, a
changed seed mode or a restarted key service with a recovery instruction:
recreate the whole demo (`down`, `up --build -d`). `run_migrations(reset=True)`
refuses any non-loopback database host before connecting.

## 7. API surface

**Facility node** (`api/hospital.py`): `GET /health`, `POST /records/ingest`,
`POST /records/{id}/read`, `POST /records/{id}/revoke`,
`POST /records/{id}/breakglass`, `POST /records/{id}/emergency-search`,
`GET /patients/{id}/records` (discovery), `POST /search/records`,
`POST /consent/requests`, `POST /consent/grants`, `POST /consent/grants/revoke`.

**Audit service**: `GET /health`, `GET /public-key`, `GET /chain/head`,
`GET /chain/verify`, `POST /entries`, `POST /breakglass/shares`,
`POST /breakglass/release`.

**Authority service**: `GET /health`, `GET|PUT /certificate`, `GET /public-key`,
credential issue/verify/status/revoke, `POST /attribute-keys/release`,
`POST /attribute-keys/author`.

**Key Custodian**: `PUT /trust`, `POST /subjects/{id}/material`,
`GET /subjects/{id}`, `GET /subjects/{id}/public-key`,
`POST /subjects/{id}/consent/{request|decide|revoke}`,
`POST /subjects/{id}/read`, `POST /subjects/{id}/breakglass`,
`POST /subjects/{id}/records`, `POST /records/{id}/shares`.

## 8. Data model

**Store tables** (`src/storage/migrations/`): `authorities`, `facilities`,
`patients`, `attributes`, `records`, `dek_wrappings`, `lifecycle_state`,
`transition_events`, `audit_log`, `search_index`, and from migration 0003:
`compiled_policies` (encrypted leaf shares + tree layout, versioned JSON),
`consent_requests`, `consent_grants` (signed contract JSON), and
`deployment_bootstrap`. No plaintext keys or unencrypted shares.

**Portal tables** (Django, schema `portal`): `Profile` (login to
subject_id + role), `RegistrationRequest`, `PatientDirectory` (name + DOB,
PII lives only here, ADR-0011/0033), `ConsentRecord` (a display mirror of
grants), `BreakglassCase`, `PatientNotification`.

The portals reach the store through a **read-only** Postgres role
`portal_ro` (`portal/sql/roles.sql`): SELECT only. Anything needing a key goes
to the custodian by `subject_id`.

## 9. Audit events you will see

`patient.lookup` (hit/miss/selection), `consent.decision`, `access_granted`,
`access_denied` (with `denied_by`: policy, assertion, patient-binding),
`federation.discovery`, `breakglass_share_released`, `federation.rewrap`,
`patient.notification`, `lifecycle_transition`. Events share a `correlation_id`
so one emergency or one consent flow can be traced end to end on
`/oversight/trace/?cid=...`.

## 10. Request authorisation order

`ARCHITECTURE.md` §8: **endpoint authorisation runs first, cryptographic
authorisation second.** The endpoint checks that this caller may ask; the
policy engine then decides whether a key can be rebuilt. Both must pass.
Consent (ADR-0031) is a read-time gate before the crypto path, not a re-wrap.

## 11. Repository layout

```
src/        crypto_core shamir pre storage identity authority policy records
            lifecycle audit breakglass search federation consent api contracts
portal/     Django: accounts patient clinician admin_audit ledger portal_core
deploy/     run_local, run_portal_demo, bootstrap, docker-compose, seed_portal
demo/       seed_data (synthetic personas and records), driver
wire/       capture, tls, analyze_traffic (Module 7)
tests/      mirrors src/, plus security/ (negative tests) and e2e/ (hand-run)
docs/       adr/ (decision log), threat-model, explainers/
bench/ paper/   evaluation harness and the write-up (Phase 5/6)
```

One owner per `src/` module (`CONVENTIONS.md` §3); `src/contracts/` is frozen
after Phase 0 and changes only by a contract PR approved by all four.

## 12. Testing

| Kind | Where | Command |
|---|---|---|
| Unit + negative security | `tests/`, `tests/security/` | `python -m pytest tests -q` |
| Needs Postgres | storage, audit, deploy, demo suites | set `DATABASE_URL` first |
| Portal | `portal/*/tests.py` | `cd portal; python manage.py test --settings=config.test_settings` |
| Format / lint (as CI) | `src/`, `tests/` | `black --check src/ tests/`, `ruff check src/ tests/` |
| Live end-to-end + stress | `tests/e2e/portal_flows.py` | see [00-quick-startup.md](00-quick-startup.md) |

A control is not finished until it has a negative test proving it fails closed
(`tests/security/`). Each phase has its own security test file.

## 13. Decision log

`docs/adr/README.md` is the tracker (47 ADRs). The ones most worth knowing:

| ADR | Decision |
|---|---|
| 0001 / 0002 | Reject Charm-Crypto; policy tree over Shamir instead of CP-ABE |
| 0003 | Simulated HSM timer |
| 0011 | One shared semi-trusted store |
| 0014 | Web portals and Postgres store data, never decide access |
| 0016 | Patient self-access as an `owner:` attribute |
| 0030 | State machine transition table |
| 0031 | Consent is a read-time gate |
| 0032 | Emergency assertion and anti-replay |
| 0033 | Emergency identification by name + DOB |
| 0034 / 0035 | Audit chain with log-before-release; time-boxed expiry |
| 0036 | Revocation by full key rotation |
| 0043 | Key Custodian and portal integration |
| 0044 | Break-glass patient binding, stale-state reconciliation (Proposed) |
| 0045 / 0046 | P5-5 wire-claim checks; P5-1 claim registry with strict xfails (Proposed) |
| 0047 | Shared policy/consent state, verified bootstrap, loopback Compose, verified TLS (Proposed) |
