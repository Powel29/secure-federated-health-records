# 9. Technical details

The "how it is actually built" companion to the plain-language files. Use it when
a question goes below the analogy. Every item points at the source of truth (the
paper, `ARCHITECTURE.md`, an ADR, or a file you can open). Paper Section IX
(Implementation and Evaluation) and Section V (lifecycle) are the references.

## 1. Stack and size

| Layer | Choice | Notes |
|---|---|---|
| Language | Python **3.11.9** | `src/` has **97 Python files, 16,450 non-blank lines** |
| Crypto primitives | `cryptography` (pyca) | every `hazmat` import is confined to `crypto_core`; **Shamir sharing, the ElGamal PRE and the policy tree are hand-rolled** |
| Federation services | **FastAPI under uvicorn**, six of them | facilities A and B, authorities med and net, audit, custodian |
| Storage | **PostgreSQL 16**, psycopg3, raw parameterised SQL (ADR-0020) | one shared store; also shares encrypted policy layouts and signed consent between facility processes (ADR-0047) |
| Portals | **One Django process** serving patient, clinician and admin portals | own `portal` schema plus a role-restricted window on the store |
| Contracts | Pydantic v2 (ADR-0007), frozen schemas (ADR-0008/0017) | `src/contracts/` |
| Tests | pytest (Postgres suites need `DATABASE_URL`) + Django test runner | |
| Style | black + ruff, line length 88 | CI runs lint, format, test |
| Paper | IEEEtran LaTeX built with Tectonic (ADR-0087) | `paper/build/main.pdf` |

Rejected: Charm-Crypto (C build chain, ADR-0001).

## 2. Cryptographic parameters

| Item | Value | Where |
|---|---|---|
| Symmetric encryption | AES-256-GCM, 96-bit nonce generated per encryption, **never supplied by the caller** (ADR-0022) | `crypto_core/symmetric.py` |
| Signatures | **ECDSA P-256 / SHA-256** | `crypto_core` |
| Key derivation | HKDF-SHA-256 (`hkdf_derive`); search tokens use salt `search-token-v1` | `crypto_core`, `search/service.py` |
| Hash chain | SHA-256 | `audit/chain.py` |
| Shamir field | **GF(p), p = 2^256 + 297** (257-bit prime); secret length-prefixed (4 B), zero-padded into 32-byte blocks; 33-byte share element | `shamir/` |
| Emergency key split | **k = 3, n = 4**, x=1 custodian, x=2 home authority, x=3,4 audit | `breakglass/emergency_key.py` |
| PRE / KEM / share sealing | ElGamal-style over a **256-bit demonstration group**, generator 4, subgroup membership validated on every input (ADR-0023); PRE is bidirectional (ADR-0076) | `pre/elgamal.py` |
| Signed-bytes encoding | **domain tag + length-prefixed fields** (ADR-0077), e.g. `ehr/transition-event/v1` | all signed artefacts |
| Certificates | X.509, single root, cross-certified facility CAs (ADR-0024) | `identity/` |
| DEK wrapping | AES-GCM under policy root secret / emergency key; **AAD = record id + policy id + generation** | `records/service.py` |
| Payload | AES-GCM with **no AAD** (paper limitation) | `records/service.py` |
| Assertion | nonce ≥ 128 bits; lifetime ≤ 15 min; future skew ≤ 30 s | `breakglass/assertion.py` |
| Signed service requests | envelope age ≤ 120 s, skew 30 s (ADR-0066) | `breakglass/envelopes.py` |
| Cert/service TLS | self-signed, server-only, no version/cipher pinned | `wire/tls.py` |

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
DEK --wrapped under--> emergency key K_E (wrapped_for="emergency")
root secret --Shamir over the policy tree--> per-attribute leaf ciphertexts
K_E --Shamir 3-of-4--> shares x=1 (custodian), 2 (home auth.), 3,4 (audit)
```

Ciphertext expansion is a **constant 16 bytes (the GCM tag)**: 25 % at 64 B, 6.25 %
at 256 B, 1.56 % at 1 KiB, 0.39 % at 4 KiB, **0.098 % at 16 KiB**. It excludes
everything stored beside the payload: the 12-byte nonce, **two 48-byte DEK
wrappings**, the compiled policy, a **66-byte share per x** and the search index.

## 4. State machine

`src/lifecycle/state_machine.py`. States `granted`, `revoked`, `emergency_open`,
`expired`. **Seven** legal pairs (frozen set):

```
granted -> revoked        granted -> emergency_open     revoked -> emergency_open
revoked -> granted (legal, never emitted)
emergency_open -> expired
expired -> granted        expired -> revoked (ADR-0058)
```

Each move builds a signed `TransitionEvent` (domain-tagged, length-prefixed);
`event_id` is single-use (durable consumed store); the record store adds a
**compare-and-set** on the stored state (ADR-0050). Apply order: **signature →
legality → from-state matches current → consume id**. History in
`transition_events`, current state in `lifecycle_state`.

**Expiry** (`lifecycle/expiry.py`, ADRs 0035/0058/0069/0081): timer key (a fresh
one per facility process) signs `emergency_open → expired`, a **full rotation** runs
(`lifecycle/rotation.py`), new shares are deposited, then the timer signs the return
to the prior state. Monitor sweeps every 0.5 s; failures retry with backoff capped
at 60 s; the session row persisted at open holds identifiers only; startup recovery
reloads open/expired records as keyless sessions that expire on the next sweep.
Deployed window **14,400 s**; library default 60 s.

## 5. Break-glass protocol (3-of-4)

1. **Assertion** (`breakglass/assertion.py`, ADR-0032): fields `assertion_id,
   patient_id, clinician_id, facility_id, reason_code (enum of 13), issued_at,
   expires_at, nonce, clinical_context_digest, signature`. The custodian requests a
   **120 s** assertion by default and refuses more than 15 minutes.
2. **Shares 1 / 2.** Custodian presents share 1 from memory; if it has none, it asks
   the **home authority** for share 2 first (the authority runs the same validation).
3. **Shares 3 and 4** (`audit_service`, `POST /breakglass/release`): `check_release_
   assertion`; verify the gate recipient's key statement; build the log event; append
   the entry in **one transaction**; only then seal shares 3 and 4 (KEM, AAD record+x+
   recipient) and return them with the signed entry. Failure → **503, no share**.
   Code: `audit/share_custody.py`, `api/share_release.py`.
4. **Unlock** (`POST /records/{id}/breakglass` at the facility): open sealed shares;
   validate the assertion; load the record; **patient binding** (ADR-0044); clinical
   context; if already open → **join** (ADR-0057); else check/verify the transition
   event; compare-and-set the state; apply the event; run the gate (`gate.py`: needs
   3 distinct x); log the **re-wrap before** delivering the DEK; KEM-deliver the DEK
   to the clinician; register the expiry session.
5. **Search** (`POST /records/{id}/emergency-search`): tokens by HKDF from the
   emergency key; valid only while a live session exists.

Share holders: 1 = custodian, 2 = home authority (`authority-net`, reserved),
3 and 4 = audit service. **Any three with distinct x rebuild `K_E`; every such set
contains an audit share by placement**, not by a gate check (ADR-0089, supersedes
ADR-0074).

## 6. Processes and ports

| Process | Port | Role |
|---|---|---|
| store | (Postgres; host port 55433 in Compose) | ciphertext, wrapped keys, coded index, log. Never plaintext |
| facility-a / facility-b | 8001 / 8002 | facility nodes (`api/hospital.py`); hold **no records** |
| authority-med / authority-net | 8010 / 8011 | attribute authorities; `authority-net` is the home authority holding share 2 |
| audit | 8020 | hash chain + shares 3, 4 (`api/audit_service.py`) |
| custodian | 8030 | persona key agent + share 1 (`api/custodian_service.py`, ADR-0043) |
| portals | 8000 | Django: `/patient/`, `/clinician/`, `/oversight/` |

All service URLs come from config (`CUSTODIAN_URL`, `AUDIT_SERVICE_URL`,
`FACILITY_URLS`, `AUTHORITY_URLS`). Docker Compose publishes every port on
`127.0.0.1` only; the store password comes from the git-ignored `deploy/.env`
(ADR-0047). The portal runs with `DEBUG` off and fixed `ALLOWED_HOSTS`.

**Trust boundary on every call** (ADR-0066): a root-issued service certificate and
a signed one-time request envelope are checked **before any route code runs**;
key-bearing facility routes admit only the custodian or bootstrap.

**TLS profile.** `TLS_ENABLED=true` upgrades every federation URL to HTTPS.
`python -m wire.tls` writes per-service keys and a trust bundle; clients verify
against the bundle. TLS on the store link too (ADR-0071). Self-signed, server-only.

**Bootstrap and restarts.** Bootstrap writes `deployment_bootstrap` only after
seeding and chain verification succeed. A rerun re-checks and refuses a partial
bootstrap, a changed seed mode or a restarted key service with a recovery
instruction: recreate the whole demo. `run_migrations(reset=True)` refuses any
non-loopback database host.

## 7. API surface

**Facility node** (`api/hospital.py`): `GET /health`, `POST /records/ingest`,
`POST /records/{id}/read`, `POST /records/{id}/revoke`,
`POST /records/{id}/breakglass`, `POST /records/{id}/emergency-search`,
`GET /records/{id}/lifecycle`, `GET /patients/{id}/records` (discovery),
`POST /search/records`, `POST /consent/grants`.

**Audit service**: `GET /health`, `GET /public-key`, `GET /chain/head`,
`GET /chain/verify`, `POST /entries`, `PUT /breakglass/shares/{share_key}` (deposit),
`POST /breakglass/release`.

**Authority service**: `GET /health`, `GET /public-key`, `GET|PUT /certificate`,
`POST /credentials/{verify,status}`, `POST /credentials/{serial}/revoke`,
`POST /attribute-keys/release`, `POST /attribute-keys/author`, and, as home
authority, `PUT /breakglass/shares/{share_key}` and `POST /breakglass/release`
(share 2).

**Key Custodian**: `GET /health`, `PUT /trust`, `POST /subjects/{id}/material`,
`GET /subjects/{id}`, `GET /subjects/{id}/public-key`,
`POST /subjects/{id}/consent/{request|decide|revoke}`, `POST /subjects/{id}/read`,
`POST /subjects/{id}/revoke`, `POST /subjects/{id}/breakglass`,
`POST /subjects/{id}/records`, `POST|PUT /records/{id}/shares`.

## 8. Data model

**Store tables** (`src/storage/migrations/0001` to `0006`): `authorities`,
`facilities`, `patients`, `attributes`, `records`, `dek_wrappings`,
`lifecycle_state`, `transition_events`, `audit_log`, `search_index`; consumed ids;
compiled policies, consent requests and grants, `deployment_bootstrap`; clinical
metadata (record labels, readable in the store: ADR-0064); service-auth and rotation
state; emergency sessions (identifier rows with **no key**). No plaintext keys or
unencrypted shares.

**Portal tables** (Django, schema `portal`): `Profile`, `RegistrationRequest`,
`PatientDirectory` (name + DOB; PII lives only here), `ConsentRecord` (a display
mirror that no read path consults), `BreakglassCase`, `PatientNotification`.

The portal's database roles cannot write store tables (`portal/sql/roles.sql`).
Anything needing a key goes to the custodian by `subject_id`. **Caveat:**
federation services connect to Postgres as the `postgres` superuser; only the portal
is role-restricted.

## 9. Audit events you will see

`patient.lookup` (hit/miss/selection), `consent.decision`, `access_granted`,
`access_denied` (with `denied_by`: policy, assertion, patient-binding, clinical
context), `federation.discovery`, `breakglass_share_released` (with `unlock_path`),
`federation.rewrap`, `patient.notification`, timer `lifecycle_transition`s. Events
share a `correlation_id` so one emergency can be traced on
`/oversight/trace/?cid=...`.

## 10. Request authorisation order

`ARCHITECTURE.md` §8: **endpoint authorisation runs first, cryptographic
authorisation second.** The endpoint checks that this caller may ask; the policy
engine then decides whether a key can be rebuilt. Both must pass (claim C9: an
unauthorised caller is denied before any crypto or DB work).

## 11. Repository layout

```
src/        crypto_core shamir pre storage identity authority policy records
            lifecycle audit breakglass search federation consent api contracts custodian
portal/     Django: accounts patient clinician admin_audit ledger portal_core
deploy/     docker-compose, bootstrap, run_local, run_portal_demo, run_scenario
demo/       seed_data (synthetic personas and records), driver
wire/       capture, tls, analyze_traffic, checks, canaries (Module 7)
tests/      mirrors src/, plus security/ (negative tests) and e2e/ (hand-run)
bench/      evaluation harness and results (benchmark_summary.csv, environment.json)
paper/      the IEEE paper (sections/, tables/, figures/, data/, notes/)
docs/       adr/ (decision log), threat-model, explainers/
```

One owner per `src/` module (`CONVENTIONS.md` §3); `src/contracts/` is frozen
after Phase 0 and changes only by a contract PR approved by all four.

## 12. Testing

| Kind | Where | Command |
|---|---|---|
| Unit + negative security | `tests/`, `tests/security/` | `python -m pytest tests -q` |
| Needs Postgres | storage, audit, deploy, demo suites | set `DATABASE_URL` first |
| Claims table | `tests/security/claims.py` | `python -m tests.security.claims --table` |
| Mutation check | `tests/security/mutations.py` | `python -m tests.security.mutations` |
| Portal | `portal/*/tests.py` | `cd portal; python manage.py test --settings=config.test_settings` |
| Format / lint (as CI) | `src/`, `tests/` | `black --check src/ tests/`, `ruff check src/ tests/` |

A control is not finished until it has a negative test proving it fails closed.
**Numbers (paper, commit `57a1a8c`, run 2026-10-21):** full suite against Postgres
**1006 passed, 2 skipped, 0 failed**; **53 claim-tagged tests** (35 system-level +
18 module-level); **C1 to C11 all hold**; **18 mutations** cover C1 to C10.

## 13. Decision log

`docs/adr/README.md` is the tracker (**89 ADRs**, 0001 to 0089; many are still
*Proposed* and the paper notes this). The ones most worth knowing:

| ADR | Decision |
|---|---|
| 0001 / 0002 | Reject Charm-Crypto; policy tree over Shamir instead of CP-ABE |
| 0003 | Simulated HSM timer |
| 0011 | One shared semi-trusted store |
| 0014 | Web portals and Postgres store data, never decide access |
| 0016 | Patient self-access as an `owner:` attribute |
| 0030 | State machine transition table |
| 0031 | Consent as a read-time gate |
| 0032 | Emergency assertion and anti-replay |
| 0033 / 0085 | Emergency identification by name + DOB; no name/DOB in the chain |
| 0034 / 0035 | Audit chain with log-before-release; time-boxed expiry |
| 0036 / 0069 / 0080 | Revocation and expiry as full rotation |
| 0043 | Key Custodian and portal integration |
| 0044 | Break-glass patient binding |
| 0045 / 0046 | Wire-claim checks; claim registry with strict xfails |
| 0050 | Lifecycle state compare-and-set |
| 0058 | Expiry restores the pre-emergency state (adds Expired→Revoked) |
| 0066 / 0067 | Signed service requests; audit validates the assertion |
| 0068 | Clinician-signed break-glass transition |
| 0073 | Claim 1 scoped to TLS |
| 0076 | PRE is bidirectional |
| 0079 | Shares travel sealed |
| 0081 / 0083 / 0084 | Restart/crash recovery; audit high-water mark; patient-only revocation |
| 0087 / 0088 / 0089 | Paper toolchain; novelty is the combination; weighted 3-of-4 |
