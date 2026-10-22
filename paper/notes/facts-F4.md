# Facts F4 — System architecture: processes, ports, trust boundaries, PKI/TLS

Extracted 2026-10-21 against HEAD `57a1a8c` (branch `paper/ieee-draft`).
Precedence: code (`src/`, `deploy/`, `wire/`, `portal/`) > ARCHITECTURE/ADRs >
`docs/federation-topology.md`. "Proposed" ADRs are design choices of this
build, not ratified decisions. Cite as `% src: facts-F4#N`.

## Processes and ports

1. The federation is **simulated** on one machine: two facilities
   (`facility-a`, `facility-b`), two attribute authorities (`authority-med`,
   `authority-net`), one audit service, one Key Custodian, one PostgreSQL
   store, and one Django process serving the three portals. All run as local
   processes (Path A) or as Docker Compose containers on one bridge network
   (Path B); nothing is an external HIE. — `deploy/run_local.py:47-50,82-156`;
   `deploy/docker-compose.yml:30-409`; `docs/adr/0019-federation-topology-and-attributes.md` (Status: Accepted)
2. HTTP service ports (fixed in code): `facility-a` 8001, `facility-b` 8002,
   `authority-med` 8010, `authority-net` 8011, `audit` 8020, `custodian` 8030.
   — `deploy/run_local.py:47-50`; `wire/tls.py:22-29`;
   `deploy/docker-compose.yml:97-98,141,183,221,267,313`
3. All six HTTP services are FastAPI apps run by uvicorn through one
   entrypoint that dispatches on `SERVICE_ROLE` ∈ {facility, authority, audit,
   custodian}; both deployment paths use this same entrypoint. —
   `deploy/entrypoint.py:1-20,28,63-71`; `deploy/run_local.py:159-169`
4. The `store` is PostgreSQL 16 (`postgres:16-alpine`), **not** an HTTP
   service: port 5432 inside the bridge, published on host loopback
   `127.0.0.1:55433` in Compose; Path A uses an externally started Postgres
   (README example host port 55432). Its data directory is a tmpfs, so every
   `up` starts an empty store. — `deploy/docker-compose.yml:31-50`;
   `deploy/README.md:30,36,72`; `deploy/run_local.py:9-18`
5. The three portals (patient, clinician, admin/audit) are one Django
   development server on port 8000, published only on `127.0.0.1:8000`, with
   `DJANGO_DEBUG=0` and `ALLOWED_HOSTS=127.0.0.1,localhost`. It is started
   after bootstrap succeeds. — `deploy/docker-compose.yml:374-406`;
   `deploy/run_portal_demo.py:108`; `deploy/seed_portal.py:278`;
   `docs/adr/0047-local-deployment-state-and-tls.md` (Status: Proposed)
6. Compose also runs three one-shot jobs: `migrate` (schema), `pki`
   (generates federation PKI with `network_mode: none`) and `bootstrap`
   (registration + seeding). Every published port binds to 127.0.0.1 only. —
   `deploy/docker-compose.yml:7-8,52-81,337-372`
7. Role of each process. Facilities hold **no records**: they read ciphertext
   from the shared store and run the policy engine and the threshold gate.
   Authorities issue attribute credentials and release attribute keys for
   their own namespace. The audit service keeps the hash-chained log and
   custody of break-glass shares 3 and 4. The custodian is every subject's key
   agent. — `ARCHITECTURE.md:388-398`;
   `docs/adr/0011-single-shared-store.md` (Status: Accepted);
   `src/breakglass/emergency_key.py:1-17`
8. Attribute-namespace ownership is configured per authority:
   `authority-med` owns `role`; `authority-net` owns `specialty`, `facility`,
   `owner`. Issuance outside the owned namespace raises
   `UnauthorizedAttributeError`. — `deploy/docker-compose.yml:103,146`;
   `deploy/run_local.py:93-97`;
   `docs/adr/0024-single-root-cross-certification.md:81-87` (Status: Accepted)
9. Patient discovery is a patient-indexed lookup in the single shared store
   (`SELECT record_id FROM records WHERE patient_id = %s`), not a
   cross-facility search. — `src/federation/discovery.py:18-26`;
   `docs/adr/0011-single-shared-store.md` (Status: Accepted)

## Trust boundaries and who holds / signs what

10. The emergency key is a weighted Shamir 3-of-4 split: x=1 clinician custody
    (held by the custodian), x=2 the patient's home authority (issuer of the
    `owner` credential), x=3 and x=4 the audit service. Every reconstruction
    therefore includes the audit service; custodian + home authority (two
    points) cannot open a record. — `src/breakglass/emergency_key.py:1-17,29-30`;
    `docs/adr/0089-weighted-3-of-4-breakglass.md` (Status: Proposed)
11. Because only `authority-net` owns `owner:*` in the shipped config, in
    practice `authority-net` is the home authority holding share 2 for every
    seeded patient; the custodian finds the home authority from the issuer of
    the patient's `owner` credential. — `deploy/docker-compose.yml:146`;
    `src/api/custodian_service.py:406-427`
12. Break-glass at the custodian: share 1 from its vault is used; only if
    share 1 is missing does it ask the home authority for share 2. Shares are
    sealed to the declaring facility's gate, so the custodian never holds
    three points in the clear; the audit service releases shares 3 and 4 only
    after it validates the assertion and commits its log entry. —
    `src/api/custodian_service.py:1448-1580`;
    `src/api/audit_service.py:379-440`;
    `docs/adr/0079-shares-travel-sealed.md` (Status: Proposed);
    `docs/adr/0067-audit-validates-assertion.md` (Status: Proposed)
13. The audit service verifies the whole chain at startup (writing a genesis
    entry if empty); any break aborts startup, and in Compose every writer
    waits for audit to be healthy. — `src/api/audit_service.py:190-213`;
    `deploy/docker-compose.yml:16-18,214-215`
14. The Key Custodian (port 8030) is **one** process standing in for every
    subject's personal key agent: it holds each persona's signing key,
    certificate, PRE keypair and issued credentials plus share 1 per record,
    in memory; it signs consent artifacts, emergency assertions, revocation
    transitions and record labels on a subject's behalf and "decides nothing".
    A memory dump of it yields every deposited key — the largest trust
    concentration, to be stated as a limitation. —
    `src/api/custodian_service.py:180-192`;
    `docs/adr/0043-key-custodian-and-portal-integration.md:37-51,94-102` (Status: Accepted)
15. Route permission tables restrict which **service kind** may call each
    route. Key-bearing facility routes (`/records/{id}/read`, `/revoke`,
    `/breakglass`, `/records/ingest`, `/search/records`) accept only
    `custodian` or `bootstrap`; the portal may call only grant submission,
    discovery and emergency search at a facility. Attribute-key release and
    share release at authorities/audit accept only `custodian`/`bootstrap`. —
    `src/api/hospital.py:205-218`; `src/api/authority_service.py:139-161`;
    `src/api/audit_service.py:109-113`; `src/api/custodian_service.py:145-160`
16. Every service-to-service call carries the caller's root-issued service
    certificate (`X-Service-Certificate`) and a signed one-time
    `RequestEnvelope` (`X-Request-Envelope`) binding caller, recipient,
    method+path, body, time and nonce. The callee checks chain, caller id,
    binding, freshness (max age 120 s, skew 30 s), signature and an unused
    `request_id` before any route code runs; failure is 401, a disallowed
    kind is 403. — `src/api/service_auth.py:1-28,337-378,412-470`;
    `src/breakglass/envelopes.py:37-38`; `src/contracts/messaging.py:76-102`;
    `docs/adr/0066-signed-service-requests.md` (Status: Proposed)
17. Service identities issued at bootstrap: `authority-med`, `authority-net`
    (kind authority), `audit-service` (audit), `facility-a`, `facility-b`
    (facility), `custodian`, `portal`, `bootstrap`. Each container mounts only
    its own `pki/services/<id>` directory plus the public `pki/trust`. —
    `deploy/bootstrap.py:80-89,209-229`; `src/identity/certificates.py:35-41`;
    `deploy/docker-compose.yml:13-17`
18. No facility request model accepts a private key or a DEK; revocation is
    signed with the patient's key inside the custodian and the facility only
    verifies it. Enforced by a schema test. —
    `tests/api/test_revoke.py:267` (`test_no_facility_request_takes_a_private_key_or_dek`);
    `docs/adr/0072-no-private-key-or-dek-in-facility-requests.md` (Status: Proposed)

## What portals and Postgres may NOT do (ADR-0014)

19. Rule: portals and Postgres "store data and identify users; they never
    decide access"; Django login answers who is asking, not whether anything
    may be decrypted. — `docs/adr/0014-web-portals-and-postgres.md:28-34` (Status: Accepted);
    `ARCHITECTURE.md:118-123`
20. Enforcement 1 — the portal holds no subject key. Every key-needing action
    goes to the custodian by `subject_id`; the portal's own service key
    identifies the portal process only and opens nothing. —
    `portal/portal_core/services.py:1-18,115-245`; `ARCHITECTURE.md:561-563`
21. Enforcement 2 — a portal account alone grants zero access: a subject with
    no deposited material gets 404 from the custodian and nothing decrypts. —
    `tests/api/test_custodian_service.py:523` (`test_unknown_subject_is_404_everywhere`);
    `docs/adr/0043-key-custodian-and-portal-integration.md:52-57`
22. Enforcement 3 — Postgres roles: Django's default connection is
    `portal_app`, which owns only the `portal` schema and has all store-table
    privileges revoked; the portal's store alias is `portal_ro`, SELECT-only.
    Negative test: `test_portal_default_connection_cannot_write_store_tables`.
    — `portal/sql/roles.sql:1-55`; `portal/config/settings.py:80-98`;
    `tests/security/test_portal_roles.py:57`;
    `docs/adr/0053-portal-identity-hardening.md` (Status: Proposed)
23. Enforcement 4 — consent state mirrored in the portal DB is display data
    only; no read path consults it, and a forged ledger row cannot pass the
    facility's grant-signature check. —
    `docs/adr/0043-key-custodian-and-portal-integration.md:58-62`
24. Enforcement 5 — store-held clinical labels cannot loosen access: unsigned
    or mis-signed labels get the strictest disclosure rules. —
    `docs/adr/0064-patient-certificates-and-signed-labels.md:37-43` (Status: Proposed)
25. The store holds ciphertext, wrapped keys, the coded search index and the
    audit chain (`audit_log`), never plaintext or unwrapped keys. —
    `ARCHITECTURE.md:56-58,392`; `docs/adr/0011-single-shared-store.md:20-22`
26. Caveat: federation services (facilities, authorities, audit, custodian,
    bootstrap) all connect to the store as the `postgres` user; only the
    portal is confined by DB roles. — `deploy/docker-compose.yml:101,144,184,225,271,314,359`

## PKI

27. Single hierarchical root, not a peer mesh: one self-signed root (CN
    `federation-root`, 3650 days) signs every facility CA, every authority
    certificate and every service certificate. "Cross-certification" of the
    facilities is the consequence of both CAs chaining to the same root; there
    is no direct facility-to-facility cross-signature. —
    `src/identity/root_anchor.py:18-19,36-66`; `deploy/bootstrap.py:174-206`;
    `docs/adr/0024-single-root-cross-certification.md:32-66` (Status: Accepted)
28. Certificate types and lifetimes: facility CA (root-signed, 3650 d);
    attribute authority (root-signed, 3650 d); clinician (facility-CA-signed,
    365 d, no OU); patient (home-facility-CA-signed, 365 d, OU `patient`);
    service (root-signed, 365 d, OU `service:<kind>`, CN = service id).
    Attribute credentials default to 365 d. —
    `src/identity/certificates.py:25-41,83-260`; `src/authority/issuance.py:40`
29. Algorithms: ECDSA on P-256 (SECP256R1) with SHA-256 for all keys,
    certificates and signatures. — `src/crypto_core/asymmetric.py:1,27,45,68`;
    `src/crypto_core/x509_certs.py:90,147`
30. Chain validation walks to a caller-configured `trusted_root` and fails
    closed on a bad signature, expired window, non-CA intermediate or
    issuer/subject mismatch; facilities load the root and facility CA certs
    from config at startup and refuse to start without them, never taking
    them from a request. — `docs/adr/0024-single-root-cross-certification.md:38-44,67-73`;
    `deploy/asgi/facility.py:69-81`; `deploy/docker-compose.yml:68-72`
31. The root private key is held only by the bootstrap step (Compose `pki`
    job writes `federation-pki.json`, read only by `bootstrap`); keys and certs
    live under git-ignored `deploy/pki/`. Single point of trust: a compromised
    root invalidates the whole PKI. — `src/identity/root_anchor.py:22-29`;
    `deploy/docker-compose.yml:68-81`;
    `docs/adr/0024-single-root-cross-certification.md:60-66`
32. Credential lifecycle: each authority keeps its own revocation registry;
    verification order is signature, static status, revocation lookup, then
    validity window; a revoked/expired credential releases no attribute key.
    — `docs/adr/0028-credential-lifecycle-and-revocation-registry.md:21-42` (Status: Accepted)

## TLS / transport profiles

33. Two profiles chosen by one env var, `TLS_ENABLED` (default false):
    `capture-plain` (plain HTTP, the primary evidence profile) and
    `capture-tls`. When on, every federation URL is rewritten to `https://`
    and the process trusts a bundle of the generated certificates; a missing
    bundle is a startup error. — `deploy/config.py:44-46,80-105`;
    `wire/capture.py:5-7,241-243`; `ARCHITECTURE.md:471-477`
34. TLS server certificates are separate from the federation PKI: `python -m
    wire.tls` makes one self-signed EC certificate per HTTP service (SANs
    name, `localhost`, `127.0.0.1`; 90 days) and a trust bundle of exactly
    those certificates; verification is never disabled. TLS is server-auth
    only (uvicorn gets cert+key; no client certificates); caller identity
    comes from the signed envelope (fact 16). No TLS version or cipher suite
    is configured for the HTTP services (library defaults). —
    `wire/tls.py:22-80`; `deploy/entrypoint.py:52-71`;
    `docs/adr/0047-local-deployment-state-and-tls.md:28-31,54-58`
35. In the TLS profile the facility-store link is also encrypted: every
    Postgres client uses `sslmode=verify-full` against `trust/store.crt`
    (a DSN asking for a weaker mode is refused), and the store sets `ssl=on`,
    `ssl_min_protocol_version=TLSv1.3` and `hostnossl … reject`. The plain
    profile leaves the store link plaintext. — `deploy/config.py:49-77`;
    `deploy/store-entrypoint.sh:5-44`;
    `docs/adr/0071-tls-on-the-store-link.md` (Status: Proposed)
36. The browser-to-portal link stays HTTP on loopback in both profiles. —
    `docs/adr/0047-local-deployment-state-and-tls.md:70-72`;
    `deploy/docker-compose.yml:396-399`
37. Captures are allowed only on loopback or the Docker bridge. —
    `wire/capture.py:62-105`

## Deployment and bootstrap

38. Path A (`python -m deploy.run_local`) runs six service subprocesses with
    no Docker for the application (Postgres supplied separately); Path B is
    Compose. Keys are ephemeral: every start is a fresh federation. —
    `deploy/run_local.py:1-19,159-169`; `deploy/docker-compose.yml:20-23`;
    `docs/adr/0039-audit-authority-services-and-deployment.md` (Status: Accepted)
39. Bootstrap order in code: [1] migrations (reset only on a loopback DB);
    [2] root anchor + facility CAs + service identities; [3] authorities
    start and receive root-signed certificates; [4] audit starts (chain
    genesis/verify); [5] facilities start; [6] custodian starts; then registry
    population and synthetic seeding; [7] audit chain verified from genesis.
    — `deploy/run_local.py:213-298`; `deploy/bootstrap.py:388-420`
40. Seeding splits each record's emergency key: shares 3 and 4 to audit,
    share 2 to the home authority, share 1 to the custodian, and deposits
    each persona's key material at the custodian. —
    `deploy/run_portal_demo.py:18-22`

## Revocation and audit pseudonymity

41. Only the patient revokes in this build: the facility verifies a
    patient-signed `GRANTED -> REVOKED` event against a patient certificate
    and passes `owner_authority_id=""` ("authorities do not sign revocations
    here"); home-authority revocation is future work and a patient who cannot
    sign has no revocation path. — `src/api/hospital.py:1043-1124`;
    `docs/adr/0084-revocation-is-patient-only-in-this-build.md` (Status: Proposed)
42. The audit chain is pseudonymous, not anonymous: it holds no name or date
    of birth and names patients only by `patient_id`, which links to a person
    only through the portal DB; `query_hash` and `patient_id_hash` were
    removed. A chain reader learns which pseudonymous patient was accessed,
    by whom and when. — `ARCHITECTURE.md:536-542`;
    `docs/adr/0085-no-name-or-dob-in-the-chain-patient-id-is-the-pseudonym.md:45-64` (Status: Proposed)

## Figure

43. Component / trust-boundary figure (nodes and edges as shipped; every
    HTTP edge carries a service cert + signed one-time envelope, fact 16;
    HTTP edges become HTTPS and the Postgres edge becomes TLS 1.3 verify-full
    when `TLS_ENABLED`):
    - Nodes: Browser; `portal` (Django, :8000, 3 portals, no subject keys);
      `custodian` :8030 (all personas' keys, share 1); `facility-a` :8001;
      `facility-b` :8002 (policy engine + threshold gate, no records);
      `authority-med` :8010 (`role`); `authority-net` :8011 (`specialty`,
      `facility`, `owner`; share 2); `audit` :8020 (hash chain, shares 3+4);
      `store` (PostgreSQL :5432; ciphertext, wrapped keys, coded index,
      `audit_log`); offline `root` (bootstrap only).
    - Edges: Browser→portal (HTTP, loopback); portal→custodian (all
      key-needing actions, by `subject_id`); portal→facility-a/b (grant
      submission, discovery, emergency search); portal→audit (append, chain
      reads); portal→store (`portal_ro`, SELECT only); custodian→facility-a/b
      (`/read`, `/breakglass`, `/revoke`, `/ingest`); custodian→authorities
      (attribute-key release, share-2 release); custodian→audit (share 3+4
      release, sealed to facility gate); facility→audit (append, share
      replacement); facility→authorities (policy authoring at rotation);
      facility→custodian (rotated share 1); facilities/authorities/audit/
      custodian→store (Postgres); root⇢facility CAs, authority certs,
      service certs (signing, at bootstrap); facility CA⇢clinician and
      patient certs.
    — `deploy/docker-compose.yml:30-409`; `src/api/hospital.py:205-218`;
    `src/api/authority_service.py:139-161`; `src/api/audit_service.py:109-113`;
    `src/api/custodian_service.py:145-160`; `portal/portal_core/services.py:115-345`;
    `src/identity/certificates.py:83-260`

## Contradictions found

Code wins in every case.

- **C-1 Store port/protocol.** `ARCHITECTURE.md:392` (and ADR-0019 decision 1,
  `docs/federation-topology.md:38`) list `store` on port 8000 as a process.
  In code the store is PostgreSQL (5432; host 55433/55432), and port 8000 is
  the Django portal (`deploy/docker-compose.yml:43-44,396-397`).
  `ARCHITECTURE.md:400-401` puts the portals on 8000 as well, which collides
  with its own store row.
- **C-2 Process counts.** `ARCHITECTURE.md:388,415,419-420,476` say "five
  federation services", "all five uvicorn processes", "Five services in one
  docker-compose.yml", "between all five services". Code runs six uvicorn
  services (`deploy/run_local.py:82-156`, `wire/tls.py:22-29`), and Compose
  defines 11 services including the store, portal and three one-shot jobs.
  The `deploy/run_local.py:4` docstring also says "five".
- **C-3 federation-topology.md is stale.** It shows a 2-of-3 gate with audit
  holding share 3 only (lines 39, 96, 126, 146), no custodian, a direct
  `facility-a <-> facility-b` cross-certify edge (line 43), and root CN
  `FEDERATION-ROOT-CA` (line 26). Code: 3-of-4, audit holds 3 and 4
  (`src/breakglass/emergency_key.py:1-17`); custodian present; single-root
  hierarchy with no direct facility link (ADR-0024); root CN
  `federation-root` (`src/identity/root_anchor.py:19`).
- **C-4 Older ADR text on shares.** ADR-0019 consequences ("needs 2 of 3") and
  ADR-0043:124-125 ("Share 2 … never requested; threshold met by shares
  1 + 3") are superseded by the code: share 2 is the fallback when share 1
  is missing, and audit releases shares 3 and 4
  (`src/api/custodian_service.py:1448-1580`; ADR-0089, Proposed).
- **C-5 Envelope docstring.** `src/contracts/messaging.py:88-92` says the
  envelope is "not a separate service identity control" (ADR-0015). The
  service middleware now uses the envelope plus a root-issued service
  certificate as service identity with kind-based route permissions
  (`src/api/service_auth.py:1-28,412-470`; ADR-0066, Proposed). The
  frozen-contract docstring is out of date.
- **C-6 Two homes for authority share 2.** `ARCHITECTURE.md:395-396` says both
  authorities hold share 2 for patients whose `owner` credential they issued.
  ADR-0019 and federation-topology.md name `authority-net` alone. Code
  supports either (`src/api/custodian_service.py:406-427`), but only
  `authority-net` owns `owner` in config (`deploy/docker-compose.yml:146`).
  So in the shipped deployment it is `authority-net` only.
- **C-7 Key/cert location.** `ARCHITECTURE.md:449` says keys and certs land
  in `deploy/pki/`. The federation PKI does, but TLS certificates are written
  to `wire/certs/` (`wire/tls.py:83`; `deploy/docker-compose.yml:49,121-122`).

## Added by writers

44. Real HIE / FHIR / HL7 interoperability is explicitly out of scope: the
    federation is simulated with mock facilities and cross-certification, and
    standards-based interoperability is not implemented. — `PROJECT.md:452-454` (added by W2)
