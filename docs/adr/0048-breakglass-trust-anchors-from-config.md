# ADR-0048: Break-glass trust anchors come from facility configuration

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** Avaneeth (implementer) → Powel (breakglass), Ojas (deploy) → all four
- **Task / source:** Review `docs/review/2026-10-07-fix-proposals.md` F1; ARCHITECTURE.md §5 (cross-facility break-glass step 1), §7 (bootstrap), §8
- **Affects:** `api/hospital.py` (`FacilityTrust`, break-glass handler), `api/schemas.py` (`BreakglassUnlockRequest`, `extra="forbid"`), `breakglass/assertion.py` (`revoked_serials`, chain errors), `deploy/asgi/facility.py` (`load_trust`), `deploy/bootstrap.py` (`write_trust_bundle`, `save/load_federation_pki`, `facility_trust`), new `deploy/compose_pki.py`, `deploy/docker-compose.yml` (`pki` job, facility mounts), `deploy/run_local.py`, `api/custodian_service.py` (stops sending PEMs), `deploy/run_scenario.py`, `demo/driver.py`, `bench/run_benchmarks.py`

## Context

The facility built the root and facility-CA certificates for break-glass chain
validation from the request body. Anyone could mint their own root, CA and a
`CN=doc-201` leaf, sign an assertion, and pass `validate_chain`. Chain errors
were also outside the handler's `except` list, so they surfaced as 500 with no
denial logged, and no clinician revocation check existed.

Loading trust at startup needs the PKI to exist before the facilities start.
Path A already generated it first; in Compose the bootstrap job runs after
every service is healthy.

## Decision

- The facility gets a `FacilityTrust` (federation root, facility CAs by id,
  revoked clinician serials) at construction. It picks the intermediate by
  matching the clinician certificate's issuer to a configured CA subject; an
  unknown issuer, a broken chain, an expired or revoked certificate is a 403
  with one denial entry. Without trust anchors break-glass returns 503.
- `BreakglassUnlockRequest` forbids extra fields, so a caller still sending
  `trusted_root_certificate_pem` / `facility_ca_certificate_pem` gets 422.
- `validate_emergency_assertion` takes a required `revoked_serials` and
  reports a link whose signature fails as `ChainValidationError`, keeping
  `InvalidSignatureError` for a tampered assertion.
- Deployment: `FEDERATION_ROOT_CERT` and `FACILITY_CA_CERTS_DIR` name the
  files; the facility refuses to start without them. Path A writes them at
  bootstrap step 2. Compose gains a one-shot `pki` job that generates the PKI
  before the facilities, writes certificates only to `deploy/pki/trust/` (the
  one directory facilities mount) and the private keys to
  `deploy/pki/federation-pki.json` (read by the bootstrap job only).

## Consequences

- Minting a private PKI no longer opens records; the C-claims about the
  emergency assertion now rest on the federation's PKI.
- The root private key now sits on disk (git-ignored `deploy/pki/`) between
  the `pki` and `bootstrap` jobs, next to the facility CA keys that
  `federation.json` already held. Same exposure class, stated here.
- Re-running `docker compose up` on a running stack regenerates the PKI files
  while running facilities keep the old anchors; bootstrap already says to
  recreate the whole stack, and a mismatch fails closed (403).
- Revocation is a static serial list from config; there is no CRL/OCSP.

## Alternatives considered

- **Read trust from the shared store's registry** — the store is
  honest-but-curious; anything that can write it could plant a CA.
- **Lazy-load the files on first break-glass** — keeps the old Compose order
  but a missing or late file fails on a request instead of at startup.
