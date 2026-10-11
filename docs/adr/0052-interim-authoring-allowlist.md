# ADR-0052: Interim address allowlist on `/attribute-keys/author`

- **Status:** Proposed (exit-plan item F14-i lists the trust boundary as Ojas's decision; this records the interim chosen so the hole is not left open)
- **Date:** 2026-10-11
- **Deciders:** Avaneeth (implementer) → Ojas (authority, deploy trust boundary) → all four
- **Task / source:** Review F14 (interim), exit plan F14-i; ADR-0026 (one key per attribute)
- **Affects:** `api/authority_service.py` (`authoring_callers`), `deploy/asgi/authority.py` (`AUTHORING_CALLERS`), `deploy/docker-compose.yml`, `tests/api/conftest.py` (`FromHost`)

## Context

`/attribute-keys/author` returned, with no authentication at all, the very key
`/attribute-keys/release` gates behind a credential (ADR-0026). One POST for
`owner:pat-101` was enough to read every one of that patient's records.
Signed service requests (D5-a) are the real fix and wait on a decision.

## Decision

The authority answers `/attribute-keys/author` only for callers whose address
is on an allowlist: loopback by default; in Compose `AUTHORING_CALLERS`
defaults to `custodian,bootstrap` (hostnames resolved per request, literal
matches checked first). Everything else gets 403 with no key.

## Consequences

- The open endpoint is closed to anyone outside the allowlist; allowlisted
  authoring services are trusted parties by construction (ADR-0026), which is
  what C10's test now states.
- As the exit plan warns, host-run `run_scenario` / `seed_data` against the
  Compose stack reach the authorities from the bridge gateway, not loopback;
  they need that address added to `AUTHORING_CALLERS`.
- An address is not an identity; anything that can send from an allowed
  address can author. D5-a replaces this.

## Alternatives considered

- **Leave it open until D5** — the review rates it HIGH; one request reads a
  patient's records.
- **Shared secret header** — another secret to distribute and leak, for the
  same interim value.
