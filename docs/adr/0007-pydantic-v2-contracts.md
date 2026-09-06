# ADR-0007: Pydantic v2 for the contract schemas

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-08-12
- **Deciders:** Powel (proposed) → all four (CONVENTIONS §3 freeze)
- **Task / source:** T02
- **Affects:** `src/contracts/` (all nine schemas); every module that imports them

## Context

`src/contracts/` holds the shared schemas that freeze after Phase 0 and that
every module and both service boundaries consume. The modeling choice is
inherited by the whole codebase and cannot be swapped cheaply after the freeze.

## Decision

Model contracts as **pydantic v2** `BaseModel`s. Pydantic is already a pinned
dependency (via FastAPI), the API layer consumes these as JSON directly, and we
get validation, enum handling, and wire serialization for free. Base config:
`frozen=True` (a signed struct must not mutate), `extra="forbid"` (unknown fields
fail closed, not silently dropped), and `bytes` fields serialized as base64 in
JSON via a shared `B64Bytes` type. Timestamps use `AwareDatetime` so naive
datetimes are rejected. No contract computes crypto (CONVENTIONS §2 rule 1).

## Consequences

- Boundary validation and fail-closed structural checks come with the type;
  79 contract tests pass.
- Couples contracts to pydantic v2 semantics — acceptable, since FastAPI already
  couples the whole system to it.
- `frozen=True` makes instances immutable and hashable; mutation raises.

## Alternatives considered

- **Stdlib `@dataclass`** — no validation, manual JSON/bytes handling, and
  FastAPI would wrap them in pydantic anyway. Rejected.
- **Plain `TypedDict`/dicts** — no runtime enforcement of the invariants that
  are the point of a frozen contract. Rejected.
