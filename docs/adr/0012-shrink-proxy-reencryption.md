# ADR-0012: Shrink proxy re-encryption to one-direction re-wrap

Status: Accepted (2026-08-18)

## Context
PRE was scoped as cross-facility key handoff (hospital A → hospital B). Under one
shared store (ADR-0011) records never move between facilities, so that handoff
has no job.

## Decision
Keep PRE, but reduced to a single direction: re-wrap a record key to the
**emergency clinician** during break-glass, without decryption. Drop the
facility-to-facility framing.

## Consequences
- T13 reduced 12h → 7h (one-direction primitive only).
- T29 (standalone cross-facility handoff, 10h) removed; ~2h absorbed into T24
  (break-glass now carries the re-wrap-to-clinician step).
- ~13h drops from the total (Option A: not reallocated).
- The paper's PRE claim narrows to "re-wrap to emergency clinician without
  decryption" — more honest under one store than claiming cross-facility handoff.
- PRE remains a demonstrated course topic.
