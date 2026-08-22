# ADR-0013: Dashboard built as an early shell that grows per phase

Status: Accepted (2026-08-18)

## Context
The team wanted a visible UI from the start rather than watching terminals. A
full dashboard cannot exist early because it renders state that later phases
create.

## Decision
Build an empty four-pane dashboard **shell** in Phase 0 (T47), reading the real
schema read-only; populate the panes per phase as features land (T55). Ownership
kept off Powel's crypto critical path: T47 moved to Powel for Phase-0 balance
only, T55 (pane population) stays with Avaneeth.

## Consequences
- T11 (schema) moves to Phase 0 and gains WAL mode, so a live reader never blocks
  writers.
- Phase 0 exit criteria now include a running shell against a real (empty) schema.
- The shell is a debugging aid through Phases 1–3, not only a demo tool.
- Dashboard is read-only observability; it shows state, never actions, and holds
  no keys. Actions are driven by the CLI.
- Constraint accepted: at end of Phase 0 the panes are empty by design.
