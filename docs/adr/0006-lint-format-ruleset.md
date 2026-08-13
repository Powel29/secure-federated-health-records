# ADR-0006: Lint/format ruleset that enforces the crypto conventions in CI

- **Status:** Proposed (needs Nandini's sign-off as T05/CI owner)
- **Date:** 2026-08-12
- **Deciders:** Powel (proposed) → Nandini (T05)
- **Task / source:** T01, ratified under T05
- **Affects:** `pyproject.toml` `[tool.ruff]`; every PR once CI enforces it

## Context

Ruff's default rule set is only pyflakes plus a few syntax checks. Two
CONVENTIONS §2 rules are mechanically checkable but were unenforced: rule 2
(never `random` for security → `S311`) and rule 7 (no f-string SQL → `S608`).
§1 also requires type hints on public functions (`ANN`).

## Decision

`select = ["E", "W", "F", "I", "B", "S", "ANN"]`, with
`ignore = ["ANN101", "ANN102"]` (annotating `self`/`cls` is deprecated in ruff
and contradicts convention). Per-file ignores let tests `assert` (S101) and hold
fixed test-only vectors (S105/S106). black at line length 88, target py311.

## Consequences

- The crypto rules that can be caught by a linter are caught from the first
  commit, not in review. Verified: a probe using `random.randint` and f-string
  SQL trips `S311` and `S608`.
- `ANN` will reject un-annotated public functions repo-wide — intended by §1,
  but everyone feels it immediately. This is why sign-off sits with the CI owner.

## Alternatives considered

- **Ruff defaults** — miss the two enforceable crypto rules. Rejected.
- **A dedicated security linter (bandit)** — `S` rules already are bandit,
  inside the tool we run. No second tool needed.
