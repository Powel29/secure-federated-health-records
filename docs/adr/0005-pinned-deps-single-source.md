# ADR-0005: Pin runtime dependencies once, in requirements.txt

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** Powel (T01 owner)
- **Task / source:** T01
- **Affects:** `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`

## Context

The scaffold declared dependencies twice: pinned in `requirements.txt`,
**unpinned** in `pyproject.toml`. Once anyone runs `pip install -e .`, the
unpinned set resolves and silently defeats the pins — the opposite of T01's
"pinned deps" requirement.

## Decision

`requirements.txt` is the single pinned source of truth. `pyproject.toml`
declares `dynamic = ["dependencies"]` and reads the same file via
`[tool.setuptools.dynamic]`. There is exactly one place versions live.

## Consequences

- No drift between the two files; the pins hold under both `pip install -r` and
  `pip install -e .`. Verified in a clean venv.
- Adding a dependency means editing `requirements.txt` only.
- `pyproject.toml` no longer reads as a standalone dependency list — the comment
  there points at `requirements.txt`.

## Alternatives considered

- **Pin in `pyproject.toml`, generate `requirements.txt`** — needs a lock tool
  (pip-tools) we chose not to add for a project this size.
- **Keep both, keep them in sync by hand** — guaranteed to drift. Rejected.
