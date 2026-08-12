# ADR-0004: Python src-layout, bare-name imports, editable install

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** Powel (T01 owner)
- **Task / source:** T01
- **Affects:** every module and test in the repo; `pyproject.toml`, `requirements-dev.txt`, `README.md`

## Context

The scaffold left no working import path: a fresh clone could not `import`
anything, and the spelling of imports (`from contracts import X` vs
`from src.contracts import X`) gets baked into every file and is miserable to
change later. It is also T05's "CI green on empty suite" precondition.

## Decision

Use a `src/` layout. Packages are importable by their **bare names**
(`from contracts import Record`), not under a `src.` prefix. Achieved by
`[tool.setuptools.packages.find] where = ["src"]` plus `-e .` in
`requirements-dev.txt`; pytest also sets `pythonpath = ["src"]` so the suite runs
from a clean clone before any install.

## Consequences

- One canonical import spelling across the codebase; verified working with and
  without the editable install.
- Everyone installs via `requirements-dev.txt`, which pulls in `-e .`.
- Ties us to setuptools src-layout discovery; fine for this project's size.

## Alternatives considered

- **`from src.contracts import ...`** — leaks the layout into every import and
  breaks if the package is ever installed properly. Rejected.
- **Flat layout (packages at repo root)** — pollutes the root and invites
  accidental imports of test/config modules. Rejected.
