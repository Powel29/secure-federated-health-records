"""Deployment orchestration (P4-3, C14, ARCHITECTURE.md §7).

Not part of the installed ``src/`` package (see ``pyproject.toml``'s
``[tool.setuptools.packages.find]``) -- this directory is run in place, from
the repository root, exactly like ``bench/`` and ``demo/`` (ARCHITECTURE.md
§6). ``deploy/run_local.py`` and ``deploy/compose_bootstrap.py`` add
``src/`` to ``PYTHONPATH`` (or rely on the dev install's ``-e .``) so the
modules under here can still ``from api... import ...`` freely.
"""
