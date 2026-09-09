"""ASGI application factories, one module per service role (P4-3).

Each module exposes a zero-argument ``app()`` factory reading its own
configuration from the environment, so the exact same factory can be handed
to ``uvicorn --factory`` (or ``uvicorn.run(..., factory=True)``) whether the
process was launched as a local subprocess (Path A,
``deploy/run_local.py``) or as a Docker container (Path B,
``deploy/Dockerfile`` + ``deploy/entrypoint.py``).
"""
