"""Path A: local-process supervisor for the federation (P4-3, ARCHITECTURE.md §7).

No Docker required -- "keep it easy to install and run" (ARCHITECTURE.md
§1). Launches the five service processes as local subprocesses, all through
``deploy/entrypoint.py`` (the exact same entrypoint Path B's containers
use), waits for health, runs the bootstrap sequence, and tears everything
down together on Ctrl+C ("one command up, one command down").

Requires a reachable PostgreSQL at ``DATABASE_URL`` -- this script does not
start Postgres itself; see README.md "Database (PostgreSQL)" for a
throwaway ``docker run`` one-liner, or point at an already-installed local
instance. Path A's whole point is not requiring Docker for the *application*
processes; a local Postgres (or a single throwaway container just for the
database) is a different, much smaller ask.

Usage::

    DATABASE_URL=postgresql://postgres@localhost:55432/ehr python -m deploy.run_local
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from deploy import bootstrap

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
FEDERATION_CONFIG_PATH = REPO_ROOT / "deploy" / "pki" / "federation.json"

_AUDIT_PORT = 8020
_AUTHORITY_PORTS = {"authority-med": 8010, "authority-net": 8011}
_FACILITY_PORTS = {"facility-a": 8001, "facility-b": 8002}


@dataclass(frozen=True)
class ServiceSpec:
    """One subprocess to launch: its display name, role, port, and env."""

    name: str
    role: str
    port: int
    extra_env: dict[str, str]


def _default_specs(database_url: str, audit_base_url: str) -> list[ServiceSpec]:
    specs = [
        ServiceSpec(
            authority_id,
            "authority",
            port,
            {
                "AUTHORITY_ID": authority_id,
                "OWNED_ATTRIBUTES": (
                    "role"
                    if authority_id == "authority-med"
                    else "specialty,facility,owner"
                ),
            },
        )
        for authority_id, port in _AUTHORITY_PORTS.items()
    ]
    specs.append(
        ServiceSpec(
            "audit",
            "audit",
            _AUDIT_PORT,
            {"DATABASE_URL": database_url, "AUDIT_ACTOR_ID": "audit-service"},
        )
    )
    specs.extend(
        ServiceSpec(
            facility_id,
            "facility",
            port,
            {
                "FACILITY_ID": facility_id,
                "DATABASE_URL": database_url,
                "AUDIT_SERVICE_URL": audit_base_url,
            },
        )
        for facility_id, port in _FACILITY_PORTS.items()
    )
    return specs


def _spawn(spec: ServiceSpec) -> subprocess.Popen:
    env = {
        **os.environ,
        "SERVICE_ROLE": spec.role,
        "PORT": str(spec.port),
        **spec.extra_env,
    }
    env.setdefault("PYTHONPATH", str(SRC_DIR))
    return subprocess.Popen(
        [sys.executable, "-m", "deploy.entrypoint"], cwd=str(REPO_ROOT), env=env
    )


def _base_url(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def main() -> int:
    """Run the full bootstrap sequence, then block until Ctrl+C."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print(
            "DATABASE_URL is not set. See README.md 'Database (PostgreSQL)' for a "
            "throwaway `docker run` one-liner, or point at an existing instance.",
            file=sys.stderr,
        )
        return 2

    audit_base_url = _base_url(_AUDIT_PORT)
    specs = _default_specs(database_url, audit_base_url)
    processes: dict[str, subprocess.Popen] = {}

    def shutdown() -> None:
        for name, proc in processes.items():
            if proc.poll() is None:
                print(f"stopping {name}...")
                proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    try:
        print("[1/7] applying database migrations...")
        applied = bootstrap.run_migrations(database_url)
        print(f"      applied: {applied or 'nothing to apply'}")

        print("[2/7] generating federation PKI (root anchor + facility CAs)...")
        root, pki = bootstrap.generate_federation_pki(list(_FACILITY_PORTS))

        print("[3/7] starting authority services...")
        for spec in specs:
            if spec.role == "authority":
                processes[spec.name] = _spawn(spec)
        for port in _AUTHORITY_PORTS.values():
            bootstrap.wait_for_health(_base_url(port))

        print("      registering authorities with the root anchor...")
        authority_certificates = {
            authority_id: bootstrap.register_authority(
                _base_url(port), root, authority_id
            )
            for authority_id, port in _AUTHORITY_PORTS.items()
        }

        print("[4/7] starting the audit service...")
        for spec in specs:
            if spec.role == "audit":
                processes[spec.name] = _spawn(spec)
        bootstrap.wait_for_health(audit_base_url)

        print("[5/7] starting facility nodes...")
        for spec in specs:
            if spec.role == "facility":
                processes[spec.name] = _spawn(spec)
        for port in _FACILITY_PORTS.values():
            bootstrap.wait_for_health(_base_url(port))

        print(
            "[6/7] seeding synthetic data -- left to the demo driver (P4-5); "
            "skipped here."
        )

        print("[7/7] verifying the audit chain from genesis...")
        head_seq = bootstrap.check_audit_chain(audit_base_url)
        print(f"      chain verified, head seq={head_seq}")

        bootstrap.write_federation_config(
            FEDERATION_CONFIG_PATH,
            pki,
            authority_certificates,
            {aid: _base_url(port) for aid, port in _AUTHORITY_PORTS.items()},
            audit_base_url,
        )
        print(f"federation config written to {FEDERATION_CONFIG_PATH}")

        print("\nfederation is up:")
        for spec in specs:
            print(f"  {spec.name:14s} {_base_url(spec.port)}")
        print("\nPress Ctrl+C to stop the federation.")

        while True:
            time.sleep(1)
            for name, proc in processes.items():
                if proc.poll() is not None:
                    raise bootstrap.BootstrapError(
                        f"{name} exited unexpectedly (code {proc.returncode})"
                    )
    except KeyboardInterrupt:
        print("\nshutting down...")
        return 0
    except bootstrap.BootstrapError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 1
    finally:
        shutdown()


if __name__ == "__main__":
    sys.exit(main())
