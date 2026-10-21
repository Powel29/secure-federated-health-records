"""One command: the whole federation + key custodian + the three portals.

    DATABASE_URL=postgresql://postgres:postgres@localhost:5432/mydb \\
        python -m deploy.run_portal_demo

What it does, in order (ARCHITECTURE.md §7 bootstrap sequence, then ADR-0043):

1. Resets the shared store's ``public`` schema and applies the P0-8
   migrations (fresh federation every run, ADR-0039).
2. Starts the five federation services and the Key Custodian as separate
   processes on the fixed ports, exactly as Path A does
   (``deploy.run_local.start_federation``): audit is its own process, as
   ARCHITECTURE.md §7 requires, and the capture filter sees every port
   (review F38). ``--in-process`` keeps the old in-process threads
   (``demo.driver.standalone_federation``) for tests and quick checks.
3. Root anchor + facility CAs generated, authorities registered, genesis
   entry written, facilities configured with the trust anchors.
4. Seeds the synthetic dataset (P4-5): credentials issued, records ingested
   at their facilities, weighted 3-of-4 emergency keys split -- shares 3
   and 4 deposited at the audit service, share 2 at the patient's home
   authority, share 1 at the custodian (ADR-0089), each persona's key
   material deposited at the custodian.
5. Creates the ``portal`` schema and the read-only ``portal_ro`` store role,
   runs the Django migrations, and seeds the portal logins + patient
   directory (name + DOB, ADR-0033).
6. Runs the Django dev server and prints the logins.

Ctrl+C stops everything. Nothing is written to disk except the database.
For the Path A / Path B multi-process deployments see ``deploy/run_local.py``
and ``deploy/docker-compose.yml`` (both now include the custodian).
"""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import psycopg
from psycopg import sql

from deploy.bootstrap import _require_local_database as require_local_database

if TYPE_CHECKING:
    from demo.seed_data import SyntheticDataset
    from deploy.run_scenario import ScenarioEndpoints

REPO_ROOT = Path(__file__).resolve().parent.parent
PORTAL_DIR = REPO_ROOT / "portal"
ROLES_SQL = PORTAL_DIR / "sql" / "roles.sql"
# Every service's identity, as run_local and the in-process demo write it.
SERVICES_DIR = REPO_ROOT / "deploy" / "pki" / "services"

STORE_RO_USER = "portal_ro"
# Django's own role: owns the portal schema, no store privileges (review F36).
PORTAL_APP_USER = "portal_app"
# Role passwords are generated per run, set on the roles by _prepare_portal_schema
# and handed to Django through its environment: none is ever committed.
STORE_RO_PASSWORD = secrets.token_urlsafe(16)
PORTAL_APP_PASSWORD = secrets.token_urlsafe(16)


def _db_parts(database_url: str) -> dict[str, str]:
    u = urlparse(database_url)
    return {
        "host": u.hostname or "localhost",
        "port": str(u.port or 5432),
        "name": (u.path or "/postgres").lstrip("/"),
        "user": u.username or "postgres",
        "password": u.password or os.environ.get("PGPASSWORD", ""),
    }


def _prepare_portal_schema(database_url: str, *, reset: bool = True) -> None:
    """Create the portal schema + read-only store role (portal/sql/roles.sql)."""
    if reset:
        require_local_database(database_url)
    roles_sql = ROLES_SQL.read_text(encoding="utf-8")
    with psycopg.connect(database_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            # Fresh portal state every run, matching the fresh federation
            # (ADR-0039): stale case files would point at a chain that no
            # longer exists.
            if reset:
                cur.execute("DROP SCHEMA IF EXISTS portal CASCADE")
            cur.execute(roles_sql)
            # Password auth for the read-only role (the Docker Postgres most
            # people run uses scram, not trust). Dev-only, documented.
            for user, password in (
                (STORE_RO_USER, STORE_RO_PASSWORD),
                (PORTAL_APP_USER, PORTAL_APP_PASSWORD),
            ):
                cur.execute(
                    sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
                        sql.Identifier(user), sql.Literal(password)
                    )
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8000, help="Django dev server port")
    parser.add_argument(
        "--duration",
        type=float,
        default=float(os.environ.get("EMERGENCY_DURATION_SECONDS", "14400")),
        help="break-glass time-box in seconds (ARCHITECTURE §7: adjustable)",
    )
    parser.add_argument(
        "--no-server", action="store_true", help="seed everything, then exit (CI smoke)"
    )
    parser.add_argument(
        "--in-process",
        action="store_true",
        help="run the services as threads in this process (tests only; audit is "
        "then not a separate process, review F38)",
    )
    args = parser.parse_args(argv)

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print(
            "DATABASE_URL is not set (e.g. postgresql://postgres:postgres@localhost:5432/mydb)",
            file=sys.stderr,
        )
        return 2

    # Late imports: src/ packages resolve after `pip install -e .` / PYTHONPATH.

    if args.in_process:
        return _run_in_process(args, database_url)
    from demo.seed_data import create_synthetic_dataset
    from deploy import run_local

    os.environ.setdefault("SEED_DATA", "true")
    print("[1/6] starting the federation and custodian as separate processes...")
    try:
        with run_local.start_federation(
            database_url, emergency_duration_seconds=args.duration
        ) as endpoints:
            return _serve_portal(
                args,
                database_url,
                endpoints,
                run_local.custodian_url(),
                create_synthetic_dataset(),
            )
    except KeyboardInterrupt:
        return 0


def _run_in_process(args: argparse.Namespace, database_url: str) -> int:
    """The old single-process path: services as threads (tests only)."""
    from demo.driver import standalone_federation
    from demo.seed_data import seed_synthetic_data
    from deploy.seed_portal import deposit_custodian

    print("[1/6] resetting the store and starting the services in-process...")
    with standalone_federation(database_url, default_duration=args.duration) as fed:
        endpoints = fed["endpoints"]
        custodian_url = endpoints.custodian
        print("[3/6] seeding synthetic patients, clinicians and records (P4-5)...")
        seed = seed_synthetic_data(endpoints, fed["config"], client=fed["client"])
        counts = deposit_custodian(
            custodian_url, seed, audit_url=endpoints.audit, client=fed["client"]
        )
        print(
            f"      {len(seed['records'])} records ingested; custodian holds "
            f"{counts['subjects']} subjects and {counts['shares']} clinician shares"
        )
        return _serve_portal(
            args, database_url, endpoints, custodian_url, seed["dataset"]
        )


def _serve_portal(
    args: argparse.Namespace,
    database_url: str,
    endpoints: ScenarioEndpoints,
    custodian_url: str,
    dataset: SyntheticDataset,
) -> int:
    """Steps 4-6: portal schema and roles, Django accounts, the dev server."""
    from deploy.seed_portal import (
        DEMO_PASSWORD,
        PORTAL_LOGINS,
        django_setup,
        seed_portal_accounts,
    )

    print("[4/6] preparing the portal schema and read-only store role...")
    _prepare_portal_schema(database_url)
    db = _db_parts(database_url)
    env = {
        "PORTAL_DB_HOST": db["host"],
        "PORTAL_DB_PORT": db["port"],
        "PORTAL_DB_NAME": db["name"],
        "PORTAL_DB_USER": PORTAL_APP_USER,
        "PORTAL_DB_PASSWORD": PORTAL_APP_PASSWORD,
        "STORE_DB_USER": STORE_RO_USER,
        "STORE_DB_PASSWORD": STORE_RO_PASSWORD,
        "CUSTODIAN_URL": custodian_url,
        "AUDIT_SERVICE_URL": endpoints.audit,
        "FACILITY_URLS": (
            f"facility-a={endpoints.facility_a},facility-b={endpoints.facility_b}"
        ),
        "AUTHORITY_URLS": (
            f"authority-med={endpoints.authority_med},"
            f"authority-net={endpoints.authority_net}"
        ),
        "EMERGENCY_DURATION_SECONDS": str(args.duration),
        "DJANGO_SETTINGS_MODULE": "config.settings",
        # Loopback developer demo: debug pages on, explicitly (F42).
        "DJANGO_DEBUG": "1",
        # The portal signs its calls with its own service identity, written
        # next to every other service's at bootstrap (ADR-0066).
        "SERVICE_KEY_FILE": str(SERVICES_DIR / "portal" / "service.key"),
        "SERVICE_CERT_FILE": str(SERVICES_DIR / "portal" / "service.crt"),
    }
    django_setup(env)
    from django.core.management import call_command

    call_command("migrate", verbosity=0)
    seeded = seed_portal_accounts(dataset)
    print(f"      {seeded['users']} portal logins, {seeded['directory']} directory")

    print("[5/6] federation is up:")
    for name, url in [
        ("authority-med", endpoints.authority_med),
        ("authority-net", endpoints.authority_net),
        ("audit", endpoints.audit),
        ("facility-a", endpoints.facility_a),
        ("facility-b", endpoints.facility_b),
        ("custodian", custodian_url),
    ]:
        print(f"      {name:14s} {url}")

    if args.no_server:
        return 0

    print(f"[6/6] starting the portals at http://127.0.0.1:{args.port}/")
    print("\n      login (password for all: %s)" % DEMO_PASSWORD)
    for username, (subject_id, role) in PORTAL_LOGINS.items():
        print(f"      {username:10s} {role:10s} {subject_id}")
    print(
        f"\n      break-glass time-box: {args.duration:.0f}s   "
        "Ctrl+C stops everything\n"
    )

    proc = (
        subprocess.Popen(  # noqa: S603 - this repo's own manage.py via sys.executable
            [
                sys.executable,
                str(PORTAL_DIR / "manage.py"),
                "runserver",
                f"127.0.0.1:{args.port}",
                "--noreload",
            ],
            cwd=str(PORTAL_DIR),
            env={**os.environ, **env},
        )
    )
    try:
        while proc.poll() is None:
            time.sleep(0.5)
        return proc.returncode or 0
    except KeyboardInterrupt:
        print("\nshutting down...")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 0


if __name__ == "__main__":
    sys.exit(main())
