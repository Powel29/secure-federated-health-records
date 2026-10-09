"""One command: the whole federation + key custodian + the three portals.

    DATABASE_URL=postgresql://postgres:postgres@localhost:5432/mydb \\
        python -m deploy.run_portal_demo

What it does, in order (ARCHITECTURE.md §7 bootstrap sequence, then ADR-0043):

1. Resets the shared store's ``public`` schema and applies the P0-8
   migrations (fresh federation every run, ADR-0039).
2. Starts the five federation services in-process on ephemeral ports
   (``demo.driver.standalone_federation``): two authorities, the audit
   service, two facility nodes -- root anchor + facility CAs generated,
   authorities registered, genesis entry written.
3. Starts the Key Custodian (sixth process, ADR-0043) pointed at them.
4. Seeds the synthetic dataset (P4-5): credentials issued, records ingested
   at their facilities, 2-of-3 emergency keys split -- share 3 deposited at
   the audit service, share 1 at the custodian, each persona's key material
   deposited at the custodian.
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
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import psycopg
from psycopg import sql

from deploy.bootstrap import _require_local_database as require_local_database

REPO_ROOT = Path(__file__).resolve().parent.parent
PORTAL_DIR = REPO_ROOT / "portal"
ROLES_SQL = PORTAL_DIR / "sql" / "roles.sql"

STORE_RO_USER = "portal_ro"
STORE_RO_PASSWORD = "portal_ro"  # noqa: S105 - dev-only role password, see roles.sql


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
            cur.execute(
                sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
                    sql.Identifier(STORE_RO_USER), sql.Literal(STORE_RO_PASSWORD)
                )
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8000, help="Django dev server port")
    parser.add_argument(
        "--duration",
        type=float,
        default=float(os.environ.get("EMERGENCY_DURATION_SECONDS", "120")),
        help="break-glass time-box in seconds (ARCHITECTURE §7: adjustable)",
    )
    parser.add_argument(
        "--no-server", action="store_true", help="seed everything, then exit (CI smoke)"
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
    from api.custodian_service import CustodianEndpoints, create_custodian_app
    from storage.repositories import get_record

    from demo.driver import _LiveServer, standalone_federation
    from demo.seed_data import seed_synthetic_data
    from deploy.seed_portal import (
        DEMO_PASSWORD,
        PORTAL_LOGINS,
        deposit_custodian,
        django_setup,
        seed_portal_accounts,
    )

    print("[1/6] resetting the store and starting the five federation services...")
    with standalone_federation(database_url, default_duration=args.duration) as fed:
        endpoints = fed["endpoints"]
        config = fed["config"]

        print("[2/6] starting the key custodian (ADR-0043)...")
        store_conn = psycopg.connect(database_url)
        store_conn.autocommit = True
        custodian_app = create_custodian_app(
            endpoints=CustodianEndpoints(
                authorities={
                    "authority-med": endpoints.authority_med,
                    "authority-net": endpoints.authority_net,
                },
                facilities={
                    "facility-a": endpoints.facility_a,
                    "facility-b": endpoints.facility_b,
                },
                audit=endpoints.audit,
            ),
            record_loader=lambda rid: get_record(store_conn, rid),
        )
        custodian = _LiveServer(custodian_app)
        custodian_url = custodian.start()

        print("[3/6] seeding synthetic patients, clinicians and records (P4-5)...")
        seed = seed_synthetic_data(endpoints, config)
        counts = deposit_custodian(custodian_url, seed)
        print(
            f"      {len(seed['records'])} records ingested; custodian holds "
            f"{counts['subjects']} subjects and {counts['shares']} clinician shares"
        )

        print("[4/6] preparing the portal schema and read-only store role...")
        _prepare_portal_schema(database_url)
        db = _db_parts(database_url)
        env = {
            "PORTAL_DB_HOST": db["host"],
            "PORTAL_DB_PORT": db["port"],
            "PORTAL_DB_NAME": db["name"],
            "PORTAL_DB_USER": db["user"],
            "PORTAL_DB_PASSWORD": db["password"],
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
        }
        django_setup(env)
        from django.core.management import call_command

        call_command("migrate", verbosity=0)
        seeded = seed_portal_accounts(seed["dataset"])
        print(
            f"      {seeded['users']} portal logins, "
            f"{seeded['directory']} directory rows"
        )

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
            custodian.stop()
            return 0

        print(f"[6/6] starting the portals at http://127.0.0.1:{args.port}/")
        print("\n      login (password for all: %s)" % DEMO_PASSWORD)
        for username, (subject_id, role) in PORTAL_LOGINS.items():
            print(f"      {username:10s} {role:10s} {subject_id}")
        print(
            f"\n      break-glass time-box: {args.duration:.0f}s   "
            "Ctrl+C stops everything\n"
        )

        proc = subprocess.Popen(  # noqa: S603 - this repo's own manage.py via sys.executable
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
        finally:
            custodian.stop()
            store_conn.close()


if __name__ == "__main__":
    sys.exit(main())
