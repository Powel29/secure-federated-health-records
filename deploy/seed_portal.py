"""Seed the portals' side of the federation (ADR-0043).

Two steps after ``demo.seed_data.seed_synthetic_data`` has ingested the
synthetic records and issued credentials:

1. :func:`deposit_custodian` -- hand each persona's private material (signing
   key, certificate, PRE keypair, issued credentials) and each record's
   clinician-custody share (share 1) to the Key Custodian, and register the
   federation trust anchors with it. This is the portal-era equivalent of
   ``POST /breakglass/shares`` at the audit service: a one-time bootstrap
   deposit, never repeated at request time.
2. :func:`seed_portal_accounts` -- create the Django logins, ``Profile`` rows
   and ``PatientDirectory`` rows (name + DOB, ADR-0033) for the same personas,
   so the three portals have someone to identify.

Dev-only credentials (documented, synthetic, never reused): every seeded
login's password is ``demo1234``.

Run as a script, it does step 2 (step 1 is part of the Path A/B bootstrap)
and serves the portals against an already running federation::

    DATABASE_URL=postgresql://postgres@127.0.0.1:55433/ehr python -m deploy.seed_portal
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
from crypto_core import certificate_to_pem

from demo.seed_data import SyntheticDataset, create_synthetic_dataset
from deploy.config import configure_transport, tls_enabled

REPO_ROOT = Path(__file__).resolve().parent.parent
PORTAL_DIR = REPO_ROOT / "portal"

DEMO_PASSWORD = "demo1234"  # noqa: S105 - synthetic demo login, documented

# Portal logins for the synthetic personas (demo/seed_data.py). Username ->
# (subject_id, role). Names/DOBs come from the dataset itself.
PORTAL_LOGINS: dict[str, tuple[str, str]] = {
    "alice": ("pat-101", "patient"),
    "david": ("pat-102", "patient"),
    "emma": ("pat-103", "patient"),
    "house": ("doc-201", "clinician"),
    "chase": ("doc-301", "clinician"),
    "cameron": ("doc-202", "clinician"),
    "auditor": ("admin-1", "admin"),
}


def deposit_custodian(
    custodian_url: str,
    seed_result: dict[str, Any],
    *,
    client: httpx.Client | None = None,
) -> dict[str, int]:
    """Deposit trust anchors, per-subject material and share 1s. Returns counts."""
    http = client or httpx.Client(timeout=15.0)
    facility_ca_pems = {
        fid: certificate_to_pem(cert).decode("ascii")
        for fid, (_priv, cert) in seed_result["facility_cas"].items()
    }
    http.put(
        f"{custodian_url}/trust",
        json={
            "root_certificate_pem": seed_result["root_cert_pem"],
            "facility_ca_certificate_pems": facility_ca_pems,
        },
    ).raise_for_status()

    subjects = 0
    for clinician_id, meta in seed_result["clinicians"].items():
        clinician = meta["clinician"]
        http.post(
            f"{custodian_url}/subjects/{clinician_id}/material",
            json={
                "kind": "clinician",
                "display_name": clinician.name,
                "facility_id": clinician.facility_id,
                "signing_key_pem": meta["private_key_pem"],
                "certificate_pem": meta["certificate_pem"],
                "pre_private_key": meta["pre_private_key"],
                "pre_public_key": meta["pre_public_key"],
                "credentials": meta["credentials"],
            },
        ).raise_for_status()
        subjects += 1

    for patient_id, meta in seed_result["patients"].items():
        patient = meta["patient"]
        http.post(
            f"{custodian_url}/subjects/{patient_id}/material",
            json={
                "kind": "patient",
                "display_name": patient.name,
                "facility_id": patient.home_facility,
                "signing_key_pem": meta["private_key_pem"],
                "credentials": meta["credentials"],
            },
        ).raise_for_status()
        subjects += 1

    shares = 0
    for record_id, meta in seed_result["records"].items():
        x, share_bytes = meta["share1"]
        http.post(
            f"{custodian_url}/records/{record_id}/shares",
            json={"x": x, "share_hex": share_bytes.hex()},
        ).raise_for_status()
        shares += 1

    return {"subjects": subjects, "shares": shares}


def django_setup(env: dict[str, str] | None = None) -> None:
    """Configure Django for the portal in this process (idempotent)."""
    if env:
        os.environ.update(env)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    if str(PORTAL_DIR) not in sys.path:
        sys.path.insert(0, str(PORTAL_DIR))
    import django

    django.setup()


def seed_portal_accounts(dataset: SyntheticDataset) -> dict[str, int]:
    """Create logins, profiles and directory rows for the dataset's personas."""
    from accounts.models import PatientDirectory, Profile, RegistrationRequest
    from django.contrib.auth.models import User

    patients = {p.patient_id: p for p in dataset.patients}
    clinicians = {c.clinician_id: c for c in dataset.clinicians}

    users = 0
    for username, (subject_id, role) in PORTAL_LOGINS.items():
        user, created = User.objects.get_or_create(username=username)
        if created:
            user.set_password(DEMO_PASSWORD)
            user.save()
        facility = ""
        if role == "clinician" and subject_id in clinicians:
            facility = clinicians[subject_id].facility_id
        elif role == "patient" and subject_id in patients:
            facility = patients[subject_id].home_facility
        Profile.objects.update_or_create(
            user=user,
            defaults={
                "role": role,
                "subject_id": subject_id,
                "home_facility_id": facility,
            },
        )
        # Mark the seeded personas as issued: their credentials really were
        # issued by the authorities during seed_synthetic_data.
        RegistrationRequest.objects.update_or_create(
            user=user,
            defaults={
                "role": role,
                "subject_id": subject_id,
                "status": "issued" if role != "admin" else "approved",
                "requested_attributes": (
                    f"owner:{subject_id}"
                    if role == "patient"
                    else (
                        ", ".join(
                            f"{k}:{v}"
                            for k, v in (
                                ("role", clinicians[subject_id].role),
                                ("specialty", clinicians[subject_id].specialty),
                            )
                            if v
                        )
                        if subject_id in clinicians
                        else ""
                    )
                ),
            },
        )
        users += 1

    directory = 0
    for p in dataset.patients:
        given, _, family = p.name.partition(" ")
        PatientDirectory.objects.update_or_create(
            subject_id=p.patient_id,
            defaults={
                "given_name": given,
                "family_name": family or given,
                "date_of_birth": p.date_of_birth,
                "home_facility_id": p.home_facility,
                "home_authority_id": p.owner_authority,
            },
        )
        directory += 1
    # One deliberately ambiguous namesake (ADR-0033 rule 4): same name and
    # DOB as Alice, different identifier, no records. The clinician must
    # choose; the portal never picks.
    PatientDirectory.objects.update_or_create(
        subject_id="pat-777",
        defaults={
            "given_name": "Alice",
            "family_name": "Vance",
            "date_of_birth": "1982-04-15",
            "home_facility_id": "facility-b",
            "home_authority_id": "authority-net",
        },
    )
    directory += 1
    return {"users": users, "directory": directory}


def main(argv: list[str] | None = None) -> int:
    """Seed the portal schema + logins, then serve the portals on localhost."""
    from deploy.run_portal_demo import (
        STORE_RO_PASSWORD,
        STORE_RO_USER,
        _db_parts,
        _prepare_portal_schema,
    )

    parser = argparse.ArgumentParser(
        description="Run the portals against a running federation."
    )
    parser.add_argument("--port", type=int, default=8000, help="Django dev server port")
    parser.add_argument("--host", default="127.0.0.1", help="Django bind address")
    parser.add_argument(
        "--no-server", action="store_true", help="seed the portal side, then exit"
    )
    args = parser.parse_args(argv)

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print(
            "DATABASE_URL is not set (Path B: postgresql://postgres@127.0.0.1:55433/ehr)",
            file=sys.stderr,
        )
        return 2

    # Restarting only the portal must preserve consents and case history.
    _prepare_portal_schema(database_url, reset=False)
    if tls_enabled():
        os.environ.setdefault("CUSTODIAN_URL", "https://127.0.0.1:8030")
        os.environ.setdefault("AUDIT_SERVICE_URL", "https://127.0.0.1:8020")
        os.environ.setdefault(
            "FACILITY_URLS",
            "facility-a=https://127.0.0.1:8001,facility-b=https://127.0.0.1:8002",
        )
        os.environ.setdefault(
            "AUTHORITY_URLS",
            "authority-med=https://127.0.0.1:8010,authority-net=https://127.0.0.1:8011",
        )
    configure_transport()
    db = _db_parts(database_url)
    env = {
        "PORTAL_DB_HOST": db["host"],
        "PORTAL_DB_PORT": db["port"],
        "PORTAL_DB_NAME": db["name"],
        "PORTAL_DB_USER": db["user"],
        "PORTAL_DB_PASSWORD": db["password"],
        "STORE_DB_USER": STORE_RO_USER,
        "STORE_DB_PASSWORD": STORE_RO_PASSWORD,
        "DJANGO_SETTINGS_MODULE": "config.settings",
    }
    # CUSTODIAN_URL, FACILITY_URLS, ... default to the published localhost
    # ports (portal/config/settings.py); set them to point elsewhere.
    django_setup(env)
    from django.core.management import call_command

    call_command("migrate", verbosity=0)
    seeded = seed_portal_accounts(create_synthetic_dataset())
    print(f"{seeded['users']} portal logins, {seeded['directory']} directory rows")
    if args.no_server:
        return 0

    print(
        f"portals at http://127.0.0.1:{args.port}/  (password for all: {DEMO_PASSWORD})"
    )
    for username, (subject_id, role) in PORTAL_LOGINS.items():
        print(f"  {username:10s} {role:10s} {subject_id}")
    try:
        return subprocess.call(
            [  # noqa: S603 - this repo's own manage.py via sys.executable
                sys.executable,
                str(PORTAL_DIR / "manage.py"),
                "runserver",
                f"{args.host}:{args.port}",
                "--noreload",
                # Serve the portal's CSS when DJANGO_DEBUG=0 (Compose);
                # runserver serves static files only in DEBUG otherwise.
                "--insecure",
            ],
            cwd=str(PORTAL_DIR),
            env={**os.environ, **env},
        )
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
