"""A facility restart or a crash mid-rotation closes the record (ADR-0081).

Review F5 and the ADR-0069 residual: the emergency key lives only in the
facility process. Before ADR-0081 a restart mid-window left the record
``emergency_open`` for good, and a crash between the rotation's store commit
and its share deposits left it with no holder set that matched. Now every open
session is kept in the store without its key, and a restarted facility closes
its own sessions with a rotation recovered through the record's policy.

Each test restarts the facility the way a real restart does: a fresh expiry
manager and a fresh app over the same store, with nothing carried in memory.
"""

from __future__ import annotations

import datetime
import os

import psycopg
import pytest
from api.hospital import create_hospital_app
from api.repository import InMemoryStorageRepository, PostgresStorageRepository
from breakglass.emergency_key import THRESHOLD
from contracts import Facility
from contracts.enums import FacilityStatus, LifecycleState
from crypto_core import generate_ec_keypair, public_key_to_pem
from lifecycle.expiry import EmergencyExpiryManager
from records.exceptions import UnwrappingError
from records.service import decrypt_record, unwrap_dek
from shamir import combine_shares
from storage.migrate import apply_migrations
from storage.repositories import insert_authority, insert_facility, insert_patient

from tests.api.conftest import (  # noqa: F401
    RecordingAuditSink,
    RecordingRotationPorts,
    attribute_materials,
    federation_pki,
    make_trust,
)
from tests.security.conftest import skip_or_fail_without_postgres
from tests.security.test_p51_system_claims import (
    PATIENT,
    PLAINTEXT,
    RECORD,
    _seed,
    _unlock_payload,
)
from tests.shares import deposited_unlock_points, unlock_points


class FacilityProcess:
    """One facility process over a shared store; ``restart`` replaces it."""

    def __init__(self, repo, pki, rotation, facility_id="facility-a") -> None:
        self.repo, self.pki, self.rotation = repo, pki, rotation
        self.facility_id = facility_id
        self.start()

    def start(self) -> None:
        self.manager = EmergencyExpiryManager(
            signing_key=self.pki["life_priv"], default_duration_seconds=60.0
        )
        app = create_hospital_app(
            facility_id=self.facility_id,
            repository=self.repo,
            expiry_manager=self.manager,
            trust=make_trust(self.pki),
            audit_sink=RecordingAuditSink(),
            rotation_ports=self.rotation.ports,
        )
        self.client = self.pki["services"].client(app, self.facility_id)

    restart = start


def _postgres_repo() -> PostgresStorageRepository:
    url = os.environ.get("DATABASE_URL")
    if not url:
        skip_or_fail_without_postgres("DATABASE_URL not set; this test needs Postgres")
    try:
        conn = psycopg.connect(url)
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    conn.autocommit = False
    apply_migrations(conn)
    conn.commit()
    conn.autocommit = True
    _, public_key = generate_ec_keypair()
    for authority in ("authority-med", "authority-net"):
        insert_authority(conn, authority, authority, public_key_to_pem(public_key))
    for facility_id in ("facility-a", "facility-b"):
        insert_facility(
            conn,
            Facility(
                facility_id=facility_id,
                display_name=facility_id,
                endpoint=f"http://{facility_id}",
                public_key=public_key_to_pem(public_key),
                status=FacilityStatus.ACTIVE,
            ),
        )
    insert_patient(conn, PATIENT, "authority-net")
    return PostgresStorageRepository(conn)


@pytest.fixture(params=["memory", "postgres"])
def site(request, federation_pki, attribute_materials):  # noqa: F811
    """The same store a restarted facility finds: in memory, and Postgres
    (where the session rows and the rotation are real transactions)."""
    repo = (
        InMemoryStorageRepository() if request.param == "memory" else _postgres_repo()
    )
    seeded = _seed(repo, attribute_materials, federation_pki)
    rotation = RecordingRotationPorts(attribute_materials["attr_keyring"])
    facility = FacilityProcess(repo, federation_pki, rotation)
    return {
        "repo": repo,
        "rotation": rotation,
        "facility": facility,
        "pki": federation_pki,
        "attrs": attribute_materials,
        **seeded,
    }


def _open(site) -> None:
    h = {**site, "client": site["facility"].client}
    response = site["facility"].client.post(
        f"/records/{RECORD}/breakglass", json=_unlock_payload(h)
    )
    assert response.status_code == 200, response.text
    assert site["repo"].get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN
    assert site["repo"].list_emergency_sessions("facility-a")


def _opens_with(repo, shares) -> bytes:
    emergency = repo.get_wrapping_for_record(RECORD, wrapped_for="emergency")
    dek = unwrap_dek(emergency, combine_shares(list(shares), k=THRESHOLD))
    return decrypt_record(repo.get_record(RECORD), dek)


@pytest.mark.claim("C4", level="system")
def test_restart_mid_window_closes_the_record_with_a_rotation(site):
    """Review F5: after a restart the lost session cannot be joined, the record
    returns to its pre-emergency state, and only the new shares open it."""
    _open(site)
    facility = site["facility"]

    facility.restart()

    # Nobody joins a session whose key died with the old process.
    h = {**site, "client": facility.client}
    joined = facility.client.post(
        f"/records/{RECORD}/breakglass", json=_unlock_payload(h)
    )
    assert joined.status_code == 409
    assert "plaintext" not in joined.text

    facility.manager.check_and_expire_due()

    repo = site["repo"]
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    assert repo.list_emergency_sessions("facility-a") == []
    deposit = site["rotation"].deposits[-1]
    assert deposit["generation"] == 1
    assert _opens_with(repo, deposited_unlock_points(deposit)) == PLAINTEXT
    with pytest.raises(UnwrappingError):
        _opens_with(repo, unlock_points(site["shares"]))


@pytest.mark.claim("C4", level="system")
def test_crash_between_store_and_share_deposit_is_finished_at_restart(
    site, monkeypatch
):
    """ADR-0069 residual: the rotation stored, then the process died before the
    holders got their shares. The restarted facility re-keys again, one
    generation on, and hands both holders matching shares."""
    _open(site)
    facility, rotation, repo = site["facility"], site["rotation"], site["repo"]
    real_deposit = rotation.deposit_shares

    def holders_down(*_args):
        raise ConnectionError("custodian down")

    monkeypatch.setattr(rotation, "deposit_shares", holders_down)
    with pytest.raises(ConnectionError):
        facility.manager.expire_session(RECORD, force=True)
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.EXPIRED
    stored = repo.get_wrapping_for_record(RECORD, wrapped_for="emergency")
    assert stored.generation == 1  # the lost plan's rotation was stored

    monkeypatch.setattr(rotation, "deposit_shares", real_deposit)
    facility.restart()
    facility.manager.check_and_expire_due()

    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    deposit = rotation.deposits[-1]
    assert deposit["generation"] == 2
    assert _opens_with(repo, deposited_unlock_points(deposit)) == PLAINTEXT
    assert repo.list_emergency_sessions("facility-a") == []


def test_restart_recovers_only_its_own_sessions(site):
    """Another facility's open session is that facility's to finish."""
    _open(site)
    repo = site["repo"]
    other = FacilityProcess(
        repo, site["pki"], site["rotation"], facility_id="facility-b"
    )
    other.manager.check_and_expire_due()
    assert not other.manager.has_session(RECORD)
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN
    assert repo.list_emergency_sessions("facility-a")


def test_a_left_over_row_for_a_closed_record_is_dropped(site):
    """A row whose expiry already finished (its delete failed) is only removed."""
    repo = site["repo"]
    now = datetime.datetime.now(datetime.timezone.utc)
    repo.save_emergency_session(
        {
            "record_id": RECORD,
            "facility_id": "facility-a",
            "return_state": "granted",
            "actor_id": "dr-alice",
            "correlation_id": "corr-old",
            "opener_facility_id": "facility-a",
            "opened_at": now,
            "expires_at": now,
        }
    )
    site["facility"].restart()
    assert repo.list_emergency_sessions("facility-a") == []
    assert not site["facility"].manager.has_session(RECORD)
    assert site["rotation"].deposits == []


def test_a_session_that_cannot_be_recorded_does_not_open(site, monkeypatch):
    """Fail closed: a window no restart could close is refused, and the record
    is left as it was."""
    repo = site["repo"]

    def store_down(row):
        raise RuntimeError("store down")

    monkeypatch.setattr(repo, "save_emergency_session", store_down)
    h = {**site, "client": site["facility"].client}
    with pytest.raises(RuntimeError, match="store down"):
        site["facility"].client.post(
            f"/records/{RECORD}/breakglass", json=_unlock_payload(h)
        )
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    assert not site["facility"].manager.has_session(RECORD)
