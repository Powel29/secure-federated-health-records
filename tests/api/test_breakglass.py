"""Unit tests for the Hospital Node Break-Glass endpoint (P4-1, P3-5, P3-10, P3-11).

Verifies:
- 2-of-3 threshold unlock produces re-wrapped DEK and sets EMERGENCY_OPEN.
- Refusal when fewer than 2 shares presented (400).
- Replay prevention: reusing an assertion_id is rejected (400).
- Facility mismatch is rejected (400).
- Trust anchors come from facility configuration, never the request (F1).
- The caller can only shorten the time-box (F6).
- A failed unlock leaves no side effects; concurrent opens cannot both win
  (F7, N1).
- A second unlock on an open record joins it: same threshold, logged before
  release, no transition, no extension (ADR-0057) -- but only for clinicians
  of the opener's facility (ADR-0063).
- Every refusal is audited exactly once (F8).
"""

from __future__ import annotations

import base64
import datetime
import threading
import time

import pytest
from api.audit_client import AuditServiceError
from api.hospital import create_hospital_app
from audit.events import EVENT_ACCESS_DENIED, EVENT_FEDERATION_REWRAP
from breakglass import create_emergency_assertion
from contracts.base import GCM_NONCE_BYTES
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import (
    certificate_to_pem,
    generate_ec_keypair,
    private_key_to_pem,
)
from crypto_core.symmetric import aes_gcm_decrypt
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.root_anchor import generate_root_anchor
from pre.elgamal import decapsulate_key
from shamir.finite_field import PRIME_MODULUS

from tests.api.conftest import RecordingAuditSink, make_trust
from tests.sealing import seal_all
from tests.transitions import open_event


def _unwrap_rewrapped_dek(rewrapped_dek: bytes, pre_priv: int, record_id: str) -> bytes:
    """Helper: reverse the gate's fixed-length PRE delivery packaging."""
    field_bytes = 32
    c1 = int.from_bytes(rewrapped_dek[:field_bytes], byteorder="big")
    c2 = int.from_bytes(rewrapped_dek[field_bytes : 2 * field_bytes], byteorder="big")
    offset = 2 * field_bytes
    nonce = rewrapped_dek[offset : offset + GCM_NONCE_BYTES]
    ciphertext = rewrapped_dek[offset + GCM_NONCE_BYTES :]
    delivery_key = decapsulate_key(pre_priv, c1, c2)
    return aes_gcm_decrypt(
        key=delivery_key,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=record_id.encode("utf-8"),
    )


def _payload(
    test_setup,
    *,
    patient_id: str = "patient-001",
    facility_id: str = "facility-a",
    clinician_id: str = "dr-alice",
    signing_key=None,
    certificate=None,
    shares=None,
    record_id: str = "rec-001",
    target=None,
    **extra,
) -> dict:
    """A well-formed unlock request; keyword overrides build the attacks.

    Presents the shares of the share-1 path that the holders hold now --
    share 1 and the audit service's shares 3 and 4 (ADR-0089) -- from the
    ingest split, or the one the latest expiry rotation handed out
    (ADR-0069), each sealed to the facility for ``record_id`` (ADR-0079).
    """
    pki = test_setup["pki"]
    em_shares = test_setup["em_shares"]
    deposits = test_setup["rotation"].deposits
    if shares is None and deposits:
        latest = deposits[-1]
        shares = [
            (x, s.hex())
            for x, s in (latest["clinician_share"], *latest["audit_shares"])
        ]
    key = signing_key or pki["alice_priv"]
    assertion = create_emergency_assertion(
        patient_id=patient_id,
        clinician_id=clinician_id,
        facility_id=facility_id,
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        signing_key=key,
    )
    # The clinician's own signed open, from the record's current state
    # (ADR-0068); ignored when the record is already open and this joins.
    state = test_setup["repo"].get_lifecycle_state("rec-001")
    from_state = (
        state
        if state in (LifecycleState.GRANTED, LifecycleState.REVOKED)
        else LifecycleState.GRANTED
    )
    event = open_event(
        "rec-001", from_state, clinician_id, ReasonCode.UNCONSCIOUS_PATIENT, key
    )
    body = {
        "assertion": assertion.model_dump(mode="json"),
        "clinician_certificate_pem": certificate_to_pem(
            certificate or pki["alice_cert"]
        ).decode("ascii"),
        "sealed_shares": seal_all(
            target or test_setup["client"],
            record_id,
            [
                (x, bytes.fromhex(share_hex))
                for x, share_hex in (
                    shares if shares is not None else _hex(_points(em_shares, 1, 3, 4))
                )
            ],
        ),
        "pre_rewrap_key": pki["alice_pre_pub"],
        "transition_event": event.model_dump(mode="json"),
    }
    body.update(extra)
    return body


def _points(shares, *xs: int) -> list:
    """The shares of a split at the given x-coordinates."""
    return [s for s in shares if s[0] in xs]


def _hex(shares) -> list[tuple[int, str]]:
    return [(x, s.hex()) for x, s in shares]


def _assert_no_side_effects(test_setup, sink: RecordingAuditSink) -> None:
    """The record is still GRANTED, no event, no session, nothing released."""
    repo = test_setup["repo"]
    assert repo.get_lifecycle_state("rec-001") == LifecycleState.GRANTED
    assert repo.transition_events == {}
    with pytest.raises(Exception):  # noqa: B017 -- SessionNotFound or Expired
        test_setup["expiry_manager"].get_active_emergency_key("rec-001")
    assert sink.of_type(EVENT_FEDERATION_REWRAP) == []


class TestHospitalBreakglassEndpoint:
    """Test suite for POST /records/{record_id}/breakglass."""

    def test_breakglass_unlock_with_three_shares(self, test_setup):
        """Share 1 plus shares 3 and 4 with a valid EmergencyAssertion unlock
        the record (ADR-0089)."""
        client = test_setup["client"]
        pki = test_setup["pki"]

        response = client.post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, correlation_id="corr-bg-001"),
        )

        assert response.status_code == 200, response.text
        data = response.json()
        assert data["record_id"] == "rec-001"
        assert (
            data["transition_event"]["to_state"] == LifecycleState.EMERGENCY_OPEN.value
        )

        # Clinician Alice recovers the DEK using her PRE private key
        rewrapped_bytes = base64.b64decode(data["rewrapped_dek_b64"])
        recovered_dek = _unwrap_rewrapped_dek(
            rewrapped_bytes, pki["alice_pre_priv"], "rec-001"
        )
        assert len(recovered_dek) == 32

        # The store records the state and the signed event against it.
        repo = test_setup["repo"]
        assert repo.get_lifecycle_state("rec-001") == LifecycleState.EMERGENCY_OPEN
        event_id = data["transition_event"]["event_id"]
        assert repo.lifecycle_last_event_ids["rec-001"] == event_id
        assert event_id in repo.transition_events

    @pytest.mark.claim("C3", level="system")
    def test_breakglass_single_share_fails(self, test_setup):
        """Presenting fewer than 3 shares fails with HTTP 400 and no side effect."""
        em_shares = test_setup["em_shares"]
        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, shares=_hex(_points(em_shares, 1))),
        )

        assert response.status_code == 400
        # The threshold itself refused -- not a later format check on a
        # one-share "reconstruction" (the C3a mutation shows the difference).
        assert "requires 3 unique shares" in response.json()["detail"]
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

    @pytest.mark.claim("C3", level="system")
    def test_custodian_and_home_authority_shares_alone_open_nothing(self, test_setup):
        """ADR-0089: shares 1 and 2 -- every point outside the audit service --
        are two of three, so the gate refuses before any key exists, and the
        same request with share 3 added proves the setup was valid."""
        em_shares = test_setup["em_shares"]
        client = test_setup["client"]
        response = client.post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, shares=_hex(_points(em_shares, 1, 2))),
        )
        assert response.status_code == 400
        assert "requires 3 unique shares" in response.json()["detail"]
        assert "rewrapped_dek_b64" not in response.text
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

        opened = client.post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, shares=_hex(_points(em_shares, 1, 2, 3))),
        )
        assert opened.status_code == 200, opened.text

    @pytest.mark.claim("C3", level="system")
    def test_audit_service_shares_alone_open_nothing(self, test_setup):
        """The audit service's two points are not a threshold: refused (400)."""
        em_shares = test_setup["em_shares"]
        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, shares=_hex(_points(em_shares, 3, 4))),
        )
        assert response.status_code == 400
        assert "requires 3 unique shares" in response.json()["detail"]
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

    def test_home_authority_share_stands_in_for_share_1(self, test_setup):
        """Shares 2, 3 and 4 -- the fallback path -- open the record."""
        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(
                test_setup, shares=_hex(_points(test_setup["em_shares"], 2, 3, 4))
            ),
        )
        assert response.status_code == 200, response.text

    def test_share_sealed_to_another_facility_is_refused(self, test_setup):
        """ADR-0079: shares sealed to another facility's gate open nothing here;
        refused (400) and audited before any state changes."""
        from breakglass.share_sealing import (
            ShareRecipient,
            ShareSealingKey,
            seal_share,
        )

        elsewhere = ShareRecipient("facility-b", ShareSealingKey.generate().public_key)
        payload = _payload(test_setup)
        payload["sealed_shares"] = [
            seal_share(s, record_id="rec-001", recipient=elsewhere).model_dump(
                mode="json"
            )
            for s in _points(test_setup["em_shares"], 1, 3, 4)
        ]
        response = test_setup["client"].post(
            "/records/rec-001/breakglass", json=payload
        )
        assert response.status_code == 400
        assert "Sealed share refused" in response.json()["detail"]
        assert "rewrapped_dek_b64" not in response.text
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

    @pytest.mark.claim("C8", level="system")
    def test_breakglass_replayed_assertion_fails(self, test_setup):
        """Replaying a previously used assertion is rejected (P3-11 -> 400)."""
        client = test_setup["client"]
        payload = _payload(test_setup)

        res1 = client.post("/records/rec-001/breakglass", json=payload)
        assert res1.status_code == 200
        # Let the first session end so only the replay check can refuse.
        test_setup["expiry_manager"].expire_session("rec-001", force=True)

        res2 = client.post("/records/rec-001/breakglass", json=payload)
        assert res2.status_code == 400
        assert "Emergency assertion invalid" in res2.json()["detail"]

    def test_breakglass_facility_mismatch_fails(self, test_setup):
        """Assertion declared for facility-b is rejected at facility-a node (400)."""
        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, facility_id="facility-b"),
        )

        assert response.status_code == 400
        assert "FacilityMismatchError" in response.json()["detail"]

    def test_breakglass_assertion_for_another_patient_is_refused(self, test_setup):
        """An assertion bound to a different patient cannot open this record (403).

        Negative security test: the refusal must have no side effect, so the
        record stays GRANTED and a correct assertion still opens it afterwards.
        """
        client = test_setup["client"]
        wrong = client.post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, patient_id="patient-999"),
        )
        assert wrong.status_code == 403
        assert "not valid for this record" in wrong.json()["detail"]
        assert "rewrapped_dek_b64" not in wrong.text
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

        right = client.post("/records/rec-001/breakglass", json=_payload(test_setup))
        assert right.status_code == 200

    def test_breakglass_reopens_after_the_timebox_expired(self, test_setup):
        """Expiry returns the stored state to GRANTED, so break-glass works again.

        The expiry timer mirrors its transitions into the store (review N1),
        replacing the old reset that guessed from a missing session.
        """
        client = test_setup["client"]
        repo = test_setup["repo"]

        assert client.post(
            "/records/rec-001/breakglass", json=_payload(test_setup)
        ).status_code == (200)
        assert repo.get_lifecycle_state("rec-001") == LifecycleState.EMERGENCY_OPEN

        # While the session is live a second unlock joins it (ADR-0057).
        joined = client.post("/records/rec-001/breakglass", json=_payload(test_setup))
        assert joined.status_code == 200, joined.text
        assert joined.json()["joined"] is True

        test_setup["expiry_manager"].expire_session("rec-001", force=True)
        assert repo.get_lifecycle_state("rec-001") == LifecycleState.GRANTED

        # The rotation handed new shares to the holders (ADR-0069); the shares
        # presented before expiry open nothing any more.
        old = test_setup["em_shares"]
        stale = client.post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, shares=_hex(_points(old, 1, 3, 4))),
        )
        assert stale.status_code == 403, stale.text
        assert "rewrapped_dek_b64" not in stale.text

        second = client.post("/records/rec-001/breakglass", json=_payload(test_setup))
        assert second.status_code == 200, second.text

    def test_stale_emergency_open_returns_409_not_silent_reset(self, test_setup):
        """A stored EMERGENCY_OPEN with no session here is not silently reset (N1).

        The old ADR-0044 reset wrote GRANTED whenever this process held no
        session -- which raced another facility's live session.
        """
        repo = test_setup["repo"]
        repo.upsert_lifecycle_state("rec-001", LifecycleState.EMERGENCY_OPEN)

        response = test_setup["client"].post(
            "/records/rec-001/breakglass", json=_payload(test_setup)
        )
        assert response.status_code == 409
        assert "already emergency_open" in response.json()["detail"]
        assert repo.get_lifecycle_state("rec-001") == LifecycleState.EMERGENCY_OPEN


class TestConfiguredTrust:
    """Review F1: the facility, not the caller, decides which root it trusts."""

    def test_breakglass_rejects_assertion_chained_to_attacker_root(self, test_setup):
        """A forged root + 'facility-a' CA + 'dr-alice' leaf opens nothing (403).

        Paper claim: break-glass needs a clinician certificate from the
        federation's PKI; minting your own PKI does not help.
        """
        evil_root = generate_root_anchor()
        evil_ca_priv, evil_ca_pub = generate_ec_keypair()
        evil_ca = issue_facility_ca_certificate(evil_root, "facility-a", evil_ca_pub)
        evil_priv, evil_pub = generate_ec_keypair()
        evil_leaf = issue_clinician_certificate(
            evil_ca_priv, evil_ca, "dr-alice", evil_pub
        )
        sink = test_setup["audit_sink"]

        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, signing_key=evil_priv, certificate=evil_leaf),
        )

        assert response.status_code == 403, response.text
        assert "rewrapped_dek_b64" not in response.text
        denials = sink.of_type(EVENT_ACCESS_DENIED)
        assert [d["event_data"]["denied_by"] for d in denials] == ["breakglass_chain"]
        _assert_no_side_effects(test_setup, sink)

    def test_breakglass_rejects_certificate_from_unconfigured_ca(self, test_setup):
        """A CA name the facility was never configured with is refused (403)."""
        evil_root = generate_root_anchor()
        evil_ca_priv, evil_ca_pub = generate_ec_keypair()
        evil_ca = issue_facility_ca_certificate(evil_root, "facility-z", evil_ca_pub)
        evil_priv, evil_pub = generate_ec_keypair()
        evil_leaf = issue_clinician_certificate(
            evil_ca_priv, evil_ca, "dr-alice", evil_pub
        )

        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, signing_key=evil_priv, certificate=evil_leaf),
        )
        assert response.status_code == 403
        assert "configured facility CA" in response.json()["detail"]
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

    def test_breakglass_request_with_trust_fields_is_rejected(self, test_setup):
        """A caller still sending its own root or CA gets 422, not silent ignore."""
        pki = test_setup["pki"]
        payload = _payload(
            test_setup,
            trusted_root_certificate_pem=certificate_to_pem(
                pki["root"].certificate
            ).decode("ascii"),
        )
        response = test_setup["client"].post(
            "/records/rec-001/breakglass", json=payload
        )
        assert response.status_code == 422
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

    def test_breakglass_rejects_revoked_clinician_cert(self, test_setup):
        """A revoked clinician certificate cannot break the glass (403)."""
        pki = test_setup["pki"]
        sink = RecordingAuditSink()
        app = create_hospital_app(
            facility_id="facility-a",
            rotation_ports=test_setup["rotation"].ports,
            service_root=test_setup["pki"]["root"].certificate,
            repository=test_setup["repo"],
            expiry_manager=test_setup["expiry_manager"],
            trust=make_trust(pki, {pki["alice_cert"].serial_number}),
            audit_sink=sink,
        )
        response = (
            test_setup["pki"]["services"]
            .client(app, "facility-a")
            .post("/records/rec-001/breakglass", json=_payload(test_setup, target=app))
        )
        assert response.status_code == 403
        assert "CertificateRevokedError" in response.json()["detail"]
        _assert_no_side_effects(test_setup, sink)

    def test_breakglass_rejects_expired_clinician_cert_with_403_and_denial(
        self, test_setup
    ):
        """An expired clinician certificate is a 403 with a denial, not a 500."""
        pki = test_setup["pki"]
        expired = issue_clinician_certificate(
            pki["fa_priv"], pki["fa_cert"], "dr-alice", pki["alice_pub"], valid_days=0
        )
        sink = test_setup["audit_sink"]
        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, certificate=expired),
        )
        assert response.status_code == 403, response.text
        assert len(sink.of_type(EVENT_ACCESS_DENIED)) == 1
        _assert_no_side_effects(test_setup, sink)

    def test_breakglass_without_trust_or_expiry_manager_refused(self, test_setup):
        """No configured trust or no timer: 503, never an unbounded unlock (F1/F7)."""
        pki = test_setup["pki"]
        rotation = test_setup["rotation"].ports
        expiry = test_setup["expiry_manager"]
        for kwargs in (
            {"expiry_manager": expiry, "rotation_ports": rotation},
            {"trust": make_trust(pki), "rotation_ports": rotation},
            # No rotation: a session that cannot be rotated must not open.
            {"trust": make_trust(pki), "expiry_manager": expiry},
        ):
            app = create_hospital_app(
                facility_id="facility-a",
                service_root=pki["root"].certificate,
                repository=test_setup["repo"],
                audit_sink=RecordingAuditSink(),
                **kwargs,
            )
            response = (
                test_setup["pki"]["services"]
                .client(app, "facility-a")
                .post(
                    "/records/rec-001/breakglass", json=_payload(test_setup, target=app)
                )
            )
            assert response.status_code == 503
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])


class TestTimeBox:
    """Review F6: the configured duration is a ceiling the caller cannot raise."""

    def test_breakglass_duration_cannot_exceed_configured(self, test_setup):
        """Asking for 3 days at a facility configured for 60s gets 60s."""
        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, emergency_duration_seconds=3 * 24 * 3600),
        )
        assert response.status_code == 200, response.text
        expires_at = datetime.datetime.fromisoformat(response.json()["expires_at"])
        remaining = expires_at - datetime.datetime.now(datetime.timezone.utc)
        assert remaining <= datetime.timedelta(seconds=60)

    def test_breakglass_duration_above_three_days_rejected(self, test_setup):
        """A window longer than the 3-day maximum is a 422 before anything runs."""
        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, emergency_duration_seconds=3 * 24 * 3600 + 1),
        )
        assert response.status_code == 422
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

    def test_a_private_key_in_the_request_is_refused(self, test_setup):
        """No private key travels to the facility any more (ADR-0068): the old
        ``lifecycle_signing_key_pem`` field is a 422, not silently ignored."""
        payload = _payload(
            test_setup,
            lifecycle_signing_key_pem=private_key_to_pem(
                test_setup["pki"]["life_priv"]
            ).decode("ascii"),
        )
        response = test_setup["client"].post(
            "/records/rec-001/breakglass", json=payload
        )
        assert response.status_code == 422
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])


class TestFailureLeavesNoTrace:
    """Review F7 / N1: a failed or losing unlock changes nothing."""

    def test_audit_outage_during_breakglass_leaves_state_unchanged(self, test_setup):
        """If the re-wrap cannot be logged: 503, still GRANTED, no session."""

        def failing_sink(event_type, event_data, actor_id, correlation_id):
            if event_type == EVENT_FEDERATION_REWRAP:
                raise AuditServiceError("audit down")

        app = create_hospital_app(
            facility_id="facility-a",
            rotation_ports=test_setup["rotation"].ports,
            service_root=test_setup["pki"]["root"].certificate,
            repository=test_setup["repo"],
            expiry_manager=test_setup["expiry_manager"],
            trust=make_trust(test_setup["pki"]),
            audit_sink=failing_sink,
        )
        response = (
            test_setup["pki"]["services"]
            .client(app, "facility-a")
            .post("/records/rec-001/breakglass", json=_payload(test_setup, target=app))
        )
        assert response.status_code == 503
        assert "rewrapped_dek_b64" not in response.text
        _assert_no_side_effects(test_setup, test_setup["audit_sink"])

        # Setup was valid: with the audit back, the same record opens.
        ok = test_setup["client"].post(
            "/records/rec-001/breakglass", json=_payload(test_setup)
        )
        assert ok.status_code == 200

    def test_concurrent_breakglass_one_wins(self, test_setup):
        """Two simultaneous opens of one record: exactly one transition wins.

        The other request either loses the claim (409) or joins the session
        the winner opened (200, ADR-0057); it never signs a second transition.
        """
        client = test_setup["client"]
        payloads = [_payload(test_setup), _payload(test_setup)]
        results: list[int] = []
        barrier = threading.Barrier(2)

        def open_record(payload):
            barrier.wait()
            results.append(
                client.post("/records/rec-001/breakglass", json=payload).status_code
            )

        threads = [threading.Thread(target=open_record, args=(p,)) for p in payloads]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert 200 in results and set(results) <= {200, 409}
        assert len(test_setup["repo"].transition_events) == 1
        assert (
            test_setup["repo"].get_lifecycle_state("rec-001")
            == LifecycleState.EMERGENCY_OPEN
        )


class TestJoinOpenSession:
    """ADR-0057: a record already open is joined, not refused -- but every
    viewer still needs the threshold and a committed audit entry, and joining
    never extends the window."""

    def _open(self, test_setup, **extra):
        response = test_setup["client"].post(
            "/records/rec-001/breakglass", json=_payload(test_setup, **extra)
        )
        assert response.status_code == 200, response.text
        return response.json()

    def test_second_unlock_joins_without_transition_or_extension(self, test_setup):
        """The clinician can see the record again inside the same window."""
        pki = test_setup["pki"]
        sink = test_setup["audit_sink"]
        first = self._open(test_setup)

        second = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, emergency_duration_seconds=3 * 24 * 3600),
        )

        assert second.status_code == 200, second.text
        body = second.json()
        assert body["joined"] is True
        assert body["transition_event"] is None
        assert body["expires_at"] == first["expires_at"]
        dek_first = _unwrap_rewrapped_dek(
            base64.b64decode(first["rewrapped_dek_b64"]),
            pki["alice_pre_priv"],
            "rec-001",
        )
        dek_second = _unwrap_rewrapped_dek(
            base64.b64decode(body["rewrapped_dek_b64"]),
            pki["alice_pre_priv"],
            "rec-001",
        )
        assert dek_second == dek_first
        assert len(test_setup["repo"].transition_events) == 1
        assert len(sink.of_type(EVENT_FEDERATION_REWRAP)) == 2

    def test_join_with_one_share_releases_nothing(self, test_setup):
        """Joining is not a shortcut around the 3-of-4 threshold."""
        sink = test_setup["audit_sink"]
        em_shares = test_setup["em_shares"]
        self._open(test_setup)

        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(test_setup, shares=_hex(_points(em_shares, 1))),
        )

        assert response.status_code == 400
        assert "requires 3 unique shares" in response.json()["detail"]
        assert "rewrapped_dek_b64" not in response.text
        assert len(sink.of_type(EVENT_FEDERATION_REWRAP)) == 1
        assert [
            d["event_data"]["denied_by"] for d in sink.of_type(EVENT_ACCESS_DENIED)
        ] == ["breakglass_gate"]

    def test_join_after_window_ran_out_is_refused(self, test_setup):
        """A window past expires_at cannot be joined, even before the sweep."""
        sink = test_setup["audit_sink"]
        self._open(test_setup, emergency_duration_seconds=0.05)
        time.sleep(0.1)  # the monitor is not running; the session is only late

        response = test_setup["client"].post(
            "/records/rec-001/breakglass", json=_payload(test_setup)
        )

        assert response.status_code == 409
        assert "no live session to join" in response.json()["detail"]
        assert "rewrapped_dek_b64" not in response.text
        assert len(sink.of_type(EVENT_FEDERATION_REWRAP)) == 1

    def _bob(self, test_setup) -> dict:
        """Dr. Bob (facility-b CA) asking facility-a, as the custodian routes him."""
        pki = test_setup["pki"]
        return _payload(
            test_setup,
            clinician_id="dr-bob",
            signing_key=pki["bob_priv"],
            certificate=pki["bob_cert"],
            pre_rewrap_key=pki["bob_pre_pub"],
        )

    def test_clinician_of_same_facility_joins(self, test_setup):
        """A second facility-a clinician (the care team on scene) joins."""
        pki = test_setup["pki"]
        first = self._open(test_setup)
        carol_priv, carol_pub = generate_ec_keypair()
        carol_cert = issue_clinician_certificate(
            pki["fa_priv"], pki["fa_cert"], "dr-carol", carol_pub
        )

        response = test_setup["client"].post(
            "/records/rec-001/breakglass",
            json=_payload(
                test_setup,
                clinician_id="dr-carol",
                signing_key=carol_priv,
                certificate=carol_cert,
            ),
        )

        assert response.status_code == 200, response.text
        assert response.json()["joined"] is True
        assert response.json()["expires_at"] == first["expires_at"]

    def test_clinician_of_another_facility_cannot_join_open_session(self, test_setup):
        """Paper claim: an open emergency session is joinable only by the
        opener's facility; a credentialed clinician elsewhere gets nothing."""
        repo = test_setup["repo"]
        sink = test_setup["audit_sink"]
        self._open(test_setup)

        response = test_setup["client"].post(
            "/records/rec-001/breakglass", json=self._bob(test_setup)
        )

        assert response.status_code == 403, response.text
        assert "cannot join" in response.json()["detail"]
        assert "rewrapped_dek_b64" not in response.text
        assert len(sink.of_type(EVENT_FEDERATION_REWRAP)) == 1
        assert [
            d["event_data"]["denied_by"] for d in sink.of_type(EVENT_ACCESS_DENIED)
        ] == ["breakglass_join_facility"]
        assert len(repo.transition_events) == 1
        assert repo.get_lifecycle_state("rec-001") == LifecycleState.EMERGENCY_OPEN

        # Setup was valid: the same request opens the record once the session
        # has ended, so only the facility check refused it above.
        test_setup["expiry_manager"].expire_session("rec-001", force=True)
        reopened = test_setup["client"].post(
            "/records/rec-001/breakglass", json=self._bob(test_setup)
        )
        assert reopened.status_code == 200, reopened.text
        assert reopened.json()["joined"] is False

    def test_join_with_audit_outage_releases_nothing(self, test_setup):
        """Log-before-release holds for every viewer, not only the opener."""
        self._open(test_setup)

        def failing_sink(event_type, event_data, actor_id, correlation_id):
            if event_type == EVENT_FEDERATION_REWRAP:
                raise AuditServiceError("audit down")

        app = create_hospital_app(
            facility_id="facility-a",
            rotation_ports=test_setup["rotation"].ports,
            service_root=test_setup["pki"]["root"].certificate,
            repository=test_setup["repo"],
            expiry_manager=test_setup["expiry_manager"],
            trust=make_trust(test_setup["pki"]),
            audit_sink=failing_sink,
        )
        response = (
            test_setup["pki"]["services"]
            .client(app, "facility-a")
            .post("/records/rec-001/breakglass", json=_payload(test_setup, target=app))
        )

        assert response.status_code == 503
        assert "rewrapped_dek_b64" not in response.text
        assert len(test_setup["repo"].transition_events) == 1


class TestEveryRefusalIsAudited:
    """Review F8: each refusal appends exactly one denial with its own reason."""

    @pytest.mark.parametrize(
        ("case", "denied_by"),
        [
            ("single_share", "breakglass_gate"),
            ("aliased_share", "breakglass_gate"),
            ("wrong_shares", "breakglass_gate"),
            ("unknown_record", "record_not_found"),
            ("other_patient", "breakglass_patient_binding"),
            ("wrong_facility", "breakglass_assertion"),
        ],
    )
    def test_every_breakglass_refusal_appends_one_denial(
        self, test_setup, case, denied_by
    ):
        em_shares = test_setup["em_shares"]
        path = "/records/rec-001/breakglass"
        if case == "single_share":
            payload = _payload(test_setup, shares=_hex(_points(em_shares, 1)))
        elif case == "aliased_share":
            x, share = em_shares[0]
            payload = _payload(
                test_setup,
                shares=[(x, share.hex()), (x + PRIME_MODULUS, share.hex())],
            )
        elif case == "wrong_shares":
            # Three genuine-looking shares of some other key: unwrap fails.
            from breakglass.emergency_key import (
                generate_emergency_key,
                split_emergency_key,
            )

            other = split_emergency_key(generate_emergency_key())
            payload = _payload(test_setup, shares=_hex(_points(other, 1, 3, 4)))
        elif case == "unknown_record":
            path = "/records/rec-nope/breakglass"
            payload = _payload(test_setup, record_id="rec-nope")
        elif case == "other_patient":
            payload = _payload(test_setup, patient_id="patient-999")
        else:
            payload = _payload(test_setup, facility_id="facility-b")

        sink = test_setup["audit_sink"]
        response = test_setup["client"].post(path, json=payload)

        assert response.status_code in (400, 403, 404), response.text
        denials = sink.of_type(EVENT_ACCESS_DENIED)
        assert [d["event_data"]["denied_by"] for d in denials] == [denied_by]
        _assert_no_side_effects(test_setup, sink)
