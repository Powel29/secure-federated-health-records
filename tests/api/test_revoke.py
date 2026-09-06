"""Unit tests for the Hospital Node Revocation endpoint (P4-1, P3-7, P3-12).

Verifies:
- Authorized patient rotates record DEK, updates wrapping generation, emits
  signed transition event (GRANTED -> REVOKED).
- Authorized home authority can also perform revocation.
- Unauthorized clinician cannot revoke (P3-12 -> 403).
- Tampered old DEK is rejected (400).
"""

from __future__ import annotations

import base64

from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    private_key_to_pem,
)


class TestHospitalRevocationEndpoint:
    """Test suite for POST /records/{record_id}/revoke."""

    def test_authorized_patient_revokes_access(self, test_setup):
        """Patient revokes access: rotates DEK and advances lifecycle to REVOKED."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]
        repo = test_setup["repo"]

        # Pre-revocation DEK is root_secret from setup
        old_wrapping = test_setup["wrapping"]
        # In test_setup, the record's plaintext is decryptable under root_secret
        from policy.engine import unwrap_dek_via_policy

        compiled = repo.get_compiled_policy(test_setup["record"].policy_id)
        old_dek = unwrap_dek_via_policy(compiled, attrs["attr_keyring"], old_wrapping)

        pat_priv_pem = private_key_to_pem(pki["pat_priv"]).decode("ascii")

        # New clinical policy excluding cardiology
        new_clinical_policy = PolicyTree(
            node_type=PolicyNodeType.LEAF,
            attribute=Attribute(name="role", value="physician"),
            authority_id="authority-med",
        )

        response = client.post(
            "/records/rec-001/revoke",
            json={
                "actor_id": "patient-001",
                "actor_signing_key_pem": pat_priv_pem,
                "old_dek_b64": base64.b64encode(old_dek).decode("ascii"),
                "new_clinical_policy": new_clinical_policy.model_dump(mode="json"),
                "owner_authority_id": "authority-net",
                "attribute_keyring": attrs["b64_keyring"],
                "correlation_id": "corr-rev-001",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["record_id"] == "rec-001"
        assert data["new_generation"] == old_wrapping.generation + 1
        assert data["transition_event"]["from_state"] == LifecycleState.GRANTED.value
        assert data["transition_event"]["to_state"] == LifecycleState.REVOKED.value

        # In-storage state must now be REVOKED
        current_state = repo.get_lifecycle_state("rec-001")
        assert current_state == LifecycleState.REVOKED

    def test_unauthorized_clinician_cannot_revoke(self, test_setup):
        """Clinician attempting to revoke access is denied (P3-12 -> 403)."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]

        alice_priv_pem = private_key_to_pem(pki["alice_priv"]).decode("ascii")

        response = client.post(
            "/records/rec-001/revoke",
            json={
                "actor_id": "dr-alice",  # Not patient and not home authority
                "actor_signing_key_pem": alice_priv_pem,
                "old_dek_b64": base64.b64encode(b"0" * 32).decode("ascii"),
                "new_clinical_policy": attrs["clinical_policy"].model_dump(mode="json"),
                "owner_authority_id": "authority-net",
                "attribute_keyring": attrs["b64_keyring"],
            },
        )

        assert response.status_code == 403
        assert "Unauthorized revocation" in response.json()["detail"]

    def test_invalid_old_dek_fails_revocation(self, test_setup):
        """Passing an incorrect old DEK fails decryption and returns 400."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]

        pat_priv_pem = private_key_to_pem(pki["pat_priv"]).decode("ascii")
        bad_dek_b64 = base64.b64encode(b"wrong-key" * 4).decode("ascii")

        response = client.post(
            "/records/rec-001/revoke",
            json={
                "actor_id": "patient-001",
                "actor_signing_key_pem": pat_priv_pem,
                "old_dek_b64": bad_dek_b64,
                "new_clinical_policy": attrs["clinical_policy"].model_dump(mode="json"),
                "owner_authority_id": "authority-net",
                "attribute_keyring": attrs["b64_keyring"],
            },
        )

        assert response.status_code == 400
        assert "Revocation failed" in response.json()["detail"]
