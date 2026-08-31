"""Negative security tests for the P3-2 patient-consent gate (CONVENTIONS §5).

Backs the P3-2 exit criteria in WORKFLOW.md:

- a patient-issued grant is signed and scoped;
- an approved doctor reads within scope;
- an unauthorized doctor cannot read;
- only the patient can revoke it, and post-revocation reads fail closed.

Each test states the paper claim it backs and pairs its negative assertion
with a positive control in the same fixture, so a broken setup cannot
masquerade as a passing test (see the ``negative-security-test`` skill).
"""

from __future__ import annotations

import datetime

import pytest
from authority.issuance import (
    AttributeAuthority,
    generate_authority,
    issue_credential,
)
from consent import (
    ConsentExpiredError,
    ConsentRevokedError,
    ConsentScopeError,
    ConsentSubjectError,
    authorize_read,
    create_consent_grant,
    create_consent_request,
    read_record_under_consent,
    revoke_consent_grant,
)
from contracts import Attribute, AttributeCredential, Record
from contracts.enums import ConsentStatus, PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import (
    InvalidSignatureError,
    aes_gcm_encrypt,
    generate_ec_keypair,
    generate_key,
)
from policy import author_policy_with_owner, compile_policy
from policy.exceptions import PolicyDeniedError
from records import wrap_dek

MED = "authority-med"
NET = "authority-net"
PATIENT = "patient-101"


# ---------------------------------------------------------------------------
# Federation + record scaffold
# ---------------------------------------------------------------------------


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _federation() -> tuple[AttributeAuthority, AttributeAuthority, PolicyTree]:
    med = generate_authority(MED, frozenset({"role"}))
    net = generate_authority(NET, frozenset({"specialty", "owner"}))
    clinical = _leaf("role", "physician", MED)
    tree = author_policy_with_owner(clinical, PATIENT, NET)
    return med, net, tree


def _authoring_keyring(med, net):
    return {
        (MED, "role", "physician"): med.attribute_key("role", "physician"),
        (NET, "owner", PATIENT): net.attribute_key("owner", PATIENT),
    }


def _holder_keyring(*pairs: tuple[AttributeAuthority, AttributeCredential]):
    ring = {}
    for authority, cred in pairs:
        key = authority.get_attribute_key(cred)
        ring[(cred.issuer_id, cred.attribute.name, cred.attribute.value)] = key
    return ring


def _issue_physician_credential(med) -> AttributeCredential:
    now = datetime.datetime.now(datetime.timezone.utc)
    return issue_credential(
        med,
        "dr-alice",
        Attribute(name="role", value="physician"),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=365),
    )


def _build_record_and_wrapping(record_id: str, plaintext: bytes, root_secret: bytes):
    dek = generate_key()
    aad = record_id.encode("utf-8")
    ciphertext, nonce = aes_gcm_encrypt(key=dek, plaintext=plaintext, aad=aad)
    record = Record(
        record_id=record_id,
        patient_id=PATIENT,
        facility_id="facility-a",
        policy_id="pol-1",
        content_type="text/plain",
        ciphertext=ciphertext,
        nonce=nonce,
        aad=aad,
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    wrapping = wrap_dek(
        dek=dek,
        record_id=record_id,
        wrapping_key=root_secret,
        wrapped_for="pol-1",
    )
    return record, wrapping


def _make_grant(patient_sk, *, requester_id="dr-alice", grantee_id="dr-alice"):
    clinician_sk, _ = generate_ec_keypair()
    request = create_consent_request(
        patient_id=PATIENT,
        requester_id=requester_id,
        scope=("rec-1", "rec-2"),
        purpose="Cardiology follow-up",
        requester_signing_key=clinician_sk,
    )
    return (
        create_consent_grant(
            request=request,
            status=ConsentStatus.GRANTED,
            grantee_id=grantee_id,
            patient_signing_key=patient_sk,
        ),
        request,
    )


# ---------------------------------------------------------------------------
# Positive control: the approved doctor reads within scope
# ---------------------------------------------------------------------------


def test_sec_approved_doctor_reads_within_scope() -> None:
    """Security property: a grant + a policy-satisfying credential = a read.

    Backs the P3-2 "approved doctor reads within scope" exit. The two gates --
    patient consent and cryptographic policy -- both fire on the happy path;
    if this test fails, no other consent negative test proves anything (a
    broken setup would make every negative pass trivially).
    """
    med, net, tree = _federation()
    root_secret = generate_key()
    compiled = compile_policy(tree, root_secret, _authoring_keyring(med, net))

    record, wrapping = _build_record_and_wrapping("rec-1", b"ECG report", root_secret)

    physician = _issue_physician_credential(med)
    holder = _holder_keyring((med, physician))

    patient_sk, patient_pk = generate_ec_keypair()
    grant, _ = _make_grant(patient_sk)

    plaintext = read_record_under_consent(
        record=record,
        wrapping=wrapping,
        compiled_policy=compiled,
        grant=grant,
        grantee_id="dr-alice",
        patient_public_key=patient_pk,
        holder_keyring=holder,
    )
    assert plaintext == b"ECG report"


# ---------------------------------------------------------------------------
# Negative: unauthorized doctor cannot read
# ---------------------------------------------------------------------------


def test_sec_unauthorized_doctor_cannot_read() -> None:
    """Security property: a clinician with no policy-satisfying keys is refused.

    Even with a valid patient grant naming them, a clinician who does not
    hold ``role:physician`` cannot satisfy the record's policy and the
    crypto gate refuses. Grants do not conjure attribute keys.
    """
    med, net, tree = _federation()
    root_secret = generate_key()
    compiled = compile_policy(tree, root_secret, _authoring_keyring(med, net))

    record, wrapping = _build_record_and_wrapping("rec-1", b"labs", root_secret)

    patient_sk, patient_pk = generate_ec_keypair()
    grant, _ = _make_grant(patient_sk, grantee_id="dr-bob")

    # Positive control: the consent gate accepts (patient signed for dr-bob).
    authorize_read(
        grant,
        record_id="rec-1",
        grantee_id="dr-bob",
        patient_public_key=patient_pk,
    )

    # Negative: dr-bob holds no credentials, so policy reconstruction fails.
    with pytest.raises(PolicyDeniedError):
        read_record_under_consent(
            record=record,
            wrapping=wrapping,
            compiled_policy=compiled,
            grant=grant,
            grantee_id="dr-bob",
            patient_public_key=patient_pk,
            holder_keyring={},
        )


# ---------------------------------------------------------------------------
# Negative: reading outside grant scope
# ---------------------------------------------------------------------------


def test_sec_doctor_cannot_read_outside_scope() -> None:
    """Security property: a grant for rec-1..rec-2 does not permit rec-99.

    Even a crypto-satisfying clinician is refused if the record is outside
    what the patient signed. This is the primary defense against a valid
    grant being reused beyond the records the patient actually approved.
    """
    patient_sk, patient_pk = generate_ec_keypair()
    grant, _ = _make_grant(patient_sk)

    # Positive control: in-scope record is accepted by the gate.
    authorize_read(
        grant,
        record_id="rec-1",
        grantee_id="dr-alice",
        patient_public_key=patient_pk,
    )

    # Negative: out-of-scope read is refused BEFORE any crypto runs.
    with pytest.raises(ConsentScopeError):
        authorize_read(
            grant,
            record_id="rec-99",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
        )


# ---------------------------------------------------------------------------
# Negative: expired / denied / revoked grants
# ---------------------------------------------------------------------------


def test_sec_expired_consent_grant_denies_access() -> None:
    """Security property: a grant past ``expires_at`` cannot authorize a read.

    Consent is time-boxed by design (ARCHITECTURE §8 "nothing issues forever").
    A grant whose window has closed is treated as absent -- the caller must
    obtain a fresh grant, not renew this one.
    """
    patient_sk, patient_pk = generate_ec_keypair()
    grant, _ = _make_grant(patient_sk)

    # Positive control: within window, gate accepts.
    authorize_read(
        grant,
        record_id="rec-1",
        grantee_id="dr-alice",
        patient_public_key=patient_pk,
    )

    # Negative: one second past expiry, gate refuses.
    late = grant.expires_at + datetime.timedelta(seconds=1)
    with pytest.raises(ConsentExpiredError):
        authorize_read(
            grant,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
            at=late,
        )


def test_sec_revoked_consent_grant_denies_access() -> None:
    """Security property: a patient-signed revocation stops subsequent reads.

    Backs the P3-2 "only the patient can revoke it, and post-revocation
    decryption fails" exit. The revocation is a fresh signed ``ConsentGrant``
    with ``status=REVOKED`` answering the same ``request_id``.
    """
    patient_sk, patient_pk = generate_ec_keypair()
    grant, _ = _make_grant(patient_sk)

    # Positive control: pre-revocation, the grant authorizes.
    authorize_read(
        grant,
        record_id="rec-1",
        grantee_id="dr-alice",
        patient_public_key=patient_pk,
    )

    revocation = revoke_consent_grant(
        prior_grant=grant,
        patient_signing_key=patient_sk,
    )

    # Negative: the revocation refuses.
    with pytest.raises(ConsentRevokedError):
        authorize_read(
            revocation,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
        )


# ---------------------------------------------------------------------------
# Negative: only the patient can revoke; forged signatures rejected
# ---------------------------------------------------------------------------


def test_sec_unauthorized_party_cannot_revoke_consent() -> None:
    """Security property: revocation requires the patient's private key.

    Backs the P3-2 "only the patient can revoke" exit. A clinician, an
    admin, or any other party who signs a "revocation" produces an artifact
    that fails :func:`verify_consent_grant` against the patient's public key.
    """
    patient_sk, patient_pk = generate_ec_keypair()
    attacker_sk, _ = generate_ec_keypair()

    grant, _ = _make_grant(patient_sk)

    # Positive control: legitimate revocation verifies.
    real_revocation = revoke_consent_grant(
        prior_grant=grant,
        patient_signing_key=patient_sk,
    )
    with pytest.raises(ConsentRevokedError):
        authorize_read(
            real_revocation,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
        )

    # Negative: an attacker-signed "revocation" fails signature check first,
    # so it cannot even reach the status check -- crypto refuses it.
    forged_revocation = revoke_consent_grant(
        prior_grant=grant,
        patient_signing_key=attacker_sk,
    )
    with pytest.raises(InvalidSignatureError):
        authorize_read(
            forged_revocation,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=patient_pk,
        )


def test_sec_forged_consent_grant_signature_rejected() -> None:
    """Security property: a grant signed by anyone other than the patient fails.

    The signature is what makes consent attributable to the patient; without
    it, any party could fabricate a "grant" naming any clinician. This test
    proves the gate refuses one.
    """
    _, real_patient_pk = generate_ec_keypair()
    attacker_sk, _ = generate_ec_keypair()

    # Attacker builds a plausible-looking grant with their own key.
    attacker_request = create_consent_request(
        patient_id=PATIENT,
        requester_id="dr-alice",
        scope=("rec-1",),
        purpose="Cardiology",
        requester_signing_key=attacker_sk,
    )
    forged_grant = create_consent_grant(
        request=attacker_request,
        status=ConsentStatus.GRANTED,
        grantee_id="dr-alice",
        patient_signing_key=attacker_sk,
    )

    with pytest.raises(InvalidSignatureError):
        authorize_read(
            forged_grant,
            record_id="rec-1",
            grantee_id="dr-alice",
            patient_public_key=real_patient_pk,
        )


def test_sec_grant_cannot_be_replayed_against_a_different_grantee() -> None:
    """Security property: a grant naming dr-alice cannot authorize dr-bob.

    Consent is not transferable. A stolen or leaked grant naming one
    clinician does not become a bearer token any clinician can present.
    """
    patient_sk, patient_pk = generate_ec_keypair()
    grant, _ = _make_grant(patient_sk, grantee_id="dr-alice")

    # Positive control: dr-alice is accepted.
    authorize_read(
        grant,
        record_id="rec-1",
        grantee_id="dr-alice",
        patient_public_key=patient_pk,
    )

    # Negative: dr-bob presenting the same signed grant is refused.
    with pytest.raises(ConsentSubjectError):
        authorize_read(
            grant,
            record_id="rec-1",
            grantee_id="dr-bob",
            patient_public_key=patient_pk,
        )
