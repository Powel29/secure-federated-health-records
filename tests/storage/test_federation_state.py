"""Separate facility processes must see policies and signed consent artifacts."""

from __future__ import annotations

import json
import subprocess
import sys
from uuid import uuid4

from api.repository import PostgresStorageRepository
from consent.service import create_consent_grant, create_consent_request
from contracts.enums import ConsentStatus
from crypto_core import generate_ec_keypair, generate_key
from policy import compile_policy
from storage.policy_codec import encode_policy

from tests.policy.test_engine import _clinical_policy, _full_keyring


def test_policy_and_consent_survive_a_new_process(conn):
    """A fresh process reads persisted state, never a shared Python dictionary."""
    repo = PostgresStorageRepository(conn)
    policy_id = str(uuid4())
    policy = compile_policy(_clinical_policy(), generate_key(), _full_keyring())
    private_key, _ = generate_ec_keypair()
    request = create_consent_request(
        patient_id="patient-state-test",
        requester_id="clinician-state-test",
        scope=("record-state-test",),
        purpose="deployment regression",
        requester_signing_key=private_key,
    )
    grant = create_consent_grant(
        request=request,
        status=ConsentStatus.GRANTED,
        grantee_id=request.requester_id,
        patient_signing_key=private_key,
    )
    repo.store_compiled_policy(policy_id, policy)
    repo.store_consent_request(request)
    repo.store_consent_grant(grant)
    conn.commit()
    script = """
import json, os, sys
from uuid import UUID
import psycopg
from api.repository import PostgresStorageRepository
from storage.policy_codec import encode_policy
with psycopg.connect(os.environ['DATABASE_URL']) as conn:
    repo = PostgresStorageRepository(conn)
    print(json.dumps({
        'policy': encode_policy(repo.get_compiled_policy(sys.argv[1])),
        'request': repo.get_consent_request(UUID(sys.argv[2])).model_dump(mode='json'),
        'grant': repo.get_consent_grant(UUID(sys.argv[3])).model_dump(mode='json'),
        'mine': len(repo.list_consent_grants_by_patient('patient-state-test')),
        'other': len(repo.list_consent_grants_by_patient('other-patient')),
    }))
"""
    result = subprocess.run(
        [  # noqa: S603 - our interpreter and fixed regression script
            sys.executable,
            "-c",
            script,
            policy_id,
            str(request.request_id),
            str(grant.grant_id),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    assert data == {
        "policy": encode_policy(policy),
        "request": request.model_dump(mode="json"),
        "grant": grant.model_dump(mode="json"),
        "mine": 1,
        "other": 0,
    }
