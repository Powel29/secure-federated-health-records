"""Persisting encrypted policy shares must preserve cryptographic enforcement."""

from __future__ import annotations

import json

import pytest
from crypto_core import generate_key
from policy import compile_policy, reconstruct_root_secret
from policy.exceptions import PolicyDeniedError
from storage.policy_codec import decode_policy, encode_policy

from tests.policy.test_engine import _clinical_policy, _full_keyring


def test_stored_policy_still_requires_attribute_keys():
    keys = _full_keyring()
    secret = generate_key()
    original = compile_policy(_clinical_policy(), secret, keys)
    encoded = json.dumps(encode_policy(original))
    restored = decode_policy(json.loads(encoded))
    assert reconstruct_root_secret(restored, keys) == secret
    assert secret.hex() not in encoded
    assert all(key.hex() not in encoded for key in keys.values())
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(restored, {})
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(restored, {key: generate_key() for key in keys})


def test_tampered_stored_share_cannot_reconstruct():
    keys = _full_keyring()
    secret = generate_key()
    payload = encode_policy(compile_policy(_clinical_policy(), secret, keys))
    assert reconstruct_root_secret(decode_policy(payload), keys) == secret

    # Corrupt every possible branch; a healthy OR branch could still satisfy it.
    def corrupt(node):
        if node["node_type"] == "leaf":
            share = bytearray.fromhex(node["encrypted_share"])
            share[0] ^= 1
            node["encrypted_share"] = share.hex()
        else:
            for child in node["children"]:
                corrupt(child)

    corrupt(payload["root"])
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(decode_policy(payload), keys)


def test_unknown_storage_version_is_rejected():
    payload = encode_policy(
        compile_policy(_clinical_policy(), generate_key(), _full_keyring())
    )
    payload["version"] = 2
    with pytest.raises(ValueError, match="unsupported compiled policy format"):
        decode_policy(payload)
