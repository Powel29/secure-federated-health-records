"""Key material never appears in a result's repr() (F26, CONVENTIONS §2 rule 3).

A dataclass's default repr prints every field, so a log line or traceback that
formats one of these results would print the key. Each field below must be
declared ``field(repr=False)``.
"""

from __future__ import annotations

import dataclasses

import pytest
from breakglass.gate import EmergencyUnlockResult
from lifecycle.expiry import EmergencySession
from lifecycle.rotation import RotationPlan
from records.ingest import IngestResult
from records.revocation import RevocationResult

_KEY_FIELDS = [
    (EmergencyUnlockResult, "emergency_key"),
    (EmergencyUnlockResult, "rewrapped_dek"),
    (EmergencySession, "emergency_key"),
    (EmergencySession, "rotation_plan"),
    (RotationPlan, "shares"),
    (RotationPlan, "search_tokens"),
    (RotationPlan, "compiled_policy"),
    (IngestResult, "root_secret"),
    (IngestResult, "search_tokens"),
    (RevocationResult, "new_root_secret"),
]


@pytest.mark.parametrize(("cls", "name"), _KEY_FIELDS)
def test_result_reprs_contain_no_key_bytes(cls, name):
    """Logging a result object cannot leak its key material."""
    fields = {f.name: f for f in dataclasses.fields(cls)}
    assert name in fields, f"{cls.__name__} has no field {name}"
    assert fields[name].repr is False, f"{cls.__name__}.{name} is printed by repr()"
