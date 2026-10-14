"""Security checks cannot be skipped by leaving an argument out (review F21).

``consumed_store=None`` used to skip the replay check and
``revocation_registry=None`` the credential revocation check. Each is now a
required keyword argument with no default.
"""

from __future__ import annotations

import inspect

import pytest
from authority.issuance import verify_credential
from breakglass.assertion import validate_emergency_assertion
from breakglass.envelopes import verify_request_envelope

_REQUIRED = [
    (validate_emergency_assertion, "consumed_store"),
    (validate_emergency_assertion, "revoked_serials"),
    (verify_request_envelope, "consumed_store"),
    (verify_credential, "revocation_registry"),
]


@pytest.mark.parametrize(("func", "name"), _REQUIRED)
def test_security_check_argument_has_no_default(func, name):
    param = inspect.signature(func).parameters[name]
    assert (
        param.default is inspect.Parameter.empty
    ), f"{func.__name__}({name}=...) has a default, so the check can be skipped"
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
