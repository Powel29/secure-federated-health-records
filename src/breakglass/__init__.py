"""Break-glass module (C11). Public surface for emergency assertions and replay defense.

P3-10: Emergency assertion creation and five-point validation.
P3-11: Anti-replay consumed-ID stores and request envelope protection.
P3-5: Emergency key generation/split and the threshold unlock gate.
"""

from breakglass.assertion import (
    create_emergency_assertion,
    validate_emergency_assertion,
    verify_emergency_assertion_signature,
)
from breakglass.emergency_key import (
    EMERGENCY_KEY_BYTES,
    THRESHOLD,
    TOTAL_SHARES,
    generate_emergency_key,
    split_emergency_key,
)
from breakglass.envelopes import (
    check_envelope_binding,
    create_request_envelope,
    verify_request_envelope,
)
from breakglass.exceptions import (
    AssertionExpiredError,
    BreakglassError,
    ClinicianMismatchError,
    EnvelopeRecipientMismatchError,
    FacilityMismatchError,
    InsufficientSharesError,
    ReplayedAssertionError,
    ReplayedRequestError,
)
from breakglass.gate import (
    EmergencyUnlockResult,
    join_emergency_access,
    open_emergency_access,
)
from breakglass.replay import (
    ConsumedAssertionIds,
    ConsumedRequestIds,
)

__all__ = [
    # Assertion (P3-10)
    "create_emergency_assertion",
    "validate_emergency_assertion",
    "verify_emergency_assertion_signature",
    # Emergency key + gate (P3-5)
    "EMERGENCY_KEY_BYTES",
    "THRESHOLD",
    "TOTAL_SHARES",
    "EmergencyUnlockResult",
    "generate_emergency_key",
    "join_emergency_access",
    "open_emergency_access",
    "split_emergency_key",
    # Envelope (P3-11, ADR-0066)
    "check_envelope_binding",
    "create_request_envelope",
    "verify_request_envelope",
    # Replay stores (P3-11)
    "ConsumedAssertionIds",
    "ConsumedRequestIds",
    # Exceptions
    "AssertionExpiredError",
    "BreakglassError",
    "ClinicianMismatchError",
    "EnvelopeRecipientMismatchError",
    "FacilityMismatchError",
    "InsufficientSharesError",
    "ReplayedAssertionError",
    "ReplayedRequestError",
]
