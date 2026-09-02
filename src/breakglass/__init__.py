"""Break-glass module (C11). Public surface for emergency assertions and replay defense.

P3-10: Emergency assertion creation and five-point validation.
P3-11: Anti-replay consumed-ID stores and request envelope protection.
"""

from breakglass.assertion import (
    create_emergency_assertion,
    validate_emergency_assertion,
    verify_emergency_assertion_signature,
)
from breakglass.envelopes import (
    create_request_envelope,
    verify_request_envelope,
)
from breakglass.exceptions import (
    AssertionExpiredError,
    BreakglassError,
    ClinicianMismatchError,
    EnvelopeRecipientMismatchError,
    FacilityMismatchError,
    ReplayedAssertionError,
    ReplayedRequestError,
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
    # Envelope (P3-11)
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
    "ReplayedAssertionError",
    "ReplayedRequestError",
]
