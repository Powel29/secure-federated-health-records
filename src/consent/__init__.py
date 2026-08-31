"""Patient consent: request-then-approve gate over already-wrapped records (P3-2).

Consent is a **gate** at read time, not a re-wrap trigger. Records are wrapped
at ingest (P3-14) as ``OR(clinical_policy, owner:<patient_id>)`` via
``policy.author_policy_with_owner``. Consent verifies the patient's signed
intent before a clinician's crypto-satisfying read is permitted -- see
``docs/adr/0031-consent-as-gate.md`` for why this stays a gate and not a wrap.
"""

from consent.exceptions import (
    ConsentDeniedError,
    ConsentError,
    ConsentExpiredError,
    ConsentRevokedError,
    ConsentScopeError,
    ConsentSubjectError,
)
from consent.service import (
    authorize_read,
    create_consent_grant,
    create_consent_request,
    read_record_under_consent,
    revoke_consent_grant,
    verify_consent_grant,
    verify_consent_request,
)

__all__ = [
    "ConsentDeniedError",
    "ConsentError",
    "ConsentExpiredError",
    "ConsentRevokedError",
    "ConsentScopeError",
    "ConsentSubjectError",
    "authorize_read",
    "create_consent_grant",
    "create_consent_request",
    "read_record_under_consent",
    "revoke_consent_grant",
    "verify_consent_grant",
    "verify_consent_request",
]
