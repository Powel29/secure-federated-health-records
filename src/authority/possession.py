"""Proof that a credential's subject is the one asking for its key (ADR-0075).

Review F15: a credential is public signed data, so presenting a copy used to
be enough to release the attribute key it certifies. A release now also needs
a one-time ``RequestEnvelope`` (``breakglass.envelopes``, the existing
construction) signed with the subject's own key, verified here against the
subject's certificate:

- the caller is the credential's subject;
- it is addressed to this authority, for ``attribute_key.release``;
- its body is the credential's canonical bytes, so it proves possession for
  this credential only;
- it is recent, and its ``request_id`` has never been used.

The custodian holds every subject's key (ADR-0043), so this stops a copied
credential, not the custodian; that trust is stated in ADR-0043 and the paper.
"""

from __future__ import annotations

import datetime

from breakglass.envelopes import check_envelope_binding, verify_request_envelope
from breakglass.replay import ConsumedRequestIds
from contracts import AttributeCredential, RequestEnvelope
from crypto_core.types import ECPublicKey

from authority.exceptions import PossessionError
from authority.issuance import KEY_RELEASE_OPERATION, credential_binding


def verify_key_release_possession(
    credential: AttributeCredential,
    envelope: RequestEnvelope,
    subject_public_key: ECPublicKey,
    *,
    authority_id: str,
    consumed_store: ConsumedRequestIds,
    now: datetime.datetime | None = None,
) -> None:
    """Fail closed unless ``envelope`` proves the subject asks for this key.

    The subject's key must come from a certificate the caller has validated
    for ``credential.subject_id``; this function checks the envelope only.

    Args:
        credential: The credential presented for release.
        envelope: The subject-signed possession envelope.
        subject_public_key: The key from the subject's validated certificate.
        authority_id: This authority, which the envelope must be addressed to.
        consumed_store: One-time ids already used for releases here.
        now: The authority's clock; defaults to now (UTC).

    Raises:
        PossessionError: The envelope is for another subject or credential.
        EnvelopeOperationMismatchError / EnvelopeExpiredError: Another
            operation, or outside its time window.
        InvalidSignatureError: Not signed by the subject's key.
        EnvelopeRecipientMismatchError: Addressed to another service.
        ReplayedRequestError: Its ``request_id`` was used before.

    Security property:
        Checks without side effects run first; the one-time id is consumed
        last, after the signature, so a forged envelope cannot burn a real
        one's id.
    """
    if envelope.caller_id != credential.subject_id:
        raise PossessionError(
            f"possession envelope is from {envelope.caller_id!r}, not the "
            f"credential's subject {credential.subject_id!r}"
        )
    if envelope.body != credential_binding(credential):
        raise PossessionError("possession envelope is for another credential")
    check_envelope_binding(
        envelope,
        expected_operation=KEY_RELEASE_OPERATION,
        now=now if now is not None else datetime.datetime.now(datetime.timezone.utc),
    )
    verify_request_envelope(
        envelope,
        subject_public_key,
        authority_id,
        consumed_store=consumed_store,
    )
