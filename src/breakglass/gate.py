"""Emergency unlock gate: threshold reconstruction -> DEK recovery -> PRE
rewrap -> lifecycle transition (P3-5, ARCHITECTURE.md §8).

``open_emergency_access`` is the single choke point where a presented set of
emergency-key shares becomes a decryptable DEK for an emergency clinician.
It performs, in order:

1. Reject fewer than :data:`breakglass.emergency_key.THRESHOLD` *unique*
   shares (:class:`~breakglass.exceptions.InsufficientSharesError`) -- this is
   what makes break-glass a 2-of-3 threshold rather than a single custodian's
   decision, and is why the audit service's share alone cannot open a record
   (see ``tests/security/test_phase3_breakglass_security.py``).
2. Reconstruct the emergency key via ``shamir.combine_shares``.
3. Unwrap the record's DEK, which is AES-256-GCM wrapped under the emergency
   key (``contracts.records.DEKWrapping`` / ``records.service.unwrap_dek``).
4. Re-wrap the recovered DEK for delivery to the emergency clinician.
5. Emit a signed ``TransitionEvent`` moving the record from
   ``transition_source_state`` to ``EMERGENCY_OPEN``
   (``lifecycle.state_machine.create_transition_event``).
6. Return all three artefacts as a frozen result.

Precondition (caller's responsibility, not re-checked here): the
``EmergencyAssertion`` that authorized this call has already passed
``breakglass.assertion.validate_emergency_assertion``'s five-point check.
This gate trusts that has happened -- it is not itself a validation function,
and re-validating here would just duplicate a check the API layer (Phase 4)
already owns.

Design note on step 4 (PRE rewrap): ``contracts.records.DEKWrapping`` is
AES-256-GCM only -- it carries no ElGamal ciphertext components. So there is
no pre-existing PRE ciphertext for ``pre.elgamal.reencrypt(rk, c1, c2)`` to
transform (that call needs a ciphertext already encrypted under a persistent
custodian's PRE public key, which nothing in this codebase currently
produces for a DEK). Instead this gate uses the PRE primitive that *is* a
complete, self-contained operation: ``pre.elgamal.encapsulate_key`` mints a
fresh symmetric delivery key directly under the emergency clinician's PRE
public key (``pre_rewrap_key``), and the recovered DEK is AES-GCM-wrapped
under that delivery key, bound to ``record_id`` as AAD -- the same
AAD-binding convention ``records.service.wrap_dek`` uses. The four resulting
pieces (``c1``, ``c2``, the wrap nonce, and the wrapped DEK) are packed into
``EmergencyUnlockResult.rewrapped_dek`` using fixed-length framing (32 + 32 +
``GCM_NONCE_BYTES`` bytes, then the remainder), not the ``_FIELD_SEPARATOR``
convention -- unlike the signed canonical payloads elsewhere, this blob must
be split back into its parts by a downstream consumer, and ``c1``/``c2``/the
ciphertext are raw binary values that could legitimately contain the
separator byte. The clinician
recovers the DEK by decapsulating with their PRE private key and then
AES-GCM-decrypting; that recovery step lives in the API layer (Phase 4), not
here. A future phase introducing a genuine delegator -> delegatee PRE
transform for DEKs would need its own ``DEKWrapping``-shaped PRE envelope
contract; that is out of scope for this gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from contracts import TransitionEvent
from contracts.enums import LifecycleState, ReasonCode
from contracts.records import DEKWrapping
from crypto_core.symmetric import aes_gcm_encrypt
from crypto_core.types import ECPrivateKey
from lifecycle.state_machine import create_transition_event
from pre.elgamal import encapsulate_key
from records.service import unwrap_dek
from shamir.exceptions import InvalidShareError
from shamir.finite_field import PRIME_MODULUS
from shamir.split import combine_shares

from breakglass.emergency_key import THRESHOLD, Share
from breakglass.exceptions import InsufficientSharesError

# ASCII unit separator -- the project-wide convention (matches
# lifecycle/state_machine.py, breakglass/assertion.py) for building the
# canonical byte payload a signature covers. Deliberately NOT used to pack
# ``rewrapped_dek`` below: that convention only ever joins fields for a
# verifier that recomputes the same payload from its own copies of the
# fields and never re-splits the joined bytes. ``rewrapped_dek`` is the
# opposite case -- a consumer holding only the blob must split it back into
# c1, c2, nonce, and ciphertext -- and c1/c2/ciphertext are raw binary data
# that can legitimately contain the 0x1f separator byte, which would corrupt
# a split-based parse. Fixed-length framing (sizes below) avoids that
# ambiguity entirely.
_FIELD_SEPARATOR = b"\x1f"

# SAFE_PRIME_P in pre.elgamal is a 256-bit safe prime, so PRE ciphertext
# components (c1, c2) always fit in this many bytes.
_PRE_FIELD_BYTES = 32


@dataclass(frozen=True)
class EmergencyUnlockResult:
    """Everything ``open_emergency_access`` produces for one break-glass open.

    Attributes:
        emergency_key: The reconstructed 256-bit emergency key. Callers must
            not persist this (CLAUDE.md: "No key material in git. Ever." --
            the same rule applies to any durable store at runtime).
        rewrapped_dek: The DEK re-wrapped for the emergency clinician, packed
            as ``c1 (32B) || c2 (32B) || nonce (GCM_NONCE_BYTES) ||
            wrapped_dek`` (fixed-length framing; see module docstring,
            "Design note on step 4").
        transition_event: The signed ``TransitionEvent`` moving the record
            into ``EMERGENCY_OPEN``.
    """

    emergency_key: bytes = field(repr=False)
    rewrapped_dek: bytes = field(repr=False)
    transition_event: TransitionEvent


def open_emergency_access(
    *,
    shares_presented: list[Share],
    dek_wrapping: DEKWrapping,
    transition_source_state: LifecycleState,
    record_id: str,
    actor_id: str,
    correlation_id: str,
    reason_code: ReasonCode,
    lifecycle_signing_key: ECPrivateKey,
    pre_rewrap_key: int,
) -> EmergencyUnlockResult:
    """Open emergency access to one record from presented threshold shares.

    Args:
        shares_presented: Emergency-key shares gathered from custodians
            (``(x, share_bytes)`` tuples, ``shamir.split.split_secret``'s
            shape). May include more than ``THRESHOLD`` shares (redundancy)
            or duplicates; both are handled safely (see Raises).
        dek_wrapping: The record's DEK, AES-256-GCM wrapped under the
            emergency key.
        transition_source_state: The record's current lifecycle state
            (``GRANTED`` or ``REVOKED`` -- the two legal predecessors of
            ``EMERGENCY_OPEN``; anything else is rejected by the state
            machine).
        record_id: The record being opened.
        actor_id: The clinician (or service) causing the transition -- bound
            into the signed ``TransitionEvent``.
        correlation_id: Caller's audit-correlation identifier
            (``contracts.audit.AuditEntry.correlation_id``). This gate does
            not audit-log itself (C10 is a separate module); the caller uses
            this value to tie its own audit entry to this unlock.
        reason_code: Clinical justification for the emergency open --
            required by the state machine for any transition into
            ``EMERGENCY_OPEN`` (``lifecycle.state_machine.validate_transition``).
        lifecycle_signing_key: The actor's ECDSA-P256 private key, used to
            sign the emitted ``TransitionEvent``.
        pre_rewrap_key: The emergency clinician's ElGamal PRE public key
            (see module docstring, "Design note on step 4").

    Returns:
        An :class:`EmergencyUnlockResult` with the reconstructed emergency
        key, the DEK re-wrapped for the clinician, and the signed transition
        event.

    Raises:
        InsufficientSharesError: Fewer than ``THRESHOLD`` unique shares (by
            x-coordinate) were presented. A single custodian's share --
            including the audit service's -- is never enough on its own.
        shamir.exceptions.SecretSharingError (and subclasses): Reconstruction
            fails on corrupted or inconsistent shares.
        records.exceptions.UnwrappingError: The reconstructed emergency key
            does not authenticate against ``dek_wrapping`` (wrong key --
            e.g. from tampered shares -- or tampered wrapping).
        lifecycle.exceptions.IllegalTransitionError /
            MissingReasonCodeError: ``transition_source_state`` cannot
            legally reach ``EMERGENCY_OPEN``, or no ``reason_code`` was given.

    Security property:
        Fail-closed at every step: share sufficiency is checked before any
        reconstruction is attempted, DEK unwrap authenticates via AES-GCM
        before any key material is re-wrapped, and the transition event is
        only emitted -- meaning only signed -- once every prior step has
        succeeded. This function does not itself validate the
        ``EmergencyAssertion`` that authorized the caller to collect shares
        in the first place; see the module precondition.
    """
    unique_by_x: dict[int, bytes] = {}
    for x, share_bytes in shares_presented:
        # Range-check before counting: x and x + P would otherwise count as
        # two distinct shares of the same point (F27).
        if not 1 <= x < PRIME_MODULUS:
            raise InvalidShareError(f"share index x={x} outside 1..P-1")
        unique_by_x.setdefault(x, share_bytes)

    if len(unique_by_x) < THRESHOLD:
        raise InsufficientSharesError(
            f"break-glass requires {THRESHOLD} unique shares, got "
            f"{len(unique_by_x)}"
        )

    # --- Step 1/2: Reconstruct the emergency key from threshold shares ---
    emergency_key = combine_shares(list(unique_by_x.items()), k=THRESHOLD)

    # --- Step 3: Unwrap the record's DEK under the emergency key ---
    dek = unwrap_dek(wrapping=dek_wrapping, wrapping_key=emergency_key)

    # --- Step 4: Re-wrap the DEK for the emergency clinician via PRE ---
    (c1, c2), delivery_key = encapsulate_key(pre_rewrap_key)
    wrapped_dek, wrap_nonce = aes_gcm_encrypt(
        key=delivery_key, plaintext=dek, aad=record_id.encode("utf-8")
    )
    # Fixed-length framing, not the _FIELD_SEPARATOR convention -- see the
    # module-level comment above _FIELD_SEPARATOR for why.
    rewrapped_dek = (
        c1.to_bytes(_PRE_FIELD_BYTES, byteorder="big")
        + c2.to_bytes(_PRE_FIELD_BYTES, byteorder="big")
        + wrap_nonce
        + wrapped_dek
    )

    # --- Step 5: Emit the signed EMERGENCY_OPEN transition ---
    transition_event = create_transition_event(
        record_id=record_id,
        from_state=transition_source_state,
        to_state=LifecycleState.EMERGENCY_OPEN,
        actor_id=actor_id,
        signing_key=lifecycle_signing_key,
        reason_code=reason_code,
    )

    # correlation_id is not consumed here -- see Args docstring above.

    # --- Step 6: Return all artefacts ---
    return EmergencyUnlockResult(
        emergency_key=emergency_key,
        rewrapped_dek=rewrapped_dek,
        transition_event=transition_event,
    )
