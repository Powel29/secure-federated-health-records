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
5. Carry the ``TransitionEvent`` the clinician signed (ADR-0068, D8-a): the
   custodian signs it with the clinician's own key, so the event is
   attributable to them, and this gate verifies it against the clinician's
   already-validated certificate before any share is combined.
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
under that delivery key, bound to ``record_id`` as AAD. The four resulting
pieces (``c1``, ``c2``, the wrap nonce, and the wrapped DEK) are packed into
``EmergencyUnlockResult.rewrapped_dek`` using fixed-length framing (32 + 32 +
``GCM_NONCE_BYTES`` bytes, then the remainder): a downstream consumer splits
the blob back into its parts, and they are raw binary values. The clinician
recovers the DEK by decapsulating with their PRE private key and then
AES-GCM-decrypting; that recovery step lives in the API layer (Phase 4), not
here. A future phase introducing a genuine delegator -> delegatee PRE
transform for DEKs would need its own ``DEKWrapping``-shaped PRE envelope
contract; that is out of scope for this gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from contracts import TransitionEvent
from contracts.enums import LifecycleState
from contracts.records import DEKWrapping
from crypto_core.symmetric import aes_gcm_encrypt
from crypto_core.types import ECPublicKey
from lifecycle.exceptions import IllegalTransitionError
from lifecycle.state_machine import verify_transition_event
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
# ``rewrapped_dek`` below: a consumer holding only the blob must split it back
# into c1, c2, nonce, and ciphertext, and those are raw binary data, so the
# blob uses fixed-length framing (sizes below) rather than a separator.

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
        transition_event: The clinician-signed ``TransitionEvent`` moving
            the record into ``EMERGENCY_OPEN`` (ADR-0068).
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
    transition_event: TransitionEvent,
    actor_public_key: ECPublicKey,
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
            ``EMERGENCY_OPEN``); the event must start from it.
        record_id: The record being opened.
        transition_event: The ``TransitionEvent`` the clinician signed for
            this open (ADR-0068). The caller still applies it through the
            state machine, which consumes its one-time id.
        actor_public_key: The clinician's public key, from the certificate
            the caller already validated.
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
        crypto_core.exceptions.InvalidSignatureError: The event is not
            signed by ``actor_public_key``.
        lifecycle.exceptions.IllegalTransitionError /
            MissingReasonCodeError: The event is not this record's
            ``transition_source_state -> EMERGENCY_OPEN``, or carries no
            ``reason_code``.

    Security property:
        Fail-closed at every step, and the event is checked first: a forged,
        mis-signed or wrong-record event stops the gate before any share is
        combined. Share sufficiency is checked before any reconstruction, and
        the DEK unwrap authenticates via AES-GCM before any key material is
        re-wrapped. This function does not itself validate the
        ``EmergencyAssertion`` that authorized the caller to collect shares
        in the first place; see the module precondition.
    """
    # --- Step 5 first: the clinician's signed transition (ADR-0068) ---
    verify_transition_event(transition_event, actor_public_key)
    if (
        transition_event.record_id != record_id
        or transition_event.from_state is not transition_source_state
        or transition_event.to_state is not LifecycleState.EMERGENCY_OPEN
    ):
        raise IllegalTransitionError(
            "transition event is not this record's "
            f"{transition_source_state.value} -> emergency_open"
        )

    emergency_key, rewrapped_dek = _reconstruct_and_deliver(
        shares_presented, dek_wrapping, record_id, pre_rewrap_key
    )

    # --- Step 6: Return all artefacts ---
    return EmergencyUnlockResult(
        emergency_key=emergency_key,
        rewrapped_dek=rewrapped_dek,
        transition_event=transition_event,
    )


def join_emergency_access(
    *,
    shares_presented: list[Share],
    dek_wrapping: DEKWrapping,
    record_id: str,
    pre_rewrap_key: int,
) -> bytes:
    """Deliver the DEK of an already EMERGENCY_OPEN record to one more clinician.

    Steps 1-4 of :func:`open_emergency_access` -- the same threshold, the same
    reconstruction, the same PRE delivery -- with no transition, because the
    record is already open (ADR-0057). A second clinician, or the first one
    viewing the record again, still needs ``THRESHOLD`` shares, so the audit
    service still commits before its share is released for every viewer.

    Returns:
        The DEK packed for the clinician, framed as in
        :class:`EmergencyUnlockResult`.``rewrapped_dek``.

    Raises:
        Same as :func:`open_emergency_access`, minus the transition errors.
    """
    _, rewrapped_dek = _reconstruct_and_deliver(
        shares_presented, dek_wrapping, record_id, pre_rewrap_key
    )
    return rewrapped_dek


def _reconstruct_and_deliver(
    shares_presented: list[Share],
    dek_wrapping: DEKWrapping,
    record_id: str,
    pre_rewrap_key: int,
) -> tuple[bytes, bytes]:
    """Steps 1-4: threshold check, reconstruct, unwrap, PRE re-wrap.

    Returns ``(emergency_key, rewrapped_dek)``. Fails closed before any
    re-wrap if the shares are too few or do not open ``dek_wrapping``.
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
    # Fixed-length framing -- see the module-level comment above
    # _PRE_FIELD_BYTES for why.
    rewrapped_dek = (
        c1.to_bytes(_PRE_FIELD_BYTES, byteorder="big")
        + c2.to_bytes(_PRE_FIELD_BYTES, byteorder="big")
        + wrap_nonce
        + wrapped_dek
    )
    return emergency_key, rewrapped_dek
