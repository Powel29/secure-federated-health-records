"""The forced rotation at emergency expiry, computed in full (ADR-0069, D3-a).

ARCHITECTURE.md §5 step 7: when the time-box runs out the record goes through
"forced rotation back to baseline", and "search tokens are dead because the
key they derive from is gone". :func:`plan_rotation` computes every artefact
that rotation replaces, from material the facility holds while the emergency
session is open:

1. **New DEK.** The record is decrypted with the DEK the emergency key
   unwraps and re-encrypted under a fresh DEK (``records.service``).
2. **New policy root secret.** The record's access tree is read back from its
   compiled policy and compiled again under a fresh root secret with the
   authorities' authoring keys (``policy.engine``), and the new DEK is wrapped
   under it. The old root secret -- and every unwrap it allowed -- is dead.
3. **New emergency key.** A fresh key is split 2-of-3
   (``breakglass.emergency_key``) and the new DEK is wrapped under it. The old
   shares no longer open anything.
4. **New search tokens.** The record's term list, sealed under its DEK at
   ingest (``search.service.seal_search_terms``), is opened with the old DEK,
   re-derived under the new emergency key, and sealed again under the new DEK.

No step is a new construction: each reuses the module that built the same
artefact at ingest. The function is pure -- the caller (the facility) fetches
the authoring keys, persists the plan atomically and hands the new shares to
their holders. It is imported by the facility API only, never by
``lifecycle.expiry``, so ``lifecycle`` still does not import ``breakglass``
at module load.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field

from breakglass.emergency_key import Share, generate_emergency_key, split_emergency_key
from contracts.policy import PolicyTree
from contracts.records import DEKWrapping, Record
from crypto_core.symmetric import generate_key
from policy.engine import (
    CompiledPolicy,
    compile_policy,
    policy_tree_of,
    unwrap_dek_via_policy,
)
from records.service import decrypt_record, encrypt_record, unwrap_dek, wrap_dek
from search.service import (
    SealedSearchTerms,
    derive_search_token,
    open_search_terms,
    seal_search_terms,
)

EMERGENCY_WRAPPED_FOR = "emergency"
_ROOT_SECRET_BYTES = 32


@dataclass(frozen=True)
class RotationPlan:
    """Everything one rotation replaces. Holds no key in ``repr``.

    Attributes:
        record: The record re-encrypted under a fresh DEK, with a new policy id.
        previous_nonce: The GCM nonce of the ciphertext being replaced; the
            store applies the plan only if that ciphertext is still current.
        compiled_policy: The same access tree compiled under a fresh root.
        baseline_wrapping: The fresh DEK under the fresh root secret.
        emergency_wrapping: The fresh DEK under the fresh emergency key, one
            generation after the wrapping it replaces.
        shares: The fresh emergency key's 2-of-3 split, ``(x, bytes)`` each.
        search_tokens: The record's search index under the fresh emergency key.
        sealed_search_terms: The term list sealed under the fresh DEK, or
            ``None`` if the record was ingested without one.
    """

    record: Record
    previous_nonce: bytes
    compiled_policy: CompiledPolicy = field(repr=False)
    baseline_wrapping: DEKWrapping
    emergency_wrapping: DEKWrapping
    shares: tuple[Share, ...] = field(repr=False)
    search_tokens: tuple[bytes, ...] = field(repr=False)
    sealed_search_terms: SealedSearchTerms | None = field(repr=False)

    @property
    def generation(self) -> int:
        """The emergency-key generation this rotation creates."""
        return self.emergency_wrapping.generation

    def share(self, x: int) -> Share:
        """The new share at x-coordinate ``x``."""
        for share in self.shares:
            if share[0] == x:
                return share
        raise KeyError(f"no share at x={x}")


def plan_rotation(
    *,
    record: Record,
    emergency_wrapping: DEKWrapping,
    emergency_key: bytes,
    baseline_generation: int,
    compiled_policy: CompiledPolicy,
    authoring_keyring: Mapping[tuple[str, str, str], bytes],
    sealed_search_terms: SealedSearchTerms | None,
) -> RotationPlan:
    """Compute a full rotation of one record's keys (ADR-0069).

    Args:
        record: The record as it stands during the emergency session.
        emergency_wrapping: Its DEK wrapped under ``emergency_key``.
        emergency_key: The session's reconstructed emergency key.
        baseline_generation: Generation of the record's current policy
            wrapping; the new one is one higher.
        compiled_policy: The record's current compiled policy, read for its
            tree only.
        authoring_keyring: An authoring key for every leaf of that tree,
            keyed ``(authority_id, name, value)``.
        sealed_search_terms: The record's sealed term list, if it has one.

    Returns:
        The :class:`RotationPlan`.

    Raises:
        UnwrappingError: ``emergency_key`` does not open ``emergency_wrapping``.
        DecryptionError: The DEK does not open the record.
        PolicyCompileError: The keyring lacks a key for a leaf of the tree.
        SearchTermsError: The sealed term list does not open under the DEK.

    Security property:
        Every key that could open the record before -- the DEK, the policy
        root secret, the emergency key -- is replaced by a fresh one from the
        CSPRNG (CONVENTIONS.md §2 rules 2 and 5), and every ciphertext is
        produced with a fresh nonce. The plaintext exists only inside this
        call.
    """
    return _plan_from_dek(
        record=record,
        old_dek=unwrap_dek(emergency_wrapping, emergency_key),
        emergency_generation=emergency_wrapping.generation,
        baseline_generation=baseline_generation,
        tree=policy_tree_of(compiled_policy),
        authoring_keyring=authoring_keyring,
        sealed_search_terms=sealed_search_terms,
    )


def plan_rotation_via_policy(
    *,
    record: Record,
    baseline_wrapping: DEKWrapping,
    emergency_generation: int,
    compiled_policy: CompiledPolicy,
    authoring_keyring: Mapping[tuple[str, str, str], bytes],
    sealed_search_terms: SealedSearchTerms | None,
    new_tree: PolicyTree | None = None,
) -> RotationPlan:
    """Compute a full rotation without an emergency session (ADR-0072, ADR-0073).

    Used where no emergency key is held: a patient's revocation (with
    ``new_tree``, the revoked access structure) and the recovery of an
    emergency session whose key was lost to a facility restart or a crash
    mid-rotation. The old DEK is recovered through the record's own policy
    (``policy.engine.unwrap_dek_via_policy``) with the authoring keys of its
    leaves -- the keys the facility already fetches for every rotation
    (ADR-0069). Everything after that is :func:`plan_rotation`'s computation.

    Args:
        record: The record as stored.
        baseline_wrapping: Its DEK wrapped under ``compiled_policy``'s root.
        emergency_generation: Generation of its current emergency wrapping;
            the new one is one higher.
        compiled_policy: The record's current compiled policy.
        authoring_keyring: An authoring key for every leaf of the current
            tree and of ``new_tree``, keyed ``(authority_id, name, value)``.
        sealed_search_terms: The record's sealed term list, if it has one.
        new_tree: The access tree to compile the new root under; ``None``
            keeps the current one.

    Raises:
        PolicyDeniedError: The keyring does not open the current policy.
        UnwrappingError: The policy root does not open ``baseline_wrapping``.
        DecryptionError: The DEK does not open the record.
        PolicyCompileError: The keyring lacks a key for a leaf of the new tree.

    Security property:
        Same as :func:`plan_rotation`. Recovering the DEK this way gives the
        facility no power it lacks at every expiry: authoring keys and holder
        keys are the same keys (ADR-0026), and the facility already fetches
        them for each leaf to recompile the policy.
    """
    return _plan_from_dek(
        record=record,
        old_dek=unwrap_dek_via_policy(
            compiled_policy, authoring_keyring, baseline_wrapping
        ),
        emergency_generation=emergency_generation,
        baseline_generation=baseline_wrapping.generation,
        tree=new_tree if new_tree is not None else policy_tree_of(compiled_policy),
        authoring_keyring=authoring_keyring,
        sealed_search_terms=sealed_search_terms,
    )


def _plan_from_dek(
    *,
    record: Record,
    old_dek: bytes,
    emergency_generation: int,
    baseline_generation: int,
    tree: PolicyTree,
    authoring_keyring: Mapping[tuple[str, str, str], bytes],
    sealed_search_terms: SealedSearchTerms | None,
) -> RotationPlan:
    """Steps 1-4 of the module docstring, from the record's current DEK."""
    plaintext = decrypt_record(record, old_dek)
    terms = (
        open_search_terms(sealed_search_terms, old_dek, record.record_id)
        if sealed_search_terms is not None
        else []
    )

    new_policy_id = f"pol-{uuid.uuid4()}"
    rotated, new_dek = encrypt_record(
        plaintext=plaintext,
        patient_id=record.patient_id,
        facility_id=record.facility_id,
        policy_id=new_policy_id,
        content_type=record.content_type,
        aad=record.aad,
        record_id=record.record_id,
        created_at=record.created_at,
        clinical=record.clinical,
    )

    root_secret = generate_key(_ROOT_SECRET_BYTES)
    recompiled = compile_policy(
        tree=tree,
        root_secret=root_secret,
        attribute_keyring=authoring_keyring,
    )
    baseline = wrap_dek(
        dek=new_dek,
        record_id=record.record_id,
        wrapping_key=root_secret,
        wrapped_for=new_policy_id,
        generation=baseline_generation + 1,
    )

    new_emergency_key = generate_emergency_key()
    shares = tuple(split_emergency_key(new_emergency_key))
    emergency = wrap_dek(
        dek=new_dek,
        record_id=record.record_id,
        wrapping_key=new_emergency_key,
        wrapped_for=EMERGENCY_WRAPPED_FOR,
        generation=emergency_generation + 1,
    )

    tokens = tuple(derive_search_token(new_emergency_key, term) for term in terms)
    resealed = (
        seal_search_terms(terms, new_dek, record.record_id)
        if sealed_search_terms is not None
        else None
    )

    return RotationPlan(
        record=rotated,
        previous_nonce=record.nonce,
        compiled_policy=recompiled,
        baseline_wrapping=baseline,
        emergency_wrapping=emergency,
        shares=shares,
        search_tokens=tokens,
        sealed_search_terms=resealed,
    )
