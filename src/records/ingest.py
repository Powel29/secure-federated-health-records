"""Record upload / ingest pipeline (P3-14).

Orchestrates the full ingest flow for a submitted health record:

1. Mint a fresh DEK and encrypt the plaintext (via ``records.service``).
2. Author the access policy with the ADR-0016 ``owner:<patient_id>`` leaf
   (via ``policy.engine.author_policy_with_owner``).
3. Generate a root secret (the wrapping key) and compile the policy tree
   against the authoring attribute keyring (via ``policy.engine.compile_policy``).
4. Wrap the DEK under the root secret (via ``records.service.wrap_dek``).
5. Derive and collect search-index tokens for each provided search term
   (via ``search.service.derive_search_token``).
6. Initialize lifecycle state to GRANTED.
7. Return all artefacts as a frozen result object for the caller to persist
   and audit-log.

Design choice: the function does NOT take a database connection or call
storage/audit directly.  It returns a self-contained ``IngestResult`` and the
caller (the API / service layer) persists and logs.  This keeps the ingest
logic purely testable without Postgres or a running audit service, and avoids
mixing C8/C7 responsibilities with C4/C10 (ARCHITECTURE.md §2).
"""

from __future__ import annotations

import datetime
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from contracts.clinical import ClinicalMetadata, latest_local_date
from contracts.enums import LifecycleState
from contracts.policy import PolicyTree
from contracts.records import DEKWrapping, Record
from crypto_core.symmetric import generate_key

from records.service import encrypt_record, wrap_dek

if TYPE_CHECKING:
    from policy.engine import AttributeKeyring, CompiledPolicy
    from search.service import SealedSearchTerms

# Re-export the type alias at module level for callers that only need the name.
AttributeKeyring = Mapping[tuple[str, str, str], bytes]


@dataclass(frozen=True)
class IngestResult:
    """All artefacts produced by ingesting one health record.

    The caller persists these to storage and emits an audit entry.  Every
    field is deterministically derived from the inputs; the only randomness
    is the DEK, the root secret, and the GCM nonces inside the crypto layer.
    """

    record: Record
    dek_wrapping: DEKWrapping
    compiled_policy: CompiledPolicy
    policy_tree: PolicyTree  # the authored tree (with owner leaf)
    # The wrapping key (caller must NOT persist this) and the search tokens
    # stay out of repr() so a log line or traceback never prints them (F26).
    root_secret: bytes = field(repr=False)
    lifecycle_state: LifecycleState
    search_tokens: dict[str, bytes] = field(repr=False)  # {term: coded_token}
    emergency_dek_wrapping: DEKWrapping | None = None
    # The term list sealed under the DEK, so expiry can re-index under a new
    # emergency key (ADR-0069). ``None`` when no terms were indexed.
    sealed_search_terms: SealedSearchTerms | None = None


def ingest_record(
    plaintext: bytes,
    patient_id: str,
    facility_id: str,
    owner_authority_id: str,
    clinical_policy: PolicyTree,
    attribute_keyring: AttributeKeyring,
    search_terms: list[str] | None = None,
    emergency_key: bytes | None = None,
    content_type: str = "application/json",
    aad: bytes | None = None,
    record_id: str | None = None,
    policy_id: str | None = None,
    created_at: datetime.datetime | None = None,
    clinical: ClinicalMetadata | None = None,
) -> IngestResult:
    """Ingest a health record: encrypt, compile policy, wrap DEK, index.

    Args:
        plaintext: Raw record content bytes.
        patient_id: The patient this record belongs to.
        facility_id: The facility that created / holds the record.
        owner_authority_id: The patient's home authority that owns the
            ``owner`` attribute namespace (ADR-0016, ADR-0019).
        clinical_policy: The clinical access branch (e.g. ``AND(role:physician,
            specialty:cardiology)``).  The function wraps it with the
            ``owner:<patient_id>`` leaf automatically.
        attribute_keyring: The compile-time keyring containing every
            authority's attribute keys referenced by the policy tree, keyed
            ``(authority_id, name, value)``.  Must include the owner key.
        search_terms: Optional plaintext search terms to index. Each term is
            HKDF-derived against ``emergency_key`` (ADR-0027).
        emergency_key: The emergency key for deriving search tokens.  Required
            if ``search_terms`` is non-empty.
        content_type: MIME type of the plaintext (default ``application/json``).
        aad: Optional associated authenticated data bound by GCM.
        record_id: Optional explicit record ID (auto-generated if omitted).
        policy_id: Optional policy identifier (auto-generated if omitted).
        created_at: Optional timestamp (defaults to current UTC).

    Returns:
        An :class:`IngestResult` containing the encrypted record, the DEK
        wrapping, the compiled policy, the authored tree, and the coded
        search tokens.

    Raises:
        ValueError: If ``search_terms`` is provided but ``emergency_key`` is
            missing.
        PolicyCompileError: If the attribute keyring is incomplete for the
            policy tree.

    Security properties:
        - Fresh 256-bit DEK per record (CONVENTIONS.md §2 rule 5).
        - Owner leaf baked into the policy at ingest, not retrofitted (ADR-0016).
        - DEK bound to record_id via AAD in the wrapping.
        - Search tokens derive from the emergency key; no emergency key means
          no indexing (search dies with the emergency, per P3-8 design).
    """
    if search_terms and not emergency_key:
        raise ValueError("emergency_key is required when search_terms are provided")

    # Lazy imports: policy.engine imports records (for unwrap_dek), so importing
    # it at module level from inside the records package creates a circular
    # import chain.  Deferring to call time breaks the cycle cleanly.
    from policy.engine import author_policy_with_owner, compile_policy
    from search.service import derive_search_token, seal_search_terms

    if created_at is None:
        created_at = datetime.datetime.now(datetime.timezone.utc)

    # Validate the supported structured report dates, not future follow-up plans.
    # Arbitrary PDFs/images remain opaque and require uploader-supplied metadata.
    if content_type == "application/json":
        try:
            document = json.loads(plaintext)
        except (ValueError, UnicodeDecodeError):
            document = None
        if isinstance(document, dict):
            encounter = document.get("encounter")
            dates = [document.get("clinical_date"), document.get("performed_at")]
            if isinstance(encounter, dict):
                dates.append(encounter.get("performed_at"))
            for value in dates:
                if value is None:
                    continue
                try:
                    event_date = datetime.date.fromisoformat(str(value)[:10])
                except ValueError:
                    continue  # not an ISO date: opaque content, like a PDF
                if event_date > latest_local_date():
                    raise ValueError("A clinical event date cannot be in the future")

    # Generate a policy_id if not provided.
    if policy_id is None:
        import uuid

        policy_id = f"pol-{uuid.uuid4()}"

    # --- Step 1: Mint DEK and encrypt the record payload ---
    record, dek = encrypt_record(
        plaintext=plaintext,
        patient_id=patient_id,
        facility_id=facility_id,
        policy_id=policy_id,
        content_type=content_type,
        aad=aad,
        record_id=record_id,
        created_at=created_at,
        clinical=clinical,
    )

    # --- Step 2: Author the policy tree with owner leaf (ADR-0016) ---
    authored_tree = author_policy_with_owner(
        clinical_policy=clinical_policy,
        patient_id=patient_id,
        owner_authority_id=owner_authority_id,
    )

    # --- Step 3: Generate root secret and compile the policy ---
    root_secret = generate_key(32)
    compiled = compile_policy(
        tree=authored_tree,
        root_secret=root_secret,
        attribute_keyring=attribute_keyring,
    )

    # --- Step 4: Wrap the DEK under the root secret ---
    wrapping = wrap_dek(
        dek=dek,
        record_id=record.record_id,
        wrapping_key=root_secret,
        wrapped_for=policy_id,
        generation=0,
        created_at=created_at,
    )

    # --- Step 5: Derive search tokens for each term ---
    search_tokens: dict[str, bytes] = {}
    sealed_terms = None
    if search_terms and emergency_key:
        for term in search_terms:
            search_tokens[term] = derive_search_token(emergency_key, term)
        sealed_terms = seal_search_terms(list(search_terms), dek, record.record_id)

    # Wrap DEK for emergency recovery if emergency_key is provided
    em_wrapping: DEKWrapping | None = None
    if emergency_key:
        em_wrapping = wrap_dek(
            dek=dek,
            record_id=record.record_id,
            wrapping_key=emergency_key,
            wrapped_for="emergency",
            generation=0,
            created_at=created_at,
        )

    # --- Step 6: Return all artefacts ---
    return IngestResult(
        record=record,
        dek_wrapping=wrapping,
        compiled_policy=compiled,
        policy_tree=authored_tree,
        root_secret=root_secret,
        lifecycle_state=LifecycleState.GRANTED,
        search_tokens=search_tokens,
        emergency_dek_wrapping=em_wrapping,
        sealed_search_terms=sealed_terms,
    )
