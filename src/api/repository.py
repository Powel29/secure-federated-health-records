"""Storage repository abstraction for the Hospital Node API (P4-1, C14).

Decouples API orchestration routes from underlying storage engines. Provides:
- ``StorageRepository`` protocol defining the operations needed by the hospital node.
- ``InMemoryStorageRepository``: Complete, thread-safe in-memory implementation for
  fast, zero-dependency unit tests and standalone mock environments.
- ``PostgresStorageRepository``: Production database implementation that delegates
  to ``storage.repositories`` and ``federation.discovery``.
"""

from __future__ import annotations

import threading
from typing import Protocol
from uuid import UUID

import psycopg
from contracts.audit import AuditEntry
from contracts.consent import ConsentGrant, ConsentRequest
from contracts.enums import LifecycleState
from contracts.lifecycle import TransitionEvent
from contracts.records import DEKWrapping, Record
from federation.discovery import find_record_ids_by_patient
from policy.engine import CompiledPolicy
from psycopg.types.json import Jsonb
from storage.policy_codec import decode_policy, encode_policy
from storage.repositories import (
    consume_id,
    find_records_by_search_term,
    get_chain_head,
    get_dek_wrapping,
    get_lifecycle_state,
    get_record,
    get_transition_event,
    has_consumed_id,
    insert_audit_entry,
    insert_dek_wrapping,
    insert_record,
    insert_search_term,
    insert_transition_event,
    transition_lifecycle_state,
    upsert_lifecycle_state,
)


class StateConflictError(Exception):
    """A compare-and-set lost: the record's state was not what the caller expected.

    Two concurrent transitions from the same state must not both succeed
    (review F12). Callers map this to HTTP 409 and never treat it as success.
    """


class StorageRepository(Protocol):
    """Protocol for data-plane storage access in the hospital node service."""

    def get_record(self, record_id: str) -> Record | None:
        """Fetch a Record by identifier."""
        ...

    def insert_record(self, record: Record) -> None:
        """Persist an encrypted Record."""
        ...

    def get_dek_wrapping(self, wrapping_id: str) -> DEKWrapping | None:
        """Fetch a DEKWrapping by wrapping identifier."""
        ...

    def get_wrapping_for_record(
        self, record_id: str, wrapped_for: str | None = None
    ) -> DEKWrapping | None:
        """Fetch the most recent DEKWrapping for a record."""
        ...

    def insert_dek_wrapping(self, wrapping: DEKWrapping) -> None:
        """Persist a DEKWrapping."""
        ...

    def get_lifecycle_state(self, record_id: str) -> LifecycleState | None:
        """Get the current lifecycle state of a record."""
        ...

    def upsert_lifecycle_state(
        self,
        record_id: str,
        state: LifecycleState,
        last_event_id: str | None = None,
    ) -> None:
        """Update or insert lifecycle state for a record."""
        ...

    def insert_transition_event(self, event: TransitionEvent) -> None:
        """Persist a signed transition event."""
        ...

    def get_transition_event(self, event_id: str) -> TransitionEvent | None:
        """Fetch a transition event by UUID string."""
        ...

    def insert_audit_entry(self, entry: AuditEntry) -> None:
        """Append an entry to the audit log."""
        ...

    def get_chain_head(self) -> AuditEntry | None:
        """Get the current head of the audit chain."""
        ...

    def insert_search_term(self, record_id: str, coded_term: bytes) -> None:
        """Index a coded search term for a record."""
        ...

    def find_records_by_search_term(self, coded_term: bytes) -> list[str]:
        """Find record identifiers matching a coded search token."""
        ...

    def find_record_ids_by_patient(self, patient_id: str) -> list[str]:
        """Find all record identifiers belonging to a patient."""
        ...

    def store_compiled_policy(
        self, policy_id: str, compiled_policy: CompiledPolicy
    ) -> None:
        """Cache or persist a compiled policy structure."""
        ...

    def get_compiled_policy(self, policy_id: str) -> CompiledPolicy | None:
        """Retrieve a cached compiled policy structure."""
        ...

    def store_consent_request(self, request: ConsentRequest) -> None:
        """Persist an incoming or outgoing ConsentRequest."""
        ...

    def get_consent_request(self, request_id: UUID) -> ConsentRequest | None:
        """Fetch a ConsentRequest by UUID."""
        ...

    def store_consent_grant(self, grant: ConsentGrant) -> None:
        """Persist a signed ConsentGrant."""
        ...

    def get_consent_grant(self, grant_id: UUID) -> ConsentGrant | None:
        """Fetch a ConsentGrant by UUID."""
        ...

    def list_consent_grants_by_patient(self, patient_id: str) -> list[ConsentGrant]:
        """List every ConsentGrant whose subject is ``patient_id``.

        Powers the patient portal's "who has access" view (P4-7). Returns all
        grants for the patient regardless of status -- GRANTED, DENIED, and
        REVOKED alike -- so the caller can render current access and its
        history; filtering by status is the caller's concern.
        """
        ...

    def transition_lifecycle_state(
        self,
        record_id: str,
        expected: LifecycleState,
        new: LifecycleState,
        last_event_id: str | None = None,
    ) -> None:
        """Compare-and-set the state; raise :class:`StateConflictError` if it moved."""
        ...

    def consume_once(self, kind: str, item_id: UUID) -> bool:
        """Record a one-time id; ``True`` on first use, ``False`` on replay (F22)."""
        ...

    def has_consumed(self, kind: str, item_id: UUID) -> bool:
        """Whether a one-time id has been consumed (diagnostics and tests only)."""
        ...


class InMemoryStorageRepository:
    """Thread-safe, fully in-memory repository implementation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.records: dict[str, Record] = {}
        self.wrappings: dict[str, DEKWrapping] = {}
        self.record_wrappings: dict[str, list[DEKWrapping]] = {}
        self.lifecycle_states: dict[str, LifecycleState] = {}
        self.transition_events: dict[str, TransitionEvent] = {}
        self.audit_log: list[AuditEntry] = []
        self.search_index: list[tuple[str, bytes]] = []
        self.compiled_policies: dict[str, CompiledPolicy] = {}
        self.consent_requests: dict[UUID, ConsentRequest] = {}
        self.consent_grants: dict[UUID, ConsentGrant] = {}
        self.consumed_ids: set[tuple[str, UUID]] = set()

    def get_record(self, record_id: str) -> Record | None:
        with self._lock:
            return self.records.get(record_id)

    def insert_record(self, record: Record) -> None:
        with self._lock:
            self.records[record.record_id] = record

    def get_dek_wrapping(self, wrapping_id: str) -> DEKWrapping | None:
        with self._lock:
            return self.wrappings.get(wrapping_id)

    def get_wrapping_for_record(
        self, record_id: str, wrapped_for: str | None = None
    ) -> DEKWrapping | None:
        with self._lock:
            wraps = self.record_wrappings.get(record_id, [])
            if not wraps:
                return None
            if wrapped_for is not None:
                matching = [w for w in wraps if w.wrapped_for == wrapped_for]
                return matching[-1] if matching else None
            return wraps[-1]

    def insert_dek_wrapping(self, wrapping: DEKWrapping) -> None:
        with self._lock:
            self.wrappings[wrapping.wrapping_id] = wrapping
            self.record_wrappings.setdefault(wrapping.record_id, []).append(wrapping)

    def get_lifecycle_state(self, record_id: str) -> LifecycleState | None:
        with self._lock:
            return self.lifecycle_states.get(record_id)

    def upsert_lifecycle_state(
        self,
        record_id: str,
        state: LifecycleState,
        last_event_id: str | None = None,
    ) -> None:
        with self._lock:
            self.lifecycle_states[record_id] = state

    def transition_lifecycle_state(
        self,
        record_id: str,
        expected: LifecycleState,
        new: LifecycleState,
        last_event_id: str | None = None,
    ) -> None:
        with self._lock:
            current = self.lifecycle_states.get(record_id)
            if current is not expected:
                raise StateConflictError(
                    f"record {record_id!r} is {current}, expected {expected}"
                )
            self.lifecycle_states[record_id] = new

    def consume_once(self, kind: str, item_id: UUID) -> bool:
        with self._lock:
            if (kind, item_id) in self.consumed_ids:
                return False
            self.consumed_ids.add((kind, item_id))
            return True

    def has_consumed(self, kind: str, item_id: UUID) -> bool:
        with self._lock:
            return (kind, item_id) in self.consumed_ids

    def insert_transition_event(self, event: TransitionEvent) -> None:
        with self._lock:
            self.transition_events[str(event.event_id)] = event

    def get_transition_event(self, event_id: str) -> TransitionEvent | None:
        with self._lock:
            return self.transition_events.get(event_id)

    def insert_audit_entry(self, entry: AuditEntry) -> None:
        with self._lock:
            self.audit_log.append(entry)

    def get_chain_head(self) -> AuditEntry | None:
        with self._lock:
            return self.audit_log[-1] if self.audit_log else None

    def insert_search_term(self, record_id: str, coded_term: bytes) -> None:
        with self._lock:
            self.search_index.append((record_id, coded_term))

    def find_records_by_search_term(self, coded_term: bytes) -> list[str]:
        with self._lock:
            results: list[str] = []
            for rec_id, term in self.search_index:
                if term == coded_term and rec_id not in results:
                    results.append(rec_id)
            return results

    def find_record_ids_by_patient(self, patient_id: str) -> list[str]:
        with self._lock:
            return [
                rec.record_id
                for rec in self.records.values()
                if rec.patient_id == patient_id
            ]

    def store_compiled_policy(
        self, policy_id: str, compiled_policy: CompiledPolicy
    ) -> None:
        with self._lock:
            self.compiled_policies[policy_id] = compiled_policy

    def get_compiled_policy(self, policy_id: str) -> CompiledPolicy | None:
        with self._lock:
            return self.compiled_policies.get(policy_id)

    def store_consent_request(self, request: ConsentRequest) -> None:
        with self._lock:
            self.consent_requests[request.request_id] = request

    def get_consent_request(self, request_id: UUID) -> ConsentRequest | None:
        with self._lock:
            return self.consent_requests.get(request_id)

    def store_consent_grant(self, grant: ConsentGrant) -> None:
        with self._lock:
            self.consent_grants[grant.grant_id] = grant

    def get_consent_grant(self, grant_id: UUID) -> ConsentGrant | None:
        with self._lock:
            return self.consent_grants.get(grant_id)

    def list_consent_grants_by_patient(self, patient_id: str) -> list[ConsentGrant]:
        with self._lock:
            return [
                grant
                for grant in self.consent_grants.values()
                if grant.patient_id == patient_id
            ]


class PostgresStorageRepository:
    """PostgreSQL storage repository backed by ``storage.repositories``."""

    def __init__(self, conn: psycopg.Connection) -> None:
        self._conn = conn

    def get_record(self, record_id: str) -> Record | None:
        return get_record(self._conn, record_id)

    def insert_record(self, record: Record) -> None:
        insert_record(self._conn, record)

    def get_dek_wrapping(self, wrapping_id: str) -> DEKWrapping | None:
        return get_dek_wrapping(self._conn, wrapping_id)

    def get_wrapping_for_record(
        self, record_id: str, wrapped_for: str | None = None
    ) -> DEKWrapping | None:
        with self._conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            if wrapped_for is not None:
                cur.execute(
                    "SELECT * FROM dek_wrappings "
                    "WHERE record_id = %s AND wrapped_for = %s "
                    "ORDER BY generation DESC, created_at DESC LIMIT 1",
                    (record_id, wrapped_for),
                )
            else:
                cur.execute(
                    "SELECT * FROM dek_wrappings WHERE record_id = %s "
                    "ORDER BY generation DESC, created_at DESC LIMIT 1",
                    (record_id,),
                )
            row = cur.fetchone()
        return DEKWrapping(**row) if row else None

    def insert_dek_wrapping(self, wrapping: DEKWrapping) -> None:
        insert_dek_wrapping(self._conn, wrapping)

    def get_lifecycle_state(self, record_id: str) -> LifecycleState | None:
        row = get_lifecycle_state(self._conn, record_id)
        if not row:
            return None
        return LifecycleState(row["state"])

    def upsert_lifecycle_state(
        self,
        record_id: str,
        state: LifecycleState,
        last_event_id: str | None = None,
    ) -> None:
        upsert_lifecycle_state(self._conn, record_id, state, last_event_id)

    def transition_lifecycle_state(
        self,
        record_id: str,
        expected: LifecycleState,
        new: LifecycleState,
        last_event_id: str | None = None,
    ) -> None:
        if not transition_lifecycle_state(
            self._conn, record_id, expected, new, last_event_id
        ):
            raise StateConflictError(
                f"record {record_id!r} is no longer {expected}; transition refused"
            )

    def consume_once(self, kind: str, item_id: UUID) -> bool:
        return consume_id(self._conn, kind, item_id)

    def has_consumed(self, kind: str, item_id: UUID) -> bool:
        return has_consumed_id(self._conn, kind, item_id)

    def insert_transition_event(self, event: TransitionEvent) -> None:
        insert_transition_event(self._conn, event)

    def get_transition_event(self, event_id: str) -> TransitionEvent | None:
        return get_transition_event(self._conn, event_id)

    def insert_audit_entry(self, entry: AuditEntry) -> None:
        insert_audit_entry(self._conn, entry)

    def get_chain_head(self) -> AuditEntry | None:
        return get_chain_head(self._conn)

    def insert_search_term(self, record_id: str, coded_term: bytes) -> None:
        insert_search_term(self._conn, record_id, coded_term)

    def find_records_by_search_term(self, coded_term: bytes) -> list[str]:
        return find_records_by_search_term(self._conn, coded_term)

    def find_record_ids_by_patient(self, patient_id: str) -> list[str]:
        return find_record_ids_by_patient(self._conn, patient_id)

    def store_compiled_policy(
        self, policy_id: str, compiled_policy: CompiledPolicy
    ) -> None:
        self._conn.execute(
            "INSERT INTO compiled_policies (policy_id, payload) VALUES (%s, %s) "
            "ON CONFLICT (policy_id) DO UPDATE SET payload = EXCLUDED.payload",
            (policy_id, Jsonb(encode_policy(compiled_policy))),
        )

    def get_compiled_policy(self, policy_id: str) -> CompiledPolicy | None:
        row = self._conn.execute(
            "SELECT payload FROM compiled_policies WHERE policy_id = %s", (policy_id,)
        ).fetchone()
        return decode_policy(row[0]) if row else None

    def store_consent_request(self, request: ConsentRequest) -> None:
        self._conn.execute(
            "INSERT INTO consent_requests (request_id, payload) VALUES (%s, %s) "
            "ON CONFLICT (request_id) DO UPDATE SET payload = EXCLUDED.payload",
            (request.request_id, Jsonb(request.model_dump(mode="json"))),
        )

    def get_consent_request(self, request_id: UUID) -> ConsentRequest | None:
        row = self._conn.execute(
            "SELECT payload FROM consent_requests WHERE request_id = %s", (request_id,)
        ).fetchone()
        return ConsentRequest.model_validate(row[0]) if row else None

    def store_consent_grant(self, grant: ConsentGrant) -> None:
        self._conn.execute(
            "INSERT INTO consent_grants (grant_id, patient_id, payload) "
            "VALUES (%s, %s, %s) ON CONFLICT (grant_id) "
            "DO UPDATE SET patient_id = EXCLUDED.patient_id, "
            "payload = EXCLUDED.payload",
            (grant.grant_id, grant.patient_id, Jsonb(grant.model_dump(mode="json"))),
        )

    def get_consent_grant(self, grant_id: UUID) -> ConsentGrant | None:
        row = self._conn.execute(
            "SELECT payload FROM consent_grants WHERE grant_id = %s", (grant_id,)
        ).fetchone()
        return ConsentGrant.model_validate(row[0]) if row else None

    def list_consent_grants_by_patient(self, patient_id: str) -> list[ConsentGrant]:
        rows = self._conn.execute(
            "SELECT payload FROM consent_grants WHERE patient_id = %s", (patient_id,)
        ).fetchall()
        return [ConsentGrant.model_validate(row[0]) for row in rows]
