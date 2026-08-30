# ADR-0029: Simplify revocation registry to serial-keyed O(1) lookup

- **Status:** Proposed
- **Date:** 2026-08-30
- **Deciders:** Avaneeth (author), Powel, Ojas → all four for ratification
- **Task / source:** P2-6 review pass; ADR-0028 follow-up
- **Affects:** `src/authority/revocation.py`, `src/authority/issuance.py`, `tests/authority/test_lifecycle.py`

## Context

During the implementation of Phase 2 Task 6 (P2-6, [ADR-0028](0028-credential-lifecycle-and-revocation-registry.md)), an early draft of `RevocationRegistry` used a composite dictionary key `(serial, issuer_id)` and included multi-tenant filtering logic.

A pre-commit review pass for over-engineering identified four areas of accidental complexity:
1. **Redundant composite keys:** `RevocationRegistry` is instantiated per `AttributeAuthority` instance (`self.revocation_registry = RevocationRegistry()`). Because each registry is private to a single authority, storing `issuer_id` inside the lookup key was solving multi-tenant isolation inside an already isolated single-tenant object.
2. **Linear search fallbacks:** Because keys were composite tuples `(serial, issuer_id)`, checking revocation by `serial` alone forced a `for (entry_serial, _) in self._entries` loop across all entries, degrading dictionary lookups from $O(1)$ to $O(N)$.
3. **Speculative filtering helpers:** `all_revoked()` contained 12 lines of optional `issuer_id` filtering code with zero production callers.

## Decision

Adopt the simplifications across `src/authority/revocation.py` and its callers in `src/authority/issuance.py`:
1. Key `RevocationRegistry._entries` directly by `serial: str` (`dict[str, RevocationEntry]`).
2. Replace the $O(N)$ linear scans in `is_revoked(serial)` and `get_entry(serial)` with instant $O(1)$ dictionary lookups.
3. Simplify `all_revoked()` to a 1-line `list(self._entries.values())`.

---

## Before and After Comparison

### 1. Dictionary Structure and Storage

#### **Before (Composite Key)**
```python
class RevocationRegistry:
    def __init__(self) -> None:
        # Keyed by (serial, issuer_id) -> RevocationEntry
        self._entries: dict[tuple[str, str], RevocationEntry] = {}

    def revoke(self, serial: str, issuer_id: str, reason: str = "", revoked_at: datetime | None = None) -> RevocationEntry:
        # ...
        entry = RevocationEntry(serial=serial, issuer_id=issuer_id, revoked_at=revoked_at, reason=reason)
        self._entries[(serial, issuer_id)] = entry
        return entry
```

#### **After (Direct Serial Key)**
```python
class RevocationRegistry:
    def __init__(self) -> None:
        # Keyed directly by serial -> RevocationEntry
        self._entries: dict[str, RevocationEntry] = {}

    def revoke(self, serial: str, issuer_id: str, reason: str = "", revoked_at: datetime | None = None) -> RevocationEntry:
        # ...
        entry = RevocationEntry(serial=serial, issuer_id=issuer_id, revoked_at=revoked_at, reason=reason)
        self._entries[serial] = entry
        return entry
```

---

### 2. `is_revoked()` Method

#### **Before (13 lines, $O(N)$ fallback loop)**
```python
def is_revoked(self, serial: str, issuer_id: str | None = None) -> bool:
    if issuer_id is not None:
        return (serial, issuer_id) in self._entries
    return any(entry_serial == serial for (entry_serial, _) in self._entries)
```

#### **After (2 lines, $O(1)$ instant check)**
```python
def is_revoked(self, serial: str) -> bool:
    return serial in self._entries
```

---

### 3. `get_entry()` Method

#### **Before (17 lines, $O(N)$ manual loop)**
```python
def get_entry(self, serial: str, issuer_id: str | None = None) -> RevocationEntry | None:
    if issuer_id is not None:
        return self._entries.get((serial, issuer_id))
    for (entry_serial, _), entry in self._entries.items():
        if entry_serial == serial:
            return entry
    return None
```

#### **After (2 lines, $O(1)$ dictionary get)**
```python
def get_entry(self, serial: str) -> RevocationEntry | None:
    return self._entries.get(serial)
```

---

### 4. `all_revoked()` Method

#### **Before (12 lines with filtering)**
```python
def all_revoked(self, issuer_id: str | None = None) -> list[RevocationEntry]:
    if issuer_id is not None:
        return [e for e in self._entries.values() if e.issuer_id == issuer_id]
    return list(self._entries.values())
```

#### **After (2 lines)**
```python
def all_revoked(self) -> list[RevocationEntry]:
    return list(self._entries.values())
```

---

### 5. Verification Integration (`src/authority/issuance.py`)

#### **Before (passing redundant `credential.issuer_id`)**
```python
if revocation_registry is not None and revocation_registry.is_revoked(
    credential.serial, credential.issuer_id
):
    raise CredentialRevokedError(...)
```

#### **After (clean serial-only lookup)**
```python
if revocation_registry is not None and revocation_registry.is_revoked(
    credential.serial
):
    raise CredentialRevokedError(...)
```

---

## Consequences

**What this makes better:**
- **Performance:** Dynamic revocation check is now a true $O(1)$ hash table operation instead of an $O(N)$ linear loop over all revoked items.
- **Code Size & Readability:** Removed 36 lines of redundant iteration, nested tuple indexing, and speculative filtering branches.
- **Maintainability:** The code aligns directly with the architectural model where authority processes hold their own isolated state.
- **Security Invariance:** Zero reduction in security. Fails closed with `CredentialRevokedError` identically across all test suites.

**Honesty caveats / Trade-offs:**
- If a future phase requires a global centralized multi-tenant registry table that mixes multiple authorities in a single shared dict, that shared registry would need to key by `(serial, issuer_id)`. However, since federated authorities maintain independent state boundaries by design (ARCHITECTURE §2 C6), this future scenario is unlikely and should be handled in storage migrations if ever needed.

## Alternatives considered

- **Leave the $O(N)$ loop in place:** Rejected because linear scans in dictionary wrappers are an anti-pattern and hard to justify in a security viva.
- **Delete `all_revoked()` entirely:** Rejected; keeping `all_revoked()` as a 2-line list comprehension is trivial and useful for future admin inspection endpoints (Phase 4).

