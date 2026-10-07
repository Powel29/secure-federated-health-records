"""Unit tests for the anti-replay consumed-ID stores (P3-11).

Covers:
- First consumption succeeds; second raises the correct error.
- Two independent store instances do not cross-pollinate.
- ``has_seen`` is a read-only probe.
- Thread-safety under concurrent consumption attempts.
"""

from __future__ import annotations

import threading
from uuid import uuid4

import pytest
from breakglass import (
    ConsumedAssertionIds,
    ConsumedRequestIds,
    ReplayedAssertionError,
    ReplayedRequestError,
)

# ---------------------------------------------------------------------------
# ConsumedAssertionIds
# ---------------------------------------------------------------------------


class TestConsumedAssertionIds:
    """Unit tests for the assertion one-time-ID store."""

    def test_first_consume_succeeds(self):
        store = ConsumedAssertionIds()
        aid = uuid4()
        store.consume(aid)  # should not raise
        assert store.has_seen(aid)

    def test_second_consume_raises(self):
        store = ConsumedAssertionIds()
        aid = uuid4()
        store.consume(aid)
        with pytest.raises(ReplayedAssertionError, match=str(aid)):
            store.consume(aid)

    def test_different_ids_independent(self):
        store = ConsumedAssertionIds()
        aid1, aid2 = uuid4(), uuid4()
        store.consume(aid1)
        store.consume(aid2)  # should not raise
        assert store.has_seen(aid1) and store.has_seen(aid2)

    def test_two_stores_do_not_cross_pollinate(self):
        store_a = ConsumedAssertionIds()
        store_b = ConsumedAssertionIds()
        aid = uuid4()
        store_a.consume(aid)
        # store_b has never seen aid
        assert not store_b.has_seen(aid)
        store_b.consume(aid)  # should not raise

    def test_has_seen_does_not_consume(self):
        store = ConsumedAssertionIds()
        aid = uuid4()
        assert not store.has_seen(aid)
        assert not store.has_seen(aid)  # still False, not consumed

    def test_thread_safety(self):
        """Concurrent consumption of the same ID should yield exactly one success."""
        store = ConsumedAssertionIds()
        aid = uuid4()
        results: list[str] = []
        barrier = threading.Barrier(10)

        def attempt():
            barrier.wait()
            try:
                store.consume(aid)
                results.append("ok")
            except ReplayedAssertionError:
                results.append("replay")

        threads = [threading.Thread(target=attempt) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count("ok") == 1
        assert results.count("replay") == 9


# ---------------------------------------------------------------------------
# ConsumedRequestIds
# ---------------------------------------------------------------------------


class TestConsumedRequestIds:
    """Unit tests for the request one-time-ID store."""

    def test_first_consume_succeeds(self):
        store = ConsumedRequestIds()
        rid = uuid4()
        store.consume(rid)
        assert store.has_seen(rid)

    def test_second_consume_raises(self):
        store = ConsumedRequestIds()
        rid = uuid4()
        store.consume(rid)
        with pytest.raises(ReplayedRequestError, match=str(rid)):
            store.consume(rid)

    def test_two_stores_do_not_cross_pollinate(self):
        store_a = ConsumedRequestIds()
        store_b = ConsumedRequestIds()
        rid = uuid4()
        store_a.consume(rid)
        assert not store_b.has_seen(rid)
        store_b.consume(rid)  # should not raise

    def test_thread_safety(self):
        """Concurrent consumption yields exactly one success."""
        store = ConsumedRequestIds()
        rid = uuid4()
        results: list[str] = []
        barrier = threading.Barrier(10)

        def attempt():
            barrier.wait()
            try:
                store.consume(rid)
                results.append("ok")
            except ReplayedRequestError:
                results.append("replay")

        threads = [threading.Thread(target=attempt) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count("ok") == 1
        assert results.count("replay") == 9


class TestDurableBackend:
    """F22: a store backed by the repository survives a process restart."""

    def test_new_store_on_same_backend_still_rejects_replay(self):
        from api.repository import InMemoryStorageRepository

        backend = InMemoryStorageRepository()
        assertion_id = uuid4()
        ConsumedAssertionIds(backend=backend).consume(assertion_id)

        restarted = ConsumedAssertionIds(backend=backend)
        assert restarted.has_seen(assertion_id)
        with pytest.raises(ReplayedAssertionError):
            restarted.consume(assertion_id)

    def test_kinds_do_not_collide(self):
        from api.repository import InMemoryStorageRepository

        backend = InMemoryStorageRepository()
        shared = uuid4()
        ConsumedAssertionIds(backend=backend).consume(shared)
        # The same UUID as a request id is a different one-time id.
        ConsumedRequestIds(backend=backend).consume(shared)
