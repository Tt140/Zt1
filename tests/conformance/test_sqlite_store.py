"""
tests/conformance/test_sqlite_store.py
Conformance test suite CS-01..11 + AUTH-* against SQLiteEventStore
"""
import pytest
import sys
import itertools
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from src.store.sqlite_store import SQLiteEventStore
from src.conformance.suite import (
    ConformanceSuite,
    cs_01_write_read_order,
    cs_02_concurrent_append,
    cs_03_idempotent_retry,
    cs_04_strong_consistency_no_gaps,
    cs_05_lease_exclusivity,
    cs_06_create_if_absent_concurrent,
    cs_07_crash_injection,
    cs_08_tamper_detection,
    cs_09_blobs,
    cs_10_clock_independence,
    cs_11_replay_determinism,
    auth_01_unauthorized_writer_flagged,
    auth_02_auth_tag_present_for_approval,
    auth_03_latch_release_requires_auth_tag,
    auth_04_authorized_writers_table_complete,
)


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test.db"
    return SQLiteEventStore(db_path=str(db))


@pytest.fixture
def memory_sqlite_store():
    """In-memory SQLiteEventStore for tests that do not require disk persistence."""
    return SQLiteEventStore(db_path=":memory:")


def test_cs01_sqlite(store): cs_01_write_read_order(store)
def test_cs02_sqlite(store): cs_02_concurrent_append(store, iterations=100)
def test_cs03_sqlite(store): cs_03_idempotent_retry(store)
def test_cs04_sqlite(store): cs_04_strong_consistency_no_gaps(store)
def test_cs05_sqlite(store): cs_05_lease_exclusivity(store)
def test_cs06_sqlite(memory_sqlite_store): cs_06_create_if_absent_concurrent(memory_sqlite_store)
def test_cs07_sqlite(store): cs_07_crash_injection(store)
def test_cs08_sqlite(store): cs_08_tamper_detection(store)
def test_cs09_sqlite(store): cs_09_blobs(store)
def test_cs10_sqlite(store): cs_10_clock_independence(store)
def test_cs11_sqlite(store): cs_11_replay_determinism(store)


def test_auth01_sqlite(store): auth_01_unauthorized_writer_flagged(store)
def test_auth02_sqlite(store): auth_02_auth_tag_present_for_approval(store)
def test_auth03_sqlite(store): auth_03_latch_release_requires_auth_tag(store)
def test_auth04_sqlite(): auth_04_authorized_writers_table_complete(None)


def test_full_suite_sqlite(tmp_path):
    """
    Full suite runner against SQLiteEventStore.
    Uses discrete files with unique names (atomic counter rather than id(object())).
    iterations=30 because SQLite file I/O is slower under heavy concurrency.
    """
    _counter = itertools.count()

    def factory():
        db = tmp_path / f"cs_{next(_counter)}.db"
        return SQLiteEventStore(db_path=str(db))

    suite = ConformanceSuite(factory, concurrent_iterations=30)
    suite.run_all()


def test_sqlite_persistence(tmp_path):
    """SQLite: Data persists across connection close and re-open."""
    db_path = tmp_path / "persist.db"
    store1 = SQLiteEventStore(db_path=str(db_path))

    from src.conformance.suite import _open_incident, _append_worker_started
    iid, _ = _open_incident(store1)
    _append_worker_started(store1, iid, 1)
    last = store1.last_seq(iid)

    # Fresh connection
    store2 = SQLiteEventStore(db_path=str(db_path))
    assert store2.last_seq(iid) == last
    events = store2.read(iid)
    assert len(events) == 2
    assert store2.verify_chain(iid) is True
