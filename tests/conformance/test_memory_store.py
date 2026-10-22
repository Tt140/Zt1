"""
tests/conformance/test_memory_store.py
Conformance test suite CS-01..11 + AUTH-* against MemoryEventStore
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from src.store.memory import MemoryEventStore
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
def store():
    return MemoryEventStore()


def test_cs01_memory(store): cs_01_write_read_order(store)
def test_cs02_memory(store): cs_02_concurrent_append(store, iterations=200)
def test_cs03_memory(store): cs_03_idempotent_retry(store)
def test_cs04_memory(store): cs_04_strong_consistency_no_gaps(store)
def test_cs05_memory(store): cs_05_lease_exclusivity(store)
def test_cs06_memory(store): cs_06_create_if_absent_concurrent(store)
def test_cs07_memory(store): cs_07_crash_injection(store)
def test_cs08_memory(store): cs_08_tamper_detection(store)
def test_cs09_memory(store): cs_09_blobs(store)
def test_cs10_memory(store): cs_10_clock_independence(store)
def test_cs11_memory(store): cs_11_replay_determinism(store)


def test_auth01_memory(store): auth_01_unauthorized_writer_flagged(store)
def test_auth02_memory(store): auth_02_auth_tag_present_for_approval(store)
def test_auth03_memory(store): auth_03_latch_release_requires_auth_tag(store)
def test_auth04_memory(): auth_04_authorized_writers_table_complete(None)


def test_full_suite_memory():
    """Full suite runner against MemoryEventStore."""
    suite = ConformanceSuite(MemoryEventStore, concurrent_iterations=200)
    suite.run_all()
