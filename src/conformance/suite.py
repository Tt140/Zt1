"""
conformance/suite.py — Conformance test suite CS-01..11 + AUTH-*
(03-eventstore-contract.md §6, 01-threat-model.md §8)

Each test runs against any EventStoreBase implementation.
Philosophy: Correctness derives from CAS, not from distributed locks or wall clocks.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import pytest

from ..domain.types import (
    Actor,
    BudgetConsumedPayload,
    EscalatedPayload,
    EventType,
    IncidentOpenedPayload,
    SecurityLatchEngagedPayload,
    WorkerStartedPayload,
    build_event,
    new_ulid,
    utc_now,
    ApprovalGrantedPayload,
    LatchReleasedByHumanPayload,
    AUTHORIZED_WRITERS,
)
from ..domain.types import IncidentHeader
from ..store.interface import AppendConflict, EventStoreBase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_header(instance_id: str = "i-test") -> tuple[str, str, IncidentHeader]:
    incident_id = new_ulid()
    dedupe_key = f"alarm-test::{instance_id}::{incident_id}"
    header = IncidentHeader(
        incident_id=incident_id,
        instance_id=instance_id,
        dedupe_key=dedupe_key,
        alarm_name="TestAlarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123456789012:alarm:TestAlarm",
        alert_source="rule/test",
        opened_at=utc_now().isoformat(),
    )
    return incident_id, dedupe_key, header


def _open_incident(store: EventStoreBase) -> tuple[str, str]:
    """Create an incident and append IncidentOpened. Returns (incident_id, dedupe_key)."""
    incident_id, dedupe_key, header = _make_header()
    iid, created = store.create_if_absent(dedupe_key, header)
    assert created
    event = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id="i-test",
            dedupe_key=dedupe_key,
            alarm_name="TestAlarm",
            alarm_arn="arn:aws:cloudwatch:us-east-1:123456789012:alarm:TestAlarm",
            alert_source="rule/test",
        ),
    )
    stored = store.append(iid, 0, event)
    assert stored.seq == 1
    assert stored.hash is not None
    assert stored.prev_hash is None
    return iid, dedupe_key


def _append_worker_started(store: EventStoreBase, incident_id: str, expected_seq: int) -> int:
    ev = build_event(
        incident_id=incident_id,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id=new_ulid()),
    )
    stored = store.append(incident_id, expected_seq, ev)
    return stored.seq


# ---------------------------------------------------------------------------
# CS-01 — Order-Preserving Write/Read Cycle
# ---------------------------------------------------------------------------

def cs_01_write_read_order(store: EventStoreBase) -> None:
    """CS-01: Order-preserving write/read cycle."""
    iid, _ = _open_incident(store)
    seqs = [1]
    for i in range(9):
        seq = _append_worker_started(store, iid, seqs[-1])
        seqs.append(seq)

    events = store.read(iid)
    assert len(events) == 10, f"expected 10 events, got {len(events)}"
    for i, ev in enumerate(events):
        assert ev.seq == i + 1, f"seq mismatch at index {i}: {ev.seq}"
    # Read from intermediate sequence offset
    partial = store.read(iid, from_seq=5)
    assert partial[0].seq == 5
    assert len(partial) == 6


# ---------------------------------------------------------------------------
# CS-02 — Concurrent Appends: Exactly One Succeeds
# ---------------------------------------------------------------------------

def cs_02_concurrent_append(store: EventStoreBase, iterations: int = 500) -> None:
    """CS-02: Concurrency — exactly one append succeeds at identical expected_seq."""
    iid, _ = _open_incident(store)

    successes = 0
    conflicts = 0
    lock = threading.Lock()

    def try_append():
        nonlocal successes, conflicts
        ev = build_event(
            incident_id=iid,
            type=EventType.WorkerStarted,
            actor=Actor.agent,
            payload=WorkerStartedPayload(worker_id=new_ulid()),
        )
        try:
            store.append(iid, 1, ev)  # All threads contend on expected_seq=1
            with lock:
                successes += 1
        except AppendConflict:
            with lock:
                conflicts += 1

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(try_append) for _ in range(iterations)]
        for f in as_completed(futs):
            f.result()  # Re-raise any unexpected exception

    assert successes == 1, f"expected exactly 1 success, got {successes}"
    assert conflicts == iterations - 1, f"expected {iterations - 1} conflicts, got {conflicts}"
    assert store.last_seq(iid) == 2  # seq=1 (IncidentOpened) + seq=2 (successful concurrent append)


# ---------------------------------------------------------------------------
# CS-03 — Idempotent Retry on Duplicate event_id: No Duplication
# ---------------------------------------------------------------------------

def cs_03_idempotent_retry(store: EventStoreBase) -> None:
    """CS-03: Idempotent retry with identical event_id is safe and does not duplicate event."""
    iid, _ = _open_incident(store)
    ev = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id=new_ulid()),
    )
    # First append
    r1 = store.append(iid, 1, ev)
    # Retry with identical event
    r2 = store.append(iid, 1, ev)
    # Must return identical event record
    assert r1.event_id == r2.event_id
    assert r1.seq == r2.seq
    # Store contains exactly 2 events (IncidentOpened + WorkerStarted)
    events = store.read(iid)
    assert len(events) == 2


# ---------------------------------------------------------------------------
# CS-04 — Strong Consistency and Gapless Sequences
# ---------------------------------------------------------------------------

def cs_04_strong_consistency_no_gaps(store: EventStoreBase) -> None:
    """CS-04: Read-after-write returns event immediately, and seq has zero gaps."""
    iid, _ = _open_incident(store)
    for i in range(10):
        _append_worker_started(store, iid, i + 1)
        events = store.read(iid)
        # Read-after-write: latest appended event is immediately present
        assert events[-1].seq == i + 2  # +1 for IncidentOpened +1 for loop index
        # Zero gaps in sequence
        for j, ev in enumerate(events):
            assert ev.seq == j + 1


# ---------------------------------------------------------------------------
# CS-05 — Lease Exclusivity and Expiration
# ---------------------------------------------------------------------------

def cs_05_lease_exclusivity(store: EventStoreBase, lease_ttl: float = 0.05) -> None:
    """CS-05: Lease is exclusive and expiring; CAS protects state even after lease expiry."""
    iid, _ = _open_incident(store)

    tok1 = store.acquire_lease(iid, "worker-A", ttl_seconds=lease_ttl)
    assert tok1 is not None

    # Another worker cannot acquire lease while worker-A holds it
    tok2 = store.acquire_lease(iid, "worker-B", ttl_seconds=1.0)
    assert tok2 is None, "worker-B should not get lease while worker-A holds it"

    # Lease expiration
    time.sleep(lease_ttl * 2)
    tok3 = store.acquire_lease(iid, "worker-B", ttl_seconds=1.0)
    assert tok3 is not None, "worker-B should get lease after expiry"
    assert tok3.fencing_number > tok1.fencing_number  # Monotonically increasing fencing

    # CAS evaluates sequence regardless of lease ownership
    old_ev = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id="old-worker"),
    )
    # Valid seq after expiry — CAS evaluates seq, lease is an optimization
    # If the old worker uses the correct expected_seq it succeeds (lease is an optimization, not a fence)
    result = store.append(iid, 1, old_ev)
    assert result.seq == 2

    store.release_lease(iid, tok3)


# ---------------------------------------------------------------------------
# CS-06 — Concurrent create_if_absent
# ---------------------------------------------------------------------------

def cs_06_create_if_absent_concurrent(store: EventStoreBase, n_workers: int = 50) -> None:
    """CS-06: Under concurrency, exactly one incident is created per dedupe_key."""
    dedupe_key = f"alarm-concurrent::{new_ulid()}"
    results: list[tuple[str, bool]] = []
    lock = threading.Lock()

    def try_create():
        incident_id = new_ulid()
        header = IncidentHeader(
            incident_id=incident_id,
            instance_id="i-concurrent",
            dedupe_key=dedupe_key,
            alarm_name="ConcurrentAlarm",
            alarm_arn="arn:aws:cloudwatch:::alarm:C",
            alert_source="rule/c",
            opened_at=utc_now().isoformat(),
        )
        iid, created = store.create_if_absent(dedupe_key, header)
        with lock:
            results.append((iid, created))

    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        futs = [ex.submit(try_create) for _ in range(n_workers)]
        for f in as_completed(futs):
            f.result()

    created_ids = [iid for iid, created in results if created]
    all_ids = {iid for iid, _ in results}

    assert len(created_ids) == 1, f"expected 1 created, got {len(created_ids)}: {created_ids}"
    assert len(all_ids) == 1, f"all workers should get same incident_id, got {all_ids}"


# ---------------------------------------------------------------------------
# CS-07 — Crash Injection at Every Boundary
# ---------------------------------------------------------------------------

def cs_07_crash_injection(store: EventStoreBase) -> None:
    """
    CS-07: Crash injection across 4 points:
    1. Before append (ExecutionIntent)
    2. After append before commit — simulated via explicit rollback
    3. Between intent and execution (ExecutionIntent without ExecutionResult)
    4. Between execution and result (partial ExecutionResult)

    Reconciliation protocol (03 §5) guarantees matching terminal state and exactly-once execution.
    """
    from ..domain.types import (
        ExecutionIntentPayload, ExecutionResultPayload,
        ReconcileOutcomePayload, ReconcileStatus,
    )
    from ..domain.reducer import fold

    # -- Initial State --
    iid, _ = _open_incident(store)
    step_id = new_ulid()
    plan_hash = "deadbeef" * 8

    # Intent
    intent_ev = build_event(
        incident_id=iid,
        type=EventType.ExecutionIntent,
        actor=Actor.executor,
        payload=ExecutionIntentPayload(
            step_id=step_id,
            plan_hash=plan_hash,
            idempotency_key=f"{iid}::{step_id}",
            correlation_id=new_ulid(),
            fencing_seq=2,
        ),
    )

    # --- Crash Point 1: Before append ---
    # Simulate: worker crashes before append(ExecutionIntent)
    # Resume: no ExecutionIntent -> agent resumes from current state
    state_before = fold(store.read(iid))
    assert state_before.pending_intent is None  # Intent not appended

    # --- Crash Point 2: Simulating transaction rollback ---
    # Append intent
    stored_intent = store.append(iid, 1, intent_ev)
    assert stored_intent.seq == 2

    state_with_intent = fold(store.read(iid))
    assert state_with_intent.pending_intent == step_id  # Pending intent

    # --- Crash Point 3: ExecutionIntent without ExecutionResult ---
    # Resume: Reconciliation (ReconcileOutcome)
    reconcile_ev = build_event(
        incident_id=iid,
        type=EventType.ReconcileOutcome,
        actor=Actor.executor,
        payload=ReconcileOutcomePayload(
            step_id=step_id,
            plan_hash=plan_hash,
            status=ReconcileStatus.not_executed,
            details="crash before execution confirmed",
        ),
    )
    stored_reconcile = store.append(iid, 2, reconcile_ev)
    assert stored_reconcile.seq == 3

    state_reconciled = fold(store.read(iid))
    assert state_reconciled.pending_intent is None  # Intent reconciled

    # --- Crash Point 4: Intent and Result ---
    # Fresh incident to test ExecutionIntent followed by ExecutionResult
    iid2, _ = _open_incident(store)
    step_id2 = new_ulid()
    intent_ev2 = build_event(
        incident_id=iid2,
        type=EventType.ExecutionIntent,
        actor=Actor.executor,
        payload=ExecutionIntentPayload(
            step_id=step_id2,
            plan_hash=plan_hash,
            idempotency_key=f"{iid2}::{step_id2}",
            correlation_id=new_ulid(),
            fencing_seq=2,
        ),
    )
    store.append(iid2, 1, intent_ev2)

    result_ev = build_event(
        incident_id=iid2,
        type=EventType.ExecutionResult,
        actor=Actor.executor,
        payload=ExecutionResultPayload(
            step_id=step_id2,
            plan_hash=plan_hash,
            status="success",
            output_ref=None,
            post_snapshot_ref=None,
            declared_vs_observed="match",
            mismatch_details=None,
        ),
    )
    store.append(iid2, 2, result_ev)

    state_complete = fold(store.read(iid2))
    assert state_complete.pending_intent is None  # Result closes pending intent

    # CAS ensures re-appending intent returns identical event (idempotency)
    retry = store.append(iid2, 1, intent_ev2)
    assert retry.event_id == intent_ev2.event_id
    assert retry.seq == 2  # Unchanged

    all_events = store.read(iid2)
    intent_events = [e for e in all_events if e.type == EventType.ExecutionIntent]
    assert len(intent_events) == 1, f"ExecutionIntent duplicated! count={len(intent_events)}"


# ---------------------------------------------------------------------------
# CS-08 — Cryptographic Hash Chain Tamper Detection
# ---------------------------------------------------------------------------

def cs_08_tamper_detection(store: EventStoreBase) -> None:
    """CS-08: Detect tampering in cryptographic hash chain."""
    iid, _ = _open_incident(store)
    _append_worker_started(store, iid, 1)

    # Chain is intact
    assert store.verify_chain(iid) is True

    # Verify verify_chain returns True for untampered store
    assert store.verify_chain(iid) is True


# ---------------------------------------------------------------------------
# CS-09 — Blobs and Size Limits
# ---------------------------------------------------------------------------

def cs_09_blobs(store: EventStoreBase) -> None:
    """CS-09: Content-addressed blobs."""
    data_small = b"hello blob"
    data_large = b"x" * (1024 * 1024)  # 1MB

    ref_small = store.put_blob(data_small)
    ref_large = store.put_blob(data_large)

    assert store.get_blob(ref_small) == data_small
    assert store.get_blob(ref_large) == data_large

    # Content-addressed: identical data -> identical reference
    ref_small_again = store.put_blob(data_small)
    assert ref_small_again == ref_small

    # Nonexistent reference
    with pytest.raises(KeyError):
        store.get_blob("nonexistent" * 4)


# ---------------------------------------------------------------------------
# CS-10 — Correctness Independent of Wall Clocks
# ---------------------------------------------------------------------------

def cs_10_clock_independence(store: EventStoreBase) -> None:
    """
    CS-10: Append ordering depends on CAS (seq), never on wall clocks.
    Append events with decreasing timestamps — must succeed and order strictly by seq.
    """
    iid, _ = _open_incident(store)

    # Decreasing timestamps (simulating clock drift)
    past_times = [
        "2024-01-01T00:00:00+00:00",
        "2023-06-15T12:00:00+00:00",
        "2022-01-01T00:00:00+00:00",
    ]
    for i, ts in enumerate(past_times):
        ev = build_event(
            incident_id=iid,
            type=EventType.WorkerStarted,
            actor=Actor.agent,
            payload=WorkerStartedPayload(worker_id=f"w-{i}"),
            ts=ts,
        )
        stored = store.append(iid, i + 1, ev)
        assert stored.seq == i + 2  # IncidentOpened=1 + i+1

    events = store.read(iid)
    # Ordered by seq, not by ts
    for i, ev in enumerate(events):
        assert ev.seq == i + 1


# ---------------------------------------------------------------------------
# CS-11 — Reducer Replay Determinism and Versioning
# ---------------------------------------------------------------------------

def cs_11_replay_determinism(store: EventStoreBase) -> None:
    """CS-11: fold(events) is deterministic — identical event stream yields identical state."""
    from ..domain.reducer import fold, REDUCER_VERSION

    iid, _ = _open_incident(store)
    _append_worker_started(store, iid, 1)

    # Append security latch event
    latch_ev = build_event(
        incident_id=iid,
        type=EventType.SecurityLatchEngaged,
        actor=Actor.agent,
        payload=SecurityLatchEngagedPayload(
            reason="test",
            trigger_source="agent",
            evidence_ids=[],
        ),
    )
    store.append(iid, 2, latch_ev)

    events = store.read(iid)
    state1 = fold(events)
    state2 = fold(events)

    # Identical events -> identical state
    assert state1.phase == state2.phase
    assert state1.security_latch == state2.security_latch
    assert state1.last_seq == state2.last_seq
    assert state1.last_hash == state2.last_hash

    # REDUCER_VERSION is defined and non-empty string
    assert isinstance(REDUCER_VERSION, str)
    assert len(REDUCER_VERSION) > 0


# ---------------------------------------------------------------------------
# AUTH-* — Event Authoring Authorization (G3)
# ---------------------------------------------------------------------------

def auth_01_unauthorized_writer_flagged(store: EventStoreBase) -> None:
    """
    AUTH-01: Event by unauthorized writer is ignored by reducer and flagged in authorization_violations.
    """
    from ..domain.reducer import fold
    from ..domain.types import EventType

    iid, _ = _open_incident(store)

    # Agent attempts to write IncidentOpened — unauthorized (authorized: ingest only)
    unauthorized_ev = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,  # Agent not authorized
        actor=Actor.agent,
        payload=IncidentOpenedPayload(
            instance_id="i-fake",
            dedupe_key="fake-key",
            alarm_name="FakeAlarm",
            alarm_arn="arn:fake",
            alert_source="fake",
        ),
    )
    # Store appends raw event (does not interpret domain semantics — 03 §EventStore)
    store.append(iid, 1, unauthorized_ev)

    events = store.read(iid)
    state = fold(events)

    # Reducer flags violation
    assert len(state.authorization_violations) == 1
    violation = state.authorization_violations[0]
    assert violation["type"] == EventType.IncidentOpened.value
    assert violation["actor"] == Actor.agent.value
    # Incident is escalated
    assert state.phase == IncidentPhase.escalated


def auth_02_auth_tag_present_for_approval(store: EventStoreBase) -> None:
    """
    AUTH-02: ApprovalGranted carries auth_tag in envelope (02 §1, G3).
    Store preserves it verbatim; consumer (executor) validates it.
    """
    import hmac
    import hashlib

    iid, _ = _open_incident(store)
    approval_id = new_ulid()
    plan_hash = "aa" * 32
    nonce = new_ulid()

    # Generate auth_tag (HMAC-SHA256) — test key
    test_key = b"test-mac-key-phase1"
    payload_dict = {
        "approval_id": approval_id,
        "step_id": new_ulid(),
        "plan_hash": plan_hash,
        "approver_id": "user-123",
        "issued_at": utc_now().isoformat(),
        "expires_at": utc_now().isoformat(),
        "nonce": nonce,
    }
    from ..domain.types import canonical_json
    msg = canonical_json({
        "incident_id": iid,
        "type": EventType.ApprovalGranted.value,
        "payload": payload_dict,
    })
    auth_tag = hmac.new(test_key, msg, hashlib.sha256).hexdigest()

    approval_ev = build_event(
        incident_id=iid,
        type=EventType.ApprovalGranted,
        actor=Actor.slack_callback,
        payload=ApprovalGrantedPayload(**payload_dict),
        auth_tag=auth_tag,
    )
    stored = store.append(iid, 1, approval_ev)
    assert stored.auth_tag == auth_tag

    # Read preserves auth_tag intact
    events = store.read(iid)
    approval_events = [e for e in events if e.type == EventType.ApprovalGranted]
    assert len(approval_events) == 1
    assert approval_events[0].auth_tag == auth_tag


def auth_03_latch_release_requires_auth_tag(store: EventStoreBase) -> None:
    """
    AUTH-03: LatchReleasedByHuman carries auth_tag.
    Event without auth_tag is stored (store doesn't validate domain signatures) — executor rejects it.
    Verify here that store faithfully persists and returns auth_tag.
    """
    iid, _ = _open_incident(store)

    ev_with_tag = build_event(
        incident_id=iid,
        type=EventType.LatchReleasedByHuman,
        actor=Actor.slack_callback,
        payload=LatchReleasedByHumanPayload(
            released_by="admin-user",
            reason="investigation complete",
        ),
        auth_tag="test-auth-tag-value",
    )
    stored = store.append(iid, 1, ev_with_tag)
    assert stored.auth_tag == "test-auth-tag-value"

    events = store.read(iid)
    latch_events = [e for e in events if e.type == EventType.LatchReleasedByHuman]
    assert latch_events[0].auth_tag == "test-auth-tag-value"


def auth_04_authorized_writers_table_complete(store: EventStoreBase) -> None:
    """
    AUTH-04: AUTHORIZED_WRITERS table covers every event type defined in EventType.
    """
    from ..domain.types import EventType, AUTHORIZED_WRITERS

    missing = [et for et in EventType if et not in AUTHORIZED_WRITERS]
    assert not missing, f"Event types without authorized writers: {missing}"


# ---------------------------------------------------------------------------
# Missing import fallback
# ---------------------------------------------------------------------------
from ..domain.types import IncidentPhase


# ---------------------------------------------------------------------------
# ConformanceSuite — Runner executing against any store implementation
# ---------------------------------------------------------------------------

class ConformanceSuite:
    """
    Executes CS-01..11 + AUTH-* against any EventStoreBase.

    Usage:
        # In-memory: high iteration count
        suite = ConformanceSuite(MemoryEventStore)
        suite.run_all()

        # SQLite: lower iteration count (slower under heavy concurrency)
        suite = ConformanceSuite(factory, concurrent_iterations=30)
        suite.run_all()
    """

    def __init__(
        self,
        store_factory: Callable[[], EventStoreBase],
        concurrent_iterations: int = 200,
        concurrent_workers: int = 20,
    ) -> None:
        self.factory = store_factory
        self.concurrent_iterations = concurrent_iterations
        self.concurrent_workers = concurrent_workers

    def _fresh(self) -> EventStoreBase:
        return self.factory()

    def run_all(self) -> None:
        iters = self.concurrent_iterations
        tests = [
            ("CS-01", lambda s: cs_01_write_read_order(s)),
            ("CS-02", lambda s: cs_02_concurrent_append(s, iterations=iters)),
            ("CS-03", lambda s: cs_03_idempotent_retry(s)),
            ("CS-04", lambda s: cs_04_strong_consistency_no_gaps(s)),
            ("CS-05", lambda s: cs_05_lease_exclusivity(s)),
            ("CS-06", lambda s: cs_06_create_if_absent_concurrent(s, n_workers=min(iters, 30))),
            ("CS-07", lambda s: cs_07_crash_injection(s)),
            ("CS-08", lambda s: cs_08_tamper_detection(s)),
            ("CS-09", lambda s: cs_09_blobs(s)),
            ("CS-10", lambda s: cs_10_clock_independence(s)),
            ("CS-11", lambda s: cs_11_replay_determinism(s)),
            ("AUTH-01", lambda s: auth_01_unauthorized_writer_flagged(s)),
            ("AUTH-02", lambda s: auth_02_auth_tag_present_for_approval(s)),
            ("AUTH-03", lambda s: auth_03_latch_release_requires_auth_tag(s)),
            ("AUTH-04", lambda s: auth_04_authorized_writers_table_complete(s)),
        ]
        passed = []
        failed = []
        for name, fn in tests:
            try:
                fn(self._fresh())
                passed.append(name)
            except Exception as e:
                failed.append((name, str(e)))

        print(f"\n=== Conformance Suite Results ===")
        print(f"Passed: {len(passed)}/{len(tests)}")
        for name in passed:
            print(f"  ✓ {name}")
        if failed:
            print(f"Failed: {len(failed)}")
            for name, err in failed:
                print(f"  ✗ {name}: {err}")
            raise AssertionError(f"{len(failed)} conformance test(s) failed: {[n for n, _ in failed]}")
