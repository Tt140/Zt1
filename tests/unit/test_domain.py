"""
tests/unit/test_domain.py — Unit tests for the domain model
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from src.domain import (
    Actor, EventType, IncidentPhase, TrustLevel, HypothesisStatus,
    Event, build_event, new_ulid, utc_now, canonical_json, sha256_hex,
    IncidentOpenedPayload, WorkerStartedPayload, SecurityLatchEngagedPayload,
    HypothesisUpdatedPayload, HypothesisRecord,
    EvidenceRef, EvidenceAddedPayload,
    LatchReleasedByHumanPayload,
    BudgetConsumedPayload,
    EscalatedPayload,
    IncidentResolvedPayload,
    fold, fold_one, REDUCER_VERSION,
    AUTHORIZED_WRITERS,
)
from src.store.memory import MemoryEventStore
from src.store.interface import AppendConflict
from src.conformance.suite import _open_incident, _make_header


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_incident_header(instance_id="i-001"):
    incident_id, dedupe_key, header = _make_header(instance_id)
    return incident_id, dedupe_key, header


def open_and_fold(store):
    """Creates an incident and returns (incident_id, state_after_open)."""
    iid, _ = _open_incident(store)
    events = store.read(iid)
    state = fold(events)
    return iid, state


# ---------------------------------------------------------------------------
# Test: canonical_json
# ---------------------------------------------------------------------------

def test_canonical_json_deterministic():
    d = {"b": 2, "a": 1, "c": [3, 1, 2]}
    j1 = canonical_json(d)
    j2 = canonical_json(d)
    assert j1 == j2
    # Keys sorted
    assert b'"a":1' in j1
    assert j1.index(b'"a"') < j1.index(b'"b"')


def test_sha256_hex():
    h = sha256_hex(b"hello")
    assert len(h) == 64
    assert h == sha256_hex(b"hello")


# ---------------------------------------------------------------------------
# Test: Event hash
# ---------------------------------------------------------------------------

def test_event_hash_changes_with_payload():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)
    ev1 = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id="w1"),
    )
    ev2 = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id="w2"),
    )
    s1 = store.append(iid, 1, ev1)
    s2 = store.append(iid, 2, ev2)
    assert s1.hash != s2.hash
    assert s2.prev_hash == s1.hash


# ---------------------------------------------------------------------------
# Test: reducer — initial state
# ---------------------------------------------------------------------------

def test_fold_initial_state():
    store = MemoryEventStore()
    iid, state = open_and_fold(store)
    assert state.incident_id == iid
    assert state.phase == IncidentPhase.investigating
    assert state.security_latch is False
    assert state.last_seq == 1


def test_fold_requires_incident_opened():
    with pytest.raises(ValueError, match="IncidentOpened"):
        fold([build_event(
            incident_id="x",
            type=EventType.WorkerStarted,
            actor=Actor.agent,
            payload=WorkerStartedPayload(worker_id="w"),
        )])


# ---------------------------------------------------------------------------
# Test: reducer — security latch
# ---------------------------------------------------------------------------

def test_security_latch_one_way():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    latch_ev = build_event(
        incident_id=iid,
        type=EventType.SecurityLatchEngaged,
        actor=Actor.agent,
        payload=SecurityLatchEngagedPayload(
            reason="suspicious SSH", trigger_source="agent", evidence_ids=[]
        ),
    )
    store.append(iid, 1, latch_ev)

    state = fold(store.read(iid))
    assert state.security_latch is True
    assert state.phase == IncidentPhase.security_evidence

    # LatchReleasedByHuman releases the latch
    release_ev = build_event(
        incident_id=iid,
        type=EventType.LatchReleasedByHuman,
        actor=Actor.slack_callback,
        payload=LatchReleasedByHumanPayload(
            released_by="admin", reason="done"
        ),
        auth_tag="test-tag",
    )
    store.append(iid, 2, release_ev)

    state2 = fold(store.read(iid))
    assert state2.security_latch is False
    assert state2.phase == IncidentPhase.investigating


# ---------------------------------------------------------------------------
# Test: reducer — authorization violations (G3)
# ---------------------------------------------------------------------------

def test_unauthorized_writer_escalates_incident():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    # executor writes IncidentOpened — unauthorized violation
    bad_ev = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.executor,
        payload=IncidentOpenedPayload(
            instance_id="i-bad",
            dedupe_key="bad",
            alarm_name="bad",
            alarm_arn="arn:bad",
            alert_source="bad",
        ),
    )
    store.append(iid, 1, bad_ev)
    state = fold(store.read(iid))
    assert len(state.authorization_violations) == 1
    assert state.phase == IncidentPhase.escalated


def test_authorized_writer_accepted():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    # agent writes WorkerStarted — authorized
    ev = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id="w"),
    )
    store.append(iid, 1, ev)
    state = fold(store.read(iid))
    assert len(state.authorization_violations) == 0


# ---------------------------------------------------------------------------
# Test: reducer — hypothesis requires evidence
# ---------------------------------------------------------------------------

def test_hypothesis_updated_records_in_state():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    ev_ref = EvidenceRef(
        evidence_id=new_ulid(),
        source="tool:df",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash=None,
        summary="disk full",
        redaction_report={},
    )
    evid_ev = build_event(
        incident_id=iid,
        type=EventType.EvidenceAdded,
        actor=Actor.agent,
        payload=EvidenceAddedPayload(evidence=ev_ref),
    )
    store.append(iid, 1, evid_ev)

    hyp = HypothesisRecord(
        hypothesis_id=new_ulid(),
        statement="Disk full due to log rotation failure",
        confidence=0.8,
        supporting=[ev_ref.evidence_id],
        contradicting=[],
        status=HypothesisStatus.active,
        next_check="check inode usage",
        trigger_evidence_id=ev_ref.evidence_id,
    )
    hyp_ev = build_event(
        incident_id=iid,
        type=EventType.HypothesisUpdated,
        actor=Actor.agent,
        payload=HypothesisUpdatedPayload(hypothesis=hyp),
    )
    store.append(iid, 2, hyp_ev)

    state = fold(store.read(iid))
    assert hyp.hypothesis_id in state.hypotheses
    assert hyp.hypothesis_id in state.evidence or ev_ref.evidence_id in state.evidence


# ---------------------------------------------------------------------------
# Test: reducer — budget tracking
# ---------------------------------------------------------------------------

def test_budget_consumed_updates_state():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    bev = build_event(
        incident_id=iid,
        type=EventType.BudgetConsumed,
        actor=Actor.agent,
        payload=BudgetConsumedPayload(
            budget_type="cycles",
            amount=1.0,
            new_total=1.0,
            limit=40.0,
        ),
    )
    store.append(iid, 1, bev)
    state = fold(store.read(iid))
    assert state.budgets.cycles == 1.0


# ---------------------------------------------------------------------------
# Test: AUTHORIZED_WRITERS completeness
# ---------------------------------------------------------------------------

def test_all_event_types_have_authorized_writers():
    missing = [et for et in EventType if et not in AUTHORIZED_WRITERS]
    assert not missing, f"Missing authorized writers for: {missing}"


# ---------------------------------------------------------------------------
# Test: reducer determinism (CS-11 unit)
# ---------------------------------------------------------------------------

def test_reducer_deterministic():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    latch_ev = build_event(
        incident_id=iid,
        type=EventType.SecurityLatchEngaged,
        actor=Actor.agent,
        payload=SecurityLatchEngagedPayload(
            reason="test", trigger_source="agent", evidence_ids=[]
        ),
    )
    store.append(iid, 1, latch_ev)

    events = store.read(iid)
    s1 = fold(events)
    s2 = fold(events)
    assert s1.phase == s2.phase
    assert s1.security_latch == s2.security_latch
    assert s1.last_hash == s2.last_hash


# ---------------------------------------------------------------------------
# Test: REDUCER_VERSION
# ---------------------------------------------------------------------------

def test_reducer_version_is_string():
    assert isinstance(REDUCER_VERSION, str)
    assert len(REDUCER_VERSION) > 0


# ---------------------------------------------------------------------------
# Test: EventStore — AppendConflict
# ---------------------------------------------------------------------------

def test_append_conflict_raised():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    ev = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id="w"),
    )
    store.append(iid, 1, ev)

    # Attempt with stale expected_seq
    ev2 = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id="w2"),
    )
    with pytest.raises(AppendConflict) as exc_info:
        store.append(iid, 0, ev2)
    assert exc_info.value.current_seq == 2


# ---------------------------------------------------------------------------
# Test: chain hash integrity
# ---------------------------------------------------------------------------

def test_chain_hash_integrity():
    store = MemoryEventStore()
    iid, _ = _open_incident(store)

    ev = build_event(
        incident_id=iid,
        type=EventType.WorkerStarted,
        actor=Actor.agent,
        payload=WorkerStartedPayload(worker_id="w"),
    )
    store.append(iid, 1, ev)
    assert store.verify_chain(iid) is True

    # Direct data tampering in MemoryEventStore
    store._events[iid][0].hash = "tampered_hash_00000000000000000000000000000000"
    assert store.verify_chain(iid) is False
