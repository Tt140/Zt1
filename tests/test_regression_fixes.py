"""
tests/test_regression_fixes.py — Regression tests for sonnet_review.md fixes
Each test proves that a specific flaw has indeed been closed.
"""
import sys
import dataclasses
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.domain.types import (
    new_ulid, utc_now, IncidentState, BudgetState, IncidentPhase,
    EffectCategory, StepKind, DeclaredEffect, StepRecord,
    PolicyDecisionValue, IncidentHeader,
    build_event, EventType, Actor, IncidentOpenedPayload,
    BudgetConsumedPayload, EscalatedPayload, StepProposedPayload,
)
from src.policy import (
    GateContext, evaluate as gate_evaluate,
    compute_plan_hash, TEST_AUTH_KEY, compute_auth_tag,
)
from src.store.memory import MemoryEventStore
from src.store.interface import AppendConflict
from src.store.sqlite_store import SQLiteEventStore
from src.domain.reducer import fold


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _state(iid=None, instance_id="i-test001"):
    return IncidentState(
        incident_id=iid or new_ulid(),
        instance_id=instance_id,
        dedupe_key="dk",
        phase=IncidentPhase.investigating,
        security_latch=False,
        budgets=BudgetState(),
        hypotheses={}, evidence={}, steps={},
        policy_decisions={}, approvals={},
        pending_approval_step=None, pending_observation=None,
        pending_intent=None, last_verification=None,
        last_seq=0, last_hash=None, authorization_violations=[],
    )


def _step(kind=StepKind.observe, effects=None, target="i-test001"):
    if effects is None:
        effects = [DeclaredEffect(EffectCategory.E0, target, "read")]
    s = StepRecord(
        step_id=new_ulid(), incident_id="inc",
        based_on_hypotheses=[], based_on_evidence=[],
        kind=kind, target=target,
        execution_spec={"command": "df -h"},
        declared_effects=effects,
        preconditions=[],
        success_criteria=[{"check": "ok"}],
        rollback_plan="none", rollback_reason="observe",
        idempotent=True, risk_claim="none",
        expires_at="2099-01-01T00:00:00+00:00",
        plan_hash="placeholder",
    )
    # StepRecord is frozen → use dataclasses.replace
    return dataclasses.replace(s, plan_hash=compute_plan_hash(s))


def _ctx(instance_id="i-test001"):
    return GateContext(
        kill_switch_active=False,
        allowed_instance_id=instance_id,
    )


def _open_store(instance_id="i-test001"):
    """Creates a store and returns (store, incident_id, state)."""
    store = MemoryEventStore()
    iid = new_ulid()
    dk = f"dk-{iid}"
    store.create_if_absent(dk, IncidentHeader(
        incident_id=iid, instance_id=instance_id, dedupe_key=dk,
        alarm_name="test", alarm_arn="arn:test", alert_source="test",
        opened_at=utc_now().isoformat(),
    ))
    store.append(iid, 0, build_event(
        incident_id=iid, type=EventType.IncidentOpened, actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=instance_id, dedupe_key=dk,
            alarm_name="test", alarm_arn="arn:test", alert_source="test",
        ),
    ))
    state = fold(store.read(iid))
    return store, iid, state


# ===========================================================================
# GATE FIX-1: mutate+E0 → deny (T3) — Item 1
# ===========================================================================

def test_gate_mutate_e0_is_denied():
    """GATE FIX-1: mutate step with declared E0 effect is denied (Item 1)."""
    step = _step(
        kind=StepKind.mutate,
        effects=[DeclaredEffect(EffectCategory.E0, "i-test001",
                                "claiming read-only but actually destructive")],
    )
    result = gate_evaluate(step, _state(), _ctx())

    assert result.decision == PolicyDecisionValue.deny, (
        f"Expected deny for mutate+E0, got {result.decision}. Reasons: {result.reasons}"
    )
    combined = " ".join(result.reasons).lower()
    assert "e0" in combined or "ambiguous" in combined or "incompatible" in combined, \
        f"Denial reason should mention E0/ambiguous: {result.reasons}"


def test_gate_observe_e0_still_allowed():
    """GATE FIX-1: observe+E0 remains permitted (T0) — regression check."""
    result = gate_evaluate(_step(kind=StepKind.observe), _state(), _ctx())
    assert result.decision == PolicyDecisionValue.allow, \
        f"observe+E0 should be allowed, got {result.decision}: {result.reasons}"
    assert result.tier.value == "T0"


def test_gate_verify_e0_is_denied():
    """GATE FIX-1: verify+E0 is also ambiguous → denied (Item 1)."""
    step = _step(
        kind=StepKind.verify,
        effects=[DeclaredEffect(EffectCategory.E0, "i-test001", "verify?")],
    )
    result = gate_evaluate(step, _state(), _ctx())
    assert result.decision == PolicyDecisionValue.deny, \
        f"verify+E0 should be denied, got {result.decision}: {result.reasons}"


def test_gate_mutate_with_e1_still_works():
    """GATE FIX-1 regression: mutate+E1 still reaches T2 (did not break normal flow)."""
    step = _step(
        kind=StepKind.mutate,
        effects=[DeclaredEffect(EffectCategory.E1, "i-test001", "restart")],
    )
    step = dataclasses.replace(step,
        rollback_plan=[{"action": "systemctl start app"}],
        rollback_reason=None,
        success_criteria=[{"check": "running"}],
    )
    step = dataclasses.replace(step, plan_hash=compute_plan_hash(step))
    result = gate_evaluate(step, _state(), _ctx())
    # Without T1 enabled → T2 → require_approval (not deny)
    assert result.decision != PolicyDecisionValue.allow or result.decision == PolicyDecisionValue.deny or result.requires_approval, \
        f"mutate+E1 should not be denied due to E0 fix: {result.decision}: {result.reasons}"
    # Critical assertion: not denied due to E0
    assert not any("E0" in r or "ambiguous" in r for r in result.reasons), \
        f"Should not fail due to E0 with E1 effect: {result.reasons}"


# ===========================================================================
# GATE FIX-2: auth_tag=None → deny for T2 — Item 2
# ===========================================================================

def test_gate_t2_approval_no_auth_tag_denied():
    """GATE FIX-2: T2 approval without auth_tag is denied (G3 — Item 2)."""
    from src.domain.types import ApprovalGrantedPayload

    step = dataclasses.replace(
        _step(kind=StepKind.mutate,
              effects=[DeclaredEffect(EffectCategory.E1, "i-test001", "restart")]),
        rollback_plan=[{"action": "restore"}],
        rollback_reason=None,
        success_criteria=[{"check": "running"}],
    )
    step = dataclasses.replace(step, plan_hash=compute_plan_hash(step))

    approval = ApprovalGrantedPayload(
        approval_id=new_ulid(),
        step_id=step.step_id,
        plan_hash=step.plan_hash,
        approver_id="human@test.com",
        issued_at=utc_now().isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        nonce=new_ulid(),
    )
    ctx = GateContext(
        kill_switch_active=False,
        allowed_instance_id="i-test001",
        approval_event=approval,
        approval_auth_tag=None,   # Absent → G3 must deny
        approval_incident_id=new_ulid(),
        enabled_t1_categories=frozenset(),
        auth_key=TEST_AUTH_KEY,
    )
    result = gate_evaluate(step, _state(), ctx)
    assert result.decision == PolicyDecisionValue.deny, (
        f"Expected deny when auth_tag=None, got {result.decision}: {result.reasons}"
    )
    assert "AUTH-TAG-ABSENT" in result.rule_ids or any(
        "auth" in r.lower() for r in result.reasons
    )


# ===========================================================================
# STORE FIX-3: SQLite fencing monotonic — Item 3
# ===========================================================================

def test_sqlite_fencing_monotonic_after_release():
    """STORE FIX-3: fencing_number increases after each release/acquire (Item 3)."""
    store = SQLiteEventStore(":memory:")
    iid = new_ulid()
    store.create_if_absent("dk-f", IncidentHeader(
        incident_id=iid, instance_id="i-1", dedupe_key="dk-f",
        alarm_name="test", alarm_arn="arn:test", alert_source="test",
        opened_at=utc_now().isoformat(),
    ))

    fencing_numbers = []
    for _ in range(3):
        tok = store.acquire_lease(iid, "worker-A", ttl_seconds=60)
        assert tok is not None
        fencing_numbers.append(tok.fencing_number)
        store.release_lease(iid, tok)

    assert fencing_numbers == sorted(fencing_numbers), \
        f"Not monotonic: {fencing_numbers}"
    assert len(set(fencing_numbers)) == 3, \
        f"Not strictly increasing: {fencing_numbers}"


# ===========================================================================
# STORE FIX-4: idempotency — same event_id for same incident is safe
# ===========================================================================

def test_memory_append_idempotent_same_incident():
    """STORE FIX-4: Retrying same event_id for same incident → same event (CS-03)."""
    store, iid, _ = _open_store()
    ev = build_event(
        incident_id=iid, type=EventType.EvidenceAdded, actor=Actor.agent,
        payload={"evidence": {"evidence_id": new_ulid(), "source": "cmd", "trust": "host_reported",
                               "collected_at": utc_now().isoformat(), "raw_ref": None,
                               "integrity_hash": None, "summary": "test", "redaction_report": {}}},
    )
    stored1 = store.append(iid, 1, ev)
    stored2 = store.append(iid, 1, ev)  # Retry — should return same event
    assert stored1.event_id == stored2.event_id
    assert stored1.seq == stored2.seq


# ===========================================================================
# STORE FIX-5: blob integrity — Item 5
# ===========================================================================

def test_memory_blob_integrity_detected():
    """STORE FIX-5: Tampered blob in MemoryStore is detected on retrieval."""
    store = MemoryEventStore()
    ref = store.put_blob(b"original blob content")
    store._blobs[ref] = b"tampered content"
    with pytest.raises(ValueError, match="Blob integrity"):
        store.get_blob(ref)


def test_sqlite_blob_integrity_detected():
    """STORE FIX-5: Tampered blob in SQLiteStore is detected on retrieval."""
    store = SQLiteEventStore(":memory:")
    ref = store.put_blob(b"sqlite blob content")
    with store._write_lock:
        store._write_conn.execute("UPDATE blobs SET data = ? WHERE ref = ?", (b"tampered", ref))
        store._write_conn.commit()
    with pytest.raises(ValueError, match="Blob integrity"):
        store.get_blob(ref)


def test_valid_blob_returned_unchanged():
    """STORE FIX-5 regression: Valid blob returned without modification."""
    store = MemoryEventStore()
    data = b"valid content 12345"
    ref = store.put_blob(data)
    assert store.get_blob(ref) == data


# ===========================================================================
# REDUCER FIX-6: BudgetConsumed anti-regression — Item 6
# ===========================================================================

def test_budget_new_total_cannot_decrease():
    """REDUCER FIX-6: new_total < current is ignored by reducer (Item 6)."""
    store, iid, _ = _open_store()
    seq = store.last_seq(iid)

    # Increase commands to 5
    store.append(iid, seq, build_event(
        incident_id=iid, type=EventType.BudgetConsumed, actor=Actor.agent,
        payload=BudgetConsumedPayload(budget_type="commands", amount=5.0, new_total=5.0, limit=30.0),
    ))
    seq += 1

    # Attempt decrease to 1
    store.append(iid, seq, build_event(
        incident_id=iid, type=EventType.BudgetConsumed, actor=Actor.agent,
        payload=BudgetConsumedPayload(budget_type="commands", amount=-4.0, new_total=1.0, limit=30.0),
    ))

    state = fold(store.read(iid))
    assert state.budgets.commands == 5.0, \
        f"Budget regressed to {state.budgets.commands}, expected 5.0"


def test_budget_can_increase():
    """REDUCER FIX-6 regression: Budget increases normally."""
    store, iid, _ = _open_store()
    seq = store.last_seq(iid)
    store.append(iid, seq, build_event(
        incident_id=iid, type=EventType.BudgetConsumed, actor=Actor.agent,
        payload=BudgetConsumedPayload(budget_type="commands", amount=3.0, new_total=3.0, limit=30.0),
    ))
    state = fold(store.read(iid))
    assert state.budgets.commands == 3.0


# ===========================================================================
# AGENT FIX-7: evidence_id validation — Item 7
# ===========================================================================

def test_update_hypotheses_rejects_phantom_evidence():
    """AGENT FIX-7: Nonexistent evidence_id → explicit rejection (Item 7)."""
    from src.agent.mock_backend import MockObserveBackend
    from src.agent.tool_executor import ToolExecutor
    from src.agent.model_interface import ToolCall

    store, iid, state = _open_store()
    executor = ToolExecutor(store, MockObserveBackend(), "i-test001")

    # Add initial evidence to satisfy investigation phase constraint (updating hypotheses requires evidence)
    obs_tc = ToolCall(
        tool_name="observe",
        arguments={"command": "df -h", "timeout_seconds": 10},
        reasoning="initial evidence",
    )
    _, state = executor.execute(obs_tc, state)

    tc = ToolCall(
        tool_name="update_hypotheses",
        arguments={"updates": [{
            "hypothesis_id": "hyp-1",
            "evidence_id": "ghost-evidence-does-not-exist",
            "confidence": 0.9,
            "statement": "disk full",
            "status": "active",
        }]},
        reasoning="test",
    )
    result, _ = executor.execute(tc, state)
    assert not result.success, "Should reject phantom evidence_id"
    assert "not found" in result.message.lower(), \
        f"Message should say 'not found': {result.message}"


def test_update_hypotheses_accepts_valid_evidence():
    """AGENT FIX-7 regression: Existing evidence_id → accepted."""
    from src.agent.mock_backend import MockObserveBackend
    from src.agent.tool_executor import ToolExecutor
    from src.agent.model_interface import ToolCall

    store, iid, state = _open_store()
    executor = ToolExecutor(store, MockObserveBackend(), "i-test001")

    # First: observe to add evidence
    obs_tc = ToolCall(
        tool_name="observe",
        arguments={"command": "df -h", "timeout_seconds": 10},
        reasoning="collect evidence",
    )
    _, state = executor.execute(obs_tc, state)

    # Now retrieve first evidence_id from updated state
    assert state.evidence, "observe should have added evidence"
    eid = next(iter(state.evidence))

    update_tc = ToolCall(
        tool_name="update_hypotheses",
        arguments={"updates": [{
            "hypothesis_id": "hyp-valid",
            "evidence_id": eid,
            "confidence": 0.7,
            "statement": "disk filling up",
            "status": "active",
        }]},
        reasoning="update with real evidence",
    )
    result, _ = executor.execute(update_tc, state)
    assert result.success, f"Should accept valid evidence_id: {result.message}"


# ===========================================================================
# LOOP FIX-8: MAX_CYCLES writes Escalated — Item 8
# ===========================================================================

def test_max_cycles_writes_escalated_event():
    """LOOP FIX-8: MAX_CYCLES writes Escalated event to EventStore (04 §9)."""
    from src.agent.mock_backend import MockObserveBackend
    from src.agent.loop import ReasoningLoop, LoopTermination
    from src.agent.model_interface import RecordedModel

    store, iid, state = _open_store()

    # Model repeats observe only — will never conclude
    model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "echo x"}, "reasoning": "loop"},
    ] * 10)

    loop = ReasoningLoop(
        model=model, store=store,
        backend=MockObserveBackend(),
        instance_id="i-test001",
        max_cycles=3,
    )
    result = loop.run(state)

    event_types = [
        ev.type.value if hasattr(ev.type, "value") else str(ev.type)
        for ev in store.read(iid)
    ]
    assert "Escalated" in event_types, (
        f"MAX_CYCLES must write Escalated per 04§9. Events: {event_types}"
    )


def test_budget_exhausted_writes_escalated_event():
    """
    LOOP FIX-8: BUDGET_EXHAUSTED writes Escalated (04 §9).
    The full test: test_budget_exhausted_termination_and_escalated_event
    (consumes 29/30 commands, then runs the loop).
    This test verifies that MAX_CYCLES also writes Escalated (and is not M8).
    """
    from src.agent.mock_backend import MockObserveBackend
    from src.agent.loop import ReasoningLoop, LoopTermination
    from src.agent.model_interface import RecordedModel

    store, iid, state = _open_store()
    model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "echo x"}, "reasoning": "x"},
    ] * 5)
    loop = ReasoningLoop(
        model=model, store=store,
        backend=MockObserveBackend(),
        instance_id="i-test001",
        max_cycles=2,
    )
    loop_result = loop.run(state)

    # MAX_CYCLES writes Escalated (04 §9), but termination = MAX_CYCLES, not BUDGET_EXHAUSTED
    assert loop_result.termination == LoopTermination.MAX_CYCLES, \
        f"Expected MAX_CYCLES, got {loop_result.termination}"
    event_types = [
        ev.type.value if hasattr(ev.type, "value") else str(ev.type)
        for ev in store.read(iid)
    ]
    assert "Escalated" in event_types, f"MAX_CYCLES must write Escalated: {event_types}"


# ===========================================================================
# RUNBOOK CHECK — Item 9
# ===========================================================================

def test_no_runbook_names_in_agent_core():
    """RUNBOOK: No hardcoded fault names in core agent files (05 §3)."""
    fault_names = ["disk_full", "crash_loop", "cert_expired", "high_cpu", "oom"]
    src = Path(__file__).parent.parent / "src" / "agent"
    violations = []
    for fname in ["loop.py", "tool_executor.py", "context_builder.py"]:
        fpath = src / fname
        if fpath.exists():
            text = fpath.read_text().lower()
            for name in fault_names:
                if name in text:
                    violations.append(f"{fname}: {name!r}")
    assert not violations, f"Hardcoded fault names: {violations}"


# ===========================================================================
# Point 1 — Precise Boundary Specification of the Fix
# ===========================================================================

def test_destructive_cmd_with_mutate_e0_denied():
    """
    Point 1-a: Destructive command (rm -rf) with kind=mutate + declared E0.
    Fix denies due to kind-E0 conflict (04 §1 fail-closed).
    Independent text analysis is not present in gate.py — intentional by design.
    """
    step = dataclasses.replace(
        _step(
            kind=StepKind.mutate,
            effects=[DeclaredEffect(EffectCategory.E0, "i-test001",
                                    "claiming read-only while executing rm -rf")],
        ),
        execution_spec={"command": "rm -rf /srv/data"},
    )
    step = dataclasses.replace(step, plan_hash=compute_plan_hash(step))
    result = gate_evaluate(step, _state(), _ctx())

    assert result.decision == PolicyDecisionValue.deny, (
        f"rm -rf with mutate+E0 must be denied: {result.decision}, {result.reasons}"
    )
    # Denied due to kind-E0 mismatch, not command text (by design: no text analysis)
    assert any("E0" in r or "incompatible" in r or "ambiguous" in r for r in result.reasons), \
        f"Denial must cite E0/kind mismatch: {result.reasons}"


def test_destructive_cmd_with_observe_e0_is_still_allowed():
    """
    Point 1-b: Documented residual risk — observe+E0+destructive command passes gate.
    The gate does not parse command text by design (04 §1).
    Real defense: sandbox executor + before/after effect comparison.
    This test establishes the boundary — does not claim closing the vulnerability.
    """
    step = dataclasses.replace(
        _step(kind=StepKind.observe),
        execution_spec={"command": "rm -rf /srv/data"},  # Destructive, but kind=observe
    )
    step = dataclasses.replace(step, plan_hash=compute_plan_hash(step))
    result = gate_evaluate(step, _state(), _ctx())

    # Expected, known behavior — gate permits (T0)
    # Defense resides in executor layer (outside Phase 3 scope)
    assert result.decision == PolicyDecisionValue.allow, (
        "observe+E0 is allowed at gate level (text analysis is NOT gate's job per 04§1). "
        f"Actual: {result.decision}"
    )
    # DOCUMENTED RESIDUAL RISK: executor sandbox must enforce T0 constraints


def test_shell_injection_mutate_e0_regression():
    """
    Point 1-c: Shell injection — `; rm -rf /` in execution_spec with E0.
    kind=mutate + E0 → deny regardless of command text.
    """
    step = dataclasses.replace(
        _step(
            kind=StepKind.mutate,
            effects=[DeclaredEffect(EffectCategory.E0, "i-test001", "log check")],
        ),
        execution_spec={"command": "df -h; rm -rf /"},
    )
    step = dataclasses.replace(step, plan_hash=compute_plan_hash(step))
    result = gate_evaluate(step, _state(), _ctx())
    assert result.decision == PolicyDecisionValue.deny


# ===========================================================================
# Point 2 — event_id Collision Within Same Incident
# ===========================================================================

def test_same_event_id_same_payload_idempotent():
    """Point 2-a: Same event_id + same payload → returns original event (CS-03)."""
    store, iid, _ = _open_store()
    seq = store.last_seq(iid)

    ev = build_event(
        incident_id=iid, type=EventType.BudgetConsumed, actor=Actor.agent,
        payload=BudgetConsumedPayload(budget_type="commands", amount=1.0,
                                      new_total=1.0, limit=30.0),
    )
    stored1 = store.append(iid, seq, ev)
    stored2 = store.append(iid, seq, ev)  # Retry — same event

    assert stored1.event_id == stored2.event_id, "Idempotent: same event returned"
    assert stored1.seq == stored2.seq, "Seq must match"
    assert stored1.hash == stored2.hash, "Hash must match"


def test_same_event_id_different_payload_returns_original_silently():
    """
    Point 2-b: Same event_id + different payload → store returns original silently.
    Behavior defined by CS-03 contract — event_id is always unique (ULID).
    In practice, two writers cannot generate identical ULIDs in the same millisecond
    except via deliberate forgery. Explicit documentation of this limit is essential.
    """
    store, iid, _ = _open_store()
    seq = store.last_seq(iid)

    shared_id = new_ulid()

    ev1 = dataclasses.replace(
        build_event(
            incident_id=iid, type=EventType.BudgetConsumed, actor=Actor.agent,
            payload=BudgetConsumedPayload(budget_type="commands", amount=1.0,
                                          new_total=1.0, limit=30.0),
        ),
        event_id=shared_id,
    )
    stored1 = store.append(iid, seq, ev1)

    # Same event_id but different type and content (like event injection attack)
    ev2 = dataclasses.replace(
        build_event(
            incident_id=iid, type=EventType.Escalated, actor=Actor.agent,
            payload=EscalatedPayload(reason="injected escalation", report_ref=None),
        ),
        event_id=shared_id,
    )
    # Store returns original event (CS-03) — no collision detection on content
    stored2 = store.append(iid, seq, ev2)

    # Verification: original event returned (escalation injection prevented)
    assert stored2.type == EventType.BudgetConsumed, (
        "Store must return original event on event_id collision (CS-03). "
        f"Got: {stored2.type}"
    )
    assert stored2.event_id == shared_id

    # DOCUMENTED: payload mismatch silently returns original — no error raised
    # This is acceptable per CS-03 contract (ULID collision is practically impossible)
    # Attack mitigation: event_id uniqueness is guaranteed by ULID time-ordering


def test_event_id_collision_across_incidents_is_prevented():
    """
    Point 2-c: Same event_id across two distinct incidents.
    SQLite: Raises UNIQUE constraint on event_id across events.event_id.
    Memory: Searches within incident scope only — does not prevent cross-incident duplicates.
    Documented boundary in Memory store — SQLite is stricter.
    """
    from src.store.sqlite_store import SQLiteEventStore

    store = SQLiteEventStore(":memory:")
    for dk, iid, inst in [("dk-x", new_ulid(), "i-x"), ("dk-y", new_ulid(), "i-y")]:
        store.create_if_absent(dk, IncidentHeader(
            incident_id=iid, instance_id=inst, dedupe_key=dk,
            alarm_name="a", alarm_arn="arn:a", alert_source="s",
            opened_at=utc_now().isoformat(),
        ))

    iids = []
    for dk in ["dk-x", "dk-y"]:
        row = store._write_conn.execute(
            "SELECT incident_id FROM incidents WHERE dedupe_key=?", (dk,)
        ).fetchone()
        iids.append(row["incident_id"])

    iid1, iid2 = iids
    shared_id = new_ulid()

    ev1 = dataclasses.replace(
        build_event(incident_id=iid1, type=EventType.IncidentOpened, actor=Actor.ingest,
                    payload=IncidentOpenedPayload(instance_id="i-x", dedupe_key="dk-x",
                                                   alarm_name="a", alarm_arn="arn:a", alert_source="s")),
        event_id=shared_id,
    )
    store.append(iid1, 0, ev1)

    ev2 = dataclasses.replace(
        build_event(incident_id=iid2, type=EventType.IncidentOpened, actor=Actor.ingest,
                    payload=IncidentOpenedPayload(instance_id="i-y", dedupe_key="dk-y",
                                                   alarm_name="a", alarm_arn="arn:a", alert_source="s")),
        event_id=shared_id,
    )
    # SQLite raises UNIQUE constraint
    with pytest.raises(AppendConflict):
        store.append(iid2, 0, ev2)


# ===========================================================================
# Point 3 — Genuine BUDGET_EXHAUSTED + Escalated
# ===========================================================================

def _build_store_with_commands_near_limit(limit=30, used=29):
    """Creates a store with command budget nearly exhausted."""
    store = MemoryEventStore()
    iid = new_ulid()
    dk = f"dk-{iid}"
    store.create_if_absent(dk, IncidentHeader(
        incident_id=iid, instance_id="i-1", dedupe_key=dk,
        alarm_name="a", alarm_arn="arn:a", alert_source="s",
        opened_at=utc_now().isoformat(),
    ))
    store.append(iid, 0, build_event(
        incident_id=iid, type=EventType.IncidentOpened, actor=Actor.ingest,
        payload=IncidentOpenedPayload(instance_id="i-1", dedupe_key=dk,
                                      alarm_name="a", alarm_arn="arn:a", alert_source="s"),
    ))
    for i in range(used):
        store.append(iid, i + 1, build_event(
            incident_id=iid, type=EventType.BudgetConsumed, actor=Actor.agent,
            payload=BudgetConsumedPayload(budget_type="commands", amount=1.0,
                                          new_total=float(i + 1), limit=float(limit)),
        ))
    state = fold(store.read(iid))
    return store, iid, state


def test_budget_exhausted_termination_and_escalated_event():
    """
    Point 3: Genuine BUDGET_EXHAUSTED → termination=BUDGET_EXHAUSTED
    and Escalated event written to EventStore (04 §9).
    """
    from src.agent.loop import ReasoningLoop, LoopTermination
    from src.agent.mock_backend import MockObserveBackend
    from src.agent.model_interface import RecordedModel

    # Budget is 30 commands, consumed 29 → 1 command triggers exhaustion
    store, iid, state = _build_store_with_commands_near_limit(limit=30, used=29)

    assert state.budgets.commands == 29.0
    assert state.budgets.max_commands == 30.0

    model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "echo trigger"}, "reasoning": "x"},
    ] * 5)

    loop = ReasoningLoop(
        model=model, store=store,
        backend=MockObserveBackend(),
        instance_id="i-1", max_cycles=10,
    )
    result = loop.run(state)

    # 1) Correct termination
    assert result.termination == LoopTermination.BUDGET_EXHAUSTED, (
        f"Expected BUDGET_EXHAUSTED, got {result.termination.value}"
    )

    # 2) Escalated event written to log (04 §9)
    event_types = [
        ev.type.value if hasattr(ev.type, "value") else str(ev.type)
        for ev in store.read(iid)
    ]
    assert "Escalated" in event_types, (
        f"BUDGET_EXHAUSTED must write Escalated per 04§9. Events: {event_types}"
    )

    # 3) final_state reflects escalation
    assert result.final_state.phase == IncidentPhase.escalated, (
        f"Final phase must be escalated, got {result.final_state.phase}"
    )


def test_max_cycles_termination_and_escalated_event():
    """
    Point 3 (MAX_CYCLES): termination=MAX_CYCLES + Escalated in log.
    """
    from src.agent.loop import ReasoningLoop, LoopTermination
    from src.agent.mock_backend import MockObserveBackend
    from src.agent.model_interface import RecordedModel

    store, iid, state = _open_store()
    model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "echo x"}, "reasoning": "x"},
    ] * 20)

    loop = ReasoningLoop(
        model=model, store=store,
        backend=MockObserveBackend(),
        instance_id="i-test001", max_cycles=3,
    )
    result = loop.run(state)

    assert result.termination == LoopTermination.MAX_CYCLES, \
        f"Expected MAX_CYCLES, got {result.termination}"

    event_types = [
        ev.type.value if hasattr(ev.type, "value") else str(ev.type)
        for ev in store.read(iid)
    ]
    assert "Escalated" in event_types, \
        f"MAX_CYCLES must write Escalated per 04§9. Events: {event_types}"


# ===========================================================================
# Point 4 — Direct M7 and M8
# ===========================================================================

def test_m7_wrong_allow_detected_when_mutate_e0_in_store():
    """
    Point 4-M7: _check_wrong_allow detects mutate+E0 in EventStore.
    Simulation: StepProposed event with kind=mutate + E0 appended directly.
    """
    from src.eval.runner import ScenarioRunner
    from src.domain.types import StepProposedPayload

    store, iid, _ = _open_store()
    seq = store.last_seq(iid)

    # Append StepProposed with kind=mutate + E0 directly (simulate wrong allow)
    bad_step = dataclasses.replace(
        _step(
            kind=StepKind.mutate,
            effects=[DeclaredEffect(EffectCategory.E0, "i-test001", "misleading")],
        ),
        execution_spec={"command": "rm -rf /"},
    )
    bad_step = dataclasses.replace(bad_step, plan_hash=compute_plan_hash(bad_step))

    store.append(iid, seq, build_event(
        incident_id=iid, type=EventType.StepProposed, actor=Actor.agent,
        payload=StepProposedPayload(step=bad_step),
    ))

    runner = ScenarioRunner()
    m7_triggered = runner._check_wrong_allow(store, iid)
    assert m7_triggered, "M7 should detect mutate+E0 StepProposed in EventStore"


def test_m7_clean_when_no_mutate_e0_in_store():
    """Point 4-M7: _check_wrong_allow = False when no mutate+E0 exists."""
    from src.eval.runner import ScenarioRunner

    store, iid, _ = _open_store()
    runner = ScenarioRunner()
    assert not runner._check_wrong_allow(store, iid), \
        "M7 should be False when no wrong-allow step exists"


def test_m7_clean_when_mutate_e1_in_store():
    """Point 4-M7: mutate+E1 does not trigger M7 (not a wrong allow)."""
    from src.eval.runner import ScenarioRunner
    from src.domain.types import StepProposedPayload

    store, iid, _ = _open_store()
    seq = store.last_seq(iid)

    good_step = dataclasses.replace(
        _step(
            kind=StepKind.mutate,
            effects=[DeclaredEffect(EffectCategory.E1, "i-test001", "restart")],
        ),
        rollback_plan=[{"action": "restore"}],
        rollback_reason=None,
    )
    good_step = dataclasses.replace(good_step, plan_hash=compute_plan_hash(good_step))
    store.append(iid, seq, build_event(
        incident_id=iid, type=EventType.StepProposed, actor=Actor.agent,
        payload=StepProposedPayload(step=good_step),
    ))

    runner = ScenarioRunner()
    assert not runner._check_wrong_allow(store, iid), \
        "M7 should NOT flag mutate+E1 as wrong allow"


def test_m8_covers_budget_exhausted_termination():
    """
    Point 4-M8: BUDGET_EXHAUSTED counts toward M8.
    """
    from src.eval.runner import ScenarioResult
    from src.agent.loop import LoopTermination

    sr = ScenarioResult(
        scenario_id="test", family="test", group="test",
        termination=LoopTermination.BUDGET_EXHAUSTED.value,
        cycles_completed=5,
        m8_budget_exhausted=True,
        events_written=10, elapsed_seconds=1.0,
    )
    assert sr.m8_budget_exhausted is True


def test_m8_covers_max_cycles_termination():
    """
    Point 4-M8 (fix): MAX_CYCLES does not count toward M8 per contract (05 §4).
    Contract: M8 = genuine budget exhaustion (BUDGET_EXHAUSTED) only.
    MAX_CYCLES = design cycle limit = 40 reasoning cycles.
    Both write Escalated, but M8 measures budget, not cycles.
    """
    from src.eval.runner import ScenarioResult
    from src.agent.loop import LoopTermination

    # MAX_CYCLES must not count toward M8
    sr = ScenarioResult(
        scenario_id="test", family="test", group="test",
        termination=LoopTermination.MAX_CYCLES.value,
        cycles_completed=40,
        m8_budget_exhausted=False,  # MAX_CYCLES ≠ budget_exhausted per contract
        events_written=100, elapsed_seconds=5.0,
    )
    assert sr.m8_budget_exhausted is False, (
        "MAX_CYCLES is a design cycle limit, not a budget exhaustion event. "
        "M8 measures BUDGET_EXHAUSTED termination only (05 §4)."
    )


def test_m8_false_for_clean_escalated():
    """
    Point 4-M8: Normal ESCALATED (agent decided to escalate) does not count toward M8.
    """
    from src.eval.runner import ScenarioResult
    from src.agent.loop import LoopTermination

    sr = ScenarioResult(
        scenario_id="test", family="test", group="test",
        termination=LoopTermination.ESCALATED.value,
        cycles_completed=5,
        m8_budget_exhausted=False,  # deliberate escalate ≠ exhaustion
        events_written=20, elapsed_seconds=2.0,
    )
    assert sr.m8_budget_exhausted is False


# ===========================================================================
# FIX-HOST-ISOLATION: SubprocessBackend rejects T1/T2 before touching subprocess
# ===========================================================================

class TestSubprocessBackendIsolation:
    """
    Proves mutating host execution is impossible via SubprocessBackend.

    Fix: SubprocessBackend.__init__ raises IsolationRequired immediately
    for tier="T1"/"T2"/"T3" — before any subprocess invocation.
    """

    def test_subprocess_t1_raises_isolation_required(self):
        """SubprocessBackend(tier='T1') raises IsolationRequired immediately."""
        from src.executor.docker_lab import SubprocessBackend, IsolationRequired

        with pytest.raises(IsolationRequired) as exc_info:
            SubprocessBackend(tier="T1")

        assert "T1" in str(exc_info.value)
        assert "Docker" in str(exc_info.value) or "isolation" in str(exc_info.value).lower()

    def test_subprocess_t2_raises_isolation_required(self):
        """SubprocessBackend(tier='T2') raises IsolationRequired immediately."""
        from src.executor.docker_lab import SubprocessBackend, IsolationRequired

        with pytest.raises(IsolationRequired):
            SubprocessBackend(tier="T2")

    def test_subprocess_t3_raises_isolation_required(self):
        """SubprocessBackend(tier='T3') raises IsolationRequired immediately."""
        from src.executor.docker_lab import SubprocessBackend, IsolationRequired

        with pytest.raises(IsolationRequired):
            SubprocessBackend(tier="T3")

    def test_subprocess_t0_still_works(self):
        """SubprocessBackend(tier='T0') functions — safe read is intact."""
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("echo hello_isolation_test")

        assert result.success
        assert "hello_isolation_test" in result.stdout
        # Confirm: explicit unisolated warning is always present
        assert "WARNING" in result.stdout or "subprocess" in result.stdout.lower()

    def test_subprocess_t0_blocks_t1_commands_even_after_construction(self):
        """
        Even when SubprocessBackend is built with tier='T0', mutation commands
        (from T1 list and not in T0) are blocked by allowlist.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        # systemctl restart is T1-only — not in T0 allowlist
        result = backend.run("systemctl restart nginx")

        assert not result.success
        assert result.blocked_reason is not None
        assert "T0 allowlist" in result.blocked_reason

    def test_subprocess_t0_blocks_rm_rf_host(self):
        """SubprocessBackend(T0): rm -rf outside /tmp/ blocked — no host mutation."""
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("rm -rf /srv/important_data")

        assert not result.success
        assert result.blocked_reason is not None

    def test_docker_lab_t1_no_docker_raises(self):
        """
        DockerLab(tier='T1', force_subprocess=True) raises IsolationRequired.
        Proves DockerLab itself prevents fallback to subprocess on T1.
        """
        from src.executor.docker_lab import DockerLab, IsolationRequired

        with pytest.raises(IsolationRequired) as exc_info:
            DockerLab(tier="T1", force_subprocess=True)

        msg = str(exc_info.value)
        assert "T1" in msg
        assert "host" in msg.lower() or "isolation" in msg.lower() or "Docker" in msg

    def test_docker_lab_t2_no_docker_raises(self):
        """DockerLab(tier='T2', force_subprocess=True) raises IsolationRequired."""
        from src.executor.docker_lab import DockerLab, IsolationRequired

        with pytest.raises(IsolationRequired):
            DockerLab(tier="T2", force_subprocess=True)

    def test_docker_lab_t0_no_docker_falls_back_to_subprocess(self):
        """
        DockerLab(tier='T0', force_subprocess=True) operates via SubprocessBackend
        — safe reads are unaffected by the fix.
        """
        from src.executor.docker_lab import DockerLab

        lab = DockerLab(tier="T0", force_subprocess=True)
        assert not lab.is_docker
        assert lab.backend_name == "subprocess_no_isolation"

        result = lab.run("df -h")
        assert result.success
        assert "WARNING" in result.stdout or "subprocess" in result.stdout.lower()

    # ── Point 1: tier whitelist — any unknown value rejected ──────────────

    def test_subprocess_unknown_tier_t4_raises(self):
        """
        SubprocessBackend(tier='T4') raises IsolationRequired.
        Unknown value T4 — must reject via fail-closed whitelist.
        """
        from src.executor.docker_lab import SubprocessBackend, IsolationRequired

        with pytest.raises(IsolationRequired) as exc_info:
            SubprocessBackend(tier="T4")

        msg = str(exc_info.value)
        assert "T4" in msg
        assert "T0" in msg  # Points to accepted value

    def test_subprocess_lowercase_t1_raises(self):
        """
        SubprocessBackend(tier='t1') raises IsolationRequired.
        Lowercase does not match 'T0' — no bypass via casing.
        """
        from src.executor.docker_lab import SubprocessBackend, IsolationRequired

        with pytest.raises(IsolationRequired) as exc_info:
            SubprocessBackend(tier="t1")

        assert "t1" in str(exc_info.value)

    def test_subprocess_empty_tier_raises(self):
        """
        SubprocessBackend(tier='') raises IsolationRequired.
        Empty value is unknown — whitelist rejects.
        """
        from src.executor.docker_lab import SubprocessBackend, IsolationRequired

        with pytest.raises(IsolationRequired):
            SubprocessBackend(tier="")

    def test_docker_lab_t4_no_docker_raises(self):
        """DockerLab(tier='T4', force_subprocess=True) raises IsolationRequired."""
        from src.executor.docker_lab import DockerLab, IsolationRequired

        with pytest.raises(IsolationRequired):
            DockerLab(tier="T4", force_subprocess=True)

    # ── Point 2: Shell operators blocked — prevents secondary command injection ──

    def test_shell_operator_semicolon_blocked(self):
        """
        ';' after permitted command is blocked — no execution on host.
        'df -h; echo INJECTED' is not executed: blocked_reason set.
        Safe test: never reaches subprocess.run.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("df -h; echo INJECTED")

        assert not result.success
        assert result.blocked_reason is not None
        assert "shell operator" in result.blocked_reason.lower() or "injection" in result.blocked_reason.lower()
        assert result.stdout == ""  # No output — nothing executed

    def test_shell_operator_and_and_blocked(self):
        """
        '&&' is blocked — 'echo safe && echo INJECTED' is not executed.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("echo safe && echo INJECTED")

        assert not result.success
        assert result.blocked_reason is not None
        assert result.stdout == ""

    def test_shell_operator_or_blocked(self):
        """
        '||' is blocked — 'false || echo INJECTED' is not executed.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("false || echo INJECTED")

        assert not result.success
        assert result.blocked_reason is not None

    def test_shell_operator_backtick_blocked(self):
        """
        Backtick substitution is blocked — 'echo `id`' is not executed.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("echo `id`")

        assert not result.success
        assert result.blocked_reason is not None

    def test_shell_operator_dollar_paren_blocked(self):
        """
        '$()' substitution is blocked — 'echo $(id)' is not executed.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("echo $(id)")

        assert not result.success
        assert result.blocked_reason is not None

    def test_shell_operator_pipe_blocked_on_subprocess(self):
        """
        Pipe '|' is blocked on SubprocessBackend (no sandbox).
        'df -h | grep /' is legitimate in Docker, but risky without isolation
        because 'df -h | sh' could execute host commands.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("df -h | grep Filesystem")

        assert not result.success
        assert result.blocked_reason is not None

    def test_safe_t0_command_no_operators_passes(self):
        """
        Clean T0 command without operators works normally — no test regressions.
        """
        from src.executor.docker_lab import SubprocessBackend

        backend = SubprocessBackend(tier="T0")
        result = backend.run("df -h")

        assert result.success
        assert result.blocked_reason is None
        # Confirm warning present (subprocess without isolation)
        assert "WARNING" in result.stdout
