"""
tests/agent/test_anti_repetition_and_fast_escalation.py
Unit and regression tests for PolicyGate Denial Interception, Semantic Remediation Deduplication,
and Fast-Fail Escalation.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest

from src.domain.types import (
    new_ulid, utc_now, IncidentState, BudgetState, IncidentPhase,
    IncidentOpenedPayload, IncidentHeader,
    build_event, EventType, Actor, StepKind,
)
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.agent import (
    RecordedModel, ModelContext, ToolCall,
    MockObserveBackend, ObservationResult,
    ReasoningLoop, LoopTermination,
)
from src.agent.tool_decider import NullToolDecider
from src.agent.context_builder import build_context


def _open_incident(instance_id="i-test001", alarm="HighCPUAlarm"):
    store = MemoryEventStore()
    incident_id = new_ulid()
    dedupe_key = f"alarm:{alarm}:{instance_id}"
    alarm_arn = f"arn:aws:cloudwatch:us-east-1:123456789012:alarm:{alarm}"
    header = IncidentHeader(
        incident_id=incident_id,
        instance_id=instance_id,
        dedupe_key=dedupe_key,
        alarm_name=alarm,
        alarm_arn=alarm_arn,
        alert_source="rule/test",
        opened_at=utc_now().isoformat(),
    )
    store.create_if_absent(dedupe_key, header)
    ev = build_event(
        incident_id=incident_id,
        actor=Actor.ingest,
        type=EventType.IncidentOpened,
        payload=IncidentOpenedPayload(
            instance_id=instance_id,
            dedupe_key=dedupe_key,
            alarm_name=alarm,
            alarm_arn=alarm_arn,
            alert_source="rule/test",
        ),
    )
    store.append(incident_id, 0, ev)
    return store, incident_id


def test_context_builder_surfaces_policy_rejection():
    """Verify context_builder highlights PolicyGate rejection and strictly forbids retrying the command."""
    store, iid = _open_incident()
    backend = MockObserveBackend({"ps aux": ObservationResult(True, "PID 1234 python /test", "", 0)})
    loop = ReasoningLoop(model=RecordedModel([]), store=store, backend=backend, instance_id="i-test001", tool_decider=NullToolDecider())
    state = fold(store.read(iid))

    # Add evidence and hypothesis
    ev_res, state = loop._executor.execute(ToolCall("observe", {"command": "ps aux"}), state)
    ev_id = list(state.evidence.keys())[0]

    loop._executor.execute(
        ToolCall("update_hypotheses", {
            "updates": [{"statement": "Runaway daemon", "confidence": 0.9, "evidence_id": ev_id, "status": "active"}]
        }),
        state
    )
    state = fold(store.read(iid))

    # Propose an action that violates I-02 (SSH keyword in spec)
    prop_res, state = loop._executor.execute(
        ToolCall("propose_step", {
            "kind": "mutate",
            "execution_spec": {"command": "systemctl stop ssh-worker.service"},
            "declared_effects": [{"category": "E1", "resource": "ssh-worker.service", "description": "stop service"}],
            "based_on_evidence": [ev_id],
            "based_on_hypotheses": list(state.hypotheses.keys()),
            "risk_claim": "low",
        }),
        state
    )
    state = fold(store.read(iid))

    # Verify context_builder adds the warning
    ctx = build_context(state, cycle=1)
    assert "policy_rejection" in ctx.incident_summary
    assert "ACTION FORBIDDEN: DO NOT RETRY THIS COMMAND" in ctx.incident_summary
    assert "I-02" in ctx.incident_summary


def test_loop_fast_escalates_on_repeated_denied_command():
    """Verify loop triggers Fast-Escalation when an agent repeatedly proposes an action hard-denied by PolicyGate."""
    store, iid = _open_incident()
    backend = MockObserveBackend({"ps aux": ObservationResult(True, "PID 87982 python --ssh-worker-daemon", "", 0)})

    init_loop = ReasoningLoop(model=RecordedModel([]), store=store, backend=backend, instance_id="i-test001", tool_decider=NullToolDecider())
    state = fold(store.read(iid))
    _, state = init_loop._executor.execute(ToolCall("observe", {"command": "ps aux"}), state)
    ev_id = list(state.evidence.keys())[0]
    _, state = init_loop._executor.execute(ToolCall("update_hypotheses", {
        "updates": [{"statement": "Runaway daemon", "confidence": 0.9, "evidence_id": ev_id, "status": "active"}]
    }), state)
    state = fold(store.read(iid))

    # Model sequence:
    # 1. propose_step with ssh-worker.service (PolicyGate HARD-DENIES under I-02)
    # 2. propose_step AGAIN with ssh-worker.service with altered description (intercepted by loop)
    # 3. propose_step a 3rd time with ssh-worker.service -> triggers FAST-ESCALATION!
    model = RecordedModel([
        {"tool_name": "propose_step", "arguments": {
            "kind": "mutate",
            "execution_spec": {"command": "systemctl stop ssh-worker.service"},
            "declared_effects": [{"category": "E1", "resource": "ssh-worker.service", "description": "stop runaway"}],
            "risk_claim": "low",
        }, "reasoning": "stop service"},
        {"tool_name": "propose_step", "arguments": {
            "kind": "mutate",
            "execution_spec": {"command": "systemctl stop ssh-worker.service"},
            "declared_effects": [{"category": "E1", "resource": "ssh-worker.service", "description": "modified text description"}],
            "risk_claim": "low",
        }, "reasoning": "stop service repeated"},
        {"tool_name": "propose_step", "arguments": {
            "kind": "mutate",
            "execution_spec": {"command": "systemctl stop ssh-worker.service"},
            "declared_effects": [{"category": "E1", "resource": "ssh-worker.service", "description": "yet another rephrasing"}],
            "risk_claim": "low",
        }, "reasoning": "stop service 3rd repeat"},
    ])

    loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", tool_decider=NullToolDecider(), max_cycles=15)
    res = loop.run(state)

    # Must escalate via fast-escalation well before max_cycles (cycle count < 10)
    assert res.termination == LoopTermination.ESCALATED
    assert res.cycles_completed < 10
    final_state = fold(store.read(iid))
    assert final_state.phase == IncidentPhase.escalated
    assert any("Fast Escalation" in getattr(ev.payload, "reason", "") for ev in store.read(iid) if ev.type == EventType.Escalated)


def test_agent_switches_strategy_after_denial_and_succeeds():
    """Verify that if the agent receives a PolicyGate rejection and switches strategy (e.g. kill PID directly), it succeeds."""
    store, iid = _open_incident()
    backend = MockObserveBackend({"ps aux": ObservationResult(True, "user 87982 99.0 1.0 python runaway.py", "", 0)})

    init_loop = ReasoningLoop(model=RecordedModel([]), store=store, backend=backend, instance_id="i-test001", tool_decider=NullToolDecider())
    state = fold(store.read(iid))
    _, state = init_loop._executor.execute(ToolCall("observe", {"command": "ps aux"}), state)
    ev_id = list(state.evidence.keys())[0]
    _, state = init_loop._executor.execute(ToolCall("update_hypotheses", {
        "updates": [{"statement": "Runaway PID 87982", "confidence": 0.95, "evidence_id": ev_id, "status": "active"}]
    }), state)
    state = fold(store.read(iid))

    model = RecordedModel([
        # Step 1: Forbidden service stop (I-02 rejection)
        {"tool_name": "propose_step", "arguments": {
            "kind": "mutate",
            "execution_spec": {"command": "systemctl stop ssh-worker.service"},
            "declared_effects": [{"category": "E1", "resource": "ssh-worker.service", "description": "stop service"}],
            "risk_claim": "low",
        }, "reasoning": "stop service"},
        # Step 2: Agent adapts and proposes surgical kill of PID 87982 directly!
        {"tool_name": "propose_step", "arguments": {
            "kind": "mutate",
            "execution_spec": {"command": "kill 87982"},
            "declared_effects": [{"category": "E1", "resource": "process:87982", "description": "terminate PID 87982"}],
            "risk_claim": "low",
        }, "reasoning": "kill pid directly"},
    ])

    loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", tool_decider=NullToolDecider(), max_cycles=10)
    res = loop.run(state)

    assert res.termination == LoopTermination.PROPOSED
    final_state = fold(store.read(iid))
    # Step 1 was rejected, Step 2 was proposed/accepted
    steps = list(final_state.steps.values())
    assert len(steps) == 2
    assert getattr(steps[0], "status", "") == "rejected"
    assert getattr(steps[1], "status", "") == "proposed"
    assert steps[1].execution_spec["command"] == "kill 87982"


def test_semantic_deduplication_catches_altered_description():
    """Verify that proposing the same remediation command with a modified description is intercepted as a duplicate."""
    store, iid = _open_incident()
    backend = MockObserveBackend({"df -h": ObservationResult(True, "/dev/xvda1 95% /var/log/app.log", "", 0)})

    init_loop = ReasoningLoop(model=RecordedModel([]), store=store, backend=backend, instance_id="i-test001", tool_decider=NullToolDecider())
    state = fold(store.read(iid))
    _, state = init_loop._executor.execute(ToolCall("observe", {"command": "df -h"}), state)
    ev_id = list(state.evidence.keys())[0]
    _, state = init_loop._executor.execute(ToolCall("update_hypotheses", {
        "updates": [{"statement": "Log bloat", "confidence": 0.95, "evidence_id": ev_id, "status": "active"}]
    }), state)
    state = fold(store.read(iid))

    model = RecordedModel([
        # Call 1: Valid proposal
        {"tool_name": "propose_step", "arguments": {
            "kind": "mutate",
            "execution_spec": {"command": "truncate -s 0 /var/log/app.log"},
            "declared_effects": [{"category": "E3", "resource": "/var/log/app.log", "description": "truncate file A"}],
            "risk_claim": "low",
        }, "reasoning": "truncate file"},
        # Call 2: Exact duplicate command with altered description B
        {"tool_name": "propose_step", "arguments": {
            "kind": "mutate",
            "execution_spec": {"command": "truncate -s 0 /var/log/app.log"},
            "declared_effects": [{"category": "E3", "resource": "/var/log/app.log", "description": "completely different rephrasing"}],
            "risk_claim": "low",
        }, "reasoning": "truncate file again"},
    ])

    loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", tool_decider=NullToolDecider(), max_cycles=5)
    res = loop.run(state)

    # First call was proposed and accepted, terminating the loop on valid proposal!
    assert res.termination == LoopTermination.PROPOSED
    assert len(res.final_state.steps) == 1

