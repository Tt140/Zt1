"""
tests/agent/test_closed_loop_recovery.py — Closed-Loop Failure Recovery and Safety Cap Tests

Tests the three-part architecture:
1. First step failure does not terminate incident (feedback-driven recovery):
   - Record real error output (Address already in use).
   - Incident state stays in investigating when auto_resolve_incident=False.
   - Highlight error in remediation_history and model context.
   - Success of subsequent steps and resolving incident as resolved.
2. Safety Cap:
   - When 2 steps fail in the incident, enforce escalation to escalated.
3. Pre-check guard strictness by unit_base and preventing false matches with port in transport.
"""
import sys
import dataclasses
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest

from src.domain.types import (
    new_ulid, utc_now, IncidentState, IncidentPhase,
    IncidentOpenedPayload, IncidentHeader, StepRecord, StepKind,
    DeclaredEffect, EffectCategory, StepProposedPayload,
    build_event, EventType, Actor, TrustLevel, EvidenceRef, EvidenceAddedPayload,
    VerificationVerdict,
)
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.policy import compute_plan_hash
from src.executor.executor import ExecutorLoop, ExecutorTermination
from src.executor.verifier import Verifier, VerificationResult
from src.executor.reconciler import Reconciler
from src.executor.docker_lab import LabResult
from src.agent.context_builder import build_context
from src.agent import (
    RecordedModel, MockObserveBackend, ObservationResult,
    ReasoningLoop, LoopTermination,
)


class ScriptedLab:
    """Controlled Lab for testing failure then success scenarios."""
    def __init__(self, responses: dict[str, LabResult]):
        self.responses = responses
        self.call_history = []

    @property
    def is_docker(self):
        return False

    @property
    def backend_name(self):
        return "scripted_lab_mock"

    def run(self, command: str, tier: str = "T1") -> LabResult:
        self.call_history.append(command)
        for cmd_pattern, res in self.responses.items():
            if cmd_pattern in command:
                return res
        return LabResult(success=True, stdout="default ok", stderr="", exit_code=0, elapsed_seconds=0.01, blocked_reason=None)


from tests.conftest_phase4 import AlwaysSucceedLab


def _open_incident(instance_id="i-test001", alarm="CloudWatch-ALB-TargetGroup-Unhealthy"):
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
    return store, fold(store.read(incident_id))


def _propose_and_get_step(store: MemoryEventStore, incident_id: str, command: str, step_id: str = None) -> StepRecord:
    sid = step_id or new_ulid()
    step = StepRecord(
        step_id=sid,
        incident_id=incident_id,
        based_on_hypotheses=[],
        based_on_evidence=[],
        kind=StepKind.mutate,
        target="i-test001",
        execution_spec={"command": command},
        declared_effects=[DeclaredEffect(EffectCategory.E1, "i-test001", "remediation")],
        preconditions=[],
        success_criteria=[{"type": "command", "check": "echo ok"}],
        rollback_plan="none",
        rollback_reason="remediation",
        idempotent=True,
        risk_claim="low",
        expires_at="2099-01-01T00:00:00+00:00",
        plan_hash="placeholder",
        status="proposed",
    )
    step = dataclasses.replace(step, plan_hash=compute_plan_hash(step))
    seq = store.last_seq(incident_id)
    store.append(incident_id, seq, build_event(
        incident_id=incident_id,
        actor=Actor.agent,
        type=EventType.StepProposed,
        payload=StepProposedPayload(step=step),
    ))
    return step


# ===========================================================================
# 1. Test Full Closed-Loop Recovery Flow
# ===========================================================================

def test_closed_loop_recovery_flow():
    """
    Test full flow:
    1. Step 1 fails in Lab with 'Address already in use'
    2. Incident remains in investigating thanks to auto_resolve_incident=False and successful rollback
    3. Error output recorded in evidence and highlighted in remediation_history
    4. Step 2 (kill <pid>) succeeds and removes blocker
    5. Step 3 (restart service) succeeds
    """
    store, state = _open_incident()
    iid = state.incident_id

    lab_responses = {
        "systemctl restart order-gateway.service": LabResult(
            success=False, stdout="",
            stderr="Traceback (most recent call last):\n  File 'server.py', line 12\nOSError: [Errno 98] Address already in use",
            exit_code=1, elapsed_seconds=0.1, blocked_reason=None,
        ),
        "kill 87160": LabResult(success=True, stdout="killed 87160", stderr="", exit_code=0, elapsed_seconds=0.05, blocked_reason=None),
        "systemctl start order-gateway.service": LabResult(success=True, stdout="started", stderr="", exit_code=0, elapsed_seconds=0.1, blocked_reason=None),
    }
    lab = ScriptedLab(lab_responses)
    verifier = Verifier(AlwaysSucceedLab())
    reconciler = Reconciler(lab)

    executor = ExecutorLoop(
        store=store, lab=lab, verifier=verifier, reconciler=reconciler,
        instance_id="i-test001", allowed_instance_id="i-test001",
        auto_resolve_incident=False,
    )

    # ── Round 1: Execute first step (fails) ──
    step1 = _propose_and_get_step(store, iid, "systemctl restart order-gateway.service")
    state = fold(store.read(iid))
    res1 = executor.execute_step(step1, state)
    state = fold(store.read(iid))

    # Verify: step failed but incident phase remains investigating to enable next round
    assert res1.termination in (ExecutorTermination.ROLLBACK, ExecutorTermination.FAILED)
    assert state.steps[step1.step_id].status == "failed"
    assert state.phase == IncidentPhase.investigating

    # Verify recording of failure evidence with real error tail
    fail_evs = [e for e in state.evidence.values() if e.source == "execution_failure"]
    assert len(fail_evs) >= 1
    assert "Address already in use" in fail_evs[-1].summary

    # Verify build_context explicitly presents failure reason to the agent
    ctx_round2 = build_context(state, cycle=1)
    assert "remediation_history:" in ctx_round2.incident_summary
    assert "Address already in use" in ctx_round2.incident_summary
    assert any(ev.get("source") == "execution_failure" for ev in ctx_round2.evidence_summaries)

    # ── Round 2: Check ports and terminate blocking process (succeeds) ──
    ev_kill = EvidenceRef(
        evidence_id="ev-port-8088", source="observe:ss -tulpn", trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(), raw_ref=None, integrity_hash=None,
        summary="LISTEN 0 5 0.0.0.0:8088 python3 pid=87160", redaction_report={},
    )
    seq = store.last_seq(iid)
    store.append(iid, seq, build_event(incident_id=iid, actor=Actor.agent, type=EventType.EvidenceAdded, payload=EvidenceAddedPayload(evidence=ev_kill)))
    state = fold(store.read(iid))

    step2 = _propose_and_get_step(store, iid, "kill 87160")
    # Bind step to discovered evidence so PolicyGate permits it as T1
    step2 = dataclasses.replace(step2, based_on_evidence=["ev-port-8088"])
    state = fold(store.read(iid))
    res2 = executor.execute_step(step2, state)
    state = fold(store.read(iid))

    assert res2.termination == ExecutorTermination.COMPLETED
    assert state.steps[step2.step_id].status in ("executed", "succeeded")
    assert state.phase == IncidentPhase.investigating

    # ── Round 3: Restart service after blocker is eliminated (succeeds) ──
    step3 = _propose_and_get_step(store, iid, "systemctl start order-gateway.service")
    state = fold(store.read(iid))
    res3 = executor.execute_step(step3, state)
    state = fold(store.read(iid))

    assert res3.termination == ExecutorTermination.COMPLETED
    assert state.steps[step3.step_id].status in ("executed", "succeeded")


# ===========================================================================
# 2. Test Safety Cap and Escalation on Repeated Failure
# ===========================================================================

def test_closed_loop_safety_cap_escalates_on_two_failures():
    """
    Proves safety cap:
    - 1 failed step -> incident continues investigating
    - 2 failed steps -> incident immediately escalates to escalated and breaks loop
    """
    store, state = _open_incident()
    iid = state.incident_id

    lab_responses = {
        "systemctl restart service_a": LabResult(success=False, stdout="", stderr="Error A", exit_code=1, elapsed_seconds=0.01, blocked_reason=None),
        "systemctl restart service_b": LabResult(success=False, stdout="", stderr="Error B", exit_code=1, elapsed_seconds=0.01, blocked_reason=None),
    }
    lab = ScriptedLab(lab_responses)
    verifier = Verifier(AlwaysSucceedLab())
    reconciler = Reconciler(lab)

    executor = ExecutorLoop(
        store=store, lab=lab, verifier=verifier, reconciler=reconciler,
        instance_id="i-test001", allowed_instance_id="i-test001",
        auto_resolve_incident=False,
    )

    # First failure: remains in investigating
    step1 = _propose_and_get_step(store, iid, "systemctl restart service_a")
    state = fold(store.read(iid))
    res1 = executor.execute_step(step1, state)
    state = fold(store.read(iid))

    assert state.steps[step1.step_id].status == "failed"
    assert state.phase == IncidentPhase.investigating

    # Second failure: safety cap intervenes and escalates incident
    step2 = _propose_and_get_step(store, iid, "systemctl restart service_b")
    state = fold(store.read(iid))
    res2 = executor.execute_step(step2, state)
    state = fold(store.read(iid))

    assert state.steps[step2.step_id].status == "failed"
    assert state.phase == IncidentPhase.escalated

    events = store.read(iid)
    assert any(e.type == EventType.Escalated for e in events)


# ===========================================================================
# 3. Test pre-check guard strictness by name and preventing false positive matches
# ===========================================================================

def test_premature_start_guard_checks_unit_base_and_prevents_port_false_positive():
    """
    Proves:
    1. Generic 'systemctl status' without service name is not a sufficient check for order-gateway.service
    2. Presence of 'transport' in output is not considered a port check (false match)
    3. Guard intercepts restart proposal and redirects model to inspect service by name
    """
    from src.domain.types import HypothesisRecord, HypothesisUpdatedPayload

    # Evidence containing the word transport and a generic systemctl status
    ev_summary = "Loaded units: systemd-transport degraded"
    ev_ref1 = EvidenceRef(
        evidence_id="ev-01", source="observe:systemctl status", trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(), raw_ref=None, integrity_hash=None,
        summary=ev_summary, redaction_report={},
    )
    # Evidence showing order-gateway.service failed
    ev_ref2 = EvidenceRef(
        evidence_id="ev-02", source="observe:systemctl list-units --state=failed", trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(), raw_ref=None, integrity_hash=None,
        summary="order-gateway.service loaded failed failed Production Order Gateway API", redaction_report={},
    )

    hyp = HypothesisRecord(
        hypothesis_id="hyp-01", statement="order-gateway service failed", confidence=0.9,
        status="active", supporting=["ev-02"], contradicting=[], next_check="systemctl status order-gateway",
        trigger_evidence_id="ev-02",
    )

    store, state = _open_incident()
    iid = state.incident_id
    seq1 = store.last_seq(iid)
    store.append(iid, seq1, build_event(incident_id=iid, actor=Actor.agent, type=EventType.EvidenceAdded, payload=EvidenceAddedPayload(evidence=ev_ref1)))
    seq2 = store.last_seq(iid)
    store.append(iid, seq2, build_event(incident_id=iid, actor=Actor.agent, type=EventType.EvidenceAdded, payload=EvidenceAddedPayload(evidence=ev_ref2)))
    seq3 = store.last_seq(iid)
    store.append(iid, seq3, build_event(incident_id=iid, actor=Actor.agent, type=EventType.HypothesisUpdated, payload=HypothesisUpdatedPayload(hypothesis=hyp)))
    state = fold(store.read(iid))

    # Model proposing to restart order-gateway.service directly
    model = RecordedModel([
        {
            "tool_name": "propose_step",
            "arguments": {
                "kind": "mutate",
                "execution_spec": {"command": "systemctl restart order-gateway.service"},
                "declared_effects": [{"category": "E1", "resource": "order-gateway", "description": "restart"}],
                "risk_claim": "low",
            },
            "reasoning": "Restart failed service",
        },
        {
            "tool_name": "escalate",
            "arguments": {"reason": "done"},
            "reasoning": "end",
        },
    ])

    class TestRealBackend(MockObserveBackend):
        pass

    backend = TestRealBackend(command_responses={
        "systemctl status order-gateway.service": ObservationResult(True, "Active: failed (Result: exit-code)", "", 0),
    })

    loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=3)
    result = loop.run(state)

    # Verify: Guard intercepted propose_step because service was not checked by name, directing model to systemctl status order-gateway.service
    first_call = result.tool_calls[0]
    assert first_call.tool_name == "observe"
    assert "order-gateway" in first_call.arguments["command"]


def test_active_running_service_restart_not_blocked_and_main_pid_not_killed():
    """
    Proves pillar 1:
    1. Service is already active (active running) with Main PID: 105453.
    2. ss -tulpn output contains pid=105453 on port 8088.
    3. Proposing systemctl restart order-gateway is not blocked as Premature and does not force killing 105453!
    4. Service Main PID is strictly protected from being treated as a Blocker.
    """
    from src.domain.types import HypothesisRecord, HypothesisUpdatedPayload

    ev_summary_status = (
        "● order-gateway.service - Production Order Gateway API\n"
        "   Loaded: loaded (/etc/systemd/system/order-gateway.service; enabled)\n"
        "   Active: active (running) since Wed 2026-10-21 12:46:00 UTC; 10min ago\n"
        " Main PID: 105453 (python3)\n"
        "   CGroup: /system.slice/order-gateway.service\n"
        "           └─105453 python3 -m app.main"
    )
    ev_ref1 = EvidenceRef(
        evidence_id="ev-01",
        source="observe:systemctl status order-gateway",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash=None,
        summary=ev_summary_status,
        redaction_report={},
    )

    ev_summary_port = (
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        'tcp LISTEN 0 128 0.0.0.0:8088 0.0.0.0:* users:(("python3",pid=105453,fd=3))'
    )
    ev_ref2 = EvidenceRef(
        evidence_id="ev-02",
        source="observe:ss -tulpn",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash=None,
        summary=ev_summary_port,
        redaction_report={},
    )

    store, state = _open_incident()
    iid = state.incident_id
    seq1 = store.last_seq(iid)
    store.append(iid, seq1, build_event(incident_id=iid, actor=Actor.agent, type=EventType.EvidenceAdded, payload=EvidenceAddedPayload(evidence=ev_ref1)))
    seq2 = store.last_seq(iid)
    store.append(iid, seq2, build_event(incident_id=iid, actor=Actor.agent, type=EventType.EvidenceAdded, payload=EvidenceAddedPayload(evidence=ev_ref2)))
    state = fold(store.read(iid))

    # Model proposing to restart service
    model = RecordedModel([
        {
            "tool_name": "propose_step",
            "arguments": {
                "kind": "mutate",
                "execution_spec": {"command": "systemctl restart order-gateway"},
                "declared_effects": [{"category": "E1", "resource": "order-gateway", "description": "restart"}],
                "risk_claim": "low",
            },
            "reasoning": "Restart service to ensure clean routing state",
        },
        {
            "tool_name": "escalate",
            "arguments": {"reason": "done"},
            "reasoning": "end",
        },
    ])

    class TestRealBackend(MockObserveBackend):
        pass

    backend = TestRealBackend()
    loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=2)
    result = loop.run(state)

    first_call = result.tool_calls[0]
    # Critical assertion: tool was not modified to kill 105453!
    assert first_call.tool_name == "propose_step"
    cmd = first_call.arguments["execution_spec"]["command"]
    assert cmd == "systemctl restart order-gateway"
    assert "kill 105453" not in cmd


def test_cross_round_duplicate_remediation_rejected_and_diverts_to_conclude():
    """
    Proves pillar 2:
    1. Command 'systemctl restart order-gateway' executed successfully in a prior round (status='succeeded').
    2. Service is currently healthy 'Active: active (running)'.
    3. If model repeats 'systemctl restart order-gateway' in a new round,
       guard rejects cross-round duplicate and diverts step to 'conclude' with confidence 0.95.
    """
    from src.domain.types import (
        StepRecord, StepKind, DeclaredEffect, EffectCategory,
        StepProposedPayload, ExecutionResultPayload, VerificationRecordedPayload,
        VerificationVerdict,
    )

    ev_summary_status = (
        "● order-gateway.service - Production Order Gateway API\n"
        "   Loaded: loaded (/etc/systemd/system/order-gateway.service; enabled)\n"
        "   Active: active (running) since Wed 2026-10-21 12:46:00 UTC; 10min ago\n"
        " Main PID: 105453 (python3)"
    )
    ev_ref1 = EvidenceRef(
        evidence_id="ev-01",
        source="observe:systemctl status order-gateway",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash=None,
        summary=ev_summary_status,
        redaction_report={},
    )
    ev_ref2 = EvidenceRef(
        evidence_id="ev-02",
        source="observe:ss -tulpn",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash=None,
        summary="tcp LISTEN 0 128 0.0.0.0:8088 0.0.0.0:* users:(('python3',pid=105453,fd=3))",
        redaction_report={},
    )
    ev_ref3 = EvidenceRef(
        evidence_id="ev-03",
        source="observe:df -h",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash=None,
        summary="Filesystem Size Used Avail Use% Mounted on /dev/xvda1 20G 4G 16G 20% /",
        redaction_report={},
    )
    ev_ref4 = EvidenceRef(
        evidence_id="ev-04",
        source="observe:ps aux",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash=None,
        summary="root 1 0.0 0.1 /sbin/init\nroot 105453 0.0 0.5 python3 app.py",
        redaction_report={},
    )

    store, state = _open_incident()
    iid = state.incident_id

    # Record evidence
    for ev in (ev_ref1, ev_ref2, ev_ref3, ev_ref4):
        seq = store.last_seq(iid)
        store.append(iid, seq, build_event(incident_id=iid, actor=Actor.agent, type=EventType.EvidenceAdded, payload=EvidenceAddedPayload(evidence=ev)))

    # Record prior successful step restarting the service
    prior_step = StepRecord(
        step_id="step-round2-success",
        incident_id=iid,
        based_on_hypotheses=[],
        based_on_evidence=["ev-01"],
        kind=StepKind.mutate,
        target="i-test001",
        execution_spec={"command": "systemctl restart order-gateway"},
        declared_effects=[DeclaredEffect(EffectCategory.E1, "order-gateway", "restart")],
        preconditions=[],
        success_criteria=[],
        rollback_plan="none",
        rollback_reason=None,
        idempotent=True,
        risk_claim="low",
        expires_at=utc_now().isoformat(),
        plan_hash="hash-123",
        status="succeeded",
    )
    seq = store.last_seq(iid)
    store.append(iid, seq, build_event(incident_id=iid, actor=Actor.agent, type=EventType.StepProposed, payload=StepProposedPayload(step=prior_step)))
    seq = store.last_seq(iid)
    store.append(iid, seq, build_event(
        incident_id=iid, actor=Actor.executor, type=EventType.ExecutionResult,
        payload=ExecutionResultPayload(
            step_id="step-round2-success",
            plan_hash="hash-123",
            status="success",
            output_ref=None,
            post_snapshot_ref=None,
            declared_vs_observed="match",
            mismatch_details=None,
        )
    ))
    state = fold(store.read(iid))
    assert state.steps["step-round2-success"].status == "executed"

    # In a new round, model repeats proposal for the same remediation command that already succeeded
    model = RecordedModel([
        {
            "tool_name": "propose_step",
            "arguments": {
                "kind": "mutate",
                "execution_spec": {"command": "systemctl restart order-gateway"},
                "declared_effects": [{"category": "E1", "resource": "order-gateway", "description": "restart again"}],
                "risk_claim": "low",
            },
            "reasoning": "Restart service again",
        },
    ])

    class TestRealBackend(MockObserveBackend):
        pass

    backend = TestRealBackend()
    loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=2)
    result = loop.run(state)

    first_call = result.tool_calls[0]
    # Critical assertion: cross-round duplicate rejected and diverted immediately to conclude!
    assert first_call.tool_name == "conclude"
    assert first_call.arguments["confidence"] == 0.95
    assert "already successfully executed" in first_call.arguments["root_cause"]

    # Also: if model proposes 'sudo systemctl restart order-gateway' or passes 'command' directly
    model_sudo = RecordedModel([
        {
            "tool_name": "propose_step",
            "arguments": {
                "kind": "mutate",
                "command": "sudo systemctl restart order-gateway",
                "risk_claim": "low",
            },
            "reasoning": "Restart service again with sudo",
        },
    ])
    loop_sudo = ReasoningLoop(model=model_sudo, store=store, backend=backend, instance_id="i-test001", max_cycles=2)
    result_sudo = loop_sudo.run(state)
    first_call_sudo = result_sudo.tool_calls[0]
    assert first_call_sudo.tool_name == "conclude"
    assert first_call_sudo.arguments["confidence"] == 0.95



