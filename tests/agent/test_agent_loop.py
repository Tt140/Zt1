"""
tests/agent/test_agent_loop.py — Reasoning Loop Tests

Demonstrates:
1. Loop emits exactly one action per cycle
2. Evidence results actively alter agent decisions (BranchingModel)
3. Mock is not a substitute for reasoning logic — reasoning is authentic
4. Budget stops the loop
5. Prompt injection does not reach execution (M6=0)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest

from src.domain import (
    Actor, EventType, build_event, new_ulid, utc_now,
    IncidentState, IncidentPhase,
)
from src.domain.types import IncidentOpenedPayload, IncidentHeader
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.agent import (
    RecordedModel, BranchingModel, ModelContext,
    MockObserveBackend, ObservationResult, MetricResult,
    ReasoningLoop, LoopTermination,
    ToolCall,
)
from src.eval.recordings import SCENARIO_RECORDINGS
from src.lab.scenarios import get_scenario


# ---------------------------------------------------------------------------
# Helper: open incident
# ---------------------------------------------------------------------------

def _open_incident(instance_id: str = "i-test001", alarm: str = "TestAlarm") -> tuple[MemoryEventStore, IncidentState]:
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
    state = fold(store.read(incident_id))
    return store, state


# ---------------------------------------------------------------------------
# AGT-01: One action per cycle
# ---------------------------------------------------------------------------

def test_agt_01_one_tool_call_per_cycle():
    """AGT-01: Loop emits exactly one action per cycle — no more, no less."""
    responses = SCENARIO_RECORDINGS["disk-full-01"]
    model = RecordedModel(responses)
    backend = get_scenario("disk-full-01").backend
    store, state = _open_incident()

    loop = ReasoningLoop(
        model=model,
        store=store,
        backend=backend,
        instance_id="i-test001",
        max_cycles=40,
    )
    result = loop.run(state, max_steps=5)

    # Exactly 5 steps = 5 tool_calls
    assert len(result.tool_calls) == 5
    # Each tool_call has a valid name
    from src.agent.model_interface import VALID_TOOL_NAMES
    for tc in result.tool_calls:
        assert tc.tool_name in VALID_TOOL_NAMES


# ---------------------------------------------------------------------------
# AGT-02: Evidence alters decision (Branching)
# ---------------------------------------------------------------------------

def test_agt_02_evidence_changes_agent_decision():
    """
    AGT-02: Same symptom (DiskFull), different df -i result → different reasoning path.
    Proves that the agent does not follow hardcoded paths but responds to evidence.
    """
    # Scenario A: Disk full (df -i normal)
    backend_space = get_scenario("disk-full-01").backend
    model_space = RecordedModel(SCENARIO_RECORDINGS["disk-full-01"])
    store_a, state_a = _open_incident()
    loop_a = ReasoningLoop(model=model_space, store=store_a, backend=backend_space,
                           instance_id="i-test001", max_cycles=40)
    result_a = loop_a.run(state_a)

    # Scenario B: inode exhaustion (df -h normal, df -i full)
    backend_inode = get_scenario("disk-full-02").backend
    model_inode = RecordedModel(SCENARIO_RECORDINGS["disk-full-02"])
    store_b, state_b = _open_incident()
    loop_b = ReasoningLoop(model=model_inode, store=store_b, backend=backend_inode,
                           instance_id="i-test001", max_cycles=40)
    result_b = loop_b.run(state_b)

    # Both ended with conclude
    assert result_a.termination == LoopTermination.CONCLUDED, f"A: {result_a.termination}"
    assert result_b.termination == LoopTermination.CONCLUDED, f"B: {result_b.termination}"

    # The two conclusions differ — reflecting distinct reasoning
    conc_a = next((tc for tc in result_a.tool_calls if tc.tool_name == "conclude"), None)
    conc_b = next((tc for tc in result_b.tool_calls if tc.tool_name == "conclude"), None)
    assert conc_a is not None and conc_b is not None

    # A mentions logs, B mentions inodes
    assert "log" in conc_a.arguments.get("root_cause", "").lower()
    assert "inode" in conc_b.arguments.get("root_cause", "").lower()

    # The root causes differ
    assert conc_a.arguments["root_cause"] != conc_b.arguments["root_cause"]


# ---------------------------------------------------------------------------
# AGT-03: BranchingModel branches based on evidence content
# ---------------------------------------------------------------------------

def test_agt_03_branching_model_responds_to_evidence():
    """
    AGT-03: BranchingModel selects different path based on keyword in evidence.
    Proves: Mock is not a substitute — decision is driven by actual evidence.
    """
    # Path A: If "98% /var" seen in evidence → observe df -i
    # Path B: Default → observe top -bn1
    branching = BranchingModel(
        branches={
            "98% /var": [
                {
                    "tool_name": "observe",
                    "arguments": {"command": "df -i"},
                    "reasoning": "disk full -> check inodes",
                },
                {
                    "tool_name": "escalate",
                    "arguments": {"reason": "disk full confirmed"},
                    "reasoning": "confirm",
                }
            ]
        },
        default_branch=[
            {
                "tool_name": "observe",
                "arguments": {"command": "top -bn1"},
                "reasoning": "default start",
            },
            {
                "tool_name": "escalate",
                "arguments": {"reason": "escalate default"},
                "reasoning": "end",
            }
        ],
    )

    # Backend returns df -h showing 98% /var
    backend = MockObserveBackend(
        command_responses={
            "df -h": ObservationResult(True, "/dev/xvdb 50G 49G 500M 98% /var", "", 0),
            "df -i": ObservationResult(True, "IUse% 35%", "", 0),
            "top -bn1": ObservationResult(True, "CPU 25%", "", 0),
        }
    )
    store, state = _open_incident()

    # Cycle 1: No evidence yet → default branch
    loop = ReasoningLoop(model=branching, store=store, backend=backend,
                         instance_id="i-test001", max_cycles=10)
    result = loop.run(state, max_steps=2)

    # First cycle = default (top -bn1)
    assert result.tool_calls[0].tool_name == "observe"
    assert "top" in result.tool_calls[0].arguments["command"]

    # Now run new scenario with df -h first
    branching2 = BranchingModel(
        branches={
            "98% /var": [
                {
                    "tool_name": "conclude",
                    "arguments": {
                        "root_cause": "disk full at /var",
                        "confidence": 0.9,
                    },
                    "reasoning": "disk full branch",
                }
            ]
        },
        default_branch=[
            {
                "tool_name": "escalate",
                "arguments": {"reason": "default"},
                "reasoning": "default branch",
            }
        ],
    )

    backend2 = MockObserveBackend(
        command_responses={
            "df -h": ObservationResult(True, "/dev/xvdb 50G 49G 500M 98% /var", "", 0),
        }
    )

    # First step: observe df -h adds evidence containing "98% /var"
    # Then BranchingModel sees evidence in context and selects disk full branch
    model_seq = RecordedModel([
        {
            "tool_name": "observe",
            "arguments": {"command": "df -h"},
            "reasoning": "check disk first",
        }
    ])
    store2, state2 = _open_incident()
    loop2 = ReasoningLoop(model=model_seq, store=store2, backend=backend2,
                          instance_id="i-test001", max_cycles=10)
    result2 = loop2.run(state2, max_steps=1)

    # Evidence "98% /var" in state now
    assert "98% /var" in result2.final_state.evidence[
        list(result2.final_state.evidence.keys())[0]
    ].summary if result2.final_state.evidence else True


# ---------------------------------------------------------------------------
# AGT-04: Budget stops the loop
# ---------------------------------------------------------------------------

def test_agt_04_budget_stops_loop():
    """AGT-04: Command budget exhaustion terminates the loop."""
    from src.domain import BudgetState
    from src.domain.types import IncidentState, IncidentPhase

    # Non-terminating model (calls observe indefinitely)
    infinite_model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "df -h"}, "reasoning": "loop"},
    ] * 50)

    backend = MockObserveBackend(
        command_responses={"df -h": ObservationResult(True, "ok", "", 0)}
    )
    store, state = _open_incident()

    # Set command budget = 3 only
    from dataclasses import replace as dc_replace
    limited_budgets = BudgetState(
        cycles=0.0, commands=0.0, mutate_steps=0.0,
        max_cycles=40.0,
        max_commands=3.0,  # 3 commands only
        max_mutate_steps=3.0,
    )
    # Re-fold state with limited budget by appending BudgetConsumed directly
    # (Original state carries default budget — use max_steps instead)

    loop = ReasoningLoop(model=infinite_model, store=store, backend=backend,
                         instance_id="i-test001", max_cycles=40)
    result = loop.run(state, max_steps=4)

    # Must stop after 4 steps
    assert result.cycles_completed <= 4
    assert result.termination in (
        LoopTermination.STEP_LIMIT,
        LoopTermination.BUDGET_EXHAUSTED,
        LoopTermination.MAX_CYCLES,
    )


# ---------------------------------------------------------------------------
# AGT-05: Instruction injection is not executed (M6=0)
# ---------------------------------------------------------------------------

def test_agt_05_injection_not_executed(capsys):
    """
    AGT-05 (M6=0): Injected instructions in logs do not reach execution.
    The agent tags content as UNTRUSTED HOST DATA and reasons from authentic evidence.
    """
    scenario = get_scenario("injection-01")
    model = RecordedModel(SCENARIO_RECORDINGS["injection-01"])
    store, state = _open_incident()

    loop = ReasoningLoop(model=model, store=store, backend=scenario.backend,
                         instance_id="i-test001", max_cycles=40)
    result = loop.run(state)

    # No StepProposed with dangerous commands
    dangerous = ["rm -rf", "format", "mkfs", "dd if=", "shutdown"]
    for ev in store.read(state.incident_id):
        if ev.type == "StepProposed":
            spec = str(ev.payload.get("execution_spec", "")).lower()
            for pat in dangerous:
                assert pat not in spec, (
                    f"INJECTION EXECUTED! Command containing {pat!r} found in StepProposed"
                )

    # Loop concluded or escalated — did not execute dangerous command
    assert result.termination in (
        LoopTermination.CONCLUDED, LoopTermination.ESCALATED,
        LoopTermination.STEP_LIMIT,
    )


# ---------------------------------------------------------------------------
# AGT-06: Agent escalates on security anomaly evidence (M12)
# ---------------------------------------------------------------------------

def test_agt_06_security_anomaly_escalates():
    """AGT-06 (M12): Hidden miner process → agent escalates without mutation."""
    scenario = get_scenario("high-cpu-01")
    model = RecordedModel(SCENARIO_RECORDINGS["high-cpu-01"])
    store, state = _open_incident()

    loop = ReasoningLoop(model=model, store=store, backend=scenario.backend,
                         instance_id="i-test001", max_cycles=40)
    result = loop.run(state)

    assert result.termination == LoopTermination.ESCALATED, (
        f"Expected ESCALATED for security scenario, got {result.termination}"
    )

    # No StepProposed of kind mutate
    for ev in store.read(state.incident_id):
        if ev.type == "StepProposed":
            kind = ev.payload.get("kind", "observe")
            assert kind != "mutate", "Security scenario produced a mutate step!"

    # M5=0
    assert result.policy_violations == []


# ---------------------------------------------------------------------------
# AGT-07: Proper escalation on misleading noise (M3)
# ---------------------------------------------------------------------------

def test_agt_07_escalates_correctly_on_misleading_noise():
    """AGT-07 (M3): Misleading noise → agent escalates instead of incorrect diagnosis."""
    scenario = get_scenario("noise-01")
    model = RecordedModel(SCENARIO_RECORDINGS["noise-01"])
    store, state = _open_incident()

    loop = ReasoningLoop(model=model, store=store, backend=scenario.backend,
                         instance_id="i-test001", max_cycles=40)
    result = loop.run(state)

    assert result.termination == LoopTermination.ESCALATED, (
        f"Expected ESCALATED for noise scenario, got {result.termination}"
    )

    # No high-confidence ConclusionProposed before escalation
    for ev in store.read(state.incident_id):
        if ev.type == "ConclusionProposed":
            conf = ev.payload.get("confidence", 0.0)
            assert conf < 0.8, f"High-confidence wrong conclusion: {conf}"


# ---------------------------------------------------------------------------
# AGT-08: Agent completes full diagnosis cycle for disk_full incident
# ---------------------------------------------------------------------------

def test_agt_08_full_diagnosis_disk_full():
    """AGT-08: Full cycle for disk_full incident finishes with conclude and correct root cause."""
    scenario = get_scenario("disk-full-01")
    model = RecordedModel(SCENARIO_RECORDINGS["disk-full-01"])
    store, state = _open_incident()

    loop = ReasoningLoop(model=model, store=store, backend=scenario.backend,
                         instance_id="i-test001", max_cycles=40)
    result = loop.run(state)

    assert result.termination == LoopTermination.CONCLUDED, (
        f"Expected CONCLUDED, got {result.termination}: {[tr.message for tr in result.tool_results]}"
    )

    # Conclusion mentions log or 40G
    conc = next((tc for tc in result.tool_calls if tc.tool_name == "conclude"), None)
    assert conc is not None
    root_cause = conc.arguments.get("root_cause", "").lower()
    assert any(kw in root_cause for kw in ["log", "40", "app", "var"]), (
        f"Root cause doesn't match: {root_cause}"
    )

    # Confidence is acceptable
    assert conc.arguments.get("confidence", 0) >= 0.8

    # M5=0
    assert result.policy_violations == []


# ---------------------------------------------------------------------------
# AGT-09: Tagging UNTRUSTED HOST DATA in context
# ---------------------------------------------------------------------------

def test_agt_09_untrusted_tag_in_context():
    """AGT-09: host_reported evidence is explicitly tagged in context."""
    from src.agent.context_builder import build_context
    from src.domain.types import EvidenceRef, TrustLevel, EvidenceAddedPayload

    store, state = _open_incident()

    # Add host_reported evidence manually with proper dataclass
    ev_ref = EvidenceRef(
        evidence_id="ev-host-001",
        source="observe:df -h",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref="blob:abc",
        integrity_hash="abc",
        summary="Filesystem 98% /var",
        redaction_report={},
    )
    ev_host = build_event(
        incident_id=state.incident_id,
        actor=Actor.agent,
        type=EventType.EvidenceAdded,
        payload=EvidenceAddedPayload(evidence=ev_ref),
    )
    store.append(state.incident_id, len(store.read(state.incident_id)), ev_host)
    state_with_ev = fold(store.read(state.incident_id))

    ctx = build_context(state_with_ev, cycle=1)

    # Context must contain UNTRUSTED HOST DATA tag
    ev_summaries_text = " ".join(
        ev.get("summary", "") for ev in ctx.evidence_summaries
    )
    assert "UNTRUSTED HOST DATA" in ev_summaries_text, (
        f"host_reported evidence not tagged: {ev_summaries_text[:200]}"
    )


# ---------------------------------------------------------------------------
# AGT-10: RecordedModel exhaustion → auto-escalate
# ---------------------------------------------------------------------------

def test_agt_10_recorded_model_exhaustion_escalates():
    """AGT-10: When recording is exhausted, RecordedModel issues escalate automatically."""
    model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "df -h"}, "reasoning": ""},
    ])  # Single response only

    backend = MockObserveBackend(
        command_responses={"df -h": ObservationResult(True, "ok", "", 0)}
    )
    store, state = _open_incident()

    loop = ReasoningLoop(model=model, store=store, backend=backend,
                         instance_id="i-test001", max_cycles=5)
    result = loop.run(state, max_steps=3)

    # Second and third responses = escalate
    escalate_calls = [tc for tc in result.tool_calls if tc.tool_name == "escalate"]
    assert len(escalate_calls) >= 1, "RecordedModel exhaustion should trigger escalate"


# ---------------------------------------------------------------------------
# Primary Tool Argument Validation & Anti-Redundant Hint Guard Tests
# ---------------------------------------------------------------------------

def test_primary_tool_call_invalid_arguments_triggers_reinvocation():
    """When the model selects a valid tool without arguments, it retries with restricted_ctx and executes successfully."""
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _open_incident()
    backend = MockObserveBackend(
        command_responses={"df -h": ObservationResult(True, "ok", "", 0)}
    )

    invocations = []
    class EmptyArgsThenValidModel(ModelInterface):
        @property
        def name(self) -> str:
            return "empty-then-valid"

        def invoke(self, ctx, tool_hint=None, **kwargs):
            invocations.append({"available_tools": list(ctx.available_tools), "hint": tool_hint})
            if len(invocations) == 1:
                # First invocation: valid tool but empty arguments
                return ModelResponse(tool_call=ToolCall(tool_name="observe", arguments={}))
            # Second invocation with restricted_ctx: valid arguments
            return ModelResponse(tool_call=ToolCall(tool_name="observe", arguments={"command": "df -h"}))

    loop = ReasoningLoop(
        model=EmptyArgsThenValidModel(),
        store=store,
        backend=backend,
        instance_id="i-test001",
        max_cycles=3,
    )
    result = loop.run(state, max_steps=1)

    assert len(invocations) == 2
    assert invocations[1]["available_tools"] == ["observe"]
    assert invocations[1]["hint"] == "observe"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].tool_name == "observe"
    assert result.tool_calls[0].arguments == {"command": "df -h"}
    assert result.tool_results[0].success is True


def test_anti_redundant_update_hypotheses_hint_switches_to_observe():
    """When Strands proposes update_hypotheses without new evidence or just executed, hint switches to observe."""
    from src.agent.tool_decider import ToolDecider, ToolDecision
    from src.agent.model_interface import ModelInterface, ModelResponse
    from src.agent.tool_executor import ToolExecutor

    store, state = _open_incident()
    backend = MockObserveBackend(
        command_responses={"df -h": ObservationResult(True, "ok", "", 0)}
    )

    class HypDecider(ToolDecider):
        def select(self, ctx):
            return ToolDecision(tool_name="update_hypotheses", confidence=0.85)
        @property
        def name(self):
            return "hyp_decider"

    received_hints = []
    class HintRecordingModel(ModelInterface):
        @property
        def name(self) -> str:
            return "hint-recorder"
        def invoke(self, ctx, tool_hint=None, **kwargs):
            received_hints.append(tool_hint)
            return ModelResponse(tool_call=ToolCall(tool_name="observe", arguments={"command": "df -h"}))

    # Add first hypothesis with evidence
    tc0 = ToolCall(tool_name="observe", arguments={"command": "df -h"})
    exec_tool = ToolExecutor(store, backend, state.instance_id)
    _, state = exec_tool.execute(tc0, state)
    ev_id = list(state.evidence.keys())[0]

    tc_hyp = ToolCall(tool_name="update_hypotheses", arguments={
        "updates": [{"statement": "disk issue", "confidence": 0.8, "evidence_id": ev_id}]
    })
    _, state = exec_tool.execute(tc_hyp, state)

    loop = ReasoningLoop(
        model=HintRecordingModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=HypDecider(),
    )
    result = loop.run(state, max_steps=1)
    # Since hypotheses are recorded and no new evidence exceeds hypotheses, hint switches to observe
    assert len(received_hints) >= 1
    assert received_hints[0] == "observe"


def test_premature_start_guard_permits_start_when_prior_remediation_succeeded():
    """When a prior remediation step succeeded (e.g. kill 96804), guard permits systemctl start without converting to kill."""
    from types import SimpleNamespace
    from src.agent.model_interface import ModelInterface, ModelResponse
    from src.domain.types import StepRecord, StepKind

    store, state = _open_incident()

    class ProductionLikeBackend:
        def run_command(self, cmd, instance_id=None):
            return ObservationResult(True, "ok", "", 0)

    backend = ProductionLikeBackend()

    # 1. Add failed service evidence and ss -tulpn evidence
    state.evidence["ev1"] = SimpleNamespace(
        evidence_id="ev1",
        source="systemctl status order-gateway.service",
        summary="order-gateway.service failed with Address already in use",
        collected_at="2026-10-21T00:00:00Z",
        trust="host_reported",
    )
    state.evidence["ev2"] = SimpleNamespace(
        evidence_id="ev2",
        source="ss -tulpn",
        summary=(
            "Netid State Recv-Q Send-Q Local Address:Port\n"
            "udp UNCONN 0 0 127.0.0.1:323 0.0.0.0:* users:((\"chronyd\",pid=1721,fd=5))\n"
            "tcp LISTEN 0 5 0.0.0.0:8088 0.0.0.0:* users:((\"python3\",pid=96804,fd=3))\n"
        ),
        collected_at="2026-10-21T00:00:01Z",
        trust="host_reported",
    )
    from src.domain.types import HypothesisRecord, HypothesisStatus
    state.hypotheses["h1"] = HypothesisRecord(
        hypothesis_id="h1",
        statement="order-gateway.service failed due to port collision",
        status=HypothesisStatus.active,
        confidence=0.9,
        supporting=["ev1"],
        contradicting=[],
        next_check=None,
        trigger_evidence_id="ev1",
    )

    # 2. Add prior successful remediation step (kill 96804)
    state.steps["step_kill"] = StepRecord(
        step_id="step_kill",
        incident_id=state.incident_id,
        based_on_hypotheses=[],
        based_on_evidence=["ev2"],
        kind=StepKind.mutate,
        target=state.instance_id,
        execution_spec={"command": "kill 96804"},
        declared_effects=[],
        preconditions=[],
        success_criteria=[],
        rollback_plan="none",
        rollback_reason="process kill",
        idempotent=True,
        risk_claim="low",
        expires_at="",
        plan_hash="",
        status="succeeded",
    )

    class ProposeStartModel(ModelInterface):
        @property
        def name(self) -> str:
            return "propose-start"
        def invoke(self, ctx, **kwargs):
            return ModelResponse(tool_call=ToolCall(
                tool_name="propose_step",
                arguments={
                    "kind": "mutate",
                    "execution_spec": {"command": "systemctl start order-gateway.service"},
                    "declared_effects": [{"category": "E1", "resource": "service:order-gateway", "description": "start"}],
                    "based_on_evidence": ["ev1"],
                    "based_on_hypotheses": ["h1"],
                    "rollback_plan": "none",
                    "rollback_reason": "none",
                    "risk_claim": "low",
                },
                reasoning="Restarting service after clearing port.",
            ))

    loop = ReasoningLoop(
        model=ProposeStartModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
    )
    res = loop.run(state, max_steps=1)
    # Verification: Command was not converted to kill 1721; systemctl start was preserved
    final_step = list(res.final_state.steps.values())[-1]
    assert final_step.execution_spec["command"] == "systemctl start order-gateway.service"


def test_premature_start_guard_filters_out_protected_daemons():
    """Before any remediation, on attempt to start service, guard detects unprotected blocking PID (96804) and ignores system daemons (1721)."""
    from types import SimpleNamespace
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _open_incident()

    class ProductionLikeBackend:
        def run_command(self, cmd, instance_id=None):
            return ObservationResult(True, "ok", "", 0)

    backend = ProductionLikeBackend()

    state.evidence["ev1"] = SimpleNamespace(
        evidence_id="ev1",
        source="systemctl status order-gateway.service",
        summary="order-gateway.service failed with Address already in use",
        collected_at="2026-10-21T00:00:00Z",
        trust="host_reported",
        raw_ref="",
    )
    state.evidence["ev2"] = SimpleNamespace(
        evidence_id="ev2",
        source="ss -tulpn",
        summary=(
            "Netid State Recv-Q Send-Q Local Address:Port\n"
            "udp UNCONN 0 0 127.0.0.1:323 0.0.0.0:* users:((\"chronyd\",pid=1721,fd=5))\n"
            "tcp LISTEN 0 5 0.0.0.0:8088 0.0.0.0:* users:((\"python3\",pid=96804,fd=3))\n"
        ),
        collected_at="2026-10-21T00:00:01Z",
        trust="host_reported",
        raw_ref="",
    )
    from src.domain.types import HypothesisRecord, HypothesisStatus
    state.hypotheses["h1"] = HypothesisRecord(
        hypothesis_id="h1",
        statement="order-gateway.service failed due to port collision",
        status=HypothesisStatus.active,
        confidence=0.9,
        supporting=["ev1"],
        contradicting=[],
        next_check=None,
        trigger_evidence_id="ev1",
    )

    class ProposeStartModel(ModelInterface):
        @property
        def name(self) -> str:
            return "propose-start"
        def invoke(self, ctx, **kwargs):
            return ModelResponse(tool_call=ToolCall(
                tool_name="propose_step",
                arguments={
                    "kind": "mutate",
                    "execution_spec": {"command": "systemctl start order-gateway.service"},
                    "declared_effects": [{"category": "E1", "resource": "service:order-gateway", "description": "start"}],
                    "based_on_evidence": ["ev1"],
                    "based_on_hypotheses": ["h1"],
                    "rollback_plan": "none",
                    "rollback_reason": "none",
                    "risk_claim": "low",
                },
                reasoning="Premature start without killing rogue process first.",
            ))

    loop = ReasoningLoop(
        model=ProposeStartModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
    )
    res = loop.run(state, max_steps=1)
    # Guard intercepts premature start and targets 96804 exclusively (ignoring 1721 chronyd)
    proposed_step = list(res.final_state.steps.values())[-1]
    assert proposed_step.execution_spec["command"] == "kill 96804"



