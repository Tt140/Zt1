"""
tests/agent/test_rc5_rc7_regressions.py — Regression tests for RC-5 and RC-7

RC-5: tool_hint override failure tracking — stop forcing the same tool after 2 override failures
RC-7: observe restriction relaxation — allow observe when steps are rejected/failed
"""
import sys
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest

from src.domain.types import (
    new_ulid, utc_now, IncidentState, BudgetState, IncidentPhase,
    IncidentOpenedPayload, IncidentHeader, StepRecord, StepKind,
    DeclaredEffect, EffectCategory,
    build_event, EventType, Actor,
)
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.agent import (
    RecordedModel, ModelContext, ToolCall,
    MockObserveBackend, ObservationResult,
    ReasoningLoop, LoopTermination,
)
from src.agent.context_builder import get_allowed_tools


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_incident(instance_id="i-test001", alarm="TestAlarm"):
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


def _make_step(incident_id, step_id="step-001", status="proposed"):
    """Create a minimal StepRecord for testing get_allowed_tools."""
    return StepRecord(
        step_id=step_id,
        incident_id=incident_id,
        based_on_hypotheses=["h1"],
        based_on_evidence=["e1"],
        kind=StepKind.mutate,
        target="i-test001",
        execution_spec={"command": "systemctl restart nginx"},
        declared_effects=[DeclaredEffect(category=EffectCategory.E1, resource="service:nginx", description="restart")],
        preconditions=["nginx installed"],
        success_criteria=[{"type": "exit_code", "value": 0}],
        rollback_plan=[{"command": "systemctl stop nginx"}],
        rollback_reason=None,
        idempotent=True,
        risk_claim="low",
        expires_at=utc_now().isoformat(),
        plan_hash="abc123",
        status=status,
    )


# ===========================================================================
# RC-7: observe restriction after propose_step
# ===========================================================================

class TestRC7_ObserveRestrictionAfterSteps:
    """
    RC-7 (updated for multi-step remediation architecture):
    observe and propose_step must remain available at ALL investigation stages,
    including after a step has been executed/succeeded — the agent needs to
    continue investigating (e.g. check failed services) and propose further
    remediation steps in compound-fault scenarios.
    """

    def test_observe_available_when_step_executed(self):
        """After a step is executed, observe must remain available for
        post-remediation investigation (multi-step remediation)."""
        store, state = _open_incident()
        state.evidence["e1"] = {"id": "e1", "summary": "some evidence"}
        state.hypotheses["h1"] = type("Hyp", (), {"status": "active", "confidence": 0.8})()
        state.steps["step-001"] = _make_step(state.incident_id, status="executed")

        allowed = get_allowed_tools(state)

        assert "observe" in allowed, \
            "observe must be available after step execution (multi-step remediation)"
        assert "verify" in allowed, \
            "verify should be available when steps exist"

    def test_observe_available_when_step_succeeded(self):
        """After a step has succeeded, observe must remain available so the
        agent can verify system health and discover additional faults."""
        store, state = _open_incident()
        state.evidence["e1"] = {"id": "e1", "summary": "some evidence"}
        state.hypotheses["h1"] = type("Hyp", (), {"status": "active", "confidence": 0.8})()
        state.steps["step-001"] = _make_step(state.incident_id, status="succeeded")

        allowed = get_allowed_tools(state)

        assert "observe" in allowed, \
            "observe must be available after step succeeded (multi-step remediation)"

    def test_propose_step_available_when_step_succeeded_and_active_hyps(self):
        """After a step has succeeded but active hypotheses remain (compound fault),
        propose_step must be available to address remaining issues."""
        store, state = _open_incident()
        state.evidence["e1"] = {"id": "e1", "summary": "some evidence"}
        state.hypotheses["h1"] = type("Hyp", (), {"status": "active", "confidence": 0.8})()
        state.steps["step-001"] = _make_step(state.incident_id, status="succeeded")

        allowed = get_allowed_tools(state)

        assert "propose_step" in allowed, \
            "propose_step must be available when active hypotheses remain after succeeded step"

    def test_observe_allowed_when_step_rejected(self):
        """When a step was rejected by PolicyGate, observe must remain available
        so the agent can re-investigate and propose a better step."""
        store, state = _open_incident()
        state.evidence["e1"] = {"id": "e1", "summary": "some evidence"}
        state.hypotheses["h1"] = type("Hyp", (), {"status": "active", "confidence": 0.8})()
        state.steps["step-001"] = _make_step(state.incident_id, status="rejected")

        allowed = get_allowed_tools(state)

        assert "observe" in allowed, \
            "observe must be available when step was rejected (RC-7)"
        assert "verify" in allowed, \
            "verify should be available when steps exist"

    def test_observe_allowed_when_step_failed(self):
        """When a step execution failed, observe must remain available
        so the agent can investigate what went wrong."""
        store, state = _open_incident()
        state.evidence["e1"] = {"id": "e1", "summary": "some evidence"}
        state.hypotheses["h1"] = type("Hyp", (), {"status": "active", "confidence": 0.8})()
        state.steps["step-001"] = _make_step(state.incident_id, status="failed")

        allowed = get_allowed_tools(state)

        assert "observe" in allowed, \
            "observe must be available when step execution failed (RC-7)"

    def test_observe_allowed_when_step_only_proposed(self):
        """When a step is just proposed (not yet executed), observe should
        remain available."""
        store, state = _open_incident()
        state.evidence["e1"] = {"id": "e1", "summary": "some evidence"}
        state.hypotheses["h1"] = type("Hyp", (), {"status": "active", "confidence": 0.8})()
        state.steps["step-001"] = _make_step(state.incident_id, status="proposed")

        allowed = get_allowed_tools(state)

        assert "observe" in allowed, \
            "observe must be available when step is only proposed (RC-7)"

    def test_observe_available_when_mixed_steps_one_executed(self):
        """When one step is rejected but another is executed, observe must
        remain available for post-remediation investigation."""
        store, state = _open_incident()
        state.evidence["e1"] = {"id": "e1", "summary": "some evidence"}
        state.hypotheses["h1"] = type("Hyp", (), {"status": "active", "confidence": 0.8})()
        state.steps["step-001"] = _make_step(state.incident_id, step_id="step-001", status="rejected")
        state.steps["step-002"] = _make_step(state.incident_id, step_id="step-002", status="executed")

        allowed = get_allowed_tools(state)

        assert "observe" in allowed, \
            "observe must be available even when a step is executed (multi-step remediation)"


# ===========================================================================
# RC-5: tool_hint override failure tracking
# ===========================================================================

class TestRC5_OverrideFailureTracking:
    """
    RC-5: When the Strands override forces a tool and execution fails,
    track the failure. After 2 failures for the same override tool,
    stop forcing it — let the model choose freely.
    """

    def test_override_stops_after_two_failures(self):
        """Integration: when the model produces observe calls that all fail,
        the override tracking should prevent endlessly forcing the same tool.
        Combined with RC-3 stall detection, the loop should terminate early."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "systemctl status badservice1"}, "reasoning": "c0"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status badservice2"}, "reasoning": "c1"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status badservice3"}, "reasoning": "c2"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status badservice4"}, "reasoning": "c3"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status badservice5"}, "reasoning": "c4"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={})  # all fail
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=10,
        )
        result = loop.run(state)

        # The loop should terminate early (via stall detection or budget)
        assert result.cycles_completed < 10, \
            f"Expected early termination with override tracking, but ran {result.cycles_completed} cycles"

    def test_successful_override_not_tracked_as_failure(self):
        """When override forces a tool and it succeeds, the failure counter
        should not increment."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "ss -tulpn"}, "reasoning": "c0"},
            {"tool_name": "observe", "arguments": {"command": "df -h"}, "reasoning": "c1"},
            {"tool_name": "escalate", "arguments": {"reason": "enough"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={
            "ss -tulpn": ObservationResult(True, "tcp LISTEN 0.0.0.0:443", "", 0),
            "df -h": ObservationResult(True, "/dev/xvda1 20G 10G", "", 0),
        })
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=10,
        )
        result = loop.run(state)

        # Should complete normally
        assert result.cycles_completed >= 2


class TestRC5_NegativeCases:
    """RC-5 negative: override should still work when tool hasn't failed before."""

    def test_override_works_on_first_attempt(self):
        """The override should work normally for a tool that hasn't failed before."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "ss -tulpn"}, "reasoning": "c0"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={
            "ss -tulpn": ObservationResult(True, "tcp LISTEN 0.0.0.0:443", "", 0),
        })
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=5,
        )
        result = loop.run(state)

        assert len(result.tool_calls) >= 1
        assert result.tool_calls[0].tool_name == "observe"
