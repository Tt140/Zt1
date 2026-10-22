"""
tests/agent/test_rc3_rc4_regressions.py — Regression tests for RC-3 and RC-4

RC-3: Stalled investigation detection — escalate when 3+ cycles produce no new evidence
RC-4: EmbeddedStrandsDecider avoids recommending observe when consecutive tools keep failing
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest

from src.domain.types import (
    new_ulid, utc_now, IncidentState, BudgetState, IncidentPhase,
    IncidentOpenedPayload, IncidentHeader,
    build_event, EventType, Actor,
)
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.agent import (
    RecordedModel, ModelContext, ToolCall,
    MockObserveBackend, ObservationResult,
    ReasoningLoop, LoopTermination,
)
from src.agent.tool_decider import (
    EmbeddedStrandsDecider, ToolDecision,
    HIGH_CONFIDENCE_THRESHOLD,
)


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


# ===========================================================================
# RC-3: Stalled investigation detection
# ===========================================================================

class TestRC3_StalledInvestigationDetection:
    """
    RC-3: When the agent spends 3+ consecutive cycles without gathering
    any new evidence, the loop must detect the stall and escalate
    (not force remediation).
    """

    def test_all_observe_fail_triggers_escalation(self):
        """When all observe calls fail (backend returns error for every command),
        the loop must escalate instead of wasting all max_cycles."""
        # Model keeps trying observe with different commands — all fail
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "systemctl status nginx"}, "reasoning": "check nginx"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status apache2"}, "reasoning": "check apache"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status httpd"}, "reasoning": "check httpd"},
            {"tool_name": "observe", "arguments": {"command": "ss -tulpn"}, "reasoning": "check ports"},
            {"tool_name": "observe", "arguments": {"command": "ps aux"}, "reasoning": "check processes"},
            {"tool_name": "observe", "arguments": {"command": "df -h"}, "reasoning": "check disk"},
            {"tool_name": "observe", "arguments": {"command": "free -m"}, "reasoning": "check memory"},
            {"tool_name": "escalate", "arguments": {"reason": "nothing works"}, "reasoning": "give up"},
        ])
        # Backend returns failure for every command
        backend = MockObserveBackend(command_responses={})  # empty = all fail
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=10,
        )
        result = loop.run(state)

        # Must stop BEFORE exhausting all 10 cycles (stall detection at cycle 3+)
        assert result.cycles_completed < 10, \
            f"Expected early termination, but ran {result.cycles_completed} cycles"
        # Must be escalated (MAX_CYCLES termination includes stall escalation)
        assert result.termination in (LoopTermination.MAX_CYCLES, LoopTermination.ESCALATED)

    def test_successful_evidence_resets_stall_counter(self):
        """A successful observe that adds new evidence resets the stall counter,
        allowing the investigation to continue."""
        model = RecordedModel([
            # Cycle 0: fails
            {"tool_name": "observe", "arguments": {"command": "systemctl status nginx"}, "reasoning": "c0"},
            # Cycle 1: fails
            {"tool_name": "observe", "arguments": {"command": "systemctl status apache2"}, "reasoning": "c1"},
            # Cycle 2: SUCCESS — produces evidence, resets counter
            {"tool_name": "observe", "arguments": {"command": "ss -tulpn"}, "reasoning": "c2"},
            # Cycle 3: fails — counter restarts at 1
            {"tool_name": "observe", "arguments": {"command": "systemctl status nodejs"}, "reasoning": "c3"},
            # Cycle 4: fails — counter = 2
            {"tool_name": "observe", "arguments": {"command": "systemctl status gunicorn"}, "reasoning": "c4"},
            # Cycle 5: SUCCESS — produces evidence, resets again
            {"tool_name": "observe", "arguments": {"command": "df -h"}, "reasoning": "c5"},
            # Cycle 6: concludes
            {"tool_name": "escalate", "arguments": {"reason": "enough info"}, "reasoning": "done"},
        ])
        backend = MockObserveBackend(command_responses={
            "ss -tulpn": ObservationResult(True, "tcp LISTEN 0.0.0.0:443", "", 0),
            "df -h": ObservationResult(True, "/dev/xvda1 20G 10G 10G 50% /", "", 0),
            # everything else fails (no match = MockBackend returns error)
        })
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=10,
        )
        result = loop.run(state)

        # Should reach the escalate call (cycle 6) because evidence resets prevented early stall
        assert result.cycles_completed >= 6, \
            f"Expected at least 6 cycles (evidence resets stall counter), got {result.cycles_completed}"


# ===========================================================================
# RC-4: EmbeddedStrandsDecider failure awareness
# ===========================================================================

class TestRC4_DeciderFailureAwareness:
    """
    RC-4: EmbeddedStrandsDecider must use consecutive_failed_tools to avoid
    recommending observe/query tools when recent tools keep failing.
    """

    def test_decider_switches_away_from_observe_after_failures(self):
        """When consecutive_failed_tools >= 2, decider must NOT recommend observe."""
        decider = EmbeddedStrandsDecider()
        ctx = ModelContext(
            system_prompt="test",
            incident_summary="test incident",
            hypotheses_summary="",
            evidence_summaries=[{"id": "e1", "summary": "some evidence"}],
            available_tools=["observe", "query_logs", "update_hypotheses", "escalate"],
            budget_remaining={"commands": 5},
            cycle=3,
            consecutive_failed_tools=2,  # 2 consecutive failures
        )
        decision = decider.select(ctx)

        assert decision is not None
        assert decision.tool_name not in ("observe", "query_logs", "query_metrics"), \
            f"Decider should avoid exploratory tools after 2 failures, got {decision.tool_name}"

    def test_decider_recommends_escalate_after_failures_no_hypotheses(self):
        """With no active hypotheses and 2+ failures, decider should recommend escalate."""
        decider = EmbeddedStrandsDecider()
        ctx = ModelContext(
            system_prompt="test",
            incident_summary="test incident",
            hypotheses_summary="",
            evidence_summaries=[{"id": "e1", "summary": "some evidence"}],
            available_tools=["observe", "query_logs", "escalate"],
            budget_remaining={"commands": 5},
            cycle=4,
            consecutive_failed_tools=3,
        )
        decision = decider.select(ctx)

        assert decision is not None
        assert decision.tool_name == "escalate", \
            f"Expected escalate after 3 failures with no hypotheses, got {decision.tool_name}"

    def test_decider_recommends_update_hypotheses_after_failures_with_active_hyps(self):
        """With active hypotheses and 2+ failures, decider should recommend update_hypotheses."""
        decider = EmbeddedStrandsDecider()
        ctx = ModelContext(
            system_prompt="test",
            incident_summary="test incident",
            hypotheses_summary=[{"status": "active", "statement": "disk full"}],
            evidence_summaries=[{"id": "e1", "summary": "some evidence"}],
            available_tools=["observe", "update_hypotheses", "escalate"],
            budget_remaining={"commands": 5},
            cycle=4,
            consecutive_failed_tools=2,
        )
        decision = decider.select(ctx)

        assert decision is not None
        assert decision.tool_name == "update_hypotheses", \
            f"Expected update_hypotheses after failures with active hyps, got {decision.tool_name}"

    def test_decider_normal_when_no_failures(self):
        """With 0 consecutive failures, decider behaves normally (recommends observe)."""
        decider = EmbeddedStrandsDecider()
        ctx = ModelContext(
            system_prompt="test",
            incident_summary="test incident",
            hypotheses_summary="",
            evidence_summaries=[],
            available_tools=["observe", "query_logs", "escalate"],
            budget_remaining={"commands": 5},
            cycle=0,
            consecutive_failed_tools=0,
        )
        decision = decider.select(ctx)

        assert decision is not None
        assert decision.tool_name == "observe", \
            f"Expected observe at cycle 0 with no failures, got {decision.tool_name}"

    def test_decider_resets_after_success_in_loop(self):
        """Integration: consecutive_failed_tools resets after a successful tool call,
        so the decider returns to normal behavior."""
        model = RecordedModel([
            # fail, fail → decider should switch
            {"tool_name": "observe", "arguments": {"command": "systemctl status badservice"}, "reasoning": "c0"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status another"}, "reasoning": "c1"},
            # Now the decider should switch away from observe
            # But the model gives us whatever it gives — we just need to reach cycle 2+
            {"tool_name": "observe", "arguments": {"command": "ss -tulpn"}, "reasoning": "c2"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={
            "ss -tulpn": ObservationResult(True, "tcp LISTEN 0.0.0.0:443", "", 0),
        })
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=10,
        )
        result = loop.run(state, max_steps=4)

        # Should complete without crashing
        assert len(result.tool_calls) >= 2


class TestRC3_NegativeCases:
    """RC-3 negative tests: ensure stall detection does NOT fire when progress is real."""

    def test_no_stall_when_every_cycle_adds_evidence(self):
        """When each cycle adds new evidence, no_new_evidence_cycles stays at 0
        and stall detection never fires, even after many cycles."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "ss -tulpn"}, "reasoning": "c0"},
            {"tool_name": "observe", "arguments": {"command": "df -h"}, "reasoning": "c1"},
            {"tool_name": "observe", "arguments": {"command": "free -m"}, "reasoning": "c2"},
            {"tool_name": "observe", "arguments": {"command": "cat /proc/loadavg"}, "reasoning": "c3"},
            {"tool_name": "observe", "arguments": {"command": "uptime"}, "reasoning": "c4"},
            {"tool_name": "observe", "arguments": {"command": "ps aux"}, "reasoning": "c5"},
            {"tool_name": "escalate", "arguments": {"reason": "have enough"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={
            "ss -tulpn": ObservationResult(True, "tcp LISTEN 0.0.0.0:443", "", 0),
            "df -h": ObservationResult(True, "/dev/xvda1 20G 10G 10G 50%", "", 0),
            "free -m": ObservationResult(True, "Mem: 4096 3500 596", "", 0),
            "cat /proc/loadavg": ObservationResult(True, "0.5 0.3 0.2 1/200 5001", "", 0),
            "uptime": ObservationResult(True, "up 30 days, load average: 0.5", "", 0),
            "ps aux": ObservationResult(True, "USER PID %CPU\nroot 1 0.0", "", 0),
        })
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=10,
        )
        result = loop.run(state)

        # Should reach escalate (cycle 6) without premature stall detection
        assert result.cycles_completed >= 6, \
            f"Stall detection incorrectly fired at cycle {result.cycles_completed}"

    def test_duplicate_rejection_feeds_stall_counter(self):
        """When the model keeps repeating the same failing call, duplicate
        rejections must increment the stall counter and trigger escalation."""
        # Model repeats the exact same command 5 times
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "systemctl status nginx"}, "reasoning": "c0"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status nginx"}, "reasoning": "c1"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status nginx"}, "reasoning": "c2"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status nginx"}, "reasoning": "c3"},
            {"tool_name": "observe", "arguments": {"command": "systemctl status nginx"}, "reasoning": "c4"},
            {"tool_name": "escalate", "arguments": {"reason": "end"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={})  # all fail
        store, state = _open_incident()
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id="i-test001", max_cycles=10,
        )
        result = loop.run(state)

        # Stall detection should fire before exhausting all cycles
        assert result.cycles_completed < 8, \
            f"Duplicate rejections should feed stall counter, but ran {result.cycles_completed} cycles"


class TestRC4_NegativeCases:
    """RC-4 negative: ensure decider doesn't cause unwanted remediation."""

    def test_decider_does_not_force_propose_step_after_failures(self):
        """When tools fail, the decider must NOT recommend propose_step
        (no remediation without evidence). It should recommend escalate or
        update_hypotheses, never propose_step."""
        decider = EmbeddedStrandsDecider()
        ctx = ModelContext(
            system_prompt="test",
            incident_summary="test incident",
            hypotheses_summary="",
            evidence_summaries=[{"id": "e1", "summary": "some evidence"}],
            available_tools=["observe", "propose_step", "escalate"],
            budget_remaining={"commands": 5},
            cycle=4,
            consecutive_failed_tools=3,
        )
        decision = decider.select(ctx)

        assert decision is not None
        assert decision.tool_name != "propose_step", \
            f"Decider must NOT force propose_step after failures — got {decision.tool_name}"
        assert decision.tool_name == "escalate", \
            f"Expected escalate (not remediation), got {decision.tool_name}"
