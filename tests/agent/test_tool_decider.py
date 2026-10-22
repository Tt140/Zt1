"""
tests/agent/test_tool_decider.py

Demonstrates:
1. Strands selection binds executed tool — model cannot bypass it
2. confidence < LOW_THRESHOLD → immediate escalation (no unsafe execution)
3. NullToolDecider → unmodified loop.py behavior (backward compat)
4. RecordedModel/BranchingModel work with tool_hint without breaking
5. Policy Gate is enforced after Strands selection
"""
import pytest
from unittest.mock import MagicMock, patch
from typing import Optional

from src.agent.tool_decider import (
    ToolDecider, ToolDecision, NullToolDecider,
    HIGH_CONFIDENCE_THRESHOLD, LOW_CONFIDENCE_THRESHOLD,
)
from src.agent.model_interface import (
    ModelInterface, ModelContext, ModelResponse, ToolCall, RecordedModel,
)
from src.agent.loop import ReasoningLoop, LoopTermination
from src.store.memory import MemoryEventStore
from src.agent.mock_backend import MockObserveBackend
from src.domain.types import (
    IncidentHeader, build_event, EventType, Actor,
    IncidentOpenedPayload, new_ulid,
)
from src.domain.reducer import fold


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_store_and_state(instance_id: str = "i-test"):
    store = MemoryEventStore()
    dedupe_key = f"alarm::{new_ulid()}"
    incident_id = new_ulid()
    header = IncidentHeader(
        incident_id=incident_id,
        instance_id=instance_id,
        dedupe_key=dedupe_key,
        alarm_name="test-alarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
        alert_source="rule/test",
        opened_at="2026-01-01T00:00:00Z",
    )
    iid, _ = store.create_if_absent(dedupe_key, header)
    ev = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=instance_id,
            dedupe_key=dedupe_key,
            alarm_name="test-alarm",
            alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
            alert_source="rule/test",
        ),
    )
    store.append(iid, 0, ev)
    state = fold(store.read(iid))
    return store, state


class _FixedDecider(ToolDecider):
    """Selects a fixed tool with a specified confidence."""
    def __init__(self, tool_name: str, confidence: float):
        self._tool = tool_name
        self._confidence = confidence

    def select(self, ctx: ModelContext) -> Optional[ToolDecision]:
        return ToolDecision(tool_name=self._tool, confidence=self._confidence)

    @property
    def name(self) -> str:
        return f"fixed:{self._tool}@{self._confidence}"


# ─────────────────────────────────────────────────────────────────────────────
# 1. ToolDecision validation
# ─────────────────────────────────────────────────────────────────────────────

class TestToolDecision:
    def test_valid_tool_accepted(self):
        d = ToolDecision(tool_name="observe", confidence=0.9)
        assert d.tool_name == "observe"
        assert d.is_high_confidence

    def test_invalid_tool_raises(self):
        with pytest.raises(ValueError, match="invalid tool"):
            ToolDecision(tool_name="rm_rf", confidence=0.9)

    def test_confidence_out_of_range_raises(self):
        with pytest.raises(ValueError, match="confidence"):
            ToolDecision(tool_name="observe", confidence=1.5)

    def test_low_confidence_flag(self):
        # 0.10 < LOW_CONFIDENCE_THRESHOLD (0.15) → is_low_confidence
        # Reflects an incident without evidence with an entirely random choice
        d = ToolDecision(tool_name="escalate", confidence=0.10)
        assert d.is_low_confidence
        assert not d.is_high_confidence

    def test_review_required_flag(self):
        # 0.25: between LOW (0.15) and HIGH (0.35) → requires_human_review
        # Reflects calibrated confidence for first cycle observe in Strands 2B (~0.23)
        d = ToolDecision(tool_name="propose_step", confidence=0.25)
        assert d.requires_human_review
        assert not d.is_low_confidence
        assert not d.is_high_confidence


# ─────────────────────────────────────────────────────────────────────────────
# 2. ReasoningLoop: Strands selection is binding
# ─────────────────────────────────────────────────────────────────────────────

class TestStrandsBinding:
    def test_decider_observe_overrides_model_when_choice_invalid_or_failed(self):
        """
        Model fails or selects forbidden tool; Strands acts as safety net and selects observe.
        observe must be executed as safety net.
        """
        store, state = _make_store_and_state()
        backend = MockObserveBackend()

        # Model chooses forbidden tool
        model = RecordedModel([
            {"tool_name": "forbidden_tool", "arguments": {}},
        ])

        # Strands chooses observe with high confidence
        decider = _FixedDecider("observe", confidence=0.85)

        loop = ReasoningLoop(
            model=model,
            store=store,
            backend=backend,
            instance_id=state.instance_id,
            max_cycles=3,
            tool_decider=decider,
        )
        result = loop.run(state, max_steps=1)

        # Executed tool must be observe (safety net from Strands)
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].tool_name == "observe", (
            f"Expected 'observe' from Strands, got {result.tool_calls[0].tool_name!r}"
        )

    def test_decider_respects_valid_model_choice(self):
        """
        Model selects valid tool (observe) while Strands suggests query_metrics.
        Must respect generative model choice without overriding it.
        """
        store, state = _make_store_and_state()
        backend = MockObserveBackend()

        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "uptime"}},
        ])
        decider = _FixedDecider("query_metrics", confidence=0.85)

        loop = ReasoningLoop(
            model=model,
            store=store,
            backend=backend,
            instance_id=state.instance_id,
            max_cycles=3,
            tool_decider=decider,
        )
        result = loop.run(state, max_steps=1)

        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].tool_name == "observe"
        assert result.tool_calls[0].arguments == {"command": "uptime"}

    def test_model_cannot_override_decider_tool(self):
        """Model selects conclude (unavailable due to lack of evidence); Strands binds to query_metrics."""
        store, state = _make_store_and_state()
        backend = MockObserveBackend()

        model = RecordedModel([
            {"tool_name": "conclude", "arguments": {"root_cause": "model decision"}},
        ])
        decider = _FixedDecider("query_metrics", confidence=0.75)

        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id=state.instance_id, max_cycles=3, tool_decider=decider,
        )
        result = loop.run(state, max_steps=1)

        assert result.tool_calls[0].tool_name == "query_metrics"

    def test_strands_safety_net_override_restricts_available_tools_on_reinvoke(self):
        """
        When Strands safety net override triggers model.invoke re-invocation due to
        incompatible arguments, ctx passed to second call contains exclusively
        available_tools=[decision.tool_name].
        """
        store, state = _make_store_and_state()
        backend = MockObserveBackend()

        from src.domain.types import EvidenceRef, EvidenceAddedPayload, TrustLevel, EventType, Actor, build_event
        from src.domain.reducer import fold

        ev_ref = EvidenceRef(
            evidence_id="ev-1",
            source="observe:df",
            trust=TrustLevel.host_reported,
            collected_at="2026-01-01T00:00:00Z",
            raw_ref=None,
            integrity_hash="h1",
            summary="resource stats",
            redaction_report={},
        )
        ev = build_event(
            incident_id=state.incident_id,
            type=EventType.EvidenceAdded,
            actor=Actor.agent,
            payload=EvidenceAddedPayload(evidence=ev_ref),
        )
        store.append(state.incident_id, 1, ev)
        state = fold(store.read(state.incident_id))

        class _SpyModel(ModelInterface):
            def __init__(self):
                self.invoked_contexts: list[ModelContext] = []
                self.invoked_hints: list[Optional[str]] = []
                self.calls = [
                    ToolCall("conclude", {"root_cause": "not allowed yet", "confidence": 0.9}),
                    ToolCall("update_hypotheses", {
                        "updates": [{
                            "statement": "potential disk pressure",
                            "confidence": 0.8,
                            "evidence_id": "ev-1",
                            "status": "active",
                        }]
                    }),
                ]

            @property
            def name(self) -> str:
                return "spy-model"

            def invoke(self, ctx: ModelContext, tool_hint: Optional[str] = None, **kwargs) -> ModelResponse:
                self.invoked_contexts.append(ctx)
                self.invoked_hints.append(tool_hint)
                call = self.calls.pop(0) if self.calls else ToolCall("escalate", {})
                return ModelResponse(tool_call=call)

        spy_model = _SpyModel()
        decider = _FixedDecider("update_hypotheses", confidence=0.85)

        loop = ReasoningLoop(
            model=spy_model,
            store=store,
            backend=backend,
            instance_id=state.instance_id,
            max_cycles=3,
            tool_decider=decider,
        )
        result = loop.run(state, max_steps=1)

        # Model invoked twice: first call failed/invalid, second call retried
        assert len(spy_model.invoked_contexts) == 2
        # First call contains all available tools
        assert len(spy_model.invoked_contexts[0].available_tools) > 1
        assert "update_hypotheses" in spy_model.invoked_contexts[0].available_tools

        # Second call contains exclusively tool enforced by Strands
        assert spy_model.invoked_contexts[1].available_tools == ["update_hypotheses"]
        assert spy_model.invoked_hints[1] == "update_hypotheses"

        # Confirm enforced tool executed successfully
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].tool_name == "update_hypotheses"

    def test_null_decider_model_decides_freely(self):
        """NullToolDecider: Model chooses freely — backward compat."""
        store, state = _make_store_and_state()
        backend = MockObserveBackend()

        model = RecordedModel([
            {"tool_name": "escalate", "arguments": {"reason": "free choice"}},
        ])
        decider = NullToolDecider()

        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id=state.instance_id, max_cycles=3, tool_decider=decider,
        )
        result = loop.run(state, max_steps=1)

        # NullToolDecider changes nothing
        assert result.tool_calls[0].tool_name == "escalate"

    def test_no_decider_backward_compat(self):
        """Without tool_decider: existing test behavior remains unchanged."""
        store, state = _make_store_and_state()
        backend = MockObserveBackend()

        model = RecordedModel([
            {"tool_name": "escalate", "arguments": {"reason": "original behavior"}},
        ])

        # Without tool_decider — must behave exactly as before
        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id=state.instance_id, max_cycles=3,
        )
        result = loop.run(state, max_steps=1)
        assert result.tool_calls[0].tool_name == "escalate"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Low Confidence → Immediate Escalation
# ─────────────────────────────────────────────────────────────────────────────

class TestLowConfidenceEscalation:
    def test_below_threshold_escalates_immediately(self):
        """confidence < LOW_THRESHOLD → incident escalated without executing any tool."""
        store, state = _make_store_and_state()
        backend = MockObserveBackend()
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "df -h"}},
        ])

        # Very low confidence
        decider = _FixedDecider("observe", confidence=LOW_CONFIDENCE_THRESHOLD - 0.01)

        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id=state.instance_id, max_cycles=3, tool_decider=decider,
        )
        result = loop.run(state, max_steps=1)

        # Outcome: escalation
        assert result.termination == LoopTermination.ESCALATED
        # No ToolCall executed
        assert len(result.tool_calls) == 0
        # strands_decision retained in result
        assert result.strands_decision is not None
        assert result.strands_decision.is_low_confidence

    def test_at_threshold_does_not_escalate(self):
        """confidence == LOW_THRESHOLD (exactly) → no escalation."""
        store, state = _make_store_and_state()
        backend = MockObserveBackend()
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "df -h"}},
        ])

        decider = _FixedDecider("observe", confidence=LOW_CONFIDENCE_THRESHOLD)

        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id=state.instance_id, max_cycles=3, tool_decider=decider,
        )
        result = loop.run(state, max_steps=1)

        # No immediate escalation — tool executes
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].tool_name == "observe"

    def test_escalation_writes_event_to_store(self):
        """Escalation due to low confidence records Escalated in EventStore."""
        store, state = _make_store_and_state()
        backend = MockObserveBackend()
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "df -h"}},
        ])
        decider = _FixedDecider("propose_step", confidence=0.10)

        loop = ReasoningLoop(
            model=model, store=store, backend=backend,
            instance_id=state.instance_id, max_cycles=3, tool_decider=decider,
        )
        loop.run(state)

        events = store.read(state.incident_id)
        event_types = [e.type for e in events]
        assert EventType.Escalated in event_types


# ─────────────────────────────────────────────────────────────────────────────
# 4. Backward compat: RecordedModel/BranchingModel with tool_hint
# ─────────────────────────────────────────────────────────────────────────────

class TestModelToolHintCompat:
    def test_recorded_model_ignores_tool_hint(self):
        """RecordedModel ignores tool_hint and returns recorded response."""
        from src.agent.model_interface import ModelContext
        model = RecordedModel([
            {"tool_name": "escalate", "arguments": {"reason": "test"}},
        ])
        ctx = ModelContext(
            system_prompt="test",
            incident_summary="summary",
            hypotheses_summary="",
            evidence_summaries=[],
            available_tools=["escalate", "observe"],
            budget_remaining={"cycles": 10.0},
            cycle=0,
        )
        resp = model.invoke(ctx, tool_hint="observe")
        # Ignores hint, returns recorded response
        assert resp.tool_call.tool_name == "escalate"

    def test_branching_model_ignores_tool_hint(self):
        """BranchingModel ignores tool_hint and branches by internal criteria."""
        from src.agent.model_interface import BranchingModel, ModelContext
        model = BranchingModel(
            branches={"disk": [{"tool_name": "conclude", "arguments": {}}]},
            default_branch=[{"tool_name": "escalate", "arguments": {}}],
        )
        ctx = ModelContext(
            system_prompt="test",
            incident_summary="disk full",
            hypotheses_summary="",
            evidence_summaries=[],
            available_tools=["escalate", "conclude"],
            budget_remaining={"cycles": 5.0},
            cycle=0,
        )
        resp = model.invoke(ctx, tool_hint="observe")
        # Selects branch based on "disk" in incident_summary
        assert resp.tool_call.tool_name in {"conclude", "escalate"}


# ─────────────────────────────────────────────────────────────────────────────
# 5. Payload Bounded Under Large Context
# ─────────────────────────────────────────────────────────────────────────────

class TestStrandsPayloadBounding:
    def test_strands_decider_payload_bounded_under_large_context(self):
        """
        Verify that when StrandsDeciderClient.select is called with large context:
        (incident_summary 3000 chars, 6 hypotheses, 5 long evidence items)
        actual payload sent over HTTP to /select_tool complies with bounds:
        - incident_summary <= 400 chars, preserving head and tail
        - hypotheses_summary: last 2 hypotheses only, max 350 chars
        - evidence_summaries: last 2 evidence items only, max 250 chars each
        - default timeout = 30.0 seconds
        """
        import json
        from src.agent.tool_decider import StrandsDeciderClient

        decider = StrandsDeciderClient(strands_url="http://fake-strands:8000")
        assert decider._timeout == 30.0

        # 1) Large incident_summary (3000 chars) with designated head and tail
        head = "incident_id: 01ABC\ninstance_id: i-9999\nalarm_name: HighLoad\nphase: investigation\n"
        tail = "\nexecuted_calls: [\"df -h\"]\nfailed_calls: [\"ps aux\"]\nprevious_tool_failures: [\"timeout error\"]"
        padding = "X" * (3000 - len(head) - len(tail))
        huge_incident = head + padding + tail
        assert len(huge_incident) == 3000

        # 2) 6 hypotheses
        raw_hypotheses = [
            {"hypothesis_id": f"H{i}", "statement": f"Hypothesis statement number {i} " + ("details " * 15), "status": "active" if i % 2 == 0 else "refuted"}
            for i in range(1, 7)
        ]
        huge_hypotheses_str = json.dumps(raw_hypotheses, ensure_ascii=False, indent=2)
        assert len(huge_hypotheses_str) > 1000

        # 3) 5 long evidence records (~500 chars each)
        huge_evidence = [
            {"summary": f"Evidence record {i}: " + ("OUTPUT_LINE_" * 35)}
            for i in range(1, 6)
        ]
        assert len(huge_evidence) == 5
        assert all(len(ev["summary"]) > 400 for ev in huge_evidence)

        ctx = ModelContext(
            system_prompt="sys",
            incident_summary=huge_incident,
            hypotheses_summary=huge_hypotheses_str,
            evidence_summaries=huge_evidence,
            available_tools=["observe", "conclude"],
            budget_remaining={"cycles": 5.0},
            cycle=3,
        )

        with patch.object(decider._httpx, "post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.json.return_value = {"tool_name": "observe", "confidence": 0.88, "model_tier": "flash"}
            mock_post.return_value = mock_resp

            decision = decider.select(ctx)
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args[1]
            sent_payload = call_kwargs["json"]
            sent_timeout = call_kwargs["timeout"]

        # Verify decision
        assert decision is not None
        assert decision.tool_name == "observe"
        assert decision.confidence == 0.88
        assert sent_timeout == 30.0

        # 1. Check incident_summary <= 400
        sent_inc = sent_payload["incident_summary"]
        assert len(sent_inc) <= 400
        assert "incident_id: 01ABC" in sent_inc
        assert "previous_tool_failures" in sent_inc
        assert "\n...\n" in sent_inc

        # 2. Check hypotheses_summary: last 2 hypotheses only up to 350 chars
        sent_hyp = sent_payload["hypotheses_summary"]
        assert len(sent_hyp) <= 350
        assert "H5" in sent_hyp
        assert "H6" in sent_hyp
        assert "H1" not in sent_hyp
        assert "H2" not in sent_hyp

        # 3. Check evidence_summaries: last 2 evidence records only up to 250 chars each
        sent_evs = sent_payload["evidence_summaries"]
        assert len(sent_evs) == 2
        for ev_text in sent_evs:
            assert len(ev_text) <= 250
        assert "Evidence record 4" in sent_evs[0]
        assert "Evidence record 5" in sent_evs[1]
        assert "Evidence record 1" not in str(sent_evs)

    def test_strands_decider_payload_bounded_with_list_hypotheses(self):
        """Verify hypotheses_summary truncation when passed as Python list."""
        import json
        from src.agent.tool_decider import StrandsDeciderClient

        decider = StrandsDeciderClient(strands_url="http://fake-strands:8000")

        raw_hypotheses = [
            {"hypothesis_id": f"H{i}", "statement": f"Hypothesis {i} " + ("long details " * 10), "status": "active" if i % 2 == 0 else "refuted"}
            for i in range(1, 7)
        ]

        ctx = ModelContext(
            system_prompt="sys",
            incident_summary="short summary",
            hypotheses_summary=raw_hypotheses,  # as list
            evidence_summaries=[{"summary": "ev1"}],
            available_tools=["observe", "conclude"],
            budget_remaining={"cycles": 5.0},
            cycle=3,
        )

        with patch.object(decider._httpx, "post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.json.return_value = {"tool_name": "observe", "confidence": 0.8}
            mock_post.return_value = mock_resp

            decider.select(ctx)
            sent_payload = mock_post.call_args[1]["json"]

        sent_hyp = sent_payload["hypotheses_summary"]
        assert len(sent_hyp) <= 2
        assert len(json.dumps(sent_hyp)) <= 350
        # Only H5 and H6
        hyp_ids = [h.get("hypothesis_id") for h in sent_hyp]
        assert hyp_ids == ["H5", "H6"]


class TestEmbeddedStrandsDecider:
    """
    Verifies autonomous hybrid routing of EmbeddedStrandsDecider
    designed to run in customer environments without external Strands EC2 server.
    """

    def test_embedded_strands_decider_hybrid_routing_lifecycle(self):
        """
        Verifies hybrid routing lifecycle for EmbeddedStrandsDecider in standalone mode:
        1. At incident start (cycle == 0): selects observe with model_tier='pro' and confidence=0.85.
        2. With new evidence and no active hypotheses: selects update_hypotheses with model_tier='flash'.
        3. With mature hypotheses and evidence: selects propose_step (or conclude) with model_tier='pro'.
        4. Strictly restricts selection to available_tools.
        """
        from src.agent.tool_decider import EmbeddedStrandsDecider

        decider = EmbeddedStrandsDecider()
        assert decider.name == "embedded-strands"

        # 1. Incident start (cycle == 0) without evidence yet
        ctx_start = ModelContext(
            system_prompt="",
            incident_summary="High CPU alarm triggered",
            hypotheses_summary="",
            evidence_summaries=[],
            available_tools=["observe", "update_hypotheses", "propose_step", "conclude"],
            budget_remaining={"cycles": 5},
            cycle=0,
        )
        dec_start = decider.select(ctx_start)
        assert dec_start is not None
        assert dec_start.tool_name == "observe"
        assert dec_start.model_tier == "pro"
        assert dec_start.confidence == 0.85
        assert dec_start.tool_name in ctx_start.available_tools

        # 2. New evidence available without active hypotheses
        ctx_evidence = ModelContext(
            system_prompt="",
            incident_summary="High CPU alarm triggered",
            hypotheses_summary="[]",
            evidence_summaries=[{"evidence_id": "EV1", "summary": "top showed pid 1234 using 98% cpu"}],
            available_tools=["observe", "update_hypotheses", "propose_step", "conclude"],
            budget_remaining={"cycles": 4},
            cycle=1,
        )
        dec_evidence = decider.select(ctx_evidence)
        assert dec_evidence is not None
        assert dec_evidence.tool_name == "update_hypotheses"
        assert dec_evidence.model_tier == "flash"
        assert dec_evidence.confidence == 0.82
        assert dec_evidence.tool_name in ctx_evidence.available_tools

        # 3. Mature hypotheses (active hypothesis present) and evidence available
        ctx_mature = ModelContext(
            system_prompt="",
            incident_summary="High CPU alarm triggered",
            hypotheses_summary='[{"hypothesis_id": "H1", "statement": "pid 1234 runaway", "status": "active"}]',
            evidence_summaries=[{"evidence_id": "EV1", "summary": "top output confirmed"}],
            available_tools=["observe", "update_hypotheses", "propose_step", "conclude"],
            budget_remaining={"cycles": 3},
            cycle=2,
        )
        dec_mature = decider.select(ctx_mature)
        assert dec_mature is not None
        assert dec_mature.tool_name == "propose_step"
        assert dec_mature.model_tier == "pro"
        assert dec_mature.confidence == 0.85
        assert dec_mature.tool_name in ctx_mature.available_tools

        # Sub-case: propose_step not available but conclude is available
        ctx_conclude = ModelContext(
            system_prompt="",
            incident_summary="High CPU alarm triggered",
            hypotheses_summary='[{"hypothesis_id": "H1", "statement": "resolved", "status": "active"}]',
            evidence_summaries=[{"evidence_id": "EV1", "summary": "service healthy"}],
            available_tools=["conclude", "escalate"],
            budget_remaining={"cycles": 2},
            cycle=3,
        )
        dec_conclude = decider.select(ctx_conclude)
        assert dec_conclude is not None
        assert dec_conclude.tool_name == "conclude"
        assert dec_conclude.model_tier == "pro"
        assert dec_conclude.tool_name in ctx_conclude.available_tools

        # 4. Strict restriction to available_tools
        ctx_restricted = ModelContext(
            system_prompt="",
            incident_summary="Restricted tools test",
            hypotheses_summary="",
            evidence_summaries=[],
            available_tools=["query_metrics"],
            budget_remaining={"cycles": 1},
            cycle=0,
        )
        dec_restricted = decider.select(ctx_restricted)
        assert dec_restricted is not None
        assert dec_restricted.tool_name == "query_metrics"
        assert dec_restricted.tool_name in ctx_restricted.available_tools


