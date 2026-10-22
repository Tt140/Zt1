"""
tests/unit/test_model_router.py

Dynamic Model Routing tests:
1. flash tier -> flash model invoked
2. pro tier  -> pro model invoked
3. NullToolDecider (decision=None) -> flash (FALLBACK)
4. Low confidence in loop -> escalation (no routing to pro)
5. Recorded model_tier = actually invoked model
6. Unknown tier -> fallback to flash (no raise)
7. ReasoningLoop with ModelRouter: simple state -> flash,
   complex state (decision.model_tier='pro') -> pro

All existing RecordedModel tests unaffected (backward compat).
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, call
from dataclasses import dataclass
from typing import Optional

from src.agent.model_router import ModelRouter
from src.agent.model_interface import (
    ModelInterface, ModelContext, ModelResponse, ToolCall,
)
from src.agent.tool_decider import (
    ToolDecision, NullToolDecider, FALLBACK_MODEL_TIER, DEFAULT_MODEL_TIER,
)
from src.agent.loop import ReasoningLoop, LoopTermination, _invoke_model


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_response(tool_name="observe", reasoning="test") -> ModelResponse:
    return ModelResponse(
        tool_call=ToolCall(tool_name=tool_name, arguments={}, reasoning=reasoning)
    )


def _make_ctx() -> ModelContext:
    return ModelContext(
        system_prompt="test",
        incident_summary="disk usage high on i-0abc",
        hypotheses_summary="disk full",
        evidence_summaries=[],
        available_tools=["observe", "escalate"],
        budget_remaining={"cycles": 5, "commands": 10},
        cycle=0,
    )


class TrackingModel(ModelInterface):
    """Simple model tracking how many times it was invoked."""
    def __init__(self, name: str, response_tool="observe"):
        self._name = name
        self._response_tool = response_tool
        self.invoke_count = 0
        self.last_tool_hint: Optional[str] = None

    def invoke(self, ctx: ModelContext, tool_hint=None) -> ModelResponse:
        self.invoke_count += 1
        self.last_tool_hint = tool_hint
        return _make_response(self._response_tool)

    @property
    def name(self) -> str:
        return self._name


# ── ToolDecision.model_tier tests ─────────────────────────────────────────────

class TestToolDecisionModelTier:

    def test_default_tier_is_flash(self):
        d = ToolDecision(tool_name="observe", confidence=0.9)
        assert d.model_tier == "flash"

    def test_explicit_pro_tier(self):
        d = ToolDecision(tool_name="observe", confidence=0.9, model_tier="pro")
        assert d.model_tier == "pro"

    def test_explicit_flash_tier(self):
        d = ToolDecision(tool_name="observe", confidence=0.9, model_tier="flash")
        assert d.model_tier == "flash"

    def test_unknown_tier_falls_back_to_flash(self):
        """Unknown tier -> normalized to flash (no raise)."""
        d = ToolDecision(tool_name="observe", confidence=0.9, model_tier="ultra")
        assert d.model_tier == FALLBACK_MODEL_TIER

    def test_tier_does_not_affect_tool_enforcement(self):
        """model_tier does not alter chosen tool name."""
        d = ToolDecision(tool_name="propose_step", confidence=0.9, model_tier="pro")
        assert d.tool_name == "propose_step"


# ── ModelRouter routing tests ─────────────────────────────────────────────────

class TestModelRouterRouting:

    def setup_method(self):
        self.flash = TrackingModel("flash-model", response_tool="observe")
        self.pro   = TrackingModel("pro-model",   response_tool="update_hypotheses")
        self.router = ModelRouter(flash_model=self.flash, pro_model=self.pro)

    def test_flash_tier_calls_flash_model(self):
        ctx = _make_ctx()
        self.router.invoke(ctx, tool_hint="observe", model_tier="flash")

        assert self.flash.invoke_count == 1
        assert self.pro.invoke_count   == 0
        assert self.router.last_tier_used == "flash"

    def test_pro_tier_calls_pro_model(self):
        ctx = _make_ctx()
        self.router.invoke(ctx, tool_hint="observe", model_tier="pro")

        assert self.pro.invoke_count   == 1
        assert self.flash.invoke_count == 0
        assert self.router.last_tier_used == "pro"

    def test_none_tier_defaults_to_flash(self):
        ctx = _make_ctx()
        self.router.invoke(ctx, tool_hint="observe", model_tier=None)

        assert self.flash.invoke_count == 1
        assert self.pro.invoke_count   == 0

    def test_unknown_tier_defaults_to_flash(self):
        ctx = _make_ctx()
        self.router.invoke(ctx, tool_hint="observe", model_tier="unknown-tier")

        assert self.flash.invoke_count == 1
        assert self.pro.invoke_count   == 0

    def test_last_tier_used_tracks_actual_model(self):
        """last_tier_used tracks the model that was actually invoked."""
        ctx = _make_ctx()
        self.router.invoke(ctx, model_tier="pro")
        assert self.router.last_tier_used == "pro"
        self.router.invoke(ctx, model_tier="flash")
        assert self.router.last_tier_used == "flash"

    def test_tool_hint_passed_to_chosen_model(self):
        ctx = _make_ctx()
        self.router.invoke(ctx, tool_hint="query_logs", model_tier="pro")
        assert self.pro.last_tool_hint == "query_logs"

    def test_router_name_includes_both_models(self):
        assert "flash-model" in self.router.name
        assert "pro-model"   in self.router.name

    def test_flash_and_pro_properties(self):
        assert self.router.flash_model is self.flash
        assert self.router.pro_model   is self.pro


# ── _invoke_model helper tests ────────────────────────────────────────────────

class TestInvokeModelHelper:

    def test_plain_model_ignores_model_tier(self):
        """Standard ModelInterface invoked without model_tier kwarg."""
        plain = TrackingModel("plain")
        ctx   = _make_ctx()
        _invoke_model(plain, ctx, tool_hint="observe", model_tier="pro")
        assert plain.invoke_count == 1

    def test_router_receives_model_tier(self):
        flash  = TrackingModel("flash")
        pro    = TrackingModel("pro")
        router = ModelRouter(flash_model=flash, pro_model=pro)
        ctx    = _make_ctx()
        _invoke_model(router, ctx, tool_hint="observe", model_tier="pro")
        assert pro.invoke_count   == 1
        assert flash.invoke_count == 0


# ── ReasoningLoop integration tests ───────────────────────────────────────────

class TestReasoningLoopModelRouting:
    """
    Demonstrates that:
    1. Strands decision with model_tier="flash" -> flash model invoked
    2. Strands decision with model_tier="pro"   -> pro model invoked
    3. Recorded choice (last_tier_used) = model actually invoked
    4. model_tier does not affect Policy Gate or binding tool decision
    """

    def _make_loop(self, flash, pro, decider):
        from src.store.memory import MemoryEventStore
        from src.agent.mock_backend import MockObserveBackend
        store   = MemoryEventStore()
        backend = MockObserveBackend()
        router  = ModelRouter(flash_model=flash, pro_model=pro)
        return ReasoningLoop(
            model=router,
            store=store,
            backend=backend,
            instance_id="i-test",
            max_cycles=5,
            tool_decider=decider,
        ), store, router

    def _make_incident_state(self, store):
        from src.domain.types import (
            IncidentHeader, IncidentOpenedPayload,
            build_event, EventType, Actor, new_ulid, utc_now,
        )
        from src.domain.reducer import fold
        dk  = f"alarm::test::{new_ulid()}"
        iid = new_ulid()
        header = IncidentHeader(
            incident_id=iid, instance_id="i-test", dedupe_key=dk,
            alarm_name="DiskHigh", alarm_arn="arn:test", alert_source="eb",
            opened_at=utc_now().isoformat(),
        )
        rid, _ = store.create_if_absent(dk, header)
        ev = build_event(
            incident_id=rid, type=EventType.IncidentOpened, actor=Actor.ingest,
            payload=IncidentOpenedPayload(
                instance_id="i-test", dedupe_key=dk, alarm_name="DiskHigh",
                alarm_arn="arn:test", alert_source="eb",
            ),
        )
        store.append(rid, 0, ev)
        return fold(store.read(rid))

    def test_flash_decision_calls_flash_model(self):
        """Strands decision with model_tier='flash' -> flash model only."""
        flash = TrackingModel("flash", response_tool="escalate")
        pro   = TrackingModel("pro",   response_tool="escalate")

        # Decider returns flash tier
        decider = MagicMock()
        decider.select.return_value = ToolDecision(
            tool_name="observe", confidence=0.85, model_tier="flash"
        )
        decider.name = "mock-decider"

        loop, store, router = self._make_loop(flash, pro, decider)
        state = self._make_incident_state(store)
        loop.run(state, max_steps=1)

        assert flash.invoke_count >= 1, "flash model must be called"
        assert pro.invoke_count   == 0, "pro model must NOT be called"
        assert router.last_tier_used == "flash"

    def test_pro_decision_calls_pro_model(self):
        """Strands decision with model_tier='pro' -> pro model only."""
        flash = TrackingModel("flash", response_tool="escalate")
        pro   = TrackingModel("pro",   response_tool="escalate")

        decider = MagicMock()
        decider.select.return_value = ToolDecision(
            tool_name="update_hypotheses", confidence=0.80, model_tier="pro"
        )
        decider.name = "mock-decider"

        loop, store, router = self._make_loop(flash, pro, decider)
        state = self._make_incident_state(store)
        loop.run(state, max_steps=1)

        assert pro.invoke_count   >= 1, "pro model must be called"
        assert flash.invoke_count == 0, "flash model must NOT be called"
        assert router.last_tier_used == "pro"

    def test_null_decider_uses_flash(self):
        """NullToolDecider (decision=None) -> always flash."""
        flash = TrackingModel("flash", response_tool="escalate")
        pro   = TrackingModel("pro",   response_tool="escalate")

        loop, store, router = self._make_loop(flash, pro, NullToolDecider())
        state = self._make_incident_state(store)
        loop.run(state, max_steps=1)

        assert flash.invoke_count >= 1
        assert pro.invoke_count   == 0
        assert router.last_tier_used == "flash"

    def test_low_confidence_escalates_no_pro_call(self):
        """
        confidence < LOW_THRESHOLD -> immediate escalation.
        Neither flash nor pro model is invoked after a low-confidence decision.
        """
        flash = TrackingModel("flash", response_tool="escalate")
        pro   = TrackingModel("pro",   response_tool="escalate")

        decider = MagicMock()
        decider.select.return_value = ToolDecision(
            tool_name="observe", confidence=0.10, model_tier="pro"
        )
        decider.name = "mock-decider"

        loop, store, router = self._make_loop(flash, pro, decider)
        state = self._make_incident_state(store)
        result = loop.run(state, max_steps=3)

        assert result.termination == LoopTermination.ESCALATED
        # No model invoked on low confidence (escalation before invoke)
        assert flash.invoke_count == 0
        assert pro.invoke_count   == 0

    def test_model_tier_does_not_bypass_policy_gate(self):
        """
        model_tier='pro' does not bypass the safety path.
        Proves: pro model is invoked, but the outcome is governed by the tool, not the tier.
        The 'escalate' tool leads to phase=escalated in the final state.
        """
        pro   = TrackingModel("pro",   response_tool="escalate")
        flash = TrackingModel("flash", response_tool="escalate")

        decider = MagicMock()
        decider.select.return_value = ToolDecision(
            tool_name="escalate", confidence=0.85, model_tier="pro"
        )
        decider.name = "mock-decider"

        loop, store, router = self._make_loop(flash, pro, decider)
        state = self._make_incident_state(store)
        # max_steps=3 is sufficient to reach ESCALATED after executing escalate
        result = loop.run(state, max_steps=3)

        # pro model was invoked because tier='pro'
        assert pro.invoke_count >= 1, "pro model must be invoked for pro tier"
        assert flash.invoke_count == 0, "flash model must NOT be invoked"
        assert router.last_tier_used == "pro"

        # Result is governed by tool execution (escalate) — not by the tier
        from src.domain.types import IncidentPhase
        assert result.final_state.phase == IncidentPhase.escalated, \
            "phase must reflect tool execution (escalate), not model_tier"


# ── DeepSeekModel Bedrock Mantle routing & fallback tests ─────────────────────

class TestDeepSeekBedrockMantle:
    """
    Verifies routing DeepSeekModel to custom api_base (Bedrock Mantle Endpoint)
    and using deepseek.v3.1 as fallback_model on deepseek.v3.2 Timeout.
    """

    def test_deepseek_model_bedrock_mantle_custom_endpoint_and_fallback(self):
        from unittest.mock import MagicMock, patch
        import httpx
        from src.agent.deepseek_model import DeepSeekModel

        ctx = _make_ctx()
        bedrock_base = "https://bedrock-mantle.us-east-1.api.aws/v1"

        model = DeepSeekModel(
            api_key="test-key-probe",
            model="deepseek.v3.2",
            api_base=bedrock_base,
        )

        assert model._fallback_model == "deepseek.v3.2"
        assert model.name == "bedrock:deepseek.v3.2"
        assert model.model_id == "deepseek.v3.2"

        call_records = []

        def mock_post(url, json=None, headers=None, timeout=None):
            call_records.append({
                "url": url,
                "payload": dict(json or {}),
                "headers": headers,
                "timeout": timeout,
            })
            if len(call_records) == 1:
                # Simulate ReadTimeout when calling deepseek.v3.2
                raise httpx.ReadTimeout("Bedrock Mantle deepseek.v3.2 timeout")

            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.json.return_value = {
                "choices": [{
                    "message": {
                        "content": '{"tool_name": "observe", "arguments": {"command": "top -b -n 1"}, "reasoning": "checking cpu"}'
                    }
                }]
            }
            return mock_resp

        fallback_model = DeepSeekModel(
            api_key="test-key-probe",
            model="deepseek.v3.2",
            fallback_model="deepseek.v3.1",
            api_base=bedrock_base,
        )
        with patch("httpx.post", side_effect=mock_post):
            res = fallback_model.invoke(ctx, tool_hint="observe")

        assert len(call_records) == 2
        # Verify requests are routed to Bedrock Mantle chat completions
        assert call_records[0]["url"] == f"{bedrock_base}/chat/completions"
        assert call_records[1]["url"] == f"{bedrock_base}/chat/completions"
        # Verify the first call was for deepseek.v3.2
        assert call_records[0]["payload"]["model"] == "deepseek.v3.2"
        # Verify fallback to deepseek.v3.1 on timeout
        assert call_records[1]["payload"]["model"] == "deepseek.v3.1"
        assert res.tool_call.tool_name == "observe"

    def test_dynamic_token_and_timeout_scaling_by_context_size(self):
        """
        Verifies that _compute_dynamic_limits mathematically differentiates deepseek.v3.1 (flash) and deepseek.v3.2 (pro):
        - In short context: flash starts at 2048 tokens while pro starts at 4096 tokens and timeout >= 45.0s.
        - In long context (9,000 chars of evidence): flash expands to 4096 tokens and 45.0s, while pro expands to 8192 tokens and 90.0s.
        """
        from src.agent.deepseek_model import DeepSeekModel

        flash_model = DeepSeekModel(
            api_key="test-key-flash",
            model="deepseek.v3.1",
            timeout_seconds=30.0,
        )
        pro_model = DeepSeekModel(
            api_key="test-key-pro",
            model="deepseek.v3.2",
            timeout_seconds=30.0,
        )

        short_msgs = [{"role": "user", "content": "alarm on CPU instance i-12345"}]
        long_msgs = [{"role": "user", "content": "EVIDENCE DATA: " + ("x" * 9000)}]

        # 1. Short context
        flash_tokens_short, flash_to_short = flash_model._compute_dynamic_limits(short_msgs)
        pro_tokens_short, pro_to_short = pro_model._compute_dynamic_limits(short_msgs)

        assert flash_tokens_short == 2048
        assert flash_to_short == 30.0
        assert pro_tokens_short == 4096
        assert pro_to_short >= 45.0

        # 2. Long context
        flash_tokens_long, flash_to_long = flash_model._compute_dynamic_limits(long_msgs)
        pro_tokens_long, pro_to_long = pro_model._compute_dynamic_limits(long_msgs)

        assert flash_tokens_long == 4096
        assert flash_to_long == 45.0
        assert pro_tokens_long == 8192
        assert pro_to_long == 90.0

    def test_auto_expansion_retry_on_finish_reason_length(self):
        """
        Simulates initial response from httpx.post returning finish_reason='length' (truncated JSON),
        followed by a second successful response finish_reason='stop' with complete JSON.
        Verifies doubling max_tokens, increasing timeout, and successfully returning completed JSON.
        """
        from unittest.mock import MagicMock, patch
        from src.agent.deepseek_model import DeepSeekModel

        ctx = _make_ctx()
        bedrock_base = "https://bedrock-mantle.us-east-1.api.aws/v1"

        model = DeepSeekModel(
            api_key="test-key-expansion",
            model="deepseek.v3.2",
            api_base=bedrock_base,
        )

        call_records = []

        def mock_post(url, json=None, headers=None, timeout=None):
            call_records.append({
                "url": url,
                "payload": dict(json or {}),
                "timeout": timeout,
            })
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None

            if len(call_records) == 1:
                # First response truncated due to reaching token limit
                mock_resp.json.return_value = {
                    "choices": [{
                        "finish_reason": "length",
                        "message": {
                            "content": '{"tool_name": "observe", "arguments": {"command": "journalctl'
                        }
                    }]
                }
            else:
                # Second response complete after doubling token limit
                mock_resp.json.return_value = {
                    "choices": [{
                        "finish_reason": "stop",
                        "message": {
                            "content": '{"tool_name": "observe", "arguments": {"command": "journalctl -u nginx -n 50"}, "reasoning": "analyzing complete nginx logs after auto expansion"}'
                        }
                    }]
                }
            return mock_resp

        with patch("httpx.post", side_effect=mock_post):
            res = model.invoke(ctx, tool_hint="observe")

        assert len(call_records) == 2, "Expected exactly 1 retry due to auto-expansion"
        initial_tokens = call_records[0]["payload"]["max_tokens"]
        retry_tokens = call_records[1]["payload"]["max_tokens"]
        assert retry_tokens == min(initial_tokens * 2, 16384)
        assert call_records[1]["timeout"] >= call_records[0]["timeout"]
        assert res.tool_call.tool_name == "observe"
        assert res.tool_call.arguments["command"] == "journalctl -u nginx -n 50"
        assert "complete nginx logs" in res.tool_call.reasoning


# ── Default model constants and env override tests ───────────────────────────

class TestDefaultModelConstants:
    """Verifies default model values and env var support."""

    def test_default_flash_model_is_deepseek_v3_2(self):
        from src.agent.model_router import DEFAULT_FLASH_MODEL
        assert DEFAULT_FLASH_MODEL == "bedrock:deepseek.v3.2"

    def test_default_pro_model_is_deepseek_v3_2(self):
        from src.agent.model_router import DEFAULT_PRO_MODEL
        assert DEFAULT_PRO_MODEL == "bedrock:deepseek.v3.2"

    def test_incidents_flash_model_env_override(self, monkeypatch):
        import importlib
        import src.agent.model_router as mr
        monkeypatch.setenv("INCIDENTS_FLASH_MODEL", "custom:flash-model")
        importlib.reload(mr)
        assert mr.DEFAULT_FLASH_MODEL == "custom:flash-model"
        monkeypatch.delenv("INCIDENTS_FLASH_MODEL", raising=False)
        importlib.reload(mr)
        assert mr.DEFAULT_FLASH_MODEL == "bedrock:deepseek.v3.2"


