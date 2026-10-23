"""
tests/handlers/test_agent_handler.py

Unit tests for handlers/agent.py:
- lease acquisition failure → skipped (409)
- lease acquired → loop runs → termination stored
- ESCALATED → notifier invoked
- RESOLVED → notifier invoked
- lease released even on exception (finally block)
- max_steps calculation from remaining time
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from dataclasses import dataclass, field
from typing import Optional

from src.store.memory import MemoryEventStore
from src.domain.types import (
    IncidentHeader, IncidentOpenedPayload,
    StepRecord, StepKind, DeclaredEffect, EffectCategory,
    StepProposedPayload, PolicyDecisionPayload, PolicyDecisionValue, Tier,
    ApprovalRequestedPayload, ApprovalGrantedPayload, IncidentPhase,
    build_event, EventType, Actor, new_ulid, utc_now,
)
from src.domain.reducer import fold
from src.agent.loop import LoopTermination, LoopResult
from src.store.interface import LeaseToken


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_incident(store, instance_id="i-test"):
    dk = f"alarm::test-alarm::{instance_id}"
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid, instance_id=instance_id, dedupe_key=dk,
        alarm_name="test-alarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
        alert_source="EventBridge", opened_at=utc_now().isoformat(),
    )
    rid, _ = store.create_if_absent(dk, header)
    ev = build_event(
        incident_id=rid, type=EventType.IncidentOpened, actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=instance_id, dedupe_key=dk,
            alarm_name="test-alarm",
            alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
            alert_source="EventBridge",
        ),
    )
    store.append(rid, 0, ev)
    return rid


class _FakeContext:
    def get_remaining_time_in_millis(self): return 900_000


def _fake_loop_result(store, incident_id, termination=LoopTermination.ESCALATED):
    from src.domain.reducer import fold
    state = fold(store.read(incident_id))
    return LoopResult(termination=termination, cycles_completed=1, final_state=state)


# ── tests ─────────────────────────────────────────────────────────────────────

class TestAgentHandler:

    def _run(self, store, incident_id, termination=LoopTermination.ESCALATED, instance_id="i-test"):
        from handlers import agent as mod
        loop_result = _fake_loop_result(store, incident_id, termination)
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "get_model", return_value=MagicMock()), \
             patch.object(mod, "get_decider", return_value=MagicMock()), \
             patch.object(mod, "invoke_async") as mock_inv, \
             patch("handlers.agent.ReasoningLoop") as MockLoop, \
             patch("handlers.agent.ProxyObserveBackend"):
            MockLoop.return_value.run.return_value = loop_result
            resp = mod.handler(
                {"incident_id": incident_id, "instance_id": instance_id},
                context=_FakeContext(),
            )
        return resp, mock_inv

    def test_escalated_triggers_notifier(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        resp, mock_inv = self._run(store, iid, LoopTermination.ESCALATED)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["termination"].upper() == "ESCALATED"
        mock_inv.assert_called_once()

    def test_resolved_triggers_notifier(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        resp, mock_inv = self._run(store, iid, LoopTermination.RESOLVED)
        assert resp["statusCode"] == 200
        mock_inv.assert_called_once()

    def test_missing_incident_id_returns_400(self):
        from handlers import agent as mod
        resp = mod.handler({}, context=_FakeContext())
        assert resp["statusCode"] == 400

    def test_lease_held_skips(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        # Acquire the lease first
        tok = store.acquire_lease(iid, "other-worker", ttl_seconds=900)
        assert tok is not None

        from handlers import agent as mod
        with patch.object(mod, "get_store", return_value=store):
            resp = mod.handler(
                {"incident_id": iid, "instance_id": "i-test"},
                context=_FakeContext(),
            )
        body = json.loads(resp["body"])
        assert body.get("skipped") is True
        assert body.get("reason") == "lease_held"

    def test_lease_released_on_exception(self):
        """
        Proves that try/finally in the handler releases the lease even on exception.
        Steps:
          1. Lease is held exclusively during _run_agent (concurrent worker gets None)
          2. _run_agent raises RuntimeError
          3. finally block releases the lease
          4. Another worker can acquire it afterwards
        """
        store = MemoryEventStore()
        iid = _make_incident(store)
        from handlers import agent as mod

        lease_held_during_run: list = []

        def crashing_run_agent(*args, **kwargs):
            # During execution: another worker cannot acquire the lease
            concurrent_tok = store.acquire_lease(iid, "concurrent-worker", ttl_seconds=60)
            lease_held_during_run.append(concurrent_tok)
            raise RuntimeError("intentional crash")

        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "_run_agent", side_effect=crashing_run_agent), \
             patch("handlers.agent.ProxyObserveBackend"):
            try:
                mod.handler(
                    {"incident_id": iid, "instance_id": "i-test"},
                    context=_FakeContext(),
                )
            except RuntimeError:
                pass

        # Verification 1: Lease was held exclusively during _run_agent
        assert len(lease_held_during_run) == 1, "crashing_run_agent must have been called"
        assert lease_held_during_run[0] is None, \
            "Lease must be held exclusively during _run_agent — concurrent acquire must fail"

        # Verification 2: After exception, finally released the lease
        tok_after = store.acquire_lease(iid, "new-worker", ttl_seconds=60)
        assert tok_after is not None, \
            "Lease must be released by finally block after exception"

    def test_calc_max_steps_from_remaining_time(self):
        from handlers.agent import _calc_max_steps
        # 900s - 30s safety = 870s / 30 = 29 steps
        assert _calc_max_steps(900_000) == 29
        # Time less than safety margin
        assert _calc_max_steps(20_000) == 0
        # Time sufficient for exactly 1 step
        assert _calc_max_steps(60_000) == 1

    def test_proposed_step_t1_invokes_executor(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        sid = new_ulid()
        step = StepRecord(
            step_id=sid, incident_id=iid, kind=StepKind.mutate, target="i-test",
            execution_spec={"command": "systemctl restart nginx"},
            declared_effects=[DeclaredEffect(category=EffectCategory.E1, resource="nginx", description="restart")],
            based_on_hypotheses=[], based_on_evidence=[], preconditions=[], success_criteria=[],
            rollback_plan="", rollback_reason="", idempotent=True, risk_claim="low",
            expires_at="", plan_hash="h1",
        )
        ev1 = build_event(incident_id=iid, type=EventType.StepProposed, actor=Actor.agent, payload=StepProposedPayload(step=step))
        store.append(iid, 1, ev1)
        ev2 = build_event(incident_id=iid, type=EventType.PolicyDecision, actor=Actor.executor, payload=PolicyDecisionPayload(
            step_id=sid, plan_hash="h1", tier=Tier.T1, decision=PolicyDecisionValue.allow,
            reasons=["safe"], rule_ids=["R1"], budget_snapshot={}, gate_version="1.0"
        ))
        store.append(iid, 2, ev2)

        resp, mock_inv = self._run(store, iid, LoopTermination.PROPOSED)
        assert resp["statusCode"] == 200
        mock_inv.assert_called_once()
        target_fn, payload = mock_inv.call_args[0]
        from handlers.shared import EXECUTOR_FN
        assert target_fn == EXECUTOR_FN
        assert payload["incident_id"] == iid
        assert payload["step_id"] == sid

    def test_proposed_step_t2_invokes_notifier_approval_request(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        sid = new_ulid()
        step = StepRecord(
            step_id=sid, incident_id=iid, kind=StepKind.mutate, target="i-test",
            execution_spec={"command": "kill 5939"},
            declared_effects=[DeclaredEffect(category=EffectCategory.E1, resource="5939", description="kill")],
            based_on_hypotheses=[], based_on_evidence=[], preconditions=[], success_criteria=[],
            rollback_plan="", rollback_reason="", idempotent=True, risk_claim="high",
            expires_at="", plan_hash="h2",
        )
        ev1 = build_event(incident_id=iid, type=EventType.StepProposed, actor=Actor.agent, payload=StepProposedPayload(step=step))
        store.append(iid, 1, ev1)
        ev2 = build_event(incident_id=iid, type=EventType.PolicyDecision, actor=Actor.executor, payload=PolicyDecisionPayload(
            step_id=sid, plan_hash="h2", tier=Tier.T2, decision=PolicyDecisionValue.require_approval,
            reasons=["high risk"], rule_ids=["R2"], budget_snapshot={}, gate_version="1.0"
        ))
        store.append(iid, 2, ev2)
        ev3 = build_event(incident_id=iid, type=EventType.ApprovalRequested, actor=Actor.agent, payload=ApprovalRequestedPayload(
            approval_id=new_ulid(), step_id=sid, plan_hash="h2", expires_at=utc_now().isoformat(), notification_ref=None
        ))
        store.append(iid, 3, ev3)

        resp, mock_inv = self._run(store, iid, LoopTermination.PROPOSED)
        assert resp["statusCode"] == 200
        mock_inv.assert_called_once()
        target_fn, payload = mock_inv.call_args[0]
        from handlers.shared import NOTIFIER_FN
        assert target_fn == NOTIFIER_FN
        assert payload["type"] == "approval_request"
        assert payload["incident_id"] == iid
        assert payload["step_id"] == sid
        assert payload["command"] == "kill 5939"

    def test_resume_approval_invokes_executor(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        sid = new_ulid()
        step = StepRecord(
            step_id=sid, incident_id=iid, kind=StepKind.mutate, target="i-test",
            execution_spec={"command": "kill 5939"},
            declared_effects=[], based_on_hypotheses=[], based_on_evidence=[], preconditions=[],
            success_criteria=[], rollback_plan="", rollback_reason="", idempotent=True,
            risk_claim="high", expires_at="", plan_hash="h2",
        )
        ev1 = build_event(incident_id=iid, type=EventType.StepProposed, actor=Actor.agent, payload=StepProposedPayload(step=step))
        store.append(iid, 1, ev1)
        ev2 = build_event(incident_id=iid, type=EventType.ApprovalGranted, actor=Actor.slack_callback, payload=ApprovalGrantedPayload(
            approval_id=new_ulid(), step_id=sid, plan_hash="h2", approver_id="U123",
            issued_at=utc_now().isoformat(), expires_at=utc_now().isoformat(), nonce="n1", auth_tag="at1"
        ))
        store.append(iid, 2, ev2)

        from handlers import agent as mod
        from handlers.shared import EXECUTOR_FN
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv, \
             patch("handlers.agent.ProxyObserveBackend"):
            resp = mod.handler(
                {
                    "incident_id": iid,
                    "instance_id": "i-test",
                    "resume_from_approval": True,
                    "approval_event_id": sid,
                },
                context=_FakeContext(),
            )

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["status"] == "executor_invoked"
        assert body["step_id"] == sid
        mock_inv.assert_called_once()
        target_fn, payload = mock_inv.call_args[0]
        assert target_fn == EXECUTOR_FN
        assert payload["incident_id"] == iid
        assert payload["step_id"] == sid
        assert payload["approval_event_id"] == sid


class TestExecutorFnHandler:

    def test_build_ssm_lab_defaults_to_ssm_lab(self):
        from handlers.executor_fn import _build_ssm_lab
        from src.executor.ssm_lab import SSMLab
        with patch.dict("os.environ", {"USE_DOCKER_LAB": "", "SSM_EXEC_ROLE_ARN": ""}, clear=False):
            lab = _build_ssm_lab("i-test")
            assert isinstance(lab, SSMLab)

    def test_build_ssm_lab_uses_docker_lab_when_flag_set(self):
        from handlers.executor_fn import _build_ssm_lab
        from src.executor.docker_lab import DockerLab
        with patch.dict("os.environ", {"USE_DOCKER_LAB": "1"}, clear=False):
            lab = _build_ssm_lab("i-test")
            assert isinstance(lab, DockerLab)

    def test_executor_fn_notifies_resolution(self):
        from handlers import executor_fn as mod
        from handlers.shared import NOTIFIER_FN
        from src.executor.executor import ExecutorResult, ExecutorTermination

        store = MemoryEventStore()
        iid = _make_incident(store)
        sid = new_ulid()
        step = StepRecord(
            step_id=sid, incident_id=iid, kind=StepKind.mutate, target="i-test",
            execution_spec={"command": "systemctl restart nginx"},
            declared_effects=[], based_on_hypotheses=[], based_on_evidence=[], preconditions=[],
            success_criteria=[], rollback_plan="", rollback_reason="", idempotent=True,
            risk_claim="low", expires_at="", plan_hash="h1",
        )
        ev1 = build_event(incident_id=iid, type=EventType.StepProposed, actor=Actor.agent, payload=StepProposedPayload(step=step))
        store.append(iid, 1, ev1)

        # Write resolution event to store so post_state.phase == resolved
        from src.domain.types import IncidentResolvedPayload
        ev2 = build_event(incident_id=iid, type=EventType.IncidentResolved, actor=Actor.verifier, payload=IncidentResolvedPayload(
            verification_id="v1", summary="resolved"
        ))
        store.append(iid, 2, ev2)

        fake_res = MagicMock()
        fake_res.termination = ExecutorTermination.COMPLETED

        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv, \
             patch.object(mod, "ExecutorLoop") as MockExecutorLoop:
            MockExecutorLoop.return_value.execute_step.return_value = fake_res
            resp = mod.handler({"incident_id": iid, "step_id": sid}, context=None)

        assert resp["statusCode"] == 200
        mock_inv.assert_called_once()
        target_fn, payload = mock_inv.call_args[0]
        assert target_fn == NOTIFIER_FN
        assert payload["type"] == "resolution"
        assert payload["incident_id"] == iid

    def test_executor_fn_notifies_escalation(self):
        from handlers import executor_fn as mod
        from handlers.shared import NOTIFIER_FN
        from src.executor.executor import ExecutorResult, ExecutorTermination

        store = MemoryEventStore()
        iid = _make_incident(store)
        sid = new_ulid()
        step = StepRecord(
            step_id=sid, incident_id=iid, kind=StepKind.mutate, target="i-test",
            execution_spec={"command": "systemctl restart nginx"},
            declared_effects=[], based_on_hypotheses=[], based_on_evidence=[], preconditions=[],
            success_criteria=[], rollback_plan="", rollback_reason="", idempotent=True,
            risk_claim="low", expires_at="", plan_hash="h1",
        )
        ev1 = build_event(incident_id=iid, type=EventType.StepProposed, actor=Actor.agent, payload=StepProposedPayload(step=step))
        store.append(iid, 1, ev1)

        # Write escalated event to store so post_state.phase == escalated
        from src.domain.types import EscalatedPayload
        ev2 = build_event(incident_id=iid, type=EventType.Escalated, actor=Actor.executor, payload=EscalatedPayload(
            reason="executor failure", report_ref=None
        ))
        store.append(iid, 2, ev2)

        fake_res = MagicMock()
        fake_res.termination = ExecutorTermination.ESCALATED

        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv, \
             patch.object(mod, "ExecutorLoop") as MockExecutorLoop:
            MockExecutorLoop.return_value.execute_step.return_value = fake_res
            resp = mod.handler({"incident_id": iid, "step_id": sid}, context=None)

        assert resp["statusCode"] == 200
        mock_inv.assert_called_once()
        target_fn, payload = mock_inv.call_args[0]
        assert target_fn == NOTIFIER_FN
        assert payload["type"] == "escalation"
        assert payload["incident_id"] == iid


class TestResolveSecret:
    """Unit tests for _resolve_secret and get_approval_mac_key in handlers/shared.py."""

    def test_direct_env_var_takes_precedence(self, monkeypatch):
        from handlers.shared import _resolve_secret
        _resolve_secret.cache_clear()
        monkeypatch.setenv("DEEPSEEK_API_KEY", "direct_env_key_123")
        with patch("boto3.client") as mock_boto:
            val = _resolve_secret(
                env_var_name="DEEPSEEK_API_KEY",
                secret_arn_env_var="DEEPSEEK_API_KEY_SECRET_ARN",
                default_secret_id="/incidents/deepseek-api-key",
            )
            assert val == "direct_env_key_123"
            mock_boto.assert_not_called()

    def test_fallback_to_secrets_manager_when_env_absent(self, monkeypatch):
        from handlers.shared import _resolve_secret
        _resolve_secret.cache_clear()
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_API_KEY_SECRET_ARN", raising=False)

        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": "sm_resolved_key_456"}
        with patch("boto3.client", return_value=mock_sm) as mock_boto:
            val = _resolve_secret(
                env_var_name="DEEPSEEK_API_KEY",
                secret_arn_env_var="DEEPSEEK_API_KEY_SECRET_ARN",
                default_secret_id="/incidents/deepseek-api-key",
            )
            assert val == "sm_resolved_key_456"
            mock_boto.assert_called_once()
            mock_sm.get_secret_value.assert_called_once_with(SecretId="/incidents/deepseek-api-key")

    def test_secrets_manager_error_returns_empty_string(self, monkeypatch):
        from handlers.shared import _resolve_secret
        _resolve_secret.cache_clear()
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = Exception("ResourceNotFoundException")
        with patch("boto3.client", return_value=mock_sm):
            val = _resolve_secret(
                env_var_name="DEEPSEEK_API_KEY",
                secret_arn_env_var="DEEPSEEK_API_KEY_SECRET_ARN",
                default_secret_id="/incidents/nonexistent",
            )
            assert val == ""

    def test_resource_not_found_handled_cleanly(self, monkeypatch):
        from handlers.shared import _resolve_secret
        from botocore.exceptions import ClientError
        _resolve_secret.cache_clear()
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Secrets Manager can't find the specified secret."}},
            "GetSecretValue",
        )
        with patch("boto3.client", return_value=mock_sm):
            val = _resolve_secret(
                env_var_name="SLACK_WEBHOOK_URL",
                secret_arn_env_var="SLACK_WEBHOOK_SECRET_ARN",
                default_secret_id="/incidents/slack-webhook-url",
            )
            assert val == ""

    def test_get_approval_mac_key_resolution(self, monkeypatch):
        from handlers.shared import get_approval_mac_key, _resolve_secret
        get_approval_mac_key.cache_clear()
        _resolve_secret.cache_clear()
        hex_key = "b" * 64
        monkeypatch.setenv("APPROVAL_MAC_KEY_HEX", hex_key)
        assert get_approval_mac_key() == bytes.fromhex(hex_key)


