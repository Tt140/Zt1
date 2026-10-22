"""
tests/agent/test_anti_hesitation_and_socket_mode.py

Verifies:
1. Anti-Hesitation in ReasoningLoop: breaking analysis paralysis and advancing to propose_step
   when evidence is solid and decider confidence is high.
2. Slack Socket Mode Approval Listener: verifying fail-closed Slack RBAC, HMAC generation,
   and approval state transition.
"""
import json
import unittest
from unittest.mock import MagicMock, patch

from src.agent.loop import ReasoningLoop
from src.agent.model_interface import ToolCall, ModelResponse
from src.domain.types import (
    IncidentState,
    IncidentPhase,
    HypothesisRecord,
    HypothesisStatus,
    BudgetState,
    EvidenceRef,
    TrustLevel,
)
from src.agent.tool_decider import ToolDecision
from demos._harness import wait_for_slack_approval


class TestAntiHesitation(unittest.TestCase):
    def test_anti_hesitation_triggers_propose_step_when_model_repeats_update_hypotheses(self):
        """When the generative model hesitates on update_hypotheses repeatedly, but Strands
        Decider firmly recommends propose_step (conf >= 0.70), Anti-Hesitation must override
        and steer the agent to propose_step."""
        mock_model = MagicMock()
        mock_store = MagicMock()
        mock_backend = MagicMock()
        mock_decider = MagicMock()

        # Decider recommends propose_step with high confidence
        mock_decider.select.return_value = ToolDecision(
            tool_name="propose_step",
            confidence=0.88,
        )

        # Generative model initially returns update_hypotheses (hesitation)
        def model_invoke(ctx, **kwargs):
            if kwargs.get("tool_hint") == "propose_step":
                return ModelResponse(
                    tool_call=ToolCall(
                        tool_name="propose_step",
                        arguments={
                            "action": "restart_service",
                            "command": "systemctl restart my-service",
                            "target": "my-service",
                            "tier": "T1",
                            "risk_claim": "low risk restart",
                        },
                        reasoning="Remediating by restarting service",
                    ),
                )
            return ModelResponse(
                tool_call=ToolCall(
                    tool_name="update_hypotheses",
                    arguments={
                        "hypotheses": [
                            {
                                "hypothesis_id": "H1",
                                "statement": "Service crashed due to bad state",
                                "confidence": 0.85,
                                "supporting_evidence_ids": ["E1"],
                            }
                        ]
                    },
                    reasoning="Updating hypotheses again",
                ),
            )

        mock_model.invoke.side_effect = model_invoke

        from src.domain.reducer import fold
        from src.domain.types import IncidentOpenedPayload, EventType, Actor, build_event, utc_now

        open_ev = build_event(
            incident_id="inc-test-anti-hesitation",
            type=EventType.IncidentOpened,
            actor=Actor.ingest,
            payload=IncidentOpenedPayload(
                instance_id="i-test-anti-hesitation",
                dedupe_key="dedup-anti-hesitation",
                alarm_name="test-alarm",
                alarm_arn="arn:aws:cloudwatch:us-east-1:123456789012:alarm:test-alarm",
                alert_source="arn:aws:events:us-east-1:123456789012:rule/test-rule",
            ),
        )
        state = fold([open_ev])
        state.hypotheses = {
            "H1": HypothesisRecord(
                hypothesis_id="H1",
                statement="Service crashed due to bad state",
                confidence=0.85,
                supporting=["E1"],
                contradicting=[],
                status=HypothesisStatus.active,
                next_check=None,
                trigger_evidence_id="E1",
            )
        }
        state.evidence = {
            "E1": EvidenceRef(
                evidence_id="E1",
                source="observe:ps aux",
                trust=TrustLevel.host_reported,
                collected_at="2026-10-20T00:00:00Z",
                raw_ref="blob:1",
                integrity_hash="h1",
                summary="service is down",
                redaction_report={},
            ),
            "E2": EvidenceRef(
                evidence_id="E2",
                source="observe:systemctl status my-service",
                trust=TrustLevel.host_reported,
                collected_at="2026-10-20T00:01:00Z",
                raw_ref="blob:2",
                integrity_hash="h2",
                summary="failed with exit code 1",
                redaction_report={},
            ),
        }

        mock_store.read.return_value = [open_ev]

        loop = ReasoningLoop(
            model=mock_model,
            store=mock_store,
            backend=mock_backend,
            instance_id="i-test-anti-hesitation",
            max_cycles=10,
            tool_decider=mock_decider,
        )

        # Run 1 cycle with max_steps=1
        res = loop.run(state, max_steps=1)

        # Verify that the executed tool was propose_step, not update_hypotheses
        self.assertEqual(len(res.tool_calls), 1)
        self.assertEqual(res.tool_calls[0].tool_name, "propose_step")
        self.assertIn("systemctl restart my-service", res.tool_calls[0].arguments.get("command", ""))


class TestSlackSocketModeApproval(unittest.TestCase):
    @patch("slack_sdk.web.WebClient")
    @patch("slack_sdk.socket_mode.SocketModeClient")
    @patch("handlers.shared.get_authorized_approvers")
    @patch("handlers.slack_callback._write_approval_event")
    def test_authorized_user_approval_granted(
        self, mock_write_approval, mock_get_approvers, mock_sm_client_cls, mock_web_client_cls
    ):
        """When an authorized Slack user clicks 'Approve & Execute', Socket Mode listener
        acknowledges request, checks RBAC, and writes ApprovalGranted event."""
        mock_get_approvers.return_value = frozenset(["U_SECOPS_LEAD"])

        sm_instance = MagicMock()
        mock_sm_client_cls.return_value = sm_instance

        # Capture the listener callback
        listeners = []
        sm_instance.socket_mode_request_listeners = listeners

        def simulate_connect():
            # Trigger interactive approval click from authorized user
            req = MagicMock()
            req.envelope_id = "env-12345"
            req.type = "interactive"
            req.payload = {
                "type": "block_actions",
                "user": {"id": "U_SECOPS_LEAD"},
                "actions": [
                    {
                        "action_id": "approve",
                        "value": json.dumps({"incident_id": "inc-001", "step_id": "step-001", "plan_hash": "hash-abc"}),
                    }
                ],
                "response_url": "https://hooks.slack.com/actions/test",
            }
            # Invoke the registered listener callback
            for listener in listeners:
                listener(sm_instance, req)

        sm_instance.connect.side_effect = simulate_connect

        with patch.dict("os.environ", {"SLACK_APP_TOKEN": "xapp-test-token", "SLACK_BOT_TOKEN": "xoxb-test-token"}):
            approved, approver_id = wait_for_slack_approval(
                incident_id="inc-001",
                step_id="step-001",
                expected_plan_hash="hash-abc",
                timeout_seconds=5,
            )

        self.assertTrue(approved)
        self.assertEqual(approver_id, "U_SECOPS_LEAD")
        mock_write_approval.assert_called_once_with(
            incident_id="inc-001",
            step_id="step-001",
            approver="U_SECOPS_LEAD",
            approved=True,
            expected_plan_hash="hash-abc",
        )
        sm_instance.close.assert_called_once()

    @patch("slack_sdk.web.WebClient")
    @patch("slack_sdk.socket_mode.SocketModeClient")
    @patch("handlers.shared.get_authorized_approvers")
    @patch("handlers.slack_callback._write_approval_event")
    def test_unauthorized_user_approval_rejected_fail_closed(
        self, mock_write_approval, mock_get_approvers, mock_sm_client_cls, mock_web_client_cls
    ):
        """When an unauthorized Slack user clicks 'Approve', Slack RBAC rejects it (fail-closed)
        and no approval event is recorded."""
        mock_get_approvers.return_value = frozenset(["U_SECOPS_LEAD"])

        sm_instance = MagicMock()
        mock_sm_client_cls.return_value = sm_instance

        listeners = []
        sm_instance.socket_mode_request_listeners = listeners

        def simulate_connect():
            # Trigger interactive approval click from unauthorized rogue user
            req = MagicMock()
            req.envelope_id = "env-67890"
            req.type = "interactive"
            req.payload = {
                "type": "block_actions",
                "user": {"id": "U_UNAUTHORIZED_USER"},
                "actions": [
                    {
                        "action_id": "approve",
                        "value": json.dumps({"incident_id": "inc-001", "step_id": "step-001"}),
                    }
                ],
                "response_url": "https://hooks.slack.com/actions/test",
            }
            for listener in listeners:
                listener(sm_instance, req)

        sm_instance.connect.side_effect = simulate_connect

        with patch.dict("os.environ", {"SLACK_APP_TOKEN": "xapp-test-token", "SLACK_BOT_TOKEN": "xoxb-test-token"}):
            approved, approver_id = wait_for_slack_approval(
                incident_id="inc-001",
                step_id="step-001",
                expected_plan_hash="hash-abc",
                timeout_seconds=1,
            )

        self.assertFalse(approved)
        self.assertIsNone(approver_id)
        mock_write_approval.assert_not_called()
        sm_instance.close.assert_called_once()


class TestLineLevelIsolationAndEpistemicResolution(unittest.TestCase):
    def test_line_level_isolation_surgical_kill(self):
        """Verifies that line-level target isolation permits kill of rogue processes in T1
        even if sensitive processes like sshd are listed on other lines in the same evidence."""
        import dataclasses
        from src.policy.gate import PolicyGate, GateContext
        from src.domain.types import EffectCategory, DeclaredEffect, Tier, PolicyDecisionValue, EvidenceRecord, StepKind
        from tests.policy.conftest import make_state, make_step

        state = make_state()
        summary = (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            "tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1024,fd=3))\n"
            "tcp   LISTEN 0 5   0.0.0.0:8088 0.0.0.0:* users:((\"python3\",pid=70584,fd=3))"
        )
        state.evidence["e1"] = EvidenceRecord(
            evidence_id="e1",
            source="observe:ss -tulpn",
            trust="host_reported",
            collected_at="now",
            raw_ref="blob:123",
            integrity_hash="123",
            summary=summary,
            redaction_report={},
        )

        gate = PolicyGate()
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id=state.instance_id,
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
        )

        # Rogue process -> Tier.T1 (allow)
        raw_step1 = make_step(
            kind=StepKind.mutate,
            target=state.instance_id,
            execution_spec={"command": "kill 70584"},
            effects=[DeclaredEffect(resource=state.instance_id, category=EffectCategory.E1, description="kill rogue process")],
        )
        step1 = dataclasses.replace(raw_step1, based_on_evidence=["e1"], risk_claim="low")
        res1 = gate.evaluate(step1, state, ctx)
        self.assertEqual(res1.decision, PolicyDecisionValue.allow)
        self.assertEqual(res1.tier, Tier.T1)

        # Protected process (sshd) -> Tier.T2 (require_approval)
        raw_step2 = make_step(
            kind=StepKind.mutate,
            target=state.instance_id,
            execution_spec={"command": "kill 1024"},
            effects=[DeclaredEffect(resource=state.instance_id, category=EffectCategory.E1, description="kill sshd")],
        )
        step2 = dataclasses.replace(raw_step2, based_on_evidence=["e1"], risk_claim="low")
        res2 = gate.evaluate(step2, state, ctx)
        self.assertEqual(res2.decision, PolicyDecisionValue.require_approval)
        self.assertEqual(res2.tier, Tier.T2)

    def test_conclude_emits_incident_resolved_when_remediation_succeeded(self):
        """Verifies that when remediation succeeded, concluding the incident emits
        IncidentResolved with Actor.agent, transitioning state.phase to resolved."""
        from src.agent.tool_executor import ToolExecutor
        from tests.policy.conftest import make_state, make_step
        from src.domain.types import (
            StepKind, IncidentPhase, Actor, EventType, EvidenceRecord,
            HypothesisRecord, HypothesisStatus, build_event, IncidentOpenedPayload
        )
        import dataclasses
        from src.agent.model_interface import ToolCall

        state = make_state()
        open_ev = build_event(
            incident_id=state.incident_id,
            type=EventType.IncidentOpened,
            actor=Actor.ingest,
            payload=IncidentOpenedPayload(
                instance_id=state.instance_id,
                dedupe_key="test-dedup",
                alarm_name="test-alarm",
                alarm_arn="arn:aws:cloudwatch:us-east-1:123456789012:alarm:test",
                alert_source="arn:aws:events:us-east-1:123456789012:rule/test",
            ),
        )

        written_events = [open_ev]
        mock_store = MagicMock()
        mock_store.append.side_effect = lambda iid, seq, ev: written_events.append(ev)
        mock_store.last_seq.return_value = 1
        mock_store.read.side_effect = lambda iid: list(written_events)

        state.evidence["e1"] = EvidenceRecord(
            evidence_id="e1",
            source="observe:ps aux",
            trust="host_reported",
            collected_at="now",
            raw_ref="blob:1",
            integrity_hash="h1",
            summary="rogue process pid 70584",
            redaction_report={},
        )
        state.hypotheses["h1"] = HypothesisRecord(
            hypothesis_id="h1",
            statement="Rogue process consuming port 8088",
            confidence=0.9,
            status=HypothesisStatus.active,
            supporting=["e1"],
            contradicting=[],
            next_check=None,
            trigger_evidence_id="e1",
        )
        step = make_step(kind=StepKind.mutate, target=state.instance_id, execution_spec={"command": "kill 70584"})
        step = dataclasses.replace(step, status="succeeded")
        state.steps[step.step_id] = step

        mock_backend = MagicMock()
        executor = ToolExecutor(store=mock_store, backend=mock_backend, instance_id=state.instance_id)
        tool_call = ToolCall(tool_name="conclude", arguments={"root_cause": "Rogue process killed and verified", "confidence": 0.95})
        res, new_state = executor.execute(tool_call, state)

        self.assertTrue(res.success)
        self.assertIn("IncidentResolved", res.events_written)
        resolved_events = [e for e in written_events if e.type == EventType.IncidentResolved]
        self.assertEqual(len(resolved_events), 1)
        self.assertEqual(resolved_events[0].actor, Actor.agent)
        self.assertEqual(new_state.phase, IncidentPhase.resolved)


class TestSlackApprovalFailClosedHalt(unittest.TestCase):
    @patch("demos._harness._notify_slack_safe")
    def test_timeout_records_escalation_and_halts_safely(self, mock_notify):
        from demos._harness import _handle_unapproved_t2_halt
        from src.domain.types import EventType, Actor, IncidentPhase, IncidentOpenedPayload, build_event
        from tests.policy.conftest import make_state

        state = make_state()
        state.phase = IncidentPhase.awaiting_approval
        open_payload = IncidentOpenedPayload(
            instance_id=state.instance_id,
            dedupe_key="dedupe-test",
            alarm_name="test-alarm",
            alarm_arn="arn:aws:cloudwatch:us-east-1:123456789012:alarm:test",
            alert_source="arn:aws:events:us-east-1:123456789012:rule/test",
        )
        open_ev = build_event(
            incident_id="inc-test-timeout",
            type=EventType.IncidentOpened,
            actor=Actor.system,
            payload=open_payload,
        )
        written_events = [open_ev]
        mock_store = MagicMock()
        mock_store.read.side_effect = lambda iid: list(written_events)
        mock_store.append.side_effect = lambda iid, seq, ev: written_events.append(ev)

        updated_state = _handle_unapproved_t2_halt(
            iid="inc-test-timeout",
            instance_id="i-test-inst",
            step_id="step-t2",
            approver_id=None,
            timeout_sec=300,
            store=mock_store,
            state=state,
        )

        escalated_events = [e for e in written_events if e.type == EventType.Escalated]
        self.assertEqual(len(escalated_events), 1)
        self.assertEqual(escalated_events[0].actor, Actor.system)
        self.assertIn("timed out after 300s", escalated_events[0].payload.reason)
        self.assertIn("Fail-Closed", escalated_events[0].payload.reason)
        self.assertEqual(updated_state.phase, IncidentPhase.escalated)

        mock_notify.assert_called_once()
        call_payload = mock_notify.call_args[0][0]
        self.assertEqual(call_payload["type"], "escalation")
        self.assertEqual(call_payload["incident_id"], "inc-test-timeout")
        self.assertIn("Fail-Closed", call_payload["message"])

    @patch("demos._harness._notify_slack_safe")
    def test_denial_records_escalation_and_halts_safely(self, mock_notify):
        from demos._harness import _handle_unapproved_t2_halt
        from src.domain.types import EventType, Actor, IncidentPhase, IncidentOpenedPayload, build_event
        from tests.policy.conftest import make_state

        state = make_state()
        state.phase = IncidentPhase.awaiting_approval
        open_payload = IncidentOpenedPayload(
            instance_id=state.instance_id,
            dedupe_key="dedupe-test",
            alarm_name="test-alarm",
            alarm_arn="arn:aws:cloudwatch:us-east-1:123456789012:alarm:test",
            alert_source="arn:aws:events:us-east-1:123456789012:rule/test",
        )
        open_ev = build_event(
            incident_id="inc-test-denial",
            type=EventType.IncidentOpened,
            actor=Actor.system,
            payload=open_payload,
        )
        written_events = [open_ev]
        mock_store = MagicMock()
        mock_store.read.side_effect = lambda iid: list(written_events)
        mock_store.append.side_effect = lambda iid, seq, ev: written_events.append(ev)

        updated_state = _handle_unapproved_t2_halt(
            iid="inc-test-denial",
            instance_id="i-test-inst",
            step_id="step-t2",
            approver_id="U_SECOPS_CHIEF",
            timeout_sec=300,
            store=mock_store,
            state=state,
        )

        escalated_events = [e for e in written_events if e.type == EventType.Escalated]
        self.assertEqual(len(escalated_events), 1)
        self.assertEqual(escalated_events[0].actor, Actor.system)
        self.assertIn("explicitly denied by <@U_SECOPS_CHIEF>", escalated_events[0].payload.reason)
        self.assertEqual(updated_state.phase, IncidentPhase.escalated)

        mock_notify.assert_called_once()
        call_payload = mock_notify.call_args[0][0]
        self.assertEqual(call_payload["type"], "escalation")
        self.assertEqual(call_payload["incident_id"], "inc-test-denial")


