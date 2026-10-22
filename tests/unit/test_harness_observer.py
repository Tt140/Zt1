"""
tests/unit/test_harness_observer.py

Unit tests for RealEC2ObserveBackend monitoring functions (get_metric, get_logs, describe_alarm)
and auto_approve_t2 governance in run_incident_lifecycle from demos/_harness.py.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from demos._harness import (
    RealEC2ObserveBackend,
    run_incident_lifecycle,
    audit_incident_evidence_trail,
)
from src.agent.mock_backend import MetricResult, LogResult, AlarmState
from src.agent.tool_executor import ToolExecutor
from src.domain import (
    IncidentState,
    IncidentPhase,
    PolicyDecisionValue,
    Tier,
    StepRecord,
    StepKind,
    PolicyDecisionPayload,
    TrustLevel,
    EventType,
    build_event,
    Actor,
)


class TestRealEC2ObserveBackend(unittest.TestCase):
    def setUp(self):
        self.mock_ssm_lab = MagicMock()
        self.observer = RealEC2ObserveBackend(
            ssm_lab=self.mock_ssm_lab,
            instance_id="i-test12345",
            region="us-east-1",
        )

    def test_get_metric_with_real_datapoint(self):
        mock_cw = MagicMock()
        mock_cw.get_metric_data.return_value = {
            "MetricDataResults": [{"Values": [73.5], "Label": "CPUUtilization"}]
        }
        self.observer._cw_client = mock_cw

        result = self.observer.get_metric("i-test12345", "CPUUtilization", period_seconds=300)

        self.assertIsInstance(result, MetricResult)
        self.assertEqual(result.value, 73.5)
        self.assertEqual(result.unit, "Percent")
        self.assertIsNone(result.error)
        self.assertEqual(result.trust, "out_of_band")

    def test_get_metric_no_datapoints_returns_unavailable(self):
        """No synthetic fallback to 89.0 or 25.0 when datapoints are absent."""
        mock_cw = MagicMock()
        mock_cw.get_metric_data.return_value = {
            "MetricDataResults": [{"Values": []}]
        }
        self.observer._cw_client = mock_cw

        result = self.observer.get_metric("i-test12345", "DiskSpaceUtilization", period_seconds=300)

        self.assertIsInstance(result, MetricResult)
        self.assertEqual(result.value, 0.0)
        self.assertEqual(result.unit, "UNAVAILABLE")
        self.assertIsNotNone(result.error)
        self.assertIn("UNAVAILABLE", result.error)

    def test_get_metric_exception_returns_unavailable(self):
        mock_cw = MagicMock()
        mock_cw.get_metric_data.side_effect = RuntimeError("CloudWatch access denied")
        self.observer._cw_client = mock_cw

        result = self.observer.get_metric("i-test12345", "CPUUtilization", period_seconds=300)

        self.assertIsInstance(result, MetricResult)
        self.assertEqual(result.value, 0.0)
        self.assertEqual(result.unit, "UNAVAILABLE")
        self.assertIsNotNone(result.error)
        self.assertIn("CloudWatch access denied", result.error)

    def test_get_logs_with_events(self):
        mock_logs = MagicMock()
        mock_logs.filter_log_events.return_value = {
            "events": [{"message": "ERROR: service failure"}, {"message": "Restarting worker"}]
        }
        self.observer._logs_client = mock_logs

        result = self.observer.get_logs("i-test12345", "/var/log/syslog", minutes_back=15)

        self.assertIsInstance(result, LogResult)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.entries[0], "ERROR: service failure")
        self.assertIsNone(result.error)

    def test_get_logs_no_events_returns_unavailable(self):
        mock_logs = MagicMock()
        mock_logs.filter_log_events.return_value = {"events": []}
        self.observer._logs_client = mock_logs

        result = self.observer.get_logs("i-test12345", "/var/log/nonexistent", minutes_back=15)

        self.assertIsInstance(result, LogResult)
        self.assertEqual(result.entries, [])
        self.assertIsNotNone(result.error)
        self.assertIn("UNAVAILABLE", result.error)

    def test_get_logs_exception_returns_unavailable(self):
        mock_logs = MagicMock()
        mock_logs.filter_log_events.side_effect = RuntimeError("ResourceNotFoundException")
        self.observer._logs_client = mock_logs

        result = self.observer.get_logs("i-test12345", "/var/log/syslog", minutes_back=15)

        self.assertIsInstance(result, LogResult)
        self.assertEqual(result.entries, [])
        self.assertIsNotNone(result.error)
        self.assertIn("ResourceNotFoundException", result.error)

    def test_describe_alarm_existing(self):
        mock_cw = MagicMock()
        mock_cw.describe_alarms.return_value = {
            "MetricAlarms": [{
                "StateValue": "ALARM",
                "StateReason": "Threshold Crossed: 1 out of 1 datapoints > 80.0",
            }]
        }
        self.observer._cw_client = mock_cw

        result = self.observer.describe_alarm("HighCPUAlarm")

        self.assertIsInstance(result, AlarmState)
        self.assertEqual(result.state, "ALARM")
        self.assertIn("Threshold Crossed", result.reason)
        self.assertIsNone(result.error)

    def test_describe_alarm_not_found(self):
        mock_cw = MagicMock()
        mock_cw.describe_alarms.return_value = {
            "MetricAlarms": [],
            "CompositeAlarms": [],
        }
        self.observer._cw_client = mock_cw

        result = self.observer.describe_alarm("UnknownAlarm")

        self.assertIsInstance(result, AlarmState)
        self.assertEqual(result.state, "NOT_FOUND")
        self.assertIsNotNone(result.error)
        self.assertIn("NOT_FOUND", result.error)

    def test_describe_alarm_exception(self):
        mock_cw = MagicMock()
        mock_cw.describe_alarms.side_effect = RuntimeError("AccessDenied")
        self.observer._cw_client = mock_cw

        result = self.observer.describe_alarm("AnyAlarm")

        self.assertIsInstance(result, AlarmState)
        self.assertEqual(result.state, "UNAVAILABLE")
        self.assertIsNotNone(result.error)
        self.assertIn("AccessDenied", result.error)


class TestToolExecutorUnavailableMetric(unittest.TestCase):
    def test_query_metrics_fails_cleanly_on_unavailable_metric(self):
        """When backend returns unit='UNAVAILABLE', ToolExecutor fails without creating evidence."""
        backend = MagicMock()
        backend.get_metric.return_value = MetricResult(
            metric_name="DiskSpaceUtilization",
            value=0.0,
            unit="UNAVAILABLE",
            period_seconds=300,
            trust="out_of_band",
            error="UNAVAILABLE: no CloudWatch datapoints found",
        )

        executor = ToolExecutor(
            backend=backend,
            instance_id="i-test12345",
            store=MagicMock(),
        )
        state = MagicMock()

        res = executor._do_query_metrics({"metric_name": "DiskSpaceUtilization"}, state)

        self.assertFalse(res.success)
        self.assertIn("UNAVAILABLE", res.message)


class TestAutoApproveT2Governance(unittest.TestCase):
    @patch("demos._harness.ReasoningLoop")
    @patch("demos._harness.build_runtime")
    @patch("demos._harness.ExecutorLoop")
    def test_auto_approve_t2_false_pauses_without_issuing_approval(
        self, mock_executor_cls, mock_build_runtime, mock_loop_cls
    ):
        mock_store = MagicMock()
        mock_store.read.return_value = []
        mock_runtime = MagicMock()
        mock_runtime.store = mock_store
        mock_build_runtime.return_value = mock_runtime

        # Step and policy decision for T2
        step_id = "step-01"
        proposed_step = StepRecord(
            step_id=step_id,
            incident_id="inc-test",
            based_on_hypotheses=[],
            based_on_evidence=[],
            kind=StepKind.mutate,
            target="process",
            execution_spec={"command": "kill -9 1234"},
            declared_effects=[],
            preconditions=[],
            success_criteria=[],
            rollback_plan="none",
            rollback_reason="unrecoverable",
            idempotent=False,
            risk_claim="high risk",
            expires_at="2026-10-20T00:15:00Z",
            plan_hash="plan123",
            status="proposed",
        )
        t2_decision = PolicyDecisionPayload(
            step_id=step_id,
            plan_hash="plan123",
            tier=Tier.T2,
            decision=PolicyDecisionValue.require_approval,
            reasons=["T2 requires manual approval"],
            rule_ids=["rule-t2"],
            budget_snapshot={},
            gate_version="1.0",
        )

        state = MagicMock()
        state.phase = IncidentPhase.awaiting_approval
        state.steps = {step_id: proposed_step}
        state.policy_decisions = {step_id: t2_decision}
        state.pending_approval_step = step_id

        # Mock investigation loop returning state with proposed T2 step
        mock_loop = MagicMock()
        mock_loop_cls.return_value = mock_loop
        loop_res = MagicMock()
        loop_res.termination.value = "remediation_proposed"
        loop_res.final_state = state
        mock_loop.run.return_value = loop_res

        # Call run_incident_lifecycle with auto_approve_t2=False
        res_state, res_step, res_policy, res_exec = run_incident_lifecycle(
            iid="inc-test",
            state=state,
            ssm_client=MagicMock(),
            instance_id="i-test12345",
            auto_approve_t2=False,
        )

        # Must return (state, step, policy_decision, None)
        self.assertIs(res_state, state)
        self.assertEqual(res_step.step_id, step_id)
        self.assertEqual(res_policy.tier, Tier.T2)
        self.assertIsNone(res_exec)

        # Must NOT call store.append for ApprovalGranted
        mock_store.append.assert_not_called()
        # Must NOT initialize or run ExecutorLoop
        mock_executor_cls.assert_not_called()

    @patch("demos._harness.fold")
    @patch("demos._harness.ReasoningLoop")
    @patch("demos._harness.build_runtime")
    @patch("demos._harness.ExecutorLoop")
    def test_auto_approve_t2_true_issues_approval_and_executes(
        self, mock_executor_cls, mock_build_runtime, mock_loop_cls, mock_fold
    ):
        mock_store = MagicMock()
        mock_store.read.return_value = []
        mock_runtime = MagicMock()
        mock_runtime.store = mock_store
        mock_build_runtime.return_value = mock_runtime

        step_id = "step-01"
        proposed_step = StepRecord(
            step_id=step_id,
            incident_id="inc-test",
            based_on_hypotheses=[],
            based_on_evidence=[],
            kind=StepKind.mutate,
            target="process",
            execution_spec={"command": "kill -9 1234"},
            declared_effects=[],
            preconditions=[],
            success_criteria=[],
            rollback_plan="none",
            rollback_reason="unrecoverable",
            idempotent=False,
            risk_claim="high risk",
            expires_at="2026-10-20T00:15:00Z",
            plan_hash="plan123",
            status="proposed",
        )
        t2_decision = PolicyDecisionPayload(
            step_id=step_id,
            plan_hash="plan123",
            tier=Tier.T2,
            decision=PolicyDecisionValue.require_approval,
            reasons=["T2 requires manual approval"],
            rule_ids=["rule-t2"],
            budget_snapshot={},
            gate_version="1.0",
        )

        state = MagicMock()
        state.last_seq = 5
        state.phase = IncidentPhase.awaiting_approval
        state.steps = {step_id: proposed_step}
        state.policy_decisions = {step_id: t2_decision}
        state.pending_approval_step = step_id

        # Mock investigation loop returning state with proposed T2 step
        mock_loop = MagicMock()
        mock_loop_cls.return_value = mock_loop
        loop_res = MagicMock()
        loop_res.termination.value = "remediation_proposed"
        loop_res.final_state = state
        mock_loop.run.return_value = loop_res

        # Mock fold after approval
        approved_state = MagicMock()
        approved_state.phase = IncidentPhase.resolved
        approved_state.steps = {step_id: proposed_step}
        mock_fold.return_value = approved_state

        mock_executor = MagicMock()
        mock_executor_cls.return_value = mock_executor
        exec_res = MagicMock()
        exec_res.termination.value = "reconciled"
        exec_res.gate_decision = None
        mock_executor.execute_step.return_value = exec_res

        # Call run_incident_lifecycle with auto_approve_t2=True
        res_state, res_step, res_policy, res_exec = run_incident_lifecycle(
            iid="inc-test",
            state=state,
            ssm_client=MagicMock(),
            instance_id="i-test12345",
            auto_approve_t2=True,
        )

        # Must call store.append with ApprovalGranted event
        self.assertTrue(mock_store.append.called)
        ev = mock_store.append.call_args[0][2]
        self.assertEqual(ev.type, EventType.ApprovalGranted)

        # Must call executor_loop.execute_step
        mock_executor.execute_step.assert_called_once()
        self.assertIsNotNone(res_exec)


class TestAuditIncidentEvidenceTrail(unittest.TestCase):
    def test_audit_evidence_trail_extracts_and_formats_trail(self):
        from src.domain.types import (
            EvidenceRef,
            EvidenceAddedPayload,
            HypothesisRecord,
            HypothesisUpdatedPayload,
            HypothesisStatus,
            StepProposedPayload,
            StepRecord,
            StepKind,
            PolicyDecisionPayload,
            Tier,
            PolicyDecisionValue,
        )

        mock_store = MagicMock()
        ev_id = "01TESTEVID0000000000000000"
        hyp_id = "H1"
        step_id = "step-01"

        ev1 = MagicMock()
        ev1.seq = 1
        ev1.type.value = "EvidenceAdded"
        ev1.payload = EvidenceAddedPayload(
            evidence=EvidenceRef(
                evidence_id=ev_id,
                source="observation:df -h",
                trust=TrustLevel.host_reported,
                collected_at="2026-10-20T00:00:00Z",
                raw_ref="blob:test",
                integrity_hash="hash1",
                summary="Filesystem /dev/root size=20G used=18G (90%)",
                redaction_report={},
            )
        )

        ev2 = MagicMock()
        ev2.seq = 2
        ev2.type.value = "HypothesisUpdated"
        ev2.payload = HypothesisUpdatedPayload(
            hypothesis=HypothesisRecord(
                hypothesis_id=hyp_id,
                statement="Root filesystem full due to cache bloat",
                confidence=0.95,
                supporting=[ev_id],
                contradicting=[],
                status=HypothesisStatus.confirmed,
                next_check=None,
                trigger_evidence_id=ev_id,
            )
        )

        ev3 = MagicMock()
        ev3.seq = 3
        ev3.type.value = "StepProposed"
        ev3.payload = StepProposedPayload(
            step=StepRecord(
                step_id=step_id,
                incident_id="inc-test",
                based_on_hypotheses=[hyp_id],
                based_on_evidence=[ev_id],
                kind=StepKind.mutate,
                target="file",
                execution_spec={"command": "truncate -s 0 /var/cache/app_spool/orphaned_export_55gb.dat"},
                declared_effects=[],
                preconditions=[],
                success_criteria=[],
                rollback_plan="none",
                rollback_reason="unrecoverable",
                idempotent=True,
                risk_claim="low risk",
                expires_at="2026-10-20T00:15:00Z",
                plan_hash="hash-step",
                status="proposed",
            )
        )

        ev4 = MagicMock()
        ev4.seq = 4
        ev4.type.value = "PolicyDecision"
        ev4.payload = PolicyDecisionPayload(
            step_id=step_id,
            plan_hash="hash-step",
            tier=Tier.T1,
            decision=PolicyDecisionValue.allow,
            reasons=["Auto-allowed T1 remediation"],
            rule_ids=["rule-truncate"],
            budget_snapshot={},
            gate_version="1.0",
        )

        mock_store.read.return_value = [ev1, ev2, ev3, ev4]

        report = audit_incident_evidence_trail(iid="inc-test", store=mock_store)

        self.assertEqual(report["incident_id"], "inc-test")
        self.assertEqual(len(report["evidence"]), 1)
        self.assertEqual(report["evidence"][0]["evidence_id"], ev_id)
        self.assertEqual(len(report["hypotheses"]), 1)
        self.assertEqual(report["hypotheses"][0]["hypothesis_id"], hyp_id)
        self.assertEqual(len(report["proposed_steps"]), 1)
        self.assertEqual(report["proposed_steps"][0]["step_id"], step_id)
        self.assertEqual(report["proposed_steps"][0]["based_on_evidence"], [ev_id])
        self.assertEqual(report["proposed_steps"][0]["based_on_hypotheses"], [hyp_id])


def extract_port_owner_pid(output: str) -> Optional[str]:
    """Helper to extract port owner PID from ss or netstat output."""
    import re
    m = re.search(r"pid=(\d+)", output)
    if m:
        return m.group(1)
    m = re.search(r"\b(\d+)/", output)
    if m:
        return m.group(1)
    return None


def extract_bound_port(output: str, port: int) -> bool:
    """Helper to verify if a given port is actively bound in socket telemetry."""
    import re
    return bool(re.search(rf":{port}\b", output))


class TestPortOwnerStrictMatching(unittest.TestCase):
    """Verifies strict PID matching for network port owner, preventing false positives."""

    def test_extract_port_owner_pid_ss_format(self):
        ss_output = 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=54321,fd=3))'
        pid = extract_port_owner_pid(ss_output)
        self.assertEqual(pid, "54321")

    def test_extract_port_owner_pid_netstat_format(self):
        netstat_output = "tcp 0 0 0.0.0.0:8080 0.0.0.0:* LISTEN 54321/python3"
        pid = extract_port_owner_pid(netstat_output)
        self.assertEqual(pid, "54321")

    def test_extract_port_owner_pid_none_when_absent(self):
        raw_output = "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*"
        pid = extract_port_owner_pid(raw_output)
        self.assertIsNone(pid)

    def test_reject_mismatched_pid_even_with_python3(self):
        app_main_pid = "54321"
        rogue_pid = "9999"
        port_owner = f'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid={rogue_pid},fd=3))'

        owner_pid = extract_port_owner_pid(port_owner)
        self.assertIsNotNone(owner_pid)
        self.assertEqual(owner_pid, rogue_pid)
        self.assertNotEqual(owner_pid, app_main_pid)

        # Confirm strict PID equality check
        new_check_passed = ":8080" in port_owner and owner_pid == app_main_pid
        self.assertFalse(new_check_passed)

    def test_accept_matching_pid(self):
        app_main_pid = "54321"
        port_owner = f'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid={app_main_pid},fd=3))'

        owner_pid = extract_port_owner_pid(port_owner)
        self.assertEqual(owner_pid, app_main_pid)
        self.assertTrue(":8080" in port_owner and owner_pid == app_main_pid)


class TestTLSCertPathPolicyInvariants(unittest.TestCase):
    """Unit tests for TLS credential paths compliance with Security Policy Invariants."""

    def test_extract_bound_port(self):
        ss_output = 'tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("python3",pid=12345,fd=3))'
        self.assertTrue(extract_bound_port(ss_output, 8443))
        self.assertFalse(extract_bound_port(ss_output, 8080))
        self.assertFalse(extract_bound_port("tcp LISTEN 0 128 0.0.0.0:84433 0.0.0.0:*", 8443))

    def test_cert_paths_comply_with_invariant_i15(self):
        from src.policy.invariants import SECRET_PATH_PATTERNS, PROTECTED_PATHS
        active_cert_path = "/etc/ssl/certs/app.crt"
        renewed_cert_path = "/etc/ssl/certs/app_renewed.crt"
        private_key_path = "/etc/ssl/private/app.key"

        # 1. Public certificates must NOT be blocked by SECRET_PATH_PATTERNS
        for path in (active_cert_path, renewed_cert_path):
            for pat in SECRET_PATH_PATTERNS:
                self.assertIsNone(
                    pat.search(path),
                    f"Public certificate {path} should not match secret pattern {pat.pattern}",
                )

        # 2. Private key path MUST be matched by SECRET_PATH_PATTERNS
        matched_secret_patterns = [
            pat.pattern for pat in SECRET_PATH_PATTERNS if pat.search(private_key_path)
        ]
        self.assertGreater(
            len(matched_secret_patterns),
            0,
            f"Private key path {private_key_path} must be protected by SECRET_PATH_PATTERNS!",
        )

        # 3. Private key directory MUST be in PROTECTED_PATHS
        self.assertIn(
            "/etc/ssl/private",
            PROTECTED_PATHS,
            "/etc/ssl/private must be included in PROTECTED_PATHS",
        )


