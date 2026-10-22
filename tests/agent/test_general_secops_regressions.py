"""
tests/agent/test_general_secops_regressions.py — General SecOps Engine Regression Tests

Verifies:
1. SSMLab T0/T1 allowlists strictly align with AWS SSM document definitions (incidents-observe-readonly & incidents-repair-restricted)
2. Auto-Sudo correctly prepends 'sudo ' for T1 root mutations without duplicating existing sudo
3. Progress Guard strictly rejects compound operators (&&, ||, |, ;, >, <) without silent truncation or altered execution
4. ToolExecutor provides actionable guidance hints on allowlist/tool restriction errors
5. PolicyGate and SSM security boundaries strictly classify dangerous operations (stop, rm -f, mv, kill) as Tier.T2 and require explicit HMAC approval
6. Complete TLS investigation capability using permitted T0 tools (curl -v, cat, ls, stat, date) without openssl
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest

from src.domain.types import (
    new_ulid, utc_now, IncidentState, BudgetState, IncidentPhase,
    IncidentOpenedPayload, IncidentHeader, StepRecord, StepKind,
    DeclaredEffect, EffectCategory, EvidenceRef, TrustLevel,
    EvidenceAddedPayload, HypothesisRecord, HypothesisStatus,
    PolicyDecisionValue, PolicyDecisionPayload, Tier,
    ApprovalGrantedPayload, build_event, EventType, Actor,
)
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.agent import (
    RecordedModel, ModelContext, ToolCall,
    MockObserveBackend, ObservationResult,
    ReasoningLoop, LoopTermination,
)
from src.agent.tool_executor import ToolExecutor, ToolResult, _validate_remediation_target
from src.executor.ssm_lab import SSMLab, _T0_ALLOWED_PREFIXES, _T1_ALLOWED_PREFIXES
from src.policy import GateContext, evaluate as gate_evaluate, TEST_AUTH_KEY, compute_plan_hash
from src.policy.auth import compute_auth_tag


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


def _make_step(
    incident_id: str,
    target: str,
    command: str,
    category: EffectCategory,
    resource: str,
    risk_claim: str = "low",
    kind: StepKind = StepKind.mutate,
) -> StepRecord:
    step_id = new_ulid()
    effects = [DeclaredEffect(category=category, resource=resource, description="test action")]
    step = StepRecord(
        step_id=step_id,
        incident_id=incident_id,
        based_on_hypotheses=["h1"],
        based_on_evidence=["e1"],
        kind=kind,
        target=target,
        execution_spec={"command": command},
        declared_effects=effects,
        preconditions=[],
        success_criteria=[{"type": "exit_code", "value": 0}],
        rollback_plan="none",
        rollback_reason="test",
        idempotent=True,
        risk_claim=risk_claim,
        expires_at=utc_now().isoformat(),
        plan_hash="placeholder",
    )
    plan_hash = compute_plan_hash(step)
    return StepRecord(
        step_id=step.step_id,
        incident_id=step.incident_id,
        based_on_hypotheses=step.based_on_hypotheses,
        based_on_evidence=step.based_on_evidence,
        kind=step.kind,
        target=step.target,
        execution_spec=step.execution_spec,
        declared_effects=step.declared_effects,
        preconditions=step.preconditions,
        success_criteria=step.success_criteria,
        rollback_plan=step.rollback_plan,
        rollback_reason=step.rollback_reason,
        idempotent=step.idempotent,
        risk_claim=step.risk_claim,
        expires_at=step.expires_at,
        plan_hash=plan_hash,
    )


# ===========================================================================
# 1. SSMLab Allowlist & Auto-Sudo Alignment
# ===========================================================================

class TestSSMLabAllowlistAndAutoSudo:
    def test_openssl_not_in_t0_allowlist(self):
        """openssl must not be in T0 allowlist to avoid AWS SSM InvalidParameters error."""
        assert "openssl" not in _T0_ALLOWED_PREFIXES

    def test_openssl_command_blocked_locally_by_ssm_lab(self):
        """SSMLab should reject openssl locally with blocked_reason and not call send_command."""
        mock_ssm = MagicMock()
        lab = SSMLab(instance_id="i-test001", ssm_client=mock_ssm)
        res = lab.run("openssl x509 -in /etc/ssl/cert.crt -noout -dates", tier="T0")

        assert not res.success
        assert res.exit_code == -1
        assert "Command not in T0 allowlist" in (res.blocked_reason or "")
        mock_ssm.send_command.assert_not_called()

    def test_unsupported_commands_blocked_locally_in_t1(self):
        """Commands not in T1 SSM allowlist (chmod, chown, touch, reboot, dd) must be rejected locally."""
        mock_ssm = MagicMock()
        lab = SSMLab(instance_id="i-test001", ssm_client=mock_ssm)

        for disallowed_cmd in [
            "chmod 644 /etc/ssl/cert.crt",
            "chown root:root /etc/ssl/cert.crt",
            "touch /tmp/flag",
            "reboot",
            "dd if=/dev/zero of=/tmp/junk",
        ]:
            res = lab.run(disallowed_cmd, tier="T1")
            assert not res.success
            assert "Command not in T1 allowlist" in (res.blocked_reason or "")
            mock_ssm.send_command.assert_not_called()

    def test_auto_sudo_added_for_mv_and_rm_f_and_stop(self):
        """T1 mutations like mv, rm -f, systemctl stop, cp must automatically get sudo."""
        mock_ssm = MagicMock()
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "",
            "StandardErrorContent": "",
            "ResponseCode": 0,
        }
        lab = SSMLab(instance_id="i-test001", ssm_client=mock_ssm)

        # Test cp
        lab.run("cp /tmp/renewed.crt /etc/ssl/certs/active.crt", tier="T1")
        called_cmd = mock_ssm.send_command.call_args[1]["Parameters"]["command"][0]
        assert called_cmd.startswith("sudo cp ")

        # Test mv
        lab.run("mv /etc/ssl/certs/renewed.crt /etc/ssl/certs/active.crt", tier="T1")
        called_cmd = mock_ssm.send_command.call_args[1]["Parameters"]["command"][0]
        assert called_cmd.startswith("sudo mv ")

        # Test systemctl stop
        lab.run("systemctl stop my-service", tier="T1")
        called_cmd = mock_ssm.send_command.call_args[1]["Parameters"]["command"][0]
        assert called_cmd.startswith("sudo systemctl stop ")

        # Test rm -f
        lab.run("rm -f /var/log/junk.log", tier="T1")
        called_cmd = mock_ssm.send_command.call_args[1]["Parameters"]["command"][0]
        assert called_cmd.startswith("sudo rm -f ")

    def test_existing_sudo_not_duplicated(self):
        """Commands that already start with sudo should not have a second sudo added."""
        mock_ssm = MagicMock()
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "",
            "StandardErrorContent": "",
            "ResponseCode": 0,
        }
        lab = SSMLab(instance_id="i-test001", ssm_client=mock_ssm)

        lab.run("sudo mv /etc/ssl/certs/renewed.crt /etc/ssl/certs/active.crt", tier="T1")
        called_cmd = mock_ssm.send_command.call_args[1]["Parameters"]["command"][0]
        assert called_cmd == "sudo mv /etc/ssl/certs/renewed.crt /etc/ssl/certs/active.crt"
        assert not called_cmd.startswith("sudo sudo ")


# ===========================================================================
# 2. Progress Guard Strict Rejection (No Silent Alteration)
# ===========================================================================

class TestProgressGuardCompoundOperatorsRejection:
    """
    Verifies that Progress Guard strictly rejects compound commands and pipelines,
    never silently stripping operators and altering the command's meaning.
    """

    def test_pipe_rejected_without_silent_execution(self):
        """A pipe command (e.g. ps aux | grep nginx) must be rejected and not executed."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "ps aux | grep nginx"}, "reasoning": "check"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={})
        store, state = _open_incident()
        loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=3)
        result = loop.run(state, max_steps=2)

        first_res = result.tool_results[0]
        assert first_res.success is False
        assert "unsupported compound shell operators" in first_res.message
        # Backend was never called with stripped 'ps aux'
        assert len(backend.observation_calls) == 0

    def test_and_operator_rejected_without_silent_execution(self):
        """Commands with && must be rejected cleanly, not truncated."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "systemctl status my-service && echo ok"}, "reasoning": "check service"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={})
        store, state = _open_incident()
        loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=3)
        result = loop.run(state, max_steps=2)

        first_res = result.tool_results[0]
        assert first_res.success is False
        assert "unsupported compound shell operators" in first_res.message
        assert len(backend.observation_calls) == 0

    def test_or_operator_rejected_without_silent_execution(self):
        """Commands with || must be rejected cleanly."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "curl -v https://127.0.0.1:8443 || true"}, "reasoning": "probe"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={})
        store, state = _open_incident()
        loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=3)
        result = loop.run(state, max_steps=2)

        first_res = result.tool_results[0]
        assert first_res.success is False
        assert "unsupported compound shell operators" in first_res.message
        assert len(backend.observation_calls) == 0

    def test_redirection_rejected_without_silent_execution(self):
        """Commands with redirection (>, <) must be rejected cleanly."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "cat < /etc/ssl/certs/test.crt"}, "reasoning": "read cert"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={})
        store, state = _open_incident()
        loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=3)
        result = loop.run(state, max_steps=2)

        first_res = result.tool_results[0]
        assert first_res.success is False
        assert "unsupported compound shell operators" in first_res.message
        assert len(backend.observation_calls) == 0

    def test_find_with_exec_rejected_without_silent_execution(self):
        """Commands with find -exec or -delete must be rejected clearly."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "find /var/log -type f -exec rm {} \\;"}, "reasoning": "find exec"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={})
        store, state = _open_incident()
        loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=3)
        result = loop.run(state, max_steps=2)

        first_res = result.tool_results[0]
        assert first_res.success is False
        assert "-exec/-delete" in first_res.message
        assert len(backend.observation_calls) == 0

    def test_clean_commands_pass_through_normally(self):
        """Clean direct commands without operators execute normally."""
        model = RecordedModel([
            {"tool_name": "observe", "arguments": {"command": "ss -tlnp"}, "reasoning": "check ports"},
            {"tool_name": "escalate", "arguments": {"reason": "done"}, "reasoning": "end"},
        ])
        backend = MockObserveBackend(command_responses={
            "ss -tlnp": ObservationResult(True, "LISTEN 0.0.0.0:8443", "", 0),
        })
        store, state = _open_incident()
        loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id="i-test001", max_cycles=3)
        result = loop.run(state, max_steps=2)

        assert result.tool_results[0].success is True
        assert "ss -tlnp" in [c["command"] for c in backend.observation_calls]


# ===========================================================================
# 3. ToolExecutor Guidance Hints
# ===========================================================================

class TestToolExecutorGuidanceHints:
    def test_allowed_tools_hint_added_on_blocked_command(self):
        """When an observe command fails with blocked reason, an Allowed Tools Hint must be attached."""
        store, state = _open_incident()
        backend = MockObserveBackend(command_responses={
            "custom_binary /etc/file": ObservationResult(
                success=False, stdout="", stderr="Command not in T0 allowlist", exit_code=-1,
                blocked_reason="Command not in T0 allowlist: 'custom_binary'",
            )
        })
        executor = ToolExecutor(store=store, backend=backend, instance_id=state.instance_id)

        call = ToolCall(tool_name="observe", arguments={"command": "custom_binary /etc/file"})
        result, _ = executor.execute(call, state)

        assert not result.success
        assert "[Allowed Tools Hint]" in result.message
        assert "'cat'" in result.message
        assert "'ls'" in result.message

    def test_discovery_hint_includes_directory_listing(self):
        """When a path is not found, discovery hint should suggest listing the directory."""
        store, state = _open_incident()
        backend = MockObserveBackend(command_responses={
            "cat /etc/ssl/certs/missing.crt": ObservationResult(
                success=False, stdout="", stderr="cat: /etc/ssl/certs/missing.crt: No such file or directory", exit_code=1,
            )
        })
        executor = ToolExecutor(store=store, backend=backend, instance_id=state.instance_id)

        call = ToolCall(tool_name="observe", arguments={"command": "cat /etc/ssl/certs/missing.crt"})
        result, _ = executor.execute(call, state)

        assert not result.success
        assert "[Discovery Hint]" in result.message
        assert "ls -la <directory>" in result.message


# ===========================================================================
# 4. PolicyGate & SSM Security Boundaries (Positive & Negative)
# ===========================================================================

class TestPolicyGateAndSSMSecurityBoundaries:
    def test_safe_t1_service_restart_auto_allowed(self):
        """systemctl restart of a non-critical service is Tier.T1 surgical and auto-allowed."""
        store, state = _open_incident(instance_id="i-test001")
        step = _make_step(
            incident_id=state.incident_id,
            target="i-test001",
            command="systemctl restart my-web-app",
            category=EffectCategory.E1,
            resource="service:my-web-app",
            risk_claim="low",
        )
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-test001",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
        )
        res = gate_evaluate(step, state, ctx)
        assert res.tier == Tier.T1
        assert res.decision == PolicyDecisionValue.allow

    def test_safe_t1_log_truncation_auto_allowed(self):
        """truncate -s 0 of an application log is Tier.T1 surgical and auto-allowed."""
        store, state = _open_incident(instance_id="i-test001")
        step = _make_step(
            incident_id=state.incident_id,
            target="i-test001",
            command="truncate -s 0 /var/log/my-app/app.log",
            category=EffectCategory.E3,
            resource="/var/log/my-app/app.log",
            risk_claim="low",
        )
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-test001",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
        )
        res = gate_evaluate(step, state, ctx)
        assert res.tier == Tier.T1
        assert res.decision == PolicyDecisionValue.allow

    def test_systemctl_stop_classified_as_t2_and_blocked_without_approval(self):
        """systemctl stop is a dangerous mutation -> classified as Tier.T2 and requires human approval."""
        store, state = _open_incident(instance_id="i-test001")
        step = _make_step(
            incident_id=state.incident_id,
            target="i-test001",
            command="systemctl stop my-web-app",
            category=EffectCategory.E1,
            resource="service:my-web-app",
            risk_claim="low",
        )
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-test001",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
            approval_event=None,
        )
        res = gate_evaluate(step, state, ctx)
        assert res.tier == Tier.T2
        assert res.decision == PolicyDecisionValue.require_approval
        assert not res.allowed

    def test_rm_f_classified_as_t2_and_blocked_without_approval(self):
        """rm -f is destructive -> classified as Tier.T2 and requires human approval."""
        store, state = _open_incident(instance_id="i-test001")
        step = _make_step(
            incident_id=state.incident_id,
            target="i-test001",
            command="rm -f /var/log/app_old.log",
            category=EffectCategory.E3,
            resource="/var/log/app_old.log",
            risk_claim="low",
        )
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-test001",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
            approval_event=None,
        )
        res = gate_evaluate(step, state, ctx)
        assert res.tier == Tier.T2
        assert res.decision == PolicyDecisionValue.require_approval
        assert not res.allowed

    def test_mv_classified_as_t2_and_blocked_without_approval(self):
        """mv of config/cert file is Tier.T2 and requires approval."""
        store, state = _open_incident(instance_id="i-test001")
        step = _make_step(
            incident_id=state.incident_id,
            target="i-test001",
            command="mv /etc/ssl/certs/renewed.crt /etc/ssl/certs/active.crt",
            category=EffectCategory.E2,
            resource="/etc/ssl/certs/active.crt",
            risk_claim="low",
        )
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-test001",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
            approval_event=None,
        )
        res = gate_evaluate(step, state, ctx)
        assert res.tier == Tier.T2
        assert res.decision == PolicyDecisionValue.require_approval
        assert not res.allowed

    def test_t2_mv_with_valid_hmac_approval_allowed(self):
        """Tier.T2 mutation with valid cryptographic HMAC approval tag is authorized."""
        store, state = _open_incident(instance_id="i-test001")
        step = _make_step(
            incident_id=state.incident_id,
            target="i-test001",
            command="mv /etc/ssl/certs/renewed.crt /etc/ssl/certs/active.crt",
            category=EffectCategory.E2,
            resource="/etc/ssl/certs/active.crt",
            risk_claim="low",
        )
        expires_at = "2099-01-01T00:00:00+00:00"
        nonce = "test-nonce-123"
        approver = "security-lead@example.com"
        now_str = utc_now().isoformat()
        approval = ApprovalGrantedPayload(
            approval_id=new_ulid(),
            step_id=step.step_id,
            plan_hash=step.plan_hash,
            approver_id=approver,
            issued_at=now_str,
            expires_at=expires_at,
            nonce=nonce,
        )
        import dataclasses
        p_for_tag = dataclasses.asdict(approval)
        p_for_tag.pop("auth_tag", None)
        tag = compute_auth_tag(
            incident_id=state.incident_id,
            event_type="ApprovalGranted",
            payload_dict=p_for_tag,
            key=TEST_AUTH_KEY,
        )
        approval = dataclasses.replace(approval, auth_tag=tag)
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-test001",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
            approval_event=approval,
            approval_auth_tag=tag,
            auth_key=TEST_AUTH_KEY,
        )
        res = gate_evaluate(step, state, ctx)
        assert res.tier == Tier.T2
        assert res.decision == PolicyDecisionValue.allow

    def test_critical_service_mutation_strictly_refused(self):
        """Mutating critical services (sshd, systemd, amazon-ssm-agent) is strictly refused."""
        store, state = _open_incident(instance_id="i-test001")

        for crit_cmd in [
            "systemctl restart sshd",
            "systemctl stop sshd",
            "systemctl restart amazon-ssm-agent",
            "systemctl restart systemd",
        ]:
            err = _validate_remediation_target(crit_cmd, [], state)
            assert err is not None
            assert "Mutating critical system service" in err

    def test_bulk_destructive_commands_strictly_refused(self):
        """Bulk destructive commands (find -exec rm, rm -rf, wildcards) are strictly refused."""
        store, state = _open_incident(instance_id="i-test001")

        for dangerous_cmd in [
            "rm -rf /var/log",
            "find /var/log -type f -delete",
            "find /var/log -exec rm -f {} \\;",
            "rm -f /var/log/*.log",
        ]:
            err = _validate_remediation_target(dangerous_cmd, [], state)
            assert err is not None
            assert "Security Policy Refusal" in err


# ===========================================================================
# 5. Complete TLS Investigation Capability Without openssl
# ===========================================================================

class TestTLSInvestigationWithoutOpenssl:
    """
    Verifies that the agent has full diagnostic capability for TLS/SSL outages
    using only permitted T0 tools (curl -v, cat, ls -la, stat, date).
    """

    def test_tls_handshake_diagnosed_via_curl_v(self):
        """curl -v client probe diagnoses TLS expiration and cipher details directly in T0."""
        store, state = _open_incident(instance_id="i-test001")
        backend = MockObserveBackend(command_responses={
            "curl -v https://127.0.0.1:8443/health": ObservationResult(
                success=True,
                stdout=(
                    "* Connected to 127.0.0.1 (127.0.0.1) port 8443\n"
                    "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384\n"
                    "* Server certificate:\n"
                    "*  subject: CN=127.0.0.1\n"
                    "*  start date: Jan 01 00:00:00 2020 GMT\n"
                    "*  expire date: Feb 01 00:00:00 2020 GMT\n"
                    "*  issuer: CN=127.0.0.1\n"
                    "* SSL certificate verify result: certificate has expired (60)\n"
                ),
                stderr="",
                exit_code=0,
            )
        })
        executor = ToolExecutor(store=store, backend=backend, instance_id=state.instance_id)
        call = ToolCall(tool_name="observe", arguments={"command": "curl -v https://127.0.0.1:8443/health"})
        result, new_state = executor.execute(call, state)

        assert result.success
        out = result.data.get("output", "")
        assert "certificate has expired" in out
        assert "TLSv1.3" in out

    def test_tls_cert_dates_read_via_cat(self):
        """cat reads PEM/text certificate details directly in T0."""
        store, state = _open_incident(instance_id="i-test001")
        backend = MockObserveBackend(command_responses={
            "cat /etc/ssl/certs/app_cert.crt": ObservationResult(
                success=True,
                stdout=(
                    "Certificate:\n"
                    "    Data:\n"
                    "        Validity\n"
                    "            Not Before: Jan  1 00:00:00 2020 GMT\n"
                    "            Not After : Feb  1 00:00:00 2020 GMT\n"
                    "        Subject: CN = 127.0.0.1\n"
                ),
                stderr="",
                exit_code=0,
            )
        })
        executor = ToolExecutor(store=store, backend=backend, instance_id=state.instance_id)
        call = ToolCall(tool_name="observe", arguments={"command": "cat /etc/ssl/certs/app_cert.crt"})
        result, new_state = executor.execute(call, state)

        assert result.success
        out = result.data.get("output", "")
        assert "Not After : Feb  1 00:00:00 2020 GMT" in out

    def test_tls_directory_enumerated_via_ls(self):
        """ls -la enumerates certificate directories to discover renewed certificates."""
        store, state = _open_incident(instance_id="i-test001")
        backend = MockObserveBackend(command_responses={
            "ls -la /etc/ssl/certs": ObservationResult(
                success=True,
                stdout=(
                    "-rw-r--r-- 1 root root 1200 /etc/ssl/certs/app_cert.crt\n"
                    "-rw-r--r-- 1 root root 1200 /etc/ssl/certs/app_cert_renewed.crt\n"
                ),
                stderr="",
                exit_code=0,
            )
        })
        executor = ToolExecutor(store=store, backend=backend, instance_id=state.instance_id)
        call = ToolCall(tool_name="observe", arguments={"command": "ls -la /etc/ssl/certs"})
        result, new_state = executor.execute(call, state)

        assert result.success
        out = result.data.get("output", "")
        assert "app_cert_renewed.crt" in out

    def test_grounded_cert_mv_validation_succeeds(self):
        """Once renewed cert is grounded via ls, proposing mv passes validation."""
        store, state = _open_incident(instance_id="i-test001")
        ev_ref = EvidenceRef(
            evidence_id="ev-ls-certs",
            source="observe:ls -la /etc/ssl/certs",
            trust=TrustLevel.host_reported,
            collected_at=utc_now().isoformat(),
            raw_ref="blob:123",
            integrity_hash="123",
            summary=(
                "-rw-r--r-- 1 root root 1200 /etc/ssl/certs/app_cert.crt\n"
                "-rw-r--r-- 1 root root 1200 /etc/ssl/certs/app_cert_renewed.crt\n"
            ),
            redaction_report={"patterns_checked": 0, "items_redacted": 0},
        )
        state.evidence["ev-ls-certs"] = ev_ref

        cmd = "mv /etc/ssl/certs/app_cert_renewed.crt /etc/ssl/certs/app_cert.crt"
        effects = [
            DeclaredEffect(
                category=EffectCategory.E2,
                resource="/etc/ssl/certs/app_cert.crt",
                description="Update active certificate with renewed certificate",
            )
        ]
        err = _validate_remediation_target(cmd, effects, state)
        assert err is None
