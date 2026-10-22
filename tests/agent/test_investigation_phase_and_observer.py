"""
tests/agent/test_investigation_phase_and_observer.py

Dedicated tests for:
1. Alarm context (alarm_name and alert_source in incident_summary, without using dedupe_key as fallback).
2. Tool restriction and availability based on investigation phase (with evidence, without evidence, without active hypotheses, without steps, and with steps).
3. Blocking disallowed tools in actual execution path (ToolExecutor).
4. journalctl -n 50 fallback in handlers/observer._get_logs when /var/log/messages or /var/log/syslog does not exist.
5. Fallback failure: returning explicit error without recording it as successful evidence.
"""
from unittest.mock import MagicMock, patch
import pytest

from src.domain import (
    Actor, EventType, build_event, new_ulid, utc_now,
    IncidentState, IncidentPhase,
)
from src.domain.types import (
    IncidentHeader, IncidentOpenedPayload, EvidenceRef, TrustLevel,
    HypothesisRecord, HypothesisStatus, StepRecord, StepKind,
    EvidenceAddedPayload, HypothesisUpdatedPayload, ApprovalRejectedPayload,
)
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.agent.context_builder import build_context, get_allowed_tools
from src.agent.mock_backend import MockObserveBackend, LogResult, MetricResult, ObservationResult
from src.agent.tool_executor import ToolExecutor, ToolResult
from src.agent.model_interface import ToolCall
from src.executor.docker_lab import LabResult
import handlers.observer as observer_handler


def _create_test_state(
    instance_id: str = "i-test001",
    alarm_name: str = "DiskSpaceLow",
    alert_source: str = "rule/cloudwatch-events",
) -> tuple[MemoryEventStore, IncidentState]:
    store = MemoryEventStore()
    iid = new_ulid()
    dk = f"alarm:{alarm_name}:{instance_id}"
    header = IncidentHeader(
        incident_id=iid,
        instance_id=instance_id,
        dedupe_key=dk,
        alarm_name=alarm_name,
        alarm_arn=f"arn:aws:cloudwatch:us-east-1:123456789012:alarm:{alarm_name}",
        alert_source=alert_source,
        opened_at=utc_now().isoformat(),
    )
    store.create_if_absent(dk, header)
    ev = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=instance_id,
            dedupe_key=dk,
            alarm_name=alarm_name,
            alarm_arn=header.alarm_arn,
            alert_source=alert_source,
        ),
    )
    store.append(iid, 0, ev)
    state = fold(store.read(iid))
    return store, state


# ===========================================================================
# 1. Alarm context tests
# ===========================================================================

def test_alarm_context_in_incident_summary():
    """Verify presence of alarm_name and alert_source in incident_summary without fallback to dedupe_key."""
    store, state = _create_test_state(
        alarm_name="HighMemoryUsageAlarm",
        alert_source="aws.events.rule.memory-alert",
    )
    ctx = build_context(state, cycle=0)

    assert "alarm_name: HighMemoryUsageAlarm" in ctx.incident_summary
    assert "alert_source: aws.events.rule.memory-alert" in ctx.incident_summary
    # Ensure dedupe_key is not used as a substitute for alarm_name
    assert f"alarm_name: {state.dedupe_key}" not in ctx.incident_summary


# ===========================================================================
# 2. Tool availability tests by investigation phase and prevention of disallowed selection
# ===========================================================================

def test_tool_availability_no_evidence():
    """If no evidence exists: allow evidence-gathering tools (+ escalate) and disallow conclude/propose_step/verify/update_hypotheses."""
    store, state = _create_test_state()
    assert len(state.evidence) == 0

    allowed = get_allowed_tools(state)
    assert "observe" in allowed
    assert "query_metrics" in allowed
    assert "query_logs" in allowed
    assert "escalate" in allowed

    for disallowed in ["conclude", "propose_step", "verify", "update_hypotheses"]:
        assert disallowed not in allowed, f"{disallowed} must be disallowed when no evidence exists"

    # Verify that ToolExecutor prevents actual execution of disallowed tool
    executor = ToolExecutor(store, MockObserveBackend(), state.instance_id)
    tc = ToolCall(tool_name="conclude", arguments={"root_cause": "guess"})
    result, new_state = executor.execute(tc, state)
    assert not result.success
    assert "not allowed" in result.message.lower()


def test_tool_availability_with_evidence_no_active_hypotheses():
    """If evidence exists without active hypotheses: disallow conclude/propose_step/verify, and allow update_hypotheses and gathering tools."""
    store, state = _create_test_state()
    executor = ToolExecutor(store, MockObserveBackend(), state.instance_id)

    # Collect evidence
    obs_tc = ToolCall(
        tool_name="observe",
        arguments={"command": "df -h", "timeout_seconds": 10},
    )
    _, state = executor.execute(obs_tc, state)
    assert len(state.evidence) > 0
    assert len(state.hypotheses) == 0

    allowed = get_allowed_tools(state)
    assert "conclude" not in allowed
    assert "update_hypotheses" in allowed
    assert "observe" in allowed
    assert "query_logs" in allowed
    assert "query_metrics" in allowed
    assert "escalate" in allowed

    for disallowed in ["conclude", "propose_step", "verify"]:
        assert disallowed not in allowed, f"{disallowed} must be disallowed when no hypothesis exists"

    # Verify preventing actual execution of propose_step
    prop_tc = ToolCall(
        tool_name="propose_step",
        arguments={
            "kind": "mutate",
            "execution_spec": {"command": "systemctl restart app"},
            "declared_effects": [{"category": "E1", "target": state.instance_id, "description": "restart"}],
            "rollback_plan": "none",
            "based_on_hypotheses": [],
        },
    )
    result, _ = executor.execute(prop_tc, state)
    assert not result.success
    assert "not allowed" in result.message.lower()


def test_tool_availability_with_hypotheses_no_steps():
    """If an active hypothesis exists without proposed steps: disallow verify only."""
    store, state = _create_test_state()
    executor = ToolExecutor(store, MockObserveBackend(), state.instance_id)

    # Collect evidence
    obs_tc = ToolCall(
        tool_name="observe",
        arguments={"command": "df -h", "timeout_seconds": 10},
    )
    _, state = executor.execute(obs_tc, state)
    eid = next(iter(state.evidence))

    # Add active hypothesis
    hyp_tc = ToolCall(
        tool_name="update_hypotheses",
        arguments={"updates": [{
            "hypothesis_id": "hyp-disk",
            "evidence_id": eid,
            "statement": "disk full at /var",
            "confidence": 0.8,
            "status": "active",
        }]},
    )
    _, state = executor.execute(hyp_tc, state)
    assert any(h.status in ("active", "confirmed") for h in state.hypotheses.values())
    assert len(state.steps) == 0

    allowed = get_allowed_tools(state)
    assert "verify" not in allowed, "verify must be disallowed when no steps are proposed"
    assert "conclude" in allowed
    assert "propose_step" in allowed

    # Verify preventing actual execution of verify
    verify_tc = ToolCall(tool_name="verify", arguments={"step_id": "non-existent"})
    result, _ = executor.execute(verify_tc, state)
    assert not result.success
    assert "not allowed" in result.message.lower()


# ===========================================================================
# 3. Tests for journalctl -n 50 fallback in handlers/observer._get_logs
# ===========================================================================

def test_observer_get_logs_fallback_to_journalctl_on_missing_file():
    """When /var/log/messages is requested and the file is missing, journalctl -n 50 is invoked as a fallback."""
    with patch("handlers.observer.SSMLab") as mock_ssm_lab_cls:
        mock_lab = MagicMock()
        mock_ssm_lab_cls.return_value = mock_lab

        def fake_run(command, tier, timeout_seconds):
            if command == "cat /var/log/messages":
                return LabResult(
                    success=False,
                    stdout="",
                    stderr="cat: /var/log/messages: No such file or directory",
                    exit_code=1,
                )
            elif command == "journalctl -n 50":
                return LabResult(
                    success=True,
                    stdout="Oct 16 00:01:00 app[101]: starting\nOct 16 00:01:05 app[101]: memory warning",
                    stderr="",
                    exit_code=0,
                )
            return LabResult(success=False, stdout="", stderr="unknown", exit_code=-1)

        mock_lab.run.side_effect = fake_run

        event = {
            "operation": "get_logs",
            "log_group": "/var/log/messages",
            "instance_id": "i-test001",
        }
        res = observer_handler._get_logs(event)

        # Verify cat is called first, then journalctl -n 50
        assert mock_lab.run.call_count == 2
        calls = [c.kwargs.get("command") or c.args[0] if c.args else c.kwargs["command"] for c in mock_lab.run.call_args_list]
        assert "cat /var/log/messages" in calls
        assert "journalctl -n 50" in calls

        # Verify logs are returned in entries and lines
        assert len(res["entries"]) == 2
        assert len(res["lines"]) == 2
        assert "memory warning" in res["entries"][1]
        assert "error" not in res


def test_observer_get_logs_fallback_failure_returns_explicit_error():
    """If fallback journalctl -n 50 also fails, an explicit error is returned and not recorded as success."""
    with patch("handlers.observer.SSMLab") as mock_ssm_lab_cls:
        mock_lab = MagicMock()
        mock_ssm_lab_cls.return_value = mock_lab

        # Both fail
        mock_lab.run.return_value = LabResult(
            success=False,
            stdout="",
            stderr="systemd-journald is not running",
            exit_code=-1,
        )

        event = {
            "operation": "get_logs",
            "log_group": "/var/log/syslog",
            "instance_id": "i-test001",
        }
        res = observer_handler._get_logs(event)

        assert "error" in res
        assert "Failed reading local log" in res["error"]
        assert len(res["entries"]) == 0
        assert len(res["lines"]) == 0


def test_executor_does_not_record_evidence_when_query_logs_fails():
    """Verify that ToolExecutor does not record EvidenceAdded when get_logs fails."""
    store, state = _create_test_state()

    backend = MagicMock()
    backend.get_logs.return_value = LogResult(
        log_group="/var/log/messages",
        entries=[],
        trust="host_reported",
        error="Failed reading local log /var/log/messages: cat failed and journalctl failed",
    )

    executor = ToolExecutor(store, backend, state.instance_id)
    tc = ToolCall(tool_name="query_logs", arguments={"log_group": "/var/log/messages"})
    result, new_state = executor.execute(tc, state)

    assert not result.success
    assert "query_logs failed" in result.message
    assert len(new_state.evidence) == 0
    assert "EvidenceAdded" not in result.events_written


# ===========================================================================
# 4. DeepSeekModel tests (max_tokens=1024, Markdown cleaning, and retry)
# ===========================================================================

def test_deepseek_model_default_max_tokens_and_markdown_cleaning():
    """Verify raising max_tokens to 4096 and cleaning Markdown code blocks in _parse_response."""
    from src.agent.deepseek_model import DeepSeekModel

    model = DeepSeekModel(api_key="test-key")
    assert model._max_tokens == 4096

    # Response wrapped in Markdown code block
    raw_md = '```json\n{"tool_name": "observe", "arguments": {"command": "uptime"}}\n```'
    resp = model._parse_response(raw_md)
    assert resp.tool_call.tool_name == "observe"
    assert resp.tool_call.arguments == {"command": "uptime"}

    # Empty response
    empty_resp = model._parse_response("   \n  ")
    assert empty_resp.tool_call.tool_name == "escalate"
    assert empty_resp.tool_call.reasoning == "parse-error"

    # Invalid JSON response
    invalid_resp = model._parse_response("This is not valid json")
    assert invalid_resp.tool_call.tool_name == "escalate"
    assert invalid_resp.tool_call.reasoning == "parse-error"


def test_deepseek_model_http_retry_on_parse_error():
    """Retry once on real HTTP call when a parse-error occurs."""
    from src.agent.deepseek_model import DeepSeekModel
    from src.agent.model_interface import ModelContext

    ctx = ModelContext(
        system_prompt="sys",
        incident_summary="inc",
        hypotheses_summary="hyp",
        evidence_summaries=[],
        available_tools=["observe"],
        budget_remaining={},
        cycle=0,
    )

    model = DeepSeekModel(api_key="test-key")

    call_count = 0
    def fake_httpx_post(url, json=None, headers=None, timeout=None):
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        if call_count == 1:
            # First response is invalid
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "broken json output"}}]
            }
        else:
            # Second response is valid
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": '{"tool_name": "observe", "arguments": {"command": "df -h"}}'}}]
            }
        return mock_resp

    with patch("httpx.post", side_effect=fake_httpx_post):
        res = model.invoke(ctx)

    assert call_count == 2, "Should retry once on parse-error in real HTTP mode"
    assert res.tool_call.tool_name == "observe"
    assert res.tool_call.arguments == {"command": "df -h"}


def test_deepseek_model_mock_http_client_does_not_retry():
    """When using http_client (mock in tests), retry is not performed."""
    from src.agent.deepseek_model import DeepSeekModel
    from src.agent.model_interface import ModelContext

    mock_client = MagicMock()
    mock_client.post.return_value = "invalid json"

    model = DeepSeekModel(api_key="test-key", http_client=mock_client)
    ctx = ModelContext(
        system_prompt="sys",
        incident_summary="inc",
        hypotheses_summary="hyp",
        evidence_summaries=[],
        available_tools=["observe"],
        budget_remaining={},
        cycle=0,
    )

    res = model.invoke(ctx)
    assert mock_client.post.call_count == 1
    assert res.tool_call.reasoning == "parse-error"


# ===========================================================================
# 5. Fallback tests for tool_hint when Strands Decider fails
# ===========================================================================

def test_loop_fallback_tool_hint_when_decider_returns_none():
    """When Strands Decider fails (returns None), a deterministic tool_hint is selected by priority."""
    from src.agent.loop import ReasoningLoop
    from src.agent.tool_decider import ToolDecider, NullToolDecider
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _create_test_state()

    # Model records received tool_hint
    received_hints = []
    class InspectingModel(ModelInterface):
        @property
        def name(self) -> str:
            return "inspecting"
        def invoke(self, ctx, tool_hint=None, **kwargs):
            received_hints.append(tool_hint)
            tool = tool_hint or "observe"
            return ModelResponse(tool_call=ToolCall(tool_name=tool, arguments={"command": "uptime"}))

    # Decider is active but returns None (service outage)
    class BrokenDecider(ToolDecider):
        def select(self, ctx):
            return None
        @property
        def name(self):
            return "broken"

    # Case 1: No evidence yet -> priority to "observe"
    loop = ReasoningLoop(
        model=InspectingModel(),
        store=store,
        backend=MockObserveBackend(),
        instance_id=state.instance_id,
        tool_decider=BrokenDecider(),
    )
    loop.run(state, max_steps=1)
    assert received_hints[0] == "observe"

    # Case 2: Evidence exists without active hypotheses -> priority to "update_hypotheses"
    # Add evidence to state
    executor = ToolExecutor(store, MockObserveBackend(), state.instance_id)
    obs_tc = ToolCall(tool_name="observe", arguments={"command": "uptime"})
    _, state_with_ev = executor.execute(obs_tc, state)

    received_hints.clear()
    loop2 = ReasoningLoop(
        model=InspectingModel(),
        store=store,
        backend=MockObserveBackend(),
        instance_id=state.instance_id,
        tool_decider=BrokenDecider(),
    )
    loop2.run(state_with_ev, max_steps=1)
    assert received_hints[0] == "update_hypotheses"

    # Case 3: With NullToolDecider -> tool_hint remains None
    received_hints.clear()
    loop_null = ReasoningLoop(
        model=InspectingModel(),
        store=store,
        backend=MockObserveBackend(),
        instance_id=state.instance_id,
        tool_decider=NullToolDecider(),
    )
    loop_null.run(state, max_steps=1)
    assert received_hints[0] is None


# ===========================================================================
# 6. Handling missing CloudWatch Metric data
# ===========================================================================

def test_get_metric_returns_unavailable_when_datapoints_empty():
    """When CloudWatch Datapoints are empty, _get_metric returns UNAVAILABLE error instead of returning 0.0 as success."""
    mock_cw = MagicMock()
    mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

    with patch("boto3.client", return_value=mock_cw):
        res = observer_handler._get_metric({
            "instance_id": "i-test999",
            "metric_name": "DiskSpaceUtilization",
            "period_seconds": 300,
        })

    assert "UNAVAILABLE: no datapoints for metric DiskSpaceUtilization" in res["error"]
    assert res["values"] == []
    assert res["value"] is None
    assert res["unit"] == "UNAVAILABLE"


def test_proxy_observe_backend_handles_empty_values_or_unavailable_unit():
    """In ProxyObserveBackend, if values is empty or unit is UNAVAILABLE, record an error and prevent EvidenceAdded."""
    from src.agent.proxy_observe_backend import ProxyObserveBackend
    import json

    mock_lambda = MagicMock()
    # Case 1: observer Lambda returned result with values=[] and unit="UNAVAILABLE" without explicit error field
    mock_lambda.invoke.return_value = {
        "Payload": MagicMock(read=lambda: json.dumps({
            "values": [],
            "value": None,
            "unit": "UNAVAILABLE",
            "trust": "out_of_band",
        }).encode())
    }

    backend = ProxyObserveBackend(observer_function_name="observer-func", lambda_client=mock_lambda)
    metric_res = backend.get_metric("i-test", "DiskUsed_percent")

    assert metric_res.error == "UNAVAILABLE: no datapoints"
    assert metric_res.unit == "UNAVAILABLE"

    # Verify ToolExecutor treats this as failure and does not record EvidenceAdded
    store, state = _create_test_state()
    executor = ToolExecutor(store, backend, state.instance_id)
    tc = ToolCall(tool_name="query_metrics", arguments={"metric_name": "DiskUsed_percent"})
    tool_res, state_after = executor.execute(tc, state)

    assert not tool_res.success
    assert "UNAVAILABLE" in tool_res.message
    assert len(state_after.evidence) == 0


# ===========================================================================
# 7. Disk alternative selection (df -i) test in Progress Guard during DiskUsage-High alarm
# ===========================================================================

def test_progress_guard_prevents_duplicate_identical_calls():
    """When repeating the exact same tool and arguments, Loop Guard rejects the duplicate without forcing a rigid fallback command."""
    from src.agent.loop import ReasoningLoop
    from src.agent import RecordedModel
    from src.agent.mock_backend import ObservationResult

    store, state = _create_test_state(alarm_name="DiskUsage-High")

    # Repeated model always returns same df -h call
    repeated_model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "df -h"}},
        {"tool_name": "observe", "arguments": {"command": "df -h"}},
    ])

    backend = MockObserveBackend(
        command_responses={
            "df -h": ObservationResult(True, "/dev/xvda1 95% /", "", 0),
        }
    )

    loop = ReasoningLoop(
        model=repeated_model,
        store=store,
        backend=backend,
        instance_id=state.instance_id,
    )
    result = loop.run(state, max_steps=2)

    assert len(result.tool_calls) == 2
    # First call executed successfully
    assert result.tool_calls[0].arguments["command"] == "df -h"
    assert result.tool_results[0].success

    # Second call matched identical arguments and was rejected to prevent loop without forcing rigid fallback
    assert result.tool_calls[1].arguments["command"] == "df -h"
    assert not result.tool_results[1].success
    assert "Duplicate call rejected" in result.tool_results[1].message


# ===========================================================================
# 8. Continued availability of observation and conclusion tools after multiple evidence
# ===========================================================================

def test_investigation_phase_allows_observation_and_conclude_after_multiple_evidences():
    """After collecting two evidences with no active hypotheses, observation tools and conclude remain available, excluding propose_step and verify."""
    store, state = _create_test_state(alarm_name="DiskUsage-High")
    backend = MockObserveBackend(command_responses={
        "df": ObservationResult(True, "Filesystem 95% /", "", 0),
        "du": ObservationResult(True, "100M /var/log", "", 0),
    })
    executor = ToolExecutor(store, backend, state.instance_id)

    # Evidence 1
    tc1 = ToolCall(tool_name="observe", arguments={"command": "df -h"})
    _, state = executor.execute(tc1, state)
    allowed_1 = get_allowed_tools(state)
    assert "observe" in allowed_1
    assert "update_hypotheses" in allowed_1
    assert "conclude" not in allowed_1

    # Evidence 2
    tc2 = ToolCall(tool_name="observe", arguments={"command": "df -i"})
    _, state = executor.execute(tc2, state)
    assert len(state.evidence) == 2
    assert len(state.hypotheses) == 0

    # After two evidences without active hypotheses: observation tools and update_hypotheses are available; conclude is unavailable due to lack of hypotheses
    allowed_2 = get_allowed_tools(state)
    assert "observe" in allowed_2
    assert "query_metrics" in allowed_2
    assert "query_logs" in allowed_2
    assert "conclude" not in allowed_2
    assert "update_hypotheses" in allowed_2
    assert "escalate" in allowed_2
    # Only steps requiring active hypotheses or prior steps are excluded
    assert "propose_step" not in allowed_2
    assert "verify" not in allowed_2

    # Executing additional observe is allowed and succeeds
    tc3 = ToolCall(tool_name="observe", arguments={"command": "du -sh /var/log"})
    res, state3 = executor.execute(tc3, state)
    assert res.success
    assert len(state3.evidence) == 3


# ===========================================================================
# 9. Tests for stdout inclusion in evidence summary and shell command restrictions
# ===========================================================================

def test_observe_includes_stdout_snippet_in_evidence_summary():
    """Verify EvidenceAdded.summary contains stdout snippet enabling the model to see numbers and paths."""
    store, state = _create_test_state()
    sample_stdout = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/xvda1       20G   19G  1.1G  95% /"
    backend = MockObserveBackend(command_responses={"df -h": ObservationResult(True, sample_stdout, "", 0)})
    executor = ToolExecutor(store, backend, state.instance_id)

    tc = ToolCall(tool_name="observe", arguments={"command": "df -h"})
    res, new_state = executor.execute(tc, state)

    assert res.success
    assert len(new_state.evidence) == 1
    ev = list(new_state.evidence.values())[0]
    assert "Observed: 'df -h' -> exit_code=0" in ev.summary
    assert "Output:" in ev.summary
    assert "95% /" in ev.summary


def test_progress_guard_rejects_unsupported_shell_operators_from_observe():
    """Verify rejection of observe commands containing unsupported shell operators instead of silently truncating them."""
    from src.agent.loop import ReasoningLoop
    from src.agent import RecordedModel

    store, state = _create_test_state(alarm_name="DiskUsage-High")

    # Model requesting command with pipe or redirect
    piped_model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "ps aux | grep python3"}},
        {"tool_name": "observe", "arguments": {"command": "du -sh /var/log 2>/dev/null"}},
        {"tool_name": "escalate", "arguments": {"reason": "end"}, "reasoning": "end"},
    ])

    backend = MockObserveBackend(
        command_responses={
            "ps aux": ObservationResult(True, "USER PID ... python3", "", 0),
            "du -h -d 1 /var/log": ObservationResult(True, "1.2G /var/log", "", 0),
            "du -sh /var/log": ObservationResult(True, "1.2G /var/log", "", 0),
        }
    )

    loop = ReasoningLoop(
        model=piped_model,
        store=store,
        backend=backend,
        instance_id=state.instance_id,
    )
    result = loop.run(state, max_steps=3)

    assert len(result.tool_calls) >= 2
    # First command (pipe): clearly rejected without truncation or execution
    assert result.tool_results[0].success is False
    assert "Command rejected: contains unsupported compound shell operators or pipeline" in result.tool_results[0].message
    assert "ps aux | grep python3" in result.tool_results[0].message

    # Second command (redirect): clearly rejected without truncation or execution
    assert result.tool_results[1].success is False
    assert "Command rejected: contains unsupported compound shell operators or pipeline" in result.tool_results[1].message
    assert "du -sh /var/log 2>/dev/null" in result.tool_results[1].message

    # Backend was not called for any silently mutated command
    assert "ps aux" not in backend.calls
    assert "du -sh /var/log" not in backend.calls


def test_loop_records_executed_calls_and_maintains_autonomous_tools():
    """ReasoningLoop records executed commands in ctx.incident_summary and tools remain available per State Invariants."""
    from src.agent.loop import ReasoningLoop
    from src.agent.tool_decider import ToolDecider
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _create_test_state(alarm_name="DiskUsage-High")
    backend = MockObserveBackend(command_responses={
        "df -h": ObservationResult(True, "Use% 95%", "", 0),
        "df -i": ObservationResult(True, "IUse% 20%", "", 0),
    })

    recorded_summaries = []
    class RecordingModel(ModelInterface):
        def __init__(self):
            self.calls = 0
        @property
        def name(self) -> str:
            return "recording"
        def invoke(self, ctx, tool_hint=None, **kwargs):
            recorded_summaries.append(ctx.incident_summary)
            self.calls += 1
            if self.calls == 1:
                return ModelResponse(tool_call=ToolCall(tool_name="observe", arguments={"command": "df -h"}))
            return ModelResponse(tool_call=ToolCall(tool_name="observe", arguments={"command": "df -i"}))

    class NoOpDecider(ToolDecider):
        def select(self, ctx):
            return None
        @property
        def name(self):
            return "noop"

    loop = ReasoningLoop(
        model=RecordingModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=NoOpDecider(),
    )
    res = loop.run(state, max_steps=2)

    assert len(res.tool_calls) == 2
    # In cycle 2, previous cycle command was recorded in incident_summary
    assert len(recorded_summaries) >= 2
    assert "executed_calls:" in recorded_summaries[1]
    assert "observe(df -h)" in recorded_summaries[1]


def test_loop_strands_override_reinvokes_model_with_tool_hint_when_arguments_invalid():
    """When Strands override occurs and arguments are empty or invalid for the tool, model is re-invoked with tool_hint."""
    from src.agent.loop import ReasoningLoop
    from src.agent.tool_decider import ToolDecider, ToolDecision
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _create_test_state(alarm_name="DiskUsage-High")
    backend = MockObserveBackend(command_responses={
        "df -h": ObservationResult(True, "Use% 95%", "", 0),
    })

    invocations = []
    class CustomModel(ModelInterface):
        @property
        def name(self) -> str:
            return "custom"
        def invoke(self, ctx, tool_hint=None, **kwargs):
            invocations.append(tool_hint)
            if len(invocations) == 1:
                # In first invocation, model chose another incompatible tool
                return ModelResponse(tool_call=ToolCall(tool_name="update_hypotheses", arguments={}))
            # In second invocation triggered by Strands override, model guided to produce valid arguments
            return ModelResponse(tool_call=ToolCall(tool_name="observe", arguments={"command": "df -h"}))

    class ForceObserveDecider(ToolDecider):
        def select(self, ctx):
            return ToolDecision(tool_name="observe", confidence=0.92)
        @property
        def name(self):
            return "force_observe"

    loop = ReasoningLoop(
        model=CustomModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=ForceObserveDecider(),
    )
    res = loop.run(state, max_steps=1)

    assert len(res.tool_calls) == 1
    # Forced observe tool with valid arguments df -h thanks to re-invocation with tool_hint
    assert res.tool_calls[0].tool_name == "observe"
    assert res.tool_calls[0].arguments == {"command": "df -h"}
    assert "Strands override" in res.tool_calls[0].reasoning
    assert invocations == ["observe", "observe"]


# ===========================================================================
# 10. Test un-truncated df -h output and StrandsDeciderClient single-tool behavior
# ===========================================================================

def test_full_df_h_output_reaches_deepseek_message_without_truncation():
    """Verify multiline df -h output including root partition reaches DeepSeek message without truncation."""
    from src.agent.deepseek_model import DeepSeekModel
    from src.agent.context_builder import build_context

    sample_stdout = (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "devtmpfs        4.0M     0  4.0M   0% /dev\n"
        "tmpfs           1.9G     0  1.9G   0% /dev/shm\n"
        "tmpfs           778M  548K  778M   1% /run\n"
        "tmpfs           4.0M     0  4.0M   0% /sys/fs/cgroup\n"
        "/dev/nvme0n1p128  10M  284K  9.8M   3% /sys/fi\n"
        "/dev/nvme0n1p1  8.0G  1.7G  6.3G  21% /"
    )

    store, state = _create_test_state(alarm_name="DiskUsage-High")
    backend = MockObserveBackend(command_responses={"df -h": ObservationResult(True, sample_stdout, "", 0)})
    executor = ToolExecutor(store, backend, state.instance_id)

    # Execute observe command
    tc = ToolCall(tool_name="observe", arguments={"command": "df -h"})
    res, state_after = executor.execute(tc, state)
    assert res.success

    # Build context
    ctx = build_context(state_after, cycle=0)
    assert len(ctx.evidence_summaries) == 1

    # Invoke DeepSeekModel and monitor user message payload
    model = DeepSeekModel(api_key="test-key")
    captured_payload = {}

    def fake_httpx_post(url, json=None, headers=None, timeout=None):
        nonlocal captured_payload
        captured_payload = json or {}
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"tool_name": "conclude", "arguments": {"root_cause": "disk ok"}}'}}]
        }
        return mock_resp

    with patch("httpx.post", side_effect=fake_httpx_post):
        model.invoke(ctx)

    user_message = captured_payload["messages"][1]["content"]

    # Verify that the 6th line and root line appear completely without truncation at 3% /sys/fi
    assert "/dev/nvme0n1p128  10M  284K  9.8M   3% /sys/fi" in user_message
    assert "/dev/nvme0n1p1  8.0G  1.7G  6.3G  21% /" in user_message
    assert "3% /sys/fi" in user_message
    assert "21% /" in user_message


def test_strands_decider_client_single_tool_and_evidence_trimming():
    """Verify StrandsDeciderClient returns deterministic decision without HTTP call when single tool available, and trims evidence summaries to last 2."""
    from src.agent.tool_decider import StrandsDeciderClient
    from src.agent.model_interface import ModelContext

    decider = StrandsDeciderClient(strands_url="http://fake-strands:8000")
    assert decider._timeout == 30.0

    # 1) Single tool available case: deterministic decision without HTTP call
    ctx_single = ModelContext(
        system_prompt="sys",
        incident_summary="inc",
        hypotheses_summary="hyp",
        evidence_summaries=["ev1", "ev2"],
        available_tools=["conclude"],
        budget_remaining={},
        cycle=1,
    )
    with patch.object(decider._httpx, "post") as mock_post:
        decision = decider.select(ctx_single)
        mock_post.assert_not_called()

    assert decision is not None
    assert decision.tool_name == "conclude"
    assert decision.confidence == 1.0

    # 2) Multiple tools case: sends HTTP request with last 2 evidences max 250 chars each
    ctx_multi = ModelContext(
        system_prompt="sys",
        incident_summary="inc",
        hypotheses_summary="hyp",
        evidence_summaries=[
            {"summary": "old evidence 1" * 50},
            {"summary": "A" * 500},
            {"summary": "B" * 500},
        ],
        available_tools=["observe", "conclude"],
        budget_remaining={},
        cycle=2,
    )

    with patch.object(decider._httpx, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"tool_name": "observe", "confidence": 0.85}
        mock_post.return_value = mock_resp

        decider.select(ctx_multi)
        mock_post.assert_called_once()
        sent_payload = mock_post.call_args[1]["json"]

    sent_evs = sent_payload["evidence_summaries"]
    assert len(sent_evs) == 2
    assert sent_evs[0] == "A" * 250
    assert sent_evs[1] == "B" * 250
    assert len(sent_evs[0]) == 250
    assert len(sent_evs[1]) == 250


# ===========================================================================
# 11. Tests for preventing consecutive hypothesis updates, statement reuse, and fallback
# ===========================================================================

def test_prevent_consecutive_update_hypotheses_in_loop():
    """Prevent selecting update_hypotheses in two consecutive cycles without executing another tool in between."""
    from src.agent.loop import ReasoningLoop
    from src.agent.tool_decider import ToolDecider
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _create_test_state(alarm_name="DiskUsage-High")
    backend = MockObserveBackend(command_responses={"df -h": ObservationResult(True, "Use% 95%", "", 0)})
    executor = ToolExecutor(store, backend, state.instance_id)

    # Initial evidence so that update_hypotheses becomes available
    tc0 = ToolCall(tool_name="observe", arguments={"command": "df -h"})
    _, state = executor.execute(tc0, state)

    available_tools_history = []

    class InspectingModel(ModelInterface):
        def __init__(self):
            self.calls = 0
        @property
        def name(self) -> str:
            return "inspecting"
        def invoke(self, ctx, tool_hint=None, **kwargs):
            available_tools_history.append(list(ctx.available_tools))
            self.calls += 1
            if self.calls == 1:
                # Cycle 1: update hypothesis
                return ModelResponse(tool_call=ToolCall(
                    tool_name="update_hypotheses",
                    arguments={"updates": [{"statement": "high disk", "confidence": 0.8, "evidence_id": list(state.evidence.keys())[0]}]}
                ))
            elif self.calls == 2:
                # Cycle 2: observe
                return ModelResponse(tool_call=ToolCall(
                    tool_name="observe",
                    arguments={"command": "df -h"}
                ))
            else:
                # Cycle 3: conclude
                return ModelResponse(tool_call=ToolCall(
                    tool_name="conclude",
                    arguments={"root_cause": "disk full", "confidence": 0.9}
                ))

    class NoOpDecider(ToolDecider):
        def select(self, ctx):
            return None
        @property
        def name(self):
            return "noop"

    loop = ReasoningLoop(
        model=InspectingModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=NoOpDecider(),
    )
    res = loop.run(state, max_steps=3)

    # Cycle 1: update_hypotheses was available and succeeded
    assert "update_hypotheses" in available_tools_history[0]
    # Cycle 2: update_hypotheses is blocked because it was the immediately preceding successful tool
    assert "update_hypotheses" not in available_tools_history[1]
    # Cycle 3: after executing another tool (observe), update_hypotheses becomes available again
    assert "update_hypotheses" in available_tools_history[2]


def test_update_hypotheses_reuses_existing_hypothesis_on_matching_statement():
    """If model does not pass hypothesis_id but an existing hypothesis matches statement after whitespace normalization, reuse it without creating a new ID."""
    store, state = _create_test_state()
    backend = MockObserveBackend(command_responses={"df -h": ObservationResult(True, "Use% 95%", "", 0)})
    executor = ToolExecutor(store, backend, state.instance_id)

    # Collect initial evidence
    tc0 = ToolCall(tool_name="observe", arguments={"command": "df -h"})
    _, state = executor.execute(tc0, state)
    ev_id = list(state.evidence.keys())[0]

    # Create first hypothesis with specific statement
    hyp_tc1 = ToolCall(tool_name="update_hypotheses", arguments={
        "updates": [{
            "hypothesis_id": "hyp-orig-123",
            "statement": "Disk partition /var full",
            "confidence": 0.6,
            "status": "active",
            "evidence_id": ev_id,
        }]
    })
    res1, state1 = executor.execute(hyp_tc1, state)
    assert res1.success
    assert "hyp-orig-123" in state1.hypotheses
    assert len(state1.hypotheses) == 1

    # Call update_hypotheses without hypothesis_id with same text plus extra spaces, and refuted status
    hyp_tc2 = ToolCall(tool_name="update_hypotheses", arguments={
        "updates": [{
            "statement": "  Disk   partition /var   full  ",
            "confidence": 0.1,
            "status": "refuted",
            "evidence_id": ev_id,
        }]
    })
    res2, state2 = executor.execute(hyp_tc2, state1)
    assert res2.success
    # Did not create new hypothesis with random ID; updated hyp-orig-123
    assert len(state2.hypotheses) == 1
    assert "hyp-orig-123" in state2.hypotheses
    updated_hyp = state2.hypotheses["hyp-orig-123"]
    assert updated_hyp.status.value == "refuted"
    assert updated_hyp.confidence == 0.1
    assert ev_id in updated_hyp.contradicting


def test_deepseek_model_transient_error_fallback_to_flash():
    """When timeout or transient network error occurs on non-deepseek-flash model, fallback to deepseek-flash."""
    from src.agent.deepseek_model import DeepSeekModel
    from src.agent.model_interface import ModelContext
    import httpx

    ctx = ModelContext(
        system_prompt="sys",
        incident_summary="inc",
        hypotheses_summary="hyp",
        evidence_summaries=[],
        available_tools=["observe"],
        budget_remaining={},
        cycle=0,
    )

    # Primary model is deepseek-chat (not deepseek-flash)
    model = DeepSeekModel(api_key="test-key", model="deepseek-chat")
    assert model._timeout_seconds == 60.0

    call_records = []
    def fake_httpx_post(url, json=None, headers=None, timeout=None):
        call_records.append(dict(json or {}))
        if len(call_records) == 1:
            # First call throws ReadTimeout
            raise httpx.ReadTimeout("Request timed out")
        else:
            # Second call (fallback to deepseek-flash) succeeds
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": '{"tool_name": "observe", "arguments": {"command": "uptime"}}'}}]
            }
            return mock_resp

    with patch("httpx.post", side_effect=fake_httpx_post):
        res = model.invoke(ctx, tool_hint="observe")

    assert len(call_records) == 2
    # First call was for the original model
    assert call_records[0]["model"] == "deepseek-chat"
    # Second call transitioned to deepseek-flash
    assert call_records[1]["model"] == "deepseek-flash"
    assert res.tool_call.tool_name == "observe"


def test_deepseek_model_auth_error_does_not_fallback():
    """Authentication errors (401/403) are not masked by fallback; they are raised directly."""
    from src.agent.deepseek_model import DeepSeekModel
    from src.agent.model_interface import ModelContext
    import httpx

    ctx = ModelContext(
        system_prompt="sys",
        incident_summary="inc",
        hypotheses_summary="hyp",
        evidence_summaries=[],
        available_tools=["observe"],
        budget_remaining={},
        cycle=0,
    )

    model = DeepSeekModel(api_key="bad-key", model="deepseek-chat")

    def fake_httpx_post(url, json=None, headers=None, timeout=None):
        mock_req = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        raise httpx.HTTPStatusError("Unauthorized", request=mock_req, response=mock_resp)

    with patch("httpx.post", side_effect=fake_httpx_post):
        with pytest.raises(httpx.HTTPStatusError):
            model.invoke(ctx)


def test_do_observe_includes_stderr_and_exit_code_on_failure():
    """
    Verify:
    1. stderr and exit_code appear in EvidenceRef.summary and ToolResult.message when command fails in _do_observe.
    2. blocked_reason and success=False appear when blocked by policy.
    """
    store, state = _create_test_state()
    # Case 1: Command fails with non-zero exit code and stderr
    backend = MockObserveBackend(
        command_responses={
            "ls /nonexistent": ObservationResult(
                success=False,
                stdout="",
                stderr="ls: cannot access '/nonexistent': No such file or directory",
                exit_code=2,
            )
        }
    )
    executor = ToolExecutor(store, backend, state.instance_id)
    tc = ToolCall(tool_name="observe", arguments={"command": "ls /nonexistent"})
    res, updated_state = executor.execute(tc, state)

    assert not res.success
    assert "exit_code=2" in res.message
    assert "Stderr:\nls: cannot access '/nonexistent': No such file or directory" in res.message

    # Inspect saved evidence summary
    assert len(updated_state.evidence) == 1
    ev = list(updated_state.evidence.values())[0]
    assert "exit_code=2" in ev.summary
    assert "Stderr:\nls: cannot access '/nonexistent': No such file or directory" in ev.summary

    # Case 2: Command blocked by security policy via blocked_reason
    backend_blocked = MockObserveBackend(
        command_responses={
            "nc -l 8080": ObservationResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=0,
                blocked_reason="Command blocked by security policy: forbidden binary 'nc'",
            )
        }
    )
    executor_blocked = ToolExecutor(store, backend_blocked, updated_state.instance_id)
    tc_blocked = ToolCall(tool_name="observe", arguments={"command": "nc -l 8080"})
    res_b, updated_state2 = executor_blocked.execute(tc_blocked, updated_state)

    assert not res_b.success
    assert "Blocked/Error: Command blocked by security policy: forbidden binary 'nc'" in res_b.message
    ev_b = list(updated_state2.evidence.values())[-1]
    assert "Blocked/Error: Command blocked by security policy: forbidden binary 'nc'" in ev_b.summary


def test_reasoning_loop_passes_previous_tool_failures_into_incident_summary():
    """
    Verify passing tool failure details (including stderr, exit_code, blocked_reason, or UNAVAILABLE)
    into the model context (ModelContext.incident_summary) in the next cycle within ReasoningLoop
    under the previous_tool_failures section.
    """
    from src.agent.loop import ReasoningLoop
    from src.agent.tool_decider import ToolDecider
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _create_test_state()
    backend = MockObserveBackend(
        command_responses={
            "bad_cmd": ObservationResult(
                success=False,
                stdout="",
                stderr="bad_cmd: command not found",
                exit_code=127,
            ),
            "good_cmd": ObservationResult(
                success=True,
                stdout="ok output",
                stderr="",
                exit_code=0,
            ),
        }
    )

    captured_summaries = []

    class MockSequenceModel(ModelInterface):
        def __init__(self):
            self.cycle_count = 0

        @property
        def name(self) -> str:
            return "seq-model"

        def invoke(self, ctx, tool_hint=None, **kwargs):
            captured_summaries.append(ctx.incident_summary)
            self.cycle_count += 1
            if self.cycle_count == 1:
                return ModelResponse(tool_call=ToolCall(
                    tool_name="observe",
                    arguments={"command": "bad_cmd"},
                    reasoning="testing failed command",
                ))
            else:
                return ModelResponse(tool_call=ToolCall(
                    tool_name="observe",
                    arguments={"command": "good_cmd"},
                    reasoning="correcting command",
                ))

    class PassThroughDecider(ToolDecider):
        def select(self, ctx):
            return None
        @property
        def name(self):
            return "passthrough"

    loop = ReasoningLoop(
        model=MockSequenceModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=PassThroughDecider(),
    )
    res = loop.run(state, max_steps=2)

    # Cycle 1: No previous failure existed
    assert "previous_tool_failures" not in captured_summaries[0]

    # Cycle 2: Received previous failure summary from cycle 1
    assert len(captured_summaries) >= 2
    summary_cycle1 = captured_summaries[1]
    assert "previous_tool_failures:" in summary_cycle1
    assert "bad_cmd" in summary_cycle1
    assert "exit_code=127" in summary_cycle1
    assert "bad_cmd: command not found" in summary_cycle1


def test_reasoning_loop_passes_metric_unavailable_and_blocked_failures():
    """Verify passing query_metrics errors (UNAVAILABLE) and security blocks in previous_tool_failures."""
    from src.agent.loop import ReasoningLoop
    from src.agent.tool_decider import ToolDecider
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _create_test_state()
    backend = MockObserveBackend(
        metric_responses={
            "NetworkIn": MetricResult(
                metric_name="NetworkIn",
                value=0.0,
                unit="UNAVAILABLE",
                period_seconds=300,
                trust="synthetic",
                error="UNAVAILABLE: no datapoints for metric NetworkIn",
            )
        }
    )

    captured_summaries = []

    class MockMetricModel(ModelInterface):
        def __init__(self):
            self.cycle_count = 0

        @property
        def name(self) -> str:
            return "seq-metric-model"

        def invoke(self, ctx, tool_hint=None, **kwargs):
            captured_summaries.append(ctx.incident_summary)
            self.cycle_count += 1
            if self.cycle_count == 1:
                return ModelResponse(tool_call=ToolCall(
                    tool_name="query_metrics",
                    arguments={"metric_name": "NetworkIn"},
                ))
            else:
                return ModelResponse(tool_call=ToolCall(
                    tool_name="escalate",
                    arguments={"reason": "metric unavailable"},
                ))

    class PassThroughDecider(ToolDecider):
        def select(self, ctx):
            return None
        @property
        def name(self):
            return "passthrough"

    loop = ReasoningLoop(
        model=MockMetricModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=PassThroughDecider(),
    )
    loop.run(state, max_steps=2)

    assert len(captured_summaries) >= 2
    summary_cycle1 = captured_summaries[1]
    assert "previous_tool_failures:" in summary_cycle1
    assert "query_metrics" in summary_cycle1
    assert "UNAVAILABLE: no datapoints for metric NetworkIn" in summary_cycle1


def test_strands_safety_net_respects_valid_model_choice_and_overrides_invalid():
    """
    Verify:
    1. Respect generative model choice when choosing a valid tool in ctx.available_tools without Strands override.
    2. Trigger Strands override only when model selects a disallowed tool outside ctx.available_tools or fails (model error).
    """
    from src.agent.loop import ReasoningLoop
    from src.agent.tool_decider import ToolDecider, ToolDecision
    from src.agent.model_interface import ModelInterface, ModelResponse

    store, state = _create_test_state()
    backend = MockObserveBackend(
        command_responses={
            "df -h": ObservationResult(True, "Filesystem 90%", "", 0),
        }
    )

    class FixedDecider(ToolDecider):
        def __init__(self, tool_name: str, confidence: float = 0.85):
            self._tool = tool_name
            self._confidence = confidence
        def select(self, ctx):
            return ToolDecision(tool_name=self._tool, confidence=self._confidence)
        @property
        def name(self):
            return "fixed"

    # Case 1: Model selects observe (valid tool in available_tools) while Strands suggests query_metrics
    class ValidChoiceModel(ModelInterface):
        @property
        def name(self) -> str:
            return "valid-model"
        def invoke(self, ctx, tool_hint=None, **kwargs):
            return ModelResponse(tool_call=ToolCall(
                tool_name="observe",
                arguments={"command": "df -h"},
                reasoning="model chosen valid tool",
            ))

    loop1 = ReasoningLoop(
        model=ValidChoiceModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=FixedDecider("query_metrics", confidence=0.90),
    )
    res1 = loop1.run(state, max_steps=1)
    assert len(res1.tool_calls) == 1
    # Model's choice of observe was respected and not overridden to query_metrics
    assert res1.tool_calls[0].tool_name == "observe"
    assert res1.tool_calls[0].arguments == {"command": "df -h"}

    # Case 2: Model selects conclude (disallowed due to lack of evidence/hypotheses) while Strands suggests observe
    class InvalidChoiceModel(ModelInterface):
        def __init__(self):
            self.invocations = 0
        @property
        def name(self) -> str:
            return "invalid-model"
        def invoke(self, ctx, tool_hint=None, **kwargs):
            self.invocations += 1
            if self.invocations == 1:
                return ModelResponse(tool_call=ToolCall(
                    tool_name="conclude",
                    arguments={"root_cause": "unfounded conclusion"},
                    reasoning="premature conclude",
                ))
            return ModelResponse(tool_call=ToolCall(
                tool_name="observe",
                arguments={"command": "df -h"},
                reasoning="corrected to observe",
            ))

    loop2 = ReasoningLoop(
        model=InvalidChoiceModel(),
        store=store,
        backend=backend,
        instance_id=state.instance_id,
        tool_decider=FixedDecider("observe", confidence=0.88),
    )
    res2 = loop2.run(state, max_steps=1)
    assert len(res2.tool_calls) == 1
    # Strands override safety net was triggered because conclude is not authorized at this phase
    assert res2.tool_calls[0].tool_name == "observe"
    assert "Strands override" in res2.tool_calls[0].reasoning


def test_update_hypotheses_deduplicates_even_with_non_existent_id():
    """If model passes a hypothesis_id non-existent in state but matching statement of existing hypothesis, update existing without duplicating."""
    store, state = _create_test_state()
    backend = MockObserveBackend(command_responses={"df -h": ObservationResult(True, "95%", "", 0)})
    executor = ToolExecutor(store, backend, state.instance_id)

    # Collect evidence
    tc0 = ToolCall(tool_name="observe", arguments={"command": "df -h"})
    _, state = executor.execute(tc0, state)
    ev_id = list(state.evidence.keys())[0]

    # Create first hypothesis
    hyp1 = ToolCall(tool_name="update_hypotheses", arguments={
        "updates": [{
            "hypothesis_id": "hyp-base-1",
            "statement": "Application memory leak",
            "confidence": 0.5,
            "evidence_id": ev_id,
        }]
    })
    _, state = executor.execute(hyp1, state)
    assert len(state.hypotheses) == 1
    assert "hyp-base-1" in state.hypotheses

    # Pass random non-existent ID but with identical statement after strip()
    hyp2 = ToolCall(tool_name="update_hypotheses", arguments={
        "updates": [{
            "hypothesis_id": "unknown-non-existent-id",
            "statement": "  Application memory leak  ",
            "confidence": 0.85,
            "evidence_id": ev_id,
        }]
    })
    _, state2 = executor.execute(hyp2, state)
    # Did not create second hypothesis; updated hyp-base-1
    assert len(state2.hypotheses) == 1
    assert "hyp-base-1" in state2.hypotheses
    assert state2.hypotheses["hyp-base-1"].confidence == 0.85


def test_deepseek_model_system_prompt_environment_capabilities_and_grammar():
    """
    Verify:
    1. _SYSTEM_PROMPT contains execution environment syntax restrictions (*, ?, |, ;, &&, ||, >, <).
    2. _SYSTEM_PROMPT contains allowed observation binaries (df, du, ls, ps, stat, etc.).
    3. _SYSTEM_PROMPT contains principle of enumeration before specification and evidence-based conclusion.
    4. _SYSTEM_PROMPT is completely free of hardcoded fault family names (FAULT_FAMILY_NAMES).
    """
    from src.agent.deepseek_model import _SYSTEM_PROMPT
    from tests.test_no_runbooks import FAULT_FAMILY_NAMES

    prompt = _SYSTEM_PROMPT.lower()

    # Check syntax rules
    assert "exec" in prompt
    assert "*" in _SYSTEM_PROMPT
    assert "|" in _SYSTEM_PROMPT
    assert ";" in _SYSTEM_PROMPT

    # Check observation binaries
    for binary in ["df", "du", "ls", "stat", "cat", "ps", "top", "free", "uptime", "systemctl status", "journalctl", "find"]:
        assert binary in _SYSTEM_PROMPT

    # Check general principles
    assert "Enumerate Before Targeting" in _SYSTEM_PROMPT
    assert "refuted" in _SYSTEM_PROMPT
    assert "conclude" in _SYSTEM_PROMPT
    assert "propose_step" in _SYSTEM_PROMPT

    # Strict check that no fault family names exist
    for name in FAULT_FAMILY_NAMES:
        assert name not in prompt


def test_ssm_lab_and_docker_lab_accept_direct_enumeration_and_reject_operators():
    """
    Verify:
    1. SSMLab and DockerLab accept direct read-only enumeration commands (ls, du, df, find, ps, etc.).
    2. Both strictly reject any command containing forbidden operators or characters (*, |, ;, etc.).
    """
    from src.executor.ssm_lab import SSMLab
    from src.executor.docker_lab import SubprocessBackend, DockerBackend

    # 1. Test SSMLab
    mock_ssm = MagicMock()
    mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-test-123"}}
    mock_ssm.get_command_invocation.return_value = {
        "Status": "Success",
        "StandardOutputContent": "total 4\n-rw-r--r-- 1 root root 100 app.log",
        "StandardErrorContent": "",
        "ResponseCode": 0,
    }
    ssm = SSMLab(instance_id="i-test001", ssm_client=mock_ssm)

    # Direct read enumeration commands accepted
    res_ls = ssm.run("ls -la /var/log")
    assert res_ls.success
    assert res_ls.blocked_reason is None

    res_du = ssm.run("du -sh /var/log")
    assert res_du.success

    res_find = ssm.run("find /var/log -maxdepth 1")
    assert res_find.success

    # Commands rejected due to containing forbidden operators/characters
    res_wildcard = ssm.run("ls -la /var/log/*.log")
    assert not res_wildcard.success
    assert "Forbidden operator or wildcard" in (res_wildcard.blocked_reason or "")

    res_pipe = ssm.run("df -h | grep /dev")
    assert not res_pipe.success
    assert "Forbidden operator or wildcard" in (res_pipe.blocked_reason or "")

    res_semi = ssm.run("uptime; ls")
    assert not res_semi.success
    assert "Forbidden operator or wildcard" in (res_semi.blocked_reason or "")

    # 2. Test DockerLab (SubprocessBackend & DockerBackend)
    sub = SubprocessBackend(tier="T0")
    # Valid direct read command
    res_sub_ok = sub.run("ls -d /var/log")
    assert res_sub_ok.success
    assert res_sub_ok.blocked_reason is None

    # Commands with forbidden characters rejected
    res_sub_star = sub.run("ls /var/log/*")
    assert not res_sub_star.success
    assert res_sub_star.blocked_reason is not None

    res_sub_pipe = sub.run("df -h | cat")
    assert not res_sub_pipe.success
    assert res_sub_pipe.blocked_reason is not None

    res_sub_semi = sub.run("ls; date")
    assert not res_sub_semi.success
    assert res_sub_semi.blocked_reason is not None

    # DockerBackend check rules
    doc = DockerBackend(tier="T0")
    assert doc._allowed("ls -la /var/log") is None
    assert doc._allowed("find /var/log -maxdepth 1") is None
    assert doc._allowed("du -sh /var/log") is None
    assert doc._allowed("ls /var/log/*.log") is not None
    assert doc._allowed("df -h | grep root") is not None
    assert doc._allowed("uptime; ls") is not None


# ===========================================================================
# 20. Tests for excluding observe on budget exhaustion and tool_hint flexibility
# ===========================================================================

def test_get_allowed_tools_disallows_observe_when_observation_budget_exhausted():
    """
    a) Exclude observe from get_allowed_tools(state) when observation budget reaches maximum,
    while conclude, escalate, and update_hypotheses remain available when evidence exists.
    """
    from types import SimpleNamespace
    from src.agent.context_builder import get_allowed_tools
    from src.domain.types import (
        IncidentState, BudgetState, IncidentPhase, EvidenceRef, HypothesisRecord,
    )

    evidence_dict = {
        "ev-1": EvidenceRef(
            evidence_id="ev-1",
            source="observe",
            trust="observer_verified",
            collected_at="2026-01-01T00:00:00Z",
            raw_ref=None,
            integrity_hash="h1",
            summary="test evidence",
            redaction_report={},
        )
    }
    hyp_dict = {
        "h-1": HypothesisRecord(
            hypothesis_id="h-1",
            statement="service port unresponsive",
            confidence=0.8,
            supporting=["ev-1"],
            contradicting=[],
            status="active",
            next_check=None,
            trigger_evidence_id="ev-1",
        )
    }

    # 1. Budget not exhausted case (commands = 5 < 30)
    budgets = BudgetState(commands=5.0, max_commands=30.0)
    state = IncidentState(
        incident_id="inc-1",
        instance_id="i-test",
        dedupe_key="dedupe-1",
        phase=IncidentPhase.investigating,
        security_latch=False,
        budgets=budgets,
        hypotheses=hyp_dict,
        evidence=evidence_dict,
        steps={},
        policy_decisions={},
        approvals={},
        pending_approval_step=None,
        pending_observation=None,
        pending_intent=None,
        last_verification=None,
        last_seq=1,
        last_hash="h1",
        authorization_violations=[],
    )

    tools_before = get_allowed_tools(state)
    assert "observe" in tools_before
    assert "conclude" in tools_before
    assert "escalate" in tools_before
    assert "update_hypotheses" in tools_before

    # 2. Observation budget exhausted (commands = max_commands)
    state.budgets.commands = 30.0
    assert state.budget_used.observations >= state.budget.max_observations

    tools_after = get_allowed_tools(state)
    assert "observe" not in tools_after
    assert "conclude" in tools_after
    assert "escalate" in tools_after
    assert "update_hypotheses" in tools_after
    assert "propose_step" in tools_after

    # 3. Verify also via object having budget_used.observations and budget.max_observations
    mock_state = SimpleNamespace(
        evidence={"ev-1": True},
        hypotheses={"h-1": SimpleNamespace(status="refuted")},
        steps={},
        budget_used=SimpleNamespace(observations=10.0),
        budget=SimpleNamespace(max_observations=10.0),
    )
    tools_mock = get_allowed_tools(mock_state)
    assert "observe" not in tools_mock
    assert "conclude" in tools_mock
    assert "escalate" in tools_mock
    assert "update_hypotheses" in tools_mock


def test_deepseek_model_advisory_tool_hint_and_system_prompt_principles():
    """
    b) Verify:
    1. Formatting tool_hint as non-binding advisory hint in _build_user_message
       when multiple tools are available in available_tools, clarifying selection rules.
    2. Formatting tool_hint as specific directive when only a single tool is available.
    3. _SYSTEM_PROMPT includes core principles (maximizing info gain, sufficiency, safe resolution).
    """
    from src.agent.deepseek_model import DeepSeekModel, _SYSTEM_PROMPT
    from src.agent.model_interface import ModelContext

    # 1. _SYSTEM_PROMPT includes core principles
    assert "Maximize Information Gain" in _SYSTEM_PROMPT
    assert "Epistemic Sufficiency" in _SYSTEM_PROMPT
    assert "Safe Resolution" in _SYSTEM_PROMPT
    assert "Root Cause Resolution" in _SYSTEM_PROMPT
    assert "Escalate on Insufficient Evidence" in _SYSTEM_PROMPT

    # 2. Context with multiple tools: tool_hint is advisory
    ctx_multi = ModelContext(
        system_prompt="sys",
        incident_summary="summary",
        hypotheses_summary="hyp",
        evidence_summaries=[{"evidence_id": "ev-1", "source": "observe", "summary": "clean system metrics"}],
        available_tools=["observe", "conclude", "update_hypotheses", "escalate"],
        budget_remaining={"commands": 10.0},
        cycle=2,
    )
    msg_multi = DeepSeekModel._build_user_message(ctx_multi, tool_hint="observe")
    assert "Advisory Tool Hint" in msg_multi
    assert "non-binding" in msg_multi
    assert "conclude" in msg_multi
    assert "update_hypotheses" in msg_multi
    assert "propose_step" in msg_multi
    assert "escalate" in msg_multi

    # 3. Context with single tool: tool_hint is directive
    ctx_single = ModelContext(
        system_prompt="sys",
        incident_summary="summary",
        hypotheses_summary="hyp",
        evidence_summaries=[],
        available_tools=["escalate"],
        budget_remaining={"commands": 0.0},
        cycle=5,
    )
    msg_single = DeepSeekModel._build_user_message(ctx_single, tool_hint="escalate")
    assert "Required tool: 'escalate'" in msg_single
    assert "non-binding" not in msg_single


def test_propose_step_defensive_normalization_and_policy_gate():
    """
    a) Verify _do_propose_step accepts inputs emitted by model in live evaluation:
       kind='modify' (normalized to StepKind.mutate)
       declared_effects=[{'category': 'E1', 'resource': ...}]
       and records step and PolicyGate decision successfully in state.steps and state.policy_decisions.
    """
    from src.agent.tool_executor import ToolExecutor
    from src.store.memory import MemoryEventStore
    from src.agent.mock_backend import MockObserveBackend
    from src.domain.types import (
        IncidentHeader, IncidentOpenedPayload, build_event, EventType, Actor, new_ulid,
        StepKind, EffectCategory, HypothesisRecord, HypothesisUpdatedPayload, PolicyDecisionPayload,
        PolicyDecisionValue
    )
    from src.domain.reducer import fold
    from src.policy.gate import PolicyGate, GateContext

    store = MemoryEventStore()
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid,
        instance_id="i-testpropose",
        dedupe_key=f"alarm::{iid}",
        alarm_name="test-alarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
        alert_source="rule/test",
        opened_at="2026-01-01T00:00:00Z",
    )
    store.create_if_absent(header.dedupe_key, header)
    ev_open = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=header.instance_id,
            dedupe_key=header.dedupe_key,
            alarm_name=header.alarm_name,
            alarm_arn=header.alarm_arn,
            alert_source=header.alert_source,
        ),
    )
    store.append(iid, 0, ev_open)
    state = fold(store.read(iid))

    backend = MockObserveBackend()
    executor = ToolExecutor(store, backend, state.instance_id)

    # 1. Add evidence proving existence of file /var/log/app_bloat.log
    from src.domain.types import EvidenceRef, EvidenceAddedPayload, TrustLevel, utc_now
    ev_ref = EvidenceRef(
        evidence_id="ev-1",
        source="observe:du -ah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref="blob:test",
        integrity_hash="hash1",
        summary="Observed: 'du -ah /var/log' -> exit_code=0\nOutput:\n1.5G /var/log/app_bloat.log",
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    # Add active hypothesis
    hyp = HypothesisRecord(
        hypothesis_id="hyp-1",
        statement="log bloat consuming resources",
        confidence=0.85,
        supporting=["ev-1"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-1",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # Actual model inputs from live test
    args = {
        "kind": "modify",  # synonym for mutate
        "execution_spec": {"command": "truncate -s 0 /var/log/app_bloat.log"},
        "declared_effects": [{"category": "E1", "resource": "/var/log/app_bloat.log", "description": "truncate file"}],
        "rollback_plan": "none",
        "risk_claim": "low",
    }

    result = executor._do_propose_step(args, state)
    assert result.success, f"Expected propose_step to succeed, got error: {result.message}"
    step_id = result.data["step_id"]

    # Check step recording in state.steps and immediate PolicyGate evaluation in state.policy_decisions
    state = fold(store.read(iid))
    assert step_id in state.steps
    step = state.steps[step_id]
    assert step.kind == StepKind.mutate  # Normalized from 'modify'
    assert len(step.declared_effects) == 1
    assert step.declared_effects[0].category == EffectCategory.E1
    assert step.declared_effects[0].resource == "/var/log/app_bloat.log"

    assert step_id in state.policy_decisions
    assert state.policy_decisions[step_id].plan_hash == step.plan_hash


def test_target_precision_enforcement_and_loop_stop_on_proposal():
    """
    Strict security tests enforcing target precision and remediation guardrails:
    a) Deterministic refusal by _do_propose_step for any command targeting general directory or find -exec.
    b) Accepting command only if targeting specific individual file present in evidence (e.g., /var/log/app_bloat.log).
    c) ReasoningLoop stops immediately upon step proposal (Stop on Proposal).
    """
    from src.agent.tool_executor import ToolExecutor
    from src.store.memory import MemoryEventStore
    from src.agent.mock_backend import MockObserveBackend
    from src.domain.types import (
        IncidentHeader, IncidentOpenedPayload, build_event, EventType, Actor, new_ulid,
        StepKind, EffectCategory, HypothesisRecord, HypothesisUpdatedPayload,
        EvidenceRef, EvidenceAddedPayload, TrustLevel, utc_now
    )
    from src.domain.reducer import fold
    from src.agent.loop import ReasoningLoop, LoopTermination
    from src.agent import RecordedModel

    store = MemoryEventStore()
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid,
        instance_id="i-testsec01",
        dedupe_key=f"alarm::{iid}",
        alarm_name="test-alarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
        alert_source="rule/test",
        opened_at="2026-01-01T00:00:00Z",
    )
    store.create_if_absent(header.dedupe_key, header)
    ev_open = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=header.instance_id,
            dedupe_key=header.dedupe_key,
            alarm_name=header.alarm_name,
            alarm_arn=header.alarm_arn,
            alert_source=header.alert_source,
        ),
    )
    store.append(iid, 0, ev_open)
    state = fold(store.read(iid))

    backend = MockObserveBackend()
    executor = ToolExecutor(store, backend, state.instance_id)

    # 1. Add evidence proving a specific file (/var/log/app_bloat.log)
    ev_ref = EvidenceRef(
        evidence_id="ev-disk-1",
        source="observe:du -ah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref="blob:test",
        integrity_hash="hash1",
        summary="Observed: 'du -ah /var/log' -> exit_code=0\nOutput:\n1.5G /var/log/app_bloat.log",
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    # Add active hypothesis
    hyp = HypothesisRecord(
        hypothesis_id="hyp-1",
        statement="log bloat causing disk pressure",
        confidence=0.85,
        supporting=["ev-disk-1"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-disk-1",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # a) Test deterministic refusal of general directory commands, find -exec, xargs, and rm -rf
    rejected_commands = [
        "find /var/log -type f -name '*.log' -exec truncate -s 0 {} \\;",
        "find /var/log -type f -delete",
        "cat /dev/null | xargs truncate",
        "rm -rf /var/log",
        "truncate -s 0 /var/log",
        "truncate -s 0 /var",
        "truncate -s 0 /etc",
        "truncate -s 0 /",
        "truncate -s 0 /var/log/unproven_random_file.log",  # File not present in evidence
    ]

    for bad_cmd in rejected_commands:
        res = executor._do_propose_step(
            {
                "kind": "mutate",
                "execution_spec": {"command": bad_cmd},
                "declared_effects": [{"category": "E1", "resource": "/var/log", "description": "bad action"}],
            },
            state,
        )
        assert not res.success, f"Command should have been rejected: {bad_cmd}"
        assert "Security Policy Refusal" in res.message, f"Unexpected message: {res.message}"

    # b) Test acceptance only if targeting a specific individual file present in evidence
    good_args = {
        "kind": "mutate",
        "execution_spec": {"command": "truncate -s 0 /var/log/app_bloat.log"},
        "declared_effects": [{"category": "E1", "resource": "/var/log/app_bloat.log", "description": "truncate file"}],
    }
    good_res = executor._do_propose_step(good_args, state)
    assert good_res.success, f"Valid step should be accepted: {good_res.message}"
    assert "PolicyGate" in good_res.message

    state = fold(store.read(iid))
    step_id = good_res.data["step_id"]
    assert step_id in state.steps
    assert step_id in state.policy_decisions

    # c) Test ReasoningLoop termination immediately upon step proposal (Stop on Proposal)
    # Create new state with evidence and hypothesis, then run loop that proposes step
    model = RecordedModel([
        {
            "tool_name": "propose_step",
            "arguments": good_args,
            "reasoning": "apply proven remediation step",
        },
        {
            "tool_name": "observe",
            "arguments": {"command": "df -h"},
            "reasoning": "should never be reached",
        },
    ])
    # Rebuild state before step to test loop
    store_loop = MemoryEventStore()
    iid_loop = new_ulid()
    header_loop = IncidentHeader(
        incident_id=iid_loop,
        instance_id="i-testsec02",
        dedupe_key=f"alarm::{iid_loop}",
        alarm_name="test-alarm-loop",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test2",
        alert_source="rule/test",
        opened_at="2026-01-01T00:00:00Z",
    )
    store_loop.create_if_absent(header_loop.dedupe_key, header_loop)
    ev_open_loop = build_event(
        incident_id=iid_loop,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=header_loop.instance_id,
            dedupe_key=header_loop.dedupe_key,
            alarm_name=header_loop.alarm_name,
            alarm_arn=header_loop.alarm_arn,
            alert_source=header_loop.alert_source,
        ),
    )
    store_loop.append(iid_loop, 0, ev_open_loop)
    state_loop = fold(store_loop.read(iid_loop))
    exec_loop = ToolExecutor(store_loop, backend, state_loop.instance_id)
    exec_loop._write_event(state_loop, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))
    exec_loop._write_event(state_loop, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state_loop = fold(store_loop.read(iid_loop))

    loop = ReasoningLoop(model=model, store=store_loop, backend=backend, instance_id=state_loop.instance_id, max_cycles=10)
    loop_result = loop.run(state_loop)
    assert loop_result.termination == LoopTermination.PROPOSED
    assert len(loop_result.tool_calls) == 1
    assert loop_result.tool_calls[0].tool_name == "propose_step"


def test_target_precision_split_output_ls_grounding():
    """
    Test target precision when file paths appear split across commands like ls -lah:
    - Parent path /var/log appears in command line.
    - Filename app_bloat.log appears in stdout without direct string connection to /var/log/app_bloat.log.
    - Verify acceptance of truncate -s 0 /var/log/app_bloat.log.
    - Verify rejection of truncate -s 0 /var/log/unseen_file.log.
    - Verify rejection of find /var/log -type f -exec truncate -s 0 {} +.
    """
    from src.agent.tool_executor import ToolExecutor
    from src.store.memory import MemoryEventStore
    from src.agent.mock_backend import MockObserveBackend
    from src.domain.types import (
        IncidentHeader, IncidentOpenedPayload, build_event, EventType, Actor, new_ulid,
        StepKind, EffectCategory, HypothesisRecord, HypothesisUpdatedPayload,
        EvidenceRef, EvidenceAddedPayload, TrustLevel, utc_now
    )
    from src.domain.reducer import fold

    store = MemoryEventStore()
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid,
        instance_id="i-testsplit01",
        dedupe_key=f"alarm::{iid}",
        alarm_name="test-alarm-split",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:testsplit",
        alert_source="rule/test",
        opened_at="2026-01-01T00:00:00Z",
    )
    store.create_if_absent(header.dedupe_key, header)
    ev_open = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=header.instance_id,
            dedupe_key=header.dedupe_key,
            alarm_name=header.alarm_name,
            alarm_arn=header.alarm_arn,
            alert_source=header.alert_source,
        ),
    )
    store.append(iid, 0, ev_open)
    state = fold(store.read(iid))

    backend = MockObserveBackend()
    executor = ToolExecutor(store, backend, state.instance_id)

    # Simulate evidence from real ls -lah /var/log:
    # Full string /var/log/app_bloat.log is disconnected in text!
    ls_summary = (
        "Observed: 'ls -lah /var/log' -> exit_code=0\n"
        "Output:\n"
        "total 5.5G\n"
        "drwxr-xr-x. 10 root root 4.0K Oct 16 11:00 .\n"
        "drwxr-xr-x. 14 root root 4.0K Oct 16 10:00 ..\n"
        "-rw-r--r--.  1 root root 5.4G Oct 16 11:20 app_bloat.log\n"
        "-rw-r--r--.  1 root root  12K Oct 16 11:05 syslog"
    )
    ev_ref = EvidenceRef(
        evidence_id="ev-ls-1",
        source="observe:ls -lah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref="blob:test_split",
        integrity_hash="hash_split",
        summary=ls_summary,
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    # Add active hypothesis
    hyp = HypothesisRecord(
        hypothesis_id="hyp-split-1",
        statement="log bloat in /var/log causing disk exhaustion",
        confidence=0.85,
        supporting=["ev-ls-1"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-ls-1",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # 1. Accept truncate -s 0 /var/log/app_bloat.log because basename (app_bloat.log) and dirname (/var/log) are both in evidence
    good_args = {
        "kind": "mutate",
        "execution_spec": {"command": "truncate -s 0 /var/log/app_bloat.log"},
        "declared_effects": [{"category": "E1", "resource": "/var/log/app_bloat.log", "description": "truncate bloat log"}],
    }
    good_res = executor._do_propose_step(good_args, state)
    assert good_res.success, f"Expected propose_step to succeed, got: {good_res.message}"
    assert "PolicyGate" in good_res.message

    state_after = fold(store.read(iid))
    step_id = good_res.data["step_id"]
    assert step_id in state_after.steps

    # 2. Reject truncate -s 0 /var/log/unseen_file.log because unseen_file.log was not in evidence
    unseen_args = {
        "kind": "mutate",
        "execution_spec": {"command": "truncate -s 0 /var/log/unseen_file.log"},
        "declared_effects": [{"category": "E1", "resource": "/var/log/unseen_file.log", "description": "truncate unseen file"}],
    }
    unseen_res = executor._do_propose_step(unseen_args, state)
    assert not unseen_res.success
    assert "Security Policy Refusal" in unseen_res.message

    # 3. Reject find /var/log -type f -exec truncate -s 0 {} +
    bulk_args = {
        "kind": "mutate",
        "execution_spec": {"command": "find /var/log -type f -exec truncate -s 0 {} +"},
        "declared_effects": [{"category": "E1", "resource": "/var/log", "description": "bulk truncate"}],
    }
    bulk_res = executor._do_propose_step(bulk_args, state)
    assert not bulk_res.success
    assert "Security Policy Refusal" in bulk_res.message


def test_conclude_requires_hypotheses_and_transitions_phase():
    """
    b) Verify:
    1. conclude is disallowed before recording a hypothesis in state.hypotheses (even with evidence).
    2. conclude is allowed after recording a refuted or active hypothesis.
    3. state.phase transitions after folding ConclusionProposed to terminal phase (resolved/concluded).
    4. confidence is capped at <= 0.85 in _do_conclude if only based on host_reported evidence lacking out_of_band.
    """
    from src.agent.context_builder import get_allowed_tools
    from src.agent.tool_executor import ToolExecutor
    from src.store.memory import MemoryEventStore
    from src.agent.mock_backend import MockObserveBackend
    from src.domain.types import (
        IncidentHeader, IncidentOpenedPayload, build_event, EventType, Actor, new_ulid,
        EvidenceRef, HypothesisRecord, IncidentPhase, HypothesisUpdatedPayload, EvidenceAddedPayload
    )
    from src.domain.reducer import fold

    store = MemoryEventStore()
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid,
        instance_id="i-testconclude",
        dedupe_key=f"alarm::{iid}",
        alarm_name="test-alarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
        alert_source="rule/test",
        opened_at="2026-01-01T00:00:00Z",
    )
    store.create_if_absent(header.dedupe_key, header)
    ev_open = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=header.instance_id,
            dedupe_key=header.dedupe_key,
            alarm_name=header.alarm_name,
            alarm_arn=header.alarm_arn,
            alert_source=header.alert_source,
        ),
    )
    store.append(iid, 0, ev_open)
    state = fold(store.read(iid))

    backend = MockObserveBackend()
    executor = ToolExecutor(store, backend, state.instance_id)

    # 1. Add host_reported evidence without adding any hypothesis
    ev_host = EvidenceRef(
        evidence_id="ev-host-1",
        source="observe",
        trust="host_reported",
        collected_at="2026-01-01T00:00:00Z",
        raw_ref=None,
        integrity_hash="h1",
        summary="normal resources observed",
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_host))
    state = fold(store.read(iid))
    assert len(state.evidence) == 1
    assert len(state.hypotheses) == 0

    # conclude is still disallowed due to lack of hypotheses
    tools = get_allowed_tools(state)
    assert "conclude" not in tools
    assert "update_hypotheses" in tools

    # 2. Add refuted hypothesis confirming system health
    hyp = HypothesisRecord(
        hypothesis_id="hyp-refuted",
        statement="resource exhaustion alarm false",
        confidence=0.9,
        supporting=[],
        contradicting=["ev-host-1"],
        status="refuted",
        next_check=None,
        trigger_evidence_id="ev-host-1",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))
    assert len(state.hypotheses) == 1

    # Now conclude becomes available!
    tools_after_hyp = get_allowed_tools(state)
    assert "conclude" in tools_after_hyp

    # 3. Call _do_conclude with high confidence (0.95) based solely on host_reported
    res_conclude = executor._do_conclude({
        "root_cause": "System verified healthy, alarm refuted",
        "confidence": 0.95,
        "supporting_evidence": ["ev-host-1"],
    }, state)
    assert res_conclude.success
    # Cap confidence at <= 0.85 due to absence of out_of_band metrics
    assert res_conclude.data["confidence"] <= 0.85

    # 4. Verify state.phase transitions via fold to concluded
    state_final = fold(store.read(iid))
    assert state_final.phase == IncidentPhase.concluded


def test_dynamic_complexity_and_epistemic_budgeting():
    """
    Test dynamic complexity evaluation and budget/cycle adaptation (Dynamic Complexity & Epistemic Budgeting):
    1. Verify sending complexity="low" reduces max_commands to 8 and max_cycles to <= 12.
    2. Verify ReasoningLoop adapts cycle cap, terminating/escalating early for simple issues.
    3. Verify sending complexity="high" expands budget flexibly (max_commands=18).
    """
    from src.agent.tool_executor import ToolExecutor
    from src.store.memory import MemoryEventStore
    from src.agent.mock_backend import MockObserveBackend
    from src.domain.types import (
        IncidentHeader, IncidentOpenedPayload, build_event, EventType, Actor, new_ulid,
        EvidenceRef, TrustLevel, utc_now
    )
    from src.domain.reducer import fold
    from src.agent.loop import ReasoningLoop, LoopTermination
    from src.agent import RecordedModel

    store = MemoryEventStore()
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid,
        instance_id="i-testdynbudget",
        dedupe_key=f"alarm::{iid}",
        alarm_name="test-dyn-alarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:testdyn",
        alert_source="rule/test",
        opened_at="2026-01-01T00:00:00Z",
    )
    store.create_if_absent(header.dedupe_key, header)
    ev_open = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=header.instance_id,
            dedupe_key=header.dedupe_key,
            alarm_name=header.alarm_name,
            alarm_arn=header.alarm_arn,
            alert_source=header.alert_source,
        ),
    )
    store.append(iid, 0, ev_open)
    state = fold(store.read(iid))
    assert state.budgets.max_commands >= 20.0  # Initial default value

    backend = MockObserveBackend()
    executor = ToolExecutor(store, backend, state.instance_id)

    # 1. Add initial evidence
    res_ev = executor._do_observe({"command": "df -h"}, state)
    state = fold(store.read(iid))

    # 2. Send update_hypotheses with complexity="low"
    res_hyp = executor._do_update_hypotheses({
        "updates": [{
            "statement": "single resource pressure",
            "confidence": 0.8,
            "evidence_id": list(state.evidence.keys())[0],
            "status": "active",
        }],
        "complexity": "low",
    }, state)
    assert res_hyp.success
    assert res_hyp.data.get("complexity") == "low"

    state = fold(store.read(iid))
    # Verify smart adjustment of budget and cycle ceiling for low complexity
    assert state.budgets.max_commands == 8.0
    assert state.budgets.max_cycles <= 12.0
    hyp_rec = list(state.hypotheses.values())[0]
    assert hyp_rec.complexity == "low"

    # 3. Verify ReasoningLoop adapts cycle ceiling and terminates at reduced effective limit
    model = RecordedModel([
        {"tool_name": "observe", "arguments": {"command": "df -h"}, "reasoning": "checking"},
    ] * 20)
    loop = ReasoningLoop(model=model, store=store, backend=backend, instance_id=state.instance_id, max_cycles=40)
    assert loop._compute_effective_limit(state) <= 12

    loop_res = loop.run(state)
    assert loop_res.termination == LoopTermination.MAX_CYCLES
    assert loop_res.cycles_completed <= 12  # Terminated at reduced limit without running 40 cycles!

    # 4. Verify sending complexity="high" expands budget
    res_hyp_high = executor._do_update_hypotheses({
        "updates": [{
            "hypothesis_id": hyp_rec.hypothesis_id,
            "statement": "complex cascade failure across subsystems",
            "confidence": 0.5,
            "evidence_id": list(state.evidence.keys())[0],
            "status": "active",
        }],
        "complexity": "high",
    }, state)
    assert res_hyp_high.success

    state_high = fold(store.read(iid))
    assert state_high.budgets.max_commands == 18.0
    assert state_high.budgets.max_cycles <= 25.0
    assert loop._compute_effective_limit(state_high) == 25


def test_policy_gate_i05_allows_app_log_and_denies_audit_logs():
    """
    PolicyGate and Rule I-05 integration test:
    a) Command 'truncate -s 0 /var/log/app_bloat.log' passes through _do_propose_step and PolicyGate without I-05 rejection (decision != PolicyDecisionValue.deny).
    b) Commands 'truncate -s 0 /var/log/audit/audit.log', 'truncate -s 0 /var/log/secure', and 'truncate -s 0 /var/log/wtmp'
       are strictly denied by I-05 (decision == PolicyDecisionValue.deny).
    """
    from src.agent.tool_executor import ToolExecutor
    from src.store.memory import MemoryEventStore
    from src.agent.mock_backend import MockObserveBackend
    from src.domain.types import (
        IncidentHeader, IncidentOpenedPayload, build_event, EventType, Actor, new_ulid,
        EvidenceRef, TrustLevel, utc_now, HypothesisRecord, HypothesisUpdatedPayload,
        EvidenceAddedPayload, PolicyDecisionValue
    )
    from src.domain.reducer import fold

    store = MemoryEventStore()
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid,
        instance_id="i-testi05gate",
        dedupe_key=f"alarm::{iid}",
        alarm_name="test-i05-alarm",
        alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:testi05",
        alert_source="rule/test",
        opened_at=utc_now().isoformat(),
    )
    store.create_if_absent(header.dedupe_key, header)
    ev_open = build_event(
        incident_id=iid,
        type=EventType.IncidentOpened,
        actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=header.instance_id,
            dedupe_key=header.dedupe_key,
            alarm_name=header.alarm_name,
            alarm_arn=header.alarm_arn,
            alert_source=header.alert_source,
        ),
    )
    store.append(iid, 0, ev_open)
    state = fold(store.read(iid))

    backend = MockObserveBackend()
    executor = ToolExecutor(store, backend, state.instance_id)

    ls_summary = (
        "drwxr-xr-x. 10 root root 4.0K Oct 16 11:00 .\n"
        "-rw-r--r--.  1 root root 5.4G Oct 16 11:20 app_bloat.log\n"
        "-rw-r-----.  1 root root 1.2M Oct 16 11:20 secure\n"
        "-rw-rw-r--.  1 root utmp 2.5M Oct 16 11:20 wtmp\n"
        "-rw-r-----.  1 root root 8.0M Oct 16 11:20 audit.log\n"
        "/var/log/audit/audit.log"
    )
    ev_ref = EvidenceRef(
        evidence_id="ev-ls-audit",
        source="observe:ls -lah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_i05",
        summary=ls_summary,
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    hyp = HypothesisRecord(
        hypothesis_id="hyp-i05-1",
        statement="log file growth in /var/log",
        confidence=0.85,
        supporting=["ev-ls-audit"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-ls-audit",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # a) Verify app log truncate passes through PolicyGate without I-05 rejection
    app_args = {
        "kind": "mutate",
        "execution_spec": {"command": "truncate -s 0 /var/log/app_bloat.log"},
        "declared_effects": [{"category": "E1", "resource": "/var/log/app_bloat.log", "description": "truncate bloat log"}],
    }
    res_app = executor._do_propose_step(app_args, state)
    assert res_app.success
    state = fold(store.read(iid))
    step_id_app = res_app.data["step_id"]
    dec_app = state.policy_decisions[step_id_app]
    assert dec_app.decision != PolicyDecisionValue.deny
    assert dec_app.decision == PolicyDecisionValue.allow
    assert "I-05" not in dec_app.rule_ids

    # b) Verify sensitive audit and security logs truncate are strictly denied by I-05
    for cmd, resource in [
        ("truncate -s 0 /var/log/audit/audit.log", "/var/log/audit/audit.log"),
        ("truncate -s 0 /var/log/secure", "/var/log/secure"),
        ("truncate -s 0 /var/log/wtmp", "/var/log/wtmp"),
    ]:
        args = {
            "kind": "mutate",
            "execution_spec": {"command": cmd},
            "declared_effects": [{"category": "E1", "resource": resource, "description": "truncate sensitive log"}],
        }
        res = executor._do_propose_step(args, state)
        assert res.success
        state = fold(store.read(iid))
        step_id = res.data["step_id"]
        dec = state.policy_decisions[step_id]
        assert dec.decision == PolicyDecisionValue.deny, f"Expected {cmd} to be denied by PolicyGate"
        assert "I-05" in dec.rule_ids, f"Expected I-05 in rule_ids for {cmd}, got: {dec.rule_ids}"


def test_step_approval_granted_and_ssm_execution():
    """
    Test post-approval remediation lifecycle:
    1. Propose step truncate -s 0 /var/log/app_bloat.log with effect E2.
    2. PolicyGate evaluates require_approval (Tier.T2) and transitions incident to awaiting_approval.
    3. Record ApprovalGranted event with valid auth_tag.
    4. Call ExecutorLoop with SSMLab.
    5. Verify:
       - Command executed safely via SSM repair document (incidents-repair-restricted).
       - Both truncate and sudo truncate supported.
       - Record ExecutionIntent then ExecutionResult.
       - VerificationRecorded recorded successfully and step status transitions to 'executed' / 'succeeded'.
    """
    import dataclasses
    from datetime import datetime, timezone, timedelta
    from src.policy.auth import compute_auth_tag, TEST_AUTH_KEY
    from src.policy.gate import PolicyDecisionValue, Tier
    from src.domain.types import (
        ApprovalGrantedPayload, EvidenceAddedPayload, HypothesisUpdatedPayload,
        VerificationVerdict,
    )
    from src.executor.executor import ExecutorLoop, ExecutorTermination
    from src.executor.ssm_lab import SSMLab
    from src.executor.verifier import Verifier
    from src.executor.reconciler import Reconciler

    store, state = _create_test_state(instance_id="i-test001")
    iid = state.incident_id
    executor = ToolExecutor(backend=MockObserveBackend(), store=store, instance_id="i-test001")

    # Add evidence proving existence of file
    ls_summary = (
        "-rw-r--r--. 1 root root 5.4G Oct 16 11:20 app_bloat.log\n"
        "/var/log/app_bloat.log"
    )
    ev_ref = EvidenceRef(
        evidence_id="ev-ls-bloat",
        source="observe:ls -lah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_bloat_test",
        summary=ls_summary,
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    hyp = HypothesisRecord(
        hypothesis_id="hyp-bloat-1",
        statement="log bloat in /var/log/app_bloat.log",
        confidence=0.9,
        supporting=["ev-ls-bloat"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-ls-bloat",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # 1. Propose truncate step (with sudo to safely empty root-owned file) with high risk requiring approval
    cmd = "sudo truncate -s 0 /var/log/app_bloat.log"
    step_args = {
        "kind": "mutate",
        "risk_claim": "high",
        "execution_spec": {"command": cmd},
        "declared_effects": [{"category": "E2", "resource": "/var/log/app_bloat.log", "description": "truncate bloat log"}],
    }
    res_prop = executor._do_propose_step(step_args, state)
    assert res_prop.success, f"Propose step failed: {res_prop.error}"

    state = fold(store.read(iid))
    step_id = res_prop.data["step_id"]
    step = state.steps[step_id]
    dec = state.policy_decisions[step_id]

    # Ensure incident reaches awaiting_approval with require_approval decision (T2)
    assert dec.decision == PolicyDecisionValue.require_approval
    assert dec.tier == Tier.T2
    assert state.phase == IncidentPhase.awaiting_approval
    assert step.status == "proposed"

    # 2. Grant approval (ApprovalGranted) with valid auth_tag
    plan_hash = dec.plan_hash
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    approval_payload = ApprovalGrantedPayload(
        approval_id=new_ulid(),
        step_id=step_id,
        plan_hash=plan_hash,
        approver_id="security_lead",
        issued_at=utc_now().isoformat(),
        expires_at=expires_at,
        nonce=new_ulid(),
    )
    payload_dict = dataclasses.asdict(approval_payload)
    payload_dict.pop("auth_tag", None)
    auth_tag = compute_auth_tag(
        incident_id=iid,
        event_type="ApprovalGranted",
        payload_dict=payload_dict,
        key=TEST_AUTH_KEY,
    )
    approval_payload = dataclasses.replace(approval_payload, auth_tag=auth_tag)

    ev_app = build_event(
        incident_id=iid,
        type=EventType.ApprovalGranted,
        actor=Actor.slack_callback,
        payload=approval_payload,
        auth_tag=auth_tag,
    )
    store.append(iid, state.last_seq, ev_app)
    state = fold(store.read(iid))

    assert approval_payload.approval_id in state.approvals
    assert state.pending_approval_step is None

    # 3. Setup SSMLab with Mock SSM Client
    mock_ssm = MagicMock()
    mock_ssm.send_command.return_value = {
        "Command": {"CommandId": "cmd-test-truncate-001"}
    }
    mock_ssm.get_command_invocation.return_value = {
        "Status": "Success",
        "StandardOutputContent": "",
        "StandardErrorContent": "",
        "ResponseCode": 0,
    }

    lab = SSMLab(
        instance_id="i-test001",
        region="us-east-1",
        ssm_client=mock_ssm,
    )

    executor_loop = ExecutorLoop(
        store=store,
        lab=lab,
        verifier=Verifier(lab),
        reconciler=Reconciler(lab),
        instance_id="i-test001",
        allowed_instance_id="i-test001",
        max_verify_attempts=1,
    )

    # 4. Execute step via ExecutorLoop
    exec_result = executor_loop.execute_step(step=step, state=state)
    assert exec_result.termination == ExecutorTermination.COMPLETED
    assert exec_result.gate_decision == PolicyDecisionValue.allow

    # 5. Verify state and recorded events
    state_final = fold(store.read(iid))
    events = store.read(iid)
    event_types = [e.type for e in events]

    assert EventType.ExecutionIntent in event_types
    assert EventType.ExecutionResult in event_types
    assert EventType.VerificationRecorded in event_types

    # Verify step status transitioned to successfully executed
    step_final = state_final.steps[step_id]
    assert step_final.status in ("executed", "succeeded")
    assert state_final.last_verification is not None
    assert state_final.last_verification.verdict == VerificationVerdict.verified
    assert state_final.phase == IncidentPhase.resolved
    assert EventType.IncidentResolved in event_types

    # Verify SSM received repair command in incidents-repair-restricted document
    assert mock_ssm.send_command.call_count >= 2
    repair_call = None
    for call in mock_ssm.send_command.call_args_list:
        kwargs = call[1]
        if kwargs.get("DocumentName") == "incidents-repair-restricted":
            repair_call = kwargs
            break

    assert repair_call is not None, "Repair command not sent with incidents-repair-restricted document"
    assert repair_call["Parameters"]["command"] == [cmd]

    # 6. Direct verification that SSMLab safely accepts both truncate and sudo truncate
    res_direct_sudo = lab.run("sudo truncate -s 0 /var/log/app_bloat.log", tier="T1")
    assert res_direct_sudo.success
    assert res_direct_sudo.blocked_reason is None

    res_direct_no_sudo = lab.run("truncate -s 0 /var/log/app_bloat.log", tier="T1")
    assert res_direct_no_sudo.success
    assert res_direct_no_sudo.blocked_reason is None


def test_low_risk_surgical_truncate_is_auto_allowed_t1_without_human_approval():
    """
    Verify safe low-risk surgical step (truncate -s 0 on permitted application log):
    1. Directly classified as Tier.T1 with PolicyDecisionValue.allow.
    2. Does not halt at awaiting_approval phase (autonomous self-execution).
    3. Can be executed directly via ExecutorLoop without human ApprovalGranted.
    """
    from src.policy.gate import PolicyDecisionValue, Tier
    from src.executor.executor import ExecutorLoop, ExecutorTermination
    from src.executor.ssm_lab import SSMLab
    from src.executor.verifier import Verifier
    from src.executor.reconciler import Reconciler

    store, state = _create_test_state(instance_id="i-test001")
    iid = state.incident_id
    executor = ToolExecutor(backend=MockObserveBackend(), store=store, instance_id="i-test001")

    # Add evidence proving presence of bloated file
    ls_summary = (
        "-rw-r--r--. 1 root root 5.4G Oct 16 11:20 app_bloat.log\n"
        "/var/log/app_bloat.log"
    )
    ev_ref = EvidenceRef(
        evidence_id="ev-ls-bloat-auto",
        source="observe:ls -lah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_bloat_auto",
        summary=ls_summary,
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    hyp = HypothesisRecord(
        hypothesis_id="hyp-bloat-auto",
        statement="bloat in /var/log/app_bloat.log",
        confidence=0.9,
        supporting=["ev-ls-bloat-auto"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-ls-bloat-auto",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # Propose low-risk surgical step to truncate log file
    cmd = "truncate -s 0 /var/log/app_bloat.log"
    step_args = {
        "kind": "mutate",
        "risk_claim": "low",
        "execution_spec": {"command": cmd},
        "declared_effects": [{"category": "E3", "resource": "/var/log/app_bloat.log", "description": "truncate bloat log"}],
    }
    res_prop = executor._do_propose_step(step_args, state)
    assert res_prop.success, f"Propose step failed: {res_prop.error}"

    state = fold(store.read(iid))
    step_id = res_prop.data["step_id"]
    step = state.steps[step_id]
    dec = state.policy_decisions[step_id]

    # Ensure automatic self-classification as T1 and allow without halting at awaiting_approval
    assert dec.decision == PolicyDecisionValue.allow
    assert dec.tier == Tier.T1
    assert state.phase != IncidentPhase.awaiting_approval
    assert state.phase == IncidentPhase.investigating

    # Verify ExecutorLoop executes step without human intervention
    mock_ssm = MagicMock()
    mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-auto-truncate-001"}}
    mock_ssm.get_command_invocation.return_value = {
        "Status": "Success",
        "StandardOutputContent": "",
        "StandardErrorContent": "",
        "ResponseCode": 0,
    }
    lab = SSMLab(instance_id="i-test001", region="us-east-1", ssm_client=mock_ssm)
    executor_loop = ExecutorLoop(
        store=store,
        lab=lab,
        verifier=Verifier(lab),
        reconciler=Reconciler(lab),
        instance_id="i-test001",
        allowed_instance_id="i-test001",
        max_verify_attempts=1,
    )
    exec_result = executor_loop.execute_step(step=step, state=state)
    assert exec_result.termination == ExecutorTermination.COMPLETED
    assert exec_result.gate_decision == PolicyDecisionValue.allow
    assert mock_ssm.send_command.call_count >= 1


def test_high_risk_t2_step_requires_approval_and_blocks_on_rejection():
    """
    Verify strict safety gating when high risk claimed (Tier.T2):
    1. High-risk step (risk_claim="high") classified as Tier.T2 and requires human approval.
    2. Calling ExecutorLoop without valid approval prevents sending any command to SSMLab (0 commands).
    3. Recording ApprovalRejected transitions incident phase to escalated and marks step as 'rejected'.
    4. Calling ExecutorLoop after rejection completely refuses execution and sends 0 commands to SSMLab.
    """
    from src.policy.gate import PolicyDecisionValue, Tier
    from src.domain.types import ApprovalRejectedPayload
    from src.executor.executor import ExecutorLoop, ExecutorTermination
    from src.executor.ssm_lab import SSMLab
    from src.executor.verifier import Verifier
    from src.executor.reconciler import Reconciler

    store, state = _create_test_state(instance_id="i-test001")
    iid = state.incident_id
    executor = ToolExecutor(backend=MockObserveBackend(), store=store, instance_id="i-test001")

    # Add evidence proving presence of bloated file
    ls_summary = (
        "-rw-r--r--. 1 root root 5.4G Oct 16 11:20 app_bloat.log\n"
        "/var/log/app_bloat.log"
    )
    ev_ref = EvidenceRef(
        evidence_id="ev-restart-app",
        source="observe:ls -lah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_restart_app",
        summary=ls_summary,
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    hyp = HypothesisRecord(
        hypothesis_id="hyp-restart-app",
        statement="bloat in /var/log/app_bloat.log",
        confidence=0.8,
        supporting=["ev-restart-app"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-restart-app",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # Propose high-risk step (requiring human approval Tier.T2)
    cmd = "truncate -s 0 /var/log/app_bloat.log"
    step_args = {
        "kind": "mutate",
        "risk_claim": "high",
        "execution_spec": {"command": cmd},
        "declared_effects": [{"category": "E3", "resource": "/var/log/app_bloat.log", "description": "high-risk truncate"}],
    }
    res_prop = executor._do_propose_step(step_args, state)
    assert res_prop.success, f"Propose step failed: {res_prop.message}"

    state = fold(store.read(iid))
    step_id = res_prop.data["step_id"]
    step = state.steps[step_id]
    dec = state.policy_decisions[step_id]

    # 1. Verify T2 classification and approval requirement
    assert dec.decision == PolicyDecisionValue.require_approval
    assert dec.tier == Tier.T2
    assert state.phase == IncidentPhase.awaiting_approval
    assert step.status == "proposed"

    mock_ssm = MagicMock()
    lab = SSMLab(instance_id="i-test001", region="us-east-1", ssm_client=mock_ssm)
    executor_loop = ExecutorLoop(
        store=store,
        lab=lab,
        verifier=Verifier(lab),
        reconciler=Reconciler(lab),
        instance_id="i-test001",
        allowed_instance_id="i-test001",
        max_verify_attempts=1,
    )

    # 2. Invoke ExecutorLoop without valid approval
    res_no_approval = executor_loop.execute_step(step=step, state=state)
    assert res_no_approval.termination == ExecutorTermination.DENIED
    assert res_no_approval.gate_decision == PolicyDecisionValue.require_approval
    # Confirm no command was sent to SSMLab (0 commands)
    assert mock_ssm.send_command.call_count == 0

    # 3. Record explicit human approval rejection (ApprovalRejected)
    rejection_payload = ApprovalRejectedPayload(
        approval_id=new_ulid(),
        step_id=step_id,
        approver_id="ops_lead",
        reason="Operation deemed too risky during peak traffic hours",
    )
    executor._write_event(
        state,
        EventType.ApprovalRejected,
        rejection_payload,
        actor=Actor.slack_callback,
    )

    state_after_reject = fold(store.read(iid))
    # Verify phase transitions to escalated and step marked as 'rejected'
    assert state_after_reject.phase == IncidentPhase.escalated
    assert state_after_reject.steps[step_id].status == "rejected"

    # 4. Attempt calling ExecutorLoop after rejection
    res_after_reject = executor_loop.execute_step(step=state_after_reject.steps[step_id], state=state_after_reject)
    assert res_after_reject.termination == ExecutorTermination.DENIED
    assert res_after_reject.gate_decision == PolicyDecisionValue.deny
    # Still 0 commands sent
    assert mock_ssm.send_command.call_count == 0


def test_failed_execution_or_verification_never_marks_incident_resolved():
    """
    Engineering safety test (State Honesty):
    Part (A): Simulate repair command failure in SSMLab (exit_code=1) and verify:
      - step.status == 'failed'
      - state.phase != IncidentPhase.resolved (transitions to escalated)
      - Absence of any IncidentResolved event in event log.
    Part (B): Simulate command success (exit_code=0) but Verifier failure (VerificationVerdict.failed) and verify:
      - step.status == 'failed'
      - Incident does not transition to IncidentPhase.resolved (transitions to escalated)
      - No IncidentResolved event is emitted.
    """
    from src.policy.gate import PolicyDecisionValue, Tier
    from src.domain.types import (
        VerificationVerdict, VerificationCheck, StabilityWindow,
    )
    from src.executor.executor import ExecutorLoop, ExecutorTermination
    from src.executor.ssm_lab import SSMLab
    from src.executor.verifier import Verifier, VerificationResult
    from src.executor.reconciler import Reconciler

    # ══════════════════════════════════════════════════════════════════════════
    # Part (A): Server-level repair command failure (exit_code=1)
    # ══════════════════════════════════════════════════════════════════════════
    store_a, state_a = _create_test_state(instance_id="i-test001")
    iid_a = state_a.incident_id
    executor_a = ToolExecutor(backend=MockObserveBackend(), store=store_a, instance_id="i-test001")

    # Add evidence proving presence of bloated file
    ls_summary = (
        "-rw-r--r--. 1 root root 5.4G Oct 16 11:20 app_bloat.log\n"
        "/var/log/app_bloat.log"
    )
    ev_ref = EvidenceRef(
        evidence_id="ev-fail-exec",
        source="observe:ls -lah /var/log",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_fail_exec",
        summary=ls_summary,
        redaction_report={},
    )
    executor_a._write_event(state_a, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    hyp = HypothesisRecord(
        hypothesis_id="hyp-fail-exec",
        statement="bloat in /var/log/app_bloat.log",
        confidence=0.9,
        supporting=["ev-fail-exec"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-fail-exec",
    )
    executor_a._write_event(state_a, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state_a = fold(store_a.read(iid_a))

    # Propose T1 surgical step
    cmd = "truncate -s 0 /var/log/app_bloat.log"
    step_args = {
        "kind": "mutate",
        "risk_claim": "low",
        "execution_spec": {"command": cmd},
        "declared_effects": [{"category": "E3", "resource": "/var/log/app_bloat.log", "description": "truncate bloat log"}],
    }
    res_prop = executor_a._do_propose_step(step_args, state_a)
    assert res_prop.success

    state_a = fold(store_a.read(iid_a))
    step_id_a = res_prop.data["step_id"]
    step_a = state_a.steps[step_id_a]

    # Simulate command failure in SSMLab with exit code 1
    mock_ssm_fail = MagicMock()
    mock_ssm_fail.send_command.return_value = {"Command": {"CommandId": "cmd-fail-101"}}
    mock_ssm_fail.get_command_invocation.return_value = {
        "Status": "Failed",
        "StandardOutputContent": "",
        "StandardErrorContent": "truncate: cannot open '/var/log/app_bloat.log': Permission denied",
        "ResponseCode": 1,
    }
    lab_fail = SSMLab(instance_id="i-test001", region="us-east-1", ssm_client=mock_ssm_fail)
    executor_loop_a = ExecutorLoop(
        store=store_a,
        lab=lab_fail,
        verifier=Verifier(lab_fail),
        reconciler=Reconciler(lab_fail),
        instance_id="i-test001",
        allowed_instance_id="i-test001",
        max_verify_attempts=1,
    )

    exec_result_a = executor_loop_a.execute_step(step=step_a, state=state_a)
    state_after_exec_fail = fold(store_a.read(iid_a))
    events_a = store_a.read(iid_a)
    event_types_a = [e.type for e in events_a]

    # Verify step status transitioned to failed
    assert state_after_exec_fail.steps[step_id_a].status == "failed"
    # Verify incident did not transition to resolved
    assert state_after_exec_fail.phase != IncidentPhase.resolved
    assert state_after_exec_fail.phase == IncidentPhase.escalated
    # Ensure no IncidentResolved event was recorded
    assert EventType.IncidentResolved not in event_types_a
    assert EventType.ExecutionResult in event_types_a
    # Verify execution result
    assert exec_result_a.termination in (ExecutorTermination.FAILED, ExecutorTermination.ROLLBACK)

    # ══════════════════════════════════════════════════════════════════════════
    # Part (B): Successful repair command but Verifier check failure
    # ══════════════════════════════════════════════════════════════════════════
    store_b, state_b = _create_test_state(instance_id="i-test001")
    iid_b = state_b.incident_id
    executor_b = ToolExecutor(backend=MockObserveBackend(), store=store_b, instance_id="i-test001")

    executor_b._write_event(state_b, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))
    executor_b._write_event(state_b, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state_b = fold(store_b.read(iid_b))

    res_prop_b = executor_b._do_propose_step(step_args, state_b)
    assert res_prop_b.success

    state_b = fold(store_b.read(iid_b))
    step_id_b = res_prop_b.data["step_id"]
    step_b = state_b.steps[step_id_b]

    # Simulate command success in SSMLab
    mock_ssm_ok = MagicMock()
    mock_ssm_ok.send_command.return_value = {"Command": {"CommandId": "cmd-ok-202"}}
    mock_ssm_ok.get_command_invocation.return_value = {
        "Status": "Success",
        "StandardOutputContent": "",
        "StandardErrorContent": "",
        "ResponseCode": 0,
    }
    lab_ok = SSMLab(instance_id="i-test001", region="us-east-1", ssm_client=mock_ssm_ok)

    # Simulate verifier failing verification (criteria check failure)
    mock_verifier = MagicMock()
    fail_verification_res = VerificationResult(
        verdict=VerificationVerdict.failed,
        checks=[VerificationCheck(check_type="metric", result="fail", source="verifier", details="Disk usage still 99%")],
        alarm_state="alarm",
        stability_window=StabilityWindow(duration_seconds=30, result="unstable"),
        side_effect_checks=[],
        details="Verification failed: file still bloated",
    )
    mock_verifier.verify.return_value = fail_verification_res
    real_verifier = Verifier(lab_ok)
    mock_verifier.write_verification_event.side_effect = real_verifier.write_verification_event

    executor_loop_b = ExecutorLoop(
        store=store_b,
        lab=lab_ok,
        verifier=mock_verifier,
        reconciler=Reconciler(lab_ok),
        instance_id="i-test001",
        allowed_instance_id="i-test001",
        max_verify_attempts=1,
    )

    exec_result_b = executor_loop_b.execute_step(step=step_b, state=state_b)
    state_after_verify_fail = fold(store_b.read(iid_b))
    events_b = store_b.read(iid_b)
    event_types_b = [e.type for e in events_b]

    # Verify step status transitioned to failed
    assert state_after_verify_fail.steps[step_id_b].status == "failed"
    # Verify incident did not transition to resolved
    assert state_after_verify_fail.phase != IncidentPhase.resolved
    assert state_after_verify_fail.phase == IncidentPhase.escalated
    # Ensure no IncidentResolved event was emitted
    assert EventType.IncidentResolved not in event_types_b
    assert EventType.VerificationRecorded in event_types_b
    assert exec_result_b.termination == ExecutorTermination.ESCALATED


def test_post_execution_verification_and_incident_resolved():
    """
    Unit and integration test for terminal incident transition (state.phase) to IncidentPhase.resolved:
    1. Simulate incident following repair step execution (successful ExecutionResult, step status 'executed').
    2. Invoke verify tool by agent (ToolExecutor._do_verify).
    3. Verify:
       - VerificationRequested recorded.
       - VerificationRecorded recorded with verified verdict.
       - IncidentResolved recorded.
       - Incident phase immediately transitions to IncidentPhase.resolved.
       - Step status transitions to 'succeeded'.
    4. Resume ReasoningLoop.run and verify loop terminates with LoopTermination.RESOLVED.
    """
    import dataclasses
    from src.domain.types import (
        EvidenceAddedPayload, HypothesisUpdatedPayload, StepRecord, StepKind,
        DeclaredEffect, EffectCategory, ExecutionIntentPayload, ExecutionResultPayload,
        VerificationVerdict, StepProposedPayload,
    )
    from src.policy import compute_plan_hash
    from src.agent.loop import ReasoningLoop, LoopTermination

    store, state = _create_test_state(instance_id="i-test001")
    iid = state.incident_id
    executor = ToolExecutor(backend=MockObserveBackend(), store=store, instance_id="i-test001")

    # Add evidence and hypothesis
    ev_ref = EvidenceRef(
        evidence_id="ev-disk-1",
        source="observe:df -h",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_disk_1",
        summary="/var/log/app_bloat.log 5.4G",
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

    hyp = HypothesisRecord(
        hypothesis_id="hyp-disk-1",
        statement="log bloat in /var/log/app_bloat.log",
        confidence=0.9,
        supporting=["ev-disk-1"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-disk-1",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp))
    state = fold(store.read(iid))

    # Propose remediation step and record its execution
    step_id = "step-truncate-01"
    step = StepRecord(
        step_id=step_id,
        incident_id=iid,
        based_on_hypotheses=["hyp-disk-1"],
        based_on_evidence=["ev-disk-1"],
        kind=StepKind.mutate,
        target="i-test001",
        execution_spec={"command": "truncate -s 0 /var/log/app_bloat.log"},
        declared_effects=[DeclaredEffect(EffectCategory.E1, "/var/log/app_bloat.log", "truncate log")],
        preconditions=[],
        success_criteria=[{"type": "state", "check": "no_security_latch"}],
        rollback_plan="none",
        rollback_reason="remediation",
        idempotent=True,
        risk_claim="low",
        expires_at="",
        plan_hash="",
        status="proposed",
    )
    step = dataclasses.replace(step, plan_hash=compute_plan_hash(step))
    executor._write_event(state, EventType.StepProposed, StepProposedPayload(step=step))
    state = fold(store.read(iid))

    # Record ExecutionIntent then ExecutionResult successfully
    executor._write_event(
        state,
        EventType.ExecutionIntent,
        ExecutionIntentPayload(step_id=step_id, plan_hash=step.plan_hash, idempotency_key=f"{iid}:{step_id}", correlation_id="c-01", fencing_seq=1),
        actor=Actor.executor,
    )
    executor._write_event(
        state,
        EventType.ExecutionResult,
        ExecutionResultPayload(
            step_id=step_id,
            plan_hash=step.plan_hash,
            status="success",
            output_ref="ref-out-01",
            post_snapshot_ref=None,
            declared_vs_observed="match",
            mismatch_details=None,
        ),
        actor=Actor.executor,
    )
    state = fold(store.read(iid))
    assert state.steps[step_id].status == "executed"
    assert state.phase == IncidentPhase.verifying

    # 2. Invoke verify tool by agent
    res_verify = executor._do_verify({"step_id": step_id}, state)
    assert res_verify.success is True
    assert res_verify.data.get("resolved") is True

    # 3. Verify state after invocation
    state_after_verify = fold(store.read(iid))
    assert state_after_verify.steps[step_id].status == "succeeded"
    assert state_after_verify.phase == IncidentPhase.resolved
    assert state_after_verify.last_verification is not None
    assert state_after_verify.last_verification.verdict == VerificationVerdict.verified

    # 4. Run ReasoningLoop.run and verify loop terminates with RESOLVED
    mock_model = MagicMock()
    loop = ReasoningLoop(
        model=mock_model,
        store=store,
        backend=MockObserveBackend(),
        instance_id="i-test001",
        max_cycles=5,
    )
    loop_result = loop.run(state_after_verify)
    assert loop_result.termination == LoopTermination.RESOLVED
    assert loop_result.final_state.phase == IncidentPhase.resolved


def test_epistemic_sufficiency_gate_stops_over_investigation_on_healthy_host():
    """
    Epistemic Sufficiency Gate:
    When 2 or more evidences exist (len(state.evidence) >= 2) and recorded hypotheses are
    either refuted or low-confidence (<= 0.35), get_allowed_tools excludes observe
    and propose_step to halt random exploration and direct the agent to conclude.
    """
    from src.domain.types import EvidenceAddedPayload, HypothesisUpdatedPayload

    store, state = _create_test_state(instance_id="i-healthy001")
    iid = state.incident_id
    executor = ToolExecutor(backend=MockObserveBackend(), store=store, instance_id="i-healthy001")

    # 1. Add first evidence only (df -h shows 22%)
    ev1 = EvidenceRef(
        evidence_id="ev-df-healthy",
        source="observe:df -h /",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_ev1",
        summary="Filesystem 8.0G Used 1.7G Avail 6.3G Use% 22% /",
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev1))

    hyp_refuted = HypothesisRecord(
        hypothesis_id="hyp-disk-1",
        statement="disk capacity exhausted",
        confidence=0.1,
        supporting=[],
        contradicting=["ev-df-healthy"],
        status="refuted",
        next_check=None,
        trigger_evidence_id="ev-df-healthy",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp_refuted))
    state = fold(store.read(iid))

    # With only one evidence, observe tool is still permitted for continued verification
    tools_1 = get_allowed_tools(state)
    assert "observe" in tools_1

    # 2. Add second evidence (df -i shows 2% inodes)
    ev2 = EvidenceRef(
        evidence_id="ev-df-inodes",
        source="observe:df -i /",
        trust=TrustLevel.host_reported,
        collected_at=utc_now().isoformat(),
        raw_ref=None,
        integrity_hash="hash_ev2",
        summary="Inodes 524288 IUsed 10240 IFree 514048 IUse% 2% /",
        redaction_report={},
    )
    executor._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev2))
    state = fold(store.read(iid))
    assert len(state.evidence) >= 2

    # With two evidences and refuted hypothesis: observe and propose_step excluded; conclude remains available
    tools_refuted = get_allowed_tools(state)
    assert "observe" not in tools_refuted, "observe must be disallowed by Epistemic Sufficiency Gate"
    assert "propose_step" not in tools_refuted, "propose_step must be disallowed when no active hypothesis"
    assert "conclude" in tools_refuted, "conclude must be allowed to close healthy incident"
    assert "update_hypotheses" in tools_refuted

    # 3. Scenario: active hypothesis with low confidence (0.25 <= 0.35)
    hyp_low_conf = HypothesisRecord(
        hypothesis_id="hyp-disk-2",
        statement="minor log accumulation",
        confidence=0.25,
        supporting=[],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-df-inodes",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp_low_conf))
    state = fold(store.read(iid))

    tools_low_conf = get_allowed_tools(state)
    assert "observe" not in tools_low_conf, "observe must be disallowed when max_active_conf <= 0.35"
    assert "propose_step" not in tools_low_conf, "propose_step must be disallowed when confidence <= 0.35"
    assert "conclude" in tools_low_conf

    # 4. Scenario: strong active hypothesis (0.85 > 0.35) — observe and propose_step permitted
    hyp_high_conf = HypothesisRecord(
        hypothesis_id="hyp-disk-3",
        statement="specific bloat in /var/log",
        confidence=0.85,
        supporting=["ev-df-healthy"],
        contradicting=[],
        status="active",
        next_check=None,
        trigger_evidence_id="ev-df-healthy",
    )
    executor._write_event(state, EventType.HypothesisUpdated, HypothesisUpdatedPayload(hypothesis=hyp_high_conf))
    state = fold(store.read(iid))

    tools_high_conf = get_allowed_tools(state)
    assert "observe" in tools_high_conf, "observe should be allowed when strong active hypothesis exists"
    assert "propose_step" in tools_high_conf, "propose_step should be allowed when strong active hypothesis exists"






