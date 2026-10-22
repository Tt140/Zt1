# demos/_harness.py — Shared Live AWS Test Harness & Lifecycle Runner
from __future__ import annotations

import os
import sys
import time
import json
import queue
import dataclasses
from datetime import datetime, timezone, timedelta
from functools import lru_cache
from typing import Any, Optional, Tuple

# ── Dynamic Project Root & Environment ─────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

# Harmonize DynamoDB table environment variables
if "EVENTS_TABLE_NAME" in os.environ and "EVENTS_TABLE" not in os.environ:
    os.environ["EVENTS_TABLE"] = os.environ["EVENTS_TABLE_NAME"]
if "EVENTS_TABLE" in os.environ and "EVENTS_TABLE_NAME" not in os.environ:
    os.environ["EVENTS_TABLE_NAME"] = os.environ["EVENTS_TABLE"]

# Configure explicit approval MAC key and authorized approvers for test harness execution
os.environ.setdefault("APPROVAL_MAC_KEY_HEX", "a" * 64)
os.environ.setdefault("SLACK_AUTHORIZED_APPROVERS", "U123456,U_DEMO_LEAD")

import boto3

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def resolve_target_instance_id(region: Optional[str] = None) -> str:
    """
    Dynamically resolves target EC2 instance ID:
    1. Checks explicit TARGET_INSTANCE_ID environment variable.
    2. Auto-discovers running EC2 instance tagged IncidentsAgent=true via EC2 API.
    3. Falls back to a safe identifier in test/mock environments.
    """
    env_id = os.environ.get("TARGET_INSTANCE_ID", "").strip()
    if env_id:
        return env_id

    reg = region or os.environ.get("AWS_REGION", "us-east-1")
    try:
        ec2 = boto3.client("ec2", region_name=reg)
        res = ec2.describe_instances(
            Filters=[
                {"Name": "instance-state-name", "Values": ["running"]},
                {"Name": "tag:IncidentsAgent", "Values": ["true"]},
            ]
        )
        for r in res.get("Reservations", []):
            for inst in r.get("Instances", []):
                inst_id = inst.get("InstanceId")
                if inst_id:
                    return inst_id
    except Exception:
        pass

    if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
        return "i-mock-target-instance"

    return os.environ.get("TARGET_INSTANCE_ID", "i-target-instance-placeholder")


INSTANCE_ID = resolve_target_instance_id(AWS_REGION)
from src.domain import (
    Actor, EventType, IncidentPhase, build_event, new_ulid, utc_now,
)
from src.domain.types import (
    ApprovalGrantedPayload, EscalatedPayload, PolicyDecisionValue, Tier,
)
from src.domain.reducer import fold
from src.agent.loop import ReasoningLoop, LoopTermination
from src.agent.mock_backend import (
    ObserveBackend, ObservationResult, MetricResult, LogResult, AlarmState,
)
from src.executor.ssm_lab import SSMLab
from src.executor.executor import ExecutorLoop, ExecutorTermination
from src.executor.verifier import Verifier
from src.executor.reconciler import Reconciler
from src.policy.auth import compute_auth_tag

import handlers.shared as shared_mod
from handlers.shared import (
    get_store, get_model, get_decider, APPROVAL_MAC_KEY,
)
import handlers.ingest as ingest_mod

# Prevent handle_ingest from invoking nonexistent Lambda async in synchronous runs
ingest_mod.invoke_async = lambda *args, **kwargs: None


# ── External Test Harness / Chaos Injector (Admin Only) ───────────────────────
def harness_ssm_exec(
    ssm_client,
    instance_id: str,
    shell_cmd: str,
    timeout: int = 60,
    check: bool = True,
) -> str:
    """
    Admin test harness for fault injection and independent verification via AWS-RunShellScript.
    - Enforces TimeoutSeconds >= 30 per AWS SSM requirements.
    - Returns StandardOutputContent on successful execution.
    - Raises explicit RuntimeError on TimedOut, Cancelled, or Failed (when check=True).
    """
    eff_timeout = max(30, int(timeout))
    resp = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [shell_cmd]},
        TimeoutSeconds=eff_timeout,
    )
    cmd_id = resp["Command"]["CommandId"]
    deadline = time.time() + eff_timeout
    last_inv: dict = {}
    last_status = "Pending"

    while time.time() < deadline:
        time.sleep(2)
        try:
            inv = ssm_client.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            last_inv = inv
            last_status = inv.get("Status", "")
            if last_status == "Success":
                return inv.get("StandardOutputContent", "").strip()
            elif last_status in ("Failed", "Cancelled", "TimedOut"):
                break
        except Exception:
            pass

    stdout = last_inv.get("StandardOutputContent", "").strip() if last_inv else ""
    stderr = last_inv.get("StandardErrorContent", "").strip() if last_inv else ""
    truncated_cmd = shell_cmd[:200] + ("..." if len(shell_cmd) > 200 else "")

    if last_status in ("TimedOut", "Cancelled"):
        raise RuntimeError(
            f"❌ [SSM TIMEOUT / UNRESPONSIVE AGENT] SSM Command {cmd_id} on {instance_id} ended with status='{last_status}'.\n"
            f"   Command: {truncated_cmd}\n"
            f"   Stderr:  {stderr or '(empty)'}\n"
            f"   Stdout:  {stdout or '(empty)'}\n"
            f"   ⚠️ Warning: amazon-ssm-agent on {instance_id} is unresponsive or timed out. "
            f"The EC2 instance may be CPU-starved or requires health check/reboot."
        )

    if last_status == "Failed":
        if not check:
            return stdout
        response_code = last_inv.get("ResponseCode", "non-zero")
        raise RuntimeError(
            f"❌ [SSM COMMAND FAILED] SSM Command {cmd_id} on {instance_id} failed with exit_code={response_code} (status='Failed').\n"
            f"   Command: {truncated_cmd}\n"
            f"   Stderr:  {stderr or '(empty)'}\n"
            f"   Stdout:  {stdout or '(empty)'}\n"
            f"   ⚠️ Warning: Command execution failed on target instance {instance_id}."
        )

    # Polling deadline elapsed without terminal status (still Pending/InProgress/etc.)
    raise RuntimeError(
        f"❌ [SSM POLLING TIMEOUT] SSM Command {cmd_id} on {instance_id} did not reach terminal status within {eff_timeout}s (last_status='{last_status}').\n"
        f"   Command: {truncated_cmd}\n"
        f"   Stderr:  {stderr or '(empty)'}\n"
        f"   ⚠️ Warning: amazon-ssm-agent on {instance_id} did not respond in time. "
        f"The EC2 instance may be severely overloaded, CPU-starved, or disconnected."
    )


# ── Real EC2 Observe Backend (Restricted Read-Only Document) ──────────────────
class RealEC2ObserveBackend(ObserveBackend):
    """
    Real EC2 Observe Backend executing observation commands strictly via restricted
    SSM document (incidents-observe-readonly).
    """

    def __init__(self, ssm_lab: SSMLab, instance_id: str, region: str = "us-east-1"):
        self._ssm_lab = ssm_lab
        self._instance_id = instance_id
        self._region = region
        self._cw_client = None
        self._logs_client = None

    def _get_cw(self):
        if self._cw_client is None:
            self._cw_client = boto3.client("cloudwatch", region_name=self._region)
        return self._cw_client

    def _get_logs(self):
        if self._logs_client is None:
            self._logs_client = boto3.client("logs", region_name=self._region)
        return self._logs_client

    def run_observation(
        self, instance_id: str, command: str, timeout_seconds: int = 30
    ) -> ObservationResult:
        payload = {"command": command}
        print(f"   -> [REAL OBSERVER] op=run_observation payload={payload}")
        lab_res = self._ssm_lab.run(command, tier="T0", timeout_seconds=timeout_seconds)
        stdout = lab_res.stdout
        exit_code = lab_res.exit_code
        success = lab_res.success
        if not success and stdout and exit_code in (1, 3):
            success = True
            exit_code = 0
        return ObservationResult(
            success=success,
            stdout=stdout,
            stderr=lab_res.stderr,
            exit_code=exit_code,
            trust="host_reported",
            blocked_reason=lab_res.blocked_reason,
        )

    def get_metric(
        self, instance_id: str, metric_name: str, period_seconds: int = 300
    ) -> MetricResult:
        payload = {"metric_name": metric_name}
        print(f"   -> [REAL OBSERVER] op=get_metric payload={payload}")
        try:
            cw = self._get_cw()
            now = datetime.now(timezone.utc)
            start = now - timedelta(seconds=period_seconds * 2)
            resp = cw.get_metric_data(
                MetricDataQueries=[{
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/EC2",
                            "MetricName": metric_name,
                            "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                        },
                        "Period": period_seconds,
                        "Stat": "Average",
                    },
                }],
                StartTime=start,
                EndTime=now,
            )
            results = resp.get("MetricDataResults", [])
            if results and results[0].get("Values"):
                val = float(results[0]["Values"][0])
                return MetricResult(
                    metric_name=metric_name,
                    value=val,
                    unit="Percent",
                    period_seconds=period_seconds,
                    trust="out_of_band",
                    error=None,
                )
            return MetricResult(
                metric_name=metric_name,
                value=0.0,
                unit="UNAVAILABLE",
                period_seconds=period_seconds,
                trust="out_of_band",
                error=f"UNAVAILABLE: no CloudWatch datapoints found for metric '{metric_name}' on instance '{instance_id}'",
            )
        except Exception as exc:
            return MetricResult(
                metric_name=metric_name,
                value=0.0,
                unit="UNAVAILABLE",
                period_seconds=period_seconds,
                trust="out_of_band",
                error=f"UNAVAILABLE: CloudWatch get_metric_data failed: {exc}",
            )

    def get_logs(
        self, instance_id: str, log_group: str, query: str = "", minutes_back: int = 30
    ) -> LogResult:
        payload = {"log_group": log_group, "query": query, "minutes_back": minutes_back}
        print(f"   -> [REAL OBSERVER] op=get_logs payload={payload}")
        try:
            logs = self._get_logs()
            now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
            start_ms = now_ms - (minutes_back * 60 * 1000)
            kwargs = {
                "logGroupName": log_group,
                "startTime": start_ms,
                "endTime": now_ms,
                "limit": 100,
            }
            if query:
                kwargs["filterPattern"] = query
            resp = logs.filter_log_events(**kwargs)
            events = resp.get("events", [])
            lines = [e["message"] for e in events if "message" in e]
            if not lines:
                return LogResult(
                    log_group=log_group,
                    entries=[],
                    trust="host_reported",
                    error=f"UNAVAILABLE: no log events found in {log_group} for last {minutes_back}m",
                )
            return LogResult(
                log_group=log_group,
                entries=lines,
                trust="host_reported",
                error=None,
            )
        except Exception as exc:
            return LogResult(
                log_group=log_group,
                entries=[],
                trust="host_reported",
                error=f"UNAVAILABLE: CloudWatch filter_log_events failed: {exc}",
            )

    def describe_alarm(self, alarm_name: str) -> AlarmState:
        payload = {"alarm_name": alarm_name}
        print(f"   -> [REAL OBSERVER] op=describe_alarm payload={payload}")
        try:
            cw = self._get_cw()
            resp = cw.describe_alarms(AlarmNames=[alarm_name])
            metric_alarms = resp.get("MetricAlarms", [])
            composite_alarms = resp.get("CompositeAlarms", [])
            alarms = metric_alarms or composite_alarms
            if not alarms:
                return AlarmState(
                    alarm_name=alarm_name,
                    state="NOT_FOUND",
                    reason=f"Alarm '{alarm_name}' was not found in CloudWatch",
                    trust="out_of_band",
                    error="NOT_FOUND: alarm not registered in CloudWatch",
                )
            alarm = alarms[0]
            return AlarmState(
                alarm_name=alarm_name,
                state=alarm.get("StateValue", "UNKNOWN"),
                reason=alarm.get("StateReason", ""),
                trust="out_of_band",
                error=None,
            )
        except Exception as exc:
            return AlarmState(
                alarm_name=alarm_name,
                state="UNAVAILABLE",
                reason=f"CloudWatch describe_alarms failed: {exc}",
                trust="out_of_band",
                error=f"UNAVAILABLE: {exc}",
            )


# ── Incident Ingestion Helper ─────────────────────────────────────────────────
@lru_cache(maxsize=1)
def get_caller_account_id() -> str:
    """Dynamically extracts current AWS account ID with safe fallback."""
    account = os.environ.get("AWS_ACCOUNT_ID", "").strip()
    if account:
        return account
    try:
        sts = boto3.client("sts", region_name=AWS_REGION)
        return sts.get_caller_identity()["Account"]
    except Exception:
        return os.environ.get("AWS_ACCOUNT_ID", "000000000000")


def _notify_slack_safe(event_payload: dict) -> None:
    """
    Safe, non-disruptive invocation of handlers.notifier.handler.
    Dispatches formatted notification if SLACK_WEBHOOK_URL is configured;
    silently skips without raising errors if unconfigured.
    """
    try:
        from handlers import notifier
        res = notifier.handler(event_payload, None)
        body = json.loads(res.get("body", "{}")) if isinstance(res.get("body"), str) else res.get("body", {})
        if body.get("sent"):
            print(f"   -> [SLACK NOTIFICATION SENT] type={event_payload.get('type')} (status=200)")
    except Exception:
        pass


def open_incident(alarm_name: str, instance_id: str, description: str = ""):
    """Opens a real incident in DynamoEventStore via handlers.ingest.handler."""
    account_id = get_caller_account_id()
    event = {
        "source": "aws.cloudwatch",
        "detail-type": "CloudWatch Alarm State Change",
        "detail": {
            "alarmName": alarm_name,
            "state": {"value": "ALARM"},
            "configuration": {"description": description},
        },
        "resources": [f"arn:aws:cloudwatch:{AWS_REGION}:{account_id}:alarm:{alarm_name}"],
        "region": AWS_REGION,
    }
    res = ingest_mod.handler(event, None)
    body = json.loads(res["body"]) if isinstance(res["body"], str) else res["body"]
    if res.get("statusCode") != 200 or not body.get("created"):
        raise RuntimeError(f"open_incident failed: {res}")
    iid = body["incident_id"]
    store = get_store()
    state = fold(store.read(iid))
    _notify_slack_safe({
        "type": "incident_opened",
        "incident_id": iid,
        "instance_id": instance_id,
        "alarm_name": alarm_name,
        "message": f"Alarm '{alarm_name}' triggered incident {iid} on instance {instance_id}",
    })
    return iid, state


# ── Runtime Components Builder ────────────────────────────────────────────────
class RuntimeComponents(dict):
    """
    Runtime components container supporting dict access, attribute access, and tuple unpacking:
    store, model, decider = build_runtime()
    """
    def __iter__(self):
        return iter((self["store"], self["model"], self["decider"]))

    @property
    def store(self):
        return self["store"]

    @property
    def model(self):
        return self["model"]

    @property
    def decider(self):
        return self["decider"]

    @property
    def base_url(self):
        return self["base_url"]

    @property
    def flash_model(self):
        return self["flash_model"]

    @property
    def pro_model(self):
        return self["pro_model"]


def build_runtime() -> RuntimeComponents:
    """
    Builds shared runtime components (store, model, decider) reading:
    - DEEPSEEK_BASE_URL (defaults to https://bedrock-mantle.us-east-1.api.aws/v1)
    - DEEPSEEK_FLASH_MODEL (defaults to deepseek.v3.1)
    - DEEPSEEK_PRO_MODEL (defaults to deepseek.v3.2)
    and passing api_base to DeepSeekModel.
    """
    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://bedrock-mantle.us-east-1.api.aws/v1")
    flash_model = os.environ.get("DEEPSEEK_FLASH_MODEL", "deepseek.v3.1")
    pro_model = os.environ.get("DEEPSEEK_PRO_MODEL", "deepseek.v3.2")

    store = get_store()
    decider = get_decider()

    deepseek_key = shared_mod._resolve_secret(
        env_var_name="DEEPSEEK_API_KEY",
        secret_arn_env_var="DEEPSEEK_API_KEY_SECRET_ARN",
        default_secret_id="/incidents/deepseek-api-key",
    )
    if deepseek_key:
        from src.agent.deepseek_model import DeepSeekModel
        from src.agent.model_router import ModelRouter
        flash = DeepSeekModel(api_key=deepseek_key, model=flash_model, api_base=base_url)
        pro = DeepSeekModel(api_key=deepseek_key, model=pro_model, api_base=base_url)
        model = ModelRouter(flash_model=flash, pro_model=pro)
    else:
        model = get_model()

    return RuntimeComponents({
        "store": store,
        "model": model,
        "decider": decider,
        "base_url": base_url,
        "flash_model": flash_model,
        "pro_model": pro_model,
    })


# ── Slack Socket Mode Approval Listener ───────────────────────────────────────
def wait_for_slack_approval(
    incident_id: str,
    step_id: str,
    expected_plan_hash: Optional[str] = None,
    timeout_seconds: int = 300,
) -> Tuple[bool, Optional[str]]:
    """
    Listens for interactive Slack BlockKit approval/denial via Socket Mode (SLACK_APP_TOKEN).
    Enforces approver identity via Slack RBAC (Fail-Closed).
    Upon approval, appends an HMAC-authenticated ApprovalGranted event to the EventStore.
    Returns (True, approver_id) on approval, or (False, approver_id/None) on denial or timeout.
    """
    app_token = os.environ.get("SLACK_APP_TOKEN", "").strip()
    bot_token = os.environ.get("SLACK_BOT_TOKEN", "").strip()

    if not app_token:
        print("⚠️ SLACK_APP_TOKEN not configured — cannot listen via Socket Mode")
        return False, None

    try:
        from slack_sdk.web import WebClient
        from slack_sdk.socket_mode import SocketModeClient
        from slack_sdk.socket_mode.response import SocketModeResponse
        from slack_sdk.socket_mode.request import SocketModeRequest
        from handlers.shared import get_authorized_approvers
        from handlers.slack_callback import _write_approval_event
        import urllib.request
    except ImportError as e:
        print(f"⚠️ Failed to import slack_sdk or handler modules: {e}")
        return False, None

    result_queue: queue.Queue[Tuple[bool, str]] = queue.Queue()
    authorized_approvers = get_authorized_approvers()
    web_client = WebClient(token=bot_token) if bot_token else None
    client = SocketModeClient(app_token=app_token, web_client=web_client)

    def _socket_mode_listener(sm_client: SocketModeClient, req: SocketModeRequest):
        try:
            ack_resp = SocketModeResponse(envelope_id=req.envelope_id)
            sm_client.send_socket_mode_response(ack_resp)

            if req.type != "interactive":
                return
            payload = req.payload or {}
            action_type = payload.get("type", "")
            if action_type not in ("block_actions", "interactive_message"):
                return

            actions = payload.get("actions", [])
            if not actions:
                return

            action = actions[0]
            action_id = action.get("action_id", "")
            value_str = action.get("value", "{}")

            try:
                value = json.loads(value_str) if isinstance(value_str, str) else (value_str or {})
                req_iid = value.get("incident_id")
                req_step = value.get("step_id")
                req_plan_hash = value.get("plan_hash")
            except Exception:
                return

            if req_iid != incident_id or req_step != step_id:
                return

            user_info = payload.get("user") or {}
            user_id = user_info.get("id", "").strip()
            clean_approver = user_id.strip("<@> ").strip()

            if not clean_approver or (clean_approver not in authorized_approvers and user_id not in authorized_approvers):
                print(f"\n⚠️ [SLACK RBAC REJECTED] Unauthorized user {user_id} attempted {action_id} for step {step_id}!")
                resp_url = payload.get("response_url")
                if resp_url:
                    try:
                        req_data = json.dumps({
                            "response_type": "ephemeral",
                            "replace_original": False,
                            "text": f"❌ Unauthorized: User <@{user_id}> is not authorized to approve Tier.T2 actions.",
                        }).encode("utf-8")
                        urllib.request.urlopen(urllib.request.Request(resp_url, data=req_data, headers={"Content-Type": "application/json"}))
                    except Exception:
                        pass
                return

            is_approve = action_id == "approve"
            plan_hash = req_plan_hash or expected_plan_hash

            _write_approval_event(
                incident_id=incident_id,
                step_id=step_id,
                approver=user_id,
                approved=is_approve,
                expected_plan_hash=plan_hash,
            )

            resp_url = payload.get("response_url")
            if resp_url:
                try:
                    status_text = "✅ Approved & Executing" if is_approve else "❌ Denied"
                    req_data = json.dumps({
                        "response_type": "in_channel",
                        "replace_original": True,
                        "text": f"{status_text} step `{step_id}` for incident `{incident_id}` by <@{user_id}>",
                    }).encode("utf-8")
                    urllib.request.urlopen(urllib.request.Request(resp_url, data=req_data, headers={"Content-Type": "application/json"}))
                except Exception:
                    pass

            result_queue.put((is_approve, user_id))
        except Exception as exc:
            print(f"⚠️ Error in Socket Mode listener: {exc}")

    client.socket_mode_request_listeners.append(_socket_mode_listener)

    try:
        client.connect()
        print("\n" + "=" * 80)
        print("🔔 [AWAITING HUMAN APPROVAL VIA SLACK SOCKET MODE]")
        print(f"   Incident ID:         {incident_id}")
        print(f"   Step ID:             {step_id}")
        print(f"   Authorized Users:    {list(authorized_approvers)}")
        print(f"   Timeout:             {timeout_seconds} seconds ({timeout_seconds // 60} minutes)")
        print("👉 Action Required: Open Slack (#incidents-approval) and click 'Approve & Execute'!")
        print("=" * 80 + "\n")

        approved, approver_id = result_queue.get(timeout=timeout_seconds)
        if approved:
            print(f"\n🎉 [SLACK APPROVAL GRANTED] User <@{approver_id}> approved step {step_id} via Socket Mode!")
        else:
            print(f"\n🚫 [SLACK APPROVAL DENIED] User <@{approver_id}> denied step {step_id} via Socket Mode.")
        return approved, approver_id
    except queue.Empty:
        print(f"\n⏱️ [SLACK APPROVAL TIMED OUT] No approval response received within {timeout_seconds} seconds ({timeout_seconds // 60} minutes).")
        return False, None
    finally:
        try:
            client.close()
        except Exception:
            pass


def _handle_unapproved_t2_halt(
    iid: str,
    instance_id: str,
    step_id: str,
    approver_id: Optional[str],
    timeout_sec: int,
    store: Any,
    state: Any,
) -> Any:
    """
    Safe Fail-Closed behavior upon human approval timeout or denial via Slack:
    1. Records an EventType.Escalated event, transitioning phase to IncidentPhase.escalated.
    2. Sends immediate escalation alert to Slack via _notify_slack_safe.
    3. Immediately halts automated execution without executing unapproved mutations.
    """
    if approver_id is None:
        reason = f"Slack approval timed out after {timeout_sec}s. Automated remediation halted safely (Fail-Closed)."
    else:
        reason = f"Step {step_id} was explicitly denied by <@{approver_id}> via Slack."
    print(f"\n🛑 [REMEDIATION HALTED] {reason}")
    try:
        events = store.read(iid)
        if events:
            state = fold(events)
        esc_payload = EscalatedPayload(reason=reason, report_ref=None)
        ev_esc = build_event(
            incident_id=iid,
            type=EventType.Escalated,
            actor=Actor.system,
            payload=esc_payload,
        )
        store.append(iid, state.last_seq, ev_esc)
        refreshed = store.read(iid)
        if refreshed:
            state = fold(refreshed)
        else:
            state.phase = IncidentPhase.escalated
    except Exception as e:
        print(f"⚠️ Warning: Could not record Escalated event: {e}")
        state.phase = IncidentPhase.escalated

    _notify_slack_safe({
        "type": "escalation",
        "incident_id": iid,
        "instance_id": instance_id,
        "message": f"Incident {iid} remediation halted safely (Fail-Closed): {reason}",
        "reason": reason,
    })
    return state


# ── Unified Incident Lifecycle Runner ─────────────────────────────────────────
def run_incident_lifecycle(
    iid: str,
    state: Any,
    ssm_client: Any,
    instance_id: str,
    require_t2_approval: bool = False,
    expect_remediation: bool = True,
    max_cycles: int = int(os.environ.get("MAX_CYCLES", "20")),
    auto_approve_t2: bool = False,
    expect_escalation: bool = False,
    allow_any_terminal_state: bool = False,
):
    """
    Executes complete incident lifecycle:
    1. Autonomous investigation via ReasoningLoop.
    2. PolicyGate governance (autonomous execution for T1 allow, HMAC-verified ApprovalGranted for T2).
    3. Authenticated remediation execution via ExecutorLoop with incidents-repair-restricted SSM document.
    """
    rt = build_runtime()
    store = rt.store
    model = rt.model
    decider = rt.decider
    ssm_lab = SSMLab(ssm_client=ssm_client, instance_id=instance_id)
    observer = RealEC2ObserveBackend(ssm_lab=ssm_lab, instance_id=instance_id, region=AWS_REGION)

    loop = ReasoningLoop(
        model=model,
        store=store,
        backend=observer,
        instance_id=instance_id,
        max_cycles=max_cycles,
        tool_decider=decider,
    )

    print(f"\nRunning ReasoningLoop (max_cycles={max_cycles})...")
    investigation_result = loop.run(state)
    state = investigation_result.final_state

    print(f"\n[Investigation Summary]")
    print(f"- Termination:    {investigation_result.termination.value}")
    print(f"- Final Phase:    {state.phase.value}")
    print(f"- Proposed Steps: {len(state.steps)}")

    # Handle concluded / resolved / false alarm gracefully
    is_concluded = (
        state.phase in (IncidentPhase.concluded, IncidentPhase.resolved)
        or investigation_result.termination in (LoopTermination.CONCLUDED, LoopTermination.RESOLVED)
        or getattr(investigation_result.termination, "value", "") in ("concluded", "resolved")
    )

    if is_concluded:
        print("\n" + "=" * 80)
        print("✅ [INCIDENT CONCLUDED / RESOLVED / FALSE ALARM]")
        print(f"   Incident ID:     {iid}")
        print(f"   Target Instance: {instance_id}")
        print("   Autonomous agent verified system state and concluded incident without further mutations.")
        print("=" * 80)
        _notify_slack_safe({
            "type": "resolution",
            "incident_id": iid,
            "instance_id": instance_id,
            "message": f"Incident {iid} concluded/resolved: system verified healthy (Termination: {investigation_result.termination.value})",
            "reason": f"Termination: {investigation_result.termination.value}, Phase: {state.phase.value}",
        })
        if allow_any_terminal_state or not expect_remediation:
            return state, None, None, None
        return state, None, None, None

    # Handle graceful Human Escalation before asserting proposed steps
    is_escalated = (
        state.phase == IncidentPhase.escalated
        or investigation_result.termination == LoopTermination.ESCALATED
        or getattr(investigation_result.termination, "value", "") == "escalated"
    )

    if is_escalated:
        escalation_reason = "Unspecified / Hypothesis confidence exhausted"
        try:
            for ev in reversed(store.read(iid)):
                if getattr(ev, "type", None) == EventType.Escalated:
                    p = getattr(ev, "payload", None)
                    if hasattr(p, "reason") and p.reason:
                        escalation_reason = p.reason
                        break
                    elif isinstance(p, dict) and p.get("reason"):
                        escalation_reason = p["reason"]
                        break
        except Exception:
            pass

        print("\n" + "=" * 80)
        print("🚨 [HUMAN ESCALATION TRIGGERED]")
        print(f"   Incident ID:       {iid}")
        print(f"   Target Instance:   {instance_id}")
        print(f"   Incident Phase:    {state.phase.value}")
        print(f"   Loop Termination:  {investigation_result.termination.value}")
        print(f"   Reasoning Cycles:  {getattr(state.budgets, 'cycles', max_cycles)} / {max_cycles}")
        print(f"   Escalation Reason: {escalation_reason}")
        print("=" * 80)

        _notify_slack_safe({
            "type": "escalation",
            "incident_id": iid,
            "instance_id": instance_id,
            "message": f"Incident {iid} escalated to human — autonomous investigation stopped",
            "reason": escalation_reason,
            "termination": investigation_result.termination.value,
            "cycles": getattr(state.budgets, "cycles", max_cycles),
        })

        if allow_any_terminal_state or expect_escalation:
            print("✅ [EXPECTED ESCALATION] Lifecycle successfully handled human escalation.")
            return state, None, None, None

        raise RuntimeError(
            f"❌ Incident {iid} escalated to human operator (termination={investigation_result.termination.value}): "
            f"{escalation_reason}"
        )

    if not state.steps and allow_any_terminal_state:
        print("ℹ️ No remediation steps proposed.")
        return state, None, None, None

    assert len(state.steps) > 0, "❌ Error: No remediation step was proposed by the agent!"

    valid_steps = [s for s in state.steps.values() if getattr(s, "status", None) != "rejected"]
    step = valid_steps[-1] if valid_steps else list(state.steps.values())[-1]
    step_id = step.step_id
    policy_decision = state.policy_decisions.get(step_id)

    print(f"\n[Proposed Remediation Step]")
    print(f"- Step ID:     {step_id}")
    print(f"- Command:     {step.execution_spec.get('command')}")
    print(f"- Policy Gate: {policy_decision.decision.value if policy_decision else 'unknown'} (Tier: {policy_decision.tier.value if policy_decision else 'unknown'})")

    is_t1_auto_allowed = (
        policy_decision
        and policy_decision.decision == PolicyDecisionValue.allow
        and policy_decision.tier == Tier.T1
    )

    cmd = step.execution_spec.get("command", "") if isinstance(step.execution_spec, dict) else ""
    if is_t1_auto_allowed:
        print("\n⚡ [AUTONOMOUS T1 EXECUTION] Step auto-approved by PolicyGate — no human intervention required!")
        _notify_slack_safe({
            "type": "action_proposed",
            "incident_id": iid,
            "instance_id": instance_id,
            "step_id": step_id,
            "step_description": cmd or f"Execute {step.kind.value} step",
            "command": cmd,
            "tier": "T1",
        })
    else:
        assert policy_decision.tier == Tier.T2, f"Expected Tier.T2, got {policy_decision.tier}"
        assert policy_decision.decision == PolicyDecisionValue.require_approval, f"Expected require_approval, got {policy_decision.decision}"
        print("✅ [POLICY GATE VERIFIED] Step correctly classified as Tier.T2 (require_approval).")
        plan_hash = policy_decision.plan_hash if policy_decision else step.plan_hash
        _notify_slack_safe({
            "type": "approval_request",
            "incident_id": iid,
            "instance_id": instance_id,
            "step_id": step_id,
            "step_description": cmd or f"Execute {step.kind.value} step",
            "command": cmd,
            "risk_claim": step.risk_claim or "high (process termination / mutation)",
            "plan_hash": plan_hash,
        })

        if not auto_approve_t2:
            app_token = os.environ.get("SLACK_APP_TOKEN", "").strip()
            if app_token and require_t2_approval:
                timeout_sec = int(os.environ.get("SLACK_APPROVAL_TIMEOUT", "300"))
                approved, approver_id = wait_for_slack_approval(
                    incident_id=iid,
                    step_id=step_id,
                    expected_plan_hash=plan_hash,
                    timeout_seconds=timeout_sec,
                )
                if approved:
                    state = fold(store.read(iid))
                    print(f"✅ [SLACK APPROVAL RECORDED] Pending approval step: {state.pending_approval_step}")
                else:
                    state = _handle_unapproved_t2_halt(
                        iid=iid,
                        instance_id=instance_id,
                        step_id=step_id,
                        approver_id=approver_id,
                        timeout_sec=timeout_sec,
                        store=store,
                        state=state,
                    )
                    return state, step, policy_decision, None
            else:
                print("\n⏸️ [AWAITING HUMAN APPROVAL] Incident execution paused pending manual T2 authorization (auto_approve_t2=False).")
                print(f"   Incident ID:           {iid}")
                print(f"   Step ID:               {step_id}")
                print(f"   Incident Phase:        {state.phase.value}")
                print(f"   Pending Approval Step: {state.pending_approval_step}")
                print("   Autonomous agent lifecycle stopped safely without executing unapproved T2 action.")
                return state, step, policy_decision, None
        else:
            print("\n[SIMULATED T2 APPROVAL: auto_approve_t2=True] Issuing cryptographic ApprovalGranted event for test automation...")
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
            approval_payload = ApprovalGrantedPayload(
                approval_id=new_ulid(),
                step_id=step_id,
                plan_hash=plan_hash,
                approver_id="secops_lead",
                issued_at=utc_now().isoformat(),
                expires_at=expires_at,
                nonce=new_ulid(),
            )
            p_dict = dataclasses.asdict(approval_payload)
            p_dict.pop("auth_tag", None)
            auth_tag = compute_auth_tag(
                incident_id=iid,
                event_type="ApprovalGranted",
                payload_dict=p_dict,
                key=APPROVAL_MAC_KEY,
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
            print(f"✅ [SIMULATED T2 APPROVAL: auto_approve_t2=True] ApprovalGranted recorded. Pending approval step: {state.pending_approval_step}")

    print("\nExecuting remediation step via ExecutorLoop (incidents-repair-restricted)...")
    exec_ssm_lab = SSMLab(ssm_client=ssm_client, instance_id=instance_id)
    verifier = Verifier(exec_ssm_lab)
    reconciler = Reconciler(exec_ssm_lab)

    executor_loop = ExecutorLoop(
        store=store,
        lab=exec_ssm_lab,
        verifier=verifier,
        reconciler=reconciler,
        instance_id=instance_id,
        allowed_instance_id=instance_id,
        max_verify_attempts=1,
        auth_key=APPROVAL_MAC_KEY,
        auto_resolve_incident=False,
    )

    exec_result = executor_loop.execute_step(step=step, state=state)
    state = fold(store.read(iid))

    print(f"\n[Executor Result]")
    print(f"- Termination:   {exec_result.termination.value}")
    print(f"- Gate Decision: {exec_result.gate_decision.value if exec_result.gate_decision else 'n/a'}")
    print(f"- Step Status:   {state.steps[step_id].status}")
    print(f"- State Phase:   {state.phase.value}")

    if state.phase == IncidentPhase.investigating and exec_result.termination in (ExecutorTermination.ROLLBACK, ExecutorTermination.FAILED):
        print(f"⚠️ [STEP EXECUTION FAILED & ROLLED BACK] ExitCode={exec_result.lab_result.exit_code if exec_result.lab_result else 'n/a'}")
        print(f"ℹ️ Incident state remains in 'investigating' (Closed-loop recovery active). Resuming next reasoning round...")

    remediation_round = 1
    max_remediation_rounds = 5

    while state.phase == IncidentPhase.investigating and remediation_round < max_remediation_rounds:
        remediation_round += 1
        print(f"\n🔄 [MULTI-STEP REMEDIATION: ROUND {remediation_round}] Resuming ReasoningLoop...")
        subsequent_loop_res = loop.run(state)
        state = subsequent_loop_res.final_state
        print(f"- Subsequent Loop Termination: {subsequent_loop_res.termination.value}")
        print(f"- Incident Phase:              {state.phase.value}")

        # If subsequent sub-round reached resolution or conclusion -> exit immediately
        if state.phase in (IncidentPhase.resolved, IncidentPhase.concluded):
            print(f"✅ [ROUND {remediation_round} RESOLVED] Incident resolved/concluded during subsequent reasoning.")
            break

        pending_steps = [
            s for s in state.steps.values()
            if getattr(s, "status", "") in ("proposed", None)
        ]
        if not pending_steps:
            break

        next_step = pending_steps[-1]
        next_step_id = next_step.step_id
        next_cmd = next_step.execution_spec.get("command", "")
        print(f"\n[Multi-Step Proposed Remediation] Step ID: {next_step_id} | Command: {next_cmd}")

        next_policy = state.policy_decisions.get(next_step_id)
        if not next_policy:
            from src.policy import evaluate as gate_eval_step, GateContext
            next_ctx = GateContext(
                kill_switch_active=False,
                allowed_instance_id=instance_id,
                auth_key=APPROVAL_MAC_KEY,
            )
            next_policy = gate_eval_step(step=next_step, state=state, ctx=next_ctx)
        print(f"- Policy Gate: {next_policy.decision.value} (Tier: {next_policy.tier.value})")

        if next_policy.tier == Tier.T2 and next_policy.decision == PolicyDecisionValue.require_approval:
            next_plan_hash = next_policy.plan_hash if next_policy else next_step.plan_hash
            _notify_slack_safe({
                "type": "approval_request",
                "incident_id": iid,
                "instance_id": instance_id,
                "step_id": next_step_id,
                "step_description": next_cmd or f"Execute {next_step.kind.value} step",
                "command": next_cmd,
                "risk_claim": next_step.risk_claim or "high (mutation)",
                "plan_hash": next_plan_hash,
            })
            if not auto_approve_t2:
                app_token = os.environ.get("SLACK_APP_TOKEN", "").strip()
                if app_token and require_t2_approval:
                    timeout_sec = int(os.environ.get("SLACK_APPROVAL_TIMEOUT", "300"))
                    approved, approver_id = wait_for_slack_approval(
                        incident_id=iid,
                        step_id=next_step_id,
                        expected_plan_hash=next_plan_hash,
                        timeout_seconds=timeout_sec,
                    )
                    if not approved:
                        state = _handle_unapproved_t2_halt(
                            iid=iid,
                            instance_id=instance_id,
                            step_id=next_step_id,
                            approver_id=approver_id,
                            timeout_sec=timeout_sec,
                            store=store,
                            state=state,
                        )
                        return state, next_step, next_policy, None
                else:
                    print(f"⏸️ [AWAITING HUMAN APPROVAL] Incident execution paused pending manual T2 authorization.")
                    return state, next_step, next_policy, None
            else:
                print(f"[SIMULATED T2 APPROVAL: auto_approve_t2=True] Issuing approval for step {next_step_id}...")
                expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
                approval_payload = ApprovalGrantedPayload(
                    approval_id=new_ulid(),
                    step_id=next_step_id,
                    plan_hash=next_plan_hash,
                    approver_id="secops_lead",
                    issued_at=utc_now().isoformat(),
                    expires_at=expires_at,
                    nonce=new_ulid(),
                )
                p_dict = dataclasses.asdict(approval_payload)
                p_dict.pop("auth_tag", None)
                auth_tag = compute_auth_tag(
                    incident_id=iid,
                    event_type="ApprovalGranted",
                    payload_dict=p_dict,
                    key=APPROVAL_MAC_KEY,
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
        else:
            print("⚡ [AUTONOMOUS T1 EXECUTION] Step auto-approved by PolicyGate — no human intervention required!")
            _notify_slack_safe({
                "type": "action_proposed",
                "incident_id": iid,
                "instance_id": instance_id,
                "step_id": next_step_id,
                "step_description": next_cmd,
                "command": next_cmd,
                "risk_claim": next_step.risk_claim or "low",
                "plan_hash": next_step.plan_hash,
            })

        print(f"Executing step {next_step_id} via ExecutorLoop...")
        exec_result = executor_loop.execute_step(step=next_step, state=state)
        state = fold(store.read(iid))
        step = next_step
        policy_decision = next_policy
        print(f"- Step Status:   {state.steps[next_step_id].status}")
        print(f"- State Phase:   {state.phase.value}")

        if state.phase == IncidentPhase.investigating and exec_result.termination in (ExecutorTermination.ROLLBACK, ExecutorTermination.FAILED):
            print(f"⚠️ [STEP EXECUTION FAILED & ROLLED BACK] ExitCode={exec_result.lab_result.exit_code if exec_result.lab_result else 'n/a'}")
            print(f"ℹ️ Incident state remains in 'investigating' (Closed-loop recovery active). Resuming next reasoning round...")

    if state.phase in (IncidentPhase.resolved, IncidentPhase.concluded):
        active_step_id = step.step_id if step else step_id
        _notify_slack_safe({
            "type": "resolution",
            "incident_id": iid,
            "instance_id": instance_id,
            "message": f"Incident {iid} resolved automatically after verified remediation",
            "reason": f"Termination: {exec_result.termination.value if exec_result else 'resolved'}, Step status: {state.steps[active_step_id].status if active_step_id in state.steps else 'completed'}",
        })
    elif state.phase == IncidentPhase.escalated:
        _notify_slack_safe({
            "type": "escalation",
            "incident_id": iid,
            "instance_id": instance_id,
            "message": f"Incident {iid} escalated — human review required",
            "reason": f"Termination: {exec_result.termination.value if exec_result else 'escalated'}",
        })

    return state, step, policy_decision, exec_result


# ── Incident Evidence & Reasoning Audit Trail ─────────────────────────────────
def audit_incident_evidence_trail(
    iid: str,
    store: Optional[Any] = None,
    state: Optional[Any] = None,
) -> dict[str, Any]:
    """
    Builds structured evidence report and chronological reasoning trail from EventStore events:
    - Chronologically correlates:
      1. Observations, outputs, and evidence records (EvidenceAdded / ObservationRecorded).
      2. Hypothesis formulation and evolution (HypothesisUpdated).
      3. Remediation proposals (StepProposed) linked to supporting evidence and hypotheses.
      4. Policy decisions (PolicyDecision), approvals, and executions.
    """
    if store is None:
        store = get_store()

    events = store.read(iid)
    if state is None:
        try:
            state = fold(events)
        except Exception:
            state = None

    evidence_items = []
    hypotheses_items = []
    proposed_steps = []
    policy_decisions = []

    for ev in events:
        ev_type = getattr(ev, "type", None)
        ev_type_val = ev_type.value if hasattr(ev_type, "value") else str(ev_type)
        payload = getattr(ev, "payload", None)

        if ev_type_val in ("EvidenceAdded", "ObservationRecorded"):
            ref = getattr(payload, "evidence", payload)
            if ref:
                eid = getattr(ref, "evidence_id", None) or (ref.get("evidence_id") if isinstance(ref, dict) else None)
                src = getattr(ref, "source", None) or (ref.get("source") if isinstance(ref, dict) else None)
                summ = getattr(ref, "summary", None) or (ref.get("summary") if isinstance(ref, dict) else None)
                trust = getattr(ref, "trust", None) or (ref.get("trust") if isinstance(ref, dict) else None)
                trust_val = trust.value if hasattr(trust, "value") else str(trust or "unknown")
                ts = getattr(ref, "collected_at", None) or getattr(ev, "ts", "")
                evidence_items.append({
                    "evidence_id": eid,
                    "source": src,
                    "summary": summ,
                    "trust": trust_val,
                    "timestamp": ts,
                    "seq": getattr(ev, "seq", 0),
                })

        elif ev_type_val == "HypothesisUpdated":
            hyp = getattr(payload, "hypothesis", payload)
            if hyp:
                hid = getattr(hyp, "hypothesis_id", None) or (hyp.get("hypothesis_id") if isinstance(hyp, dict) else None)
                stmt = getattr(hyp, "statement", None) or (hyp.get("statement") if isinstance(hyp, dict) else None)
                status = getattr(hyp, "status", None) or (hyp.get("status") if isinstance(hyp, dict) else None)
                status_val = status.value if hasattr(status, "value") else str(status)
                conf = getattr(hyp, "confidence", None) or (hyp.get("confidence") if isinstance(hyp, dict) else 0.0)
                supp = getattr(hyp, "supporting", None) or (hyp.get("supporting") if isinstance(hyp, dict) else [])
                cont = getattr(hyp, "contradicting", None) or (hyp.get("contradicting") if isinstance(hyp, dict) else [])
                trig = getattr(hyp, "trigger_evidence_id", None) or (hyp.get("trigger_evidence_id") if isinstance(hyp, dict) else None)
                hypotheses_items.append({
                    "hypothesis_id": hid,
                    "statement": stmt,
                    "status": status_val,
                    "confidence": conf,
                    "supporting": supp,
                    "contradicting": cont,
                    "trigger_evidence_id": trig,
                    "seq": getattr(ev, "seq", 0),
                })

        elif ev_type_val == "StepProposed":
            step = getattr(payload, "step", payload)
            if step:
                sid = getattr(step, "step_id", None) or (step.get("step_id") if isinstance(step, dict) else None)
                kind = getattr(step, "kind", None) or (step.get("kind") if isinstance(step, dict) else None)
                kind_val = kind.value if hasattr(kind, "value") else str(kind)
                spec = getattr(step, "execution_spec", None) or (step.get("execution_spec") if isinstance(step, dict) else {})
                cmd = spec.get("command", "") if isinstance(spec, dict) else ""
                target = getattr(step, "target", None) or (step.get("target") if isinstance(step, dict) else "")
                b_ev = getattr(step, "based_on_evidence", None) or (step.get("based_on_evidence") if isinstance(step, dict) else [])
                b_hyp = getattr(step, "based_on_hypotheses", None) or (step.get("based_on_hypotheses") if isinstance(step, dict) else [])
                risk = getattr(step, "risk_claim", None) or (step.get("risk_claim") if isinstance(step, dict) else "")
                proposed_steps.append({
                    "step_id": sid,
                    "kind": kind_val,
                    "command": cmd,
                    "target": target,
                    "based_on_evidence": b_ev,
                    "based_on_hypotheses": b_hyp,
                    "risk_claim": risk,
                    "seq": getattr(ev, "seq", 0),
                })

        elif ev_type_val == "PolicyDecision":
            sid = getattr(payload, "step_id", None) or (payload.get("step_id") if isinstance(payload, dict) else None)
            tier = getattr(payload, "tier", None) or (payload.get("tier") if isinstance(payload, dict) else None)
            tier_val = tier.value if hasattr(tier, "value") else str(tier)
            dec = getattr(payload, "decision", None) or (payload.get("decision") if isinstance(payload, dict) else None)
            dec_val = dec.value if hasattr(dec, "value") else str(dec)
            reasons = getattr(payload, "reasons", None) or (payload.get("reasons") if isinstance(payload, dict) else [])
            policy_decisions.append({
                "step_id": sid,
                "tier": tier_val,
                "decision": dec_val,
                "reasons": reasons,
                "seq": getattr(ev, "seq", 0),
            })

    evidence_map = {item["evidence_id"]: item for item in evidence_items if item["evidence_id"]}
    hypo_map = {item["hypothesis_id"]: item for item in hypotheses_items if item["hypothesis_id"]}

    table_name = (
        store._tbl
        if (store and hasattr(store, "_tbl") and isinstance(store._tbl, str))
        else os.environ.get("EVENTS_TABLE", "incidents-events")
    )
    bucket_name = (
        store._s3_bucket
        if (store and hasattr(store, "_s3_bucket") and isinstance(store._s3_bucket, str))
        else (os.environ.get("BLOBS_BUCKET") or "incidents-blobs")
    )
    region_name = (
        store._region
        if (store and hasattr(store, "_region") and isinstance(store._region, str))
        else os.environ.get("AWS_REGION", "us-east-1")
    )

    print("\n" + "=" * 80)
    print(f"📜 [AWS DYNAMODB EVENTSTORE AUDIT TRAIL — Table: {table_name} | Events: {len(events)}]")
    print(f"   Storage Engine: Amazon DynamoDB ({table_name}) + Amazon S3 ({bucket_name}) | Region: {region_name}")
    print(f"   Incident ID:    {iid}")
    print(f"   Target Host:    {getattr(state, 'instance_id', 'unknown')}")
    final_phase_val = state.phase.value if (state and hasattr(state.phase, 'value')) else getattr(state, 'phase', 'unknown')
    print(f"   Final Phase:    {final_phase_val}")
    print(f"   Total Events:   {len(events)} (Immutable Ledger in DynamoDB)")
    print("=" * 80)

    print(f"\n🔎 1. OBSERVATIONS & EVIDENCE COLLECTED ({len(evidence_items)}):")
    if not evidence_items:
        print("   (No evidence records logged)")
    for idx, e in enumerate(evidence_items, 1):
        eid = e['evidence_id']
        src = e['source']
        trust = e['trust']
        summary = (e['summary'] or '').strip().replace('\n', ' ')
        if len(summary) > 120:
            summary = summary[:117] + "..."
        print(f"   [{idx}] [{eid}] {src} (trust={trust})")
        print(f"       Summary: {summary}")

    print(f"\n💡 2. HYPOTHESES REASONING & EVOLUTION ({len(hypotheses_items)}):")
    if not hypotheses_items:
        print("   (No hypothesis records logged)")
    for idx, h in enumerate(hypotheses_items, 1):
        hid = h['hypothesis_id']
        status = h['status']
        conf = h['confidence']
        stmt = h['statement']
        trig = h['trigger_evidence_id']
        supp = h['supporting']
        print(f"   [{idx}] [{hid}] status={status} (confidence={conf:.0%})")
        print(f"       Statement: {stmt}")
        print(f"       Triggered By: {trig or 'initial'} | Supporting Evidence: {supp}")

    print(f"\n⚡ 3. PROPOSED REMEDIATION & EVIDENCE CITATIONS ({len(proposed_steps)}):")
    if not proposed_steps:
        print("   (No proposed steps recorded)")
    for idx, s in enumerate(proposed_steps, 1):
        sid = s['step_id']
        cmd = s['command']
        kind = s['kind']
        target = s['target']
        risk = s['risk_claim']
        p_match = next((p for p in policy_decisions if p["step_id"] == sid), None)
        tier_str = f"{p_match['tier']} ({p_match['decision']})" if p_match else "pending / not evaluated"

        print(f"   [{idx}] Step ID:     {sid} (kind={kind})")
        print(f"       Command:     {cmd}")
        print(f"       Target:      {target}")
        print(f"       Policy Gate: {tier_str}")
        print(f"       Risk Claim:  {risk}")

        cited_ev = s['based_on_evidence']
        print(f"       Cited Evidence ({len(cited_ev)}):")
        for ceid in cited_ev:
            ev_info = evidence_map.get(ceid)
            if ev_info:
                sm = (ev_info['summary'] or '').strip().replace('\n', ' ')
                if len(sm) > 100:
                    sm = sm[:97] + "..."
                print(f"         * [{ceid}] {ev_info['source']} -> {sm}")
            else:
                print(f"         * [{ceid}] (recorded in event stream)")

        cited_hy = s['based_on_hypotheses']
        print(f"       Cited Hypotheses ({len(cited_hy)}):")
        for chid in cited_hy:
            hy_info = hypo_map.get(chid)
            if hy_info:
                print(f"         * [{chid}] ({hy_info['status']}): {hy_info['statement']}")
            else:
                print(f"         * [{chid}] (recorded in hypothesis stream)")

    print("=" * 80 + "\n")

    return {
        "incident_id": iid,
        "instance_id": getattr(state, "instance_id", ""),
        "phase": final_phase_val,
        "total_events": len(events),
        "evidence": evidence_items,
        "hypotheses": hypotheses_items,
        "proposed_steps": proposed_steps,
        "policy_decisions": policy_decisions,
    }




