#!/usr/bin/env python3
"""
demos/run_live_incident.py — Universal Live Incident Runner (Zero Fault Injection)

Run this script to launch the autonomous agent against your live AWS EC2 instance
without any pre-injected or predetermined scenarios.

Architecture Highlights:
  - Anti-Hesitation Reasoning: Dynamically breaks circular analysis loops and scales
    investigation budget up to 25 cycles.
  - PolicyGate & Fail-Closed Governance: Strictly enforces T0/T1/T2 tiers. T1 actions
    execute autonomously, while T2 mutations require human authorization.
  - Live Slack Socket Mode: Full interactive approval in Slack (#incidents-approval)
    with fail-closed RBAC and HMAC-SHA256 signature verification.
  - Decoupled Verification & Multi-Step Remediation: Passes auto_resolve_incident=False
    to ExecutorLoop, allowing the agent to observe outcomes, perform sequential actions,
    and drive epistemic resolution via agent-authored conclusion.

Usage Examples:
    # 1. Run with default comprehensive health probe:
    python3 demos/run_live_incident.py

    # 2. Run with custom symptom as positional argument:
    python3 demos/run_live_incident.py "High CPU utilization and rogue process detected on port 8080"

    # 3. Run with full CLI flags:
    python3 demos/run_live_incident.py \\
        --alarm-name "Custom-Port-Conflict-Alarm" \\
        --desc "Service health check failed on port 8443, connection refused" \\
        --max-cycles 20

    # 4. Run in headless test mode (auto-approves T2 without waiting for Slack click):
    python3 demos/run_live_incident.py --auto-approve
"""
import os
import sys
import re
import time
import argparse
from typing import Optional
import boto3

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from demos._harness import (
    AWS_REGION,
    INSTANCE_ID,
    open_incident,
    run_incident_lifecycle,
    audit_incident_evidence_trail,
)
from src.domain.types import IncidentPhase, Tier, PolicyDecisionValue


DEFAULT_ALARM_DESC = (
    "System health degradation detected on instance - investigate processes, ports, disk, and services"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Launch autonomous SecOps agent against live EC2 instance without fault injection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "symptom",
        nargs="?",
        default=None,
        help="Optional positional argument describing the incident symptom.",
    )
    parser.add_argument(
        "-d",
        "--desc",
        dest="desc",
        default=None,
        help="Explicit incident description (overrides positional symptom).",
    )
    parser.add_argument(
        "-n",
        "--alarm-name",
        dest="alarm_name",
        default=None,
        help="Custom CloudWatch alarm name. Default: LiveManualIncident-<instance_id>-<timestamp>",
    )
    parser.add_argument(
        "-i",
        "--instance-id",
        dest="instance_id",
        default=None,
        help=f"Target EC2 instance ID. Default from .env: {INSTANCE_ID}",
    )
    parser.add_argument(
        "-c",
        "--max-cycles",
        dest="max_cycles",
        type=int,
        default=int(os.environ.get("MAX_CYCLES", "20")),
        help="Maximum reasoning cycles for investigation loop. Default: 20",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        default=False,
        help="Auto-approve Tier.T2 actions without waiting for interactive Slack button click.",
    )
    parser.add_argument(
        "--allow-healthy",
        action="store_true",
        default=False,
        help="Allow the agent to safely conclude as healthy if no fault is detected (does not require remediation).",
    )
    return parser.parse_args()


def check_prerequisites(instance_id: str, ssm_client):
    """Verifies that the target instance is online and reachable via AWS SSM."""
    print("🔎 Checking AWS SSM Agent connectivity...")
    try:
        resp = ssm_client.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        info_list = resp.get("InstanceInformationList", [])
        if not info_list:
            print(f"⚠️ Warning: Instance {instance_id} was not found in SSM Managed Instances list for {AWS_REGION}.")
            print("   Ensure the amazon-ssm-agent is running and instance has appropriate IAM instance profile.")
        else:
            status = info_list[0].get("PingStatus", "Unknown")
            platform = info_list[0].get("PlatformName", "Linux")
            agent_ver = info_list[0].get("AgentVersion", "Unknown")
            print(f"   -> Instance:     {instance_id}")
            print(f"   -> Status:       {status} (Ping)")
            print(f"   -> Platform:     {platform}")
            print(f"   -> Agent Version:{agent_ver}")
            if status != "Online":
                print(f"⚠️ Warning: Instance ping status is '{status}', not 'Online'. Commands might time out.")
    except Exception as e:
        print(f"⚠️ Non-blocking SSM check warning: {e}")


def main():
    args = parse_args()

    # Determine description and instance
    description = args.desc or args.symptom or DEFAULT_ALARM_DESC
    instance_id = args.instance_id or INSTANCE_ID
    timestamp = int(time.time())

    # Build descriptive alarm_name slug from the symptom text
    words = re.findall(r"[A-Za-z0-9]+", description)
    significant_words = [w for w in words if w.lower() not in ("and", "the", "on", "in", "is", "a", "an", "to", "for", "of")]
    slug = "-".join(significant_words[:5]) if significant_words else "LiveManualIncident"
    alarm_name = args.alarm_name or f"{slug}-{instance_id}-{timestamp}"

    # Slack integration state
    has_slack_bot = bool(os.environ.get("SLACK_BOT_TOKEN"))
    has_slack_app = bool(os.environ.get("SLACK_APP_TOKEN"))
    slack_channel = os.environ.get("SLACK_APPROVAL_CHANNEL", "#incidents-approval")
    approvers = os.environ.get("SLACK_AUTHORIZED_APPROVERS", "(all authenticated members)")

    print("=" * 80)
    print("⚡ [LIVE ZERO-FAULT AUTONOMOUS INCIDENT INVESTIGATION]")
    print(f"  Target Instance:       {instance_id} ({AWS_REGION})")
    print(f"  Alarm Name:            {alarm_name}")
    print(f"  Incident Description:  {description}")
    print(f"  Reasoning Cycle Cap:   {args.max_cycles}")
    print(f"  Slack Interactive Mode:{'ENABLED (Socket Mode)' if has_slack_app else 'DISABLED (Polling/Simulated)'}")
    print(f"  Slack Channel:         {slack_channel}")
    print(f"  Authorized Approvers:  {approvers}")
    print(f"  Auto-Approve T2:       {args.auto_approve}")
    print("=" * 80)

    ssm_client = boto3.client("ssm", region_name=AWS_REGION)
    check_prerequisites(instance_id, ssm_client)

    # 1. Open Incident in DynamoDB & EventStore
    print(f"\n[Step 1: Ingesting Incident & Initializing State]")
    iid, state = open_incident(alarm_name, instance_id, description)
    print(f"✅ Incident opened successfully: {iid}")

    # 2. Run Autonomous Lifecycle
    print(f"\n[Step 2: Launching Autonomous Reasoning & Governance Lifecycle]")
    try:
        final_state, step, policy_decision, exec_result = run_incident_lifecycle(
            iid=iid,
            state=state,
            ssm_client=ssm_client,
            instance_id=instance_id,
            require_t2_approval=True,
            auto_approve_t2=args.auto_approve,
            expect_remediation=not args.allow_healthy,
            max_cycles=args.max_cycles,
            allow_any_terminal_state=True,
        )
    except Exception as exc:
        print(f"\n❌ [INCIDENT EXECUTION ERROR]: {exc}")
        audit_incident_evidence_trail(iid=iid, state=state)
        sys.exit(1)

    # 3. Audit Evidence & Reasoning Trail
    audit_incident_evidence_trail(iid=iid, state=final_state)

    # 4. Final Executive Summary
    print("\n" + "=" * 80)
    print("📊 [FINAL EXECUTIVE OUTCOME SUMMARY]")
    print(f"   Incident ID:    {iid}")
    print(f"   Final Phase:    {final_state.phase.value if hasattr(final_state.phase, 'value') else final_state.phase}")

    if getattr(final_state, "hypotheses", None):
        active_or_confirmed = [
            h for h in final_state.hypotheses.values()
            if str(getattr(h, "status", "")).lower() in ("confirmed", "active", "hypothesisstatus.confirmed", "hypothesisstatus.active")
        ]
        if active_or_confirmed:
            best_h = max(active_or_confirmed, key=lambda h: getattr(h, "confidence", 0.0))
            print(f"   Diagnostic:     {best_h.statement} (Confidence: {best_h.confidence:.2f})")

    if final_state.steps:
        print(f"   Remediation Steps Executed ({len(final_state.steps)}):")
        for idx, (sid, s) in enumerate(final_state.steps.items(), 1):
            scmd = s.execution_spec.get("command", "") if isinstance(s.execution_spec, dict) else ""
            sstatus = getattr(s, "status", "unknown")
            print(f"     [{idx}] Step ID: {sid} | Command: {scmd!r} | Status: {sstatus}")
        if exec_result and getattr(exec_result, "lab_result", None):
            lr = exec_result.lab_result
            print(f"   Last Execution: ExitCode={lr.exit_code} | Duration={lr.elapsed_seconds:.2f}s")
            if lr.stdout:
                print(f"   Stdout Snippet: {lr.stdout[:200]}")
            if lr.stderr:
                print(f"   Stderr Snippet: {lr.stderr[:200]}")
    elif step:
        cmd = step.execution_spec.get("command", "") if isinstance(step.execution_spec, dict) else ""
        tier_val = policy_decision.tier.value if policy_decision else "unknown"
        dec_val = policy_decision.decision.value if policy_decision else "unknown"
        print(f"   Remediation:    {step.step_id} ({cmd})")
        print(f"   Policy Decision:{dec_val} (Tier: {tier_val})")

        if exec_result and getattr(exec_result, "lab_result", None):
            lr = exec_result.lab_result
            print(f"   Execution:      ExitCode={lr.exit_code} | Duration={lr.elapsed_seconds:.2f}s")
            print(f"   Stdout Snippet: {lr.stdout[:200] or '(empty)'}")
            if lr.stderr:
                print(f"   Stderr Snippet: {lr.stderr[:200]}")
        elif exec_result:
            term_val = getattr(exec_result.termination, "value", str(exec_result.termination))
            print(f"   Execution:      Termination={term_val}")
        else:
            print(f"   Execution:      Pending / Halted (Awaiting Human Approval or Rejected)")
    else:
        print("   Remediation:    None proposed (System evaluated as healthy or escalated to human)")

    print("=" * 80)


if __name__ == "__main__":
    main()
