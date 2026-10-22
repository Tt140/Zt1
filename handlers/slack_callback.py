"""
handlers/slack_callback.py — incidents-slack-callback Lambda (Function URL)

Trigger: Slack Interactivity → HTTPS POST (Lambda Function URL)
Responsibilities:
  1. Verify Slack signing secret (fail-closed)
  2. Extract action (approve/deny) + incident_id + step_id
  3. Write ApprovalGranted/ApprovalDenied event to EventStore
  4. Invoke incidents-agent async to resume investigation
  5. Respond to Slack in < 3 seconds (mandatory Slack timeout constraint)

Security:
  - Slack signing secret verification on all incoming requests
  - Cryptographic approval auth_tag: HMAC-SHA256 with APPROVAL_MAC_KEY

Note: Slack expects HTTP 200 OK within 3 seconds. Agent re-invocation is async.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
from typing import Optional

import boto3

from src.domain.types import (
    Actor, EventType, utc_now, new_ulid, build_event,
    ApprovalGrantedPayload, ApprovalDeniedPayload, ApprovalRejectedPayload,
    IncidentPhase,
)
from src.domain.reducer import fold
from src.policy.auth import compute_auth_tag
from .shared import (
    get_store, invoke_async, ok, err, cfg,
    get_approval_mac_key, get_authorized_approvers, _resolve_secret, AWS_REGION,
)

logger = logging.getLogger(__name__)

AGENT_FN           = cfg("AGENT_FUNCTION",             "incidents-agent")
SIGNING_SECRET_ARN = cfg("SLACK_SIGNING_SECRET_ARN",   "")

_signing_secret_cache: Optional[bytes] = None


# ── Slack signature verification ──────────────────────────────────────────────

def _get_signing_secret() -> bytes:
    global _signing_secret_cache
    if _signing_secret_cache is not None:
        return _signing_secret_cache
    secret = _resolve_secret(
        env_var_name="SLACK_SIGNING_SECRET",
        secret_arn_env_var="SLACK_SIGNING_SECRET_ARN",
        default_secret_id="/incidents/slack-signing-secret",
    )
    if not secret:
        raise RuntimeError("SLACK_SIGNING_SECRET or SLACK_SIGNING_SECRET_ARN not set")
    _signing_secret_cache = secret.encode()
    return _signing_secret_cache


def _verify_slack_signature(headers: dict, raw_body: bytes) -> bool:
    """Verifies Slack request signature — fail-closed."""
    try:
        ts  = headers.get("x-slack-request-timestamp", "")
        sig = headers.get("x-slack-signature", "")

        # Reject stale requests (> 5 minutes) to prevent replay attacks
        if abs(time.time() - int(ts)) > 300:
            logger.warning("Slack timestamp too old — possible replay")
            return False

        secret = _get_signing_secret()
        base_string = f"v0:{ts}:{raw_body.decode()}".encode()
        expected_sig = "v0=" + hmac.new(secret, base_string, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, sig)
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


# ── handler ───────────────────────────────────────────────────────────────────

def handler(event: dict, context) -> dict:
    """Lambda Function URL handler."""
    # Extract body and headers
    headers  = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw_body = event.get("body", "")
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body)
    elif isinstance(raw_body, str):
        raw_body = raw_body.encode()

    # 1. Verify Slack signature
    if not _verify_slack_signature(headers, raw_body):
        logger.error("Invalid Slack signature")
        return {"statusCode": 403, "body": "Forbidden"}

    # 2. parse payload & form data
    try:
        form_data = urllib.parse.parse_qs(raw_body.decode())
        payload_str = form_data.get("payload", [""])[0]
        payload = json.loads(payload_str) if payload_str else {}
    except Exception as e:
        return {"statusCode": 400, "body": f"Invalid payload: {e}"}

    action_type = payload.get("type", "")

    if action_type in ("block_actions", "interactive_message"):
        return _handle_block_action(payload)
    elif "command" in form_data:
        return _handle_slash_command(form_data)
    else:
        logger.info(f"Unhandled Slack action type: {action_type!r}")
        return {"statusCode": 200, "body": ""}


def _handle_slash_command(form_data: dict) -> dict:
    """Handles alternative slash commands /approve and /deny from Slack."""
    command = form_data.get("command", [""])[0].strip().lower()
    text = form_data.get("text", [""])[0].strip()
    user_id = form_data.get("user_id", [""])[0].strip()

    parts = text.split()
    if len(parts) < 2:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "response_type": "ephemeral",
                "text": "⚠️ Usage: `/approve <incident_id> <step_id>` or `/deny <incident_id> <step_id>`",
            }),
        }

    incident_id, step_id = parts[0], parts[1]
    is_approve = command == "/approve"
    action_id = "approve" if is_approve else "deny"

    # Slack RBAC (Fail-Closed)
    authorized_approvers = get_authorized_approvers()
    clean_approver = user_id.strip("<@> ").strip()

    if not clean_approver or (clean_approver not in authorized_approvers and user_id not in authorized_approvers):
        logger.warning(
            f"Unauthorized Slack user {user_id!r} attempted command {command!r} "
            f"for incident {incident_id} step {step_id}. Action rejected (fail-closed)."
        )
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "response_type": "ephemeral",
                "replace_original": False,
                "text": f"❌ Unauthorized: User <@{user_id}> is not authorized for Tier.T2 remediation.",
            }),
        }

    try:
        _write_approval_event(
            incident_id=incident_id,
            step_id=step_id,
            approver=user_id,
            approved=is_approve,
        )
    except Exception as e:
        logger.exception(f"Failed to record approval from slash command: {e}")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "response_type": "ephemeral",
                "replace_original": False,
                "text": f"⚠️ Error recording approval: {e}",
            }),
        }

    if is_approve:
        try:
            invoke_async(AGENT_FN, {
                "incident_id": incident_id,
                "resume_from_approval": True,
                "approval_event_id": step_id,
            })
        except Exception as e:
            logger.error(f"Failed to invoke agent after slash approval: {e}")

    status_text = "✅ Approved" if is_approve else "❌ Denied"
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "response_type": "in_channel",
            "text": f"{status_text} step `{step_id}` for incident `{incident_id}` by <@{user_id}>",
        }),
    }


def _handle_block_action(payload: dict) -> dict:
    actions = payload.get("actions", [])
    if not actions:
        return {"statusCode": 200, "body": ""}

    action = actions[0]
    action_id = action.get("action_id", "")   # "approve" or "deny"
    value_str = action.get("value", "{}")

    try:
        value = json.loads(value_str)
        incident_id = value["incident_id"]
        step_id     = value["step_id"]
        plan_hash   = value.get("plan_hash")
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Failed to parse callback value: {e}")
        return {"statusCode": 200, "body": "Error parsing callback"}

    approver = payload.get("user", {}).get("id", "").strip()
    is_approve = action_id == "approve"

    # ── Slack RBAC Verification (Fail-Closed) ─────────────────────────────────
    authorized_approvers = get_authorized_approvers()
    clean_approver = approver.strip("<@> ").strip()

    if not clean_approver or (clean_approver not in authorized_approvers and approver not in authorized_approvers):
        logger.warning(
            f"Unauthorized Slack user {approver!r} attempted action {action_id!r} "
            f"for incident {incident_id} step {step_id}. Action rejected (fail-closed)."
        )
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "response_type": "ephemeral",
                "replace_original": False,
                "text": f"❌ Unauthorized: User <@{approver}> is not in the authorized approvers list for Tier.T2 remediation.",
            }),
        }

    try:
        _write_approval_event(
            incident_id=incident_id,
            step_id=step_id,
            approver=approver,
            approved=is_approve,
            expected_plan_hash=plan_hash,
        )
    except Exception as e:
        logger.exception(f"Failed to write approval event: {e}")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "response_type": "ephemeral",
                "replace_original": False,
                "text": f"⚠️ Error recording approval: {e}",
            }),
        }

    if is_approve:
        # Invoke agent asynchronously to resume investigation after approval
        try:
            invoke_async(AGENT_FN, {
                "incident_id": incident_id,
                "resume_from_approval": True,
                "approval_event_id": step_id,
            })
        except Exception as e:
            logger.error(f"Failed to invoke agent after approval: {e}")

    # Respond to Slack immediately (< 3 seconds)
    status_text = "✅ Approved" if is_approve else "❌ Denied"
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "response_type": "in_channel",
            "replace_original": True,
            "text": f"{status_text} by <@{approver}>",
        }),
    }


def _write_approval_event(
    incident_id: str,
    step_id: str,
    approver: str,
    approved: bool,
    expected_plan_hash: Optional[str] = None,
) -> None:
    store = get_store()
    events = store.read(incident_id)
    if not events:
        raise ValueError(f"Incident {incident_id} not found")

    state = fold(events)
    expected_seq = state.last_seq

    # 1. Verify incident is not already in a terminal closed/resolved state
    if state.phase in (IncidentPhase.resolved, IncidentPhase.closed):
        raise ValueError(f"Incident {incident_id} is already {state.phase.value}")

    # 2. Verify target step exists and state is eligible for decision
    step_record = state.steps.get(step_id)
    if state.steps and not step_record:
        raise ValueError(f"Step {step_id} not found in incident {incident_id}")

    if step_record:
        if getattr(step_record, "status", None) == "executed":
            raise ValueError(f"Step {step_id} has already been executed — cannot re-approve")
        if getattr(step_record, "status", None) == "rejected":
            raise ValueError(f"Step {step_id} has already been rejected")
        if expected_plan_hash and step_record.plan_hash and expected_plan_hash != step_record.plan_hash:
            raise ValueError(
                f"Plan hash mismatch for step {step_id}: callback={expected_plan_hash!r} ≠ step={step_record.plan_hash!r}"
            )
        plan_hash = step_record.plan_hash
    else:
        plan_hash = expected_plan_hash or "unknown"

    # 3. Prevent duplicate or replayed decision
    if state.approvals:
        for ap in state.approvals.values():
            if getattr(ap, "step_id", None) == step_id:
                if isinstance(ap, ApprovalGrantedPayload):
                    raise ValueError(f"Approval already granted for step {step_id} — cannot reuse")
                elif isinstance(ap, (ApprovalDeniedPayload, ApprovalRejectedPayload)):
                    raise ValueError(f"Approval already decided for step {step_id}")

    nonce = new_ulid()
    # Approval expiration window: 15 minutes from creation
    from datetime import timezone, timedelta
    from datetime import datetime as _dt
    expires_at  = (_dt.now(timezone.utc) + timedelta(minutes=15)).isoformat()

    if approved:
        import dataclasses
        payload = ApprovalGrantedPayload(
            approval_id=new_ulid(),
            step_id=step_id,
            plan_hash=plan_hash,
            approver_id=approver,
            issued_at=utc_now().isoformat(),
            expires_at=expires_at,
            nonce=nonce,
        )
        payload_dict = dataclasses.asdict(payload)
        payload_dict.pop("auth_tag", None)
        auth_tag = compute_auth_tag(
            incident_id=incident_id,
            event_type="ApprovalGranted",
            payload_dict=payload_dict,
            key=get_approval_mac_key(),
        )
        payload = dataclasses.replace(payload, auth_tag=auth_tag)
        ev = build_event(
            incident_id=incident_id,
            type=EventType.ApprovalGranted,
            actor=Actor.slack_callback,
            payload=payload,
            auth_tag=auth_tag,
        )
    else:
        payload = ApprovalDeniedPayload(
            approval_id=new_ulid(),
            step_id=step_id,
            approver_id=approver,
            reason="Denied via Slack",
        )
        ev = build_event(
            incident_id=incident_id,
            type=EventType.ApprovalDenied,
            actor=Actor.slack_callback,
            payload=payload,
        )

    store.append(incident_id, expected_seq, ev)
    logger.info(f"Approval {'granted' if approved else 'denied'}: {incident_id}/{step_id} by {approver}")
