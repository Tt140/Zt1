"""
handlers/notifier.py — incidents-notifier Lambda

Trigger: InvokeAsync from agent / executor
Responsibilities: Dispatches Slack messages (approval_request / resolution / escalation / incident_opened)

Resilient Provider Architecture:
1. SLACK_WEBHOOK_URL (from environment or AWS Secrets Manager: /incidents/slack-webhook-url)
2. SLACK_BOT_TOKEN (from environment or AWS Secrets Manager: /incidents/slack-bot-token) as fallback
3. 100% Optional: If neither is configured, notification is skipped cleanly without exceptions.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, List, Optional

import boto3

from .shared import ok, err, cfg, AWS_REGION, get_slack_webhook_url, _resolve_secret

logger = logging.getLogger(__name__)

SLACK_CHANNEL    = cfg("SLACK_CHANNEL",   "#incidents-alerts")
BOT_SECRET_ARN   = cfg("SLACK_BOT_TOKEN_SECRET_ARN", "")
APPROVAL_CHANNEL = cfg("SLACK_APPROVAL_CHANNEL", "#incidents-approval")

# Callback URL for approval actions (Function URL of slack_callback Lambda)
SLACK_CALLBACK_URL = cfg("SLACK_CALLBACK_URL", "")

_bot_token_cache: str = ""


def _get_bot_token_safe() -> str:
    global _bot_token_cache
    if _bot_token_cache:
        return _bot_token_cache
    token = _resolve_secret(
        env_var_name="SLACK_BOT_TOKEN",
        secret_arn_env_var="SLACK_BOT_TOKEN_SECRET_ARN",
        default_secret_id="/incidents/slack-bot-token",
    )
    if token:
        _bot_token_cache = token
        return _bot_token_cache
    return ""


def _get_bot_token() -> str:
    token = _get_bot_token_safe()
    if not token:
        raise RuntimeError("SLACK_BOT_TOKEN or SLACK_BOT_TOKEN_SECRET_ARN not set")
    return token


def _post_webhook(webhook_url: str, text: str, blocks: Optional[List[dict]] = None) -> bool:
    """Dispatches Slack message via Incoming Webhook (urllib.request)."""
    import urllib.request
    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks

    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
            if resp.getcode() == 200:
                logger.info(f"Slack webhook delivered successfully (status=200): {body}")
                return True
            logger.error(f"Slack webhook returned non-200 status {resp.getcode()}: {body}")
            return False
    except Exception as exc:
        logger.error(f"Failed to post to Slack webhook: {exc}")
        return False


def _post_bot_message(token: str, channel: str, text: str, blocks: Optional[List[dict]] = None) -> bool:
    """Dispatches Slack message via Bot Token API (chat.postMessage)."""
    import urllib.request
    payload: dict[str, Any] = {"channel": channel, "text": text}
    if blocks:
        payload["blocks"] = blocks

    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            if not body.get("ok"):
                logger.error(f"Slack API error: {body.get('error')}")
                return False
            return True
    except Exception as exc:
        logger.error(f"Failed to post to Slack bot API: {exc}")
        return False


def _post_slack(channel: str, text: str, blocks: Optional[List[dict]] = None) -> bool:
    """
    Dispatches Slack message via Webhook if available (primary), or Bot Token API as fallback.
    Returns True on successful delivery.
    """
    webhook_url = get_slack_webhook_url()
    if webhook_url:
        return _post_webhook(webhook_url, text, blocks)

    token = _get_bot_token_safe()
    if token:
        return _post_bot_message(token, channel, text, blocks)

    logger.info("Slack not configured — skipping notification")
    return False


def handler(event: dict, context=None) -> dict:
    webhook_url = get_slack_webhook_url()
    bot_token   = _get_bot_token_safe()

    if not webhook_url and not bot_token:
        logger.info("Slack not configured — skipping notification")
        return {"statusCode": 200, "body": json.dumps({"sent": False, "reason": "slack_not_configured"})}

    msg_type    = event.get("type", "")
    incident_id = event.get("incident_id", "")
    message     = event.get("message", "")

    try:
        if msg_type == "escalation":
            return _handle_escalation(event)
        elif msg_type == "resolution":
            return _handle_resolution(event)
        elif msg_type == "approval_request":
            return _handle_approval_request(event)
        elif msg_type == "incident_opened":
            return _handle_incident_opened(event)
        elif msg_type == "action_proposed":
            return _handle_action_proposed(event)
        elif msg_type == "test":
            return _handle_test(event)
        else:
            logger.warning(f"Unknown notification type: {msg_type!r}")
            return ok({"sent": False, "reason": "unknown_type"})
    except Exception as exc:
        logger.exception(f"notifier error: {exc}")
        return err(str(exc))


def _handle_escalation(event: dict) -> dict:
    incident_id = event.get("incident_id", "")
    instance_id = event.get("instance_id", "")
    reason = event.get("reason", "") or event.get("message", "")
    text = (
        f"⚠️ *Incident Escalated* — needs human review\n"
        f"Incident: `{incident_id}`\nInstance: `{instance_id}`"
    )
    if reason:
        text += f"\nReason: {reason}"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "⚠️ Incident Escalated — Human Review Required", "emoji": True},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Target Instance:*\n`{instance_id}`"},
            ],
        },
    ]
    if reason:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Forensics / Reason:*\n{reason}"},
        })
    sent = _post_slack(SLACK_CHANNEL, text, blocks=blocks)
    return ok({"sent": sent, "type": "escalation"})


def _handle_resolution(event: dict) -> dict:
    incident_id = event.get("incident_id", "")
    instance_id = event.get("instance_id", "")
    reason = event.get("reason", "") or event.get("message", "")
    text = (
        f"✅ *Incident Resolved Automatically*\n"
        f"Incident: `{incident_id}`\nInstance: `{instance_id}`"
    )
    if reason:
        text += f"\nSummary: {reason}"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "✅ Incident Resolved Automatically", "emoji": True},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Target Instance:*\n`{instance_id}`"},
            ],
        },
    ]
    if reason:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Resolution Summary:*\n{reason}"},
        })
    sent = _post_slack(SLACK_CHANNEL, text, blocks=blocks)
    return ok({"sent": sent, "type": "resolution"})


def _handle_incident_opened(event: dict) -> dict:
    incident_id = event.get("incident_id", "")
    instance_id = event.get("instance_id", "")
    alarm_name  = event.get("alarm_name", "") or event.get("message", "")
    text = (
        f"🚨 *New Incident Detected*\n"
        f"Incident: `{incident_id}`\nInstance: `{instance_id}`"
    )
    if alarm_name:
        text += f"\nAlarm: {alarm_name}"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🚨 New Incident Detected — Autonomous Investigation Started", "emoji": True},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Target Instance:*\n`{instance_id}`"},
            ],
        },
    ]
    if alarm_name:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Alarm / Trigger:*\n{alarm_name}"},
        })
    sent = _post_slack(SLACK_CHANNEL, text, blocks=blocks)
    return ok({"sent": sent, "type": "incident_opened"})


def _handle_approval_request(event: dict) -> dict:
    """
    Dispatches Slack message requesting human approval for a Tier T2 remediation step.
    Embeds interactive Block Kit action buttons (Approve/Deny) with action_id and value
    binding the decision to incident, step, and plan hash, without external browser URLs.
    """
    incident_id = event.get("incident_id", "")
    instance_id = event.get("instance_id", "")
    step_id     = event.get("step_id", "")
    step_desc   = event.get("step_description", "") or event.get("command", "")
    risk_claim  = event.get("risk_claim", "")
    plan_hash   = event.get("plan_hash", "")

    callback_data = {
        "incident_id": incident_id,
        "step_id":     step_id,
    }
    if plan_hash:
        callback_data["plan_hash"] = plan_hash
    callback_id = json.dumps(callback_data)

    text = (
        f"🔐 *Approval Required (Tier.T2 High-Risk)*\n"
        f"Incident: `{incident_id}`\n"
        f"Target Instance: `{instance_id}`\n"
        f"Step: `{step_id}`\n"
        f"Action: {step_desc}\n"
        f"Risk: {risk_claim}\n"
    )

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔐 Approval Required (Tier.T2 High-Risk Action)", "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": (
                f"*Incident:* `{incident_id}`\n"
                f"*Target Instance:* `{instance_id}`\n"
                f"*Proposed Step:* `{step_id}`\n"
                f"*Action:* `{step_desc}`\n"
                f"*Risk:* `{risk_claim}`"
            )},
        },
        {
            "type": "actions",
            "block_id": "approval_actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Approve & Execute"},
                    "style": "primary",
                    "action_id": "approve",
                    "value": callback_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ Deny"},
                    "style": "danger",
                    "action_id": "deny",
                    "value": callback_id,
                },
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"ℹ️ Authorized approvers can click the buttons above or reply with:\n"
                        f"`/approve {incident_id} {step_id}` or `/deny {incident_id} {step_id}`"
                    ),
                }
            ],
        },
    ]

    sent = _post_slack(APPROVAL_CHANNEL, text, blocks=blocks)
    return ok({"sent": sent, "type": "approval_request"})


def _handle_action_proposed(event: dict) -> dict:
    incident_id = event.get("incident_id", "")
    instance_id = event.get("instance_id", "")
    step_id     = event.get("step_id", "")
    step_desc   = event.get("step_description", "") or event.get("command", "")
    tier        = event.get("tier", "T1")
    text = (
        f"⚡ *Autonomous Remediation Step Proposed ({tier})*\n"
        f"Incident: `{incident_id}`\n"
        f"Instance: `{instance_id}`\n"
        f"Step: `{step_id}`\n"
        f"Action: `{step_desc}`"
    )
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"⚡ Autonomous Remediation ({tier} Auto-Approved)", "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": (
                f"*Incident:* `{incident_id}`\n"
                f"*Target Instance:* `{instance_id}`\n"
                f"*Proposed Step:* `{step_id}`\n"
                f"*Command:* `{step_desc}`\n"
                f"*Policy Gate:* Auto-allowed (low-risk surgical operation)"
            )},
        },
    ]
    sent = _post_slack(SLACK_CHANNEL, text, blocks=blocks)
    return ok({"sent": sent, "type": "action_proposed"})


def _handle_test(event: dict) -> dict:
    message     = event.get("message", "🧪 Test notification from Autonomous Cloud SRE Agent")
    incident_id = event.get("incident_id", "inc-test-live")
    instance_id = event.get("instance_id") or os.environ.get("TARGET_INSTANCE_ID", "i-test-instance")
    text = f"⚡ *Autonomous SRE Agent — Slack Test Notification*\n{message}"
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "⚡ Autonomous SRE Agent — Slack Integration Test", "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": (
                f"✅ *Slack Webhook Connection Verified*\n"
                f"*Status:* Active & Listening\n"
                f"*Incident Reference:* `{incident_id}`\n"
                f"*Target EC2 Instance:* `{instance_id}`\n"
                f"*Message:* {message}"
            )},
        },
    ]
    sent = _post_slack(SLACK_CHANNEL, text, blocks=blocks)
    return ok({"sent": sent, "type": "test"})
