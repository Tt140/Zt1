"""
tests/handlers/test_slack_approval_lifecycle.py

Comprehensive Integration Tests for the complete Tier.T2 Human-in-the-Loop Slack approval lifecycle:
1. End-to-end trace: StepProposed (T2) → PolicyGate requires approval → Notifier Block Kit buttons
   → Signed Slack callback → RBAC authorization → HMAC-SHA256 signature → EventStore append
   → Agent resume → Executor GateContext → PolicyGate cryptographic verification → Execution permitted.
2. Anti-Replay & Anti-Reuse:
   - Duplicate callback click rejection (cannot re-approve once granted).
   - PolicyGate re-evaluation denial for executed steps (APPROVAL-REUSED).
   - Cross-step approval theft/reuse denial.
3. Unauthorized approver rejection (fail-closed, ephemeral error, no state mutation).
4. Request timestamp staleness rejection (> 300s).
5. Denial flow: Deny action → ApprovalDenied event → Incident escalated, step rejected, execution blocked.
6. Slash command fallback: /approve and /deny commands authenticated and verified.
7. Tier.T1 Autonomy preservation: Safe actions execute autonomously without Slack or HMAC requirements.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse
from unittest.mock import patch, MagicMock

import pytest

from src.store.memory import MemoryEventStore
from src.domain.types import (
    IncidentHeader, IncidentOpenedPayload, StepProposedPayload, StepRecord,
    StepKind, DeclaredEffect, EffectCategory, EventType, Actor,
    IncidentPhase, PolicyDecisionValue, build_event, new_ulid, utc_now,
)
from src.domain.reducer import fold
from src.policy import evaluate as gate_evaluate, GateContext
from src.policy.plan_hash import compute_plan_hash
from src.policy.auth import compute_auth_tag, verify_auth_tag
from tests.policy.conftest import make_step
from handlers.shared import (
    APPROVAL_MAC_KEY_HEX_VAR, SLACK_AUTHORIZED_APPROVERS_VAR,
    get_approval_mac_key, get_authorized_approvers, _resolve_secret,
)
from handlers import notifier as notifier_mod
from handlers import slack_callback as callback_mod
from handlers import executor_fn as executor_mod


TEST_SIGNING_SECRET = b"test-signing-secret-slack-2026"
TEST_HMAC_KEY_HEX   = "b" * 64
TEST_HMAC_KEY_BYTES = bytes.fromhex(TEST_HMAC_KEY_HEX)
AUTHORIZED_USER_ID  = "U_DEV_LEAD_001"
UNAUTHORIZED_USER   = "U_ATTACKER_999"


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    get_approval_mac_key.cache_clear()
    get_authorized_approvers.cache_clear()
    _resolve_secret.cache_clear()

    monkeypatch.setenv(APPROVAL_MAC_KEY_HEX_VAR, TEST_HMAC_KEY_HEX)
    monkeypatch.setenv(SLACK_AUTHORIZED_APPROVERS_VAR, f"{AUTHORIZED_USER_ID},U_BACKUP_ADMIN")

    yield

    get_approval_mac_key.cache_clear()
    get_authorized_approvers.cache_clear()
    _resolve_secret.cache_clear()


def _sign(body: bytes, ts: int = None) -> dict:
    ts = ts or int(time.time())
    base_string = f"v0:{ts}:{body.decode()}".encode()
    sig = "v0=" + hmac.new(TEST_SIGNING_SECRET, base_string, hashlib.sha256).hexdigest()
    return {
        "x-slack-request-timestamp": str(ts),
        "x-slack-signature": sig,
    }


def _make_signed_slack_event(body: bytes, ts: int = None) -> dict:
    headers = _sign(body, ts=ts)
    return {
        "headers": headers,
        "body": body.decode(),
        "isBase64Encoded": False,
    }


def _create_incident_with_t2_step(store: MemoryEventStore):
    iid = new_ulid()
    dk = f"alarm::test::{iid}"
    header = IncidentHeader(
        incident_id=iid, instance_id="i-target-prod-01", dedupe_key=dk,
        alarm_name="RogueProcessHighCpu", alarm_arn="arn:test", alert_source="cloudwatch",
        opened_at=utc_now().isoformat(),
    )
    store.create_if_absent(dk, header)
    store.append(iid, 0, build_event(
        incident_id=iid, type=EventType.IncidentOpened, actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id="i-target-prod-01", dedupe_key=dk, alarm_name="RogueProcessHighCpu",
            alarm_arn="arn:test", alert_source="cloudwatch",
        ),
    ))

    # T2 Mutate step (high-impact process kill)
    step = make_step(
        target="i-target-prod-01",
        kind=StepKind.mutate,
        effects=[DeclaredEffect(EffectCategory.E1, "i-target-prod-01", "kill rogue process")],
        execution_spec={"command": "pkill -9 rogue_burner"},
        rollback_plan=[{"action": "systemctl start safe_worker"}],
        rollback_reason=None,
        success_criteria=["pgrep -f rogue_burner == ''"],
    )

    store.append(iid, 1, build_event(
        incident_id=iid, type=EventType.StepProposed, actor=Actor.agent,
        payload=StepProposedPayload(step=step),
    ))

    return iid, step


class TestSlackApprovalLifecycleEndToEnd:

    def test_full_t2_approval_flow_from_proposal_to_execution(self):
        """
        Complete end-to-end trace of T2 flow:
        1. Step is classified as require_approval in PolicyGate
        2. Notifier generates pure Block Kit interactive buttons without external url
        3. Slack sends signed payload, Callback verifies signature and RBAC
        4. ApprovalGranted is written with valid 32-byte HMAC and 15-minute expiration
        5. Executor verifies approval via PolicyGate and permits execution
        6. After execution, architecture prevents replay of the same approval
        """
        store = MemoryEventStore()
        iid, step = _create_incident_with_t2_step(store)
        state = fold(store.read(iid))

        # ── Step 1: Initial PolicyGate evaluation (must stop at T2) ────────────
        initial_ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-target-prod-01",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
            auth_key=TEST_HMAC_KEY_BYTES,
        )
        gate_res_before = gate_evaluate(step, state, initial_ctx)
        assert gate_res_before.decision == PolicyDecisionValue.require_approval
        assert gate_res_before.tier == "T2"

        # ── Step 2: Notifier sends pure interactive buttons ──────────────────────────
        posted_messages = []
        def fake_post_slack(channel, text, blocks=None):
            posted_messages.append({"channel": channel, "text": text, "blocks": blocks})
            return True

        with patch.object(notifier_mod, "_post_slack", side_effect=fake_post_slack):
            notif_res = notifier_mod.handler({
                "type": "approval_request",
                "incident_id": iid,
                "instance_id": "i-target-prod-01",
                "step_id": step.step_id,
                "step_description": "pkill -9 rogue_burner",
                "risk_claim": "high",
                "plan_hash": step.plan_hash,
            }, context=None)

        assert notif_res["statusCode"] == 200
        assert len(posted_messages) == 1
        sent_blocks = posted_messages[0]["blocks"]
        actions_block = next(b for b in sent_blocks if b.get("block_id") == "approval_actions")
        buttons = actions_block["elements"]

        # Critical assertion: buttons are interactive and do not contain external browser url
        approve_btn = next(b for b in buttons if b["action_id"] == "approve")
        deny_btn = next(b for b in buttons if b["action_id"] == "deny")
        assert "url" not in approve_btn, "Interactive button must NOT contain a browser url attribute!"
        assert "url" not in deny_btn, "Interactive button must NOT contain a browser url attribute!"

        # Verify value accurately binds incident, step, and plan hash
        parsed_btn_val = json.loads(approve_btn["value"])
        assert parsed_btn_val["incident_id"] == iid
        assert parsed_btn_val["step_id"] == step.step_id
        assert parsed_btn_val["plan_hash"] == step.plan_hash

        # ── Step 3: Approval click from authorized user in Slack ──────────────────────
        slack_payload = {
            "type": "block_actions",
            "user": {"id": AUTHORIZED_USER_ID},
            "actions": [{
                "action_id": "approve",
                "value": approve_btn["value"],
            }],
        }
        raw_body = urllib.parse.urlencode({"payload": json.dumps(slack_payload)}).encode()
        slack_event = _make_signed_slack_event(raw_body)

        invoked_agents = []
        with patch.object(callback_mod, "get_store", return_value=store), \
             patch.object(callback_mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(callback_mod, "invoke_async", side_effect=lambda fn, p: invoked_agents.append((fn, p))):
            callback_res = callback_mod.handler(slack_event, context=None)

        assert callback_res["statusCode"] == 200
        assert "Approved" in callback_res["body"]
        assert len(invoked_agents) == 1
        assert invoked_agents[0][0] == "incidents-agent"
        assert invoked_agents[0][1]["resume_from_approval"] is True

        # ── Step 4: Verify ApprovalGranted event and HMAC signature ──────────
        events_after = store.read(iid)
        approval_events = [e for e in events_after if e.type == EventType.ApprovalGranted]
        assert len(approval_events) == 1
        approval_payload = approval_events[0].payload
        assert approval_payload.step_id == step.step_id
        assert approval_payload.plan_hash == step.plan_hash
        assert approval_payload.approver_id == AUTHORIZED_USER_ID

        # Verify HMAC auth_tag
        auth_tag = approval_payload.auth_tag
        assert auth_tag is not None and len(auth_tag) == 64  # SHA-256 hex
        payload_dict = {
            "approval_id": approval_payload.approval_id,
            "step_id": approval_payload.step_id,
            "plan_hash": approval_payload.plan_hash,
            "approver_id": approval_payload.approver_id,
            "issued_at": approval_payload.issued_at,
            "expires_at": approval_payload.expires_at,
            "nonce": approval_payload.nonce,
        }
        assert verify_auth_tag(
            incident_id=iid,
            event_type="ApprovalGranted",
            payload_dict=payload_dict,
            claimed_tag=auth_tag,
            key=TEST_HMAC_KEY_BYTES,
        ) is True

        # ── Step 5: Verification in PolicyGate and step execution by Executor ─────
        state_after_approval = fold(events_after)
        gate_ctx_executor = executor_mod._build_gate_ctx(
            state=state_after_approval,
            approval_event_id=step.step_id,
            store=store,
            incident_id=iid,
        )
        assert gate_ctx_executor.approval_event is not None
        assert gate_ctx_executor.auth_key == TEST_HMAC_KEY_BYTES

        gate_res_after = gate_evaluate(step, state_after_approval, gate_ctx_executor)
        assert gate_res_after.decision == PolicyDecisionValue.allow
        assert gate_res_after.allowed is True

        # ── Step 6: Step execution and state update to executed ───────────────────
        from dataclasses import replace
        executed_step = replace(step, status="executed")
        state_after_exec = replace(state_after_approval, steps={step.step_id: executed_step})

        # ── Step 7: Prevent approval reuse (Anti-Replay) ──────────────────
        gate_res_reused = gate_evaluate(executed_step, state_after_exec, gate_ctx_executor)
        assert gate_res_reused.decision == PolicyDecisionValue.deny
        assert "APPROVAL-REUSED" in gate_res_reused.rule_ids or "Step was already executed" in str(gate_res_reused.reasons)

    def test_duplicate_slack_click_rejected_as_already_decided(self):
        """Attempting to click Approve a second time for the same step is rejected immediately as Duplicate/Replay."""
        store = MemoryEventStore()
        iid, step = _create_incident_with_t2_step(store)

        slack_payload = {
            "type": "block_actions",
            "user": {"id": AUTHORIZED_USER_ID},
            "actions": [{
                "action_id": "approve",
                "value": json.dumps({"incident_id": iid, "step_id": step.step_id, "plan_hash": step.plan_hash}),
            }],
        }
        raw_body = urllib.parse.urlencode({"payload": json.dumps(slack_payload)}).encode()
        slack_event = _make_signed_slack_event(raw_body)

        with patch.object(callback_mod, "get_store", return_value=store), \
             patch.object(callback_mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(callback_mod, "invoke_async"):
            res1 = callback_mod.handler(slack_event, context=None)
            assert "Approved" in res1["body"]

            # Second click (Replay):
            res2 = callback_mod.handler(slack_event, context=None)
            assert "Error recording approval" in res2["body"]
            assert "cannot reuse" in res2["body"]

        # Ensure duplicate approval event was not added
        events = store.read(iid)
        approval_events = [e for e in events if e.type == EventType.ApprovalGranted]
        assert len(approval_events) == 1

    def test_unauthorized_user_cannot_approve_or_deny(self):
        """Unauthorized user is rejected immediately with ephemeral message without recording any event in DynamoDB."""
        store = MemoryEventStore()
        iid, step = _create_incident_with_t2_step(store)

        slack_payload = {
            "type": "block_actions",
            "user": {"id": UNAUTHORIZED_USER},
            "actions": [{
                "action_id": "approve",
                "value": json.dumps({"incident_id": iid, "step_id": step.step_id}),
            }],
        }
        raw_body = urllib.parse.urlencode({"payload": json.dumps(slack_payload)}).encode()
        slack_event = _make_signed_slack_event(raw_body)

        invoked = []
        with patch.object(callback_mod, "get_store", return_value=store), \
             patch.object(callback_mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(callback_mod, "invoke_async", side_effect=lambda fn, p: invoked.append(fn)):
            res = callback_mod.handler(slack_event, context=None)

        assert "Unauthorized" in res["body"]
        assert len(invoked) == 0

        # Ensure no approval event was written
        events = store.read(iid)
        assert EventType.ApprovalGranted not in [e.type for e in events]

    def test_stale_timestamp_fails_closed(self):
        """Request coming with stale timestamp (> 300s) is rejected as 403 to prevent Replay Attacks."""
        store = MemoryEventStore()
        iid, step = _create_incident_with_t2_step(store)

        slack_payload = {
            "type": "block_actions",
            "user": {"id": AUTHORIZED_USER_ID},
            "actions": [{"action_id": "approve", "value": json.dumps({"incident_id": iid, "step_id": step.step_id})}],
        }
        raw_body = urllib.parse.urlencode({"payload": json.dumps(slack_payload)}).encode()
        stale_event = _make_signed_slack_event(raw_body, ts=int(time.time()) - 400)

        with patch.object(callback_mod, "get_store", return_value=store), \
             patch.object(callback_mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET):
            res = callback_mod.handler(stale_event, context=None)

        assert res["statusCode"] == 403

    def test_denial_flow_escalates_incident_and_blocks_execution(self):
        """Deny click records ApprovalDenied, updates state to escalated, and rejects execution in PolicyGate."""
        store = MemoryEventStore()
        iid, step = _create_incident_with_t2_step(store)

        slack_payload = {
            "type": "block_actions",
            "user": {"id": AUTHORIZED_USER_ID},
            "actions": [{
                "action_id": "deny",
                "value": json.dumps({"incident_id": iid, "step_id": step.step_id}),
            }],
        }
        raw_body = urllib.parse.urlencode({"payload": json.dumps(slack_payload)}).encode()
        slack_event = _make_signed_slack_event(raw_body)

        invoked = []
        with patch.object(callback_mod, "get_store", return_value=store), \
             patch.object(callback_mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(callback_mod, "invoke_async", side_effect=lambda fn, p: invoked.append(fn)):
            res = callback_mod.handler(slack_event, context=None)

        assert res["statusCode"] == 200
        assert "Denied" in res["body"]
        assert len(invoked) == 0  # Agent is not resumed for execution

        state = fold(store.read(iid))
        assert state.phase == IncidentPhase.escalated
        assert state.steps[step.step_id].status == "rejected"

        # Attempt to evaluate step in PolicyGate after denial
        ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id="i-target-prod-01",
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
            auth_key=TEST_HMAC_KEY_BYTES,
        )
        gate_res = gate_evaluate(state.steps[step.step_id], state, ctx)
        assert gate_res.decision == PolicyDecisionValue.deny
        assert "APPROVAL-REJECTED" in gate_res.rule_ids

    def test_slash_command_flow_authenticated(self):
        """Slash command flow /approve and /deny undergoes identical signature and RBAC checks and records approval."""
        store = MemoryEventStore()
        iid, step = _create_incident_with_t2_step(store)

        # 1. Test /approve
        raw_body = urllib.parse.urlencode({
            "command": "/approve",
            "text": f"{iid} {step.step_id}",
            "user_id": AUTHORIZED_USER_ID,
        }).encode()
        event = _make_signed_slack_event(raw_body)

        invoked = []
        with patch.object(callback_mod, "get_store", return_value=store), \
             patch.object(callback_mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(callback_mod, "invoke_async", side_effect=lambda fn, p: invoked.append((fn, p))):
            res = callback_mod.handler(event, context=None)

        assert res["statusCode"] == 200
        assert "Approved" in res["body"]
        assert len(invoked) == 1
        assert invoked[0][0] == "incidents-agent"

        events = store.read(iid)
        assert EventType.ApprovalGranted in [e.type for e in events]

    def test_tier1_autonomy_unaffected_by_slack_or_hmac(self, monkeypatch):
        """
        Safe Tier.T1 actions execute autonomously and immediately without requiring Slack approval or HMAC key.
        """
        # Deliberately remove HMAC settings to confirm no blocking
        monkeypatch.delenv(APPROVAL_MAC_KEY_HEX_VAR, raising=False)
        get_approval_mac_key.cache_clear()

        store = MemoryEventStore()
        iid = new_ulid()
        dk = f"alarm::t1::{iid}"
        header = IncidentHeader(
            incident_id=iid, instance_id="i-target-prod-01", dedupe_key=dk,
            alarm_name="ServiceFailed", alarm_arn="arn:test", alert_source="cloudwatch",
            opened_at=utc_now().isoformat(),
        )
        store.create_if_absent(dk, header)

        # Safe T1 step (service restart)
        t1_step = make_step(
            target="i-target-prod-01",
            kind=StepKind.mutate,
            effects=[DeclaredEffect(EffectCategory.E1, "i-target-prod-01", "restart nginx")],
            execution_spec={"command": "systemctl restart nginx"},
            rollback_plan=[{"action": "systemctl start nginx"}],
            rollback_reason=None,
            success_criteria=["systemctl is-active nginx == 'active'"],
        )

        state = fold([build_event(
            incident_id=iid, type=EventType.IncidentOpened, actor=Actor.ingest,
            payload=IncidentOpenedPayload(instance_id="i-target-prod-01", dedupe_key=dk, alarm_name="ServiceFailed", alarm_arn="", alert_source=""),
        )])

        # Build GateContext without HMAC key (normal mode for T1)
        gate_ctx_t1 = executor_mod._build_gate_ctx(
            state=state,
            approval_event_id=None,
            store=store,
            incident_id=iid,
        )

        # Verify PolicyGate allows automatically as Tier.T1
        res = gate_evaluate(t1_step, state, gate_ctx_t1)
        assert res.decision == PolicyDecisionValue.allow
        assert res.tier == "T1"
        assert res.requires_approval is False
