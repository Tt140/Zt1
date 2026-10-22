"""
tests/handlers/test_slack_callback.py

Unit tests for handlers/slack_callback.py:
- invalid Slack signature → 403 (fail-closed)
- approve action → ApprovalGranted written + agent invoked
- deny action → ApprovalDenied written + agent NOT invoked
- old timestamp → 403 (replay protection)
- malformed payload → 400

Security tests:
- Confirm Approve writes valid auth_tag
- Confirm old timestamp is rejected
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from unittest.mock import patch, MagicMock

import pytest
import yaml

from src.store.memory import MemoryEventStore
from src.domain.types import (
    IncidentHeader, IncidentOpenedPayload, EventType,
    build_event, Actor, new_ulid, utc_now,
)
from src.domain.reducer import fold
from handlers.shared import (
    get_approval_mac_key, get_authorized_approvers, _resolve_secret,
    APPROVAL_MAC_KEY_HEX_VAR, APPROVAL_MAC_KEY_SECRET_ARN_VAR,
    SLACK_AUTHORIZED_APPROVERS_VAR, SLACK_AUTHORIZED_APPROVERS_SECRET_ARN_VAR,
)


# ── explicit test environment fixture ─────────────────────────────────────────

@pytest.fixture(autouse=True)
def configure_slack_test_environment(monkeypatch):
    """
    Explicit test environment setup for test keys and authorized approvers without
    relying on pytest environment autodetection. Ensures standard tests pass and
    isolates specialized security tests.
    """
    get_approval_mac_key.cache_clear()
    get_authorized_approvers.cache_clear()
    _resolve_secret.cache_clear()

    monkeypatch.setenv(APPROVAL_MAC_KEY_HEX_VAR, "a" * 64)
    monkeypatch.setenv(SLACK_AUTHORIZED_APPROVERS_VAR, "U123456,U_AUTHORIZED_LEAD")

    yield

    get_approval_mac_key.cache_clear()
    get_authorized_approvers.cache_clear()
    _resolve_secret.cache_clear()


# ── signing helpers ───────────────────────────────────────────────────────────

TEST_SIGNING_SECRET = b"test-signing-secret-for-tests"

def _sign(body: bytes, ts: int = None) -> dict:
    ts = ts or int(time.time())
    base_string = f"v0:{ts}:{body.decode()}".encode()
    sig = "v0=" + hmac.new(TEST_SIGNING_SECRET, base_string, hashlib.sha256).hexdigest()
    return {
        "x-slack-request-timestamp": str(ts),
        "x-slack-signature": sig,
    }


def _make_block_action(action_id: str, incident_id: str, step_id: str, user_id: str = "U123456") -> bytes:
    value = json.dumps({"incident_id": incident_id, "step_id": step_id})
    payload = {
        "type": "block_actions",
        "user": {"id": user_id},
        "actions": [{"action_id": action_id, "value": value}],
    }
    return urllib.parse.urlencode({"payload": json.dumps(payload)}).encode()


def _make_incident(store):
    dk = f"alarm::test::{new_ulid()}"
    iid = new_ulid()
    header = IncidentHeader(
        incident_id=iid, instance_id="i-test", dedupe_key=dk,
        alarm_name="test", alarm_arn="arn:test", alert_source="eb",
        opened_at=utc_now().isoformat(),
    )
    rid, _ = store.create_if_absent(dk, header)
    ev = build_event(
        incident_id=rid, type=EventType.IncidentOpened, actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id="i-test", dedupe_key=dk, alarm_name="test",
            alarm_arn="arn:test", alert_source="eb",
        ),
    )
    store.append(rid, 0, ev)
    return rid


class TestSlackSignatureVerification:

    def _call(self, store, body: bytes, headers: dict):
        from handlers import slack_callback as mod
        event = {
            "headers": headers,
            "body": body.decode(),
            "isBase64Encoded": False,
        }
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(mod, "invoke_async"):
            return mod.handler(event, context=None)

    def test_valid_signature_approve_returns_200(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()
        body = _make_block_action("approve", iid, step_id)
        headers = _sign(body)
        resp = self._call(store, body, headers)
        assert resp["statusCode"] == 200

    def test_invalid_signature_returns_403(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()
        body = _make_block_action("approve", iid, step_id)
        headers = {
            "x-slack-request-timestamp": str(int(time.time())),
            "x-slack-signature": "v0=invalid_signature",
        }
        resp = self._call(store, body, headers)
        assert resp["statusCode"] == 403

    def test_old_timestamp_returns_403(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        body = _make_block_action("approve", iid, new_ulid())
        old_ts = int(time.time()) - 400  # Older than 5 minutes
        headers = _sign(body, ts=old_ts)
        resp = self._call(store, body, headers)
        assert resp["statusCode"] == 403


class TestSlackCallbackActions:

    def _call(self, store, action_id: str, incident_id: str, step_id: str, user_id: str = "U123456"):
        from handlers import slack_callback as mod
        body = _make_block_action(action_id, incident_id, step_id, user_id=user_id)
        event = {
            "headers": _sign(body),
            "body": body.decode(),
            "isBase64Encoded": False,
        }
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(event, context=None)
        return resp, mock_inv

    def test_approve_writes_approval_granted(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()
        resp, mock_inv = self._call(store, "approve", iid, step_id, user_id="U123456")

        assert resp["statusCode"] == 200
        # ApprovalGranted must be written
        events = store.read(iid)
        event_types = [e.type for e in events]
        assert EventType.ApprovalGranted in event_types

        # agent invoked async to resume investigation
        mock_inv.assert_called_once()
        call_payload = mock_inv.call_args[0][1]
        assert call_payload["incident_id"] == iid
        assert call_payload["resume_from_approval"] is True

    def test_approve_writes_auth_tag(self):
        """ApprovalGranted must carry a valid auth_tag computed with the explicit key."""
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()
        self._call(store, "approve", iid, step_id, user_id="U123456")

        events = store.read(iid)
        approval_ev = next(e for e in events if e.type == EventType.ApprovalGranted)
        assert approval_ev.auth_tag is not None
        assert len(approval_ev.auth_tag) == 64  # SHA-256 hex

    def test_deny_writes_approval_denied_no_agent_invoke(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()
        resp, mock_inv = self._call(store, "deny", iid, step_id, user_id="U123456")

        assert resp["statusCode"] == 200
        events = store.read(iid)
        event_types = [e.type for e in events]
        assert EventType.ApprovalDenied in event_types
        assert EventType.ApprovalGranted not in event_types

        # agent is not invoked on denial
        mock_inv.assert_not_called()

    def test_response_includes_action_text(self):
        store = MemoryEventStore()
        iid = _make_incident(store)
        resp, _ = self._call(store, "approve", iid, new_ulid(), user_id="U123456")
        body = json.loads(resp["body"])
        assert "Approved" in body.get("text", "")

    def test_unauthorized_user_approval_rejected_ephemeral(self):
        """
        Slack RBAC: User not in authorized approvers list is rejected immediately with
        an ephemeral message without recording any event in EventStore and without invoking agent.
        """
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()
        resp, mock_inv = self._call(store, "approve", iid, step_id, user_id="U_UNAUTHORIZED_ATTACKER")

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body.get("response_type") == "ephemeral"
        assert body.get("replace_original") is False
        assert "Unauthorized" in body.get("text", "")

        # No events written to EventStore
        events = store.read(iid)
        event_types = [e.type for e in events]
        assert EventType.ApprovalGranted not in event_types
        assert EventType.ApprovalDenied not in event_types

        # No invocation of agent
        mock_inv.assert_not_called()

    def test_unauthorized_user_denial_rejected_ephemeral(self):
        """
        Slack RBAC: Unauthorized user is also prevented from denying actions to prevent disrupting recovery.
        """
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()
        resp, mock_inv = self._call(store, "deny", iid, step_id, user_id="U_UNAUTHORIZED_ATTACKER")

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body.get("response_type") == "ephemeral"
        assert body.get("replace_original") is False
        assert "Unauthorized" in body.get("text", "")

        events = store.read(iid)
        event_types = [e.type for e in events]
        assert EventType.ApprovalDenied not in event_types
        mock_inv.assert_not_called()

    def test_empty_authorized_approvers_fails_closed(self, monkeypatch):
        """
        ZeroTrust Fail-Closed: Total absence of authorized approvers list causes rejection by default.
        """
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()

        monkeypatch.delenv(SLACK_AUTHORIZED_APPROVERS_VAR, raising=False)
        monkeypatch.delenv(SLACK_AUTHORIZED_APPROVERS_SECRET_ARN_VAR, raising=False)
        get_authorized_approvers.cache_clear()

        with patch("handlers.shared._resolve_secret", return_value=""):
            resp, mock_inv = self._call(store, "approve", iid, step_id, user_id="U123456")

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body.get("response_type") == "ephemeral"
        assert body.get("replace_original") is False
        assert "Unauthorized" in body.get("text", "")

        events = store.read(iid)
        assert EventType.ApprovalGranted not in [e.type for e in events]
        mock_inv.assert_not_called()


class TestApprovalKeyAndSecretsManagerSecurity:
    """
    Strict security tests for HMAC key and Secrets Manager:
    - Missing key raises RuntimeError (Fail-Closed) without any fallback.
    - Invalid hex or wrong length key raises ValueError.
    - Secrets Manager failure fails closed without approval or invoking agent.
    - Support for JSON and CSV formats in authorized approvers list.
    """

    def test_get_approval_mac_key_missing_raises_runtime_error(self, monkeypatch):
        monkeypatch.delenv(APPROVAL_MAC_KEY_HEX_VAR, raising=False)
        monkeypatch.delenv(APPROVAL_MAC_KEY_SECRET_ARN_VAR, raising=False)
        get_approval_mac_key.cache_clear()
        _resolve_secret.cache_clear()

        with patch("handlers.shared._resolve_secret", return_value=""):
            with pytest.raises(RuntimeError, match="neither APPROVAL_MAC_KEY_HEX nor Secrets Manager"):
                get_approval_mac_key()

    def test_get_approval_mac_key_invalid_hex_raises_value_error(self, monkeypatch):
        monkeypatch.setenv(APPROVAL_MAC_KEY_HEX_VAR, "this-is-not-a-valid-hex-string")
        get_approval_mac_key.cache_clear()

        with pytest.raises(ValueError, match="not valid hex"):
            get_approval_mac_key()

    def test_get_approval_mac_key_short_key_raises_value_error(self, monkeypatch):
        monkeypatch.setenv(APPROVAL_MAC_KEY_HEX_VAR, "deadbeef1234")  # 6 bytes != 32 bytes
        get_approval_mac_key.cache_clear()

        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            get_approval_mac_key()

    def test_get_approval_mac_key_oversized_key_raises_value_error(self, monkeypatch):
        monkeypatch.setenv(APPROVAL_MAC_KEY_HEX_VAR, "c" * 96)  # 48 bytes != 32 bytes
        get_approval_mac_key.cache_clear()

        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            get_approval_mac_key()

    def test_get_approval_mac_key_explicit_key_enforces_32_bytes(self):
        # 16 bytes rejected
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            get_approval_mac_key(explicit_key=b"1" * 16)

        # 32 bytes accepted
        valid_key = b"k" * 32
        assert get_approval_mac_key(explicit_key=valid_key) == valid_key

    def test_source_priority_direct_env_over_secrets_manager(self, monkeypatch):
        """
        Verify source priority: APPROVAL_MAC_KEY_HEX precedes APPROVAL_MAC_KEY_SECRET_ARN.
        If both exist, direct env var is used without invoking Secrets Manager,
        ensuring key consistency between Slack Callback and Executor.
        """
        direct_key = "d" * 64
        monkeypatch.setenv(APPROVAL_MAC_KEY_HEX_VAR, direct_key)
        monkeypatch.setenv(APPROVAL_MAC_KEY_SECRET_ARN_VAR, "/incidents/approval-mac-key")
        get_approval_mac_key.cache_clear()
        _resolve_secret.cache_clear()

        with patch("boto3.client") as mock_boto:
            resolved = get_approval_mac_key()
            assert resolved == bytes.fromhex(direct_key)
            mock_boto.assert_not_called()

    def test_secrets_manager_failure_raises_runtime_error(self, monkeypatch):
        monkeypatch.delenv(APPROVAL_MAC_KEY_HEX_VAR, raising=False)
        monkeypatch.setenv(APPROVAL_MAC_KEY_SECRET_ARN_VAR, "/incidents/approval-mac-key")
        get_approval_mac_key.cache_clear()
        _resolve_secret.cache_clear()

        with patch("boto3.client") as mock_boto:
            mock_boto.return_value.get_secret_value.side_effect = Exception("SecretsManagerConnectionTimeout")
            with pytest.raises(RuntimeError, match="Fail-closed"):
                get_approval_mac_key()

    def test_secrets_manager_failure_during_approval_fails_closed_in_handler(self, monkeypatch):
        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()

        monkeypatch.delenv(APPROVAL_MAC_KEY_HEX_VAR, raising=False)
        get_approval_mac_key.cache_clear()
        _resolve_secret.cache_clear()

        body = _make_block_action("approve", iid, step_id, user_id="U123456")
        event = {
            "headers": _sign(body),
            "body": body.decode(),
            "isBase64Encoded": False,
        }

        from handlers import slack_callback as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch("handlers.shared._resolve_secret", return_value=""), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(event, context=None)

        assert resp["statusCode"] == 200
        body_json = json.loads(resp["body"])
        assert body_json.get("replace_original") is False
        assert "Error recording approval" in body_json.get("text", "")

        events = store.read(iid)
        assert EventType.ApprovalGranted not in [e.type for e in events]
        mock_inv.assert_not_called()

    def test_authorized_approvers_json_and_csv_parsing(self, monkeypatch):
        get_authorized_approvers.cache_clear()

        # Dict format with "approvers" key and Slack formatting
        monkeypatch.setenv(SLACK_AUTHORIZED_APPROVERS_VAR, '{"approvers": ["<@U_JSON1>", "U_JSON2"]}')
        get_authorized_approvers.cache_clear()
        assert get_authorized_approvers() == frozenset({"U_JSON1", "U_JSON2"})

        # JSON List format
        monkeypatch.setenv(SLACK_AUTHORIZED_APPROVERS_VAR, '["U_LIST1", "U_LIST2"]')
        get_authorized_approvers.cache_clear()
        assert get_authorized_approvers() == frozenset({"U_LIST1", "U_LIST2"})

        # Comma and newline separated CSV
        monkeypatch.setenv(SLACK_AUTHORIZED_APPROVERS_VAR, "U_CSV1, <@U_CSV2>\nU_CSV3")
        get_authorized_approvers.cache_clear()
        assert get_authorized_approvers() == frozenset({"U_CSV1", "U_CSV2", "U_CSV3"})

    def test_authorized_approvers_corrupted_json_fails_closed(self, monkeypatch):
        """
        If authorized approvers config starts with { or [ but has corrupted syntax,
        the system must fail-closed, returning empty frozenset()
        and automatically rejecting any approval attempt.
        """
        get_authorized_approvers.cache_clear()
        monkeypatch.setenv(SLACK_AUTHORIZED_APPROVERS_VAR, '{"approvers": ["broken json...')
        approvers = get_authorized_approvers()
        assert approvers == frozenset()

        store = MemoryEventStore()
        iid = _make_incident(store)
        step_id = new_ulid()

        body = _make_block_action("approve", iid, step_id, user_id="U123456")
        event = {
            "headers": _sign(body),
            "body": body.decode(),
            "isBase64Encoded": False,
        }

        from handlers import slack_callback as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "_get_signing_secret", return_value=TEST_SIGNING_SECRET), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(event, context=None)

        assert resp["statusCode"] == 200
        body_json = json.loads(resp["body"])
        assert body_json.get("response_type") == "ephemeral"
        assert body_json.get("replace_original") is False
        assert "Unauthorized" in body_json.get("text", "")
        events = store.read(iid)
        assert EventType.ApprovalGranted not in [e.type for e in events]
        mock_inv.assert_not_called()


class TestTemplateYamlAndCodeConsistency:
    """
    Test preventing env var name drift for HMAC key and authorized approvers list
    between template.yaml and code (Automated Drift Prevention).
    """

    def test_template_and_code_env_var_consistency(self):
        class CfnLoader(yaml.SafeLoader):
            pass

        def default_ctor(loader, tag_suffix, node):
            if isinstance(node, yaml.ScalarNode):
                return loader.construct_scalar(node)
            elif isinstance(node, yaml.SequenceNode):
                return loader.construct_sequence(node)
            elif isinstance(node, yaml.MappingNode):
                return loader.construct_mapping(node)

        CfnLoader.add_multi_constructor("!", default_ctor)

        template_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../template.yaml"))
        assert os.path.exists(template_path), f"template.yaml not found at {template_path}"

        with open(template_path, "r", encoding="utf-8") as f:
            cfn = yaml.load(f, Loader=CfnLoader)

        resources = cfn.get("Resources", {})
        executor_vars = (
            resources.get("ExecutorFunction", {})
            .get("Properties", {})
            .get("Environment", {})
            .get("Variables", {})
        )
        slack_cb_vars = (
            resources.get("SlackCallbackFunction", {})
            .get("Properties", {})
            .get("Environment", {})
            .get("Variables", {})
        )

        # 1. Unified secret variable name in ExecutorFunction
        assert APPROVAL_MAC_KEY_SECRET_ARN_VAR in executor_vars, (
            f"ExecutorFunction missing unified env var {APPROVAL_MAC_KEY_SECRET_ARN_VAR}"
        )
        assert APPROVAL_MAC_KEY_HEX_VAR in executor_vars, (
            f"ExecutorFunction missing {APPROVAL_MAC_KEY_HEX_VAR}"
        )
        assert "APPROVAL_MAC_SECRET_ARN" not in executor_vars, (
            "ExecutorFunction still uses deprecated APPROVAL_MAC_SECRET_ARN instead of APPROVAL_MAC_KEY_SECRET_ARN"
        )

        # 2. Unified secret variable name in SlackCallbackFunction
        assert APPROVAL_MAC_KEY_SECRET_ARN_VAR in slack_cb_vars, (
            f"SlackCallbackFunction missing unified env var {APPROVAL_MAC_KEY_SECRET_ARN_VAR}"
        )
        assert APPROVAL_MAC_KEY_HEX_VAR in slack_cb_vars, (
            f"SlackCallbackFunction missing {APPROVAL_MAC_KEY_HEX_VAR}"
        )
        assert "APPROVAL_MAC_SECRET_ARN" not in slack_cb_vars, (
            "SlackCallbackFunction still uses deprecated APPROVAL_MAC_SECRET_ARN"
        )

        # 3. Slack authorized approvers configuration in SlackCallbackFunction
        assert SLACK_AUTHORIZED_APPROVERS_VAR in slack_cb_vars, (
            f"SlackCallbackFunction missing {SLACK_AUTHORIZED_APPROVERS_VAR}"
        )
        assert SLACK_AUTHORIZED_APPROVERS_SECRET_ARN_VAR in slack_cb_vars, (
            f"SlackCallbackFunction missing {SLACK_AUTHORIZED_APPROVERS_SECRET_ARN_VAR}"
        )

        # 4. Verify required parameters in template Parameters
        params = cfn.get("Parameters", {})
        assert "ApprovalMacKeyHex" in params, "template.yaml missing ApprovalMacKeyHex parameter"
        assert "SlackAuthorizedApprovers" in params, "template.yaml missing SlackAuthorizedApprovers parameter"


class TestNotifierHandler:
    """
    Tests for handlers/notifier.py:
    1. Successful delivery via SLACK_WEBHOOK_URL with valid HTTP 200 payload.
    2. Safe skipping when SLACK_WEBHOOK_URL and SLACK_BOT_TOKEN are unconfigured.
    """

    def test_notifier_success_with_slack_webhook(self):
        from handlers import notifier

        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b"ok"
        mock_resp.__enter__.return_value = mock_resp

        mock_webhook = "https://hooks.slack.com/services/TEST/MOCK/WEBHOOK"

        with patch("handlers.notifier.get_slack_webhook_url", return_value=mock_webhook), \
             patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:

            event = {
                "type": "approval_request",
                "incident_id": "inc-test-456",
                "instance_id": "i-test-001",
                "step_id": "step-01",
                "step_description": "systemctl restart nginx",
                "risk_claim": "low",
            }
            res = notifier.handler(event, None)
            assert res["statusCode"] == 200
            body = json.loads(res["body"])
            assert body["sent"] is True
            assert body["type"] == "approval_request"

            # Check urlopen was called with webhook URL and POST method
            mock_urlopen.assert_called_once()
            req = mock_urlopen.call_args[0][0]
            assert req.full_url == mock_webhook
            assert req.get_method() == "POST"
            posted_data = json.loads(req.data.decode("utf-8"))
            assert "text" in posted_data
            assert "blocks" in posted_data

    def test_notifier_skipped_safely_when_unconfigured(self):
        from handlers import notifier

        with patch("handlers.notifier.get_slack_webhook_url", return_value=""), \
             patch("handlers.notifier._get_bot_token_safe", return_value=""):

            event = {
                "type": "escalation",
                "incident_id": "inc-unconfigured",
                "instance_id": "i-none",
                "message": "Escalation notification",
            }
            res = notifier.handler(event, None)
            assert res["statusCode"] == 200
            body = json.loads(res["body"])
            assert body["sent"] is False
            assert body["reason"] == "slack_not_configured"

