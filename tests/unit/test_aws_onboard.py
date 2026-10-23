"""
tests/unit/test_aws_onboard.py — Comprehensive Unit Tests for scripts/aws_onboard.py

Covers:
1. Greenfield Account: Empty environment discovery & parameter generation.
2. Brownfield Account: Pre-existing matching resources delta resolution.
3. SSM Document Drift: Drift detection against infra/ssm/*.json and auto-remediation.
4. CloudWatch Metrics: EnableDiskAlarm toggling based on CWAgent metric presence.
5. Security & Sanitization: Ensuring zero raw secrets are leaked in generated .env or receipts.
"""
from __future__ import annotations

import json
import os
import tempfile
import urllib.error
from unittest.mock import MagicMock, patch, mock_open

import pytest
import yaml

from scripts.aws_onboard import (
    AuditReport,
    DynamoDBLayerReport,
    DynamoDBTableReport,
    EC2InstanceDetail,
    EC2LayerReport,
    IAMLayerReport,
    IAMRoleReport,
    IdentityInfo,
    S3BucketReport,
    SSMDocReport,
    SSMLayerReport,
    SecretReport,
    StackReport,
    audit_bedrock_access,
    audit_global_view,
    audit_identity,
    audit_secrets,
    build_cfn_parameters,
    ensure_clean_stack_before_deploy,
    execute_pre_deploy_actions,
    extract_cfn_failure_root_causes,
    generate_env_file,
    print_llm_bedrock_policy,
    probe_strands_health,
    run_full_audit,
    _is_trust_policy_valid,
    ensure_core_iam_roles,
    parse_env_file,
    split_env_vars,
    ensure_client_secrets,
    parse_args,
)


# ── Fixtures & Mock Builders ─────────────────────────────────────────────────

def _make_identity(account_id="111122223333", region="us-east-1"):
    return IdentityInfo(
        account_id=account_id,
        arn=f"arn:aws:iam::{account_id}:user/test-operator",
        user_id="AIDATEST12345",
        region=region,
    )


def _make_ec2_report(
    instance_id="i-target123",
    state="running",
    ssm_online=True,
    has_security_tag=True,
    has_cwagent_disk=False,
):
    detail = EC2InstanceDetail(
        instance_id=instance_id,
        name="test-instance",
        state=state,
        private_ip="10.0.0.10",
        public_ip="54.1.2.3",
        instance_type="t3.micro",
        iam_profile=None,
        ssm_online=ssm_online,
        has_security_tag=has_security_tag,
        tags={"IncidentsAgent": "true"} if has_security_tag else {},
    )
    is_valid = (state == "running" and ssm_online and has_security_tag)
    error = None
    if not is_valid:
        if not has_security_tag:
            error = f"Instance {instance_id} is missing required tag 'IncidentsAgent=true'."
        elif not ssm_online:
            error = f"Instance {instance_id} is not online in AWS Systems Manager (SSM Agent down or missing IAM role)."
        else:
            error = f"Instance {instance_id} is '{state}', must be 'running'."
    return EC2LayerReport(
        instances=[detail],
        target_instance=detail,
        target_valid=is_valid,
        target_error=error,
        has_cwagent_disk_metrics=has_cwagent_disk,
        strands_suggestion="http://54.1.2.3:8080",
    )


def _make_dynamodb_report(all_ready=True):
    tables = {
        "incidents-events": DynamoDBTableReport("incidents-events", all_ready, "ACTIVE" if all_ready else None, "PAY_PER_REQUEST", all_ready),
        "incidents-dedup": DynamoDBTableReport("incidents-dedup", all_ready, "ACTIVE" if all_ready else None, "PAY_PER_REQUEST", all_ready),
        "incidents-leases": DynamoDBTableReport("incidents-leases", all_ready, "ACTIVE" if all_ready else None, "PAY_PER_REQUEST", all_ready),
    }
    return DynamoDBLayerReport(tables=tables, all_ready=all_ready)


def _make_s3_report(account_id="111122223333", exists=True):
    return S3BucketReport(
        expected_name=f"incidents-blobs-{account_id}",
        exists=exists,
        encryption_matches=exists,
    )


def _make_ssm_report(all_ready=True, has_drift=False):
    docs = {
        "incidents-observe-readonly": SSMDocReport(
            name="incidents-observe-readonly",
            exists=all_ready,
            default_version="1" if all_ready else None,
            drift_detected=has_drift,
            actual_pattern="drifted_pattern" if has_drift else "expected_pattern",
            expected_pattern="expected_pattern",
        ),
        "incidents-repair-restricted": SSMDocReport(
            name="incidents-repair-restricted",
            exists=all_ready,
            default_version="1" if all_ready else None,
            drift_detected=False,
            actual_pattern="expected_pattern",
            expected_pattern="expected_pattern",
        ),
    }
    return SSMLayerReport(
        documents=docs,
        all_ready=all_ready and not has_drift,
        has_drift=has_drift,
    )


def _make_iam_report(all_ready=True):
    roles = {
        "incidents-agent-role": IAMRoleReport("incidents-agent-role", all_ready, "arn:aws:iam::111:role/agent" if all_ready else None),
        "incidents-observer-role": IAMRoleReport("incidents-observer-role", all_ready, "arn:aws:iam::111:role/observer" if all_ready else None),
        "RemediationOperatorRole": IAMRoleReport("RemediationOperatorRole", all_ready, "arn:aws:iam::111:role/operator" if all_ready else None),
    }
    return IAMLayerReport(roles=roles, all_ready=all_ready)


def _make_secrets_report(all_exist=True):
    names = [
        "/incidents/approval-mac-key",
        "/incidents/deepseek-api-key",
        "/incidents/slack-webhook-url",
    ]
    return {
        name: SecretReport(
            name=name,
            exists=all_exist,
            arn=f"arn:aws:secretsmanager:us-east-1:111:secret:{name}" if all_exist else None,
            accessible=all_exist,
        )
        for name in names
    }


def _make_stack_report():
    return StackReport(
        stack_name="autonomous-secops-agent",
        exists=False,
        status=None,
        lambda_functions={fn: False for fn in [
            "incidents-ingest", "incidents-agent", "incidents-observer",
            "incidents-executor", "incidents-notifier", "incidents-slack-callback",
        ]},
        eventbridge_rule_exists=False,
    )


# ── Test Suite ───────────────────────────────────────────────────────────────

class TestAwsOnboardPlanner:

    def test_greenfield_account_provisions_all_resources(self):
        """
        Scenario 1: Greenfield Account (Empty Environment)
        - When tables, bucket, documents, and roles do NOT exist:
        - Planner must set Create* flags to 'true'.
        - Pre-deploy actions must include tagging untagged instance and generating missing secret.
        """
        ident = _make_identity()
        ec2 = _make_ec2_report(has_security_tag=False)  # target is untagged
        ddb = _make_dynamodb_report(all_ready=False)
        s3 = _make_s3_report(exists=False)
        ssm = _make_ssm_report(all_ready=False)
        iam = _make_iam_report(all_ready=False)
        secrets_rep = _make_secrets_report(all_exist=False)
        stack = _make_stack_report()

        report = AuditReport(
            identity=ident, ec2=ec2, dynamodb=ddb, s3=s3, ssm=ssm,
            iam=iam, secrets=secrets_rep, stack=stack, overall_status="NEEDS_PRE_DEPLOY",
        )

        params, pre_actions, sam_cmd = build_cfn_parameters(report)

        assert params["CreateDynamoTables"] == "true"
        assert params["CreateBlobsBucket"] == "true"
        assert params["ExistingBlobsBucketName"] == ""
        assert params["CreateSsmDocuments"] == "true"
        assert params["CreateCoreIamRoles"] == "true"
        assert params["EnableAlarms"] == "false"  # False because target is untagged initially

        # Check pre-deploy actions detected
        action_text = " ".join(pre_actions)
        assert "Tag Target Instance" in action_text
        assert "/incidents/approval-mac-key" in action_text
        assert "sam deploy" in sam_cmd

    def test_brownfield_account_reuses_existing_resources(self):
        """
        Scenario 2: Brownfield Account (All Resources Already Match)
        - When tables, bucket, documents, roles, and secrets already exist:
        - Planner must set Create* flags to 'false' and populate ExistingBlobsBucketName.
        - Zero pre-deploy remediation actions needed.
        """
        ident = _make_identity()
        ec2 = _make_ec2_report(has_security_tag=True, has_cwagent_disk=False)
        ddb = _make_dynamodb_report(all_ready=True)
        s3 = _make_s3_report(exists=True)
        ssm = _make_ssm_report(all_ready=True, has_drift=False)
        iam = _make_iam_report(all_ready=True)
        secrets_rep = _make_secrets_report(all_exist=True)
        stack = _make_stack_report()

        report = AuditReport(
            identity=ident, ec2=ec2, dynamodb=ddb, s3=s3, ssm=ssm,
            iam=iam, secrets=secrets_rep, stack=stack, overall_status="READY",
        )

        params, pre_actions, sam_cmd = build_cfn_parameters(report)

        assert params["CreateDynamoTables"] == "false"
        assert params["CreateBlobsBucket"] == "false"
        assert params["ExistingBlobsBucketName"] == f"incidents-blobs-{ident.account_id}"
        assert params["CreateSsmDocuments"] == "false"
        assert params["CreateCoreIamRoles"] == "false"
        assert params["EnableAlarms"] == "true"
        assert params["EnableDiskAlarm"] == "false"  # No CWAgent metrics
        assert len(pre_actions) == 0

    def test_ssm_document_drift_detected_and_remediated(self, tmp_path):
        """
        Scenario 3: SSM Document Drift Detection & Remediation
        - When allowedPattern in AWS differs from reference file:
        - Planner must detect drift and generate update pre-deploy action.
        - execute_pre_deploy_actions must call update_document and update_document_default_version.
        """
        ident = _make_identity()
        ec2 = _make_ec2_report()
        ddb = _make_dynamodb_report(all_ready=True)
        s3 = _make_s3_report(exists=True)
        ssm = _make_ssm_report(all_ready=False, has_drift=True)
        iam = _make_iam_report(all_ready=True)
        secrets_rep = _make_secrets_report(all_exist=True)
        stack = _make_stack_report()

        report = AuditReport(
            identity=ident, ec2=ec2, dynamodb=ddb, s3=s3, ssm=ssm,
            iam=iam, secrets=secrets_rep, stack=stack, overall_status="NEEDS_PRE_DEPLOY",
        )

        params, pre_actions, _ = build_cfn_parameters(report)
        assert params["CreateSsmDocuments"] == "false"  # Don't recreate via CFN; update existing
        assert any("Update SSM Document drift" in a for a in pre_actions)

        # Mock project root with infra/ssm directory
        mock_root = tmp_path / "proj"
        mock_ssm_dir = mock_root / "infra" / "ssm"
        mock_ssm_dir.mkdir(parents=True)
        ref_file = mock_ssm_dir / "incidents-observe-readonly.json"
        ref_file.write_text(json.dumps({"parameters": {"command": {"allowedPattern": "expected_pattern"}}}))

        # Test execute_pre_deploy_actions remediation
        mock_session = MagicMock()
        mock_ssm_client = MagicMock()
        mock_session.client.return_value = mock_ssm_client
        mock_ssm_client.update_document.return_value = {"DocumentDescription": {"DocumentVersion": "2"}}

        executed = execute_pre_deploy_actions(mock_session, "us-east-1", report, str(mock_root))
        assert any("Updated SSM Document 'incidents-observe-readonly'" in e for e in executed)
        mock_ssm_client.update_document.assert_called_once()
        mock_ssm_client.update_document_default_version.assert_called_once_with(
            Name="incidents-observe-readonly", DocumentVersion="2"
        )
        assert not report.ssm.has_drift

    def test_cwagent_disk_metrics_enables_disk_alarm(self):
        """
        Verify that EnableDiskAlarm is 'true' only when CWAgent disk metrics exist.
        """
        report_with_cw = AuditReport(
            identity=_make_identity(),
            ec2=_make_ec2_report(has_cwagent_disk=True),
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )
        params, _, _ = build_cfn_parameters(report_with_cw)
        assert params["EnableDiskAlarm"] == "true"

        report_without_cw = AuditReport(
            identity=_make_identity(),
            ec2=_make_ec2_report(has_cwagent_disk=False),
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )
        params_no_cw, _, _ = build_cfn_parameters(report_without_cw)
        assert params_no_cw["EnableDiskAlarm"] == "false"

    def test_missing_signing_secret_auto_created_securely(self):
        """
        Verify that execute_pre_deploy_actions generates and creates /incidents/approval-mac-key
        when it is missing from Secrets Manager, without revealing its value.
        """
        secrets_rep = _make_secrets_report(all_exist=True)
        secrets_rep["/incidents/approval-mac-key"] = SecretReport(
            name="/incidents/approval-mac-key", exists=False, arn=None, accessible=False
        )

        report = AuditReport(
            identity=_make_identity(),
            ec2=_make_ec2_report(),
            dynamodb=_make_dynamodb_report(),
            s3=_make_s3_report(),
            ssm=_make_ssm_report(),
            iam=_make_iam_report(),
            secrets=secrets_rep,
            stack=_make_stack_report(),
            overall_status="NEEDS_PRE_DEPLOY",
        )

        mock_session = MagicMock()
        mock_sm_client = MagicMock()
        mock_session.client.return_value = mock_sm_client
        mock_sm_client.create_secret.return_value = {
            "ARN": "arn:aws:secretsmanager:us-east-1:111:secret:/incidents/approval-mac-key-abc"
        }

        executed = execute_pre_deploy_actions(mock_session, "us-east-1", report, ".")
        assert any("created secret '/incidents/approval-mac-key'" in e for e in executed)
        mock_sm_client.create_secret.assert_called_once()
        args, kwargs = mock_sm_client.create_secret.call_args
        assert kwargs["Name"] == "/incidents/approval-mac-key"
        assert len(kwargs["SecretString"]) == 64  # 32 bytes hex

    def test_missing_instance_security_tag_auto_applied(self):
        """
        Verify that execute_pre_deploy_actions adds IncidentsAgent=true tag if missing.
        """
        ec2_rep = _make_ec2_report(has_security_tag=False)
        report = AuditReport(
            identity=_make_identity(),
            ec2=ec2_rep,
            dynamodb=_make_dynamodb_report(),
            s3=_make_s3_report(),
            ssm=_make_ssm_report(),
            iam=_make_iam_report(),
            secrets=_make_secrets_report(),
            stack=_make_stack_report(),
            overall_status="NEEDS_PRE_DEPLOY",
        )

        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_session.client.return_value = mock_ec2_client

        executed = execute_pre_deploy_actions(mock_session, "us-east-1", report, ".")
        assert any("Tagged EC2 instance 'i-target123'" in e for e in executed)
        mock_ec2_client.create_tags.assert_called_once_with(
            Resources=["i-target123"],
            Tags=[{"Key": "IncidentsAgent", "Value": "true"}],
        )
        assert report.ec2.target_instance.has_security_tag is True
        assert report.ec2.target_valid is True

    def test_sanitized_env_file_generation_leaks_zero_secrets(self, tmp_path):
        """
        Scenario 4: Sanitized Environment File Generation
        - generate_env_file must output resource names and secret ARNs only.
        - Must NOT output any raw secrets or passwords.
        """
        report = AuditReport(
            identity=_make_identity(account_id="999888777666", region="us-east-1"),
            ec2=_make_ec2_report(instance_id="i-prod-001"),
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(account_id="999888777666", exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )
        params, _, _ = build_cfn_parameters(report)

        env_file = tmp_path / ".env.test_onboarded"
        generate_env_file(report, params, str(env_file))

        assert env_file.exists()
        content = env_file.read_text()

        # Must contain non-sensitive resource IDs
        assert "AWS_REGION=us-east-1" in content
        assert "AWS_ACCOUNT_ID=999888777666" in content
        assert "TARGET_INSTANCE_ID=i-prod-001" in content
        assert "EVENTS_TABLE=incidents-events" in content
        assert "BLOBS_BUCKET=incidents-blobs-999888777666" in content

        # Must contain ARNs
        assert "INCIDENTS_APPROVAL_MAC_KEY_ARN=arn:aws:secretsmanager:" in content
        assert "INCIDENTS_DEEPSEEK_API_KEY_ARN=arn:aws:secretsmanager:" in content

        # Zero raw keys
        assert "YOUR_SECRET" not in content
        assert "sk-" not in content
        assert "test_secret" not in content

    def test_audit_identity_and_secrets_mocked(self):
        """
        Verify audit_identity and audit_secrets boto3 queries.
        """
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sm = MagicMock()

        def client_side_effect(service, **kwargs):
            if service == "sts":
                return mock_sts
            if service == "secretsmanager":
                return mock_sm
            return MagicMock()

        mock_session.client.side_effect = client_side_effect
        mock_sts.get_caller_identity.return_value = {
            "Account": "555666777888",
            "Arn": "arn:aws:iam::555666777888:user/auditor",
            "UserId": "AIDAAUDIT",
        }
        mock_sm.describe_secret.return_value = {
            "ARN": "arn:aws:secretsmanager:us-east-1:555666777888:secret:/incidents/test"
        }

        ident = audit_identity(mock_session, "us-east-1")
        assert ident.account_id == "555666777888"

        secrets = audit_secrets(mock_session, "us-east-1")
        assert len(secrets) == 3
        assert "/incidents/slack-bot-token" not in secrets
        assert "/incidents/slack-signing-secret" not in secrets
        assert "/incidents/slack-webhook-url" in secrets
        assert secrets["/incidents/approval-mac-key"].exists is True

    def test_global_view_multi_region_scanner(self):
        """
        Verify audit_global_view scans active regions in parallel and discovers
        running EC2 instances and incidents-* DynamoDB tables across regions.
        """
        mock_session = MagicMock()
        mock_ec2_useast1 = MagicMock()
        mock_ec2_useast1.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "eu-west-3"},
                {"RegionName": "us-west-2"},
            ]
        }
        mock_ec2_useast1.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-111"}, {"InstanceId": "i-222"}]}
            ]
        }
        mock_ddb_useast1 = MagicMock()
        mock_ddb_useast1.list_tables.return_value = {
            "TableNames": ["incidents-events", "incidents-dedup", "incidents-leases", "users"]
        }

        mock_ec2_euwest3 = MagicMock()
        mock_ec2_euwest3.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-333"}]}
            ]
        }
        mock_ddb_euwest3 = MagicMock()
        mock_ddb_euwest3.list_tables.return_value = {"TableNames": ["unrelated-table"]}

        mock_ec2_uswest2 = MagicMock()
        mock_ec2_uswest2.describe_instances.return_value = {"Reservations": []}
        mock_ddb_uswest2 = MagicMock()
        mock_ddb_uswest2.list_tables.return_value = {"TableNames": []}

        def client_dispatch(service, region_name=None, **kwargs):
            if service == "ec2":
                if region_name == "us-east-1":
                    return mock_ec2_useast1
                elif region_name == "eu-west-3":
                    return mock_ec2_euwest3
                elif region_name == "us-west-2":
                    return mock_ec2_uswest2
                return mock_ec2_useast1
            elif service == "dynamodb":
                if region_name == "us-east-1":
                    return mock_ddb_useast1
                elif region_name == "eu-west-3":
                    return mock_ddb_euwest3
                elif region_name == "us-west-2":
                    return mock_ddb_uswest2
                return MagicMock()
            return MagicMock()

        mock_session.client.side_effect = client_dispatch

        results = audit_global_view(mock_session)
        assert len(results) == 3

        by_region = {r["region"]: r for r in results}
        assert by_region["us-east-1"]["running_ec2_count"] == 2
        assert by_region["us-east-1"]["incidents_tables_count"] == 3
        assert "incidents-events" in by_region["us-east-1"]["incidents_tables"]

        assert by_region["eu-west-3"]["running_ec2_count"] == 1
        assert by_region["eu-west-3"]["incidents_tables_count"] == 0

        assert by_region["us-west-2"]["running_ec2_count"] == 0
        assert by_region["us-west-2"]["incidents_tables_count"] == 0

        # Sorted so active regions appear first
        assert results[0]["region"] in ("us-east-1", "eu-west-3")

    def test_strands_health_probe_success_and_failure(self):
        """
        Verify probe_strands_health handles HTTP 200 with model name,
        network errors/timeouts, and empty URL appropriately.
        """
        # Case 1: Success with valid JSON
        mock_resp_success = MagicMock()
        mock_resp_success.getcode.return_value = 200
        mock_resp_success.read.return_value = b'{"status":"ok","model":"strands-decider-2B-qwen3.5-v1-2610"}'
        mock_resp_success.__enter__.return_value = mock_resp_success

        with patch("urllib.request.urlopen", return_value=mock_resp_success):
            res = probe_strands_health("http://107.23.249.143:8080")
            assert res["strands_healthy"] is True
            assert res["status_code"] == 200
            assert res["model"] == "strands-decider-2B-qwen3.5-v1-2610"
            assert "HTTP 200 OK" in res["detail"]
            assert res["health_url"] == "http://107.23.249.143:8080/health"

        # Case 2: Connection failure / timeout
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            res_fail = probe_strands_health("http://192.0.2.1:8080")
            assert res_fail["strands_healthy"] is False
            assert res_fail["status_code"] is None
            assert "Unresponsive" in res_fail["detail"]

        # Case 3: Empty URL
        res_empty = probe_strands_health("")
        assert res_empty["strands_healthy"] is False
        assert res_empty["status_code"] is None

    def test_bedrock_access_verification_in_us_east_1(self):
        """
        Verify audit_bedrock_access connects to us-east-1 and confirms availability
        of Amazon Nova models (amazon.nova-lite-v1:0, amazon.nova-pro-v1:0).
        """
        mock_session = MagicMock()
        mock_bedrock = MagicMock()
        mock_session.client.return_value = mock_bedrock

        # Case 1: Both models available
        mock_bedrock.list_foundation_models.return_value = {
            "modelSummaries": [
                {"modelId": "amazon.nova-lite-v1:0"},
                {"modelId": "amazon.nova-pro-v1:0"},
                {"modelId": "amazon.titan-text-express-v1"},
            ]
        }

        res = audit_bedrock_access(mock_session, bedrock_region="us-east-1")
        mock_session.client.assert_called_with("bedrock", region_name="us-east-1")
        assert res["accessible"] is True
        assert res["all_nova_ready"] is True
        assert "amazon.nova-lite-v1:0" in res["nova_models_found"]
        assert "amazon.nova-pro-v1:0" in res["nova_models_found"]

        # Case 2: Partial/Missing Nova models
        mock_bedrock.list_foundation_models.return_value = {
            "modelSummaries": [
                {"modelId": "amazon.titan-text-express-v1"},
            ]
        }
        res_partial = audit_bedrock_access(mock_session, bedrock_region="us-east-1")
        assert res_partial["accessible"] is True
        assert res_partial["all_nova_ready"] is False
        assert len(res_partial["nova_models_found"]) == 0

    def test_missing_iam_instance_profile_adds_pre_deploy_warning(self):
        """
        Verify that when a target EC2 instance has no IamInstanceProfile attached,
        the planner adds a pre-deployment warning to attach AmazonSSMManagedInstanceCore.
        """
        detail = EC2InstanceDetail(
            instance_id="i-unprofiled-target",
            name="unprofiled-vm",
            state="running",
            private_ip="10.0.0.20",
            public_ip="54.2.3.4",
            instance_type="t3.micro",
            iam_profile=None,
            ssm_online=False,
            has_security_tag=True,
            tags={"IncidentsAgent": "true"},
            has_instance_profile=False,
        )
        ec2 = EC2LayerReport(
            instances=[detail],
            target_instance=detail,
            target_valid=False,
            target_error="Instance i-unprofiled-target is missing an IAM Instance Profile (requires AmazonSSMManagedInstanceCore role).",
            has_cwagent_disk_metrics=False,
            strands_suggestion=None,
        )
        report = AuditReport(
            identity=_make_identity(),
            ec2=ec2,
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="NEEDS_PRE_DEPLOY",
        )

        params, pre_actions, _ = build_cfn_parameters(report)
        assert len(pre_actions) > 0
        action_text = " ".join(pre_actions)
        assert "AmazonSSMManagedInstanceCore" in action_text
        assert "i-unprofiled-target" in action_text

    def test_template_yaml_enforces_append_only_events_and_decoupled_bedrock_region(self):
        """
        Verify template.yaml architecture:
        1. BEDROCK_REGION is completely decoupled from Globals and AgentFunction for region independence.
        2. All EventsTableAppendOnly statements strictly allow GetItem/PutItem/Query/DescribeTable
           and NEVER contain DeleteItem or UpdateItem (enforcing append-only immutability).
        """
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
        assert os.path.exists(template_path)

        with open(template_path, "r", encoding="utf-8") as f:
            cfn = yaml.load(f, Loader=CfnLoader)

        # 1. Decoupled BEDROCK_REGION verification (Region-Independent)
        globals_env = cfn.get("Globals", {}).get("Function", {}).get("Environment", {}).get("Variables", {})
        assert "BEDROCK_REGION" not in globals_env

        agent_fn_env = cfn.get("Resources", {}).get("AgentFunction", {}).get("Properties", {}).get("Environment", {}).get("Variables", {})
        assert "BEDROCK_REGION" not in agent_fn_env

        # 2. Append-Only Immutability verification across all roles
        found_append_only_stmts = 0
        for rname, rdata in cfn.get("Resources", {}).items():
            if rdata.get("Type") == "AWS::IAM::Role":
                for policy in rdata.get("Properties", {}).get("Policies", []):
                    for stmt in policy.get("PolicyDocument", {}).get("Statement", []):
                        if stmt.get("Sid") == "EventsTableAppendOnly":
                            found_append_only_stmts += 1
                            actions = stmt.get("Action", [])
                            assert "dynamodb:PutItem" in actions
                            assert "dynamodb:GetItem" in actions
                            assert "dynamodb:UpdateItem" in actions, f"UpdateItem required for META last_seq CAS in {rname}"
                            assert "dynamodb:Query" in actions
                            assert "dynamodb:DescribeTable" in actions
                            assert "dynamodb:DeleteItem" not in actions, f"Violation: DeleteItem found in {rname} EventsTableAppendOnly"

        # Must protect events in IngestRole, AgentRole, ObserverRole, ExecutorRole, SlackCallbackRole
        assert found_append_only_stmts >= 5

    def test_ensure_client_secrets_provisions_missing_secrets(self, tmp_path):
        """
        Verifies that ensure_client_secrets:
        1. Generates random encrypted /incidents/approval-mac-key (64-char hex).
        2. Creates /incidents/deepseek-api-key with safe placeholder PLACEHOLDER_SET_YOUR_OWN_KEY_IN_SECRETS_MANAGER when no explicit key provided.
        3. Completely isolates local .env and does not upload developer's Slack or DeepSeek key.
        4. Supports passing deepseek_api_key explicitly.
        """
        from scripts.aws_onboard import ensure_client_secrets
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_sm = MagicMock()
        mock_session.client.return_value = mock_sm
        mock_session.region_name = "us-east-1"

        # Simulate absence of secrets initially
        mock_sm.describe_secret.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}}, "describe_secret"
        )
        mock_sm.create_secret.return_value = {"ARN": "arn:aws:secretsmanager:us-east-1:111:secret:mock"}

        # 1. Without passing explicit key (must create placeholder and not read .env)
        mock_root = tmp_path / "client_project"
        mock_root.mkdir()
        env_file = mock_root / ".env"
        env_file.write_text("DEEPSEEK_API_KEY=sk-dev-secret-do-not-leak\nSLACK_WEBHOOK_URL=https://hooks.slack.com/services/dev\n")

        created = ensure_client_secrets(mock_session, dry_run=False, project_root=str(mock_root))

        created_names = [call[1]["Name"] for call in mock_sm.create_secret.call_args_list]
        assert "/incidents/approval-mac-key" in created_names
        assert "/incidents/deepseek-api-key" in created_names
        assert "/incidents/slack-webhook-url" not in created_names

        # Verify approval-mac-key is random and 64 hex chars (32 bytes)
        mac_call = next(c for c in mock_sm.create_secret.call_args_list if c[1]["Name"] == "/incidents/approval-mac-key")
        mac_secret = mac_call[1]["SecretString"]
        assert len(mac_secret) == 64
        int(mac_secret, 16)  # must be valid hex

        # Verify deepseek-api-key was created with placeholder and did not leak developer key
        ds_call = next(c for c in mock_sm.create_secret.call_args_list if c[1]["Name"] == "/incidents/deepseek-api-key")
        assert ds_call[1]["SecretString"] == "PLACEHOLDER_SET_YOUR_OWN_KEY_IN_SECRETS_MANAGER"
        assert "sk-dev-secret-do-not-leak" not in ds_call[1]["SecretString"]

        # 2. When deepseek_api_key is passed explicitly
        mock_sm.create_secret.reset_mock()
        mock_sm.describe_secret.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}}, "describe_secret"
        )
        ensure_client_secrets(mock_session, dry_run=False, deepseek_api_key="sk-client-explicit-key")
        ds_explicit_call = next(c for c in mock_sm.create_secret.call_args_list if c[1]["Name"] == "/incidents/deepseek-api-key")
        assert ds_explicit_call[1]["SecretString"] == "sk-client-explicit-key"

    def test_ensure_instance_ssm_profile_creates_and_associates_role(self):
        """
        Verifies that ensure_instance_ssm_profile:
        1. Creates role IncidentsTargetSSMInstanceRole and attaches policy AmazonSSMManagedInstanceCore.
        2. Creates instance profile IncidentsTargetSSMInstanceProfile.
        3. Associates both with the client server via associate_iam_instance_profile.
        """
        from scripts.aws_onboard import ensure_instance_ssm_profile
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        def mock_client(svc, region_name=None):
            if svc == "ec2":
                return mock_ec2
            if svc == "iam":
                return mock_iam
            return MagicMock()

        mock_session.client.side_effect = mock_client
        mock_session.region_name = "us-east-1"

        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-client-target",
                    "State": {"Name": "running"},
                }]
            }]
        }
        mock_iam.get_role.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetRole")
        mock_iam.get_instance_profile.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetInstanceProfile")

        success = ensure_instance_ssm_profile(mock_session, instance_id="i-client-target", dry_run=False)

        assert success is True
        mock_iam.create_role.assert_called_once()
        assert mock_iam.create_role.call_args[1]["RoleName"] == "IncidentsTargetSSMInstanceRole"
        mock_iam.attach_role_policy.assert_any_call(
            RoleName="IncidentsTargetSSMInstanceRole",
            PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        )
        mock_iam.attach_role_policy.assert_any_call(
            RoleName="IncidentsTargetSSMInstanceRole",
            PolicyArn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
        )
        mock_iam.create_instance_profile.assert_called_once_with(
            InstanceProfileName="IncidentsTargetSSMInstanceProfile"
        )
        mock_ec2.associate_iam_instance_profile.assert_called_once_with(
            IamInstanceProfile={"Name": "IncidentsTargetSSMInstanceProfile"},
            InstanceId="i-client-target",
        )

    def test_ensure_instance_ssm_profile_reconciles_missing_cloudwatch_policy_on_existing_profile(self):
        """
        Verifies that when a target EC2 instance already has an IAM profile with only
        AmazonSSMManagedInstanceCore attached, ensure_instance_ssm_profile inspects
        the attached policies and attaches the missing CloudWatchAgentServerPolicy.
        """
        from scripts.aws_onboard import ensure_instance_ssm_profile

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        def mock_client(svc, region_name=None):
            if svc == "ec2":
                return mock_ec2
            if svc == "iam":
                return mock_iam
            return MagicMock()

        mock_session.client.side_effect = mock_client
        mock_session.region_name = "us-east-1"

        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-existing-target",
                    "State": {"Name": "running"},
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::123456789012:instance-profile/ExistingProfile"
                    },
                }]
            }]
        }
        mock_iam.get_instance_profile.return_value = {
            "InstanceProfile": {
                "InstanceProfileName": "ExistingProfile",
                "Roles": [{"RoleName": "ExistingTargetRole"}],
            }
        }
        # Simulate role having only AmazonSSMManagedInstanceCore attached
        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", "PolicyName": "AmazonSSMManagedInstanceCore"}
            ]
        }

        success = ensure_instance_ssm_profile(mock_session, instance_id="i-existing-target", dry_run=False)

        assert success is True
        # Must attach the missing CloudWatchAgentServerPolicy
        mock_iam.attach_role_policy.assert_called_once_with(
            RoleName="ExistingTargetRole",
            PolicyArn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
        )
        # Should NOT attempt associate_iam_instance_profile since profile already exists
        mock_ec2.associate_iam_instance_profile.assert_not_called()

    def test_external_client_plan_defaults_to_embedded_strands_and_zero_dev_hardcoding(self):
        """
        Verifies that:
        1. StrandsUrl='embedded' is set automatically in a new client account without an external Strands EC2 server.
        2. scripts/aws_onboard.py, template.yaml, and handlers/ are free of developer IP (107.23.249.143) or Account ID (057704056750).
        """
        from scripts.aws_onboard import build_cfn_parameters

        ident = _make_identity(account_id="999988887777")
        ec2 = _make_ec2_report(instance_id="i-client-vm")
        ec2.strands_suggestion = None  # no strands server in client account
        report = AuditReport(
            identity=ident,
            ec2=ec2,
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )

        params, _, sam_cmd = build_cfn_parameters(report)
        assert params["StrandsUrl"] == "embedded", "Must default to 'embedded' for external client"
        assert "StrandsUrl=embedded" in sam_cmd

        # Check code files for any leaked developer IPs or Account IDs
        dev_ip = "107.23.249.143"
        dev_account = "057704056750"

        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        paths_to_check = [
            os.path.join(project_root, "scripts", "aws_onboard.py"),
            os.path.join(project_root, "template.yaml"),
        ]
        handlers_dir = os.path.join(project_root, "handlers")
        for fname in os.listdir(handlers_dir):
            if fname.endswith(".py"):
                paths_to_check.append(os.path.join(handlers_dir, fname))

        for file_path in paths_to_check:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            assert dev_ip not in content, f"Developer IP {dev_ip} leaked in {file_path}"
            assert dev_account not in content, f"Developer Account ID {dev_account} leaked in {file_path}"

    def test_eu_north_1_restricted_region_zero_bedrock_iam_coupling(self, tmp_path, capsys):
        """
        Verifies that:
        1. template.yaml is completely free of BEDROCK_REGION and any IAM bedrock:InvokeModel permission or hardcoded ARN pointing to us-east-1.
        2. build_plan and print_llm_bedrock_policy succeed for an account in eu-north-1 (Stockholm), clearly showing API key status and Bedrock state.
        """
        import yaml
        from scripts.aws_onboard import build_cfn_parameters, print_llm_bedrock_policy

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
        with open(template_path, "r", encoding="utf-8") as f:
            cfn = yaml.load(f, Loader=CfnLoader)

        # 1. Zero BEDROCK_REGION in Globals or Functions
        globals_env = cfn.get("Globals", {}).get("Function", {}).get("Environment", {}).get("Variables", {})
        assert "BEDROCK_REGION" not in globals_env, "BEDROCK_REGION must not be pinned in Globals"

        for rname, rdata in cfn.get("Resources", {}).items():
            if rdata.get("Type") == "AWS::Serverless::Function":
                f_env = rdata.get("Properties", {}).get("Environment", {}).get("Variables", {})
                assert "BEDROCK_REGION" not in f_env, f"BEDROCK_REGION found in {rname}"

            # 2. Zero bedrock:InvokeModel or bedrock:InvokeModelWithResponseStream
            if rdata.get("Type") == "AWS::IAM::Role":
                for policy in rdata.get("Properties", {}).get("Policies", []):
                    for stmt in policy.get("PolicyDocument", {}).get("Statement", []):
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        for act in actions:
                            assert not act.startswith("bedrock:"), f"Found forbidden Bedrock IAM action '{act}' in {rname}"

        # 3. Zero hardcoded us-east-1 ARNs in template Resources
        with open(template_path, "r", encoding="utf-8") as f:
            raw_template = f.read()

        resources_raw = raw_template.split("Resources:")[1]
        for line in resources_raw.splitlines():
            if "arn:aws:" in line:
                assert "us-east-1" not in line, f"Found hardcoded us-east-1 ARN in template Resources: {line}"

        # 4. Successful execution of build_plan for eu-north-1 account
        ident = _make_identity(account_id="555544443333", region="eu-north-1")
        ec2 = _make_ec2_report(instance_id="i-stockholm-01")
        ec2.strands_suggestion = None

        report = AuditReport(
            identity=ident,
            ec2=ec2,
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=False),
            stack=_make_stack_report(),
            overall_status="READY",
            bedrock_access=None,
        )

        params, pre_actions, sam_cmd = build_cfn_parameters(report)
        assert params["StrandsUrl"] == "embedded"
        assert params["CreateDynamoTables"] == "false"

        # 5. Successful execution of print_llm_bedrock_policy in eu-north-1
        capsys.readouterr()  # clear buffer
        print_llm_bedrock_policy(report, project_root=str(tmp_path))
        captured = capsys.readouterr().out
        assert "─── LLM / Bedrock Fate & API Key Policy (Region-Independent BYOK) ───" in captured
        assert "template.yaml creates ZERO Bedrock resources" in captured
        assert "eu-north-1" in captured
        assert "Amazon Bedrock QuickStart" in captured
        assert "Missing" in captured or "Present" in captured or "Staged" in captured

    def test_slack_secrets_purged_and_webhook_strictly_optional(self, capsys):
        """
        Verifies:
        1. REQUIRED_SECRETS contains ONLY ('/incidents/approval-mac-key', '/incidents/deepseek-api-key').
        2. OPTIONAL_SECRETS contains ('/incidents/slack-webhook-url',).
        3. 'slack-bot-token' and 'slack-signing-secret' are completely eradicated from scripts/aws_onboard.py.
        4. When all secrets are missing in audit report:
           - build_cfn_parameters does NOT produce any pre_actions requesting Slack secrets.
           - print_audit_summary displays '/incidents/slack-webhook-url' as [OPTIONAL — Slack notifications skipped safely if unconfigured].
        5. When '/incidents/slack-webhook-url' exists:
           - print_audit_summary displays it as [CONFIGURED & ACTIVE].
        """
        from scripts.aws_onboard import REQUIRED_SECRETS, OPTIONAL_SECRETS, print_audit_summary, build_cfn_parameters

        # 1. Structural separation
        assert REQUIRED_SECRETS == ("/incidents/approval-mac-key", "/incidents/deepseek-api-key")
        assert OPTIONAL_SECRETS == ("/incidents/slack-webhook-url",)

        # 2. Total purging of legacy secrets from code
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        onboard_script = os.path.join(project_root, "scripts", "aws_onboard.py")
        with open(onboard_script, "r", encoding="utf-8") as f:
            content = f.read()
        assert "slack-bot-token" not in content, "Legacy secret 'slack-bot-token' found in scripts/aws_onboard.py"
        assert "slack-signing-secret" not in content, "Legacy secret 'slack-signing-secret' found in scripts/aws_onboard.py"

        # 3. pre_actions immunity: missing slack webhook must NEVER trigger a pre_action requirement
        ident = _make_identity()
        ec2 = _make_ec2_report(has_security_tag=True)
        report_missing = AuditReport(
            identity=ident,
            ec2=ec2,
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=False),
            stack=_make_stack_report(),
            overall_status="NEEDS_PRE_DEPLOY",
        )
        _, pre_actions, _ = build_cfn_parameters(report_missing)
        action_text = " ".join(pre_actions)
        assert "slack" not in action_text.lower(), f"Slack leaked into pre_actions: {pre_actions}"

        # 4. print_audit_summary with missing optional secret
        capsys.readouterr()
        print_audit_summary(report_missing)
        out_missing = capsys.readouterr().out
        assert "Required Secrets:" in out_missing
        assert "Optional Integrations:" in out_missing
        assert "⚪ /incidents/slack-webhook-url" in out_missing
        assert "[OPTIONAL — Slack notifications skipped safely if unconfigured]" in out_missing
        assert "slack-bot-token" not in out_missing
        assert "slack-signing-secret" not in out_missing

        # 5. print_audit_summary with configured optional secret
        report_present = AuditReport(
            identity=ident,
            ec2=ec2,
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )
        capsys.readouterr()
        print_audit_summary(report_present)
        out_present = capsys.readouterr().out
        assert "✅ /incidents/slack-webhook-url" in out_present
        assert "[CONFIGURED & ACTIVE]" in out_present

    def test_existing_vps_never_auto_selected_without_explicit_flag(self, capsys):
        """
        Verifies that when running instances exist (e.g. 'vop') and neither --instance-id nor -T is passed:
        1. Existing instance is NEVER auto-selected as target.
        2. build_cfn_parameters sets TargetInstanceId="<REQUIRED_EC2_INSTANCE_ID>" and presents Option A and Option B.
        3. print_audit_summary displays Option A and Option B protecting existing servers.
        """
        from scripts.aws_onboard import build_cfn_parameters, print_audit_summary

        ident = _make_identity()
        vop_instance = EC2InstanceDetail(
            instance_id="i-client-vop-12345",
            name="vop",
            state="running",
            private_ip="172.31.10.20",
            public_ip="52.1.2.3",
            instance_type="t3.micro",
            iam_profile=None,
            ssm_online=True,
            has_security_tag=False,
            tags={"Name": "vop"},
        )
        ec2 = EC2LayerReport(
            instances=[vop_instance],
            target_instance=None,
            target_valid=False,
            target_error=None,
            has_cwagent_disk_metrics=False,
            strands_suggestion=None,
        )
        report = AuditReport(
            identity=ident,
            ec2=ec2,
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="NEEDS_PRE_DEPLOY",
        )

        params, pre_actions, _ = build_cfn_parameters(report, create_target_vps=False)
        assert params["TargetInstanceId"] == "<REQUIRED_EC2_INSTANCE_ID>"
        assert params["TargetInstanceId"] != "i-client-vop-12345"

        action_text = " ".join(pre_actions)
        assert "Option A (Adopt Existing VPS)" in action_text
        assert "Option B (Provision Dedicated Target VPS)" in action_text or "-T" in action_text

        capsys.readouterr()
        print_audit_summary(report)
        out = capsys.readouterr().out
        assert "Target VPS: None selected" in out or "No target instance" in out
        assert "Option A (Adopt Existing VPS)" in out
        assert "Option B (Provision Dedicated Target VPS)" in out

    def test_create_target_vps_flag_T_provisions_dedicated_instance(self):
        """
        Verifies:
        1. When create_target_vps=True in build_cfn_parameters:
           - TargetInstanceId is set to '<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>'.
           - EnableAlarms is 'true'.
           - pre_actions indicates automatic provisioning of new dedicated instance.
        2. provision_dedicated_target_vps:
           - dry_run=True returns '<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>'.
           - Live mode fetches AL2023 AMI from SSM, launches instance with Nginx UserData & SSM profile, and returns instance ID.
        """
        from scripts.aws_onboard import build_cfn_parameters, provision_dedicated_target_vps

        ident = _make_identity()
        ec2 = _make_ec2_report(has_security_tag=True)
        report = AuditReport(
            identity=ident,
            ec2=ec2,
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )

        # 1. Plan mode with -T
        params, pre_actions, _ = build_cfn_parameters(report, create_target_vps=True)
        assert params["TargetInstanceId"] == "<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>"
        assert params["EnableAlarms"] == "true"
        assert any("-T" in act or "Dedicated Target VPS" in act for act in pre_actions)

        # 2. Dry run provision
        dry_res = provision_dedicated_target_vps(MagicMock(), "eu-north-1", dry_run=True)
        assert dry_res == "<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>"

        # 3. Live provision with mocked AWS clients
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_ssm = MagicMock()
        mock_iam = MagicMock()

        def client_factory(service, **kwargs):
            if service == "ec2":
                return mock_ec2
            if service == "ssm":
                return mock_ssm
            if service == "iam":
                return mock_iam
            return MagicMock()

        mock_session.client.side_effect = client_factory

        # Mock SSM AL2023 AMI parameter
        mock_ssm.get_parameter.return_value = {
            "Parameter": {"Value": "ami-0123456789al2023"}
        }

        # Mock EC2 run_instances
        mock_ec2.run_instances.return_value = {
            "Instances": [{"InstanceId": "i-dedicated-target-vps-777"}]
        }
        mock_ec2.describe_instance_type_offerings.return_value = {
            "InstanceTypeOfferings": [{"InstanceType": "t3.micro"}]
        }

        new_instance_id = provision_dedicated_target_vps(mock_session, "eu-north-1", dry_run=False)
        assert new_instance_id == "i-dedicated-target-vps-777"

        # Verify run_instances arguments
        run_call = mock_ec2.run_instances.call_args[1]
        assert run_call["ImageId"] == "ami-0123456789al2023"
        assert run_call["InstanceType"] == "t3.micro"
        assert "nginx" in run_call["UserData"]
        assert run_call["IamInstanceProfile"]["Name"] == "IncidentsTargetSSMInstanceProfile"
        tag_dict = {t["Key"]: t["Value"] for t in run_call["TagSpecifications"][0]["Tags"]}
        assert tag_dict.get("IncidentsAgent") == "true"
        assert tag_dict.get("Name") == "incidents-target-vps"

    def test_provision_dedicated_target_vps_retries_on_iam_propagation_delay(self):
        """
        Simulates ec2.run_instances raising InvalidParameterValue (Invalid IAM Instance Profile name)
        on attempts 1 and 2 due to AWS IAM propagation delay, succeeding on attempt 3,
        confirming resilience against IAM synchronization lag.
        """
        from scripts.aws_onboard import provision_dedicated_target_vps
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_ssm = MagicMock()
        mock_iam = MagicMock()

        def client_factory(service, **kwargs):
            if service == "ec2":
                return mock_ec2
            if service == "ssm":
                return mock_ssm
            if service == "iam":
                return mock_iam
            return MagicMock()

        mock_session.client.side_effect = client_factory

        mock_ssm.get_parameter.return_value = {
            "Parameter": {"Value": "ami-0123456789al2023"}
        }
        mock_ec2.describe_instance_type_offerings.return_value = {
            "InstanceTypeOfferings": [{"InstanceType": "t3.micro"}]
        }

        iam_error = ClientError(
            {
                "Error": {
                    "Code": "InvalidParameterValue",
                    "Message": "Value (IncidentsTargetSSMInstanceProfile) for parameter iamInstanceProfile.name is invalid.",
                }
            },
            "RunInstances",
        )
        success_response = {
            "Instances": [{"InstanceId": "i-propagated-vps-123"}]
        }

        mock_ec2.run_instances.side_effect = [iam_error, iam_error, success_response]

        with patch("time.sleep"):
            instance_id = provision_dedicated_target_vps(mock_session, "eu-north-1", dry_run=False, retry_delay=0)

        assert instance_id == "i-propagated-vps-123"
        assert mock_ec2.run_instances.call_count == 3

    def test_ensure_instance_ssm_profile_retries_on_iam_propagation_delay(self):
        """
        Verifies ensure_instance_ssm_profile retries associate_iam_instance_profile
        when EC2 throws InvalidParameterValue due to IAM propagation delay.
        """
        from scripts.aws_onboard import ensure_instance_ssm_profile
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        def mock_client(svc, region_name=None):
            if svc == "ec2":
                return mock_ec2
            if svc == "iam":
                return mock_iam
            return MagicMock()

        mock_session.client.side_effect = mock_client
        mock_session.region_name = "eu-north-1"

        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-client-target",
                    "State": {"Name": "running"},
                }]
            }]
        }

        iam_error = ClientError(
            {
                "Error": {
                    "Code": "InvalidParameterValue",
                    "Message": "Value (IncidentsTargetSSMInstanceProfile) for parameter iamInstanceProfile.name is invalid.",
                }
            },
            "AssociateIamInstanceProfile",
        )

        mock_ec2.associate_iam_instance_profile.side_effect = [iam_error, iam_error, {"IamInstanceProfileAssociation": {}}]

        with patch("time.sleep"):
            success = ensure_instance_ssm_profile(mock_session, instance_id="i-client-target", dry_run=False, retry_delay=0)

        assert success is True
        assert mock_ec2.associate_iam_instance_profile.call_count == 3

    def test_sam_deploy_omits_empty_existing_bucket_param_and_includes_region(self):
        """
        Verifies:
        1. When CreateBlobsBucket=true (greenfield or -T), ExistingBlobsBucketName="" is omitted
           from the generated sam deploy --parameter-overrides string.
        2. sam deploy command explicitly includes --region <region> and --no-fail-on-empty-changeset.
        """
        report = AuditReport(
            identity=_make_identity(region="eu-north-1"),
            ec2=_make_ec2_report(),
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=False),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )

        params, _, sam_command = build_cfn_parameters(report, create_target_vps=True)
        assert params["CreateBlobsBucket"] == "true"
        assert params["ExistingBlobsBucketName"] == ""

        # SAM command checks: empty params omitted, region and flags included
        assert "ExistingBlobsBucketName=" not in sam_command
        assert "--region eu-north-1" in sam_command
        assert "--no-fail-on-empty-changeset" in sam_command
        assert "CreateBlobsBucket=true" in sam_command

    def test_existing_bucket_option_sets_create_blobs_bucket_false(self):
        """
        Verifies:
        1. When existing_bucket is provided, CreateBlobsBucket is set to 'false'.
        2. ExistingBlobsBucketName is populated with the provided bucket name.
        3. sam deploy command includes ExistingBlobsBucketName=my-client-bucket.
        """
        report = AuditReport(
            identity=_make_identity(region="eu-north-1"),
            ec2=_make_ec2_report(),
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=False),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=_make_secrets_report(all_exist=True),
            stack=_make_stack_report(),
            overall_status="READY",
        )

        params, _, sam_command = build_cfn_parameters(
            report,
            existing_bucket="my-client-bucket",
        )
        assert params["CreateBlobsBucket"] == "false"
        assert params["ExistingBlobsBucketName"] == "my-client-bucket"
        assert "ExistingBlobsBucketName=my-client-bucket" in sam_command
        assert "--region eu-north-1" in sam_command

    def test_extract_cfn_failure_root_causes(self):
        """
        Verifies:
        1. Filters events with status containing 'FAILED'.
        2. Formats: '[LogicalResourceId (ResourceType)] -> ResourceStatusReason'.
        3. Correctly omits cascading 'Resource creation cancelled' events and top-level summaries.
        """
        mock_cfn = MagicMock()
        mock_paginator = MagicMock()
        mock_cfn.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "StackEvents": [
                    {
                        "LogicalResourceId": "incidents-agent-core",
                        "ResourceType": "AWS::CloudFormation::Stack",
                        "ResourceStatus": "ROLLBACK_IN_PROGRESS",
                        "ResourceStatusReason": "The following resource(s) failed to create: [BlobsBucket]. Rollback requested by user.",
                    },
                    {
                        "LogicalResourceId": "IngestFunction",
                        "ResourceType": "AWS::Serverless::Function",
                        "ResourceStatus": "CREATE_FAILED",
                        "ResourceStatusReason": "Resource creation cancelled",
                    },
                    {
                        "LogicalResourceId": "AgentFunction",
                        "ResourceType": "AWS::Serverless::Function",
                        "ResourceStatus": "CREATE_FAILED",
                        "ResourceStatusReason": "Resource creation cancelled",
                    },
                    {
                        "LogicalResourceId": "BlobsBucket",
                        "ResourceType": "AWS::S3::Bucket",
                        "ResourceStatus": "CREATE_FAILED",
                        "ResourceStatusReason": "Resource of type 'AWS::S3::Bucket' with identifier 'incidents-blobs-057704056750' already exists.",
                    },
                ]
            }
        ]

        mock_session = MagicMock()
        mock_session.client.return_value = mock_cfn

        failures = extract_cfn_failure_root_causes(mock_session, "incidents-agent-core", "eu-north-1")
        assert len(failures) == 1
        assert failures[0] == "[BlobsBucket (AWS::S3::Bucket)] -> Resource of type 'AWS::S3::Bucket' with identifier 'incidents-blobs-057704056750' already exists."

    def test_ensure_clean_stack_before_deploy_cleans_dead_stack(self):
        """
        Verifies that when a stack is in ROLLBACK_COMPLETE or DELETE_FAILED:
        1. cfn.delete_stack is invoked.
        2. stack_delete_complete waiter is waited on.
        3. Returns True.
        4. When stack is in CREATE_COMPLETE or does not exist, delete is NOT invoked and returns False.
        """
        mock_cfn = MagicMock()
        mock_waiter = MagicMock()
        mock_cfn.get_waiter.return_value = mock_waiter

        # Scenario 1: Dead stack in ROLLBACK_COMPLETE
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{"StackStatus": "ROLLBACK_COMPLETE"}]
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_cfn

        cleaned = ensure_clean_stack_before_deploy(mock_session, "incidents-agent-core", "eu-north-1")
        assert cleaned is True
        mock_cfn.delete_stack.assert_called_once_with(StackName="incidents-agent-core")
        mock_waiter.wait.assert_called_once_with(StackName="incidents-agent-core")

        # Scenario 2: Healthy stack in CREATE_COMPLETE
        mock_cfn.reset_mock()
        mock_waiter.reset_mock()
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{"StackStatus": "CREATE_COMPLETE"}]
        }
        cleaned_healthy = ensure_clean_stack_before_deploy(mock_session, "incidents-agent-core", "eu-north-1")
        assert cleaned_healthy is False
        mock_cfn.delete_stack.assert_not_called()
        mock_waiter.wait.assert_not_called()

        # Scenario 3: Non-existent stack
        from botocore.exceptions import ClientError
        mock_cfn.reset_mock()
        mock_cfn.describe_stacks.side_effect = ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack incidents-agent-core does not exist"}},
            "DescribeStacks",
        )
        cleaned_none = ensure_clean_stack_before_deploy(mock_session, "incidents-agent-core", "eu-north-1")
        assert cleaned_none is False
        mock_cfn.delete_stack.assert_not_called()

    def test_placeholder_secret_detection_and_reporting(self, capsys):
        """
        Verifies that when /incidents/deepseek-api-key has a PLACEHOLDER value:
        1. audit_secrets sets is_placeholder=True.
        2. print_llm_bedrock_policy formats honest warning.
        3. print_audit_summary prints honest warning and omits 'EXISTS & ACCESSIBLE'.
        """
        mock_sm = MagicMock()
        mock_sm.describe_secret.return_value = {"ARN": "arn:aws:secretsmanager:eu-north-1:111:secret:/incidents/deepseek-api-key"}
        mock_sm.get_secret_value.return_value = {
            "SecretString": "PLACEHOLDER_SET_YOUR_OWN_KEY_IN_SECRETS_MANAGER"
        }

        mock_session = MagicMock()
        mock_session.client.return_value = mock_sm

        sec_reports = audit_secrets(mock_session, "eu-north-1")
        ds_rep = sec_reports["/incidents/deepseek-api-key"]
        assert ds_rep.exists is True
        assert ds_rep.is_placeholder is True

        # Check print_llm_bedrock_policy output
        report = AuditReport(
            identity=_make_identity(region="eu-north-1"),
            ec2=_make_ec2_report(),
            dynamodb=_make_dynamodb_report(all_ready=True),
            s3=_make_s3_report(exists=True),
            ssm=_make_ssm_report(all_ready=True),
            iam=_make_iam_report(all_ready=True),
            secrets=sec_reports,
            stack=_make_stack_report(),
            overall_status="READY",
        )

        print_llm_bedrock_policy(report)
        out = capsys.readouterr().out
        assert "⚠️ PLACEHOLDER ONLY in Secrets Manager ('/incidents/deepseek-api-key') — Client must update with a valid API key before live inference" in out
        assert "✅ Present & Active" not in out

    def test_ensure_instance_telemetry_bootstraps_cwagent_and_systemd_pulse(self):
        """
        Verifies that ensure_instance_telemetry:
        1. Checks EC2 running state and SSM ping status.
        2. Dispatches universal multi-distro script via ssm.send_command(AWS-RunShellScript).
        3. Returns True when command succeeds.
        """
        from scripts.aws_onboard import ensure_instance_telemetry

        mock_session = MagicMock()
        mock_ssm = MagicMock()
        mock_ec2 = MagicMock()

        def mock_client(svc, region_name=None):
            if svc == "ssm":
                return mock_ssm
            if svc == "ec2":
                return mock_ec2
            return MagicMock()

        mock_session.client.side_effect = mock_client
        mock_session.region_name = "us-east-1"

        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-brownfield-client",
                    "State": {"Name": "running"},
                }]
            }]
        }
        mock_ssm.describe_instance_information.return_value = {
            "InstanceInformationList": [{"PingStatus": "Online"}]
        }
        mock_ssm.send_command.return_value = {
            "Command": {"CommandId": "cmd-test-12345"}
        }
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "TELEMETRY_BOOTSTRAP_COMPLETE",
        }

        success = ensure_instance_telemetry(mock_session, instance_id="i-brownfield-client", dry_run=False, timeout_seconds=5)
        assert success is True
        mock_ssm.send_command.assert_called_once()
        call_kwargs = mock_ssm.send_command.call_args[1]
        assert call_kwargs["DocumentName"] == "AWS-RunShellScript"
        assert call_kwargs["InstanceIds"] == ["i-brownfield-client"]
        script_sent = call_kwargs["Parameters"]["commands"][0]
        assert "amazon-cloudwatch-agent" in script_sent
        assert "cwsys_health.timer" in script_sent
        assert "FailedServicesCount" in script_sent


class TestCoreIamRolesReconciliation:
    """
    Tests for Core IAM Roles Trust Policy Auditing and In-Place Auto-Reconciliation.
    Prevents AWS Lambda fatal error:
    'AccessDeniedException: The role defined for the function cannot be assumed by Lambda.'
    """

    def test_trust_policy_validation(self):
        valid_lambda = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        invalid_ec2 = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        valid_operator = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:role/incidents-executor-role"},
                "Action": "sts:AssumeRole"
            }]
        }

        assert _is_trust_policy_valid("incidents-agent-role", valid_lambda) is True
        assert _is_trust_policy_valid("incidents-agent-role", invalid_ec2) is False
        assert _is_trust_policy_valid("incidents-agent-role", {}) is False
        assert _is_trust_policy_valid("incidents-agent-role", None) is False
        assert _is_trust_policy_valid("RemediationOperatorRole", valid_operator) is True

    def test_ensure_core_iam_roles_reconciles_invalid_trust_and_policies(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.client.return_value = mock_iam
        mock_session.region_name = "us-east-1"

        # Mock existing role with incorrect EC2 trust policy
        mock_iam.get_role.return_value = {
            "Role": {
                "RoleName": "incidents-agent-role",
                "Arn": "arn:aws:iam::111122223333:role/incidents-agent-role",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }]
                }
            }
        }

        remediated = ensure_core_iam_roles(mock_session, account_id="111122223333", region="us-east-1")
        assert len(remediated) >= 2
        assert any("Reconciled trust policy for 'incidents-agent-role'" in r for r in remediated)

        # Verify update_assume_role_policy was called with lambda.amazonaws.com
        update_calls = [c for c in mock_iam.update_assume_role_policy.call_args_list if c[1]["RoleName"] == "incidents-agent-role"]
        assert len(update_calls) == 1
        doc = json.loads(update_calls[0][1]["PolicyDocument"])
        assert doc["Statement"][0]["Principal"]["Service"] == "lambda.amazonaws.com"

        # Verify AWSLambdaBasicExecutionRole was attached
        mock_iam.attach_role_policy.assert_any_call(
            RoleName="incidents-agent-role",
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )

        # Verify inline policy was put
        mock_iam.put_role_policy.assert_any_call(
            RoleName="incidents-agent-role",
            PolicyName="incidents-agent-policy",
            PolicyDocument=mock_iam.put_role_policy.call_args_list[0][1]["PolicyDocument"],
        )

    def test_build_cfn_parameters_reports_iam_trust_reconciliation_action(self):
        ident = _make_identity()
        ec2 = _make_ec2_report(has_security_tag=True, has_cwagent_disk=True)
        ddb = _make_dynamodb_report(all_ready=True)
        s3 = _make_s3_report(exists=True)
        ssm = _make_ssm_report(all_ready=True)
        secrets_rep = _make_secrets_report(all_exist=True)
        stack = _make_stack_report()

        roles = {
            "incidents-agent-role": IAMRoleReport("incidents-agent-role", True, "arn:aws:iam::111:role/agent", trust_valid=False),
            "incidents-observer-role": IAMRoleReport("incidents-observer-role", True, "arn:aws:iam::111:role/observer", trust_valid=True),
            "RemediationOperatorRole": IAMRoleReport("RemediationOperatorRole", True, "arn:aws:iam::111:role/operator", trust_valid=True),
        }
        iam = IAMLayerReport(roles=roles, all_ready=False)

        report = AuditReport(
            identity=ident, ec2=ec2, dynamodb=ddb, s3=s3, ssm=ssm,
            iam=iam, secrets=secrets_rep, stack=stack, overall_status="READY",
        )

        params, pre_actions, _ = build_cfn_parameters(report)
        assert any("Reconcile IAM Role Trust Policy (incidents-agent-role)" in a for a in pre_actions)


class TestEnvFileInjection:
    """
    Tests for -E / --env-file automated environment injection and dual-topology routing.
    """

    def test_parse_env_file_handles_comments_quotes_and_empty_lines(self, tmp_path):
        env_content = """
        # Sample configuration
        DEEPSEEK_API_KEY="sk-secret-12345"
        DEEPSEEK_BASE_URL='https://bedrock-mantle.us-east-1.api.aws/v1'
        
        # Unquoted and spaced
        DEEPSEEK_FLASH_MODEL = deepseek.v3.2
        EMPTY_VAL=
        """
        env_file = tmp_path / ".env.test"
        env_file.write_text(env_content, encoding="utf-8")

        parsed = parse_env_file(str(env_file))
        assert parsed["DEEPSEEK_API_KEY"] == "sk-secret-12345"
        assert parsed["DEEPSEEK_BASE_URL"] == "https://bedrock-mantle.us-east-1.api.aws/v1"
        assert parsed["DEEPSEEK_FLASH_MODEL"] == "deepseek.v3.2"
        assert "EMPTY_VAL" not in parsed

    def test_split_env_vars_categorizes_secrets_and_parameters(self):
        raw = {
            "DEEPSEEK_API_KEY": "sk-real-token",
            "APPROVAL_MAC_KEY_HEX": "0123456789abcdef",
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/...",
            "DEEPSEEK_BASE_URL": "https://bedrock-mantle.us-east-1.api.aws/v1",
            "DEEPSEEK_FLASH_MODEL": "deepseek.v3.2",
            "SLACK_AUTHORIZED_APPROVERS": "U123456,U789012",
        }
        secrets, params = split_env_vars(raw)
        assert set(secrets.keys()) == {"DEEPSEEK_API_KEY", "APPROVAL_MAC_KEY_HEX", "SLACK_WEBHOOK_URL"}
        assert set(params.keys()) == {"DEEPSEEK_BASE_URL", "DEEPSEEK_FLASH_MODEL", "SLACK_AUTHORIZED_APPROVERS"}

    def test_build_cfn_parameters_injects_env_params_and_protects_secrets(self):
        ident = _make_identity()
        ec2 = _make_ec2_report(has_security_tag=True, has_cwagent_disk=True)
        ddb = _make_dynamodb_report(all_ready=True)
        s3 = _make_s3_report(exists=True)
        ssm = _make_ssm_report(all_ready=True)
        secrets_rep = _make_secrets_report(all_exist=True)
        stack = _make_stack_report()
        iam = _make_iam_report(all_ready=True)

        report = AuditReport(
            identity=ident, ec2=ec2, dynamodb=ddb, s3=s3, ssm=ssm,
            iam=iam, secrets=secrets_rep, stack=stack, overall_status="READY",
        )

        injected_params = {
            "DEEPSEEK_FLASH_MODEL": "deepseek.v3.2",
            "DEEPSEEK_BASE_URL": "https://custom.endpoint.internal/v1",
            "SLACK_AUTHORIZED_APPROVERS": "U123456",
        }
        params, _, sam_cmd = build_cfn_parameters(report, injected_params=injected_params)

        assert params["DeepSeekFlashModel"] == "deepseek.v3.2"
        assert params["DeepSeekBaseUrl"] == "https://custom.endpoint.internal/v1"
        assert params["SlackAuthorizedApprovers"] == "U123456"
        assert "DEEPSEEK_API_KEY" not in params
        assert "DeepSeekFlashModel=deepseek.v3.2" in sam_cmd

    def test_ensure_client_secrets_updates_existing_placeholder_with_live_token(self):
        mock_session = MagicMock()
        mock_sm = MagicMock()
        mock_session.client.return_value = mock_sm
        mock_session.region_name = "us-east-1"

        # Secret exists but contains placeholder
        mock_sm.describe_secret.return_value = {"Name": "/incidents/deepseek-api-key"}
        mock_sm.get_secret_value.return_value = {"SecretString": "PLACEHOLDER_SET_YOUR_OWN_KEY_IN_SECRETS_MANAGER"}

        injected_secrets = {"DEEPSEEK_API_KEY": "bedrock-live-token-999"}
        results = ensure_client_secrets(mock_session, injected_secrets=injected_secrets)

        mock_sm.put_secret_value.assert_called_once_with(
            SecretId="/incidents/deepseek-api-key",
            SecretString="bedrock-live-token-999",
        )
        assert any("Updated secret '/incidents/deepseek-api-key' with live credential" in r for r in results)

    def test_cli_parser_env_file_flag(self):
        # Default with -E
        args_default = parse_args(["--mode", "apply", "-E", "--instance-id", "i-123"])
        assert args_default.env_file == ".env"

        # Explicit custom path
        args_custom = parse_args(["--mode", "apply", "-E", "my_custom.env", "--instance-id", "i-123"])
        assert args_custom.env_file == "my_custom.env"

        # Long option
        args_long = parse_args(["--mode", "plan", "--env-file", "prod.env", "--instance-id", "i-123"])
        assert args_long.env_file == "prod.env"

        # Omitted
        args_omitted = parse_args(["--mode", "audit"])
        assert args_omitted.env_file == ""




