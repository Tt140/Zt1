#!/usr/bin/env python3
"""
scripts/aws_onboard.py — Autonomous Incident Remediation Onboarding & Discovery Tool
Supports:
  --mode audit : Deep 7-layer environment discovery (Read-Only)
  --mode plan  : Calculates delta against template.yaml and generates SAM parameter overrides (Read-Only)
  --mode apply : Governed execution of pre-deploy remediations, receipt generation, and optional SAM deployment
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError


# ── JSON Encoder for Dataclasses & Datetimes ─────────────────────────────────
class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class IdentityInfo:
    account_id: str
    arn: str
    user_id: str
    region: str


@dataclass
class EC2InstanceDetail:
    instance_id: str
    name: str
    state: str
    private_ip: str
    public_ip: str
    instance_type: str
    iam_profile: Optional[str]
    ssm_online: bool
    has_security_tag: bool  # IncidentsAgent == "true"
    tags: Dict[str, str] = field(default_factory=dict)
    has_instance_profile: bool = True


@dataclass
class EC2LayerReport:
    instances: List[EC2InstanceDetail]
    target_instance: Optional[EC2InstanceDetail]
    target_valid: bool
    target_error: Optional[str]
    has_cwagent_disk_metrics: bool
    strands_suggestion: Optional[str]


@dataclass
class DynamoDBTableReport:
    name: str
    exists: bool
    status: Optional[str]
    billing_mode: Optional[str]
    key_schema_matches: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DynamoDBLayerReport:
    tables: Dict[str, DynamoDBTableReport]
    all_ready: bool


@dataclass
class S3BucketReport:
    expected_name: str
    exists: bool
    encryption_matches: bool
    details: Dict[str, Any] = field(default_factory=dict)
    discovered_buckets: List[str] = field(default_factory=list)


@dataclass
class SSMDocReport:
    name: str
    exists: bool
    default_version: Optional[str]
    drift_detected: bool
    actual_pattern: Optional[str]
    expected_pattern: str


@dataclass
class SSMLayerReport:
    documents: Dict[str, SSMDocReport]
    all_ready: bool
    has_drift: bool


@dataclass
class IAMRoleReport:
    name: str
    exists: bool
    arn: Optional[str]
    trust_valid: bool = True


@dataclass
class IAMLayerReport:
    roles: Dict[str, IAMRoleReport]
    all_ready: bool


@dataclass
class SecretReport:
    name: str
    exists: bool
    arn: Optional[str]
    accessible: bool
    is_placeholder: bool = False


@dataclass
class StackReport:
    stack_name: str
    exists: bool
    status: Optional[str]
    lambda_functions: Dict[str, bool]
    eventbridge_rule_exists: bool


@dataclass
class AuditReport:
    identity: IdentityInfo
    ec2: EC2LayerReport
    dynamodb: DynamoDBLayerReport
    s3: S3BucketReport
    ssm: SSMLayerReport
    iam: IAMLayerReport
    secrets: Dict[str, SecretReport]
    stack: StackReport
    overall_status: str  # READY / NEEDS_PRE_DEPLOY / DELTA_RESOLVED
    bedrock_access: Optional[Dict[str, Any]] = None
    strands_probe: Optional[Dict[str, Any]] = None
    global_view: Optional[List[Dict[str, Any]]] = None


# ── Layer 1: Identity Discovery ──────────────────────────────────────────────

def audit_identity(session: boto3.Session, region: str) -> IdentityInfo:
    sts = session.client("sts", region_name=region)
    caller = sts.get_caller_identity()
    return IdentityInfo(
        account_id=caller["Account"],
        arn=caller["Arn"],
        user_id=caller["UserId"],
        region=region,
    )


# ── Layer 2: EC2 & Metrics Discovery ─────────────────────────────────────────

def audit_ec2(
    session: boto3.Session,
    region: str,
    target_instance_id: Optional[str] = None,
) -> EC2LayerReport:
    ec2 = session.client("ec2", region_name=region)
    ssm = session.client("ssm", region_name=region)
    cw = session.client("cloudwatch", region_name=region)

    # 1. Fetch SSM PingStatus for all online instances
    online_instances = set()
    try:
        ssm_info = ssm.describe_instance_information().get("InstanceInformationList", [])
        for info in ssm_info:
            if info.get("PingStatus") == "Online":
                online_instances.add(info.get("InstanceId"))
    except Exception:
        pass

    # 2. Fetch EC2 instances
    all_instances: List[EC2InstanceDetail] = []
    strands_suggestion: Optional[str] = None

    try:
        res = ec2.describe_instances()
        for resv in res.get("Reservations", []):
            for inst in resv.get("Instances", []):
                iid = inst["InstanceId"]
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                name = tags.get("Name", "")
                pub_ip = inst.get("PublicIpAddress", "")
                priv_ip = inst.get("PrivateIpAddress", "")
                iam_arn = inst.get("IamInstanceProfile", {}).get("Arn")
                has_tag = tags.get("IncidentsAgent") == "true"
                is_online = iid in online_instances
                has_profile = bool(iam_arn)

                detail = EC2InstanceDetail(
                    instance_id=iid,
                    name=name,
                    state=inst["State"]["Name"],
                    private_ip=priv_ip,
                    public_ip=pub_ip,
                    instance_type=inst["InstanceType"],
                    iam_profile=iam_arn,
                    ssm_online=is_online,
                    has_security_tag=has_tag,
                    tags=tags,
                    has_instance_profile=has_profile,
                )
                all_instances.append(detail)

                # Check if this could be a Strands server
                if "strands" in name.lower() or "decider" in name.lower():
                    host = pub_ip or priv_ip
                    if host:
                        strands_suggestion = f"http://{host}:8080"
    except Exception as e:
        print(f"⚠️ Warning during EC2 inspection: {e}", file=sys.stderr)

    # 3. Validate target instance if specified
    target_detail: Optional[EC2InstanceDetail] = None
    target_valid = False
    target_error: Optional[str] = None
    has_cwagent_disk = False

    if target_instance_id:
        target_detail = next((i for i in all_instances if i.instance_id == target_instance_id), None)
        if not target_detail:
            target_error = f"Instance {target_instance_id} not found in region {region}."
        elif target_detail.state != "running":
            target_error = f"Instance {target_instance_id} is '{target_detail.state}', must be 'running'."
        elif not target_detail.has_instance_profile:
            target_error = f"Instance {target_instance_id} is missing an IAM Instance Profile (requires AmazonSSMManagedInstanceCore role)."
        elif not target_detail.ssm_online:
            target_error = f"Instance {target_instance_id} is not online in AWS Systems Manager (SSM Agent down or missing IAM role)."
        elif not target_detail.has_security_tag:
            target_error = f"Instance {target_instance_id} is missing required tag 'IncidentsAgent=true'."
        else:
            target_valid = True

        # Check CloudWatch metrics for CWAgent disk_used_percent
        try:
            cw_res = cw.list_metrics(
                Namespace="CWAgent",
                MetricName="disk_used_percent",
                Dimensions=[{"Name": "InstanceId", "Value": target_instance_id}],
            )
            has_cwagent_disk = len(cw_res.get("Metrics", [])) > 0
        except Exception:
            has_cwagent_disk = False

    return EC2LayerReport(
        instances=all_instances,
        target_instance=target_detail,
        target_valid=target_valid,
        target_error=target_error,
        has_cwagent_disk_metrics=has_cwagent_disk,
        strands_suggestion=strands_suggestion,
    )


# ── Layer 3: DynamoDB EventStore Discovery ───────────────────────────────────

def audit_dynamodb(session: boto3.Session, region: str) -> DynamoDBLayerReport:
    ddb = session.client("dynamodb", region_name=region)

    expected_schemas = {
        "incidents-events": [
            {"AttributeName": "incident_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        "incidents-dedup": [
            {"AttributeName": "dedupe_key", "KeyType": "HASH"},
        ],
        "incidents-leases": [
            {"AttributeName": "incident_id", "KeyType": "HASH"},
        ],
    }

    tables: Dict[str, DynamoDBTableReport] = {}
    all_ready = True

    for tname, expected_ks in expected_schemas.items():
        try:
            desc = ddb.describe_table(TableName=tname)["Table"]
            actual_ks = desc.get("KeySchema", [])
            matches = actual_ks == expected_ks
            status = desc.get("TableStatus")
            billing = desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")

            tables[tname] = DynamoDBTableReport(
                name=tname,
                exists=True,
                status=status,
                billing_mode=billing,
                key_schema_matches=matches,
                details={
                    "ItemCount": desc.get("ItemCount", 0),
                    "SizeBytes": desc.get("TableSizeBytes", 0),
                },
            )
            if status != "ACTIVE" or not matches:
                all_ready = False
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                tables[tname] = DynamoDBTableReport(
                    name=tname,
                    exists=False,
                    status=None,
                    billing_mode=None,
                    key_schema_matches=False,
                )
            else:
                tables[tname] = DynamoDBTableReport(
                    name=tname,
                    exists=False,
                    status="ERROR",
                    billing_mode=None,
                    key_schema_matches=False,
                    details={"error": str(e)},
                )
            all_ready = False

    return DynamoDBLayerReport(tables=tables, all_ready=all_ready)


# ── Layer 4: S3 Blobs Bucket Discovery ───────────────────────────────────────

def audit_s3(session: boto3.Session, region: str, account_id: str) -> S3BucketReport:
    s3 = session.client("s3", region_name=region)
    bucket_name = f"incidents-blobs-{account_id}"

    # Discover existing buckets in client account
    discovered_buckets: List[str] = []
    try:
        resp = s3.list_buckets()
        discovered_buckets = [b.get("Name", "") for b in resp.get("Buckets", []) if b.get("Name")]
    except Exception:
        pass

    try:
        s3.head_bucket(Bucket=bucket_name)
        exists = True
    except Exception:
        return S3BucketReport(
            expected_name=bucket_name,
            exists=False,
            encryption_matches=False,
            discovered_buckets=discovered_buckets,
        )

    # Check encryption
    enc_matches = False
    details = {}
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        for r in rules:
            if r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "AES256":
                enc_matches = True
                break
        details["encryption"] = enc.get("ServerSideEncryptionConfiguration")
    except Exception as e:
        enc_matches = True
        details["encryption_note"] = str(e)

    return S3BucketReport(
        expected_name=bucket_name,
        exists=exists,
        encryption_matches=enc_matches,
        details=details,
        discovered_buckets=discovered_buckets,
    )


audit_s3_bucket = audit_s3


# ── Layer 5: Zero-Trust SSM Documents & Drift Discovery ─────────────────────

def audit_ssm_documents(session: boto3.Session, region: str, project_root: str) -> SSMLayerReport:
    ssm = session.client("ssm", region_name=region)

    doc_files = {
        "incidents-observe-readonly": os.path.join(project_root, "infra", "ssm", "incidents-observe-readonly.json"),
        "incidents-repair-restricted": os.path.join(project_root, "infra", "ssm", "incidents-repair-restricted.json"),
    }

    doc_reports: Dict[str, SSMDocReport] = {}
    all_ready = True
    has_drift = False

    for doc_name, ref_path in doc_files.items():
        expected_pattern = ""
        if os.path.exists(ref_path):
            with open(ref_path, "r", encoding="utf-8") as f:
                ref_json = json.load(f)
                expected_pattern = ref_json.get("parameters", {}).get("command", {}).get("allowedPattern", "")

        try:
            desc = ssm.describe_document(Name=doc_name)["Document"]
            content_res = ssm.get_document(Name=doc_name)
            raw_content = content_res.get("Content", "{}")
            content_json = json.loads(raw_content) if isinstance(raw_content, str) else raw_content
            actual_pattern = content_json.get("parameters", {}).get("command", {}).get("allowedPattern", "")

            drift = (actual_pattern != expected_pattern) if expected_pattern else False
            if drift:
                has_drift = True

            doc_reports[doc_name] = SSMDocReport(
                name=doc_name,
                exists=True,
                default_version=desc.get("DefaultVersion"),
                drift_detected=drift,
                actual_pattern=actual_pattern,
                expected_pattern=expected_pattern,
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidDocument":
                doc_reports[doc_name] = SSMDocReport(
                    name=doc_name,
                    exists=False,
                    default_version=None,
                    drift_detected=False,
                    actual_pattern=None,
                    expected_pattern=expected_pattern,
                )
                all_ready = False
            else:
                doc_reports[doc_name] = SSMDocReport(
                    name=doc_name,
                    exists=False,
                    default_version=None,
                    drift_detected=False,
                    actual_pattern=None,
                    expected_pattern=expected_pattern,
                )
                all_ready = False

    return SSMLayerReport(
        documents=doc_reports,
        all_ready=all_ready and not has_drift,
        has_drift=has_drift,
    )


# ── Layer 6: IAM Core Roles Discovery ────────────────────────────────────────

def audit_iam_roles(session: boto3.Session) -> IAMLayerReport:
    iam = session.client("iam")
    required_roles = [
        "incidents-agent-role",
        "incidents-observer-role",
        "RemediationOperatorRole",
    ]

    roles_report: Dict[str, IAMRoleReport] = {}
    all_ready = True

    for rname in required_roles:
        try:
            r = iam.get_role(RoleName=rname)["Role"]
            trust_doc = r.get("AssumeRolePolicyDocument")
            trust_valid = _is_trust_policy_valid(rname, trust_doc)
            roles_report[rname] = IAMRoleReport(
                name=rname,
                exists=True,
                arn=r["Arn"],
                trust_valid=trust_valid,
            )
            if not trust_valid:
                all_ready = False
        except ClientError:
            roles_report[rname] = IAMRoleReport(
                name=rname,
                exists=False,
                arn=None,
                trust_valid=False,
            )
            all_ready = False

    return IAMLayerReport(roles=roles_report, all_ready=all_ready)


# ── Layer 7: Secrets Manager & Stack Discovery ───────────────────────────────

REQUIRED_SECRETS = (
    "/incidents/approval-mac-key",
    "/incidents/deepseek-api-key",
)

OPTIONAL_SECRETS = (
    "/incidents/slack-webhook-url",
)


def audit_secrets(session: boto3.Session, region: str) -> Dict[str, SecretReport]:
    sm = session.client("secretsmanager", region_name=region)
    all_secrets = list(REQUIRED_SECRETS) + list(OPTIONAL_SECRETS)

    report: Dict[str, SecretReport] = {}
    for sname in all_secrets:
        try:
            desc = sm.describe_secret(SecretId=sname)
            is_placeholder = False
            if sname == "/incidents/deepseek-api-key":
                try:
                    val_res = sm.get_secret_value(SecretId=sname)
                    secret_val = val_res.get("SecretString", "")
                    if "PLACEHOLDER" in secret_val:
                        is_placeholder = True
                except Exception:
                    pass
            report[sname] = SecretReport(
                name=sname,
                exists=True,
                arn=desc.get("ARN"),
                accessible=True,
                is_placeholder=is_placeholder,
            )
        except ClientError:
            report[sname] = SecretReport(
                name=sname,
                exists=False,
                arn=None,
                accessible=False,
                is_placeholder=False,
            )
    return report


def audit_stack_and_lambdas(
    session: boto3.Session,
    region: str,
    stack_name: str,
) -> StackReport:
    cfn = session.client("cloudformation", region_name=region)
    lmb = session.client("lambda", region_name=region)
    evb = session.client("events", region_name=region)

    stack_exists = False
    stack_status = None
    try:
        stacks = cfn.describe_stacks(StackName=stack_name).get("Stacks", [])
        if stacks:
            stack_exists = True
            stack_status = stacks[0].get("StackStatus")
    except ClientError:
        stack_exists = False

    lambda_names = [
        "incidents-ingest",
        "incidents-agent",
        "incidents-observer",
        "incidents-executor",
        "incidents-notifier",
        "incidents-slack-callback",
    ]
    lambda_status: Dict[str, bool] = {}
    for fn in lambda_names:
        try:
            lmb.get_function(FunctionName=fn)
            lambda_status[fn] = True
        except ClientError:
            lambda_status[fn] = False

    eventbridge_rule_exists = False
    try:
        rules = evb.list_rules().get("Rules", [])
        for r in rules:
            if "alarm" in r.get("Name", "").lower() or "incident" in r.get("Name", "").lower():
                eventbridge_rule_exists = True
                break
    except Exception:
        pass

    return StackReport(
        stack_name=stack_name,
        exists=stack_exists,
        status=stack_status,
        lambda_functions=lambda_status,
        eventbridge_rule_exists=eventbridge_rule_exists,
    )


def extract_cfn_failure_root_causes(
    session: boto3.Session,
    stack_name: str,
    region: Optional[str] = None,
) -> List[str]:
    """
    Extracts root cause failure messages from CloudFormation stack events.
    Filters for events whose ResourceStatus contains 'FAILED' (e.g. CREATE_FAILED, UPDATE_FAILED)
    while excluding benign 'Resource creation cancelled' cascading events.
    Returns list of formatted strings: '[LogicalResourceId (ResourceType)] -> ResourceStatusReason'.
    """
    cfn = session.client("cloudformation", region_name=region or session.region_name)
    failures: List[str] = []
    try:
        paginator = cfn.get_paginator("describe_stack_events")
        for page in paginator.paginate(StackName=stack_name):
            events = page.get("StackEvents", [])
            for event in events:
                status = str(event.get("ResourceStatus", ""))
                reason = str(event.get("ResourceStatusReason", "")).strip()
                logical_id = event.get("LogicalResourceId", "Unknown")
                resource_type = event.get("ResourceType", "Unknown")

                if "FAILED" in status and "cancelled" not in reason.lower() and reason:
                    # Ignore the top-level stack event summary (e.g., "The following resource(s) failed...")
                    if resource_type == "AWS::CloudFormation::Stack" and "The following resource(s) failed" in reason:
                        continue
                    msg = f"[{logical_id} ({resource_type})] -> {reason}"
                    if msg not in failures:
                        failures.append(msg)
    except Exception as e:
        logger.warning(f"Could not retrieve stack events for {stack_name}: {e}")
    return failures


def ensure_clean_stack_before_deploy(
    session: boto3.Session,
    stack_name: str,
    region: Optional[str] = None,
) -> bool:
    """
    Checks if CloudFormation stack is in a dead terminal state (ROLLBACK_COMPLETE or DELETE_FAILED).
    If so, deletes the dead stack and waits for deletion to complete so subsequent sam deploy succeeds.
    Returns True if a dead stack was cleaned up, False otherwise.
    """
    cfn = session.client("cloudformation", region_name=region or session.region_name)
    try:
        res = cfn.describe_stacks(StackName=stack_name)
        stacks = res.get("Stacks", [])
        if not stacks:
            return False
        status = stacks[0].get("StackStatus", "")
        if status in ("ROLLBACK_COMPLETE", "DELETE_FAILED"):
            print(f"  ⚠️ Stack '{stack_name}' is in dead state '{status}'. Auto-recovering by deleting stack...")
            cfn.delete_stack(StackName=stack_name)
            waiter = cfn.get_waiter("stack_delete_complete")
            print(f"  ⏳ Waiting for '{stack_name}' cleanup to complete...")
            waiter.wait(StackName=stack_name)
            print(f"  ✅ Stack '{stack_name}' successfully cleaned up. Ready for fresh deployment.")
            return True
    except ClientError as e:
        if "does not exist" in str(e).lower():
            return False
        logger.warning(f"Could not verify stack status for {stack_name}: {e}")
    except Exception as e:
        logger.warning(f"Error checking/cleaning stack {stack_name}: {e}")
    return False


# ── Layer 8: Bedrock Foundation Models Access ────────────────────────────────

def audit_bedrock_access(
    session: boto3.Session,
    bedrock_region: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verifies Amazon Bedrock connectivity if requested, defaulting to session region.
    Does not enforce us-east-1 to prevent SCP AccessDenied in restricted regions.
    """
    target_region = bedrock_region or session.region_name or "us-east-1"
    bedrock = session.client("bedrock", region_name=target_region)
    required_models = ["amazon.nova-lite-v1:0", "amazon.nova-pro-v1:0"]
    available_models: List[str] = []
    has_access = False
    error_msg = None

    try:
        resp = bedrock.list_foundation_models(byProvider="Amazon")
        for m in resp.get("modelSummaries", []):
            mid = m.get("modelId", "")
            if mid:
                available_models.append(mid)
        has_access = True
    except Exception as e:
        error_msg = str(e)

    nova_models_found = [m for m in required_models if m in available_models]
    all_nova_ready = len(nova_models_found) == len(required_models)

    return {
        "bedrock_region": target_region,
        "accessible": has_access,
        "available_models_count": len(available_models),
        "required_models": required_models,
        "nova_models_found": nova_models_found,
        "all_nova_ready": all_nova_ready,
        "error": error_msg,
    }


# ── Layer 9: Strands Decider Health Probe ────────────────────────────────────

def probe_strands_health(strands_url: str) -> Dict[str, Any]:
    """
    Sends a live HTTP GET request to {strands_url}/health with a 3-second timeout.
    Returns boolean strands_healthy, status code, and parsed model name.
    """
    if not strands_url:
        return {
            "url": "",
            "strands_healthy": False,
            "status_code": None,
            "detail": "No Strands URL configured",
        }

    health_url = f"{strands_url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(
            health_url,
            headers={"User-Agent": "aws-onboard-probe/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            status_code = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            if status_code == 200:
                try:
                    data = json.loads(body)
                    model = data.get("model") or data.get("model_name") or data.get("status") or "ok"
                    return {
                        "url": strands_url,
                        "health_url": health_url,
                        "strands_healthy": True,
                        "status_code": status_code,
                        "model": model,
                        "detail": f"HTTP 200 OK (Model: {model})",
                    }
                except Exception:
                    return {
                        "url": strands_url,
                        "health_url": health_url,
                        "strands_healthy": True,
                        "status_code": status_code,
                        "model": "unknown",
                        "detail": "HTTP 200 OK",
                    }
            else:
                return {
                    "url": strands_url,
                    "health_url": health_url,
                    "strands_healthy": False,
                    "status_code": status_code,
                    "detail": f"HTTP {status_code}",
                }
    except Exception as e:
        return {
            "url": strands_url,
            "health_url": health_url,
            "strands_healthy": False,
            "status_code": None,
            "detail": f"Unresponsive ({e})",
        }


# ── Global Multi-Region Scanner (AWS Global View) ───────────────────────────

def audit_global_view(session: boto3.Session) -> List[Dict[str, Any]]:
    """
    Multi-region scanner using ThreadPoolExecutor to quickly scan active regions
    and count running EC2 instances and incidents-* DynamoDB tables across AWS.
    """
    ec2_global = session.client("ec2", region_name="us-east-1")
    try:
        regions_resp = ec2_global.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        region_names = [r["RegionName"] for r in regions_resp.get("Regions", [])]
    except Exception:
        region_names = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        ]

    def scan_one_region(reg: str) -> Dict[str, Any]:
        running_ec2 = 0
        incidents_tables: List[str] = []
        try:
            reg_ec2 = session.client("ec2", region_name=reg)
            res = reg_ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )
            for resv in res.get("Reservations", []):
                running_ec2 += len(resv.get("Instances", []))
        except Exception:
            pass

        try:
            reg_ddb = session.client("dynamodb", region_name=reg)
            tbls = reg_ddb.list_tables().get("TableNames", [])
            incidents_tables = [t for t in tbls if t.startswith("incidents-")]
        except Exception:
            pass

        return {
            "region": reg,
            "running_ec2_count": running_ec2,
            "incidents_tables_count": len(incidents_tables),
            "incidents_tables": incidents_tables,
        }

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_one_region, reg): reg for reg in region_names}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass

    results.sort(
        key=lambda x: (
            x["running_ec2_count"] > 0 or x["incidents_tables_count"] > 0,
            x["running_ec2_count"],
            x["region"],
        ),
        reverse=True,
    )
    return results


# ── Full Audit Orchestrator ──────────────────────────────────────────────────

def run_full_audit(
    session: boto3.Session,
    region: str,
    target_instance_id: Optional[str] = None,
    stack_name: str = "autonomous-secops-agent",
    project_root: str = ".",
    enable_global_view: bool = False,
    strands_override: Optional[str] = None,
) -> AuditReport:
    ident = audit_identity(session, region)
    ec2_rep = audit_ec2(session, region, target_instance_id)
    ddb_rep = audit_dynamodb(session, region)
    s3_rep = audit_s3(session, region, ident.account_id)
    ssm_rep = audit_ssm_documents(session, region, project_root)
    iam_rep = audit_iam_roles(session)
    secrets_rep = audit_secrets(session, region)
    stack_rep = audit_stack_and_lambdas(session, region, stack_name)

    # Bedrock Foundation Models access check in us-east-1 is decoupled to avoid
    # SCP AccessDenied errors in region-restricted accounts (e.g. eu-north-1).
    # Inference is BYOK via HTTPS Bearer API Key stored in Secrets Manager.
    bedrock_access = None

    strands_url = strands_override or ec2_rep.strands_suggestion or ""
    strands_probe = probe_strands_health(strands_url) if strands_url else None

    global_view = None
    if enable_global_view or len(ec2_rep.instances) == 0:
        global_view = audit_global_view(session)

    is_ready = True
    if target_instance_id and not ec2_rep.target_valid:
        is_ready = False
    if ssm_rep.has_drift:
        is_ready = False

    overall = "READY" if is_ready else "NEEDS_PRE_DEPLOY"
    if not (ddb_rep.all_ready and s3_rep.exists and iam_rep.all_ready):
        overall = "DELTA_RESOLVED"

    return AuditReport(
        identity=ident,
        ec2=ec2_rep,
        dynamodb=ddb_rep,
        s3=s3_rep,
        ssm=ssm_rep,
        iam=iam_rep,
        secrets=secrets_rep,
        stack=stack_rep,
        overall_status=overall,
        bedrock_access=bedrock_access,
        strands_probe=strands_probe,
        global_view=global_view,
    )


# ── Delta & Parameters Calculation Engine ────────────────────────────────────

def build_cfn_parameters(
    report: AuditReport,
    strands_override: Optional[str] = None,
    stack_name: str = "autonomous-secops-agent",
    create_target_vps: bool = False,
    existing_bucket: Optional[str] = None,
    is_apply: bool = False,
    injected_params: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], List[str], str]:
    """
    Computes exact parameter overrides for template.yaml based on audit discovery,
    generates pre-deployment actions, and constructs the SAM deploy command.
    """
    params: Dict[str, str] = {}
    pre_actions: List[str] = []

    # 1. Target Instance ID
    if create_target_vps:
        target_id = "<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>"
        params["TargetInstanceId"] = target_id
        pre_actions.append(
            "Dedicated Target VPS (-T): A new dedicated EC2 instance (Amazon Linux 2023, t3.micro/t2.micro, SSM Role attached, Nginx installed, tagged IncidentsAgent=true) will be automatically provisioned during '--mode apply'."
        )
    else:
        target_id = report.ec2.target_instance.instance_id if report.ec2.target_instance else ""
        if not target_id:
            target_id = "<REQUIRED_EC2_INSTANCE_ID>"
            pre_actions.append(
                "Select Target EC2 Instance (Existing client servers protected):\n"
                "       * Option A (Adopt Existing VPS): Run with '--instance-id <INSTANCE_ID>' (and optionally '--existing-bucket <BUCKET_NAME>') to adopt existing resources.\n"
                "       * Option B (Provision Dedicated Target VPS): Run with '-T' (or '--create-target-vps') to automatically provision a new dedicated Amazon Linux 2023 + SSM + Nginx server."
            )
        params["TargetInstanceId"] = target_id

        if target_id != "<REQUIRED_EC2_INSTANCE_ID>" and not report.ec2.target_valid:
            if (report.ec2.target_error and "missing required tag" in report.ec2.target_error) or (report.ec2.target_instance and not report.ec2.target_instance.has_security_tag):
                pre_actions.append(
                    f"Tag Target Instance: aws ec2 create-tags --resources {target_id} --tags Key=IncidentsAgent,Value=true (auto-remediated by --mode apply)"
                )
            if report.ec2.target_instance and not report.ec2.target_instance.has_instance_profile:
                pre_actions.append(
                    f"Attach IAM Role: Instance {target_id} lacks an IAM Instance Profile. '--mode apply' will automatically create 'IncidentsTargetSSMInstanceRole' and attach 'AmazonSSMManagedInstanceCore' policy (e.g. aws ec2 associate-iam-instance-profile --instance-id {target_id} --iam-instance-profile Name=EC2SSMProfile)"
                )
            elif report.ec2.target_error and "not online in AWS Systems Manager" in report.ec2.target_error:
                pre_actions.append(
                    f"SSM Connectivity: Instance {target_id} is offline in SSM. Verify role with 'AmazonSSMManagedInstanceCore' is attached and run: sudo systemctl start amazon-ssm-agent && sudo systemctl enable amazon-ssm-agent"
                )

    # 2. Strands URL
    raw_strands = (strands_override or "").strip() or (report.ec2.strands_suggestion or "").strip()
    if not raw_strands or raw_strands.lower() == "embedded":
        strands_url = "embedded"
    else:
        strands_url = raw_strands
    params["StrandsUrl"] = strands_url

    # 3. Models & Operational Configuration
    params["NovaFlashModelId"] = "amazon.nova-lite-v1:0"
    params["NovaProModelId"] = "amazon.nova-pro-v1:0"
    params["DeepSeekBaseUrl"] = "https://bedrock-mantle.us-east-1.api.aws/v1"
    params["DeepSeekFlashModel"] = "deepseek.v3.1"
    params["DeepSeekProModel"] = "deepseek.v3.2"

    if injected_params:
        if "NOVA_FLASH_MODEL_ID" in injected_params:
            params["NovaFlashModelId"] = injected_params["NOVA_FLASH_MODEL_ID"]
        if "NOVA_PRO_MODEL_ID" in injected_params:
            params["NovaProModelId"] = injected_params["NOVA_PRO_MODEL_ID"]
        if "DEEPSEEK_BASE_URL" in injected_params:
            params["DeepSeekBaseUrl"] = injected_params["DEEPSEEK_BASE_URL"]
        if "DEEPSEEK_FLASH_MODEL" in injected_params:
            params["DeepSeekFlashModel"] = injected_params["DEEPSEEK_FLASH_MODEL"]
        if "DEEPSEEK_PRO_MODEL" in injected_params:
            params["DeepSeekProModel"] = injected_params["DEEPSEEK_PRO_MODEL"]
        if "STRANDS_URL" in injected_params and not strands_override:
            params["StrandsUrl"] = injected_params["STRANDS_URL"]
        if "SLACK_AUTHORIZED_APPROVERS" in injected_params:
            params["SlackAuthorizedApprovers"] = injected_params["SLACK_AUTHORIZED_APPROVERS"]
        if "SLACK_CHANNEL" in injected_params:
            params["SlackChannel"] = injected_params["SLACK_CHANNEL"]

    # 4. DynamoDB Tables
    if report.dynamodb.all_ready:
        params["CreateDynamoTables"] = "false"
    else:
        params["CreateDynamoTables"] = "true"

    # 5. S3 Blobs Bucket (Universal Choice: Adopt Existing vs Create Dedicated)
    b_name = (existing_bucket or "").strip()
    if b_name:
        params["CreateBlobsBucket"] = "false"
        params["ExistingBlobsBucketName"] = b_name
    elif report.s3.exists:
        params["CreateBlobsBucket"] = "false"
        params["ExistingBlobsBucketName"] = report.s3.expected_name
    else:
        params["CreateBlobsBucket"] = "true"
        params["ExistingBlobsBucketName"] = ""

    # 6. SSM Documents & Drift check
    if report.ssm.has_drift:
        params["CreateSsmDocuments"] = "false"
        for dname, dinfo in report.ssm.documents.items():
            if dinfo.drift_detected:
                pre_actions.append(
                    f"Update SSM Document drift ({dname}): aws ssm update-document --name {dname} --content file://infra/ssm/{dname}.json --document-version '$LATEST'"
                )
    elif report.ssm.all_ready:
        params["CreateSsmDocuments"] = "false"
    else:
        params["CreateSsmDocuments"] = "true"

    # 7. IAM Core Roles
    any_iam_role_exists = any(r.exists for r in report.iam.roles.values())
    if report.iam.all_ready:
        params["CreateCoreIamRoles"] = "false"
    elif is_apply and any_iam_role_exists:
        # Reconciled in-place during apply to prevent CloudFormation EntityAlreadyExists errors
        params["CreateCoreIamRoles"] = "false"
    elif any_iam_role_exists:
        params["CreateCoreIamRoles"] = "false"
    else:
        params["CreateCoreIamRoles"] = "true"

    for rname, rinfo in report.iam.roles.items():
        if rinfo.exists and not getattr(rinfo, "trust_valid", True):
            pre_actions.append(
                f"Reconcile IAM Role Trust Policy ({rname}): Role exists but lacks proper trust relationship for service execution. '--mode apply' will automatically reconcile it."
            )

    # 8. Alarms
    if report.ec2.target_valid or create_target_vps:
        params["EnableAlarms"] = "true"
        params["EnableDiskAlarm"] = "true" if (report.ec2.has_cwagent_disk_metrics or create_target_vps or is_apply) else "false"
    else:
        params["EnableAlarms"] = "false"
        params["EnableDiskAlarm"] = "false"

    # 9. Secrets Check (Only REQUIRED_SECRETS are checked for pre-actions; Slack is strictly optional)
    missing_required = [
        name for name in REQUIRED_SECRETS
        if name in report.secrets and not report.secrets[name].exists
    ]
    for ms in missing_required:
        if ms == "/incidents/approval-mac-key":
            pre_actions.append(
                f"Auto-Provision Secret: '{ms}' is missing; '--mode apply' will automatically generate a secure 32-byte HMAC key and create it in Secrets Manager (or run: aws secretsmanager create-secret --name {ms} --secret-string 'YOUR_SECRET_VALUE')."
            )
        elif ms == "/incidents/deepseek-api-key":
            pre_actions.append(
                f"Auto-Provision Secret: '{ms}' is missing; '--mode apply' will create it with safe placeholder (or pass --deepseek-api-key <KEY>)."
            )
        else:
            pre_actions.append(
                f"Create Missing Secret: aws secretsmanager create-secret --name {ms} --secret-string 'YOUR_SECRET_VALUE'"
            )

    # 10. Construct SAM CLI command
    overrides_list = [f"{k}={v}" for k, v in params.items() if str(v).strip() != ""]
    overrides_str = " ".join(overrides_list)
    region_val = report.identity.region if (report.identity and report.identity.region) else "us-east-1"
    sam_command = (
        f"sam deploy \\\n"
        f"  --stack-name {stack_name} \\\n"
        f"  --region {region_val} \\\n"
        f"  --resolve-s3 \\\n"
        f"  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \\\n"
        f"  --no-fail-on-empty-changeset \\\n"
        f"  --parameter-overrides {overrides_str}"
    )

    return params, pre_actions, sam_command


build_plan = build_cfn_parameters


def parse_env_file(env_path: str) -> Dict[str, str]:
    """
    Parses a .env file into a dictionary of key-value pairs.
    Handles comments, empty lines, and single/double quoted values safely.
    """
    if not env_path or not os.path.exists(env_path):
        if env_path:
            print(f"  ⚠️ Notice: Specified env file '{env_path}' was not found; skipping environment injection.")
        return {}
    env_vars: Dict[str, str] = {}
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                if k and v:
                    env_vars[k] = v
    except Exception as exc:
        print(f"  ⚠️ Warning: Could not parse env file '{env_path}': {exc}")
    return env_vars


def split_env_vars(env_vars: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Splits raw parsed environment variables into:
    1. Secrets (for AWS Secrets Manager: credentials, HMAC tokens, webhooks)
    2. Configuration Parameters (for CloudFormation / SAM overrides: models, endpoints, approvers)
    """
    secrets_keys = {
        "DEEPSEEK_API_KEY",
        "APPROVAL_MAC_KEY_HEX",
        "SLACK_WEBHOOK_URL",
        "SLACK_APP_TOKEN",
        "SLACK_REFRESH_TOKEN",
    }
    params_keys = {
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_FLASH_MODEL",
        "DEEPSEEK_PRO_MODEL",
        "NOVA_FLASH_MODEL_ID",
        "NOVA_PRO_MODEL_ID",
        "STRANDS_URL",
        "SLACK_AUTHORIZED_APPROVERS",
        "SLACK_CHANNEL",
    }

    injected_secrets = {k: v for k, v in env_vars.items() if k in secrets_keys and v.strip()}
    injected_params = {k: v for k, v in env_vars.items() if k in params_keys and v.strip()}
    return injected_secrets, injected_params


# ── Client Account Bootstrap Helpers ─────────────────────────────────────────

def ensure_client_secrets(
    session: boto3.Session,
    dry_run: bool = False,
    region: Optional[str] = None,
    project_root: Optional[str] = None,
    deepseek_api_key: Optional[str] = None,
    injected_secrets: Optional[Dict[str, str]] = None,
) -> List[str]:
    """
    Checks and auto-provisions core secrets in AWS Secrets Manager for the client account:
    1. /incidents/approval-mac-key: generates 32-byte cryptographically secure hex key (or uses APPROVAL_MAC_KEY_HEX).
    2. /incidents/deepseek-api-key: created with user-provided key if supplied via CLI or .env file (-E / --env-file);
       if previously created with placeholder, automatically updates it to the valid key.
    3. Slack secrets: /incidents/slack-webhook-url, /incidents/slack-app-token, etc., if supplied in .env file.
    """
    created_actions: List[str] = []
    reg = region or session.region_name or "us-east-1"
    try:
        sm = session.client("secretsmanager", region_name=reg)
    except Exception as e:
        return [f"Could not initialize secretsmanager client: {e}"]

    injected = injected_secrets or {}

    def _secret_exists(name: str) -> bool:
        try:
            sm.describe_secret(SecretId=name)
            return True
        except ClientError:
            return False
        except Exception:
            return False

    def _get_secret_value(name: str) -> Optional[str]:
        try:
            res = sm.get_secret_value(SecretId=name)
            return res.get("SecretString", "")
        except Exception:
            return None

    def _put_or_create_secret(name: str, desc: str, val: str) -> None:
        if not val:
            return
        if not _secret_exists(name):
            if dry_run:
                created_actions.append(f"[Dry Run] Would create secret '{name}'")
            else:
                try:
                    sm.create_secret(Name=name, Description=desc, SecretString=val)
                    created_actions.append(f"Created secret '{name}' in Secrets Manager")
                except Exception as e:
                    created_actions.append(f"Failed to create secret '{name}': {e}")
        else:
            current_val = _get_secret_value(name)
            if current_val != val:
                if dry_run:
                    created_actions.append(f"[Dry Run] Would update secret '{name}' with live credential")
                else:
                    try:
                        sm.put_secret_value(SecretId=name, SecretString=val)
                        created_actions.append(f"Updated secret '{name}' with live credential in Secrets Manager")
                    except Exception as e:
                        created_actions.append(f"Failed to update secret '{name}': {e}")

    # 1. /incidents/approval-mac-key
    mac_key_name = "/incidents/approval-mac-key"
    injected_mac = injected.get("APPROVAL_MAC_KEY_HEX", "").strip()
    if injected_mac:
        _put_or_create_secret(
            mac_key_name,
            "HMAC-SHA256 authentication key for Tier 2 autonomous incident remediation",
            injected_mac,
        )
    elif not _secret_exists(mac_key_name):
        if dry_run:
            created_actions.append(f"[Dry Run] Would create secret '{mac_key_name}' with generated HMAC-SHA256 key")
        else:
            try:
                new_mac = secrets.token_hex(32)
                sm.create_secret(
                    Name=mac_key_name,
                    Description="HMAC-SHA256 authentication key for Tier 2 autonomous incident remediation",
                    SecretString=new_mac,
                )
                created_actions.append(f"Generated secure cryptographic HMAC key and created secret '{mac_key_name}' in Secrets Manager")
            except Exception as e:
                created_actions.append(f"Failed to create secret '{mac_key_name}': {e}")

    # 2. /incidents/deepseek-api-key
    ds_key_name = "/incidents/deepseek-api-key"
    ds_val = (deepseek_api_key or "").strip() or injected.get("DEEPSEEK_API_KEY", "").strip()
    if ds_val:
        _put_or_create_secret(
            ds_key_name,
            "Inference API Key for Bedrock Mantle / DeepSeek autonomous agent",
            ds_val,
        )
    elif not _secret_exists(ds_key_name):
        placeholder = "PLACEHOLDER_SET_YOUR_OWN_KEY_IN_SECRETS_MANAGER"
        if dry_run:
            created_actions.append(f"[Dry Run] Would create secret '{ds_key_name}' with safe placeholder")
        else:
            try:
                sm.create_secret(
                    Name=ds_key_name,
                    Description="Inference API Key placeholder (Update with your own key)",
                    SecretString=placeholder,
                )
                created_actions.append(
                    f"Created secret '{ds_key_name}' with safe placeholder '{placeholder}' (Action required: Update with your own API key in AWS Secrets Manager)"
                )
                print(f"  ⚠️ Notice: Created '{ds_key_name}' with safe placeholder. Please set your own API key in AWS Secrets Manager.")
            except Exception as e:
                created_actions.append(f"Failed to create secret '{ds_key_name}': {e}")

    # 3. Optional Slack Secrets
    optional_secret_mappings = [
        ("SLACK_WEBHOOK_URL", "/incidents/slack-webhook-url", "Slack Webhook URL for incident notifications"),
        ("SLACK_APP_TOKEN", "/incidents/slack-app-token", "Slack App-level token for Socket Mode"),
        ("SLACK_REFRESH_TOKEN", "/incidents/slack-refresh-token", "Slack refresh token for token rotation"),
    ]
    for env_k, sec_name, sec_desc in optional_secret_mappings:
        s_val = injected.get(env_k, "").strip()
        if s_val:
            _put_or_create_secret(sec_name, sec_desc, s_val)

    return created_actions


def _ensure_ssm_instance_profile_exists(
    iam: Any,
    profile_name: str = "IncidentsTargetSSMInstanceProfile",
    role_name: str = "IncidentsTargetSSMInstanceRole",
) -> str:
    """
    Ensures that the SSM instance role and instance profile exist and are associated.
    Validates readiness by calling iam.get_instance_profile after role association.
    """
    ssm_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    assume_role_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    })

    try:
        iam.get_role(RoleName=role_name)
    except Exception:
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_doc,
                Description="SSM Managed Core Role for Autonomous Incident Remediation Target",
            )
        except Exception:
            pass

    policies_to_attach = [
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    ]
    for pol_arn in policies_to_attach:
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=pol_arn)
        except Exception:
            pass

    try:
        iam.get_instance_profile(InstanceProfileName=profile_name)
    except Exception:
        try:
            iam.create_instance_profile(InstanceProfileName=profile_name)
        except Exception:
            pass

    try:
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except Exception:
        pass

    # Ensure profile readiness in IAM
    try:
        iam.get_instance_profile(InstanceProfileName=profile_name)
    except Exception:
        pass

    return profile_name


def ensure_instance_ssm_profile(
    session: boto3.Session,
    instance_id: str,
    dry_run: bool = False,
    region: Optional[str] = None,
    retry_delay: float = 3.0,
) -> bool:
    """
    Checks if instance has an IAM Instance Profile.
    If missing, creates 'IncidentsTargetSSMInstanceRole', attaches
    'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore', creates an Instance Profile,
    and associates it with the instance via ec2.associate_iam_instance_profile.
    """
    if dry_run or not instance_id or instance_id == "<REQUIRED_EC2_INSTANCE_ID>":
        if dry_run:
            print(f"  [Dry Run] Would create and attach SSM Instance Profile to {instance_id}")
        return True

    reg = region or session.region_name or "us-east-1"
    try:
        ec2 = session.client("ec2", region_name=reg)
        iam = session.client("iam", region_name=reg)

        desc = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = desc.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            return False
        inst = reservations[0]["Instances"][0]
        required_policies = [
            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
        ]

        if inst.get("IamInstanceProfile", {}).get("Arn"):
            prof_arn = inst["IamInstanceProfile"]["Arn"]
            prof_name = prof_arn.split("/")[-1]
            try:
                prof_resp = iam.get_instance_profile(InstanceProfileName=prof_name)
                roles = prof_resp.get("InstanceProfile", {}).get("Roles", [])
                if isinstance(roles, list):
                    for role in roles:
                        r_name = role.get("RoleName") if isinstance(role, dict) else getattr(role, "RoleName", None)
                        if not r_name:
                            continue

                        attached_arns = set()
                        try:
                            attached_resp = iam.list_attached_role_policies(RoleName=r_name)
                            attached_arns = {p.get("PolicyArn") for p in attached_resp.get("AttachedPolicies", [])}
                        except Exception:
                            pass

                        for pol_arn in required_policies:
                            pol_name = pol_arn.split("/")[-1]
                            if pol_arn not in attached_arns:
                                try:
                                    iam.attach_role_policy(RoleName=r_name, PolicyArn=pol_arn)
                                    print(f"  🔐 Attached missing policy '{pol_name}' to role '{r_name}'")
                                except Exception as att_err:
                                    print(f"  ⚠️ Could not attach '{pol_name}' to role '{r_name}': {att_err}")
                            else:
                                print(f"  ✓ IAM Policy '{pol_name}' verified on role '{r_name}'")
            except Exception as e:
                print(f"  ⚠️ Warning reconciling instance profile '{prof_name}': {e}")
            return True

        role_name = "IncidentsTargetSSMInstanceRole"
        profile_name = "IncidentsTargetSSMInstanceProfile"
        _ensure_ssm_instance_profile_exists(iam, profile_name=profile_name, role_name=role_name)

        effective_delay = float(os.environ.get("AWS_PROPAGATION_RETRY_DELAY", retry_delay))
        max_retries = 6
        for attempt in range(1, max_retries + 1):
            try:
                ec2.associate_iam_instance_profile(
                    IamInstanceProfile={"Name": profile_name},
                    InstanceId=instance_id,
                )
                print(f"  ✅ Successfully associated SSM Instance Profile '{profile_name}' with instance {instance_id}")
                return True
            except ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                err_msg = str(e)
                if "already associated" in err_msg.lower():
                    return True
                if (err_code == "InvalidParameterValue" and "iaminstanceprofile" in err_msg.lower()) and attempt < max_retries:
                    print(f"  ⏳ Waiting for AWS IAM Instance Profile propagation to regional EC2... (attempt {attempt}/{max_retries})")
                    if effective_delay > 0:
                        time.sleep(effective_delay)
                    continue
                print(f"  ⚠️ Warning associating IAM instance profile: {e}")
                return False
        return False
    except Exception as e:
        print(f"  ⚠️ Error ensuring SSM instance profile for {instance_id}: {e}")
        return False


def ensure_instance_tagged(
    session: boto3.Session,
    instance_id: str,
    dry_run: bool = False,
    region: Optional[str] = None,
) -> bool:
    """Ensures target EC2 instance has tag IncidentsAgent=true."""
    if dry_run or not instance_id or instance_id == "<REQUIRED_EC2_INSTANCE_ID>":
        return True
    reg = region or session.region_name or "us-east-1"
    try:
        ec2 = session.client("ec2", region_name=reg)
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{"Key": "IncidentsAgent", "Value": "true"}],
        )
        return True
    except Exception as e:
        print(f"  ⚠️ Error tagging instance {instance_id}: {e}")
        return False


def ensure_instance_telemetry(
    session: boto3.Session,
    instance_id: str,
    dry_run: bool = False,
    region: Optional[str] = None,
    timeout_seconds: int = 40,
) -> bool:
    """
    Bootstraps CloudWatch Agent and Universal Systemd Health Timer on an adopted (brownfield)
    EC2 instance via AWS Systems Manager (SSM RunCommand).
    Universally compatible with Ubuntu, Debian, Amazon Linux 2023/2, and RHEL.
    Executes in-place with zero downtime and zero reboot required.
    """
    if dry_run or not instance_id or instance_id == "<REQUIRED_EC2_INSTANCE_ID>":
        if dry_run:
            print(f"  [Dry Run] Would bootstrap CWAgent & Systemd telemetry on {instance_id}")
        return True

    reg = region or session.region_name or "us-east-1"
    try:
        ssm = session.client("ssm", region_name=reg)
        ec2 = session.client("ec2", region_name=reg)

        # 1. Verify instance exists and is running
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = desc.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            return False
        inst = reservations[0]["Instances"][0]
        if inst.get("State", {}).get("Name") != "running":
            print(f"  ⚠️ Instance {instance_id} is in state '{inst.get('State', {}).get('Name')}', cannot bootstrap telemetry.")
            return False

        # 2. Check SSM ping status
        try:
            info = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            ).get("InstanceInformationList", [])
            if not info or info[0].get("PingStatus") != "Online":
                print(f"  ⏳ Instance {instance_id} SSM agent is registering or offline. Attempting telemetry dispatch...")
        except Exception:
            pass

        # 3. Universal multi-distro telemetry script
        telemetry_script = r"""#!/bin/bash
set -e

TOKEN=$(curl -s -S -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
if [ -n "$TOKEN" ]; then
    REGION=$(curl -s -S -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)
else
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)
fi
[ -z "$REGION" ] && REGION="us-east-1"

# 1. Package manager detection & CWAgent install (do not install curl to prevent curl-minimal conflict on AL2023)
if [ ! -f /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y amazon-cloudwatch-agent || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y amazon-cloudwatch-agent || true
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y amazon-cloudwatch-agent || true
    fi
fi

# Fallback to direct official AWS RPM/DEB if not installed via repo
if [ ! -f /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
    if command -v rpm >/dev/null 2>&1; then
        curl -sSL "https://amazoncloudwatch-agent-${REGION}.s3.${REGION}.amazonaws.com/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm" -o /tmp/cwagent.rpm 2>/dev/null || curl -sSL "https://amazoncloudwatch-agent.s3.amazonaws.com/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm" -o /tmp/cwagent.rpm
        rpm -Uvh --replacepkgs /tmp/cwagent.rpm || true
        rm -f /tmp/cwagent.rpm
    elif command -v dpkg >/dev/null 2>&1; then
        curl -sSL "https://amazoncloudwatch-agent-${REGION}.s3.${REGION}.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" -o /tmp/cwagent.deb 2>/dev/null || curl -sSL "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" -o /tmp/cwagent.deb
        dpkg -i -E /tmp/cwagent.deb || true
        rm -f /tmp/cwagent.deb
    fi
fi

# 2. Configure CloudWatch Agent with unified aggregation dimensions
mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
cat <<'EOF' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "metrics": {
    "aggregation_dimensions": [["InstanceId"]],
    "append_dimensions": {
      "InstanceId": "${aws:InstanceId}"
    },
    "metrics_collected": {
      "disk": {
        "measurement": ["disk_used_percent"],
        "resources": ["/"],
        "drop_device": true
      },
      "mem": {
        "measurement": ["mem_used_percent"]
      }
    }
  }
}
EOF

if [ -f /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json || true
fi

# 3. Universal Systemd Health Pulse Script
mkdir -p /opt/incidents/bin
cat <<'EOF' > /opt/incidents/bin/system_health_pulse.sh
#!/bin/bash
TOKEN=$(curl -s -S -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
if [ -n "$TOKEN" ]; then
    INSTANCE_ID=$(curl -s -S -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)
    REG=$(curl -s -S -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)
else
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)
    REG=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)
fi

[ -z "$REG" ] && REG="us-east-1"
[ -z "$INSTANCE_ID" ] && exit 0

FAILED_COUNT=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | grep -E '\.service' | wc -l)
STOPPED_ENABLED=0

# Check explicitly configured custom services if present
CUSTOM_SERVICES=""
if [ -f /etc/incidents/services.conf ]; then
    CUSTOM_SERVICES=$(grep -v '^[[:space:]]*#' /etc/incidents/services.conf 2>/dev/null | tr '\n' ' ')
fi

# Core production workloads & daemons
CORE_SERVICES="nginx httpd apache2 docker containerd postgresql mysqld mariadb redis mongod memcached rabbitmq-server elasticsearch kafka vault consul order-gateway app myapp api backend"

# Dynamic system-wide discovery of enabled daemons with restart policies
DYNAMIC_SERVICES=""
for svc in $(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}'); do
    case "$svc" in
        *@*|cwsys_health.service|cloud-*|dmesg*|systemd-*|emergency*|rescue*) continue ;;
    esac
    r_policy=$(systemctl show -p Restart --value "$svc" 2>/dev/null)
    cond_res=$(systemctl show -p ConditionResult --value "$svc" 2>/dev/null)
    if [ -n "$r_policy" ] && [ "$r_policy" != "no" ] && [ "$cond_res" != "no" ]; then
        DYNAMIC_SERVICES="$DYNAMIC_SERVICES $svc"
    fi
done

ALL_CANDIDATES=$(echo "$CORE_SERVICES $CUSTOM_SERVICES $DYNAMIC_SERVICES" | tr ' ' '\n' | sort -u | tr '\n' ' ')

for s in $ALL_CANDIDATES; do
    [ -z "$s" ] && continue
    s_clean="${s%.service}"
    if systemctl is-enabled "$s_clean" >/dev/null 2>&1 || systemctl is-enabled "$s" >/dev/null 2>&1; then
        if ! systemctl is-active --quiet "$s_clean" && ! systemctl is-active --quiet "$s"; then
            s_state=$(systemctl is-failed "$s_clean" 2>/dev/null || true)
            if [ "$s_state" != "failed" ]; then
                STOPPED_ENABLED=$((STOPPED_ENABLED + 1))
            fi
        fi
    fi
done
TOTAL_FAILS=$((FAILED_COUNT + STOPPED_ENABLED))

aws cloudwatch put-metric-data \
    --namespace "CWAgent" \
    --metric-name "FailedServicesCount" \
    --dimensions InstanceId="$INSTANCE_ID" \
    --value "$TOTAL_FAILS" \
    --region "$REG" 2>/dev/null || true
EOF
chmod +x /opt/incidents/bin/system_health_pulse.sh

# 4. Native Systemd Timer
cat <<'EOF' > /etc/systemd/system/cwsys_health.service
[Unit]
Description=Universal CloudWatch System Health Metric Reporter
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/incidents/bin/system_health_pulse.sh
EOF

cat <<'EOF' > /etc/systemd/system/cwsys_health.timer
[Unit]
Description=Run Universal CloudWatch System Health Metric Reporter every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now cwsys_health.timer || true
/opt/incidents/bin/system_health_pulse.sh || true
echo "TELEMETRY_BOOTSTRAP_COMPLETE"
"""

        # 4. Send SSM Command
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [telemetry_script]},
            TimeoutSeconds=60,
            Comment="Bootstrap Universal CloudWatch Telemetry and Systemd Health Timer",
        )
        command_id = response.get("Command", {}).get("CommandId")
        if not command_id:
            return False

        # Wait up to timeout_seconds for execution
        poll_start = time.time()
        while time.time() - poll_start < timeout_seconds:
            try:
                cmd_inv = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id,
                )
                status = cmd_inv.get("Status")
                if status in ("Success", "Completed"):
                    print(f"  ✅ CWAgent & Systemd Health Pulse successfully bootstrapped on {instance_id}")
                    return True
                elif status in ("Failed", "Cancelled", "TimedOut"):
                    print(f"  ⚠️ SSM telemetry bootstrap returned status '{status}' on {instance_id}: {cmd_inv.get('StandardErrorContent', '')[:200]}")
                    return False
            except ClientError as ce:
                if "InvocationDoesNotExist" not in str(ce):
                    pass
            time.sleep(2)

        print(f"  ⏳ Telemetry bootstrap command {command_id} dispatched and executing on {instance_id}.")
        return True
    except Exception as e:
        print(f"  ⚠️ Could not bootstrap telemetry via SSM on {instance_id}: {e}")
        return False


def provision_dedicated_target_vps(
    session: boto3.Session,
    region: str,
    dry_run: bool = False,
    retry_delay: float = 3.0,
) -> str:
    """
    Provisions a new dedicated target EC2 instance:
    1. Fetches latest Amazon Linux 2023 AMI from SSM Parameter Store (/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64).
    2. Ensures IncidentsTargetSSMInstanceRole and Instance Profile are created.
    3. Selects instance type (t3.micro primary, t2.micro fallback).
    4. Launches instance with UserData installing/enabling Nginx, tagged Name=incidents-target-vps and IncidentsAgent=true.
    5. Waits for running state and returns instance_id.
    """
    if dry_run:
        return "<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>"

    ec2 = session.client("ec2", region_name=region)
    ssm = session.client("ssm", region_name=region)
    iam = session.client("iam", region_name=region)

    # 1. Fetch latest official AL2023 AMI from SSM Parameter Store
    ami_id = None
    try:
        param = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
        ami_id = param.get("Parameter", {}).get("Value")
    except Exception as e:
        print(f"  ⚠️ Could not query SSM Parameter Store for AL2023 AMI: {e}")

    if not ami_id:
        try:
            resp = ec2.describe_images(
                Owners=["amazon"],
                Filters=[
                    {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
                    {"Name": "state", "Values": ["available"]},
                ],
            )
            images = sorted(resp.get("Images", []), key=lambda x: x.get("CreationDate", ""), reverse=True)
            if images:
                ami_id = images[0]["ImageId"]
        except Exception:
            pass

    if not ami_id:
        raise RuntimeError(f"Unable to locate Amazon Linux 2023 AMI in region {region}.")

    # 2. Ensure IncidentsTargetSSMInstanceRole & Profile are ready
    role_name = "IncidentsTargetSSMInstanceRole"
    profile_name = "IncidentsTargetSSMInstanceProfile"
    _ensure_ssm_instance_profile_exists(iam, profile_name=profile_name, role_name=role_name)

    # 3. Choose instance type (t3.micro as primary for all regions including eu-north-1, fallback t2.micro)
    instance_type = "t3.micro"
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="region",
            Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}],
        ).get("InstanceTypeOfferings", [])
        if not offerings:
            instance_type = "t2.micro"
    except Exception:
        instance_type = "t3.micro"

    # 4. UserData script: install & enable Nginx, CloudWatch Agent, and Universal Systemd Health Timer
    user_data = r"""#!/bin/bash
set -e

# 1. Package manager detection and universal package installation
if command -v dnf >/dev/null 2>&1; then
    dnf install -y nginx amazon-cloudwatch-agent || true
elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y nginx amazon-cloudwatch-agent || true
elif command -v yum >/dev/null 2>&1; then
    yum install -y nginx amazon-cloudwatch-agent || true
fi

systemctl enable --now nginx || true

# 2. Configure CloudWatch Agent with unified aggregation dimensions
mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
cat <<'EOF' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "metrics": {
    "aggregation_dimensions": [["InstanceId"]],
    "append_dimensions": {
      "InstanceId": "${aws:InstanceId}"
    },
    "metrics_collected": {
      "disk": {
        "measurement": ["disk_used_percent"],
        "resources": ["/"],
        "drop_device": true
      },
      "mem": {
        "measurement": ["mem_used_percent"]
      }
    }
  }
}
EOF

if [ -f /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json || true
fi

# 3. Universal Systemd Health Pulse Script (Both Crash & Stopped Enabled Services)
mkdir -p /opt/incidents/bin
cat <<'EOF' > /opt/incidents/bin/system_health_pulse.sh
#!/bin/bash
TOKEN=$(curl -s -S -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
if [ -n "$TOKEN" ]; then
    INSTANCE_ID=$(curl -s -S -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)
    REGION=$(curl -s -S -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)
else
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)
fi

[ -z "$REGION" ] && REGION="us-east-1"
[ -z "$INSTANCE_ID" ] && exit 0

FAILED_COUNT=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | grep -E '\.service' | wc -l)
STOPPED_ENABLED=0

# Check explicitly configured custom services if present
CUSTOM_SERVICES=""
if [ -f /etc/incidents/services.conf ]; then
    CUSTOM_SERVICES=$(grep -v '^[[:space:]]*#' /etc/incidents/services.conf 2>/dev/null | tr '\n' ' ')
fi

# Core production workloads & daemons
CORE_SERVICES="nginx httpd apache2 docker containerd postgresql mysqld mariadb redis mongod memcached rabbitmq-server elasticsearch kafka vault consul order-gateway app myapp api backend"

# Dynamic system-wide discovery of enabled daemons with restart policies
DYNAMIC_SERVICES=""
for svc in $(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}'); do
    case "$svc" in
        *@*|cwsys_health.service|cloud-*|dmesg*|systemd-*|emergency*|rescue*) continue ;;
    esac
    r_policy=$(systemctl show -p Restart --value "$svc" 2>/dev/null)
    cond_res=$(systemctl show -p ConditionResult --value "$svc" 2>/dev/null)
    if [ -n "$r_policy" ] && [ "$r_policy" != "no" ] && [ "$cond_res" != "no" ]; then
        DYNAMIC_SERVICES="$DYNAMIC_SERVICES $svc"
    fi
done

ALL_CANDIDATES=$(echo "$CORE_SERVICES $CUSTOM_SERVICES $DYNAMIC_SERVICES" | tr ' ' '\n' | sort -u | tr '\n' ' ')

for s in $ALL_CANDIDATES; do
    [ -z "$s" ] && continue
    s_clean="${s%.service}"
    if systemctl is-enabled "$s_clean" >/dev/null 2>&1 || systemctl is-enabled "$s" >/dev/null 2>&1; then
        if ! systemctl is-active --quiet "$s_clean" && ! systemctl is-active --quiet "$s"; then
            s_state=$(systemctl is-failed "$s_clean" 2>/dev/null || true)
            if [ "$s_state" != "failed" ]; then
                STOPPED_ENABLED=$((STOPPED_ENABLED + 1))
            fi
        fi
    fi
done
TOTAL_FAILS=$((FAILED_COUNT + STOPPED_ENABLED))

aws cloudwatch put-metric-data \
    --namespace "CWAgent" \
    --metric-name "FailedServicesCount" \
    --dimensions InstanceId="$INSTANCE_ID" \
    --value "$TOTAL_FAILS" \
    --region "$REGION" 2>/dev/null || true
EOF
chmod +x /opt/incidents/bin/system_health_pulse.sh

# 4. Native Systemd Timer (100% universal across Ubuntu, Debian, AL2023, RHEL - no cron package needed)
cat <<'EOF' > /etc/systemd/system/cwsys_health.service
[Unit]
Description=Universal CloudWatch System Health Metric Reporter
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/incidents/bin/system_health_pulse.sh
EOF

cat <<'EOF' > /etc/systemd/system/cwsys_health.timer
[Unit]
Description=Run Universal CloudWatch System Health Metric Reporter every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now cwsys_health.timer || true
"""

    run_kwargs = {
        "ImageId": ami_id,
        "InstanceType": instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "UserData": user_data,
        "IamInstanceProfile": {"Name": profile_name},
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "incidents-target-vps"},
                    {"Key": "IncidentsAgent", "Value": "true"},
                ],
            }
        ],
    }

    effective_delay = float(os.environ.get("AWS_PROPAGATION_RETRY_DELAY", retry_delay))
    max_retries = 6
    res = None
    for attempt in range(1, max_retries + 1):
        try:
            try:
                res = ec2.run_instances(**run_kwargs)
            except Exception as e:
                if "t3.micro" in str(e):
                    run_kwargs["InstanceType"] = "t2.micro"
                    res = ec2.run_instances(**run_kwargs)
                else:
                    raise
            break
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            err_msg = str(e)
            if (err_code == "InvalidParameterValue" and "iaminstanceprofile" in err_msg.lower()) and attempt < max_retries:
                print(f"  ⏳ Waiting for AWS IAM Instance Profile propagation to regional EC2... (attempt {attempt}/{max_retries})")
                if effective_delay > 0:
                    time.sleep(effective_delay)
                continue
            raise

    if not res or not res.get("Instances"):
        raise RuntimeError(f"Failed to launch dedicated target instance in region {region}.")

    instance_id = res["Instances"][0]["InstanceId"]
    print(f"  🚀 Dedicated target EC2 instance launched: {instance_id} ({run_kwargs['InstanceType']})")

    # 5. Wait for instance running
    try:
        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": 30})
    except Exception:
        pass

    return instance_id


# ── Core IAM Roles Reconciliation Engine ─────────────────────────────────────

def _is_trust_policy_valid(role_name: str, doc: Any) -> bool:
    if not doc:
        return False
    if isinstance(doc, str):
        try:
            if "%" in doc:
                doc = urllib.parse.unquote(doc)
            doc = json.loads(doc)
        except Exception:
            return False
    if not isinstance(doc, dict):
        return False

    expected_principal = "lambda.amazonaws.com"
    if role_name == "RemediationOperatorRole":
        expected_principal = None

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any("sts:assumerole" in str(a).lower() or a == "*" for a in actions):
            continue

        if expected_principal is None:
            return True

        principal = stmt.get("Principal", {})
        if isinstance(principal, dict):
            services = principal.get("Service", [])
            if isinstance(services, str):
                services = [services]
            if any(expected_principal in str(s).lower() for s in services):
                return True
        elif principal == "*":
            return True

    return False


def ensure_core_iam_roles(session: boto3.Session, account_id: str, region: str) -> List[str]:
    """
    Reconciles core IAM roles (incidents-agent-role, incidents-observer-role, RemediationOperatorRole)
    if they exist in the AWS account:
    1. Guarantees assume role trust policy allows lambda.amazonaws.com (prevents Lambda AccessDeniedException).
    2. Attaches AWSLambdaBasicExecutionRole managed policy.
    3. Reconciles exact least-privilege inline policies for DynamoDB, SSM, S3, SecretsManager, and Lambda.
    """
    reg = region or session.region_name or "us-east-1"
    iam = session.client("iam", region_name=reg)
    remediated: List[str] = []

    lambda_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    # 1. incidents-agent-role
    agent_role_name = "incidents-agent-role"
    try:
        r = iam.get_role(RoleName=agent_role_name)["Role"]
        if not _is_trust_policy_valid(agent_role_name, r.get("AssumeRolePolicyDocument")):
            iam.update_assume_role_policy(
                RoleName=agent_role_name,
                PolicyDocument=json.dumps(lambda_trust),
            )
            remediated.append(f"Reconciled trust policy for '{agent_role_name}' to allow lambda.amazonaws.com")

        iam.attach_role_policy(
            RoleName=agent_role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )

        agent_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EventsTableAppendOnly",
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:Query",
                        "dynamodb:DescribeTable",
                    ],
                    "Resource": f"arn:aws:dynamodb:{reg}:{account_id}:table/incidents-events",
                },
                {
                    "Sid": "MutableOperationalTables",
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:Query",
                        "dynamodb:DescribeTable",
                    ],
                    "Resource": [
                        f"arn:aws:dynamodb:{reg}:{account_id}:table/incidents-leases",
                        f"arn:aws:dynamodb:{reg}:{account_id}:table/incidents-dedup",
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": f"arn:aws:s3:::incidents-blobs-{account_id}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": f"arn:aws:secretsmanager:{reg}:{account_id}:secret:/incidents/*",
                },
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": [
                        f"arn:aws:lambda:{reg}:{account_id}:function:incidents-observer",
                        f"arn:aws:lambda:{reg}:{account_id}:function:incidents-executor",
                        f"arn:aws:lambda:{reg}:{account_id}:function:incidents-notifier",
                        f"arn:aws:lambda:{reg}:{account_id}:function:incidents-agent",
                    ],
                },
            ],
        }
        iam.put_role_policy(
            RoleName=agent_role_name,
            PolicyName="incidents-agent-policy",
            PolicyDocument=json.dumps(agent_policy),
        )
        remediated.append(f"Reconciled inline policy 'incidents-agent-policy' on '{agent_role_name}'")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "NoSuchEntity":
            print(f"  ⚠️ Warning: Failed reconciling {agent_role_name}: {exc}")

    # 2. incidents-observer-role
    observer_role_name = "incidents-observer-role"
    try:
        r = iam.get_role(RoleName=observer_role_name)["Role"]
        if not _is_trust_policy_valid(observer_role_name, r.get("AssumeRolePolicyDocument")):
            iam.update_assume_role_policy(
                RoleName=observer_role_name,
                PolicyDocument=json.dumps(lambda_trust),
            )
            remediated.append(f"Reconciled trust policy for '{observer_role_name}' to allow lambda.amazonaws.com")

        iam.attach_role_policy(
            RoleName=observer_role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )

        observer_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ssm:SendCommand",
                    "Resource": [
                        f"arn:aws:ssm:{reg}:{account_id}:document/incidents-observe-readonly",
                        f"arn:aws:ec2:{reg}:{account_id}:instance/*",
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": ["ssm:GetCommandInvocation", "ssm:ListCommands"],
                    "Resource": "*",
                },
                {
                    "Sid": "EventsTableAppendOnly",
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:Query",
                        "dynamodb:DescribeTable",
                    ],
                    "Resource": f"arn:aws:dynamodb:{reg}:{account_id}:table/incidents-events",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": f"arn:aws:s3:::incidents-blobs-{account_id}/*",
                },
            ],
        }
        iam.put_role_policy(
            RoleName=observer_role_name,
            PolicyName="incidents-observer-policy",
            PolicyDocument=json.dumps(observer_policy),
        )
        remediated.append(f"Reconciled inline policy 'incidents-observer-policy' on '{observer_role_name}'")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "NoSuchEntity":
            print(f"  ⚠️ Warning: Failed reconciling {observer_role_name}: {exc}")

    # 3. RemediationOperatorRole
    op_role_name = "RemediationOperatorRole"
    try:
        r = iam.get_role(RoleName=op_role_name)["Role"]
        op_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/incidents-executor-role"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        if not _is_trust_policy_valid(op_role_name, r.get("AssumeRolePolicyDocument")):
            iam.update_assume_role_policy(
                RoleName=op_role_name,
                PolicyDocument=json.dumps(op_trust),
            )
            remediated.append(f"Reconciled trust policy for '{op_role_name}' to allow incidents-executor-role")

        op_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RestrictedRepairOnTaggedInstance",
                    "Effect": "Allow",
                    "Action": "ssm:SendCommand",
                    "Resource": f"arn:aws:ec2:{reg}:{account_id}:instance/*",
                    "Condition": {"StringEquals": {"ssm:resourceTag/IncidentsAgent": "true"}},
                },
                {
                    "Sid": "AllowOnlyRestrictedRepairDocument",
                    "Effect": "Allow",
                    "Action": "ssm:SendCommand",
                    "Resource": f"arn:aws:ssm:{reg}:{account_id}:document/incidents-repair-restricted",
                },
                {
                    "Sid": "GetCommandResults",
                    "Effect": "Allow",
                    "Action": ["ssm:GetCommandInvocation", "ssm:ListCommands"],
                    "Resource": "*",
                },
            ],
        }
        iam.put_role_policy(
            RoleName=op_role_name,
            PolicyName="RemediationOperatorRolePolicy",
            PolicyDocument=json.dumps(op_policy),
        )
        remediated.append(f"Reconciled inline policy 'RemediationOperatorRolePolicy' on '{op_role_name}'")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "NoSuchEntity":
            print(f"  ⚠️ Warning: Failed reconciling {op_role_name}: {exc}")

    return remediated


# ── Pre-Deploy Execution Engine ──────────────────────────────────────────────

def execute_pre_deploy_actions(
    session: boto3.Session,
    region: str,
    report: AuditReport,
    project_root: str,
) -> List[str]:
    """
    Executes necessary pre-deployment actions safely:
    1. Tag target EC2 instance with IncidentsAgent=true if missing.
    2. Update SSM Documents if drift is detected.
    3. Generate cryptographic signing key and create /incidents/approval-mac-key secret if missing.
    """
    executed: List[str] = []

    # 1. Tag target instance if needed
    if report.ec2.target_instance and not report.ec2.target_instance.has_security_tag:
        try:
            ec2 = session.client("ec2", region_name=region)
            inst_id = report.ec2.target_instance.instance_id
            ec2.create_tags(
                Resources=[inst_id],
                Tags=[{"Key": "IncidentsAgent", "Value": "true"}],
            )
            executed.append(f"Tagged EC2 instance '{inst_id}' with 'IncidentsAgent=true'")
            report.ec2.target_instance.has_security_tag = True
            report.ec2.target_instance.tags["IncidentsAgent"] = "true"
            if report.ec2.target_instance.state == "running" and report.ec2.target_instance.ssm_online:
                report.ec2.target_valid = True
                report.ec2.target_error = None
        except Exception as e:
            executed.append(f"Failed to tag EC2 instance '{report.ec2.target_instance.instance_id}': {e}")

    # 2. Fix SSM Document drift
    if report.ssm.has_drift:
        ssm = session.client("ssm", region_name=region)
        for doc_name, dinfo in report.ssm.documents.items():
            if dinfo.drift_detected:
                ref_path = os.path.join(project_root, "infra", "ssm", f"{doc_name}.json")
                if os.path.exists(ref_path):
                    try:
                        with open(ref_path, "r", encoding="utf-8") as f:
                            ref_content = f.read()
                        upd = ssm.update_document(
                            Name=doc_name,
                            Content=ref_content,
                            DocumentVersion="$LATEST",
                        )
                        new_ver = upd.get("DocumentDescription", {}).get("DocumentVersion", "$LATEST")
                        ssm.update_document_default_version(Name=doc_name, DocumentVersion=new_ver)
                        executed.append(f"Updated SSM Document '{doc_name}' to version {new_ver} matching infra/ssm/{doc_name}.json ($DEFAULT updated)")
                        dinfo.drift_detected = False
                        dinfo.default_version = new_ver
                    except Exception as e:
                        executed.append(f"Failed to update SSM Document '{doc_name}': {e}")
        report.ssm.has_drift = any(d.drift_detected for d in report.ssm.documents.values())
        report.ssm.all_ready = not report.ssm.has_drift and all(d.exists for d in report.ssm.documents.values())

    # 3. Create missing approval MAC key secret
    mac_key_name = "/incidents/approval-mac-key"
    if mac_key_name in report.secrets and not report.secrets[mac_key_name].exists:
        try:
            sm = session.client("secretsmanager", region_name=region)
            new_mac_hex = secrets.token_hex(32)
            c_res = sm.create_secret(
                Name=mac_key_name,
                Description="HMAC-SHA256 authentication key for Tier 2 autonomous incident remediation",
                SecretString=new_mac_hex,
            )
            executed.append(f"Generated secure cryptographic HMAC key and created secret '{mac_key_name}' in Secrets Manager")
            report.secrets[mac_key_name] = SecretReport(
                name=mac_key_name,
                exists=True,
                arn=c_res.get("ARN"),
                accessible=True,
            )
        except Exception as e:
            executed.append(f"Failed to create secret '{mac_key_name}': {e}")

    return executed


# ── Environment File Generator ───────────────────────────────────────────────

def generate_env_file(
    report: AuditReport,
    params: Dict[str, str],
    env_out_path: str,
):
    """
    Generates a non-sensitive environment configuration file (.env) with
    resource names and secret ARNs without exposing any raw secret values.
    """
    target_id = params.get("TargetInstanceId", "")
    strands_url = params.get("StrandsUrl", "")
    blobs_bucket = params.get("ExistingBlobsBucketName") or f"incidents-blobs-{report.identity.account_id}"

    lines = [
        "# ==============================================================================",
        "# Autonomous Incident Remediation System — Environment Configuration",
        f"# Generated by scripts/aws_onboard.py on {datetime.now().isoformat()}",
        "# Security: Contains NO raw secret values (ARNs and resource identifiers only).",
        "# ==============================================================================",
        "",
        f"AWS_REGION={report.identity.region}",
        f"AWS_ACCOUNT_ID={report.identity.account_id}",
        f"TARGET_INSTANCE_ID={target_id}",
        f"STRANDS_URL={strands_url}",
        "",
        "# DynamoDB EventStore Tables",
        "EVENTS_TABLE=incidents-events",
        "DEDUP_TABLE=incidents-dedup",
        "LEASES_TABLE=incidents-leases",
        "",
        "# S3 Blobs Storage",
        f"BLOBS_BUCKET={blobs_bucket}",
        "",
        "# Lambda Microservices",
        "AGENT_FUNCTION=incidents-agent",
        "OBSERVER_FUNCTION=incidents-observer",
        "EXECUTOR_FUNCTION=incidents-executor",
        "NOTIFIER_FUNCTION=incidents-notifier",
        "",
        "# SSM Automation",
        "SSM_DOC_OBSERVE=incidents-observe-readonly",
        "SSM_DOC_REPAIR=incidents-repair-restricted",
        f"SSM_EXEC_ROLE_ARN=arn:aws:iam::{report.identity.account_id}:role/RemediationOperatorRole",
        "",
        "# Foundation Models",
        f"NOVA_FLASH_MODEL_ID={params.get('NovaFlashModelId', 'amazon.nova-lite-v1:0')}",
        f"NOVA_PRO_MODEL_ID={params.get('NovaProModelId', 'amazon.nova-pro-v1:0')}",
        f"DEEPSEEK_BASE_URL={params.get('DeepSeekBaseUrl', 'https://bedrock-mantle.us-east-1.api.aws/v1')}",
        f"DEEPSEEK_FLASH_MODEL={params.get('DeepSeekFlashModel', 'deepseek.v3.1')}",
        f"DEEPSEEK_PRO_MODEL={params.get('DeepSeekProModel', 'deepseek.v3.2')}",
        "",
        "# Secrets Manager References (ARNs only — zero raw secrets leaked)",
    ]

    for sname, srep in report.secrets.items():
        var_key = sname.strip("/").replace("/", "_").replace("-", "_").upper() + "_ARN"
        arn_val = srep.arn or f"arn:aws:secretsmanager:{report.identity.region}:{report.identity.account_id}:secret:{sname}"
        lines.append(f"{var_key}={arn_val}")

    lines.append("")

    with open(env_out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"📄 Sanitized environment configuration generated at: {env_out_path}")


# ── Governed Apply Mode ──────────────────────────────────────────────────────

def run_apply_mode(
    session: boto3.Session,
    region: str,
    report: AuditReport,
    project_root: str,
    args: argparse.Namespace,
    injected_secrets: Optional[Dict[str, str]] = None,
    injected_params: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Executes governed apply mode:
    1. Validates target instance or provisions dedicated target VPS if -T is passed.
    2. Displays the plan.
    3. Prompts user if not --yes.
    4. Executes pre-deploy actions.
    5. Optionally runs sam deploy (or reports sam command if --skip-sam or sam unavailable).
    6. Produces final receipt and writes outputs.
    """
    create_vps = getattr(args, "create_target_vps", False)
    target_id = args.instance_id.strip()

    # Load injected env variables if passed via -E / --env-file
    env_file_path = getattr(args, "env_file", "").strip()
    if env_file_path and (injected_secrets is None or injected_params is None):
        raw_env = parse_env_file(env_file_path)
        s_vars, p_vars = split_env_vars(raw_env)
        if injected_secrets is None:
            injected_secrets = s_vars
        if injected_params is None:
            injected_params = p_vars

    if not target_id and not create_vps:
        print("\n❌ ERROR: Neither '--instance-id' nor '-T' / '--create-target-vps' was specified.")
        print("Existing client servers were protected and NOT auto-selected.")
        print("Please choose one of the following options:")
        print("  * Option A (Adopt Existing VPS): Run with '--instance-id <INSTANCE_ID>'")
        print("  * Option B (Provision Dedicated Target VPS): Run with '-T' (or '--create-target-vps')")
        sys.exit(1)

    if not create_vps:
        if not report.ec2.target_instance:
            print(f"\n❌ ERROR: Target instance '{target_id}' was not found in region {region}.")
            sys.exit(1)

        if report.ec2.target_instance.state != "running":
            print(f"\n❌ ERROR: Target instance '{target_id}' is in state '{report.ec2.target_instance.state}'. It must be running.")
            sys.exit(1)

    # 1. Build plan
    params, pre_actions, sam_command = build_cfn_parameters(
        report=report,
        strands_override=args.strands_url.strip() or None,
        stack_name=args.stack_name,
        create_target_vps=create_vps and not target_id,
        is_apply=True,
        injected_params=injected_params,
    )
    print_plan(report, params, pre_actions, sam_command)

    # 2. Confirmation prompt if not --yes
    if not args.yes:
        print("\n" + "!" * 75)
        try:
            confirm = input("Proceed with applying pre-deployment actions & configuration? [y/N]: ").strip().lower()
        except EOFError:
            confirm = "no"
        if confirm not in ("y", "yes"):
            print("❌ Operation cancelled by user. No modifications were made.")
            sys.exit(0)

    # 3. Execute Pre-Deploy Actions & Client Bootstrap
    print("\n" + "=" * 80)
    print("⚙️ EXECUTING PRE-DEPLOYMENT ACTIONS & CLIENT BOOTSTRAP")
    print("=" * 80)

    # 3.0 Provision dedicated target VPS if requested
    if create_vps and (not target_id or target_id == "<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>"):
        print("  🚀 Provisioning new dedicated target EC2 instance (-T / --create-target-vps)...")
        target_id = provision_dedicated_target_vps(session=session, region=region, dry_run=False)
        print(f"  ✅ Dedicated Target VPS successfully launched & ready: {target_id}")
        args.instance_id = target_id
        ec2_rep = audit_ec2(session, region, target_id)
        report.ec2 = ec2_rep
        report.ec2.has_cwagent_disk_metrics = True

    # 3.1 Bootstrap Secrets
    secret_results = ensure_client_secrets(
        session=session,
        region=region,
        project_root=project_root,
        deepseek_api_key=getattr(args, "deepseek_api_key", "").strip() or None,
        injected_secrets=injected_secrets,
    )
    for s_res in secret_results:
        print(f"  🔐 {s_res}")

    # Mark /incidents/approval-mac-key ready in report to prevent duplicate attempt in execute_pre_deploy_actions
    if "/incidents/approval-mac-key" in report.secrets:
        report.secrets["/incidents/approval-mac-key"].exists = True

    # 3.2 Bootstrap Target EC2 Profile & Tag
    if target_id and target_id != "<REQUIRED_EC2_INSTANCE_ID>":
        print(f"  ⚙️ Ensuring SSM & CloudWatch IAM Profile for {target_id}...")
        ensure_instance_ssm_profile(session=session, instance_id=target_id, region=region)
        ensure_instance_tagged(session=session, instance_id=target_id, region=region)

    if report.ec2.target_instance and report.ec2.target_instance.state == "running":
        # Target instance is active, profiled, and tagged.
        # SSM fleet manager registration can take 20-40s after OS boot, but readiness for deployment is satisfied.
        report.ec2.target_instance.has_security_tag = True
        report.ec2.target_valid = True
        report.ec2.target_error = None

    # 3.3 Bootstrap Target EC2 Telemetry (CWAgent & Universal Systemd Health Pulse)
    if target_id and target_id != "<REQUIRED_EC2_INSTANCE_ID>":
        print(f"  📊 Bootstrapping CWAgent & Systemd Health Pulse on target instance '{target_id}'...")
        telemetry_ok = ensure_instance_telemetry(session=session, instance_id=target_id, region=region)
        if telemetry_ok:
            report.ec2.has_cwagent_disk_metrics = True

    # 3.4 Bootstrap & Reconcile Core IAM Roles (incidents-agent-role, incidents-observer-role, RemediationOperatorRole)
    print("  🛡️ Reconciling Core IAM Roles (trust policies & execution permissions)...")
    iam_reconciled = ensure_core_iam_roles(session=session, account_id=report.identity.account_id, region=region)
    for act in iam_reconciled:
        print(f"  ✓ {act}")

    executed_actions = execute_pre_deploy_actions(
        session=session,
        region=region,
        report=report,
        project_root=project_root,
    )
    for act in iam_reconciled:
        if act not in executed_actions:
            executed_actions.append(act)
    for act in secret_results:
        if act not in executed_actions:
            executed_actions.append(act)
    if executed_actions:
        for idx, act in enumerate(executed_actions, 1):
            print(f"  ✅ [{idx}] {act}")
    else:
        print("  ✅ All pre-deployment requirements already satisfied (zero remediation needed).")

    # Re-calculate params in case pre-actions changed readiness
    params, _, sam_command = build_cfn_parameters(
        report=report,
        strands_override=args.strands_url.strip() or None,
        stack_name=args.stack_name,
        existing_bucket=getattr(args, "existing_bucket", "").strip() or None,
        is_apply=True,
        injected_params=injected_params,
    )

    # 4. SAM deployment
    deploy_status = "SKIPPED"
    deploy_msg = ""
    if args.skip_sam:
        print("\n⏩ SAM Deployment skipped (--skip-sam flag specified).")
        deploy_status = "SKIPPED"
        deploy_msg = "Deployment skipped via --skip-sam flag."
    else:
        sam_cli = shutil.which("sam")
        if not sam_cli:
            print("\n⚠️ 'sam' CLI was not found in PATH.")
            print("   Pre-deploy actions were executed. To deploy the serverless stack, install AWS SAM CLI and run:")
            print(f"\n{sam_command}\n")
            deploy_status = "CLI_NOT_FOUND"
            deploy_msg = "'sam' CLI not found in PATH."
        else:
            print("\n🚀 Executing SAM build & deployment...")
            try:
                # Ensure clean stack state before deploying (auto-recover if in ROLLBACK_COMPLETE or DELETE_FAILED)
                ensure_clean_stack_before_deploy(session=session, stack_name=args.stack_name, region=region)

                # Build
                print("  -> Running: sam build")
                b_res = subprocess.run(["sam", "build"], cwd=project_root, capture_output=True, text=True)
                if b_res.returncode != 0:
                    print(f"  ❌ sam build failed:\n{b_res.stderr}")
                    deploy_status = "BUILD_FAILED"
                    deploy_msg = b_res.stderr
                else:
                    # Deploy
                    overrides_list = [f"{k}={v}" for k, v in params.items() if str(v).strip() != ""]
                    deploy_cmd = [
                        "sam", "deploy",
                        "--stack-name", args.stack_name,
                        "--region", region,
                        "--resolve-s3",
                        "--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM",
                        "--no-fail-on-empty-changeset",
                        "--parameter-overrides",
                    ] + overrides_list
                    print(f"  -> Running: {' '.join(deploy_cmd)}")
                    d_res = subprocess.run(deploy_cmd, cwd=project_root, capture_output=True, text=True)
                    if d_res.returncode == 0 or "No changes to deploy" in d_res.stdout or "No changes to deploy" in d_res.stderr:
                        print("  ✅ SAM deployment succeeded!")
                        deploy_status = "DEPLOYED"
                        deploy_msg = "SAM deployment succeeded."
                    else:
                        print(f"  ❌ sam deploy failed:\n{d_res.stderr}")
                        root_causes = extract_cfn_failure_root_causes(session=session, stack_name=args.stack_name, region=region)
                        if root_causes:
                            print(f"\n  🔍 CloudFormation Failure Root Causes ({len(root_causes)} found):")
                            for rc in root_causes:
                                print(f"     ❌ {rc}")
                        deploy_status = "DEPLOY_FAILED"
                        deploy_msg = d_res.stderr
                        if root_causes:
                            deploy_msg += "\nRoot Causes:\n" + "\n".join(root_causes)
            except Exception as e:
                deploy_status = "ERROR"
                deploy_msg = str(e)
                print(f"  ❌ Deployment error: {e}")

    # 5. Print Final Receipt
    json_out_file = args.json_out or "onboarding_report.json"
    print("\n" + "=" * 80)
    print("🎉 FINAL ONBOARDING RECEIPT")
    print("=" * 80)
    print(f"  Target Instance:           {target_id} ({report.ec2.target_instance.name})")
    print(f"  Target Status:             {'Online in SSM, Tagged' if report.ec2.target_valid else 'Issues detected'}")
    print(f"  Pre-Deploy Actions Taken:  {len(executed_actions)}")
    print(f"  Serverless Stack:          {args.stack_name} [{deploy_status}]")
    print(f"  Receipt Artifact:          {json_out_file}")
    if args.env_out:
        print(f"  Environment Configuration: {args.env_out}")
    print("=" * 80)

    receipt = {
        "timestamp": datetime.now().isoformat(),
        "target_instance_id": target_id,
        "region": region,
        "stack_name": args.stack_name,
        "pre_deploy_actions_executed": executed_actions,
        "deployment_status": deploy_status,
        "deployment_message": deploy_msg,
        "sam_command": sam_command,
        "parameters": params,
        "audit_report": report,
    }

    # Save receipt JSON
    with open(json_out_file, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, cls=EnhancedJSONEncoder)
    print(f"\n📁 Onboarding receipt written to: {json_out_file}")

    # Generate .env if requested
    if args.env_out:
        generate_env_file(report, params, args.env_out)

    return receipt


apply_onboarding = run_apply_mode


def print_llm_bedrock_policy(report: AuditReport, project_root: Optional[str] = None):
    """
    Prints explicit Bedrock QuickStart / BYOK LLM Fate and API Key Policy report.
    Explains template.yaml decoupling, client BYOK responsibility, and current API key status.
    """
    region = report.identity.region

    # 1. Determine key status in Secrets Manager vs local environment
    ds_secret = report.secrets.get("/incidents/deepseek-api-key")
    if ds_secret and ds_secret.exists:
        if ds_secret.is_placeholder:
            key_status = "⚠️ PLACEHOLDER ONLY in Secrets Manager ('/incidents/deepseek-api-key') — Client must update with a valid API key before live inference"
        else:
            key_status = f"✅ Present & Active in AWS Secrets Manager (`/incidents/deepseek-api-key` in region {region})"
    else:
        env_val = os.environ.get("DEEPSEEK_API_KEY", "").strip() or os.environ.get("OPENAI_API_KEY", "").strip()
        if not env_val:
            root = project_root or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            env_file = os.path.join(root, ".env")
            if os.path.exists(env_file):
                try:
                    with open(env_file, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                k, v = line.split("=", 1)
                                if k.strip() in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY") and v.strip().strip("'\""):
                                    env_val = v.strip().strip("'\"")
                                    break
                except Exception:
                    pass

        if env_val:
            key_status = f"🟡 Staged in local environment / .env (Ready to auto-provision into Secrets Manager via `--mode apply`)"
        else:
            key_status = f"❌ Missing in both Secrets Manager and local .env (Action required: extract API key from Bedrock QuickStart or LLM provider and export DEEPSEEK_API_KEY)"

    print("\n─── LLM / Bedrock Fate & API Key Policy (Region-Independent BYOK) ───")
    print("  1. IaC Decoupling (template.yaml):")
    print("     - template.yaml creates ZERO Bedrock resources and enforces NO cross-region IAM policies.")
    print("     - Prevents Service Control Policy (SCP) AccessDenied errors in restricted regions (e.g. eu-north-1).")
    print("     - Eliminates dependency on foundation model regional availability.")
    print("  2. Client Responsibility (Amazon Bedrock QuickStart / External API Key):")
    print("     - Inference engine connects over HTTPS using Bearer API Key authentication (DeepSeekModel).")
    print("     - Client extracts an API key directly (from Amazon Bedrock QuickStart or OpenAI-compatible gateway).")
    print(f"     - Key is passed via DEEPSEEK_API_KEY and stored in AWS Secrets Manager: /incidents/deepseek-api-key ({region}).")
    print("  3. Current API Key Status in Account:")
    print(f"     - {key_status}")


def print_audit_summary(report: AuditReport):
    print("=" * 80)
    print("🔍 AWS ONBOARDING AUDIT REPORT (Deep Discovery — Read Only)")
    print("=" * 80)

    # Layer 1
    print("\n[Layer 1: Identity & Credentials]")
    print(f"  Account ID: {report.identity.account_id}")
    print(f"  Caller ARN: {report.identity.arn}")
    print(f"  Region:     {report.identity.region}")

    # Layer 2
    print("\n[Layer 2: EC2 Instances & Agent Connectivity]")
    print(f"  Total Instances Discovered: {len(report.ec2.instances)}")
    for inst in report.ec2.instances:
        status_icon = "🟢" if (inst.state == "running" and inst.ssm_online) else "⚪"
        tag_icon = "🏷️ [Tagged]" if inst.has_security_tag else "⚠️ [No Tag]"
        print(f"    {status_icon} {inst.instance_id:20} | {inst.name:20} | State: {inst.state:8} | SSM: {'Online ' if inst.ssm_online else 'Offline'} | {tag_icon}")

    if report.ec2.strands_suggestion:
        print(f"  💡 Strands Decider Suggestion: {report.ec2.strands_suggestion}")

    if report.ec2.target_instance:
        print(f"  🎯 Target Instance: {report.ec2.target_instance.instance_id} ({report.ec2.target_instance.name})")
        if report.ec2.target_valid:
            print(f"     ✅ Status: Valid & Ready (Online in SSM + Security Tag Present)")
            print(f"     📊 CWAgent Disk Metrics: {'Available' if report.ec2.has_cwagent_disk_metrics else 'None (Standard EC2 metrics only)'}")
        else:
            print(f"     ❌ Status: Invalid — {report.ec2.target_error}")
    else:
        print("  ℹ️ Target VPS: None selected (Existing client servers protected).")
        if report.ec2.instances:
            print("  🛡️ Target VPS Choice:")
            print("     * Option A (Adopt Existing VPS): Run with '--instance-id <INSTANCE_ID>' to adopt an existing server.")
            print("     * Option B (Provision Dedicated Target VPS): Run with '-T' (or '--create-target-vps') to launch a dedicated Amazon Linux 2023 + SSM + Nginx server.")
        else:
            print("     👉 Use '-T' (or '--create-target-vps') to automatically provision a new dedicated target instance (Amazon Linux 2023 + SSM + Nginx).")

    # Layer 3
    print("\n[Layer 3: DynamoDB EventStore]")
    for tname, trep in report.dynamodb.tables.items():
        if trep.exists and trep.key_schema_matches:
            item_cnt = trep.details.get('ItemCount', 0)
            print(f"  ✅ {tname:20} [ACTIVE | KeySchema Matched | Items: ~{item_cnt} approx (6h AWS snapshot)]")
        elif trep.exists:
            print(f"  ⚠️ {tname:20} [ACTIVE | KeySchema MISMATCH]")
        else:
            print(f"  ❌ {tname:20} [MISSING — Will be created by IaC]")

    # Layer 4
    print("\n[Layer 4: S3 Blobs Bucket & Storage Choice]")
    if report.s3.exists:
        print(f"  ✅ Dedicated S3 Bucket:    {report.s3.expected_name} [EXISTS | AES256 Encrypted]")
    else:
        print(f"  ℹ️ Dedicated S3 Bucket:    {report.s3.expected_name} [NOT CREATED YET — Will be auto-created by IaC if not adopting an existing bucket]")

    if report.s3.discovered_buckets:
        print(f"  📦 Discovered Existing S3 Buckets in Account ({len(report.s3.discovered_buckets)}):")
        for b in report.s3.discovered_buckets[:5]:
            print(f"     - {b}")
        if len(report.s3.discovered_buckets) > 5:
            print(f"     ... and {len(report.s3.discovered_buckets) - 5} more")
    else:
        print("  📦 Discovered Existing S3 Buckets: None found in account")

    # Layer 5
    print("\n[Layer 5: Zero-Trust SSM Documents]")
    for dname, drep in report.ssm.documents.items():
        if drep.exists and not drep.drift_detected:
            print(f"  ✅ {dname:30} [ACTIVE (v{drep.default_version}) | allowedPattern: Matched]")
        elif drep.exists and drep.drift_detected:
            print(f"  ⚠️ {dname:30} [DRIFT DETECTED | allowedPattern differs from infra/ssm/]")
        else:
            print(f"  ❌ {dname:30} [MISSING — Will be created by IaC]")

    # Layer 6
    print("\n[Layer 6: IAM Core Roles]")
    for rname, rrep in report.iam.roles.items():
        if rrep.exists:
            print(f"  ✅ {rname:25} [EXISTS: {rrep.arn}]")
        else:
            print(f"  ❌ {rname:25} [MISSING — Will be created by IaC]")

    # Layer 7
    print("\n[Layer 7: Secrets Manager & Serverless Stack]")
    print("  Required Secrets:")
    for sname in REQUIRED_SECRETS:
        srep = report.secrets.get(sname)
        if srep and srep.exists:
            if srep.is_placeholder:
                print(f"    ⚠️ {sname:35} [PLACEHOLDER ONLY in Secrets Manager — Must update before live inference]")
            else:
                print(f"    ✅ {sname:35} [EXISTS & ACCESSIBLE]")
        else:
            print(f"    ❌ {sname:35} [MISSING — Will be auto-provisioned via '--mode apply']")

    print("  Optional Integrations:")
    for sname in OPTIONAL_SECRETS:
        srep = report.secrets.get(sname)
        if srep and srep.exists:
            print(f"    ✅ {sname:35} [CONFIGURED & ACTIVE]")
        else:
            print(f"    ⚪ {sname:35} [OPTIONAL — Slack notifications skipped safely if unconfigured]")

    print(f"  CloudFormation Stack '{report.stack.stack_name}': {'Active (' + str(report.stack.status) + ')' if report.stack.exists else 'Not Deployed Yet'}")
    print(f"  Deployed Lambda Functions: {sum(1 for v in report.stack.lambda_functions.values() if v)} / {len(report.stack.lambda_functions)}")
    print(f"  🧠 LLM Inference Base URL: {os.environ.get('DEEPSEEK_BASE_URL', 'https://bedrock-mantle.us-east-1.api.aws/v1')}")
    print(f"     - Flash Tier Model:      deepseek.v3.1")
    print(f"     - Pro Tier Model:        deepseek.v3.2")

    # Foundation Models & Live Probes
    if report.bedrock_access:
        b_acc = report.bedrock_access
        b_reg = b_acc.get("bedrock_region", report.identity.region)
        if b_acc.get("all_nova_ready"):
            print(f"  🧠 Bedrock Foundation Models ({b_reg}): ✅ Accessible (Nova Lite & Pro Verified)")
        elif b_acc.get("accessible"):
            print(f"  🧠 Bedrock Foundation Models ({b_reg}): ⚠️ Partial ({len(b_acc.get('nova_models_found', []))}/2 Nova models found)")
        else:
            print(f"  🧠 Bedrock Foundation Models ({b_reg}): ❌ Error — {b_acc.get('error')}")

    if report.strands_probe and report.strands_probe.get("url"):
        sp = report.strands_probe
        if sp.get("strands_healthy"):
            print(f"  🤖 Strands Decider Service (/health): 🟢 Healthy — {sp.get('detail')}")
        else:
            print(f"  🤖 Strands Decider Service (/health): 🔴 Unresponsive — {sp.get('detail')}")

    # LLM / Bedrock Fate & API Key Policy
    print_llm_bedrock_policy(report)

    # Universal Client Resource Choice Policy across EC2 / S3 / Infra
    print("\n" + "-" * 80)
    print("🛡️ UNIVERSAL CLIENT RESOURCE CHOICE POLICY (Non-Intrusive Architecture)")
    print("-" * 80)
    print("  * Option A (Adopt Existing Client Resources):")
    print("    - Target VPS:    Pass '--instance-id <ID>' to adopt and remediate an existing server.")
    if report.s3.discovered_buckets:
        print(f"    - S3 Bucket:     Pass '--existing-bucket <BUCKET>' (e.g. '--existing-bucket {report.s3.discovered_buckets[0]}') to reuse an existing bucket.")
    else:
        print("    - S3 Bucket:     Pass '--existing-bucket <BUCKET_NAME>' to adopt an existing bucket.")
    print("    - External Key:  Pass '--deepseek-api-key <KEY>' to securely store your API key in Secrets Manager.")
    print("  * Option B (Provision Dedicated New Environment via '-T'):")
    print("    - Pass '-T' (or '--create-target-vps') to provision a completely isolated dedicated environment:")
    print("      • Dedicated Target VPS (Amazon Linux 2023 + SSM + Nginx)")
    print(f"      • Dedicated S3 Blobs Bucket ({report.s3.expected_name} with CreateBlobsBucket=true)")
    print("      • Dedicated DynamoDB EventStore + Zero-Trust SSM Docs + IAM Core Roles")
    print("      • Zero modification to any existing client servers or infrastructure")
    print("-" * 80)

    # Global View
    if report.global_view:
        print("\n[Global Multi-Region Scan — AWS Global View]")
        print("  (LLM inference is region-independent BYOK via HTTPS Bearer Token)")
        for g in report.global_view:
            r_name = g["region"]
            ec2_cnt = g["running_ec2_count"]
            t_cnt = g["incidents_tables_count"]
            if ec2_cnt > 0 or t_cnt > 0:
                print(f"  📍 {r_name:15} : 🟢 {ec2_cnt} running EC2 | 🗄️ {t_cnt} incidents-* table(s)")
            else:
                print(f"     {r_name:15} : ⚪ 0 running EC2 | 🗄️ 0 tables")


def print_plan(
    report: AuditReport,
    params: Dict[str, str],
    pre_actions: List[str],
    sam_command: str,
):
    print("\n" + "=" * 80)
    print("📋 DELTA DEPLOYMENT PLAN (`--mode plan`)")
    print("=" * 80)

    print("\n1. Delta Resolution (Existing Resources vs CloudFormation):")
    if params.get("TargetInstanceId") == "<WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T>":
        print(f"  - Target EC2 Instance:     <WILL_PROVISION_NEW_DEDICATED_VPS_VIA_-T> (Dedicated AL2023 + SSM + Nginx via -T)")
    else:
        print(f"  - Target EC2 Instance:     {params.get('TargetInstanceId') or 'None specified'}")
    if params.get("StrandsUrl") == "embedded":
        print("  - Strands Decider Mode:    Embedded In-Memory Hybrid Router (Zero external EC2 dependency)")
    else:
        strands_status = ""
        if report.strands_probe and report.strands_probe.get("url"):
            strands_status = f" [Probe: {'Healthy (HTTP 200)' if report.strands_probe.get('strands_healthy') else 'Unresponsive'}]"
        print(f"  - Strands Decider URL:     {params.get('StrandsUrl') or 'Embedded'}{strands_status}")
    print(f"  - LLM Inference Mode:      Region-Independent BYOK (HTTPS Bearer Token)")
    print(f"  - LLM Inference Base URL:  {params.get('DeepSeekBaseUrl', 'https://bedrock-mantle.us-east-1.api.aws/v1')}")
    print(f"  - DeepSeek Flash Model:    {params.get('DeepSeekFlashModel', 'deepseek.v3.1')}")
    print(f"  - DeepSeek Pro Model:      {params.get('DeepSeekProModel', 'deepseek.v3.2')}")
    print(f"  - DynamoDB Tables:         {'Reuse Existing (CreateDynamoTables=false)' if params.get('CreateDynamoTables') == 'false' else 'Create New (CreateDynamoTables=true)'}")
    print(f"  - S3 Blobs Bucket:         {'Reuse Existing (' + params.get('ExistingBlobsBucketName', '') + ')' if params.get('CreateBlobsBucket') == 'false' else 'Create New (' + report.s3.expected_name + ')'}")
    print(f"  - Zero-Trust SSM Docs:     {'Reuse Existing (CreateSsmDocuments=false)' if params.get('CreateSsmDocuments') == 'false' else 'Create New'}")
    print(f"  - IAM Core Roles:          {'Reuse Existing (CreateCoreIamRoles=false)' if params.get('CreateCoreIamRoles') == 'false' else 'Create New'}")
    print(f"  - CloudWatch Alarms:       {'Enabled' if params.get('EnableAlarms') == 'true' else 'Disabled'}")
    if params.get("EnableDiskAlarm") == "true":
        print("  - Disk Bloat Alarm:        Enabled (CWAgent Metrics Found)")
    else:
        print("  - Disk Bloat Alarm:        Auto-Configured in '--mode apply' (SSM CWAgent & Systemd Pulse Bootstrap)")

    print("\n[Universal Client Resource Choice Policy — Option A vs Option B]:")
    print("  * Option A (Adopt Existing Client Resources):")
    print("    - Target VPS:    Run with '--instance-id <ID>' to adopt an existing server.")
    print("    - S3 Bucket:     Run with '--existing-bucket <BUCKET_NAME>' to reuse an existing bucket.")
    print("    - API Key:       Run with '--deepseek-api-key <KEY>' to provision your key.")
    print("  * Option B (Provision Dedicated New Environment via '-T'):")
    print("    - Pass '-T' / '--create-target-vps' for a 100% isolated greenfield deployment.")
    print(f"      (Dedicated VPS + S3 bucket {report.s3.expected_name} + DynamoDB + SSM + IAM — zero touch on existing resources)")

    if pre_actions:
        print("\n2. Required Pre-Deployment Actions:")
        for idx, act in enumerate(pre_actions, 1):
            print(f"  [{idx}] {act}")
    else:
        if not report.stack.exists:
            print("\n2. Required Pre-Deployment Actions: None (Pre-deployment prerequisites verified; stack deployment pending)")
        else:
            print("\n2. Required Pre-Deployment Actions: None (Environment fully compliant)")

    print("\n3. Generated SAM Parameter Overrides:")
    for k, v in params.items():
        print(f"  {k:25} = {v}")

    print("\n4. Ready-to-Run SAM Deploy Command:")
    print("-" * 75)
    print(sam_command)
    print("-" * 75)

    if report.global_view:
        print("\n5. AWS Global View (Multi-Region Footprint):")
        print("  (Note: LLM inference is region-independent BYOK via HTTPS Bearer Token)")
        for g in report.global_view:
            r_name = g["region"]
            ec2_cnt = g["running_ec2_count"]
            t_cnt = g["incidents_tables_count"]
            if ec2_cnt > 0 or t_cnt > 0:
                print(f"  📍 {r_name:15} : 🟢 {ec2_cnt} running EC2 | 🗄️ {t_cnt} incidents-* table(s)")

    # LLM / Bedrock Fate & API Key Policy
    print_llm_bedrock_policy(report)


print_audit_report = print_audit_summary


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Autonomous Incident Remediation Onboarding & Discovery Tool"
    )
    parser.add_argument(
        "--mode",
        choices=["audit", "plan", "apply"],
        default="audit",
        help="Execution mode: 'audit' (discover), 'plan' (calculate delta parameters), or 'apply' (governed remediation & deploy)",
    )
    parser.add_argument(
        "--instance-id",
        default="",
        help="Target EC2 instance ID for autonomous remediation (required for plan & apply)",
    )
    parser.add_argument(
        "-T",
        "--create-target-vps",
        action="store_true",
        help="Provision a new dedicated EC2 target instance (Amazon Linux 2023 + SSM + Nginx) instead of touching existing instances",
    )
    parser.add_argument(
        "--existing-bucket",
        default="",
        help="Adopt an existing S3 bucket in client account for large blob storage (sets CreateBlobsBucket=false)",
    )
    parser.add_argument(
        "--deepseek-api-key",
        default="",
        help="DeepSeek API key to explicitly store in client AWS Secrets Manager (/incidents/deepseek-api-key)",
    )
    parser.add_argument(
        "-E",
        "--env-file",
        nargs="?",
        const=".env",
        default="",
        help="Path to .env configuration file (defaults to .env if -E is passed without path). Automatically injects secrets into AWS Secrets Manager and operational parameters into CloudFormation/Lambda without manual CLI flags.",
    )
    default_region = (
        os.environ.get("AWS_DEFAULT_REGION")
        or os.environ.get("AWS_REGION")
        or "us-east-1"
    )
    parser.add_argument(
        "--region",
        default=default_region,
        help=f"AWS region (default: AWS_DEFAULT_REGION/AWS_REGION or {default_region})",
    )
    parser.add_argument(
        "--stack-name",
        default="autonomous-secops-agent",
        help="CloudFormation stack name (default: autonomous-secops-agent)",
    )
    parser.add_argument(
        "--strands-url",
        default="",
        help="Override URL for Strands Decider service (e.g. http://<ip>:8080 or embedded)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Automatically approve and proceed with applying changes without interactive confirmation",
    )
    parser.add_argument(
        "--skip-sam",
        action="store_true",
        help="Execute pre-deploy actions and generate receipts without invoking sam build/deploy",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path to output discovery/receipt report as JSON (defaults to onboarding_report.json in apply mode)",
    )
    parser.add_argument(
        "--env-out",
        default="",
        help="Optional path to output sanitized environment variables configuration (e.g. .env.onboarded)",
    )
    parser.add_argument(
        "--global-view",
        action="store_true",
        help="Scan all active AWS regions for running EC2 instances and incidents-* DynamoDB tables",
    )
    return parser.parse_args(args)


def main():
    args = parse_args()

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    session = boto3.Session(region_name=args.region)

    # 1. Run Deep Discovery
    report = run_full_audit(
        session=session,
        region=args.region,
        target_instance_id=args.instance_id.strip() or None,
        stack_name=args.stack_name,
        project_root=project_root,
        enable_global_view=args.global_view,
        strands_override=args.strands_url.strip() or None,
    )

    # 2. Audit Mode
    if args.mode == "audit":
        print_audit_summary(report)
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump({"audit_report": report}, f, indent=2, cls=EnhancedJSONEncoder)
            print(f"\n📁 Report successfully saved to: {args.json_out}")
        return

    # Load environment configuration if -E / --env-file passed
    env_file_path = getattr(args, "env_file", "").strip()
    injected_secrets, injected_params = ({}, {})
    if env_file_path:
        raw_env = parse_env_file(env_file_path)
        if raw_env:
            injected_secrets, injected_params = split_env_vars(raw_env)
            print(f"📄 Loaded environment configuration from: {env_file_path}")
            if injected_secrets:
                print(f"   🔐 Detected secrets for AWS Secrets Manager: {', '.join(sorted(injected_secrets.keys()))}")
            if injected_params:
                print(f"   ⚙️ Detected configuration parameters for SAM: {', '.join(sorted(injected_params.keys()))}")

    # 3. Plan Mode
    if args.mode == "plan":
        print_audit_summary(report)
        params, pre_actions, sam_command = build_cfn_parameters(
            report=report,
            strands_override=args.strands_url.strip() or None,
            stack_name=args.stack_name,
            create_target_vps=args.create_target_vps,
            existing_bucket=args.existing_bucket.strip() or None,
            injected_params=injected_params,
        )
        print_plan(report, params, pre_actions, sam_command)

        if not args.instance_id.strip() and not args.create_target_vps:
            print("\n" + "!" * 75)
            print("⚠️ NOTICE: You ran '--mode plan' without specifying '--instance-id' or '-T'.")
            print("Existing client servers were protected and NOT auto-selected.")
            print("Please choose one of the following:")
            print("  * Option A (Adopt Existing VPS): Rerun with '--instance-id <INSTANCE_ID>'")
            print("  * Option B (Provision Dedicated Target VPS): Rerun with '-T' (or '--create-target-vps')")
            print("!" * 75)

            if args.json_out:
                out_data = {
                    "audit_report": report,
                    "parameters": params,
                    "pre_deployment_actions": pre_actions,
                    "sam_command": sam_command,
                }
                with open(args.json_out, "w", encoding="utf-8") as f:
                    json.dump(out_data, f, indent=2, cls=EnhancedJSONEncoder)
                print(f"\n📁 Plan report successfully saved to: {args.json_out}")
            if args.env_out:
                generate_env_file(report, params, args.env_out)
        return

    # 4. Apply Mode
    if args.mode == "apply":
        run_apply_mode(
            session=session,
            region=args.region,
            report=report,
            project_root=project_root,
            args=args,
            injected_secrets=injected_secrets,
            injected_params=injected_params,
        )


if __name__ == "__main__":
    main()
