"""
handlers/shared.py — Shared runtime primitives across Lambda handlers

Reads configuration from environment variables and builds store + clients once
outside the handler lifecycle (warm-start caching).
"""
from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Optional

import boto3

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# ── config ───────────────────────────────────────────────────────────────────

def cfg(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


EVENTS_TABLE     = cfg("EVENTS_TABLE",    "incidents-events")
DEDUP_TABLE      = cfg("DEDUP_TABLE",     "incidents-dedup")
LEASES_TABLE     = cfg("LEASES_TABLE",    "incidents-leases")
BLOBS_BUCKET     = cfg("BLOBS_BUCKET",    "")           # Empty = S3 disabled (test mode)
AWS_REGION       = cfg("AWS_REGION",      "us-east-1")
OBSERVER_FN      = cfg("OBSERVER_FUNCTION",  "incidents-observer")
EXECUTOR_FN      = cfg("EXECUTOR_FUNCTION",  "incidents-executor")
NOTIFIER_FN      = cfg("NOTIFIER_FUNCTION",  "incidents-notifier")
SSM_EXEC_ROLE    = cfg("SSM_EXEC_ROLE_ARN",  "")        # Empty = direct role without AssumeRole
NOVA_MODEL_ID    = cfg("NOVA_MODEL_ID",   "amazon.nova-lite-v1:0")
STRANDS_URL      = cfg("STRANDS_URL",     "embedded")   # "embedded" or empty = EmbeddedStrandsDecider
INSTANCE_ID      = cfg("TARGET_INSTANCE_ID", "")
BEDROCK_REGION   = cfg("BEDROCK_REGION",   "us-east-1")

# ── canonical configuration keys ─────────────────────────────────────────────
APPROVAL_MAC_KEY_HEX_VAR                 = "APPROVAL_MAC_KEY_HEX"
APPROVAL_MAC_KEY_SECRET_ARN_VAR          = "APPROVAL_MAC_KEY_SECRET_ARN"
SLACK_AUTHORIZED_APPROVERS_VAR           = "SLACK_AUTHORIZED_APPROVERS"
SLACK_AUTHORIZED_APPROVERS_SECRET_ARN_VAR = "SLACK_AUTHORIZED_APPROVERS_SECRET_ARN"


# ── secrets resolution ────────────────────────────────────────────────────────

@lru_cache(maxsize=32)
def _resolve_secret(env_var_name: str, secret_arn_env_var: str, default_secret_id: str) -> str:
    """
    Resolves secrets in strict order of precedence:
    1. Direct environment variable (env_var_name), e.g., DEEPSEEK_API_KEY or APPROVAL_MAC_KEY_HEX.
    2. AWS Secrets Manager query using secret_arn_env_var if present, or default_secret_id.
    3. Safely returns empty string without failing import.
    """
    val = os.environ.get(env_var_name, "").strip()
    if val:
        return val

    # Backward compatibility with legacy HMAC key variable names if present
    secret_id = os.environ.get(secret_arn_env_var, "").strip()
    if not secret_id and secret_arn_env_var == APPROVAL_MAC_KEY_SECRET_ARN_VAR:
        secret_id = os.environ.get("APPROVAL_MAC_SECRET_ARN", "").strip()

    secret_id = secret_id or default_secret_id
    if not secret_id:
        return ""

    try:
        sm = boto3.client("secretsmanager", region_name=AWS_REGION)
        resp = sm.get_secret_value(SecretId=secret_id)
        secret_val = resp.get("SecretString", "")
        if secret_val:
            return secret_val.strip()
    except Exception as e:
        logger.warning(
            f"Failed to resolve secret from Secrets Manager ({secret_id}) for {env_var_name}: {e}"
        )
    return ""


@lru_cache(maxsize=1)
def get_approval_mac_key(explicit_key: Optional[bytes] = None) -> bytes:
    """
    Returns MAC key for validating Tier T2 human approvals as bytes.
    Reads from APPROVAL_MAC_KEY_HEX first, then AWS Secrets Manager (/incidents/approval-mac-key).

    Zero-Trust Security & Compliance:
    - Eliminates any fallback to hardcoded test keys in production paths.
    - Fails closed and raises RuntimeError if key cannot be discovered or retrieved.
    - Raises ValueError if value is invalid hex or shorter than 16 bytes.
    - Never relies on pytest discovery to infer environment.
    """
    if explicit_key is not None:
        if not isinstance(explicit_key, bytes) or len(explicit_key) != 32:
            raise ValueError(
                f"APPROVAL_MAC_KEY length must be exactly 32 bytes (256 bits), got "
                f"{len(explicit_key) if isinstance(explicit_key, bytes) else type(explicit_key)}."
            )
        return explicit_key

    hex_str = os.environ.get(APPROVAL_MAC_KEY_HEX_VAR, "").strip()
    if not hex_str:
        hex_str = _resolve_secret(
            env_var_name=APPROVAL_MAC_KEY_HEX_VAR,
            secret_arn_env_var=APPROVAL_MAC_KEY_SECRET_ARN_VAR,
            default_secret_id="/incidents/approval-mac-key",
        )

    if not hex_str:
        raise RuntimeError(
            f"APPROVAL_MAC_KEY is not configured: neither {APPROVAL_MAC_KEY_HEX_VAR} nor "
            f"Secrets Manager ({APPROVAL_MAC_KEY_SECRET_ARN_VAR}) returned a valid key. "
            "Fail-closed: approvals cannot be generated or verified."
        )

    try:
        key_bytes = bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(
            f"APPROVAL_MAC_KEY is not valid hex: {e}. Fail-closed: approvals cannot be verified."
        ) from e

    if len(key_bytes) != 32:
        raise ValueError(
            f"APPROVAL_MAC_KEY length must be exactly 32 bytes (64 hex characters), got {len(key_bytes)} bytes. "
            "Fail-closed: approvals cannot be verified."
        )

    return key_bytes


@lru_cache(maxsize=1)
def get_authorized_approvers() -> frozenset[str]:
    """
    Retrieves authorized Slack user IDs eligible to approve Tier T2 remediation actions.

    Precedence:
    1. SLACK_AUTHORIZED_APPROVERS environment variable (comma-separated or JSON list/dict).
    2. AWS Secrets Manager via SLACK_AUTHORIZED_APPROVERS_SECRET_ARN or /incidents/slack-authorized-approvers.

    Zero-Trust RBAC Security Policy:
    - Fail-closed: If unconfigured, empty, unavailable, or malformed, returns empty frozenset().
    - Any approval attempt from a user not present in this set is rejected immediately.
    """
    raw = os.environ.get(SLACK_AUTHORIZED_APPROVERS_VAR, "").strip()
    if not raw:
        raw = _resolve_secret(
            env_var_name=SLACK_AUTHORIZED_APPROVERS_VAR,
            secret_arn_env_var=SLACK_AUTHORIZED_APPROVERS_SECRET_ARN_VAR,
            default_secret_id="/incidents/slack-authorized-approvers",
        )

    if not raw:
        logger.warning(
            "SLACK_AUTHORIZED_APPROVERS is not configured or empty. "
            "Fail-closed: All Tier.T2 approvals will be rejected."
        )
        return frozenset()

    # Parse JSON list or dict if provided
    if raw.startswith("[") or raw.startswith("{"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                approvers = {str(u).strip().strip("<@>").strip() for u in parsed if str(u).strip()}
                return frozenset(approvers)
            if isinstance(parsed, dict):
                approver_list = (
                    parsed.get("approvers")
                    or parsed.get("users")
                    or parsed.get("authorized_approvers")
                    or []
                )
                if isinstance(approver_list, list):
                    approvers = {str(u).strip().strip("<@>").strip() for u in approver_list if str(u).strip()}
                    return frozenset(approvers)
        except Exception as e:
            logger.warning(f"Failed to parse SLACK_AUTHORIZED_APPROVERS JSON: {e}")

        # If text began as JSON and failed parsing or schema validation, fail closed safely
        logger.warning(
            "SLACK_AUTHORIZED_APPROVERS had invalid JSON syntax or schema. "
            "Fail-closed: returning empty approver set."
        )
        return frozenset()

    # Fallback to comma/newline-separated list
    items = [
        item.strip().strip("<@>").strip()
        for item in raw.replace("\n", ",").split(",")
        if item.strip().strip("<@>").strip()
    ]
    return frozenset(items)


def __getattr__(name: str):
    """
    Lazy dynamic loader for APPROVAL_MAC_KEY to maintain backwards compatibility
    without aborting module import when key is unconfigured at cold start.
    """
    if name == "APPROVAL_MAC_KEY":
        return get_approval_mac_key()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_slack_webhook_url() -> str:
    """
    Safely retrieves Slack Webhook URL in order of precedence:
    1. SLACK_WEBHOOK_URL environment variable.
    2. SLACK_WEBHOOK_SECRET_ARN or default /incidents/slack-webhook-url in AWS Secrets Manager.
    3. Returns empty string if unconfigured.
    """
    url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if url:
        return url
    return _resolve_secret(
        env_var_name="SLACK_WEBHOOK_URL",
        secret_arn_env_var="SLACK_WEBHOOK_SECRET_ARN",
        default_secret_id="/incidents/slack-webhook-url",
    )


# ── store factory ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_store():
    """Cached DynamoEventStore instance for warm start optimization."""
    from src.store.dynamo_store import DynamoEventStore

    s3_client = None
    if BLOBS_BUCKET:
        s3_client = boto3.client("s3", region_name=AWS_REGION)

    return DynamoEventStore(
        incidents_table=EVENTS_TABLE,
        dedup_table=DEDUP_TABLE,
        leases_table=LEASES_TABLE,
        region=AWS_REGION,
        s3_bucket=BLOBS_BUCKET or None,
        s3_client=s3_client,
    )


# ── model factory ─────────────────────────────────────────────────────────────

# DeepSeek model identifiers and API base
DEEPSEEK_BASE_URL    = cfg("DEEPSEEK_BASE_URL",    "https://bedrock-mantle.us-east-1.api.aws/v1")
DEEPSEEK_FLASH_MODEL = cfg("DEEPSEEK_FLASH_MODEL", "deepseek.v3.1")       # Fast / routine triage
DEEPSEEK_PRO_MODEL   = cfg("DEEPSEEK_PRO_MODEL",   "deepseek.v3.2")       # Complex / ambiguous diagnosis

# Bedrock Nova model identifiers
NOVA_FLASH_MODEL_ID  = cfg("NOVA_FLASH_MODEL_ID",  "amazon.nova-lite-v1:0")
NOVA_PRO_MODEL_ID    = cfg("NOVA_PRO_MODEL_ID",     "amazon.nova-pro-v1:0")


@lru_cache(maxsize=1)
def get_model():
    """
    Returns ModelRouter instance with dual flash + pro tiers.

    Provider Selection via env var or Secrets Manager:
      DEEPSEEK_API_KEY present or in Secrets Manager (/incidents/deepseek-api-key) → DeepSeek
      Otherwise                                                                 → Bedrock Nova

    Model Configuration:
      DEEPSEEK_BASE_URL    = https://bedrock-mantle.us-east-1.api.aws/v1 (default)
      DEEPSEEK_FLASH_MODEL = deepseek.v3.1    (default)
      DEEPSEEK_PRO_MODEL   = deepseek.v3.2    (default)
      NOVA_FLASH_MODEL_ID  = amazon.nova-lite-v1:0
      NOVA_PRO_MODEL_ID    = amazon.nova-pro-v1:0
    """
    from src.agent.model_router import ModelRouter

    deepseek_key = _resolve_secret(
        env_var_name="DEEPSEEK_API_KEY",
        secret_arn_env_var="DEEPSEEK_API_KEY_SECRET_ARN",
        default_secret_id="/incidents/deepseek-api-key",
    )
    if deepseek_key:
        from src.agent.deepseek_model import DeepSeekModel
        flash = DeepSeekModel(
            api_key=deepseek_key,
            model=DEEPSEEK_FLASH_MODEL,
            api_base=DEEPSEEK_BASE_URL,
        )
        pro   = DeepSeekModel(
            api_key=deepseek_key,
            model=DEEPSEEK_PRO_MODEL,
            api_base=DEEPSEEK_BASE_URL,
        )
        logger.info(
            f"ModelRouter(DeepSeek): flash={DEEPSEEK_FLASH_MODEL} pro={DEEPSEEK_PRO_MODEL} base_url={DEEPSEEK_BASE_URL}"
        )
        return ModelRouter(flash_model=flash, pro_model=pro)

    from src.agent.nova_model import BedrockNovaModel
    flash = BedrockNovaModel(model_id=NOVA_FLASH_MODEL_ID, region=BEDROCK_REGION)
    pro   = BedrockNovaModel(model_id=NOVA_PRO_MODEL_ID,   region=BEDROCK_REGION)
    logger.info(
        f"ModelRouter(Bedrock): flash={NOVA_FLASH_MODEL_ID} pro={NOVA_PRO_MODEL_ID} region={BEDROCK_REGION}"
    )
    return ModelRouter(flash_model=flash, pro_model=pro)


# ── decider factory ───────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_decider():
    """
    Returns StrandsDeciderClient if STRANDS_URL is set to an external endpoint,
    or EmbeddedStrandsDecider if empty or 'embedded' for standalone execution.
    """
    from src.agent.tool_decider import EmbeddedStrandsDecider, StrandsDeciderClient
    url = (STRANDS_URL or "").strip()
    if not url or url.lower() == "embedded":
        logger.info("Using EmbeddedStrandsDecider (self-contained embedded mode)")
        return EmbeddedStrandsDecider()
    logger.info(f"Using StrandsDeciderClient: {url}")
    return StrandsDeciderClient(endpoint_url=url, timeout_seconds=30.0)


# ── lambda client (cached) ────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_lambda_client():
    return boto3.client("lambda", region_name=AWS_REGION)


# ── helpers ───────────────────────────────────────────────────────────────────

def invoke_async(function_name: str, payload: dict) -> None:
    """Invokes Lambda asynchronously without waiting for response."""
    client = get_lambda_client()
    client.invoke(
        FunctionName=function_name,
        InvocationType="Event",       # async
        Payload=json.dumps(payload).encode(),
    )
    logger.info(f"Invoked {function_name} async")


def ok(body: dict, status: int = 200) -> dict:
    return {"statusCode": status, "body": json.dumps(body)}


def err(msg: str, status: int = 500) -> dict:
    logger.error(msg)
    return {"statusCode": status, "body": json.dumps({"error": msg})}
