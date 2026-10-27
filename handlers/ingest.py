"""
handlers/ingest.py — incidents-ingest Lambda

Trigger: EventBridge Rule (CloudWatch Alarm → ALARM state)
Responsibilities:
  1. Extract alarm_name + instance_id from CloudWatch event payload
  2. Construct dedupe_key → create_if_absent in DynamoDB
  3. Invoke incidents-agent async with incident_id

Event format (EventBridge → CloudWatch Alarm):
{
  "source": "aws.cloudwatch",
  "detail-type": "CloudWatch Alarm State Change",
  "detail": {
    "alarmName": "DiskUsage-High",
    "state": {"value": "ALARM"},
    "configuration": {"description": "..."}
  },
  "resources": ["arn:aws:cloudwatch:us-east-1:123:alarm:DiskUsage-High"],
  "region": "us-east-1"
}

Extracts instance_id from alarm name (format: {metric}-{instance_id})
or from optional description tags.
"""
from __future__ import annotations

import json
import logging
import re
import os

from src.domain.types import (
    IncidentHeader, IncidentOpenedPayload,
    build_event, EventType, Actor, utc_now, new_ulid,
    EvidenceAddedPayload, EvidenceRef, TrustLevel,
)
from src.domain.reducer import fold
from .shared import (
    get_store, invoke_async,
    EXECUTOR_FN, NOTIFIER_FN, AWS_REGION, ok, err,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger().setLevel(logging.INFO)
for _h in logging.getLogger().handlers:
    _h.setLevel(logging.INFO)

# The agent function — invoked asynchronously after incident creation
AGENT_FN = os.environ.get("AGENT_FUNCTION", "incidents-agent")

from typing import Any

# Extract instance_id from alarm name (e.g., DiskUsage-High-i-12345678)
_INSTANCE_PATTERN = re.compile(r"(i-[0-9a-f]{8,17})", re.IGNORECASE)


def _normalize_event(event: Any) -> dict:
    """
    Unwraps SNS message wrappers, API Gateway bodies, or stringified payloads into
    a standard CloudWatch Alarm State Change event dictionary.
    """
    if not isinstance(event, dict):
        return {}

    # Check for SNS wrapper: event["Records"][0]["Sns"]["Message"]
    records = event.get("Records")
    if isinstance(records, list) and records:
        record = records[0]
        if isinstance(record, dict) and "Sns" in record:
            msg = record["Sns"].get("Message")
            if isinstance(msg, str):
                try:
                    parsed = json.loads(msg)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass
            elif isinstance(msg, dict):
                return msg

    # Check for API Gateway / Function URL wrapper: event["body"]
    if "body" in event and isinstance(event["body"], str):
        try:
            parsed = json.loads(event["body"])
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    return event


def _find_instance_in_dimensions(dims: Any) -> str | None:
    """Inspects a dimensions collection (dict or list of name/value dicts) for an instance ID."""
    if not dims:
        return None
    if isinstance(dims, dict):
        for k, v in dims.items():
            if str(k).lower() in ("instanceid", "instance_id", "targetinstanceid"):
                m = _INSTANCE_PATTERN.search(str(v))
                if m:
                    return m.group(1)
            elif _INSTANCE_PATTERN.search(str(v)):
                return _INSTANCE_PATTERN.search(str(v)).group(1)
    elif isinstance(dims, list):
        for item in dims:
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("Name") or "").lower()
                val = str(item.get("value") or item.get("Value") or "")
                if name in ("instanceid", "instance_id", "targetinstanceid"):
                    m = _INSTANCE_PATTERN.search(val)
                    if m:
                        return m.group(1)
                elif _INSTANCE_PATTERN.search(val):
                    return _INSTANCE_PATTERN.search(val).group(1)
    return None


def _extract_instance_id(alarm_name: str, description: str = "", detail: dict | None = None) -> str:
    """
    Extracts instance_id using a multi-layer strategy:
      1. CloudWatch Metric Dimensions (configuration.metrics[*].metricStat.metric.dimensions or direct dimensions)
      2. Alarm name pattern matching (i-[0-9a-f]{8,17})
      3. Description pattern matching
      4. Fallback environment variables (TARGET_INSTANCE_ID / INSTANCE_ID)
    """
    # 1. Check detail configuration dimensions if provided
    if detail and isinstance(detail, dict):
        config = detail.get("configuration", {}) or {}

        # Check configuration.metrics (standard metricStat format)
        metrics = config.get("metrics") or []
        for m_entry in metrics:
            if not isinstance(m_entry, dict):
                continue
            metric_stat = m_entry.get("metricStat", {}) or {}
            metric = metric_stat.get("metric", {}) or {}
            dims = metric.get("dimensions", {})
            found = _find_instance_in_dimensions(dims)
            if found:
                return found

        # Check direct dimensions in configuration or detail
        for source_dict in [config, detail]:
            dims = source_dict.get("dimensions")
            found = _find_instance_in_dimensions(dims)
            if found:
                return found

    # 2. Check alarm_name and description via regex
    for text in [alarm_name, description]:
        if text:
            m = _INSTANCE_PATTERN.search(text)
            if m:
                return m.group(1)

    # 3. Fallback: env var when agent operates on a single dedicated instance
    return os.environ.get("TARGET_INSTANCE_ID") or os.environ.get("INSTANCE_ID") or "i-unknown"


def handler(event: dict, context) -> dict:
    """
    Lambda handler for incidents-ingest.
    Triggered by EventBridge on CloudWatch Alarm -> ALARM transition.
    """
    logger.setLevel(logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    raw_event = event or {}
    logger.info(f"[INGEST-START] Incoming event: {json.dumps(raw_event, default=str)}")

    try:
        norm_event = _normalize_event(raw_event)
        detail = norm_event.get("detail", {})
        alarm_name  = detail.get("alarmName", "")
        alarm_state = detail.get("state", {}).get("value", "")
        alarm_arn   = (norm_event.get("resources") or [""])[0]
        alert_source = norm_event.get("detail-type", "CloudWatch Alarm State Change")
        description  = detail.get("configuration", {}).get("description", "")
        region       = norm_event.get("region", AWS_REGION)

        logger.info(
            f"[INGEST-PARSED] alarm_name='{alarm_name}', state='{alarm_state}', "
            f"alert_source='{alert_source}', region='{region}'"
        )

        if not alarm_name:
            logger.error(f"[INGEST-ERROR] Missing alarmName in parsed event: {norm_event}")
            return err("missing alarmName in event", 400)

        # Ignore non-ALARM states (OK, INSUFFICIENT_DATA)
        if alarm_state != "ALARM":
            logger.warning(f"[INGEST-SKIP] Skipping alarm '{alarm_name}' with non-ALARM state '{alarm_state}'")
            return ok({"skipped": True, "reason": f"not ALARM state (state={alarm_state})"})

        instance_id = _extract_instance_id(alarm_name, description, detail=detail)
        dedupe_key  = f"alarm::{alarm_name}::{instance_id}"
        incident_id = new_ulid()

        logger.info(f"[INGEST-INSTANCE] Extracted instance_id='{instance_id}', dedupe_key='{dedupe_key}'")

        header = IncidentHeader(
            incident_id=incident_id,
            instance_id=instance_id,
            dedupe_key=dedupe_key,
            alarm_name=alarm_name,
            alarm_arn=alarm_arn,
            alert_source=alert_source,
            opened_at=utc_now().isoformat(),
        )

        store = get_store()
        logger.info(f"[INGEST-DEDUP] Checking deduplication lock for '{dedupe_key}'...")
        iid, created = store.create_if_absent(dedupe_key, header)

        if not created:
            # State-Aware Check: If prior incident was already resolved or escalated,
            # OR if it is stale (e.g. awaiting_approval past token expiry or abandoned),
            # release stale dedupe_key and open a new incident for this recurring alarm.
            logger.info(f"[INGEST-DEDUP] Existing incident '{iid}' found for key '{dedupe_key}'. Inspecting prior state...")
            try:
                events = store.read(iid)
                if events:
                    from datetime import datetime
                    from src.domain.reducer import fold
                    from src.domain.types import IncidentPhase
                    prior_state = fold(events)
                    last_ev = events[-1]
                    now_utc = utc_now()

                    is_stale = False
                    stale_reason = ""
                    try:
                        last_ts = datetime.fromisoformat(last_ev.ts)
                        age_seconds = (now_utc - last_ts).total_seconds()
                        if prior_state.phase == IncidentPhase.awaiting_approval and age_seconds > 900:
                            is_stale = True
                            stale_reason = f"approval expired ({int(age_seconds)}s > 900s)"
                        elif prior_state.phase not in (IncidentPhase.resolved, IncidentPhase.escalated) and age_seconds > 1800:
                            is_stale = True
                            stale_reason = f"incident abandoned ({int(age_seconds)}s > 1800s without activity)"
                    except Exception as ts_err:
                        logger.debug(f"Could not compute incident age: {ts_err}")

                    logger.info(
                        f"[INGEST-DEDUP-STATE] Prior incident '{iid}' phase is '{prior_state.phase.value}', "
                        f"events={len(events)}, is_stale={is_stale} ({stale_reason})"
                    )

                    if prior_state.phase in (IncidentPhase.resolved, IncidentPhase.escalated) or is_stale:
                        reason = stale_reason if is_stale else prior_state.phase.value
                        logger.warning(
                            f"[INGEST-DEDUP-RELEASE] Prior incident {iid} is {reason} — "
                            f"releasing stale dedupe key '{dedupe_key}' and opening fresh incident"
                        )
                        store.release_dedupe(dedupe_key)
                        iid, created = store.create_if_absent(dedupe_key, header)
            except Exception as e:
                logger.warning(f"[INGEST-DEDUP-ERROR] Error checking state of existing incident {iid}: {e}", exc_info=True)

        if not created:
            logger.warning(
                f"[INGEST-DEDUP-BLOCKED] Duplicate alarm for key '{dedupe_key}'. "
                f"Incident '{iid}' is actively in progress. Returning HTTP 200 without creating duplicate."
            )
            return ok({"incident_id": iid, "created": False})

        # Persist IncidentOpened event
        ev = build_event(
            incident_id=iid,
            type=EventType.IncidentOpened,
            actor=Actor.ingest,
            payload=IncidentOpenedPayload(
                instance_id=instance_id,
                dedupe_key=dedupe_key,
                alarm_name=alarm_name,
                alarm_arn=alarm_arn,
                alert_source=alert_source,
                alarm_description=description,
            ),
        )
        logger.info(f"[INGEST-STORE] Writing IncidentOpened event for incident '{iid}' to DynamoDB...")
        store.append(iid, 0, ev)
        logger.info(f"[INGEST-STORE] IncidentOpened written successfully for '{iid}'.")

        # Notify Slack async: Incident opened
        logger.info(f"[INGEST-NOTIFY] Dispatching incident notification to '{NOTIFIER_FN}' async...")
        invoke_async(NOTIFIER_FN, {
            "type": "incident_opened",
            "incident_id": iid,
            "instance_id": instance_id,
            "alarm_name": alarm_name,
            "message": f"CloudWatch alarm '{alarm_name}' triggered incident {iid} on instance {instance_id}",
        })

        # Invoke agent async
        logger.info(f"[INGEST-AGENT] Triggering remediation agent '{AGENT_FN}' async for incident '{iid}'...")
        invoke_async(AGENT_FN, {
            "incident_id": iid,
            "instance_id": instance_id,
        })

        logger.info(f"[INGEST-SUCCESS] Incident {iid} created and agent launched successfully for alarm '{alarm_name}'.")
        return ok({"incident_id": iid, "created": True})

    except Exception as exc:
        logger.exception(f"[INGEST-FATAL] Ingest handler unhandled exception: {exc}")
        return err(str(exc))
