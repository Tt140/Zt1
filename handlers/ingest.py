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
    EXECUTOR_FN, AWS_REGION, ok, err,
)

logger = logging.getLogger(__name__)

# The agent function — invoked asynchronously after incident creation
AGENT_FN = os.environ.get("AGENT_FUNCTION", "incidents-agent")

# Extract instance_id from alarm name (e.g., DiskUsage-High-i-12345678)
_INSTANCE_PATTERN = re.compile(r"(i-[0-9a-f]{8,17})", re.IGNORECASE)


def _extract_instance_id(alarm_name: str, description: str = "") -> str:
    """Extracts instance_id from alarm name or configuration description."""
    for text in [alarm_name, description]:
        m = _INSTANCE_PATTERN.search(text)
        if m:
            return m.group(1)
    # fallback: env var when agent operates on a single dedicated instance
    return os.environ.get("TARGET_INSTANCE_ID") or os.environ.get("INSTANCE_ID") or "i-unknown"


def handler(event: dict, context) -> dict:
    """
    Lambda handler for incidents-ingest.
    Triggered by EventBridge on CloudWatch Alarm -> ALARM transition.
    """
    try:
        detail = event.get("detail", {})
        alarm_name  = detail.get("alarmName", "")
        alarm_state = detail.get("state", {}).get("value", "")
        alarm_arn   = (event.get("resources") or [""])[0]
        alert_source = event.get("detail-type", "CloudWatch Alarm State Change")
        description  = detail.get("configuration", {}).get("description", "")
        region       = event.get("region", AWS_REGION)

        if not alarm_name:
            return err("missing alarmName in event", 400)

        # Ignore non-ALARM states (OK, INSUFFICIENT_DATA)
        if alarm_state != "ALARM":
            logger.info(f"Skipping alarm state {alarm_state!r} for {alarm_name}")
            return ok({"skipped": True, "reason": "not ALARM state"})

        instance_id = _extract_instance_id(alarm_name, description)
        dedupe_key  = f"alarm::{alarm_name}::{instance_id}"
        incident_id = new_ulid()

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
        iid, created = store.create_if_absent(dedupe_key, header)

        if not created:
            logger.info(f"Duplicate alarm — incident already exists: {iid}")
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
        store.append(iid, 0, ev)

        # Invoke agent async
        invoke_async(AGENT_FN, {
            "incident_id": iid,
            "instance_id": instance_id,
        })

        logger.info(f"Incident created: {iid} for alarm {alarm_name}")
        return ok({"incident_id": iid, "created": True})

    except Exception as exc:
        logger.exception(f"ingest handler error: {exc}")
        return err(str(exc))
