"""
handlers/observer.py — incidents-observer Lambda

Trigger: InvokeSync from incidents-agent (ProxyObserveBackend)
Responsibilities: Executes read-only observation commands (Tier T0) on EC2 via SSM SendCommand.

Zero-Trust: This Lambda function is the exclusive holder of ssm:SendCommand observation permissions.
The reasoning agent Lambda does not possess SSM execution capabilities.

Supported Operations:
  - run_observation: Execute read-only shell command via SSM
  - get_metric: CloudWatch GetMetricData
  - get_logs: CloudWatch Logs FilterLogEvents
  - describe_alarm: CloudWatch DescribeAlarms
"""
from __future__ import annotations

import json
import logging
import os
import time

import boto3

from src.executor.ssm_lab import SSMLab
from .shared import ok, err, cfg, AWS_REGION

logger = logging.getLogger(__name__)

INSTANCE_ID  = cfg("TARGET_INSTANCE_ID", "")
SSM_DOC_T0   = cfg("SSM_DOC_OBSERVE", "incidents-observe-readonly")
CW_NAMESPACE = cfg("CW_NAMESPACE", "AWS/EC2")


def handler(event: dict, context) -> dict:
    operation = event.get("operation", "")

    try:
        if operation == "run_observation":
            return _run_observation(event)
        elif operation == "get_metric":
            return _get_metric(event)
        elif operation == "get_logs":
            return _get_logs(event)
        elif operation == "describe_alarm":
            return _describe_alarm(event)
        else:
            return err(f"Unknown operation: {operation!r}", 400)
    except Exception as exc:
        logger.exception(f"observer error in {operation}: {exc}")
        return err(str(exc))


def _run_observation(event: dict) -> dict:
    instance_id  = event.get("instance_id") or INSTANCE_ID
    command      = event.get("command", "")
    timeout      = int(event.get("timeout_seconds", 30))

    if not instance_id:
        return err("missing instance_id", 400)
    if not command:
        return err("missing command", 400)

    # SSMLab validates command against strict allowlist before dispatch
    lab = SSMLab(instance_id=instance_id, region=AWS_REGION)
    result = lab.run(command=command, tier="T0", timeout_seconds=timeout)

    return {
        "success":   result.success,
        "stdout":    result.stdout,
        "stderr":    result.stderr,
        "exit_code": result.exit_code,
        "verified":  result.verified,
        "trust":     "host_reported",
        "blocked_reason": getattr(result, "blocked_reason", None),
    }


def _get_metric(event: dict) -> dict:
    instance_id  = event.get("instance_id") or INSTANCE_ID
    metric_name  = event.get("metric_name", "CPUUtilization")
    period       = int(event.get("period_seconds", 300))

    cw = boto3.client("cloudwatch", region_name=AWS_REGION)
    end   = int(time.time())
    start = end - period

    try:
        resp = cw.get_metric_statistics(
            Namespace=CW_NAMESPACE,
            MetricName=metric_name,
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=["Average", "Maximum"],
        )
        sorted_dps = sorted(resp.get("Datapoints", []), key=lambda d: d["Timestamp"])
        if not sorted_dps:
            return {
                "error": f"UNAVAILABLE: no datapoints for metric {metric_name}",
                "values": [],
                "value": None,
                "unit": "UNAVAILABLE",
                "period_seconds": period,
                "trust": "out_of_band",
            }
        last = sorted_dps[-1]
        latest_val = float(last.get("Average") if last.get("Average") is not None else last.get("Maximum", 0.0))
        unit = last.get("Unit", "None")
        values = [
            {"ts": dp["Timestamp"].isoformat(), "avg": dp.get("Average"), "max": dp.get("Maximum")}
            for dp in sorted_dps
        ]
        return {
            "value": latest_val,
            "period_seconds": period,
            "values": values,
            "unit": unit,
            "trust": "out_of_band",
        }
    except Exception as exc:
        logger.error(f"get_metric error: {exc}")
        return {
            "value": 0.0,
            "period_seconds": period,
            "values": [],
            "unit": "None",
            "trust": "out_of_band",
            "error": str(exc),
        }


def _get_logs(event: dict) -> dict:
    log_group    = event.get("log_group", "/var/log/messages")
    minutes      = int(event.get("minutes_back") or event.get("minutes", 10))
    query        = event.get("query", "")
    instance_id  = event.get("instance_id") or INSTANCE_ID

    # Separate local system logs from CloudWatch log streams
    if log_group.startswith("/var/log/") or log_group == "journalctl":
        if not instance_id:
            return {
                "entries": [],
                "lines": [],
                "trust": "host_reported",
                "error": f"Local log path {log_group} requires instance_id",
            }
        cmd = "journalctl -n 50" if log_group == "journalctl" else f"cat {log_group}"
        try:
            lab = SSMLab(instance_id=instance_id, region=AWS_REGION)
            result = lab.run(command=cmd, tier="T0", timeout_seconds=30)

            # Fallback: if /var/log/messages or /var/log/syslog is missing, query journalctl -n 50
            if log_group in ("/var/log/messages", "/var/log/syslog"):
                file_missing = (
                    not result.success
                    or result.exit_code != 0
                    or "no such file" in (result.stderr or "").lower()
                    or "not found" in (result.stderr or "").lower()
                    or not result.stdout.strip()
                )
                if file_missing:
                    fallback_cmd = "journalctl -n 50"
                    result = lab.run(command=fallback_cmd, tier="T0", timeout_seconds=30)

            if not result.success or result.exit_code != 0 or not result.stdout.strip():
                err_msg = result.stderr or f"SSM command failed with exit_code {result.exit_code}"
                return {
                    "entries": [],
                    "lines": [],
                    "trust": "host_reported",
                    "error": f"Failed reading local log {log_group}: {err_msg}",
                }
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            if query:
                lines = [l for l in lines if query in l]
            return {"entries": lines, "lines": lines, "trust": "host_reported"}
        except Exception as exc:
            logger.error(f"get_logs SSM error for {log_group}: {exc}")
            return {"entries": [], "lines": [], "trust": "host_reported", "error": str(exc)}

    logs = boto3.client("logs", region_name=AWS_REGION)
    end_ms   = int(time.time() * 1000)
    start_ms = end_ms - (minutes * 60 * 1000)

    try:
        kwargs = {
            "logGroupName": log_group,
            "startTime": start_ms,
            "endTime": end_ms,
            "limit": 200,
        }
        if query:
            kwargs["filterPattern"] = query

        resp = logs.filter_log_events(**kwargs)
        lines = [e["message"] for e in resp.get("events", [])]
        return {"entries": lines, "lines": lines, "trust": "host_reported"}
    except Exception as exc:
        logger.error(f"get_logs error: {exc}")
        return {"entries": [], "lines": [], "trust": "host_reported", "error": str(exc)}


def _describe_alarm(event: dict) -> dict:
    alarm_name = event.get("alarm_name", "")
    if not alarm_name:
        return err("missing alarm_name", 400)

    cw = boto3.client("cloudwatch", region_name=AWS_REGION)
    try:
        resp = cw.describe_alarms(AlarmNames=[alarm_name])
        alarms = resp.get("MetricAlarms", [])
        if not alarms:
            return {"state": "UNKNOWN", "reason": "alarm not found", "trust": "out_of_band"}
        a = alarms[0]
        return {
            "state":  a.get("StateValue", "UNKNOWN"),
            "reason": a.get("StateReason", ""),
            "trust":  "out_of_band",
        }
    except Exception as exc:
        logger.error(f"describe_alarm error: {exc}")
        return {"state": "UNKNOWN", "reason": str(exc), "trust": "out_of_band"}
