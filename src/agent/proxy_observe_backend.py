"""
agent/proxy_observe_backend.py — ProxyObserveBackend

agent Lambda invokes observer Lambda synchronously.
observer Lambda (with ssm_backend.py) holds ssm:SendCommand permission.
agent Lambda does not hold it — ZeroTrust architectural segregation.

API contract between agent Lambda and observer Lambda:
  Request:  {incident_id, instance_id, command, timeout_seconds, operation}
  Response: {success, stdout, stderr, trust, exit_code, error?}
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .mock_backend import ObserveBackend, ObservationResult, MetricResult, LogResult, AlarmState

logger = logging.getLogger(__name__)


class ProxyObserveBackend(ObserveBackend):
    """
    Proxies observation requests to observer Lambda via synchronous boto3 Lambda invoke.
    Does not hold ssm:SendCommand permissions directly.
    
    Configuration:
      observer_function_name: Lambda function name (e.g., "incidents-observer")
      region: AWS region string
    """

    def __init__(
        self,
        observer_function_name: str,
        region: str = "us-east-1",
        lambda_client=None,
    ):
        self._fn = observer_function_name
        self._region = region

        if lambda_client is not None:
            self._lambda = lambda_client
        else:
            try:
                import boto3
                self._lambda = boto3.client("lambda", region_name=region)
            except ImportError:
                raise ImportError("pip install boto3 for ProxyObserveBackend")

    def _invoke(self, operation: str, payload: dict) -> dict:
        resp = self._lambda.invoke(
            FunctionName=self._fn,
            InvocationType="RequestResponse",
            Payload=json.dumps({**payload, "operation": operation}).encode(),
        )
        result = json.loads(resp["Payload"].read())
        if "errorMessage" in result:
            raise RuntimeError(f"observer Lambda error: {result['errorMessage']}")
        return result

    def run_observation(
        self, instance_id: str, command: str, timeout_seconds: int = 30
    ) -> ObservationResult:
        try:
            result = self._invoke("run_observation", {
                "instance_id": instance_id,
                "command": command,
                "timeout_seconds": timeout_seconds,
            })
            return ObservationResult(
                success=result.get("success", False),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                trust=result.get("trust", "host_reported"),
                exit_code=result.get("exit_code", -1),
                blocked_reason=result.get("blocked_reason"),
            )
        except Exception as exc:
            logger.error(f"ProxyObserveBackend.run_observation failed: {exc}")
            return ObservationResult(
                success=False, stdout="", stderr=str(exc),
                trust="host_reported", exit_code=-1,
                blocked_reason=str(exc),
            )

    def get_metric(
        self, instance_id: str, metric_name: str, period_seconds: int = 300
    ) -> MetricResult:
        try:
            result = self._invoke("get_metric", {
                "instance_id": instance_id,
                "metric_name": metric_name,
                "period_seconds": period_seconds,
            })
            err = result.get("error")
            values = result.get("values")
            unit = result.get("unit", "None")
            if not err and (values == [] or (isinstance(values, list) and len(values) == 0) or unit == "UNAVAILABLE"):
                err = "UNAVAILABLE: no datapoints"
            val = result.get("value")
            val_float = float(val) if val is not None else 0.0
            return MetricResult(
                metric_name=metric_name,
                value=val_float,
                unit=unit,
                period_seconds=period_seconds,
                trust=result.get("trust", "out_of_band"),
                error=err,
            )
        except Exception as exc:
            logger.error(f"ProxyObserveBackend.get_metric failed: {exc}")
            return MetricResult(
                metric_name=metric_name,
                value=0.0,
                unit="None",
                period_seconds=period_seconds,
                trust="out_of_band",
                error=str(exc),
            )

    def get_logs(
        self,
        instance_id: str,
        log_group: str,
        query: str = "",
        minutes_back: int = 30,
    ) -> LogResult:
        try:
            result = self._invoke("get_logs", {
                "instance_id": instance_id,
                "log_group": log_group,
                "query": query,
                "minutes_back": minutes_back,
            })
            return LogResult(
                log_group=log_group,
                entries=result.get("entries", result.get("lines", [])),
                trust=result.get("trust", "host_reported"),
                error=result.get("error"),
            )
        except Exception as exc:
            logger.error(f"ProxyObserveBackend.get_logs failed: {exc}")
            return LogResult(log_group=log_group, entries=[], trust="host_reported", error=str(exc))

    def describe_alarm(self, alarm_name: str) -> AlarmState:
        try:
            result = self._invoke("describe_alarm", {"alarm_name": alarm_name})
            return AlarmState(
                alarm_name=alarm_name,
                state=result.get("state", "INSUFFICIENT_DATA"),
                reason=result.get("reason", ""),
                trust="out_of_band",
            )
        except Exception as exc:
            logger.error(f"ProxyObserveBackend.describe_alarm failed: {exc}")
            return AlarmState(alarm_name=alarm_name, state="UNKNOWN", reason=str(exc), trust="out_of_band")
