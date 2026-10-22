"""
agent/mock_backend.py — Mock Backend for Local Testing

Implements ObserveBackend interface without AWS dependencies.
Returns pre-configured responses for each test scenario.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# ObserveBackend Interface (Read-Only)
# ---------------------------------------------------------------------------

class ObserveBackend(ABC):
    """
    Interface for querying host/CloudWatch telemetry.
    Read-only operations — zero mutations.
    Implemented in production via SSM and CloudWatch APIs.
    Mock implementation provided here for offline scenarios.
    """

    @abstractmethod
    def run_observation(
        self,
        instance_id: str,
        command: str,
        timeout_seconds: int = 30,
    ) -> "ObservationResult":
        """Executes a command on the host (read-only in mock)."""
        ...

    @abstractmethod
    def get_metric(
        self,
        instance_id: str,
        metric_name: str,
        period_seconds: int = 300,
    ) -> "MetricResult":
        """Fetches a metric from CloudWatch."""
        ...

    @abstractmethod
    def get_logs(
        self,
        instance_id: str,
        log_group: str,
        query: str,
        minutes_back: int = 30,
    ) -> "LogResult":
        """Queries CloudWatch Logs."""
        ...

    @abstractmethod
    def describe_alarm(
        self,
        alarm_name: str,
    ) -> "AlarmState":
        """Fetches CloudWatch Alarm state."""
        ...


@dataclass(frozen=True)
class ObservationResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    trust: str = "host_reported"  # Always for host command outputs
    blocked_reason: Optional[str] = None


@dataclass(frozen=True)
class MetricResult:
    metric_name: str
    value: float
    unit: str
    period_seconds: int
    trust: str = "out_of_band"  # EC2 hypervisor metrics
    error: Optional[str] = None


@dataclass(frozen=True)
class LogResult:
    log_group: str
    entries: list[str]
    trust: str = "host_reported"
    error: Optional[str] = None


@dataclass(frozen=True)
class AlarmState:
    alarm_name: str
    state: str  # "ALARM" | "OK" | "INSUFFICIENT_DATA" | "NOT_FOUND" | "UNAVAILABLE"
    reason: str
    trust: str = "out_of_band"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# MockObserveBackend — Pre-configured Scenario Telemetry
# ---------------------------------------------------------------------------

@dataclass
class MockObserveBackend(ObserveBackend):
    """
    Mock returning telemetry based on instance_id and scenario config.

    command_responses: {command_pattern -> ObservationResult}
    metric_responses: {metric_name -> MetricResult}
    log_responses: {log_group -> LogResult}
    alarm_responses: {alarm_name -> AlarmState}

    Also maintains calls_log for verifying invocations in tests.
    """
    command_responses: dict[str, ObservationResult] = field(default_factory=dict)
    metric_responses: dict[str, MetricResult] = field(default_factory=dict)
    log_responses: dict[str, LogResult] = field(default_factory=dict)
    alarm_responses: dict[str, AlarmState] = field(default_factory=dict)
    default_instance_id: str = "i-test001"

    # For audit trail
    _calls: list[dict[str, Any]] = field(default_factory=list)

    def run_observation(
        self,
        instance_id: str,
        command: str,
        timeout_seconds: int = 30,
    ) -> ObservationResult:
        self._calls.append({"type": "observation", "instance_id": instance_id, "command": command})
        # Partial matching against command pattern
        for pattern, result in self.command_responses.items():
            if pattern in command:
                return result
        return ObservationResult(
            success=False,
            stdout="",
            stderr=f"MockBackend: no response configured for command: {command!r}",
            exit_code=1,
        )

    def get_metric(
        self,
        instance_id: str,
        metric_name: str,
        period_seconds: int = 300,
    ) -> MetricResult:
        self._calls.append({"type": "metric", "instance_id": instance_id, "metric": metric_name})
        if metric_name in self.metric_responses:
            return self.metric_responses[metric_name]
        return MetricResult(metric_name=metric_name, value=0.0, unit="None", period_seconds=period_seconds)

    def get_logs(
        self,
        instance_id: str,
        log_group: str,
        query: str,
        minutes_back: int = 30,
    ) -> LogResult:
        self._calls.append({"type": "logs", "instance_id": instance_id, "log_group": log_group})
        if log_group in self.log_responses:
            return self.log_responses[log_group]
        return LogResult(log_group=log_group, entries=[])

    def describe_alarm(self, alarm_name: str) -> AlarmState:
        self._calls.append({"type": "alarm", "alarm_name": alarm_name})
        if alarm_name in self.alarm_responses:
            return self.alarm_responses[alarm_name]
        return AlarmState(alarm_name=alarm_name, state="INSUFFICIENT_DATA", reason="not configured")

    @property
    def calls(self) -> list[dict[str, Any]]:
        return list(self._calls)

    @property
    def observation_calls(self) -> list[dict]:
        return [c for c in self._calls if c["type"] == "observation"]

    @property
    def metric_calls(self) -> list[dict]:
        return [c for c in self._calls if c["type"] == "metric"]

    def reset_calls(self) -> None:
        self._calls.clear()
