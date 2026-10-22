"""
tests/conftest_phase4.py — Fixtures for Phase 4 test suite.

Provides controlled mock backends for testing.
"""
from src.executor.docker_lab import LabResult


class AlwaysFailLab:
    """Lab that always fails — for testing rollback path."""

    @property
    def is_docker(self):
        return False

    @property
    def backend_name(self):
        return "always_fail_mock"

    def run(self, command: str) -> LabResult:
        return LabResult(
            success=False,
            stdout="",
            stderr=f"AlwaysFailLab: forced failure for command {command!r}",
            exit_code=1,
            elapsed_seconds=0.01,
            blocked_reason=None,
        )


class AlwaysSucceedLab:
    """Lab that always succeeds — for validating success path without Docker."""

    @property
    def is_docker(self):
        return False

    @property
    def backend_name(self):
        return "always_succeed_mock"

    def run(self, command: str) -> LabResult:
        return LabResult(
            success=True,
            stdout=f"mock output for: {command}\n",
            stderr="",
            exit_code=0,
            elapsed_seconds=0.01,
            blocked_reason=None,
        )
