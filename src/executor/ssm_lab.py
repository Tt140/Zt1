"""
executor/ssm_lab.py — SSMLab: Production Alternative to DockerLab

Executes restricted operations on EC2 instances via dedicated SSM Documents.
Implements the same interface as DockerLab (run -> LabResult).

ZeroTrust Guarantees:
  1. No arbitrary shell commands — each operation maps to a specific SSM Document.
  2. Parameters are validated prior to dispatch (allowlist derived from docker_lab.py).
  3. If execution fails or success cannot be proven -> UNVERIFIED (no assumed success).
  4. Rollback/Escalation on failure (controlled by ExecutorLoop).
  5. executor Lambda uses STS AssumeRole to acquire SSM permissions;
     agent Lambda never sees these credentials.

Required SSM Documents (created manually/via IaC):
  incidents-observe-readonly:   T0 — read-only observation
  incidents-repair-restricted:  T1 — restricted remediation operations
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from botocore.exceptions import ClientError

from .docker_lab import LabResult, IsolationRequired

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Operation Mapping → SSM Documents
# ─────────────────────────────────────────────────────────────────────────────

# T0: Read-only — observer Lambda
_T0_SSM_DOCUMENT = "incidents-observe-readonly"

# T1: Restricted remediation — executor Lambda (after Policy Gate approval)
_T1_SSM_DOCUMENT = "incidents-repair-restricted"

_T0_ALLOWED_PREFIXES = frozenset([
    "df", "du", "free", "top", "ps", "cat", "head", "tail", "ls", "stat", "find",
    "systemctl status", "systemctl is-active", "systemctl is-failed", "systemctl list-units", "journalctl", "dmesg", "uptime",
    "netstat", "ss", "lsof", "wc", "grep", "curl", "pgrep", "mpstat", "vmstat", "pidstat",
    "echo", "date", "id", "whoami", "uname", "hostname",
])

_T1_ALLOWED_PREFIXES = frozenset([
    "systemctl restart", "systemctl start", "systemctl stop", "systemctl reload",
    "kill", "pkill",
    "rm -f", "truncate", "mv", "cp",
]) | _T0_ALLOWED_PREFIXES

# Maximum wait time for SSM result (seconds)
_SSM_POLL_TIMEOUT  = 120
_SSM_POLL_INTERVAL = 2

# Maximum command output limit (64KB) and intelligent head/tail truncation
_MAX_OUTPUT_BYTES = 64 * 1024
_TRUNCATION_MARKER = "\n... [output truncated] ...\n"


def _truncate_head_tail(text: str, max_chars: int = _MAX_OUTPUT_BYTES) -> str:
    """
    Intelligently truncates text while preserving both head and tail:
    65% from the beginning + explicit delimiter '\n... [output truncated] ...\n' + 35% from the end.
    """
    if not text or len(text) <= max_chars:
        return text

    marker = _TRUNCATION_MARKER
    if max_chars <= len(marker):
        return text[:max_chars]

    available = max_chars - len(marker)
    head_len = int(available * 0.65)
    tail_len = available - head_len

    head = text[:head_len]
    tail = text[-tail_len:] if tail_len > 0 else ""
    return f"{head}{marker}{tail}"


def _command_prefix_allowed(command: str, allowed: frozenset) -> bool:
    cmd = command.strip()
    if cmd.lower().startswith("sudo "):
        cmd = cmd[5:].strip()
    return any(cmd.startswith(p) for p in allowed)


class SSMLab:
    """
    Executes restricted operations via SSM SendCommand on EC2.
    Used in place of DockerLab in AWS production environments.

    fail-closed: Any SSM error or TTL expiration -> LabResult(success=False, verified=False).
    Never reports success unless the outcome is positively verified.
    """

    def __init__(
        self,
        instance_id: str,
        region: str = "us-east-1",
        ssm_role_arn: Optional[str] = None,
        ssm_client=None,
        sts_client=None,
    ):
        """
        ssm_role_arn: If provided, uses STS AssumeRole to acquire SSM credentials
                      (executor Lambda does not hold SSM permissions directly — assumes a scoped role).
        """
        self._instance_id = instance_id
        self._region = region
        self._ssm_role_arn = ssm_role_arn
        self._ssm_client = ssm_client
        self._sts_client = sts_client
        self._assumed_ssm_client = None

    def _get_ssm_client(self):
        """Initializes SSM client, using STS AssumeRole if a role ARN is configured."""
        if self._ssm_client:
            return self._ssm_client

        import boto3

        if self._ssm_role_arn:
            sts = self._sts_client or boto3.client("sts", region_name=self._region)
            creds = sts.assume_role(
                RoleArn=self._ssm_role_arn,
                RoleSessionName="executor-ssm-session",
                DurationSeconds=900,
            )["Credentials"]
            return boto3.client(
                "ssm",
                region_name=self._region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

        return boto3.client("ssm", region_name=self._region)

    @property
    def backend_name(self) -> str:
        return "ssm"

    def run(
        self,
        command: str,
        tier: str = "T0",
        timeout_seconds: int = 60,
    ) -> LabResult:
        """
        Executes command via the SSM Document appropriate for the tier.
        
        T0: observe-readonly document (no mutations)
        T1: repair-restricted document (restricted mutation, requires Gate approval)
        Any other tier -> IsolationRequired (fail-closed)
        """
        if tier == "T0":
            ssm_doc = _T0_SSM_DOCUMENT
            allowed = _T0_ALLOWED_PREFIXES
        elif tier == "T1":
            ssm_doc = _T1_SSM_DOCUMENT
            allowed = _T1_ALLOWED_PREFIXES
        else:
            raise IsolationRequired(
                f"SSMLab: tier={tier!r} not supported. Only T0/T1 allowed."
            )

        # Check prohibited shell operators and special characters (*, ?, |, ;, &&, ||, >, <, ``, $())
        from .docker_lab import _has_shell_operators
        if _has_shell_operators(command):
            reason = f"Forbidden operator or wildcard in command: {command[:60]!r}"
            logger.warning(f"SSMLab: {reason}")
            return LabResult(
                success=False,
                stdout="",
                stderr=reason,
                exit_code=-1,
                elapsed_seconds=0.0,
                blocked_reason=reason,
                verified=False,
                tier=tier,
            )

        # For T1 commands: if command requires root privileges and is not prefixed with sudo, prepend sudo automatically
        if tier == "T1":
            stripped_cmd = command.strip()
            if not stripped_cmd.lower().startswith("sudo "):
                if (
                    stripped_cmd.startswith("systemctl restart")
                    or stripped_cmd.startswith("systemctl start")
                    or stripped_cmd.startswith("systemctl stop")
                    or stripped_cmd.startswith("systemctl reload")
                    or stripped_cmd.startswith("truncate")
                    or stripped_cmd.startswith("kill")
                    or stripped_cmd.startswith("pkill")
                    or stripped_cmd.startswith("mv")
                    or stripped_cmd.startswith("cp")
                    or stripped_cmd.startswith("rm -f")
                ):
                    command = f"sudo {stripped_cmd}"

        # Verify against allowlist prior to dispatch
        if not _command_prefix_allowed(command, allowed):
            reason = f"Command not in {tier} allowlist: {command!r}"
            logger.warning(f"SSMLab: {reason}")
            return LabResult(
                success=False,
                stdout="",
                stderr=reason,
                exit_code=-1,
                elapsed_seconds=0.0,
                blocked_reason=reason,
                verified=False,
                tier=tier,
            )

        ssm = self._get_ssm_client()
        t0  = time.time()

        try:
            send_resp = ssm.send_command(
                InstanceIds=[self._instance_id],
                DocumentName=ssm_doc,
                Parameters={"command": [command]},
                TimeoutSeconds=max(30, timeout_seconds),
                Comment=f"incidents-agent:{tier}",
            )
            command_id = send_resp["Command"]["CommandId"]

        except Exception as exc:
            logger.error(f"SSMLab.run send_command failed: {exc}")
            return LabResult(
                success=False, stdout="", stderr=str(exc),
                exit_code=-1, elapsed_seconds=time.time() - t0,
                verified=False, tier=tier,
            )

        # Poll for command execution result
        res = self._poll_result(ssm, command_id, tier, timeout_seconds, t0)

        # ── Post-Start Active Check: Verify service remains active after starting in T1 ──
        clean_cmd = command.strip()
        if tier == "T1" and res.success:
            is_start_or_restart = (
                "systemctl start " in clean_cmd or "systemctl restart " in clean_cmd
            )
            if is_start_or_restart:
                parts = clean_cmd.split()
                unit = parts[-1] if parts else ""
                if unit and not unit.startswith("-"):
                    time.sleep(1.5)
                    # Check actual service state via T0 (read-only)
                    active_res = self.run(f"systemctl is-active {unit}", tier="T0", timeout_seconds=15)
                    is_active_out = (active_res.stdout or "").strip()
                    if is_active_out != "active":
                        # Service dropped after fork! Extract failure logs
                        log_res = self.run(f"journalctl -u {unit} -n 15 --no-pager", tier="T0", timeout_seconds=15)
                        log_snippet = (log_res.stdout or "").strip()
                        err_msg = f"Service '{unit}' failed to remain active after start (status: {is_active_out}). Logs: {log_snippet}"
                        logger.warning(f"SSMLab: {err_msg}")
                        return LabResult(
                            success=False,
                            stdout=res.stdout,
                            stderr=err_msg,
                            exit_code=1,
                            elapsed_seconds=time.time() - t0,
                            verified=False,
                            tier=tier,
                        )

        return res

    def _poll_result(
        self, ssm, command_id: str, tier: str, timeout_seconds: int,
        t0: float = 0.0,
    ) -> LabResult:
        """Polls until command completes or deadline expires -> fail-closed."""
        if t0 == 0.0:
            t0 = time.time()
        deadline = t0 + min(timeout_seconds, _SSM_POLL_TIMEOUT)

        while time.time() < deadline:
            try:
                resp = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=self._instance_id,
                )
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code == "InvocationDoesNotExist":
                    # SSM race condition: command is still being registered in Fleet Manager.
                    # Treated as Pending/InProgress with retry.
                    logger.debug(
                        f"SSMLab: get_command_invocation returned InvocationDoesNotExist for {command_id}. "
                        "Command is still being registered in SSM. Retrying..."
                    )
                    time.sleep(_SSM_POLL_INTERVAL)
                    continue
                logger.error(f"SSMLab poll error (ClientError): {exc}")
                return LabResult(
                    success=False, stdout="", stderr=str(exc),
                    exit_code=-1, elapsed_seconds=time.time() - t0,
                    verified=False, tier=tier,
                )
            except Exception as exc:
                if "InvocationDoesNotExist" in str(exc):
                    logger.debug(
                        f"SSMLab: InvocationDoesNotExist caught in generic exception for {command_id}. Retrying..."
                    )
                    time.sleep(_SSM_POLL_INTERVAL)
                    continue
                logger.error(f"SSMLab poll error: {exc}")
                return LabResult(
                    success=False, stdout="", stderr=str(exc),
                    exit_code=-1, elapsed_seconds=time.time() - t0,
                    verified=False, tier=tier,
                )

            status = resp.get("Status", "")

            if status == "Success":
                return LabResult(
                    success=True,
                    stdout=_truncate_head_tail(resp.get("StandardOutputContent", "")),
                    stderr=_truncate_head_tail(resp.get("StandardErrorContent", "")),
                    exit_code=0,
                    elapsed_seconds=time.time() - t0,
                    verified=True,
                    tier=tier,
                )
            elif status in ("Failed", "Cancelled", "TimedOut", "Cancelling"):
                resp_code = resp.get("ResponseCode", -1)
                stdout_content = resp.get("StandardOutputContent", "")
                stderr_content = resp.get("StandardErrorContent", status)

                # For T0 observations: query commands such as systemctl status/is-active return exit_code=3 when stopped,
                # or grep returns 1. As long as valid stdout is returned by the system, query is considered successful with stdout forwarded.
                if tier == "T0" and stdout_content.strip() and resp_code in (1, 3):
                    return LabResult(
                        success=True,
                        stdout=_truncate_head_tail(stdout_content),
                        stderr=_truncate_head_tail(stderr_content),
                        exit_code=0,
                        elapsed_seconds=time.time() - t0,
                        verified=True,
                        tier=tier,
                    )

                return LabResult(
                    success=False,
                    stdout=_truncate_head_tail(stdout_content),
                    stderr=_truncate_head_tail(stderr_content),
                    exit_code=resp_code,
                    elapsed_seconds=time.time() - t0,
                    verified=False,
                    tier=tier,
                )

            time.sleep(_SSM_POLL_INTERVAL)

        # Deadline expired — UNVERIFIED
        logger.warning(f"SSMLab: command {command_id} timed out for {tier}")
        return LabResult(
            success=False,
            stdout="",
            stderr=f"SSM command timed out after {timeout_seconds}s",
            exit_code=-1,
            elapsed_seconds=time.time() - t0,
            verified=False,
            tier=tier,
        )
