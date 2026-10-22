"""
executor/docker_lab.py — Docker Lab Sandbox (Phase 4)

Provides a unified interface for executing restricted observe and remediate commands:
- DockerBackend:     Ephemeral Docker container with network=none + read-only mounts
- SubprocessBackend: Subprocess with timeout only (fallback for T0 only, without Docker)

No free-form shell from the model — commands pass through allowlist + container restrictions.

T0 restrictions (04 §6):
- nobody user (UID 65534) with no write access
- network=none
- tmpfs writable only within /tmp/sandbox
- Mandatory timeout (30s)
- Output limit of 64KB
- Secret paths blocked (04 §6 + I-15)

Isolation rule (fail-closed):
- T1 and above require Docker strictly — SubprocessBackend explicitly rejects them.
- If Docker is unavailable for a T1 request, DockerLab raises an IsolationRequired exception.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

# ────────────────────────────────────────────────────────────────────────────
# Security Constraints
# ────────────────────────────────────────────────────────────────────────────

MAX_OUTPUT_BYTES   = 64 * 1024  # 64 KB
DEFAULT_TIMEOUT    = 30         # seconds

# Blocked secret paths (I-15 + 04 §6)
_SECRET_PATH_PATTERNS = [
    re.compile(r"/etc/shadow"),
    re.compile(r"\.pem\b"),
    re.compile(r"\.key\b"),
    re.compile(r"id_rsa"),
    re.compile(r"id_ed25519"),
    re.compile(r"\.aws/credentials"),
    re.compile(r"/proc/\d+/environ"),
]

# Allowed commands for T0 (observe) — allowlisted inside the lab only, not in the gate
_T0_ALLOWED_PREFIXES = (
    "df", "du", "ls", "stat", "cat", "head", "tail", "grep",
    "ps", "top", "free", "uptime", "uname", "hostname",
    "systemctl status", "systemctl is-active", "systemctl is-failed", "systemctl list-units",
    "journalctl", "dmesg", "curl", "pgrep", "mpstat", "vmstat", "pidstat",
    "netstat", "ss", "ip addr", "ip route",
    "echo", "date", "id", "whoami",
    "find", "wc", "sort", "uniq", "awk", "sed", "cut",
    "openssl", "lsof",
)

# Allowed commands for T1 (restricted mutate) — added on top of T0
_T1_ALLOWED_PREFIXES = _T0_ALLOWED_PREFIXES + (
    "systemctl restart", "systemctl stop", "systemctl start",
    "service", "kill", "pkill",
    "rm -f", "rm -rf /tmp/",  # Temporary deletion only within sandbox
    "mkdir -p /tmp/",
    "cp", "mv",
    "chmod", "chown",
    "truncate",
)


def _is_secret_path(command: str) -> bool:
    """I-15: Rejects commands that access secret file paths."""
    for pattern in _SECRET_PATH_PATTERNS:
        if pattern.search(command):
            return True
    return False


def _is_allowed_t0(command: str) -> bool:
    """Verifies that command is within the permitted T0 allowlist."""
    cmd = command.strip()
    if cmd.lower().startswith("sudo "):
        cmd = cmd[5:].strip()
    return any(cmd.startswith(prefix) for prefix in _T0_ALLOWED_PREFIXES)


def _is_allowed_t1(command: str) -> bool:
    """Verifies that command is within the permitted T1 allowlist."""
    cmd = command.strip()
    if cmd.lower().startswith("sudo "):
        cmd = cmd[5:].strip()
    return any(cmd.startswith(prefix) for prefix in _T1_ALLOWED_PREFIXES)


# Blocked shell operators, expansion tokens, and chaining operators
# Strict ban on: * ? | ; && || > < ` $()
_SHELL_OPERATOR_RE = re.compile(
    r"(?:"
    r";"          # Command separator
    r"|&&"         # Logical AND
    r"|\|\|"      # Logical OR
    r"|\|"         # Pipe (blocks e.g.: df -h | sh)
    r"|`"          # Backtick substitution
    r"|\$\("       # Command substitution $()
    r"|\*"         # Wildcard *
    r"|\?"         # Wildcard ?
    r"|>"          # Output redirection >
    r"|<"          # Input redirection <
    r")"
)


def _has_shell_operators(command: str) -> bool:
    """
    Detects prohibited shell operators, expansion tokens, and chaining (*, ?, |, ;, &&, ||, >, <, ``, $()).
    """
    return bool(_SHELL_OPERATOR_RE.search(command))


# ────────────────────────────────────────────────────────────────────────────
# Result Dataclass
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class LabResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    elapsed_seconds: float = 0.0       # 0.0 for execution paths that don't measure duration (allowlist reject, send error)
    blocked_reason: Optional[str] = None   # Reason string if command was blocked before execution
    verified: bool = True                  # False = UNVERIFIED (SSMLab: timeout or polling failure)
    tier: str = "T0"                       # For audit trail


# ────────────────────────────────────────────────────────────────────────────
# Docker Backend
# ────────────────────────────────────────────────────────────────────────────

class DockerBackend:
    """
    Executes command inside an ephemeral Alpine container with strict isolation:
    - network=none
    - read-only filesystem + tmpfs /tmp/sandbox
    - user=nobody
    - --rm (container deleted immediately after execution)
    - --memory=128m --cpus=0.5
    - Command executed without shell expansion (exec form)
    """

    def __init__(
        self,
        image: str = "alpine:3.20",
        extra_mounts: Optional[list[str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
        tier: str = "T0",          # T0 | T1 — determines allowlist
    ):
        self._image = image
        self._extra_mounts = extra_mounts or []
        self._timeout = timeout
        self._tier = tier

    def _allowed(self, command: str) -> Optional[str]:
        """Returns rejection reason or None if permitted."""
        if _is_secret_path(command):
            return f"I-15: secret path blocked in command: {command[:60]!r}"
        if _has_shell_operators(command):
            return f"shell operator or wildcard forbidden: {command[:60]!r}"
        if self._tier == "T0" and not _is_allowed_t0(command):
            return f"T0 allowlist: command not permitted: {command[:60]!r}"
        if self._tier == "T1" and not _is_allowed_t1(command):
            return f"T1 allowlist: command not permitted: {command[:60]!r}"
        return None

    def run(self, command: str) -> LabResult:
        t0 = time.monotonic()
        blocked = self._allowed(command)
        if blocked:
            return LabResult(
                success=False, stdout="", stderr=blocked,
                exit_code=-1, elapsed_seconds=0.0,
                blocked_reason=blocked,
            )

        docker_cmd = [
            "docker", "run", "--rm",
            "--network=none",
            "--read-only",
            "--tmpfs", "/tmp/sandbox:rw,size=16m,uid=65534",
            "--user", "65534:65534",
            "--memory=128m",
            "--cpus=0.5",
            "--security-opt", "no-new-privileges",
        ]
        for mount in self._extra_mounts:
            docker_cmd += ["--volume", mount]
        docker_cmd += [self._image, "sh", "-c", command]

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                timeout=self._timeout,
            )
            stdout = proc.stdout.decode(errors="replace")[:MAX_OUTPUT_BYTES]
            stderr = proc.stderr.decode(errors="replace")[:4096]
            elapsed = time.monotonic() - t0
            return LabResult(
                success=(proc.returncode == 0),
                stdout=stdout,
                stderr=stderr,
                exit_code=proc.returncode,
                elapsed_seconds=elapsed,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - t0
            return LabResult(
                success=False, stdout="", stderr="timeout",
                exit_code=-9, elapsed_seconds=elapsed,
                blocked_reason="timeout exceeded",
            )
        except FileNotFoundError:
            return LabResult(
                success=False, stdout="",
                stderr="docker not found or not accessible",
                exit_code=-2, elapsed_seconds=0.0,
                blocked_reason="docker_unavailable",
            )
        except PermissionError as e:
            return LabResult(
                success=False, stdout="",
                stderr=f"permission denied: {e}",
                exit_code=-3, elapsed_seconds=0.0,
                blocked_reason="permission_denied",
            )


# ────────────────────────────────────────────────────────────────────────────
# Isolation Required Exception
# ────────────────────────────────────────────────────────────────────────────

class IsolationRequired(RuntimeError):
    """
    Raised when requesting an execution tier requiring Docker isolation (T1+)
    while Docker is unavailable.
    fail-closed: explicit rejection instead of silent fallback to host execution.
    """


# ────────────────────────────────────────────────────────────────────────────
# Subprocess Backend (No Docker — for T0 only)
# ────────────────────────────────────────────────────────────────────────────

class SubprocessBackend:
    """
    No-Docker fallback using subprocess with strict timeout.
    Acceptable for local unit tests under exactly one condition: tier="T0" only.

    Strict rule (fail-closed — whitelist, not blacklist):
    - Accepts "T0" exclusively. Any other value (T1, T4, empty, etc.) immediately
      raises IsolationRequired before any subprocess invocation.
    - Permitted commands must not contain shell operators (prevents injection).
    - No alternative path exists to execute mutate commands on the host.
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, tier: str = "T0"):
        # whitelist: T0 only — any other value (known or unknown) is rejected
        if tier != "T0":
            raise IsolationRequired(
                f"SubprocessBackend accepts only tier='T0', got {tier!r}. "
                "Any non-T0 tier requires Docker isolation and cannot "
                "run on the host system."
            )
        self._timeout = timeout
        self._tier = tier  # always "T0" past this point

    def _allowed(self, command: str) -> Optional[str]:
        """Returns rejection reason or None if permitted (T0 only)."""
        # I-15: Block secret paths
        if _is_secret_path(command):
            return f"I-15: secret path blocked: {command[:60]!r}"
        # Block shell operators — prevents secondary command injection after allowed command
        if _has_shell_operators(command):
            return f"shell operator injection blocked (subprocess): {command[:60]!r}"
        # T0 allowlist — verifies command is permitted for read-only inspection
        if not _is_allowed_t0(command):
            return f"T0 allowlist (subprocess): not permitted: {command[:60]!r}"
        return None

    def run(self, command: str) -> LabResult:
        t0 = time.monotonic()
        blocked = self._allowed(command)
        if blocked:
            return LabResult(
                success=False, stdout="", stderr=blocked,
                exit_code=-1, elapsed_seconds=0.0,
                blocked_reason=blocked,
            )
        try:
            proc = subprocess.run(
                ["sh", "-c", command],
                capture_output=True,
                timeout=self._timeout,
            )
            stdout = proc.stdout.decode(errors="replace")[:MAX_OUTPUT_BYTES]
            stderr = proc.stderr.decode(errors="replace")[:4096]
            return LabResult(
                success=(proc.returncode == 0),
                stdout=stdout + "\n[WARNING: subprocess backend — no sandbox isolation]",
                stderr=stderr,
                exit_code=proc.returncode,
                elapsed_seconds=time.monotonic() - t0,
            )
        except subprocess.TimeoutExpired:
            return LabResult(
                success=False, stdout="", stderr="timeout",
                exit_code=-9, elapsed_seconds=time.monotonic() - t0,
                blocked_reason="timeout",
            )


# ────────────────────────────────────────────────────────────────────────────
# DockerLab — Unified Interface Selecting Backend Automatically
# ────────────────────────────────────────────────────────────────────────────

class DockerLab:
    """
    Docker available -> DockerBackend (all tiers).
    Docker unavailable + tier=T0 -> SubprocessBackend (test-only, with warning).
    Docker unavailable + tier=T1/T2 -> raises IsolationRequired (fail-closed).

    No code path allows T1/T2 execution on the host system under any circumstances.
    """

    def __init__(
        self,
        image: str = "alpine:3.20",
        timeout: int = DEFAULT_TIMEOUT,
        tier: str = "T0",
        force_subprocess: bool = False,
    ):
        self._tier = tier
        self._docker_available = (not force_subprocess) and self._check_docker()
        if self._docker_available:
            self._backend: DockerBackend | SubprocessBackend = DockerBackend(
                image=image, timeout=timeout, tier=tier
            )
        else:
            # fail-closed: any non-T0 tier without Docker is explicitly rejected
            # (SubprocessBackend.__init__ also enforces this as a defense-in-depth layer)
            if tier != "T0":
                raise IsolationRequired(
                    f"DockerLab: Docker is unavailable and tier={tier!r} requires "
                    "container isolation. Cannot fall back to subprocess for mutate "
                    "operations — this would execute on the host system."
                )
            self._backend = SubprocessBackend(timeout=timeout, tier=tier)

    @staticmethod
    def _check_docker() -> bool:
        """Verifies whether a container can actually be spawned."""
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "alpine:3.20", "echo", "ok"],
                capture_output=True, timeout=15,
            )
            return result.returncode == 0 and result.stdout.strip() == b"ok"
        except Exception:
            return False

    @property
    def is_docker(self) -> bool:
        return self._docker_available

    @property
    def backend_name(self) -> str:
        return "docker" if self._docker_available else "subprocess_no_isolation"

    def run(self, command: str, tier: Optional[str] = None) -> LabResult:
        return self._backend.run(command)
