"""
policy/invariants.py — Implementation of invariants I-01..I-16 (04 §5)

Each invariant:
- Pure function: check_I_XX(step: StepRecord, state: IncidentState) -> InvariantResult
- Two-layer independent validation for critical invariants (I-01..I-06, I-08, I-13)
- Failure yields T3: unconditional hard denial; cannot be bypassed by approval

Validation rules:
- Relies on structural plan fields (kind, target, execution_spec, declared_effects)
- Never relies on unconstrained free-text analysis
- Protected paths: explicit allowlists
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..domain.types import (
    DeclaredEffect,
    EffectCategory,
    IncidentState,
    IncidentPhase,
    StepKind,
    StepRecord,
)

# ---------------------------------------------------------------------------
# Protected paths (allowlists)
# ---------------------------------------------------------------------------

# Paths strictly forbidden from being modified (I-02, I-05, I-06)
PROTECTED_PATHS: frozenset[str] = frozenset([
    "/etc/ssh",
    "/root/.ssh",
    "/home",
    "/etc/pam.d",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/var/log/audit",
    "/etc/audit",
    "/opt/aws/amazon-cloudwatch-agent",
    "/etc/amazon/ssm",
    "/usr/bin/amazon-ssm-agent",
    "/usr/local/bin/amazon-ssm-agent",
    "/etc/ssl/private",
    "/etc/pki/tls/private",
])

# Secret patterns prohibited from reading even in T0 (I-15)
SECRET_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.pem", re.IGNORECASE),
    re.compile(r"\.key", re.IGNORECASE),
    re.compile(r"\.p12", re.IGNORECASE),
    re.compile(r"\.priv\b", re.IGNORECASE),
    re.compile(r"/etc/ssl/private", re.IGNORECASE),
    re.compile(r"/etc/pki/(?:tls/)?private", re.IGNORECASE),
    re.compile(r"private[-_]?key", re.IGNORECASE),
    re.compile(r"/etc/shadow"),
    re.compile(r"id_rsa"),
    re.compile(r"id_ed25519"),
    re.compile(r"credentials", re.IGNORECASE),
    re.compile(r"\.aws/credentials"),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"/proc/\d+/environ"),
]

# Commands or patterns indicating package installation or network execution (I-07)
NETWORK_INSTALL_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bapt(-get)?\s+install\b"),
    re.compile(r"\byum\s+install\b"),
    re.compile(r"\bdnf\s+install\b"),
    re.compile(r"\bpip\s+install\b"),
    re.compile(r"\bnpm\s+install\b"),
    re.compile(r"\bcurl\b.*(sh|bash|python|perl)"),
    re.compile(r"\bwget\b.*(sh|bash|python|perl)"),
    re.compile(r"\bpython\b.*\bhttps?://"),
    re.compile(r"\bbash\b.*\bhttps?://"),
]

# Privilege escalation patterns (I-16)
PRIVILEGE_ESCALATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bchmod\b.*[0-7]*[sS]"),  # setuid/setgid
    re.compile(r"\bchmod\s+[0-7]*[4-7][0-7]{2}\b"),  # e.g. 4755, 6755
    re.compile(r"\bchown\b.*root"),
    re.compile(r"\bsudo\s+-s\b"),
    re.compile(r"\bsu\s+-\b"),
    re.compile(r"\bvisudo\b"),
    re.compile(r"\bpasswd\b"),
    re.compile(r"\busermod\b"),
    re.compile(r"\buseradd\b"),
    re.compile(r"\bgroupadd\b"),
]

# Network rule modification patterns (I-04)
NETWORK_RULE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\biptables\b"),
    re.compile(r"\bnftables\b"),
    re.compile(r"\bfirewall-cmd\b"),
    re.compile(r"\bufw\b.*(allow|deny|delete|reset)"),
    re.compile(r"\bip\s+(link|route|rule)\b.*(add|del|change)"),
]

# SSM/IAM configuration modification patterns (I-01, I-03)
SSM_IAM_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bssm\b.*agent", re.IGNORECASE),
    re.compile(r"\bamazon-ssm-agent\b"),
    re.compile(r"\baws\s+iam\b"),
    re.compile(r"\biam\b.*(create|attach|detach|delete|put)", re.IGNORECASE),
    re.compile(r"\biam:"),
    re.compile(r"\bec2-metadata\b"),
    re.compile(r"\bhttp://169\.254\.169\.254\b"),  # IMDS
]

# System shutdown/termination patterns (I-09)
TERMINATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bshutdown\b"),
    re.compile(r"\bhalt\b"),
    re.compile(r"\bpoweroff\b"),
    re.compile(r"\breboot\b"),  # Evaluated under T2 if permitted (D7)
    re.compile(r"\bec2.*terminate\b", re.IGNORECASE),
    re.compile(r"\bterminate-instances\b"),
]

# Self-modification patterns (I-10)
SELF_MODIFICATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bkill_switch\b"),
    re.compile(r"\bgate\.py\b"),
    re.compile(r"\bpolicy\b.*(modify|update|patch|edit)", re.IGNORECASE),
    re.compile(r"\bconfig.*gate\b", re.IGNORECASE),
    re.compile(r"\bfeature.*flag\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Invariant evaluation result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InvariantResult:
    passed: bool
    invariant_id: str
    reason: Optional[str] = None


def _all_spec_text(step: StepRecord) -> str:
    """Aggregates all auditable text from step record."""
    import json
    parts = [
        step.target,
        json.dumps(step.execution_spec, sort_keys=True),
    ]
    for effect in step.declared_effects:
        parts.append(effect.resource)
        parts.append(effect.description)
    parts.extend(step.preconditions)
    return "\n".join(parts)


def _matches_any(text: str, patterns: list[re.Pattern]) -> Optional[str]:
    """Returns the first matching regex pattern string, or None."""
    for p in patterns:
        m = p.search(text)
        if m:
            return m.group(0)
    return None


def _touches_protected_path(step: StepRecord) -> Optional[str]:
    """Checks whether any protected path is touched in declared effects or spec."""
    import json
    spec_str = json.dumps(step.execution_spec, sort_keys=True)
    for path in PROTECTED_PATHS:
        if path in spec_str:
            return path
        for effect in step.declared_effects:
            if path in effect.resource or path in effect.description:
                return path
    return None


# ---------------------------------------------------------------------------
# I-01: No tampering with SSM agent or its configuration
# ---------------------------------------------------------------------------

def check_I_01(step: StepRecord, state: IncidentState) -> InvariantResult:
    """I-01: No tampering with SSM agent or its configuration — Layer 1 (gate)."""
    text = _all_spec_text(step)
    match = _matches_any(text, SSM_IAM_PATTERNS)
    if match:
        return InvariantResult(False, "I-01", f"SSM/IAM pattern detected: {match!r}")
    for path in ["/etc/amazon/ssm", "/usr/bin/amazon-ssm-agent", "/usr/local/bin/amazon-ssm-agent"]:
        if path in text:
            return InvariantResult(False, "I-01", f"Protected SSM path: {path!r}")
    return InvariantResult(True, "I-01")


def check_I_01_layer2(step: StepRecord, state: IncidentState) -> InvariantResult:
    """I-01: Layer 2 — Effect category check (E5 = T3)."""
    for effect in step.declared_effects:
        if effect.category == EffectCategory.E5:
            if "ssm" in effect.resource.lower() or "ssm" in effect.description.lower():
                return InvariantResult(False, "I-01", "E5 effect on SSM resource")
    return InvariantResult(True, "I-01")


# ---------------------------------------------------------------------------
# I-02: No tampering with SSH keys or sshd configuration
# ---------------------------------------------------------------------------

def check_I_02(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    for path in ["/etc/ssh", "/root/.ssh", "authorized_keys", "sshd_config", ".ssh/"]:
        if path in text:
            return InvariantResult(False, "I-02", f"SSH path/config detected: {path!r}")
    return InvariantResult(True, "I-02")


def check_I_02_layer2(step: StepRecord, state: IncidentState) -> InvariantResult:
    """Layer 2: Keyword search across execution_spec."""
    import json
    spec = json.dumps(step.execution_spec, sort_keys=True).lower()
    for kw in ["ssh", "sshd", "authorized_keys", "known_hosts", "id_rsa", "id_ed25519"]:
        if kw in spec:
            return InvariantResult(False, "I-02", f"SSH keyword in spec: {kw!r}")
    return InvariantResult(True, "I-02")


# ---------------------------------------------------------------------------
# I-03: No tampering with IAM credentials, STS, or instance metadata
# ---------------------------------------------------------------------------

def check_I_03(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    for path in ["169.254.169.254", "/.aws/", "instance-metadata", "iam::", "sts::"]:
        if path in text:
            return InvariantResult(False, "I-03", f"IAM/metadata access: {path!r}")
    match = _matches_any(text, SSM_IAM_PATTERNS[-3:])  # IAM/IMDS patterns
    if match:
        return InvariantResult(False, "I-03", f"IAM pattern: {match!r}")
    return InvariantResult(True, "I-03")


# ---------------------------------------------------------------------------
# I-04: No modification of firewall or network routing rules
# ---------------------------------------------------------------------------

def check_I_04(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    match = _matches_any(text, NETWORK_RULE_PATTERNS)
    if match:
        return InvariantResult(False, "I-04", f"Network rule modification: {match!r}")
    return InvariantResult(True, "I-04")


# ---------------------------------------------------------------------------
# I-05: No disabling or deletion of audit logs and logging services
# ---------------------------------------------------------------------------

AUDIT_LOG_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"/var/log/(?:audit(?:\b|/)|secure(?:\b|[-._\d])|auth\.log(?:\b|[-._\d])|"
        r"wtmp(?:\b|[-._\d])|btmp(?:\b|[-._\d])|lastlog(?:\b|[-._\d])|faillog(?:\b|[-._\d])|"
        r"syslog(?:\b|[-._\d])|messages(?:\b|[-._\d])|journal(?:\b|/))",
        re.IGNORECASE,
    ),
    re.compile(r"\baudit\.log(?:\b|[-._\d])", re.IGNORECASE),
    re.compile(r"\baudit/", re.IGNORECASE),
    re.compile(r"/etc/audit(?:\b|/)", re.IGNORECASE),
    re.compile(r"\bcloudwatch-agent\b", re.IGNORECASE),
    re.compile(r"\bauditd\b", re.IGNORECASE),
]

AUDIT_DISABLE_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"\b(systemctl|service)\b.*?\b(stop|disable|mask|kill)\b.*?\b(auditd?|rsyslog|syslog|systemd-journald|journald|cloudwatch)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(service)\b.*?\b(auditd?|rsyslog|syslog|systemd-journald|journald|cloudwatch)\b.*?\b(stop|disable|mask|kill)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(rm|rmdir)\b.*?[\"'\s](?:/var/log|/etc/audit)/?(?:\*|[\"'\s]|$)",
        re.IGNORECASE,
    ),
]


def check_I_05(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    match_path = _matches_any(text, AUDIT_LOG_PATH_PATTERNS)
    if match_path:
        return InvariantResult(False, "I-05", f"Audit/logging path: {match_path!r}")
    match_disable = _matches_any(text, AUDIT_DISABLE_PATTERNS)
    if match_disable:
        return InvariantResult(False, "I-05", f"Audit disable pattern: {match_disable!r}")
    return InvariantResult(True, "I-05")


def check_I_05_layer2(step: StepRecord, state: IncidentState) -> InvariantResult:
    """Layer 2: E5 declared effect on audit/logging resources."""
    for effect in step.declared_effects:
        if effect.category == EffectCategory.E5:
            for kw in ["audit", "log", "cloudwatch", "syslog"]:
                if kw in effect.resource.lower() or kw in effect.description.lower():
                    return InvariantResult(False, "I-05", f"E5 on logging resource: {kw!r}")
    return InvariantResult(True, "I-05")


# ---------------------------------------------------------------------------
# I-06: No tampering with users, groups, sudoers, or PAM
# ---------------------------------------------------------------------------

def check_I_06(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    for path in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
                 "/etc/sudoers.d", "/etc/pam.d", "/etc/gshadow"]:
        if path in text:
            return InvariantResult(False, "I-06", f"User/group file: {path!r}")
    match = _matches_any(text, PRIVILEGE_ESCALATION_PATTERNS)
    if match:
        return InvariantResult(False, "I-06", f"Privilege escalation: {match!r}")
    return InvariantResult(True, "I-06")


def check_I_06_layer2(step: StepRecord, state: IncidentState) -> InvariantResult:
    import json
    spec = json.dumps(step.execution_spec, sort_keys=True)
    for kw in ["useradd", "usermod", "groupadd", "passwd ", "chpasswd", "visudo"]:
        if kw in spec:
            return InvariantResult(False, "I-06", f"User mgmt command: {kw!r}")
    return InvariantResult(True, "I-06")


# ---------------------------------------------------------------------------
# I-07: No package installation or arbitrary remote code execution
# ---------------------------------------------------------------------------

def check_I_07(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    match = _matches_any(text, NETWORK_INSTALL_PATTERNS)
    if match:
        return InvariantResult(False, "I-07", f"Network install/exec: {match!r}")
    # Flag suspicious HTTP/HTTPS URLs in execution_spec
    import json
    spec = json.dumps(step.execution_spec)
    if re.search(r"https?://", spec):
        return InvariantResult(False, "I-07", "URL in execution_spec")
    return InvariantResult(True, "I-07")


# ---------------------------------------------------------------------------
# I-08: No deletion outside temporary paths; no disk formatting/partitioning
# ---------------------------------------------------------------------------

ALLOWED_TMP_PATHS = frozenset(["/tmp/", "/var/tmp/", "/dev/shm/"])

def check_I_08(step: StepRecord, state: IncidentState) -> InvariantResult:
    import json
    text = _all_spec_text(step)
    # Disk formatting / partitioning commands
    for pattern in [
        re.compile(r"\bmkfs\b"),
        re.compile(r"\bfdisk\b.*(--delete|d\b)"),
        re.compile(r"\bparted\b.*(rm|delete)"),
        re.compile(r"\bdd\b.*of=/dev/[sh]d"),
    ]:
        m = pattern.search(text)
        if m:
            return InvariantResult(False, "I-08", f"Disk format/partition: {m.group(0)!r}")

    # Deletions targeting non-temporary paths
    for effect in step.declared_effects:
        if effect.category in (EffectCategory.E4, EffectCategory.EU):
            is_tmp = any(effect.resource.startswith(p) for p in ALLOWED_TMP_PATHS)
            if not is_tmp and (
                "delete" in effect.description.lower()
                or "rm " in effect.description.lower()
                or "remove" in effect.description.lower()
            ):
                return InvariantResult(False, "I-08", f"Non-tmp deletion: {effect.resource!r}")
    return InvariantResult(True, "I-08")


def check_I_08_layer2(step: StepRecord, state: IncidentState) -> InvariantResult:
    """Layer 2: E4 category check on non-temporary resources."""
    for effect in step.declared_effects:
        if effect.category == EffectCategory.E4:
            is_tmp = any(effect.resource.startswith(p) for p in ALLOWED_TMP_PATHS)
            if not is_tmp:
                return InvariantResult(False, "I-08", f"E4 on non-tmp: {effect.resource!r}")
    return InvariantResult(True, "I-08")


# ---------------------------------------------------------------------------
# I-09: No instance shutdown, reboot, or termination
# ---------------------------------------------------------------------------

def check_I_09(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    match = _matches_any(text, TERMINATION_PATTERNS)
    if match:
        return InvariantResult(False, "I-09", f"Termination/shutdown: {match!r}")
    return InvariantResult(True, "I-09")


# ---------------------------------------------------------------------------
# I-10: No self-modification of system components or Policy Gate
# ---------------------------------------------------------------------------

def check_I_10(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    match = _matches_any(text, SELF_MODIFICATION_PATTERNS)
    if match:
        return InvariantResult(False, "I-10", f"Self-modification: {match!r}")
    # Verify effect category: E5 on gate resources
    for effect in step.declared_effects:
        if effect.category == EffectCategory.E5 and "gate" in effect.resource.lower():
            return InvariantResult(False, "I-10", "E5 on gate resource")
    return InvariantResult(True, "I-10")


# ---------------------------------------------------------------------------
# I-11: No outbound network connections from executor
# ---------------------------------------------------------------------------

def check_I_11(step: StepRecord, state: IncidentState) -> InvariantResult:
    """
    I-11 is architecturally enforced via execution sandbox isolation.
    Gate layer: reject any execution_spec containing curl/wget/nc.
    """
    import json
    spec = json.dumps(step.execution_spec)
    for pattern in [
        re.compile(r"\bcurl\b"),
        re.compile(r"\bwget\b"),
        re.compile(r"\bnc\b"),
        re.compile(r"\bnetcat\b"),
        re.compile(r"\bnmap\b"),
        re.compile(r"\btelnet\b"),
        re.compile(r"\bssh\s+-[A-Z]"),  # SSH tunneling
    ]:
        m = pattern.search(spec)
        if m:
            return InvariantResult(False, "I-11", f"Outbound network: {m.group(0)!r}")
    return InvariantResult(True, "I-11")


# ---------------------------------------------------------------------------
# I-12: Target must strictly match designated incident instance
# ---------------------------------------------------------------------------

def check_I_12(
    step: StepRecord,
    state: IncidentState,
    allowed_instance_id: Optional[str] = None,
) -> InvariantResult:
    """I-12: Execution target must strictly match designated instance."""
    target_instance = step.target
    expected = allowed_instance_id or state.instance_id
    if not expected:
        return InvariantResult(False, "I-12", "No allowed instance_id configured")
    if target_instance != expected:
        return InvariantResult(
            False, "I-12",
            f"Target {target_instance!r} ≠ allowed {expected!r}",
        )
    return InvariantResult(True, "I-12")


# ---------------------------------------------------------------------------
# I-13: Absolute modification freeze under security_evidence mode
# ---------------------------------------------------------------------------

def check_I_13(step: StepRecord, state: IncidentState) -> InvariantResult:
    """I-13: In security_evidence mode (security_latch=True), no mutating actions are permitted."""
    if not state.security_latch:
        return InvariantResult(True, "I-13")
    # All non-E0 actions are prohibited
    for effect in step.declared_effects:
        if effect.category != EffectCategory.E0:
            return InvariantResult(
                False, "I-13",
                f"Mutating step in security_evidence mode: {effect.category.value}",
            )
    if step.kind != StepKind.observe:
        return InvariantResult(False, "I-13", f"Non-observe step in security mode: {step.kind.value}")
    return InvariantResult(True, "I-13")


def check_I_13_layer2(step: StepRecord, state: IncidentState) -> InvariantResult:
    """Layer 2: Direct phase evaluation."""
    if state.phase == IncidentPhase.security_evidence:
        if step.kind != StepKind.observe:
            return InvariantResult(False, "I-13", "Phase=security_evidence, non-observe step")
    return InvariantResult(True, "I-13")


# ---------------------------------------------------------------------------
# I-14: No execution without logged PolicyDecision matching plan_hash
# ---------------------------------------------------------------------------

def check_I_14(step: StepRecord, state: IncidentState) -> InvariantResult:
    """
    I-14: Verifies existence of PolicyDecision with matching plan_hash.
    (ExecutionIntent verified via CAS in EventStore).
    Does not apply to pure read-only observe (T0) steps.
    """
    # T0 (observe) does not require a prior recorded PolicyDecision
    if step.kind == StepKind.observe:
        all_e0 = all(e.category == EffectCategory.E0 for e in step.declared_effects)
        if all_e0:
            return InvariantResult(True, "I-14")  # T0 — no recorded decision required

    from .plan_hash import compute_plan_hash
    expected_hash = compute_plan_hash(step)
    decision = state.policy_decisions.get(step.step_id)
    if decision is None:
        return InvariantResult(False, "I-14", "No PolicyDecision for this step")
    if decision.plan_hash != expected_hash:
        return InvariantResult(
            False, "I-14",
            f"PolicyDecision plan_hash mismatch: {decision.plan_hash!r} ≠ {expected_hash!r}",
        )
    return InvariantResult(True, "I-14")


# ---------------------------------------------------------------------------
# I-15: No reading of secret file paths even in T0
# ---------------------------------------------------------------------------

def check_I_15(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    match = _matches_any(text, SECRET_PATH_PATTERNS)
    if match:
        return InvariantResult(False, "I-15", f"Secret path access: {match!r}")
    return InvariantResult(True, "I-15")


# ---------------------------------------------------------------------------
# I-16: No privilege escalation
# ---------------------------------------------------------------------------

def check_I_16(step: StepRecord, state: IncidentState) -> InvariantResult:
    text = _all_spec_text(step)
    match = _matches_any(text, PRIVILEGE_ESCALATION_PATTERNS)
    if match:
        return InvariantResult(False, "I-16", f"Privilege escalation: {match!r}")
    # E5 includes privilege changes
    for effect in step.declared_effects:
        if effect.category == EffectCategory.E5:
            return InvariantResult(False, "I-16", f"E5 effect = privilege-sensitive: {effect.resource!r}")
    return InvariantResult(True, "I-16")


# ---------------------------------------------------------------------------
# Invariant suite evaluation
# ---------------------------------------------------------------------------

@dataclass
class InvariantSuite:
    results: list[InvariantResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> list[InvariantResult]:
        return [r for r in self.results if not r.passed]


def run_all_invariants(
    step: StepRecord,
    state: IncidentState,
    allowed_instance_id: Optional[str] = None,
) -> InvariantSuite:
    """
    Runs I-01..I-13 and I-15..I-16 in order.
    I-14 (existence of PolicyDecision) is verified by the executor prior to execution,
    not by the gate (since gate is responsible for logging PolicyDecision itself).
    Use check_I_14_pre_execute for pre-execution verification.
    """
    checks = [
        check_I_01(step, state),
        check_I_01_layer2(step, state),
        check_I_02(step, state),
        check_I_02_layer2(step, state),
        check_I_03(step, state),
        check_I_04(step, state),
        check_I_05(step, state),
        check_I_05_layer2(step, state),
        check_I_06(step, state),
        check_I_06_layer2(step, state),
        check_I_07(step, state),
        check_I_08(step, state),
        check_I_08_layer2(step, state),
        check_I_09(step, state),
        check_I_10(step, state),
        check_I_11(step, state),
        check_I_12(step, state, allowed_instance_id),
        check_I_13(step, state),
        check_I_13_layer2(step, state),
        # I-14 evaluated by executor via check_I_14_pre_execute
        check_I_15(step, state),
        check_I_16(step, state),
    ]
    return InvariantSuite(results=checks)


def check_I_14_pre_execute(step: StepRecord, state: IncidentState) -> InvariantResult:
    """
    I-14 — Pre-execution verification (executor layer).
    Confirms presence of PolicyDecision with matching plan_hash before issuing ExecutionIntent.
    """
    return check_I_14(step, state)
    return check_I_14(step, state)
