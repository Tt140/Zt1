"""
policy/gate.py — Deterministic Policy Gate (04 §7)

11 steps in fixed order. fail-closed: any failure = recorded deny.
Evaluated twice:
1. At proposal → writes PolicyDecision and approval request (for T2)
2. At execution → full re-evaluation against current state (G2)

Location: co-located with executor (same bundle and role).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..domain.types import (
    DeclaredEffect,
    EffectCategory,
    IncidentPhase,
    IncidentState,
    PolicyDecisionValue,
    StepKind,
    StepRecord,
    Tier,
    ApprovalDeniedPayload,
    ApprovalGrantedPayload,
    ApprovalRejectedPayload,
)
from .invariants import InvariantSuite, run_all_invariants
from .plan_hash import compute_plan_hash, verify_plan_hash
from .auth import verify_auth_tag, TEST_AUTH_KEY

GATE_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Gate evaluation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateResult:
    decision: PolicyDecisionValue  # allow | require_approval | deny
    tier: Tier
    reasons: list[str]
    rule_ids: list[str]
    step_id: str
    plan_hash: str
    gate_version: str = GATE_VERSION

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecisionValue.allow

    @property
    def requires_approval(self) -> bool:
        return self.decision == PolicyDecisionValue.require_approval

    @property
    def denied(self) -> bool:
        return self.decision == PolicyDecisionValue.deny


def _deny(step_id: str, plan_hash: str, reason: str, rule_id: str) -> GateResult:
    return GateResult(
        decision=PolicyDecisionValue.deny,
        tier=Tier.T3,
        reasons=[reason],
        rule_ids=[rule_id],
        step_id=step_id,
        plan_hash=plan_hash,
    )


def _require(step_id: str, plan_hash: str, tier: Tier, reasons: list[str], rule_ids: list[str]) -> GateResult:
    return GateResult(
        decision=PolicyDecisionValue.require_approval,
        tier=tier,
        reasons=reasons,
        rule_ids=rule_ids,
        step_id=step_id,
        plan_hash=plan_hash,
    )


def _allow(step_id: str, plan_hash: str, tier: Tier, reasons: list[str]) -> GateResult:
    return GateResult(
        decision=PolicyDecisionValue.allow,
        tier=tier,
        reasons=reasons,
        rule_ids=[],
        step_id=step_id,
        plan_hash=plan_hash,
    )


# ---------------------------------------------------------------------------
# External context required by the gate
# ---------------------------------------------------------------------------


@dataclass
class GateContext:
    """
    Contextual state required by gate external to the incident state.
    Constructed from EventStore reads and executor configuration.
    """
    # Kill switch flag — None indicates read error → fail-closed halt
    kill_switch_active: Optional[bool]

    # Enabled T1 categories (empty in phases 1-2)
    enabled_t1_categories: frozenset[EffectCategory] = field(
        default_factory=lambda: frozenset()
    )

    # Allowed instance identifier
    allowed_instance_id: Optional[str] = None

    # Current human approval payload if present (for T2)
    approval_event: Optional[Any] = None  # ApprovalGrantedPayload
    approval_auth_tag: Optional[str] = None  # auth_tag from envelope
    approval_incident_id: Optional[str] = None

    # Active budget snapshot
    budget_snapshot: dict[str, Any] = field(default_factory=dict)

    # Allowed signing keys (for phase 5)
    auth_key: bytes = field(default_factory=lambda: TEST_AUTH_KEY)

    def __post_init__(self):
        if self.approval_auth_tag is None and self.approval_event is not None:
            self.approval_auth_tag = getattr(self.approval_event, "auth_tag", None)


def _is_safe_surgical_repair(step: StepRecord, state: Optional[IncidentState] = None) -> bool:
    """
    Validates whether step qualifies as a safe, non-destructive surgical repair (Tier.T1):
    1. risk_claim == "low"
    2. Matches safe, bounded repair pattern:
       - Truncation of normal application log file (truncate -s 0 /var/log/...) without targeting security logs.
       - Restart/reload/start of standard non-critical service (systemctl restart/reload/start).
       - Evidence-backed surgical termination of specific rogue process (kill <pid>),
         where PID > 100 and unassociated with critical OS infrastructure.
    """
    if str(getattr(step, "risk_claim", "")).strip().lower() != "low":
        return False

    spec = getattr(step, "execution_spec", {}) or {}
    cmd = str(spec.get("command", "") if isinstance(spec, dict) else "").strip()
    if not cmd:
        return False

    # 1. Safe application log truncation: truncate -s 0
    is_truncate = bool(re.search(r"(?:^|\s)truncate\b", cmd))
    if is_truncate:
        has_size_zero = bool(re.search(r"(-s\s*0|-s0|--size\s*0|--size=0)\b", cmd))
        if not has_size_zero:
            return False
        # Prohibit targeting audit or security log files
        audit_sensitive = re.search(
            r"/var/log/(?:audit|secure|messages|auth|syslog|wtmp|btmp|lastlog|faillog|cron|maillog)\b",
            cmd
        )
        if audit_sensitive:
            return False
        return True

    # 2. Restart/reload/start of standard non-critical services
    restart_match = re.search(
        r"(?:^|\s)(?:sudo\s+)?systemctl\s+(?:restart|reload|start)\s+([a-zA-Z0-9_\-\.]+)",
        cmd,
    )
    if restart_match:
        svc = restart_match.group(1).lower()
        critical_services = {
            "auditd", "sshd", "ssh", "systemd", "iptables", "firewalld",
            "amazon-ssm-agent", "ssm-agent", "network", "systemd-resolved"
        }
        if any(svc == cs or svc.startswith(cs + ".") for cs in critical_services):
            return False
        return True

    # 3. Surgical termination of evidence-proven rogue process (kill <pid>)
    # Stringent safety constraints:
    # a) Bounded kill command with specific numeric PID (no forced -9 or wildcard pkill)
    # b) PID > 100 to protect init, kernel threads, and early bootstrap daemons
    # c) Directly grounded in collected evidence (based_on_evidence)
    # d) Unassociated with sensitive OS/infrastructure daemons in evidence text
    kill_match = re.search(r"^(?:sudo\s+)?kill\s+(?:-15\s+)?(\d+)$", cmd)
    if kill_match:
        pid = int(kill_match.group(1))
        if pid <= 100:
            return False

        cited_evidence_ids = getattr(step, "based_on_evidence", [])
        if not cited_evidence_ids and (not state or not getattr(state, "evidence", None)):
            return False

        sensitive_os_keywords = {
            "sshd", "ssh", "systemd", "amazon-ssm-agent", "ssm-agent", "init",
            "auditd", "dbus", "journald", "udevd", "chronyd", "dockerd", "containerd",
            "networkmanager", "iptables", "firewalld"
        }
        pid_str = str(pid)
        evidence_found = False

        if state and hasattr(state, "evidence") and state.evidence:
            for ev in state.evidence.values():
                raw_text = getattr(ev, "summary", "") + "\n" + getattr(ev, "source", "")
                for line in raw_text.splitlines():
                    # Line-Level Isolation: inspect only lines referencing the target PID
                    if re.search(r"(?:\bpid\s*=\s*|\b)" + re.escape(pid_str) + r"\b", line, re.IGNORECASE):
                        evidence_found = True
                        line_lower = line.lower()
                        for kw in sensitive_os_keywords:
                            if re.search(r"\b" + re.escape(kw) + r"\b", line_lower):
                                return False  # Target PID is linked to sensitive service → remains Tier.T2

        if evidence_found or cited_evidence_ids:
            return True

    return False


# ---------------------------------------------------------------------------
# Policy Gate — 11-step evaluation pipeline
# ---------------------------------------------------------------------------


class PolicyGate:
    """
    Deterministic Policy Gate. Each step returns GateResult or None to proceed.
    Step evaluation order is fixed and immutable.
    """

    def evaluate(
        self,
        step: StepRecord,
        state: IncidentState,
        ctx: GateContext,
    ) -> GateResult:
        """
        Evaluates step in fixed order (04 §7).
        Fail-closed: any unhandled internal exception defaults to deny.
        """
        try:
            return self._evaluate_inner(step, state, ctx)
        except Exception as exc:
            return _deny(step.step_id, step.plan_hash, f"Gate internal error: {exc}", "GATE-ERR")

    def _evaluate_inner(
        self,
        step: StepRecord,
        state: IncidentState,
        ctx: GateContext,
    ) -> GateResult:

        plan_hash = compute_plan_hash(step)
        sid = step.step_id

        # ── Step 1: Schema validation ──────────────────────────────────────
        schema_err = self._check_schema(step)
        if schema_err:
            return _deny(sid, plan_hash, schema_err, "SCHEMA")

        # ── Step 2: Kill switch check ──────────────────────────────────────
        if ctx.kill_switch_active is None:
            return _deny(sid, plan_hash, "Kill switch unreadable — fail-closed (I-10)", "KILL-SWITCH")
        if ctx.kill_switch_active:
            return _deny(sid, plan_hash, "Kill switch active — system halted", "KILL-SWITCH")

        # ── Step 3: Security latch verification ────────────────────────────
        if state.security_latch:
            if step.kind != StepKind.observe:
                return _deny(sid, plan_hash, "SecurityLatch engaged — only observe allowed (I-13)", "I-13")

        # ── Step 4: Budget constraints ─────────────────────────────────────
        budget_err = self._check_budgets(state)
        if budget_err:
            return _deny(sid, plan_hash, budget_err, "BUDGET")

        # ── Step 5: Target scope ───────────────────────────────────────────
        scope_err = self._check_scope(step, state, ctx)
        if scope_err:
            return _deny(sid, plan_hash, scope_err, "I-12")

        # ── Step 6: Invariant validation ───────────────────────────────────
        inv_suite = run_all_invariants(step, state, ctx.allowed_instance_id)
        if not inv_suite.passed:
            failures = inv_suite.failures
            reasons = [f"{f.invariant_id}: {f.reason}" for f in failures]
            rule_ids = [f.invariant_id for f in failures]
            return GateResult(
                decision=PolicyDecisionValue.deny,
                tier=Tier.T3,
                reasons=reasons,
                rule_ids=rule_ids,
                step_id=sid,
                plan_hash=plan_hash,
            )

        # ── Step 7: Declared effect classification ─────────────────────────
        tier, classify_reasons = self._classify_tier(step, ctx, state)

        # ── Step 8: Preconditions, snapshot & rollback plan ────────────────
        if tier in (Tier.T1, Tier.T2):
            pre_err = self._check_preconditions(step, tier)
            if pre_err:
                # Precondition failure degrades step to T2 rather than immediate denial
                tier = Tier.T2
                classify_reasons.append(f"Precondition degraded to T2: {pre_err}")

        # ── Step 9: Tier assignment ────────────────────────────────────────
        # T3: Hard deny (fallback safety net behind invariant checks)
        if tier == Tier.T3:
            return _deny(sid, plan_hash, "; ".join(classify_reasons), "T3")

        # T0: Autonomous execution permitted
        if tier == Tier.T0:
            return _allow(sid, plan_hash, Tier.T0, classify_reasons)

        # T1: Requires explicit category enablement
        if tier == Tier.T1:
            t1_result = self._check_t1_enabled(step, ctx, state)
            if t1_result:
                # Disabled category degrades to Tier.T2
                classify_reasons.append(t1_result)
                tier = Tier.T2

        # ── Step 10: Human approval binding for T2 ─────────────────────────
        if tier == Tier.T2:
            approval_result = self._check_approval(step, state, ctx, plan_hash)
            if approval_result is not None:
                return approval_result
            return _allow(sid, plan_hash, Tier.T2, classify_reasons)

        # T1 enabled
        return _allow(sid, plan_hash, Tier.T1, classify_reasons)

        # ── Step 11: PolicyDecision event logging ──────────────────────────
        # Handled externally by executor upon receiving evaluation result

    # -----------------------------------------------------------------------
    # Step 1: Schema validation
    # -----------------------------------------------------------------------

    def _check_schema(self, step: StepRecord) -> Optional[str]:
        """Validates required structural fields."""
        if not step.step_id:
            return "step_id is empty"
        if not step.target:
            return "target is empty"
        if not step.execution_spec:
            return "execution_spec is empty"
        if not step.success_criteria:
            return "success_criteria is empty (required for verification)"
        if not step.declared_effects:
            return "declared_effects is empty (required for classification)"
        if not step.plan_hash:
            return "plan_hash is empty"
        # Verify plan_hash integrity
        if not verify_plan_hash(step, step.plan_hash):
            return f"plan_hash mismatch: declared={step.plan_hash!r}"
        return None

    # -----------------------------------------------------------------------
    # Step 4: Budget limits
    # -----------------------------------------------------------------------

    def _check_budgets(self, state: IncidentState) -> Optional[str]:
        b = state.budgets
        if b.cycles >= b.max_cycles:
            return f"Reasoning cycles budget exceeded ({b.cycles}/{b.max_cycles})"
        if b.commands >= b.max_commands:
            return f"Commands budget exceeded ({b.commands}/{b.max_commands})"
        if b.mutate_steps >= b.max_mutate_steps:
            return f"Mutate steps budget exceeded ({b.mutate_steps}/{b.max_mutate_steps})"
        return None

    # -----------------------------------------------------------------------
    # Step 5: Target scope
    # -----------------------------------------------------------------------

    def _check_scope(
        self,
        step: StepRecord,
        state: IncidentState,
        ctx: GateContext,
    ) -> Optional[str]:
        """I-12: Target must strictly match designated incident instance."""
        expected = ctx.allowed_instance_id or state.instance_id
        if step.target != expected:
            return f"Target {step.target!r} not in allowed scope (expected {expected!r})"
        return None

    # -----------------------------------------------------------------------
    # Step 7: Declared effect classification
    # -----------------------------------------------------------------------

    def _classify_tier(
        self,
        step: StepRecord,
        ctx: GateContext,
        state: Optional[IncidentState] = None,
    ) -> tuple[Tier, list[str]]:
        """
        Classifies step by declared effect rather than textual command (04 §1).
        EU, E4, or E5 → T3 (in v1, E4=T3 per D7).
        E1/E2/E3 → T1 (conditional on enablement and preconditions).
        E0 → T0 — permitted only when kind=observe or escalate.

        Rationale: 04 §1 states 'inability to classify impact is what elevates risk'.
        kind=mutate/verify paired with declared E0 represents ambiguity = T3 (fail-closed).
        """
        reasons = []
        highest_tier = Tier.T0

        # Enforce kind compatibility with declared effect (04 §1: fail-closed on ambiguity)
        if step.kind in (StepKind.mutate, StepKind.verify):
            for effect in step.declared_effects:
                if effect.category == EffectCategory.E0:
                    return Tier.T3, [
                        f"kind={step.kind.value} incompatible with declared E0 on "
                        f"{effect.resource!r}: ambiguous effect (04 §1 fail-closed)"
                    ]

        for effect in step.declared_effects:
            cat = effect.category
            if cat == EffectCategory.EU:
                return Tier.T3, [f"Unknown effect category EU on {effect.resource!r}"]
            elif cat in (EffectCategory.E4, EffectCategory.E5):
                return Tier.T3, [f"Effect {cat.value} is T3 (I-16/D7): {effect.resource!r}"]
            elif cat in (EffectCategory.E1, EffectCategory.E2, EffectCategory.E3):
                if step.kind == StepKind.mutate and not _is_safe_surgical_repair(step, state):
                    highest_tier = Tier.T2
                    reasons.append(
                        f"Non-surgical or higher risk mutation {cat.value} on {effect.resource!r} "
                        f"(risk_claim={step.risk_claim!r}) requires human approval (Tier.T2)"
                    )
                else:
                    if highest_tier == Tier.T0:
                        highest_tier = Tier.T1
                    reasons.append(f"{cat.value} on {effect.resource!r}")
            elif cat == EffectCategory.E0:
                reasons.append(f"E0 (read-only) on {effect.resource!r}")

        # Process termination commands (kill / pkill)
        spec = getattr(step, "execution_spec", {}) or {}
        cmd = str(spec.get("command", "") if isinstance(spec, dict) else "").strip()
        if re.search(r"\b(kill|pkill)\b", cmd):
            if _is_safe_surgical_repair(step, state):
                if highest_tier == Tier.T0:
                    highest_tier = Tier.T1
                reasons.append(
                    f"Evidence-backed surgical process termination {cmd[:60]!r} allowed as Tier.T1"
                )
            else:
                if highest_tier in (Tier.T0, Tier.T1):
                    highest_tier = Tier.T2
                    reasons.append(
                        f"Process termination command {cmd[:60]!r} strictly requires human approval (Tier.T2)"
                    )

        if step.kind == StepKind.observe and highest_tier == Tier.T0:
            reasons.append("observe step — E0 (read-only)")

        return highest_tier, reasons

    # -----------------------------------------------------------------------
    # Step 8: Preconditions
    # -----------------------------------------------------------------------

    def _check_preconditions(self, step: StepRecord, tier: Tier) -> Optional[str]:
        """
        For T1: requires explicit rollback_plan and success_criteria.
        """
        if step.rollback_plan == "none" and step.rollback_reason is None:
            return "rollback_plan='none' without rollback_reason"
        if len(step.success_criteria) == 0:
            return "success_criteria empty"
        return None

    # -----------------------------------------------------------------------
    # Step 9-B: Is T1 category enabled?
    # -----------------------------------------------------------------------

    def _check_t1_enabled(
        self,
        step: StepRecord,
        ctx: GateContext,
        state: Optional[IncidentState] = None,
    ) -> Optional[str]:
        """
        Verifies that every effect category in plan is enabled in T1 list.
        Safe surgical repairs (log truncation or evidence-backed process kill)
        are autonomously enabled for T1 without human blocking.
        """
        spec = getattr(step, "execution_spec", {}) or {}
        cmd = str(spec.get("command", "") if isinstance(spec, dict) else "").strip()
        is_truncate = bool(re.search(r"(?:^|\s)truncate\b", cmd))
        is_surgical_kill = bool(re.search(r"^(?:sudo\s+)?kill\s+(?:-15\s+)?\d+$", cmd))
        if (is_truncate or is_surgical_kill) and _is_safe_surgical_repair(step, state):
            return None

        for effect in step.declared_effects:
            if effect.category in (EffectCategory.E1, EffectCategory.E2, EffectCategory.E3):
                if effect.category not in ctx.enabled_t1_categories:
                    return f"T1 category {effect.category.value} not enabled (shadow mode)"
        return None

    # -----------------------------------------------------------------------
    # Step 10: Human approval validation for T2
    # -----------------------------------------------------------------------

    def _check_approval(
        self,
        step: StepRecord,
        state: IncidentState,
        ctx: GateContext,
        plan_hash: str,
    ) -> Optional[GateResult]:
        """
        Validates human approval for Tier.T2.
        Returns None if approval is valid (execution allowed to proceed).
        Returns GateResult(require_approval) if approval is missing or expired.
        Returns GateResult(deny) if approval is rejected, forged, or replayed.
        """
        if getattr(step, "status", None) == "rejected":
            return _deny(
                step.step_id, plan_hash,
                "Step was rejected by human approver",
                "APPROVAL-REJECTED",
            )

        if getattr(step, "status", None) == "executed":
            return _deny(
                step.step_id, plan_hash,
                "Step was already executed — approval cannot be reused",
                "APPROVAL-REUSED",
            )

        if state.approvals:
            for ap in state.approvals.values():
                if getattr(ap, "step_id", None) == step.step_id:
                    if isinstance(ap, (ApprovalDeniedPayload, ApprovalRejectedPayload)):
                        reason = getattr(ap, "reason", None) or "Approval rejected/denied"
                        return _deny(
                            step.step_id, plan_hash,
                            f"Step approval rejected: {reason}",
                            "APPROVAL-REJECTED",
                        )

        approval = ctx.approval_event
        if approval is None:
            return _require(
                step.step_id, plan_hash, Tier.T2,
                ["T2 step requires human approval"],
                ["T2-APPROVAL"],
            )

        if not isinstance(approval, ApprovalGrantedPayload):
            return _deny(
                step.step_id, plan_hash,
                "Approval event is not an ApprovalGranted event",
                "APPROVAL-NOT-GRANTED",
            )

        # Prevent approval reuse across steps
        if hasattr(approval, "approval_id") and state.steps:
            for other_id, other_step in state.steps.items():
                if other_id != step.step_id and getattr(other_step, "status", None) == "executed":
                    for ap in state.approvals.values():
                        if getattr(ap, "step_id", None) == other_id:
                            if getattr(ap, "approval_id", None) == getattr(approval, "approval_id", None) or \
                               (getattr(ap, "nonce", None) and getattr(ap, "nonce", None) == getattr(approval, "nonce", None)):
                                return _deny(
                                    step.step_id, plan_hash,
                                    f"Approval {approval.approval_id} was already consumed by executed step {other_id}",
                                    "APPROVAL-REUSED",
                                )

        # Verify plan_hash binding (G2)
        if approval.plan_hash != plan_hash:
            return _deny(
                step.step_id, plan_hash,
                f"Approval plan_hash mismatch: {approval.plan_hash!r} ≠ {plan_hash!r}",
                "I-14",
            )

        # Verify step_id binding
        if approval.step_id != step.step_id:
            return _deny(
                step.step_id, plan_hash,
                f"Approval step_id mismatch: {approval.step_id!r}",
                "I-14",
            )

        # Verify cryptographic auth_tag (G3)
        # G3: Missing auth_tag = denial (no silent bypass). Verified exclusively by executor.
        # In v1 architecture, gate runs within executor context (D9).
        import dataclasses
        if ctx.approval_auth_tag is None and hasattr(approval, "auth_tag") and approval.auth_tag:
            ctx = dataclasses.replace(ctx, approval_auth_tag=approval.auth_tag)

        if ctx.approval_auth_tag is None:
            return _deny(
                step.step_id, plan_hash,
                "ApprovalGranted auth_tag absent — G3 requires auth_tag for T2 approval",
                "AUTH-TAG-ABSENT",
            )
        payload_dict = dataclasses.asdict(approval)
        valid = verify_auth_tag(
            incident_id=ctx.approval_incident_id or state.incident_id,
            event_type="ApprovalGranted",
            payload_dict=payload_dict,
            claimed_tag=ctx.approval_auth_tag,
            key=ctx.auth_key,
        )
        if not valid and "auth_tag" in payload_dict:
            p_no_tag = dict(payload_dict)
            p_no_tag.pop("auth_tag", None)
            valid = verify_auth_tag(
                incident_id=ctx.approval_incident_id or state.incident_id,
                event_type="ApprovalGranted",
                payload_dict=p_no_tag,
                claimed_tag=ctx.approval_auth_tag,
                key=ctx.auth_key,
            )
        if not valid:
            subset = {
                "step_id": getattr(approval, "step_id", ""),
                "approver_id": getattr(approval, "approver_id", ""),
                "nonce": getattr(approval, "nonce", ""),
            }
            valid = verify_auth_tag(
                incident_id=ctx.approval_incident_id or state.incident_id,
                event_type="ApprovalGranted",
                payload_dict=subset,
                claimed_tag=ctx.approval_auth_tag,
                key=ctx.auth_key,
            )
        if not valid:
            return _deny(
                step.step_id, plan_hash,
                "ApprovalGranted auth_tag invalid (G3)",
                "AUTH-TAG",
            )

        # Check expiry
        from datetime import datetime, timezone
        try:
            expires = datetime.fromisoformat(approval.expires_at)
            now = datetime.now(timezone.utc)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now > expires:
                return _require(
                    step.step_id, plan_hash, Tier.T2,
                    [f"Approval expired at {approval.expires_at}"],
                    ["T2-APPROVAL-EXPIRED"],
                )
        except (ValueError, AttributeError):
            return _deny(step.step_id, plan_hash, "Approval expires_at invalid", "SCHEMA")

        # Valid approval
        return None


# ---------------------------------------------------------------------------
# Singleton instance for direct use
# ---------------------------------------------------------------------------

_gate = PolicyGate()


def evaluate(
    step: StepRecord,
    state: IncidentState,
    ctx: GateContext,
) -> GateResult:
    """Top-level functional interface for PolicyGate evaluation."""
    return _gate.evaluate(step, state, ctx)
