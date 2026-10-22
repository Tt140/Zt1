"""
tests/policy/conftest.py — Shared fixtures for policy tests
"""
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from src.domain import (
    Actor, EventType, IncidentPhase, EffectCategory, Tier, StepKind,
    IncidentState, BudgetState, StepRecord, DeclaredEffect,
    IncidentOpenedPayload, WorkerStartedPayload, PolicyDecisionPayload,
    PolicyDecisionValue, build_event, new_ulid, utc_now,
)
from src.store.memory import MemoryEventStore
from src.conformance.suite import _open_incident
from src.policy import (
    GateContext, compute_plan_hash, compute_auth_tag, TEST_AUTH_KEY,
)


def _future_ts(minutes: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _past_ts(minutes: int = 5) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def make_state(
    incident_id: str = None,
    instance_id: str = "i-test001",
    phase: IncidentPhase = IncidentPhase.investigating,
    security_latch: bool = False,
    budgets: BudgetState = None,
    policy_decisions: dict = None,
) -> IncidentState:
    return IncidentState(
        incident_id=incident_id or new_ulid(),
        instance_id=instance_id,
        dedupe_key="test-key",
        phase=phase,
        security_latch=security_latch,
        budgets=budgets or BudgetState(),
        hypotheses={},
        evidence={},
        steps={},
        policy_decisions=policy_decisions or {},
        approvals={},
        pending_approval_step=None,
        pending_observation=None,
        pending_intent=None,
        last_verification=None,
        last_seq=0,
        last_hash=None,
        authorization_violations=[],
    )


def make_step(
    *,
    step_id: str = None,
    target: str = "i-test001",
    kind: StepKind = StepKind.observe,
    effects: list[DeclaredEffect] = None,
    execution_spec: dict = None,
    success_criteria: list = None,
    rollback_plan=None,
    rollback_reason: str = None,
    idempotent: bool = True,
) -> StepRecord:
    if effects is None:
        effects = [DeclaredEffect(category=EffectCategory.E0, resource=target, description="read-only")]
    if execution_spec is None:
        execution_spec = {"command": "df -h", "timeout_seconds": 30}
    if success_criteria is None:
        success_criteria = [{"type": "metric", "check": "disk_usage < 90"}]
    if rollback_plan is None:
        rollback_plan = "none"
        rollback_reason = "observe step — no rollback needed"

    sid = step_id or new_ulid()
    # Build StepRecord without plan_hash first then compute it
    step_no_hash = StepRecord(
        step_id=sid,
        incident_id="placeholder",
        based_on_hypotheses=[],
        based_on_evidence=[],
        kind=kind,
        target=target,
        execution_spec=execution_spec,
        declared_effects=effects,
        preconditions=[],
        success_criteria=success_criteria,
        rollback_plan=rollback_plan,
        rollback_reason=rollback_reason,
        idempotent=idempotent,
        risk_claim="low",
        expires_at=_future_ts(),
        plan_hash="placeholder",
    )
    from src.policy import compute_plan_hash
    ph = compute_plan_hash(step_no_hash)
    return StepRecord(
        step_id=sid,
        incident_id="placeholder",
        based_on_hypotheses=[],
        based_on_evidence=[],
        kind=kind,
        target=target,
        execution_spec=execution_spec,
        declared_effects=effects,
        preconditions=[],
        success_criteria=success_criteria,
        rollback_plan=rollback_plan,
        rollback_reason=rollback_reason,
        idempotent=idempotent,
        risk_claim="low",
        expires_at=_future_ts(),
        plan_hash=ph,
    )


def make_default_ctx(
    kill_switch: bool = False,
    enabled_t1: frozenset = None,
    instance_id: str = "i-test001",
) -> GateContext:
    return GateContext(
        kill_switch_active=kill_switch,
        enabled_t1_categories=enabled_t1 or frozenset(),
        allowed_instance_id=instance_id,
        approval_event=None,
        approval_auth_tag=None,
        approval_incident_id=None,
        budget_snapshot={},
        auth_key=TEST_AUTH_KEY,
    )
