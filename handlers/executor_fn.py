"""
handlers/executor_fn.py — incidents-executor Lambda

Trigger: InvokeAsync from incidents-agent after Policy Gate clearance on T1/T2 step
Responsibilities: Executes full ExecutorLoop (Gate G2 → Intent → SSM T1/T2 → Verify → Rollback?)

Zero-Trust: Executor Lambda holds no permanent ssm:SendCommand permission.
Uses STS AssumeRole → incidents-ssm-exec-role to acquire temporary scoped credentials.

Uses SSMLab for production execution instead of DockerLab.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

from src.domain.reducer import fold
from src.executor.executor import ExecutorLoop
from src.executor.ssm_lab import SSMLab
from src.executor.verifier import Verifier
from src.executor.reconciler import Reconciler
from src.domain.types import StepRecord, IncidentPhase
from src.policy.gate import GateContext
from .shared import (
    get_store, ok, err, cfg, invoke_async,
    AWS_REGION, SSM_EXEC_ROLE, get_approval_mac_key, NOTIFIER_FN,
)

logger = logging.getLogger(__name__)

TARGET_INSTANCE_ID = cfg("TARGET_INSTANCE_ID", "")
MAX_VERIFY_ATTEMPTS = int(cfg("MAX_VERIFY_ATTEMPTS", "2"))


def handler(event: dict, context) -> dict:
    """
    event = {
      "incident_id": str,
      "step_id": str,
      "approval_event_id": str | None,   # Required for Tier T2 mutations
    }
    """
    incident_id       = event.get("incident_id")
    step_id           = event.get("step_id")
    approval_event_id = event.get("approval_event_id")

    if not incident_id or not step_id:
        return err("missing incident_id or step_id", 400)

    store = get_store()

    try:
        events = store.read(incident_id)
        if not events:
            return err(f"No events for {incident_id}", 404)

        state = fold(events)

        step = state.steps.get(step_id)
        if not step:
            return err(f"Step {step_id} not found in incident {incident_id}", 404)

        # Instantiate SSMLab as lab execution backend (production default)
        lab = _build_ssm_lab(state.instance_id or TARGET_INSTANCE_ID)

        # Construct GateContext
        gate_ctx = _build_gate_ctx(
            state=state,
            approval_event_id=approval_event_id,
            store=store,
            incident_id=incident_id,
        )

        executor = ExecutorLoop(
            store=store,
            lab=lab,
            verifier=Verifier(lab),
            reconciler=Reconciler(lab),
            instance_id=state.instance_id or TARGET_INSTANCE_ID,
            allowed_instance_id=TARGET_INSTANCE_ID,
            max_verify_attempts=MAX_VERIFY_ATTEMPTS,
        )

        result = executor.execute_step(step=step, state=state, gate_ctx=gate_ctx)

        # Refresh incident state post-execution
        latest_events = store.read(incident_id)
        latest_state = fold(latest_events) if latest_events else state

        if latest_state.phase == IncidentPhase.resolved:
            logger.info(f"Incident {incident_id} resolved — notifying")
            invoke_async(NOTIFIER_FN, {
                "type": "resolution",
                "incident_id": incident_id,
                "instance_id": latest_state.instance_id or state.instance_id,
                "reason": "Remediation verified and incident resolved",
            })
        elif latest_state.phase == IncidentPhase.escalated:
            logger.info(f"Incident {incident_id} escalated — notifying")
            term_val = result.termination.value if hasattr(result, "termination") and hasattr(result.termination, "value") else str(result)
            invoke_async(NOTIFIER_FN, {
                "type": "escalation",
                "incident_id": incident_id,
                "instance_id": latest_state.instance_id or state.instance_id,
                "reason": f"Executor terminated with {term_val}",
            })

        logger.info(
            f"Executor done: incident={incident_id} step={step_id} "
            f"outcome={result.outcome.value if hasattr(result, 'outcome') else result}"
        )

        return ok({
            "incident_id": incident_id,
            "step_id":     step_id,
            "outcome":     str(result),
        })

    except Exception as exc:
        logger.exception(f"executor error for {incident_id}/{step_id}: {exc}")
        return err(str(exc))


def _build_ssm_lab(instance_id: str):
    """
    In production → SSMLab with STS AssumeRole if configured,
    or SSMLab with default Lambda execution role credentials.
    If USE_DOCKER_LAB=1 is explicitly set for local container testing → DockerLab.
    """
    if cfg("USE_DOCKER_LAB", "") == "1":
        from src.executor.docker_lab import DockerLab
        logger.warning("USE_DOCKER_LAB=1 set — using DockerLab (test only)")
        return DockerLab()

    if SSM_EXEC_ROLE:
        return SSMLab(
            instance_id=instance_id,
            region=AWS_REGION,
            ssm_role_arn=SSM_EXEC_ROLE,
        )

    return SSMLab(
        instance_id=instance_id,
        region=AWS_REGION,
    )


def _build_gate_ctx(state, approval_event_id: Optional[str], store, incident_id: str) -> GateContext:
    """Builds GateContext from current incident state."""
    from src.policy.gate import GateContext
    from src.domain.types import EffectCategory

    # Tier T2 approval resolution
    approval_event  = None
    approval_auth_tag = None
    if approval_event_id and state.approvals:
        ap = state.approvals.get(approval_event_id)
        if not ap:
            for candidate in state.approvals.values():
                if getattr(candidate, "step_id", None) == approval_event_id:
                    ap = candidate
                    break
        if ap:
            approval_event     = ap
            approval_auth_tag  = getattr(ap, "auth_tag", None)

    # Enabled Tier T1 categories (all safe categories enabled)
    enabled_t1 = frozenset([
        EffectCategory.E1,   # Process level mutations (e.g. process restart)
        EffectCategory.E2,   # File / configuration updates
        EffectCategory.E3,   # Temporary file / log truncation
    ])

    # HMAC key: mandatory for Tier T2 (fail-closed), optional for Tier T1
    if approval_event:
        auth_key = get_approval_mac_key()
    else:
        try:
            auth_key = get_approval_mac_key()
        except Exception:
            auth_key = b""

    return GateContext(
        kill_switch_active=False,   # No kill-switch triggered
        enabled_t1_categories=enabled_t1,
        allowed_instance_id=TARGET_INSTANCE_ID or state.instance_id,
        approval_event=approval_event,
        approval_auth_tag=approval_auth_tag,
        approval_incident_id=incident_id if approval_event else None,
        budget_snapshot={
            "cycles":        state.budgets.cycles,
            "commands":      state.budgets.commands,
            "mutate_steps":  state.budgets.mutate_steps,
        },
        auth_key=auth_key,
    )
