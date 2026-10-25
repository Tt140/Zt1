"""
handlers/agent.py — incidents-agent Lambda

Trigger: invoke_async from ingest or slack_callback (resume)
Responsibilities: Runs complete ReasoningLoop for incident_id.

Two Operating Modes:
  1. Initial Triage: {incident_id, instance_id}
  2. Resume from Approval: {incident_id, resume_from_approval: true, approval_event_id}

Lease Management Flow:
  - Acquires distributed lease in DynamoDB
  - Executes ReasoningLoop until terminal resolution or escalation
  - Releases distributed lease

Timeout Safety:
  - Lambda timeout = 900s (15 minutes)
  - Loop stops before timeout based on SAFETY_MARGIN_SECONDS
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

from src.domain.reducer import fold
from src.domain.types import (
    Actor, EventType, EscalatedPayload, IncidentPhase, PolicyDecisionValue,
    build_event, utc_now, new_ulid,
)
from src.agent.loop import ReasoningLoop, LoopTermination
from src.agent.context_builder import build_context
from src.agent.proxy_observe_backend import ProxyObserveBackend
from .shared import (
    get_store, get_model, get_decider, get_approval_mac_key, invoke_async,
    OBSERVER_FN, EXECUTOR_FN, NOTIFIER_FN,
    INSTANCE_ID, AWS_REGION, ok, err, cfg,
)

logger = logging.getLogger(__name__)

# Seconds before Lambda timeout to stop the loop, release lease, and trigger continuation
SAFETY_MARGIN_SECONDS = int(cfg("SAFETY_MARGIN_SECONDS", "30"))
MAX_CYCLES            = int(cfg("MAX_CYCLES",            "20"))
LEASE_TTL             = float(cfg("LEASE_TTL_SECONDS",   "900"))
WORKER_ID             = f"agent-{new_ulid()}"


def handler(event: dict, context) -> dict:
    incident_id = event.get("incident_id")
    if not incident_id:
        return err("missing incident_id", 400)

    instance_id = event.get("instance_id") or INSTANCE_ID
    resume_approval = event.get("resume_from_approval", False)

    store = get_store()

    # ── acquire lease ────────────────────────────────────────────────────────
    token = store.acquire_lease(incident_id, WORKER_ID, ttl_seconds=LEASE_TTL)
    if token is None:
        logger.warning(f"Could not acquire lease for {incident_id} — another worker active")
        return ok({"skipped": True, "reason": "lease_held"})

    try:
        return _run_agent(
            incident_id=incident_id,
            instance_id=instance_id,
            store=store,
            token=token,
            context_obj=context,
            resume_approval=resume_approval,
            approval_event_id=event.get("approval_event_id"),
        )
    finally:
        store.release_lease(incident_id, token)


def _run_agent(
    incident_id: str,
    instance_id: str,
    store,
    token,
    context_obj,
    resume_approval: bool,
    approval_event_id: Optional[str],
) -> dict:
    # Read and fold current incident state
    events = store.read(incident_id)
    if not events:
        return err(f"No events found for incident {incident_id}", 404)

    state = fold(events)

    # Validate approval when resuming from human-in-the-loop callback
    if resume_approval:
        target_step_id = approval_event_id if (approval_event_id and approval_event_id in state.steps) else None
        if not target_step_id and state.pending_approval_step:
            target_step_id = state.pending_approval_step
        if not target_step_id and state.approvals:
            for ap in state.approvals.values():
                sid = getattr(ap, "step_id", None)
                if sid and sid in state.steps:
                    target_step_id = sid
                    break
        if not target_step_id and state.steps:
            target_step_id = list(state.steps.keys())[-1]

        if target_step_id:
            logger.info(f"Resuming from approval: invoking executor for step {target_step_id}")
            invoke_async(EXECUTOR_FN, {
                "incident_id": incident_id,
                "step_id": target_step_id,
                "approval_event_id": approval_event_id or target_step_id,
            })
            return ok({
                "incident_id": incident_id,
                "status": "executor_invoked",
                "step_id": target_step_id,
            })
        else:
            logger.info(f"No pending approval step for {incident_id} — may have been resolved")
            return ok({"incident_id": incident_id, "status": "no_pending_approval"})

    # Instantiate observe backend
    backend = ProxyObserveBackend(
        observer_function_name=OBSERVER_FN,
        region=AWS_REGION,
    )

    # Calculate max_steps based on remaining Lambda execution time
    remaining_ms = getattr(context_obj, "get_remaining_time_in_millis", lambda: 900_000)()
    max_steps = _calc_max_steps(remaining_ms)

    # Construct ReasoningLoop
    loop = ReasoningLoop(
        model=get_model(),
        store=store,
        backend=backend,
        instance_id=instance_id,
        max_cycles=MAX_CYCLES,
        tool_decider=get_decider(),
    )

    result = loop.run(state, max_steps=max_steps)

    logger.info(
        f"Loop finished: incident={incident_id} "
        f"termination={result.termination.value} "
        f"cycles={len(result.tool_calls)}"
    )

    # ── post-loop actions ────────────────────────────────────────────────────
    if result.termination == LoopTermination.ESCALATED:
        _notify_escalation(incident_id, instance_id)

    elif result.termination in (LoopTermination.STEP_LIMIT, LoopTermination.MAX_CYCLES):
        # Lambda timeout approaching — reinvoke async to continue investigation
        remaining = getattr(context_obj, "get_remaining_time_in_millis", lambda: 0)()
        if remaining > SAFETY_MARGIN_SECONDS * 1000:
            logger.info(f"Re-invoking agent for continuation: {incident_id}")
            invoke_async(cfg("AGENT_FUNCTION", "incidents-agent"), {
                "incident_id": incident_id,
                "instance_id": instance_id,
            })

    elif result.termination in (LoopTermination.RESOLVED, LoopTermination.CONCLUDED):
        _notify_resolution(incident_id, state)
        _release_dedup(store, incident_id, state)

    elif result.termination == LoopTermination.PROPOSED:
        final_state = result.final_state if hasattr(result, "final_state") and result.final_state else fold(store.read(incident_id))
        if final_state.steps:
            step_id = list(final_state.steps.keys())[-1]
            step = final_state.steps[step_id]
            decision = final_state.policy_decisions.get(step_id)

            if decision and decision.decision == PolicyDecisionValue.allow:
                logger.info(f"Step {step_id} allowed (T1) — notifying and invoking executor")
                cmd = step.execution_spec.get("command", "") if isinstance(step.execution_spec, dict) else ""
                invoke_async(NOTIFIER_FN, {
                    "type": "action_proposed",
                    "incident_id": incident_id,
                    "instance_id": final_state.instance_id or instance_id,
                    "step_id": step_id,
                    "step_description": cmd or f"Execute {step.kind.value} step",
                    "command": cmd,
                    "tier": "T1",
                })
                invoke_async(EXECUTOR_FN, {
                    "incident_id": incident_id,
                    "step_id": step_id,
                })
            elif final_state.phase == IncidentPhase.awaiting_approval or (decision and decision.decision == PolicyDecisionValue.require_approval):
                logger.info(f"Step {step_id} requires approval (T2) — notifying for approval")
                cmd = step.execution_spec.get("command", "") if isinstance(step.execution_spec, dict) else ""
                invoke_async(NOTIFIER_FN, {
                    "type": "approval_request",
                    "incident_id": incident_id,
                    "instance_id": final_state.instance_id or instance_id,
                    "step_id": step_id,
                    "step_description": cmd or f"Execute {step.kind.value} step",
                    "command": cmd,
                    "risk_claim": step.risk_claim or "medium",
                    "plan_hash": getattr(step, "plan_hash", ""),
                })

    return ok({
        "incident_id": incident_id,
        "termination": result.termination.value,
        "cycles": len(result.tool_calls),
    })


def _calc_max_steps(remaining_ms: int) -> Optional[int]:
    """Calculates max_steps from remaining execution time. None = unbounded."""
    safe_ms = remaining_ms - (SAFETY_MARGIN_SECONDS * 1000)
    if safe_ms <= 0:
        return 0
    # Conservative estimate: ~30 seconds per reasoning cycle
    return max(1, safe_ms // 30_000)


def _notify_escalation(incident_id: str, instance_id: str) -> None:
    try:
        invoke_async(NOTIFIER_FN, {
            "type": "escalation",
            "incident_id": incident_id,
            "instance_id": instance_id,
            "message": f"⚠️ Incident {incident_id} escalated — human review required",
        })
    except Exception as e:
        logger.error(f"Failed to notify escalation: {e}")


def _notify_resolution(incident_id: str, state) -> None:
    try:
        invoke_async(NOTIFIER_FN, {
            "type": "resolution",
            "incident_id": incident_id,
            "instance_id": state.instance_id,
            "message": f"✅ Incident {incident_id} resolved automatically",
        })
    except Exception as e:
        logger.error(f"Failed to notify resolution: {e}")


def _release_dedup(store, incident_id: str, state) -> None:
    """Releases the dedupe key from incidents-dedup upon resolution to unblock future alarms."""
    try:
        dk = getattr(state, "dedupe_key", None)
        if not dk:
            header = store.get_header(incident_id)
            if header:
                dk = header.dedupe_key
        if dk:
            logger.info(f"Releasing dedupe key {dk!r} for resolved incident {incident_id}")
            store.release_dedupe(dk)
    except Exception as e:
        logger.warning(f"Failed to release dedupe key for incident {incident_id}: {e}")

