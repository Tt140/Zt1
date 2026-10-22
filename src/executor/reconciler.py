"""
executor/reconciler.py — Crash Recovery / Reconciliation (Phase 4)

Handles cases where the executor crashed after emitting ExecutionIntent
but before recording ExecutionResult (CS-07).

Algorithm (04 §9, CS-07):
1. Read current incident state from EventStore.
2. If an ExecutionIntent exists without an ExecutionResult:
   a. Extract command/intent parameters.
   b. Check for proof of success in sandbox (idempotency check).
   c. If success verified -> emit ExecutionResult(success).
   d. If unverified -> emit ExecutionResult(failure) + trigger Rollback.
3. Emit ReconcileOutcome.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ..domain.types import (
    Actor, EventType, IncidentState, ReconcileOutcomePayload,
    ReconcileStatus, ExecutionIntentPayload, ExecutionResultPayload,
    RollbackStartedPayload, RollbackCompletedPayload,
    build_event, new_ulid, utc_now,
)
from ..domain.reducer import fold
from .docker_lab import DockerLab, LabResult

logger = logging.getLogger(__name__)


@dataclass
class ReconcileResult:
    status: ReconcileStatus
    details: str
    step_id: Optional[str] = None


class Reconciler:
    """
    Rebuilds consistent state after a crash.
    Does not trust any in-memory state — rebuilds strictly from EventStore.
    """

    def __init__(self, lab: Optional[DockerLab] = None):
        self._lab = lab or DockerLab(tier="T0")

    def reconcile(self, store, incident_id: str) -> ReconcileResult:
        """
        Inspects state and reconciles pending_intent if one exists.
        Returns ReconcileResult with the final resolution status.
        """
        # Reconstruct state from EventStore (fail-safe)
        state = fold(store.read(incident_id))

        if not state.pending_intent:
            return ReconcileResult(
                status=ReconcileStatus.executed,
                details="No pending intent — state is clean",
            )

        step_id = state.pending_intent
        logger.warning(f"Reconciler: pending intent detected for step {step_id}")

        # Lookup step in state
        step = state.steps.get(step_id)
        if step is None:
            # ExecutionIntent without StepProposed — state corruption
            result = self._write_execution_result(
                store, state, step_id, plan_hash="unknown",
                status="failure", output_ref=None,
                declared_vs_observed="mismatch",
                mismatch_details={"reason": "step not found in state"},
            )
            outcome = self._write_reconcile_outcome(
                store, state, step_id, plan_hash="unknown",
                status=ReconcileStatus.unknown,
                details="Step not found — possible state corruption",
            )
            return ReconcileResult(
                status=ReconcileStatus.unknown,
                details="Step not found in state",
                step_id=step_id,
            )

        # Idempotency check: did the step actually succeed?
        idempotency_result = self._check_idempotency(step)

        if idempotency_result:
            # Step succeeded — record success
            self._write_execution_result(
                store, state, step_id, plan_hash=step.plan_hash,
                status="success", output_ref=None,
                declared_vs_observed="match", mismatch_details=None,
            )
            self._write_reconcile_outcome(
                store, state, step_id, plan_hash=step.plan_hash,
                status=ReconcileStatus.executed,
                details=f"Idempotency check passed: {idempotency_result}",
            )
            return ReconcileResult(
                status=ReconcileStatus.executed,
                details=f"Reconciled: step succeeded (idempotency: {idempotency_result})",
                step_id=step_id,
            )
        else:
            # Step did not succeed — trigger rollback
            self._write_execution_result(
                store, state, step_id, plan_hash=step.plan_hash,
                status="failure", output_ref=None,
                declared_vs_observed="mismatch",
                mismatch_details={"reason": "idempotency check failed after crash"},
            )
            rollback_success = self._run_rollback(store, state, step)
            status = (
                ReconcileStatus.executed
                if rollback_success
                else ReconcileStatus.not_executed
            )
            self._write_reconcile_outcome(
                store, state, step_id, plan_hash=step.plan_hash,
                status=status,
                details=f"Reconciled after failure: rollback={'success' if rollback_success else 'failure'}",
            )
            return ReconcileResult(
                status=status,
                details=f"Crash recovery: rollback={'success' if rollback_success else 'failure'}",
                step_id=step_id,
            )

    def _check_idempotency(self, step) -> Optional[str]:
        """
        Verifies step success criteria via idempotency probes.
        Returns a description of success or None if verification failed.
        """
        # Run success_criteria as an idempotency probe
        for criterion in step.success_criteria:
            if criterion.get("type") == "command":
                cmd = criterion.get("check", "")
                if cmd.startswith("cmd:"):
                    cmd = cmd[4:].strip()
                result = self._lab.run(cmd)
                if not result.success:
                    return None  # Criterion failed
            # Other criteria are considered passing in Reconciler
        return "success_criteria_satisfied"

    def _run_rollback(self, store, state, step) -> bool:
        """Executes rollback_plan and records the outcome."""
        seq = store.last_seq(state.incident_id)
        rollback_event = build_event(
            incident_id=state.incident_id,
            type=EventType.RollbackStarted,
            actor=Actor.executor,
            payload=RollbackStartedPayload(
                step_id=step.step_id,
                plan_hash=step.plan_hash,
                reason="crash_recovery",
            ),
        )
        store.append(state.incident_id, seq, rollback_event)
        seq += 1

        # Execute rollback plan
        rollback_plan = step.rollback_plan
        success = True
        details = "no rollback needed"

        if isinstance(rollback_plan, list):
            for action in rollback_plan:
                cmd = action.get("action", action.get("command", ""))
                if cmd and cmd != "none":
                    result = self._lab.run(cmd)
                    if not result.success:
                        success = False
                        details = f"rollback command failed: {cmd!r}"
                        break
                    details = f"rollback executed: {cmd!r}"
        elif rollback_plan != "none":
            result = self._lab.run(str(rollback_plan))
            success = result.success
            details = f"rollback exit={result.exit_code}"

        seq = store.last_seq(state.incident_id)
        rollback_done = build_event(
            incident_id=state.incident_id,
            type=EventType.RollbackCompleted,
            actor=Actor.executor,
            payload=RollbackCompletedPayload(
                step_id=step.step_id,
                plan_hash=step.plan_hash,
                success=success,
                details=details,
            ),
        )
        store.append(state.incident_id, seq, rollback_done)
        return success

    def _write_execution_result(
        self, store, state, step_id: str, plan_hash: str,
        status: str, output_ref, declared_vs_observed: str,
        mismatch_details,
    ):
        seq = store.last_seq(state.incident_id)
        ev = build_event(
            incident_id=state.incident_id,
            type=EventType.ExecutionResult,
            actor=Actor.executor,
            payload=ExecutionResultPayload(
                step_id=step_id,
                plan_hash=plan_hash,
                status=status,
                output_ref=output_ref,
                post_snapshot_ref=None,
                declared_vs_observed=declared_vs_observed,
                mismatch_details=mismatch_details,
            ),
        )
        store.append(state.incident_id, seq, ev)

    def _write_reconcile_outcome(
        self, store, state, step_id: str, plan_hash: str,
        status: ReconcileStatus, details: str,
    ):
        seq = store.last_seq(state.incident_id)
        ev = build_event(
            incident_id=state.incident_id,
            type=EventType.ReconcileOutcome,
            actor=Actor.executor,
            payload=ReconcileOutcomePayload(
                step_id=step_id,
                plan_hash=plan_hash,
                status=status,
                details=details,
            ),
        )
        store.append(state.incident_id, seq, ev)
