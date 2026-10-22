"""
executor/executor.py — Phase 4 ExecutorLoop

Executes T0/T1/T2 steps through the complete execution lifecycle:
1. Policy Gate re-evaluation (G2 — double-check invariant)
2. Pre-execution snapshot (SnapshotTaken)
3. CAS-guaranteed intent emission (ExecutionIntent — I-14)
4. Isolated command execution in DockerLab
5. Result recording (ExecutionResult)
6. Independent verification (Verifier → VerificationRecorded)
7. Rollback if verification fails (or immediately if command fails)
8. Reconciler crash recovery

Binding contracts:
- I-14: No execution without logged ExecutionIntent matching plan_hash
- G2: Gate re-evaluation prior to each execution from fresh state
- ADR-004: No command string regex filtering in gate — bounded in DockerLab allowlist
- 04 §9: Double verification failure = Rollback + Escalated
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..domain.types import (
    Actor, EventType, IncidentPhase, IncidentState, StepRecord,
    ExecutionIntentPayload, ExecutionResultPayload,
    SnapshotTakenPayload, RollbackStartedPayload, RollbackCompletedPayload,
    EscalatedPayload, PolicyDecisionPayload, PolicyDecisionValue,
    Tier, EffectCategory, ApprovalGrantedPayload, build_event, new_ulid, utc_now,
    EvidenceRef, EvidenceAddedPayload, TrustLevel,
)
from ..domain.reducer import fold
from ..policy import GateContext, evaluate as gate_evaluate, TEST_AUTH_KEY
from .docker_lab import DockerLab, LabResult
from .verifier import Verifier, VerificationResult
from .reconciler import Reconciler
from ..domain.types import VerificationVerdict

logger = logging.getLogger(__name__)


class ExecutorTermination(str, Enum):
    COMPLETED  = "completed"    # Execution and verification succeeded
    ROLLBACK   = "rollback"     # Rollback executed successfully
    FAILED     = "failed"       # Execution or verification failed without rollback
    DENIED     = "denied"       # Denied by policy gate
    ESCALATED  = "escalated"    # Escalated after double failure


@dataclass
class ExecutorResult:
    termination: ExecutorTermination
    step_id: str
    plan_hash: str
    gate_decision: PolicyDecisionValue
    lab_result: Optional[LabResult]
    verification: Optional[VerificationResult]
    final_state: IncidentState
    details: str


class ExecutorLoop:
    """
    Executes a single proposed step through full lifecycle:
    Gate → Snapshot → Intent (CAS) → Lab → Verify → Rollback?
    """

    def __init__(
        self,
        store,
        lab: Optional[DockerLab] = None,
        verifier: Optional[Verifier] = None,
        reconciler: Optional[Reconciler] = None,
        instance_id: str = "",
        allowed_instance_id: str = "",
        max_verify_attempts: int = 2,
        auth_key: Optional[bytes] = None,
        auto_resolve_incident: bool = True,
    ):
        self._store = store
        self._lab = lab or DockerLab()
        self._verifier = verifier or Verifier(self._lab)
        self._reconciler = reconciler or Reconciler(self._lab)
        self._instance_id = instance_id or allowed_instance_id
        self._allowed_instance_id = allowed_instance_id or instance_id
        self._max_verify_attempts = max_verify_attempts
        self._auth_key = auth_key
        self._auto_resolve_incident = auto_resolve_incident

    # ─────────────────────────────────────────────────────────────────────
    # Entry Point
    # ─────────────────────────────────────────────────────────────────────

    def execute_step(
        self,
        step: StepRecord,
        state: IncidentState,
        ctx: Optional[GateContext] = None,
        gate_ctx: Optional[GateContext] = None,
    ) -> ExecutorResult:
        """
        Executes a single step. Returns ExecutorResult.
        """
        # ① Reconcile first — resolve pending intent from prior interrupted run
        if state.pending_intent and state.pending_intent != step.step_id:
            logger.warning(f"Reconciling pending intent: {state.pending_intent}")
            self._reconciler.reconcile(self._store, state.incident_id)
            state = fold(self._store.read(state.incident_id))

        # ② Prepare GateContext and re-evaluate Policy Gate (G2)
        effective_ctx = gate_ctx or ctx
        if effective_ctx is None:
            gate_kwargs = {
                "kill_switch_active": False,
                "allowed_instance_id": self._allowed_instance_id or state.instance_id,
                "enabled_t1_categories": frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
            }
            if self._auth_key is not None:
                gate_kwargs["auth_key"] = self._auth_key
            effective_ctx = GateContext(**gate_kwargs)
        elif self._auth_key is not None and effective_ctx.auth_key == TEST_AUTH_KEY:
            import dataclasses
            effective_ctx = dataclasses.replace(effective_ctx, auth_key=self._auth_key)
        ctx = effective_ctx

        # If approval_event not passed explicitly, check for valid ApprovalGrantedPayload in state.approvals
        if ctx.approval_event is None and state.approvals:
            import dataclasses
            for ap in state.approvals.values():
                if getattr(ap, "step_id", None) == step.step_id and isinstance(ap, ApprovalGrantedPayload):
                    auth_tag = getattr(ap, "auth_tag", None) or ctx.approval_auth_tag
                    ctx = dataclasses.replace(
                        ctx,
                        approval_event=ap,
                        approval_auth_tag=auth_tag,
                        approval_incident_id=state.incident_id,
                    )
                    break

        gate_result = gate_evaluate(step, state, ctx)
        self._write_policy_decision(gate_result, step, state)

        if gate_result.decision == PolicyDecisionValue.deny:
            state = fold(self._store.read(state.incident_id))
            return ExecutorResult(
                termination=ExecutorTermination.DENIED,
                step_id=step.step_id, plan_hash=step.plan_hash,
                gate_decision=gate_result.decision,
                lab_result=None, verification=None,
                final_state=state,
                details=f"Gate denied: {gate_result.reasons}",
            )

        if gate_result.decision == PolicyDecisionValue.require_approval:
            state = fold(self._store.read(state.incident_id))
            return ExecutorResult(
                termination=ExecutorTermination.DENIED,
                step_id=step.step_id, plan_hash=step.plan_hash,
                gate_decision=gate_result.decision,
                lab_result=None, verification=None,
                final_state=state,
                details=f"Gate requires approval — not provided: {gate_result.reasons}",
            )

        # ③ Pre-execution snapshot
        snapshot_ref = self._take_snapshot(step, state)

        # ④ ExecutionIntent (CAS — I-14)
        correlation_id = new_ulid()
        idempotency_key = f"{state.incident_id}:{step.step_id}"
        intent_event = build_event(
            incident_id=state.incident_id,
            type=EventType.ExecutionIntent,
            actor=Actor.executor,
            payload=ExecutionIntentPayload(
                step_id=step.step_id,
                plan_hash=step.plan_hash,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
                fencing_seq=0,  # Populated after store append
            ),
        )
        seq = self._store.last_seq(state.incident_id)
        stored_intent = self._store.append(state.incident_id, seq, intent_event)
        # Update sequence tracking
        actual_seq = stored_intent.seq

        state = fold(self._store.read(state.incident_id))

        # ⑤ Execute command in isolated lab
        command = step.execution_spec.get("command", "")
        from ..domain.types import StepKind
        exec_tier = "T1" if (gate_result.tier in (Tier.T1, Tier.T2) or step.kind == StepKind.mutate) else "T0"
        try:
            lab_result = self._lab.run(command, tier=exec_tier)
        except TypeError:
            lab_result = self._lab.run(command)
        logger.info(
            f"Lab [{self._lab.backend_name if hasattr(self._lab, 'backend_name') else 'lab'}] step={step.step_id[:8]} "
            f"exit={lab_result.exit_code} elapsed={lab_result.elapsed_seconds:.2f}s"
        )

        # ⑥ Write ExecutionResult
        is_success = bool(lab_result.success and lab_result.exit_code == 0 and not lab_result.blocked_reason)
        exec_status = "success" if is_success else "failure"

        self._write_execution_result(
            step, state, exec_status, lab_result,
            pre_snapshot_ref=snapshot_ref,
        )
        state = fold(self._store.read(state.incident_id))

        if not is_success:
            # Record failure as authoritative host evidence in EventStore (G3: Actor.executor authorized for EvidenceAdded)
            self._write_execution_failure_evidence(step, state, lab_result)
            state = fold(self._store.read(state.incident_id))

            # Execution failed -> trigger rollback immediately
            rollback_ok = self._run_rollback(step, state)
            state = fold(self._store.read(state.incident_id))

            # Check failed step count against safety cap
            failed_steps_count = sum(1 for s in state.steps.values() if getattr(s, "status", "") == "failed")

            # Extract concise error summary (last substantive line)
            err_raw = (lab_result.stderr or lab_result.stdout or "Command execution failed").strip()
            err_lines = [l.strip() for l in err_raw.splitlines() if l.strip()]
            err_tail = err_lines[-1] if err_lines else err_raw[:200]

            if self._auto_resolve_incident or failed_steps_count >= 2:
                # Default behavior or failsafe escalation upon repeated failures
                self._write_escalated(
                    state,
                    f"Execution failed with exit_code={lab_result.exit_code} (failed_steps={failed_steps_count}): {err_tail[:200]}"
                )
                state = fold(self._store.read(state.incident_id))
            else:
                logger.info(
                    f"Execution failed for step '{step.step_id}', but auto_resolve_incident is False "
                    f"and failed_steps_count={failed_steps_count} < 2. Incident phase remains '{state.phase.value}' for next reasoning round."
                )

            return ExecutorResult(
                termination=ExecutorTermination.ROLLBACK if rollback_ok else ExecutorTermination.FAILED,
                step_id=step.step_id, plan_hash=step.plan_hash,
                gate_decision=gate_result.decision,
                lab_result=lab_result, verification=None,
                final_state=state,
                details=f"Execution failed: {err_tail[:200]}. Rollback: {'ok' if rollback_ok else 'failed'}",
            )

        # ⑦ Independent verification
        verify_result = None
        for attempt in range(self._max_verify_attempts):
            verify_result = self._verifier.verify(step, state)
            if verify_result.verdict == VerificationVerdict.verified:
                break
            logger.warning(
                f"Verification attempt {attempt+1}/{self._max_verify_attempts} "
                f"failed: {verify_result.details}"
            )

        self._verifier.write_verification_event(
            verify_result, step, state, self._store,
            auto_resolve_incident=self._auto_resolve_incident,
        )
        state = fold(self._store.read(state.incident_id))

        if verify_result.verdict != VerificationVerdict.verified:
            # Verification failed after all retries -> rollback + escalate
            rollback_ok = self._run_rollback(step, state)
            state = fold(self._store.read(state.incident_id))
            self._write_escalated(state, f"Verification failed after {self._max_verify_attempts} attempts")
            state = fold(self._store.read(state.incident_id))
            return ExecutorResult(
                termination=ExecutorTermination.ESCALATED,
                step_id=step.step_id, plan_hash=step.plan_hash,
                gate_decision=gate_result.decision,
                lab_result=lab_result, verification=verify_result,
                final_state=state,
                details=f"Verification failed: {verify_result.details}",
            )

        # ⑧ Execution and verification succeeded
        state = fold(self._store.read(state.incident_id))
        return ExecutorResult(
            termination=ExecutorTermination.COMPLETED,
            step_id=step.step_id, plan_hash=step.plan_hash,
            gate_decision=gate_result.decision,
            lab_result=lab_result, verification=verify_result,
            final_state=state,
            details="Step completed and verified successfully",
        )

    # ─────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────

    def _write_policy_decision(self, gate_result, step, state):
        from ..policy import compute_plan_hash
        payload = PolicyDecisionPayload(
            step_id=step.step_id,
            plan_hash=step.plan_hash,
            tier=gate_result.tier,
            decision=gate_result.decision,
            reasons=gate_result.reasons,
            rule_ids=gate_result.rule_ids,
            budget_snapshot={
                "commands": state.budgets.commands,
                "max_commands": state.budgets.max_commands,
            },
            gate_version="1.0",
        )
        ev = build_event(
            incident_id=state.incident_id,
            type=EventType.PolicyDecision,
            actor=Actor.executor,
            payload=payload,
        )
        seq = self._store.last_seq(state.incident_id)
        self._store.append(state.incident_id, seq, ev)

    def _take_snapshot(self, step: StepRecord, state: IncidentState) -> str:
        """Captures lightweight filesystem snapshot ('df -h') and stores as content-addressed blob."""
        result = self._lab.run("df -h")
        snapshot_data = (result.stdout or "no_data").encode()
        ref = self._store.put_blob(snapshot_data)
        import hashlib
        integrity = hashlib.sha256(snapshot_data).hexdigest()

        ev = build_event(
            incident_id=state.incident_id,
            type=EventType.SnapshotTaken,
            actor=Actor.executor,
            payload=SnapshotTakenPayload(
                step_id=step.step_id,
                plan_hash=step.plan_hash,
                snapshot_ref=ref,
                integrity_hash=integrity,
            ),
        )
        seq = self._store.last_seq(state.incident_id)
        self._store.append(state.incident_id, seq, ev)
        return ref

    def _write_execution_result(
        self, step, state, status: str, lab_result: LabResult,
        pre_snapshot_ref: Optional[str] = None,
    ):
        output_ref = None
        if lab_result.stdout:
            output_ref = self._store.put_blob(lab_result.stdout.encode())

        is_success = bool(lab_result.success and lab_result.exit_code == 0 and not lab_result.blocked_reason)
        dv_observed = "match" if is_success else "mismatch"
        seq = self._store.last_seq(state.incident_id)
        ev = build_event(
            incident_id=state.incident_id,
            type=EventType.ExecutionResult,
            actor=Actor.executor,
            payload=ExecutionResultPayload(
                step_id=step.step_id,
                plan_hash=step.plan_hash,
                status=status,
                output_ref=output_ref,
                post_snapshot_ref=None,
                declared_vs_observed=dv_observed,
                mismatch_details={"stderr": lab_result.stderr[:500]} if not is_success else None,
            ),
        )
        self._store.append(state.incident_id, seq, ev)

    def _write_execution_failure_evidence(self, step: StepRecord, state: IncidentState, lab_result: LabResult):
        """Records command failure as authoritative EvidenceAdded in EventStore, highlighting error tail."""
        cmd = step.execution_spec.get("command", "")
        err_msg = (lab_result.stderr or lab_result.stdout or "Command execution failed").strip()
        lines = [l.strip() for l in err_msg.splitlines() if l.strip()]
        if len(lines) > 4:
            tail_snippet = " \n".join(lines[-4:])
        else:
            tail_snippet = err_msg
        if len(tail_snippet) > 400:
            tail_snippet = tail_snippet[-400:]

        ev_payload = EvidenceAddedPayload(
            evidence=EvidenceRef(
                evidence_id=new_ulid(),
                source="execution_failure",
                trust=TrustLevel.host_reported,
                collected_at=utc_now().isoformat(),
                raw_ref=None,
                integrity_hash=None,
                summary=f"Execution of step '{cmd}' failed (exit_code={lab_result.exit_code}): {tail_snippet}",
                redaction_report={},
            )
        )
        ev = build_event(
            incident_id=state.incident_id,
            type=EventType.EvidenceAdded,
            actor=Actor.executor,
            payload=ev_payload,
        )
        seq = self._store.last_seq(state.incident_id)
        self._store.append(state.incident_id, seq, ev)

    def _run_rollback(self, step: StepRecord, state: IncidentState) -> bool:
        """Executes rollback_plan actions sequentially."""
        seq = self._store.last_seq(state.incident_id)
        self._store.append(state.incident_id, seq, build_event(
            incident_id=state.incident_id,
            type=EventType.RollbackStarted,
            actor=Actor.executor,
            payload=RollbackStartedPayload(
                step_id=step.step_id, plan_hash=step.plan_hash,
                reason="execution_failure_or_verification_failure",
            ),
        ))
        seq += 1

        rollback_plan = step.rollback_plan
        success = True
        details = "none"

        if isinstance(rollback_plan, list):
            for action in rollback_plan:
                cmd = action.get("action", action.get("command", ""))
                if cmd:
                    try:
                        res = self._lab.run(cmd, tier="T1")
                    except TypeError:
                        res = self._lab.run(cmd)
                    success = success and res.success
                    details = f"cmd={cmd!r} exit={res.exit_code}"
        elif rollback_plan != "none":
            try:
                res = self._lab.run(str(rollback_plan), tier="T1")
            except TypeError:
                res = self._lab.run(str(rollback_plan))
            success = res.success
            details = f"exit={res.exit_code}"

        seq = self._store.last_seq(state.incident_id)
        self._store.append(state.incident_id, seq, build_event(
            incident_id=state.incident_id,
            type=EventType.RollbackCompleted,
            actor=Actor.executor,
            payload=RollbackCompletedPayload(
                step_id=step.step_id, plan_hash=step.plan_hash,
                success=success, details=details,
            ),
        ))
        return success

    def _write_escalated(self, state: IncidentState, reason: str):
        if state.phase == IncidentPhase.escalated:
            return
        seq = self._store.last_seq(state.incident_id)
        self._store.append(state.incident_id, seq, build_event(
            incident_id=state.incident_id,
            type=EventType.Escalated,
            actor=Actor.executor,
            payload=EscalatedPayload(reason=reason, report_ref=None),
        ))
