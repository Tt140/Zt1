"""
domain/reducer.py — Pure, deterministic state reducer (03 §4, 02 §2)

Rules:
- No I/O, no system clock, no randomness.
- state = fold(events) — deterministic and reproducible.
- Unauthorized writer events are rejected and recorded in authorization_violations (G3).
- Versioned via REDUCER_VERSION to detect incompatibility (CS-11).
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
from typing import Optional

from .types import (
    Actor,
    ApprovalDeniedPayload,
    ApprovalRejectedPayload,
    ApprovalExpiredPayload,
    ApprovalGrantedPayload,
    ApprovalRequestedPayload,
    BudgetConsumedPayload,
    BudgetState,
    ConclusionProposedPayload,
    EscalatedPayload,
    EvidenceAddedPayload,
    Event,
    EventType,
    ExecutionIntentPayload,
    ExecutionResultPayload,
    HypothesisUpdatedPayload,
    IncidentAbortedPayload,
    IncidentHeader,
    IncidentOpenedPayload,
    IncidentPhase,
    IncidentResolvedPayload,
    IncidentState,
    LatchReleasedByHumanPayload,
    ObservationRecordedPayload,
    PolicyDecisionPayload,
    ReconcileOutcomePayload,
    ReconcileStatus,
    RollbackCompletedPayload,
    RollbackStartedPayload,
    SecurityLatchEngagedPayload,
    SnapshotTakenPayload,
    StepProposedPayload,
    VerificationRecordedPayload,
    VerificationRequestedPayload,
    VerificationVerdict,
    AUTHORIZED_WRITERS,
)

REDUCER_VERSION = "1.0"


def _initial_state(incident_id: str, payload: IncidentOpenedPayload, opened_at: str) -> IncidentState:
    alarm_name = getattr(payload, "alarm_name", "") or (payload.get("alarm_name", "") if isinstance(payload, dict) else "")
    alert_source = getattr(payload, "alert_source", "") or (payload.get("alert_source", "") if isinstance(payload, dict) else "")
    alarm_description = getattr(payload, "alarm_description", "") or (payload.get("alarm_description", "") if isinstance(payload, dict) else "")
    return IncidentState(
        incident_id=incident_id,
        instance_id=payload.instance_id if hasattr(payload, "instance_id") else payload.get("instance_id", ""),
        dedupe_key=payload.dedupe_key if hasattr(payload, "dedupe_key") else payload.get("dedupe_key", ""),
        phase=IncidentPhase.investigating,
        security_latch=False,
        budgets=BudgetState(),
        hypotheses={},
        evidence={},
        steps={},
        policy_decisions={},
        approvals={},
        pending_approval_step=None,
        pending_observation=None,
        pending_intent=None,
        last_verification=None,
        last_seq=0,
        last_hash=None,
        authorization_violations=[],
        alarm_name=alarm_name,
        alert_source=alert_source,
        alarm_description=alarm_description,
    )


def _check_authorization(event: Event) -> bool:
    """Verifies writer authorization under G3 write delegation matrix. Returns True if permitted."""
    allowed = AUTHORIZED_WRITERS.get(event.type)
    if allowed is None:
        return False  # Unknown event type
    return event.actor in allowed





def _apply_one(state: IncidentState, event: Event) -> IncidentState:
    """
    Applies single event to incident state. Returns mutated/new state.
    On authorization violation: appends to authorization_violations and escalates incident.
    """
    # Update sequence and hash tracking
    state.last_seq = event.seq
    state.last_hash = event.hash

    # Verify writer authorization (G3)
    if not _check_authorization(event):
        state.authorization_violations.append({
            "seq": event.seq,
            "event_id": event.event_id,
            "type": event.type.value,
            "actor": event.actor.value,
        })
        # Escalate incident on authorization violation (G3 failsafe)
        if state.phase not in (IncidentPhase.escalated, IncidentPhase.aborted, IncidentPhase.resolved, IncidentPhase.concluded):
            state.phase = IncidentPhase.escalated
        return state

    t = event.type

    if t == EventType.IncidentOpened:
        # No-op — initial state was initialized from this event
        pass

    elif t == EventType.SecurityLatchEngaged:
        state.security_latch = True
        state.phase = IncidentPhase.security_evidence

    elif t == EventType.LatchReleasedByHuman:
        state.security_latch = False
        # Return to investigating if not in a terminal phase
        if state.phase == IncidentPhase.security_evidence:
            state.phase = IncidentPhase.investigating

    elif t == EventType.ObservationRequested:
        p = event.payload
        state.pending_observation = p.request_id

    elif t in (EventType.ObservationRecorded, EventType.EvidenceAdded):
        if t == EventType.ObservationRecorded:
            p: ObservationRecordedPayload = event.payload
            ev = p.evidence
            state.pending_observation = None
        else:
            p: EvidenceAddedPayload = event.payload
            ev = p.evidence
        state.evidence[ev.evidence_id] = ev

    elif t == EventType.HypothesisUpdated:
        p: HypothesisUpdatedPayload = event.payload
        h = p.hypothesis if hasattr(p, "hypothesis") else p.get("hypothesis")
        state.hypotheses[h.hypothesis_id] = h

        # Adapt command budget and max cycles dynamically based on complexity
        c = getattr(p, "complexity", None)
        if not c and hasattr(h, "complexity"):
            c = h.complexity
        if not c and isinstance(p, dict):
            c = p.get("complexity")

        if c:
            c = str(c).strip().lower()
            if c == "low":
                state.budgets.max_commands = 8.0
                state.budgets.max_cycles = 12.0
            elif c == "medium":
                state.budgets.max_commands = 12.0
                state.budgets.max_cycles = 16.0
            elif c == "high":
                state.budgets.max_commands = 18.0
                state.budgets.max_cycles = 25.0

    elif t == EventType.StepProposed:
        p: StepProposedPayload = event.payload
        s = p.step
        state.steps[s.step_id] = s

    elif t == EventType.PolicyDecision:
        p: PolicyDecisionPayload = event.payload
        state.policy_decisions[p.step_id] = p
        if p.decision.value == "require_approval":
            state.phase = IncidentPhase.awaiting_approval
        elif p.decision.value == "deny":
            if p.step_id in state.steps:
                state.steps[p.step_id] = replace(state.steps[p.step_id], status="rejected")

    elif t == EventType.ApprovalRequested:
        p: ApprovalRequestedPayload = event.payload
        state.pending_approval_step = p.step_id
        state.approvals[p.approval_id] = p

    elif t == EventType.ApprovalGranted:
        p: ApprovalGrantedPayload = event.payload
        if event.auth_tag and not getattr(p, "auth_tag", None):
            p = replace(p, auth_tag=event.auth_tag)
        state.approvals[p.approval_id] = p
        state.pending_approval_step = None

    elif t in (EventType.ApprovalDenied, EventType.ApprovalRejected):
        p = event.payload
        aid = p.approval_id
        state.approvals[aid] = p
        state.pending_approval_step = None
        if getattr(p, "step_id", None) and p.step_id in state.steps:
            state.steps[p.step_id] = replace(state.steps[p.step_id], status="rejected")
        state.phase = IncidentPhase.escalated

    elif t == EventType.ApprovalExpired:
        p = event.payload
        aid = p.approval_id
        state.approvals[aid] = p
        state.pending_approval_step = None
        if state.phase == IncidentPhase.awaiting_approval:
            state.phase = IncidentPhase.investigating

    elif t == EventType.SnapshotTaken:
        pass  # Recorded in event stream; no-op on derived state

    elif t == EventType.ExecutionIntent:
        p: ExecutionIntentPayload = event.payload
        state.pending_intent = p.step_id
        state.phase = IncidentPhase.executing

    elif t == EventType.ExecutionResult:
        p: ExecutionResultPayload = event.payload
        state.pending_intent = None
        if p.step_id in state.steps:
            new_status = "executed" if p.status == "success" else "failed"
            state.steps[p.step_id] = replace(state.steps[p.step_id], status=new_status)
        if state.phase == IncidentPhase.executing:
            if p.status == "success":
                state.phase = IncidentPhase.verifying
            else:
                state.phase = IncidentPhase.escalated

    elif t == EventType.ReconcileOutcome:
        p: ReconcileOutcomePayload = event.payload
        state.pending_intent = None
        if p.status == ReconcileStatus.unknown:
            state.phase = IncidentPhase.escalated
        elif state.phase == IncidentPhase.executing:
            state.phase = IncidentPhase.verifying

    elif t == EventType.VerificationRequested:
        if state.phase not in (IncidentPhase.security_evidence, IncidentPhase.escalated,
                               IncidentPhase.resolved, IncidentPhase.aborted, IncidentPhase.concluded):
            state.phase = IncidentPhase.verifying

    elif t == EventType.VerificationRecorded:
        p: VerificationRecordedPayload = event.payload
        state.last_verification = p
        if p.step_id in state.steps:
            if p.verdict == VerificationVerdict.verified:
                state.steps[p.step_id] = replace(state.steps[p.step_id], status="succeeded")
                state.phase = IncidentPhase.investigating
            else:
                state.steps[p.step_id] = replace(state.steps[p.step_id], status="failed")

    elif t in (EventType.RollbackStarted, EventType.RollbackCompleted):
        if t == EventType.RollbackCompleted:
            p: RollbackCompletedPayload = event.payload
            if p.step_id in state.steps:
                state.steps[p.step_id] = replace(state.steps[p.step_id], status="failed")
            # Rollback succeeded and system returned to safe stable state:
            # Return phase to investigating to allow closed-loop recovery, unless subsequent escalation occurs
            if p.success:
                state.phase = IncidentPhase.investigating

    elif t == EventType.BudgetConsumed:
        p: BudgetConsumedPayload = event.payload
        bt = p.budget_type
        if hasattr(state.budgets, bt):
            current_val = getattr(state.budgets, bt)
            # Monotonic budget enforcement: new_total must be >= current_val (04 §9: budget only depletes)
            if p.new_total >= current_val:
                setattr(state.budgets, bt, p.new_total)

    elif t == EventType.Escalated:
        state.phase = IncidentPhase.escalated

    elif t == EventType.IncidentResolved:
        state.phase = IncidentPhase.resolved

    elif t == EventType.IncidentAborted:
        state.phase = IncidentPhase.aborted

    elif t == EventType.ConclusionProposed:
        payload = getattr(event, "payload", None)
        verdict = getattr(payload, "verdict", "concluded") if payload else "concluded"
        if verdict == "escalate":
            state.phase = IncidentPhase.escalated
        else:
            state.phase = IncidentPhase.concluded

    # WorkerStarted, NotificationSent: no-op on derived state

    return state


def fold(events: list[Event]) -> IncidentState:
    """
    Pure reducer (03 §4): state = fold(events).
    Requires sequence starting with IncidentOpened without gaps.
    """
    if not events:
        raise ValueError("fold requires at least one event (IncidentOpened)")

    first = events[0]
    if first.type != EventType.IncidentOpened:
        raise ValueError(f"First event must be IncidentOpened, got {first.type}")

    payload: IncidentOpenedPayload = first.payload
    state = _initial_state(first.incident_id, payload, first.ts)

    for event in events:
        state = _apply_one(state, event)

    return state


def fold_one(state: IncidentState, event: Event) -> IncidentState:
    """
    Applies a single event to an existing state (for incremental resumption).
    """
    return _apply_one(state, event)
