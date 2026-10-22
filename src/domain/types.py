"""
domain/types.py — Data contracts (02-data-contracts.md)
Types here are strictly deterministic: no I/O, no system clock, no randomness.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional, Union
from dataclasses import dataclass, field

from ulid import ULID


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def new_ulid() -> str:
    return str(ULID())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON: sorted keys, compact separators, UTF-8 encoded (02 §General Rules)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Actor(str, Enum):
    ingest = "ingest"
    agent = "agent"
    executor = "executor"
    verifier = "verifier"
    notifier = "notifier"
    slack_callback = "slack_callback"
    system = "system"  # Internal use (reconciliation, lease expiry)


class EventType(str, Enum):
    IncidentOpened = "IncidentOpened"
    WorkerStarted = "WorkerStarted"
    ObservationRequested = "ObservationRequested"
    ObservationRecorded = "ObservationRecorded"
    EvidenceAdded = "EvidenceAdded"
    HypothesisUpdated = "HypothesisUpdated"
    StepProposed = "StepProposed"
    PolicyDecision = "PolicyDecision"
    ApprovalRequested = "ApprovalRequested"
    ApprovalGranted = "ApprovalGranted"
    ApprovalDenied = "ApprovalDenied"
    ApprovalRejected = "ApprovalRejected"
    ApprovalExpired = "ApprovalExpired"
    SnapshotTaken = "SnapshotTaken"
    ExecutionIntent = "ExecutionIntent"
    ExecutionResult = "ExecutionResult"
    ReconcileOutcome = "ReconcileOutcome"
    VerificationRequested = "VerificationRequested"
    VerificationRecorded = "VerificationRecorded"
    RollbackStarted = "RollbackStarted"
    RollbackCompleted = "RollbackCompleted"
    SecurityLatchEngaged = "SecurityLatchEngaged"
    BudgetConsumed = "BudgetConsumed"
    Escalated = "Escalated"
    IncidentResolved = "IncidentResolved"
    IncidentAborted = "IncidentAborted"
    LatchReleasedByHuman = "LatchReleasedByHuman"
    ConclusionProposed = "ConclusionProposed"
    NotificationSent = "NotificationSent"


class IncidentPhase(str, Enum):
    investigating = "investigating"
    awaiting_approval = "awaiting_approval"
    executing = "executing"
    verifying = "verifying"
    monitoring = "monitoring"
    security_evidence = "security_evidence"
    escalated = "escalated"
    resolved = "resolved"
    aborted = "aborted"
    # Terminal phase upon conclusion
    concluded = "concluded"
    closed = "closed"


class EffectCategory(str, Enum):
    E0 = "E0"  # Read-only
    E1 = "E1"  # Process-level impact, reversible
    E2 = "E2"  # File/config modification within allowed paths
    E3 = "E3"  # Ephemeral/temp data cleanup within allowed paths
    E4 = "E4"  # Non-reversible deletion/change
    E5 = "E5"  # Security-sensitive
    EU = "EU"  # Unknown/undefined


class Tier(str, Enum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


class TrustLevel(str, Enum):
    host_reported = "host_reported"
    out_of_band = "out_of_band"


class HypothesisStatus(str, Enum):
    active = "active"
    refuted = "refuted"
    confirmed = "confirmed"
    superseded = "superseded"


class StepKind(str, Enum):
    observe = "observe"
    mutate = "mutate"
    verify = "verify"
    escalate = "escalate"


class PolicyDecisionValue(str, Enum):
    allow = "allow"
    require_approval = "require_approval"
    deny = "deny"


class ReconcileStatus(str, Enum):
    executed = "executed"
    not_executed = "not_executed"
    unknown = "unknown"


class VerificationVerdict(str, Enum):
    verified = "verified"
    not_verified = "not_verified"
    failed = "failed"
    inconclusive = "inconclusive"


# ---------------------------------------------------------------------------
# Payload types (dataclasses — no I/O)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IncidentOpenedPayload:
    instance_id: str
    dedupe_key: str
    alarm_name: str
    alarm_arn: str
    alert_source: str  # EventBridge rule ARN
    alarm_description: Optional[str] = ""


@dataclass(frozen=True)
class WorkerStartedPayload:
    worker_id: str
    lease_token: Optional[str] = None


@dataclass(frozen=True)
class ObservationRequestedPayload:
    request_id: str
    tool: str
    query: str
    target: str  # instance_id


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    source: str
    trust: TrustLevel
    collected_at: str  # ISO-8601
    raw_ref: Optional[str]
    integrity_hash: Optional[str]
    summary: str
    redaction_report: dict[str, Any]


@dataclass(frozen=True)
class ObservationRecordedPayload:
    request_id: str
    evidence: EvidenceRef


@dataclass(frozen=True)
class EvidenceAddedPayload:
    evidence: EvidenceRef


@dataclass(frozen=True)
class HypothesisRecord:
    hypothesis_id: str
    statement: str
    confidence: float  # 0-1
    supporting: list[str]  # evidence_ids
    contradicting: list[str]  # evidence_ids
    status: HypothesisStatus
    next_check: Optional[str]
    trigger_evidence_id: str  # Evidence that triggered this update
    complexity: Optional[str] = None


@dataclass(frozen=True)
class HypothesisUpdatedPayload:
    hypothesis: HypothesisRecord
    complexity: Optional[str] = None


HypothesisCreatedPayload = HypothesisUpdatedPayload


@dataclass(frozen=True)
class DeclaredEffect:
    category: EffectCategory
    resource: str
    description: str


@dataclass(frozen=True)
class StepRecord:
    step_id: str
    incident_id: str
    based_on_hypotheses: list[str]
    based_on_evidence: list[str]
    kind: StepKind
    target: str
    execution_spec: dict[str, Any]
    declared_effects: list[DeclaredEffect]
    preconditions: list[str]
    success_criteria: list[dict[str, Any]]
    rollback_plan: Union[list[dict[str, Any]], Literal["none"]]
    rollback_reason: Optional[str]  # Required if rollback_plan="none"
    idempotent: bool
    risk_claim: str
    expires_at: str
    plan_hash: str
    status: Optional[str] = "proposed"


@dataclass(frozen=True)
class StepProposedPayload:
    step: StepRecord


@dataclass(frozen=True)
class PolicyDecisionPayload:
    step_id: str
    plan_hash: str
    tier: Tier
    decision: PolicyDecisionValue
    reasons: list[str]
    rule_ids: list[str]
    budget_snapshot: dict[str, Any]
    gate_version: str


@dataclass(frozen=True)
class ApprovalRequestedPayload:
    approval_id: str
    step_id: str
    plan_hash: str
    expires_at: str
    notification_ref: Optional[str]


@dataclass(frozen=True)
class ApprovalGrantedPayload:
    approval_id: str
    step_id: str
    plan_hash: str
    approver_id: str
    issued_at: str
    expires_at: str
    nonce: str
    auth_tag: Optional[str] = None
    # auth_tag lives in event envelope for ApprovalGranted


@dataclass(frozen=True)
class ApprovalDeniedPayload:
    approval_id: str
    step_id: str
    approver_id: str
    reason: Optional[str]


@dataclass(frozen=True)
class ApprovalRejectedPayload:
    approval_id: str
    step_id: str
    approver_id: str
    reason: Optional[str] = None


@dataclass(frozen=True)
class ApprovalExpiredPayload:
    approval_id: str
    step_id: str


@dataclass(frozen=True)
class SnapshotTakenPayload:
    step_id: str
    plan_hash: str
    snapshot_ref: str  # blob ref
    integrity_hash: str


@dataclass(frozen=True)
class ExecutionIntentPayload:
    step_id: str
    plan_hash: str
    idempotency_key: str  # incident_id + step_id
    correlation_id: str
    fencing_seq: int  # seq of the ExecutionIntent event itself (set by store)


@dataclass(frozen=True)
class ExecutionResultPayload:
    step_id: str
    plan_hash: str
    status: str  # success | failure | timeout
    output_ref: Optional[str]
    post_snapshot_ref: Optional[str]
    declared_vs_observed: str  # "match" | "mismatch"
    mismatch_details: Optional[dict[str, Any]]


@dataclass(frozen=True)
class ReconcileOutcomePayload:
    step_id: str
    plan_hash: str
    status: ReconcileStatus
    details: str


@dataclass(frozen=True)
class VerificationRequestedPayload:
    step_id: str
    plan_hash: str


@dataclass(frozen=True)
class VerificationCheck:
    check_type: str
    result: str  # pass | fail | inconclusive
    source: str
    details: Optional[str]


@dataclass(frozen=True)
class StabilityWindow:
    duration_seconds: int
    result: str  # stable | unstable


@dataclass(frozen=True)
class VerificationRecordedPayload:
    step_id: str
    plan_hash: str
    checks: list[VerificationCheck]
    alarm_state: str
    stability_window: StabilityWindow
    side_effect_checks: list[VerificationCheck]
    verdict: VerificationVerdict


@dataclass(frozen=True)
class RollbackStartedPayload:
    step_id: str
    plan_hash: str
    reason: str


@dataclass(frozen=True)
class RollbackCompletedPayload:
    step_id: str
    plan_hash: str
    success: bool
    details: str


@dataclass(frozen=True)
class SecurityLatchEngagedPayload:
    reason: str
    trigger_source: str  # Component identifier that tripped the latch
    evidence_ids: list[str]


@dataclass(frozen=True)
class BudgetConsumedPayload:
    budget_type: str  # cycles | commands | steps | tokens | time_seconds
    amount: float
    new_total: float
    limit: float


@dataclass(frozen=True)
class EscalatedPayload:
    reason: str
    report_ref: Optional[str]


@dataclass(frozen=True)
class IncidentResolvedPayload:
    verification_id: str
    summary: str


@dataclass(frozen=True)
class IncidentAbortedPayload:
    reason: str


@dataclass(frozen=True)
class LatchReleasedByHumanPayload:
    released_by: str
    reason: str
    # auth_tag in envelope


@dataclass(frozen=True)
class ConclusionProposedPayload:
    verdict: str  # resolved | escalate
    summary: str
    based_on_evidence: list[str]


@dataclass(frozen=True)
class NotificationSentPayload:
    channel: str
    message_ts: Optional[str]
    notification_type: str


# ---------------------------------------------------------------------------
# Event Envelope (02 §1)
# ---------------------------------------------------------------------------

# Authorized writers per event type (G3 — 06-adrs.md write delegation matrix)
AUTHORIZED_WRITERS: dict[EventType, set[Actor]] = {
    EventType.IncidentOpened: {Actor.ingest},
    EventType.WorkerStarted: {Actor.agent, Actor.executor, Actor.verifier, Actor.notifier, Actor.slack_callback},
    EventType.ObservationRequested: {Actor.agent},
    EventType.ObservationRecorded: {Actor.agent, Actor.executor, Actor.verifier},
    EventType.EvidenceAdded: {Actor.agent, Actor.executor, Actor.verifier},
    EventType.HypothesisUpdated: {Actor.agent},
    EventType.StepProposed: {Actor.agent},
    EventType.PolicyDecision: {Actor.executor},
    EventType.ApprovalRequested: {Actor.executor},
    EventType.ApprovalGranted: {Actor.slack_callback},
    EventType.ApprovalDenied: {Actor.slack_callback},
    EventType.ApprovalRejected: {Actor.slack_callback, Actor.executor, Actor.system, Actor.agent},
    EventType.ApprovalExpired: {Actor.executor},
    EventType.SnapshotTaken: {Actor.executor},
    EventType.ExecutionIntent: {Actor.executor},
    EventType.ExecutionResult: {Actor.executor},
    EventType.ReconcileOutcome: {Actor.executor},
    EventType.VerificationRequested: {Actor.agent},
    EventType.VerificationRecorded: {Actor.verifier, Actor.executor},
    EventType.RollbackStarted: {Actor.executor},
    EventType.RollbackCompleted: {Actor.executor},
    EventType.SecurityLatchEngaged: {Actor.ingest, Actor.agent, Actor.executor, Actor.verifier},
    EventType.BudgetConsumed: {Actor.agent, Actor.executor, Actor.verifier},
    EventType.Escalated: {Actor.ingest, Actor.agent, Actor.executor, Actor.verifier},
    EventType.IncidentResolved: {Actor.verifier, Actor.agent},
    EventType.IncidentAborted: {Actor.ingest, Actor.agent, Actor.executor, Actor.verifier},
    EventType.LatchReleasedByHuman: {Actor.slack_callback},
    EventType.ConclusionProposed: {Actor.agent},
    EventType.NotificationSent: {Actor.notifier},
}

# Event types that carry auth_tag (G3)
AUTH_TAG_REQUIRED: set[EventType] = {EventType.ApprovalGranted, EventType.LatchReleasedByHuman}


@dataclass
class Event:
    """
    Event envelope (02 §1).
    Do not instantiate directly — use build_event or EventEnvelopeBuilder.
    hash and prev_hash are computed during append in EventStore.
    """
    incident_id: str
    seq: int  # Starts from 1, assigned by store
    event_id: str
    type: EventType
    ts: str  # ISO-8601 UTC
    actor: Actor
    payload: Any  # One of Payload dataclasses above
    prev_hash: Optional[str]  # None for the genesis event
    hash: Optional[str]  # Computed by store
    writer_token: Optional[str]
    auth_tag: Optional[str]  # HMAC-SHA256 required for ApprovalGranted and LatchReleasedByHuman
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Converts event to dictionary for serialization and hashing."""
        import dataclasses
        def _convert(v: Any) -> Any:
            if isinstance(v, Enum):
                return v.value
            if dataclasses.is_dataclass(v):
                return {k: _convert(val) for k, val in dataclasses.asdict(v).items()}
            if isinstance(v, list):
                return [_convert(i) for i in v]
            if isinstance(v, dict):
                return {k: _convert(val) for k, val in v.items()}
            return v

        return {
            "incident_id": self.incident_id,
            "seq": self.seq,
            "event_id": self.event_id,
            "type": self.type.value,
            "ts": self.ts,
            "actor": self.actor.value,
            "payload": _convert(self.payload),
            "prev_hash": self.prev_hash,
            "hash": self.hash,
            "writer_token": self.writer_token,
            "auth_tag": self.auth_tag,
            "schema_version": self.schema_version,
        }

    def compute_hash(self) -> str:
        """SHA-256 over canonical JSON representation (02 §General Rules)."""
        d = self.to_dict()
        d.pop("hash", None)  # hash field excluded from hash calculation
        return sha256_hex(canonical_json(d))


def build_event(
    *,
    incident_id: str,
    type: EventType,
    actor: Actor,
    payload: Any,
    writer_token: Optional[str] = None,
    auth_tag: Optional[str] = None,
    ts: Optional[str] = None,
) -> Event:
    """Creates incomplete event (seq=0 and blank hash) to be finalized by EventStore."""
    return Event(
        incident_id=incident_id,
        seq=0,  # placeholder
        event_id=new_ulid(),
        type=type,
        ts=ts or utc_now().isoformat(),
        actor=actor,
        payload=payload,
        prev_hash=None,  # placeholder
        hash=None,       # placeholder
        writer_token=writer_token,
        auth_tag=auth_tag,
    )


# ---------------------------------------------------------------------------
# Incident Header (derived from IncidentOpened)
# ---------------------------------------------------------------------------

@dataclass
class IncidentHeader:
    incident_id: str
    instance_id: str
    dedupe_key: str
    alarm_name: str
    alarm_arn: str
    alert_source: str
    opened_at: str


# ---------------------------------------------------------------------------
# Budget state
# ---------------------------------------------------------------------------

@dataclass
class BudgetState:
    cycles: float = 0.0
    commands: float = 0.0
    mutate_steps: float = 0.0
    tokens: float = 0.0
    active_time_seconds: float = 0.0

    # limits (from config, set once)
    max_cycles: float = 40.0
    max_commands: float = 30.0
    max_mutate_steps: float = 3.0
    max_active_seconds: float = 2700.0  # 45 min

    def is_exceeded(self, budget_type: str) -> bool:
        return getattr(self, budget_type, 0.0) >= getattr(self, f"max_{budget_type}", float("inf"))

    @property
    def observations(self) -> float:
        return self.commands

    @property
    def max_observations(self) -> float:
        return self.max_commands


# ---------------------------------------------------------------------------
# Derived IncidentState (reducer output — 02 §2)
# ---------------------------------------------------------------------------

@dataclass
class IncidentState:
    """
    Derived incident state — result of fold(events). Never written directly.
    Reducer is pure and deterministic (no I/O, no system clock).
    """
    incident_id: str
    instance_id: str
    dedupe_key: str
    phase: IncidentPhase
    security_latch: bool
    budgets: BudgetState
    hypotheses: dict[str, HypothesisRecord]   # hypothesis_id → record
    evidence: dict[str, EvidenceRef]           # evidence_id → ref
    steps: dict[str, StepRecord]               # step_id → record
    policy_decisions: dict[str, PolicyDecisionPayload]  # step_id → decision
    approvals: dict[str, Any]                  # approval_id → payload
    pending_approval_step: Optional[str]       # step_id awaiting approval
    pending_observation: Optional[str]         # request_id awaiting observation result
    pending_intent: Optional[str]              # step_id: ExecutionIntent without matching Result
    last_verification: Optional[VerificationRecordedPayload]
    last_seq: int
    last_hash: Optional[str]
    # Delegation violations detected during folding
    authorization_violations: list[dict[str, Any]]
    alarm_name: str = ""
    alert_source: str = ""
    alarm_description: str = ""

    @property
    def budget(self) -> BudgetState:
        return self.budgets

    @property
    def budget_used(self) -> BudgetState:
        return self.budgets


# Alias: EvidenceRef is also aliased as EvidenceRecord for agent consumption
EvidenceRecord = EvidenceRef
