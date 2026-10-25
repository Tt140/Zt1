"""
store/sqlite_store.py — SQLite EventStore implementation

Supports persistence and resumption across runs.
Uses WAL mode + transactions to ensure proper CAS semantics.

Note: SQLite :memory: is not shared across threads by default when using
check_same_thread=False. Therefore, we use a single shared connection with a write
lock for memory DBs, or per-thread connections for persistent file DBs.
"""
from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from ..domain.types import (
    Actor,
    Event,
    EventType,
    IncidentHeader,
    sha256_hex,
)
from .interface import AppendConflict, EventStoreBase, LeaseToken


def _payload_to_dict(payload) -> dict:
    if dataclasses.is_dataclass(payload) and not isinstance(payload, type):
        return dataclasses.asdict(payload)
    if isinstance(payload, dict):
        return payload
    return {"raw": str(payload)}


# ---------------------------------------------------------------------------
# Registry for deserializing raw dict payloads back into typed dataclasses
# ---------------------------------------------------------------------------
# Each EventType maps to its corresponding payload dataclass
# Rule: Enum values are converted inside __post_init__ or during reconstruction

from ..domain.types import (
    IncidentOpenedPayload, WorkerStartedPayload,
    ObservationRequestedPayload, ObservationRecordedPayload,
    EvidenceAddedPayload, EvidenceRef, TrustLevel,
    HypothesisUpdatedPayload, HypothesisRecord, HypothesisStatus,
    StepProposedPayload, StepRecord, DeclaredEffect, EffectCategory, StepKind,
    PolicyDecisionPayload, Tier, PolicyDecisionValue,
    ApprovalRequestedPayload, ApprovalGrantedPayload,
    ApprovalDeniedPayload, ApprovalRejectedPayload, ApprovalExpiredPayload,
    SnapshotTakenPayload, ExecutionIntentPayload, ExecutionResultPayload,
    ReconcileOutcomePayload, ReconcileStatus,
    VerificationRequestedPayload, VerificationRecordedPayload,
    VerificationCheck, StabilityWindow, VerificationVerdict,
    RollbackStartedPayload, RollbackCompletedPayload,
    SecurityLatchEngagedPayload, BudgetConsumedPayload,
    EscalatedPayload, IncidentResolvedPayload, IncidentAbortedPayload,
    LatchReleasedByHumanPayload, ConclusionProposedPayload,
    NotificationSentPayload,
)


def _rebuild_evidence_ref(d: dict) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=d["evidence_id"],
        source=d["source"],
        trust=TrustLevel(d["trust"]),
        collected_at=d["collected_at"],
        raw_ref=d.get("raw_ref"),
        integrity_hash=d.get("integrity_hash"),
        summary=d["summary"],
        redaction_report=d.get("redaction_report", {}),
    )


def _rebuild_payload(event_type: EventType, d: dict):
    """Rebuilds typed dataclass payload from serialized dictionary."""
    t = event_type
    try:
        if t == EventType.IncidentOpened:
            return IncidentOpenedPayload(**d)
        elif t == EventType.WorkerStarted:
            return WorkerStartedPayload(**d)
        elif t == EventType.ObservationRequested:
            return ObservationRequestedPayload(**d)
        elif t == EventType.ObservationRecorded:
            ev = _rebuild_evidence_ref(d["evidence"])
            return ObservationRecordedPayload(request_id=d["request_id"], evidence=ev)
        elif t == EventType.EvidenceAdded:
            ev = _rebuild_evidence_ref(d["evidence"])
            return EvidenceAddedPayload(evidence=ev)
        elif t == EventType.HypothesisUpdated:
            h = d["hypothesis"]
            hyp = HypothesisRecord(
                hypothesis_id=h["hypothesis_id"],
                statement=h["statement"],
                confidence=h["confidence"],
                supporting=h["supporting"],
                contradicting=h["contradicting"],
                status=HypothesisStatus(h["status"]),
                next_check=h.get("next_check"),
                trigger_evidence_id=h["trigger_evidence_id"],
            )
            return HypothesisUpdatedPayload(hypothesis=hyp)
        elif t == EventType.StepProposed:
            s = d["step"]
            effects = [DeclaredEffect(
                category=EffectCategory(e["category"]),
                resource=e["resource"],
                description=e["description"],
            ) for e in s.get("declared_effects", [])]
            step = StepRecord(
                step_id=s["step_id"],
                incident_id=s["incident_id"],
                based_on_hypotheses=s["based_on_hypotheses"],
                based_on_evidence=s["based_on_evidence"],
                kind=StepKind(s["kind"]),
                target=s["target"],
                execution_spec=s["execution_spec"],
                declared_effects=effects,
                preconditions=s["preconditions"],
                success_criteria=s["success_criteria"],
                rollback_plan=s["rollback_plan"],
                rollback_reason=s.get("rollback_reason"),
                idempotent=s["idempotent"],
                risk_claim=s["risk_claim"],
                expires_at=s["expires_at"],
                plan_hash=s["plan_hash"],
            )
            return StepProposedPayload(step=step)
        elif t == EventType.PolicyDecision:
            return PolicyDecisionPayload(
                step_id=d["step_id"],
                plan_hash=d["plan_hash"],
                tier=Tier(d["tier"]),
                decision=PolicyDecisionValue(d["decision"]),
                reasons=d["reasons"],
                rule_ids=d["rule_ids"],
                budget_snapshot=d["budget_snapshot"],
                gate_version=d["gate_version"],
            )
        elif t == EventType.ApprovalRequested:
            return ApprovalRequestedPayload(**d)
        elif t == EventType.ApprovalGranted:
            return ApprovalGrantedPayload(**d)
        elif t == EventType.ApprovalDenied:
            return ApprovalDeniedPayload(**d)
        elif t == EventType.ApprovalRejected:
            return ApprovalRejectedPayload(**d)
        elif t == EventType.ApprovalExpired:
            return ApprovalExpiredPayload(**d)
        elif t == EventType.SnapshotTaken:
            return SnapshotTakenPayload(**d)
        elif t == EventType.ExecutionIntent:
            return ExecutionIntentPayload(**d)
        elif t == EventType.ExecutionResult:
            return ExecutionResultPayload(**d)
        elif t == EventType.ReconcileOutcome:
            return ReconcileOutcomePayload(
                step_id=d["step_id"],
                plan_hash=d["plan_hash"],
                status=ReconcileStatus(d["status"]),
                details=d["details"],
            )
        elif t == EventType.VerificationRequested:
            return VerificationRequestedPayload(**d)
        elif t == EventType.VerificationRecorded:
            checks = [VerificationCheck(**c) for c in d["checks"]]
            side = [VerificationCheck(**c) for c in d["side_effect_checks"]]
            sw = StabilityWindow(**d["stability_window"])
            return VerificationRecordedPayload(
                step_id=d["step_id"],
                plan_hash=d["plan_hash"],
                checks=checks,
                alarm_state=d["alarm_state"],
                stability_window=sw,
                side_effect_checks=side,
                verdict=VerificationVerdict(d["verdict"]),
            )
        elif t == EventType.RollbackStarted:
            return RollbackStartedPayload(**d)
        elif t == EventType.RollbackCompleted:
            return RollbackCompletedPayload(**d)
        elif t == EventType.SecurityLatchEngaged:
            return SecurityLatchEngagedPayload(**d)
        elif t == EventType.BudgetConsumed:
            return BudgetConsumedPayload(**d)
        elif t == EventType.Escalated:
            return EscalatedPayload(**d)
        elif t == EventType.IncidentResolved:
            return IncidentResolvedPayload(**d)
        elif t == EventType.IncidentAborted:
            return IncidentAbortedPayload(**d)
        elif t == EventType.LatchReleasedByHuman:
            return LatchReleasedByHumanPayload(**d)
        elif t == EventType.ConclusionProposed:
            return ConclusionProposedPayload(**d)
        elif t == EventType.NotificationSent:
            return NotificationSentPayload(**d)
        else:
            # Unknown event type — fallback to dict (reducer will flag policy violation)
            return d
    except Exception as exc:
        # Reconstruction failed — raise clear ValueError rather than silently returning raw dict
        raise ValueError(
            f"Failed to rebuild payload for {event_type.value}: {exc}"
        ) from exc


def _event_from_row(row: dict) -> Event:
    """Reconstructs Event instance from database row including typed payload."""
    raw_dict = json.loads(row["payload"])
    event_type = EventType(row["type"])
    payload = _rebuild_payload(event_type, raw_dict)
    return Event(
        incident_id=row["incident_id"],
        seq=row["seq"],
        event_id=row["event_id"],
        type=event_type,
        ts=row["ts"],
        actor=Actor(row["actor"]),
        payload=payload,
        prev_hash=row["prev_hash"],
        hash=row["hash"],
        writer_token=row["writer_token"],
        auth_tag=row["auth_tag"],
        schema_version=row["schema_version"],
    )


class SQLiteEventStore(EventStoreBase):
    """
    SQLite-backed EventStore implementation.
    - WAL mode for enhanced concurrency.
    - STRICT + INTEGER PRIMARY KEY preventing sequence gaps.
    - CAS guaranteed via write lock + last_seq counter in incidents table.
    - File DB: thread-local read connections.
    - Memory DB (:memory:): single shared connection (since in-memory DBs cannot be shared across threads).
    """

    DDL = """
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id     TEXT PRIMARY KEY,
        dedupe_key      TEXT UNIQUE NOT NULL,
        header_json     TEXT NOT NULL,
        last_seq        INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS events (
        incident_id     TEXT NOT NULL,
        seq             INTEGER NOT NULL,
        event_id        TEXT NOT NULL UNIQUE,
        type            TEXT NOT NULL,
        ts              TEXT NOT NULL,
        actor           TEXT NOT NULL,
        payload         TEXT NOT NULL,
        prev_hash       TEXT,
        hash            TEXT NOT NULL,
        writer_token    TEXT,
        auth_tag        TEXT,
        schema_version  TEXT NOT NULL DEFAULT '1.0',
        PRIMARY KEY (incident_id, seq),
        FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
    );

    CREATE TABLE IF NOT EXISTS leases (
        incident_id     TEXT PRIMARY KEY,
        worker_id       TEXT NOT NULL,
        token           TEXT NOT NULL,
        fencing_number  INTEGER NOT NULL,
        expires_at_unix REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS blobs (
        ref             TEXT PRIMARY KEY,
        data            BLOB NOT NULL
    );
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._write_lock = threading.Lock()
        # Single shared connection for writes (protected by _write_lock)
        # For reads: same connection for in-memory, or per-thread connections for file DBs
        self._write_conn = sqlite3.connect(
            self._db_path, check_same_thread=False
        )
        self._write_conn.row_factory = sqlite3.Row
        self._write_conn.execute("PRAGMA journal_mode=WAL")
        self._write_conn.execute("PRAGMA foreign_keys=ON")
        # Read-only thread-local connection for persistent files
        self._read_local = threading.local()
        self._is_memory = (self._db_path == ":memory:")
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        """Write connection — always acquired under _write_lock."""
        return self._write_conn

    def _read_conn(self) -> sqlite3.Connection:
        """
        Read connection.
        For in-memory: shared write connection (only option in SQLite :memory:).
        For persistent files: thread-local connection to prevent read starvation.
        """
        if self._is_memory:
            return self._write_conn
        if not hasattr(self._read_local, "conn") or self._read_local.conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._read_local.conn = conn
        return self._read_local.conn

    def _init_db(self) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.executescript(self.DDL)
            conn.commit()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def create_if_absent(
        self, dedupe_key: str, header: IncidentHeader
    ) -> tuple[str, bool]:
        with self._write_lock:
            conn = self._conn()
            try:
                header_json = json.dumps(dataclasses.asdict(header))
                conn.execute(
                    "INSERT INTO incidents (incident_id, dedupe_key, header_json, last_seq) "
                    "VALUES (?, ?, ?, 0)",
                    (header.incident_id, dedupe_key, header_json),
                )
                conn.commit()
                return header.incident_id, True
            except sqlite3.IntegrityError:
                # dedupe_key already exists
                row = conn.execute(
                    "SELECT incident_id FROM incidents WHERE dedupe_key = ?",
                    (dedupe_key,),
                ).fetchone()
                return row["incident_id"], False

    def release_dedupe(self, dedupe_key: str) -> bool:
        with self._write_lock:
            conn = self._conn()
            ts = int(time.time() * 1000)
            cursor = conn.execute(
                "UPDATE incidents SET dedupe_key = ? WHERE dedupe_key = ?",
                (f"released::{ts}::{dedupe_key}", dedupe_key),
            )
            conn.commit()
            return cursor.rowcount > 0

    def append(
        self,
        incident_id: str,
        expected_seq: int,
        event: Event,
    ) -> Event:
        with self._write_lock:
            conn = self._conn()

            # Idempotency check
            existing = conn.execute(
                "SELECT incident_id FROM events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            if existing:
                if existing["incident_id"] != incident_id:
                    raise AppendConflict(
                        current_seq=row["last_seq"] if (
                            row := conn.execute(
                                "SELECT last_seq FROM incidents WHERE incident_id = ?",
                                (incident_id,),
                            ).fetchone()
                        ) else 0
                    )
                # Same event_id and incident_id — return existing event idempotently
                full_row = conn.execute(
                    "SELECT * FROM events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()
                return _event_from_row(dict(full_row))

            # Read current last_seq
            row = conn.execute(
                "SELECT last_seq FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"incident_id {incident_id!r} not found")

            current_seq = row["last_seq"]
            if current_seq != expected_seq:
                raise AppendConflict(current_seq=current_seq)

            new_seq = current_seq + 1

            # Compute prev_hash
            if current_seq > 0:
                prev_row = conn.execute(
                    "SELECT hash FROM events WHERE incident_id = ? AND seq = ?",
                    (incident_id, current_seq),
                ).fetchone()
                prev_hash = prev_row["hash"] if prev_row else None
            else:
                prev_hash = None

            # Assemble finalized event
            completed = Event(
                incident_id=event.incident_id,
                seq=new_seq,
                event_id=event.event_id,
                type=event.type,
                ts=event.ts,
                actor=event.actor,
                payload=event.payload,
                prev_hash=prev_hash,
                hash=None,
                writer_token=event.writer_token,
                auth_tag=event.auth_tag,
                schema_version=event.schema_version,
            )
            completed.hash = completed.compute_hash()

            payload_json = json.dumps(_payload_to_dict(event.payload), sort_keys=True)

            try:
                conn.execute(
                    "INSERT INTO events "
                    "(incident_id, seq, event_id, type, ts, actor, payload, "
                    " prev_hash, hash, writer_token, auth_tag, schema_version) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        incident_id, new_seq, event.event_id,
                        event.type.value, event.ts, event.actor.value,
                        payload_json, prev_hash, completed.hash,
                        event.writer_token, event.auth_tag, event.schema_version,
                    ),
                )
                conn.execute(
                    "UPDATE incidents SET last_seq = ? WHERE incident_id = ?",
                    (new_seq, incident_id),
                )
                conn.commit()
            except sqlite3.IntegrityError as e:
                conn.rollback()
                # A concurrent race condition may have inserted duplicate event_id
                existing = conn.execute(
                    "SELECT * FROM events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()
                if existing:
                    return _event_from_row(dict(existing))
                raise AppendConflict(current_seq=current_seq) from e

            return completed

    def read(self, incident_id: str, from_seq: int = 1) -> list[Event]:
        conn = self._read_conn()
        rows = conn.execute(
            "SELECT * FROM events WHERE incident_id = ? AND seq >= ? ORDER BY seq",
            (incident_id, from_seq),
        ).fetchall()
        return [_event_from_row(dict(r)) for r in rows]

    def get_header(self, incident_id: str) -> Optional[IncidentHeader]:
        conn = self._read_conn()
        row = conn.execute(
            "SELECT header_json FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        d = json.loads(row["header_json"])
        return IncidentHeader(**d)

    def last_seq(self, incident_id: str) -> int:
        conn = self._read_conn()
        row = conn.execute(
            "SELECT last_seq FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        return row["last_seq"] if row else 0

    # ------------------------------------------------------------------
    # Lease
    # ------------------------------------------------------------------

    def acquire_lease(
        self, incident_id: str, worker_id: str, ttl_seconds: float
    ) -> Optional[LeaseToken]:
        import secrets
        with self._write_lock:
            conn = self._conn()
            now = time.time()
            row = conn.execute(
                "SELECT * FROM leases WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if row and row["expires_at_unix"] > now and row["worker_id"] != worker_id:
                return None
            # Compute monotonic fencing number
            fencing = (row["fencing_number"] + 1) if row else 1
            tok = secrets.token_hex(16)
            conn.execute(
                "INSERT OR REPLACE INTO leases "
                "(incident_id, worker_id, token, fencing_number, expires_at_unix) "
                "VALUES (?, ?, ?, ?, ?)",
                (incident_id, worker_id, tok, fencing, now + ttl_seconds),
            )
            conn.commit()
            return LeaseToken(token=tok, fencing_number=fencing)

    def renew_lease(self, incident_id: str, token: LeaseToken, ttl_seconds: float) -> bool:
        with self._write_lock:
            conn = self._conn()
            now = time.time()
            row = conn.execute(
                "SELECT * FROM leases WHERE incident_id = ? AND token = ?",
                (incident_id, token.token),
            ).fetchone()
            if not row or row["expires_at_unix"] <= now:
                return False
            conn.execute(
                "UPDATE leases SET expires_at_unix = ? WHERE incident_id = ?",
                (now + ttl_seconds, incident_id),
            )
            conn.commit()
            return True

    def release_lease(self, incident_id: str, token: LeaseToken) -> None:
        """
        Releases the lease by zeroing out expires_at without deleting the row,
        preserving fencing_number monotonicity (03 §2: monotonically increasing token).
        """
        with self._write_lock:
            conn = self._conn()
            # Update rather than delete: zero out TTL while retaining fencing_number
            conn.execute(
                "UPDATE leases SET expires_at_unix = 0, worker_id = '', token = '' "
                "WHERE incident_id = ? AND token = ?",
                (incident_id, token.token),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Blobs
    # ------------------------------------------------------------------

    def put_blob(self, data: bytes) -> str:
        ref = sha256_hex(data)
        with self._write_lock:
            conn = self._conn()
            conn.execute(
                "INSERT OR IGNORE INTO blobs (ref, data) VALUES (?, ?)",
                (ref, data),
            )
            conn.commit()
        return ref

    def get_blob(self, ref: str) -> bytes:
        conn = self._read_conn()
        row = conn.execute(
            "SELECT data FROM blobs WHERE ref = ?", (ref,)
        ).fetchone()
        if row is None:
            raise KeyError(f"blob ref {ref!r} not found")
        data = bytes(row["data"])
        # Verify content-addressed integrity
        actual = sha256_hex(data)
        if actual != ref:
            raise ValueError(
                f"Blob integrity violation: stored data has hash {actual!r}, "
                f"expected {ref!r}"
            )
        return data

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    def verify_chain(self, incident_id: str) -> bool:
        events = self.read(incident_id)
        if not events:
            return True
        for i, ev in enumerate(events):
            if ev.seq != i + 1:
                return False
            expected_prev = events[i - 1].hash if i > 0 else None
            if ev.prev_hash != expected_prev:
                return False
            if ev.compute_hash() != ev.hash:
                return False
        return True
