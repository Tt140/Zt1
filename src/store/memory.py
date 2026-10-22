"""
store/memory.py — In-memory EventStore implementation

Designed for fast unit tests and the conformance suite.
Supports concurrency via threading.Lock.
"""
from __future__ import annotations

import threading
import time
from typing import Optional
from dataclasses import dataclass, field

from ..domain.types import (
    Event, IncidentHeader,
    sha256_hex, canonical_json,
)
from .interface import AppendConflict, EventStoreBase, LeaseToken


@dataclass
class _LeaseEntry:
    worker_id: str
    token: str
    fencing_number: int
    expires_at: float  # time.monotonic()


class MemoryEventStore(EventStoreBase):
    """
    In-memory EventStore implementation — passes CS-01..11.
    Thread-safe via per-incident lock and global lock for create_if_absent.
    """

    def __init__(self) -> None:
        self._global_lock = threading.Lock()
        # incident_id → list[Event]
        self._events: dict[str, list[Event]] = {}
        # incident_id → IncidentHeader
        self._headers: dict[str, IncidentHeader] = {}
        # dedupe_key → incident_id
        self._dedupe: dict[str, str] = {}
        # incident_id → threading.Lock
        self._incident_locks: dict[str, threading.Lock] = {}
        # incident_id → _LeaseEntry | None
        self._leases: dict[str, Optional[_LeaseEntry]] = {}
        # SHA-256 ref → bytes
        self._blobs: dict[str, bytes] = {}
        self._blob_lock = threading.Lock()
        # fencing counter per incident
        self._fencing_counter: dict[str, int] = {}

    def _get_or_create_lock(self, incident_id: str) -> threading.Lock:
        with self._global_lock:
            if incident_id not in self._incident_locks:
                self._incident_locks[incident_id] = threading.Lock()
            return self._incident_locks[incident_id]

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def create_if_absent(
        self, dedupe_key: str, header: IncidentHeader
    ) -> tuple[str, bool]:
        with self._global_lock:
            if dedupe_key in self._dedupe:
                return self._dedupe[dedupe_key], False
            incident_id = header.incident_id
            self._dedupe[dedupe_key] = incident_id
            self._headers[incident_id] = header
            self._events[incident_id] = []
            self._incident_locks[incident_id] = threading.Lock()
            self._leases[incident_id] = None
            self._fencing_counter[incident_id] = 0
            return incident_id, True

    def append(
        self,
        incident_id: str,
        expected_seq: int,
        event: Event,
    ) -> Event:
        lock = self._get_or_create_lock(incident_id)
        with lock:
            events = self._events.get(incident_id)
            if events is None:
                raise KeyError(f"incident_id {incident_id!r} not found")

            current_seq = len(events)  # seq starts at 1 -> len = latest seq

            # Idempotency check: does event_id already exist?
            for existing in events:
                if existing.event_id == event.event_id:
                    # If associated with a different incident -> explicit conflict
                    if existing.incident_id != incident_id:
                        raise AppendConflict(current_seq=current_seq)
                    return existing  # Safe idempotent retry (CS-03)

            if current_seq != expected_seq:
                raise AppendConflict(current_seq=current_seq)

            # Assemble finalized event
            new_seq = current_seq + 1
            prev_hash = events[-1].hash if events else None

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
            # Compute hash (covers all fields except hash itself)
            completed.hash = completed.compute_hash()
            events.append(completed)
            return completed

    def read(self, incident_id: str, from_seq: int = 1) -> list[Event]:
        lock = self._get_or_create_lock(incident_id)
        with lock:
            events = self._events.get(incident_id)
            if events is None:
                raise KeyError(f"incident_id {incident_id!r} not found")
            # from_seq is 1-indexed -> index = from_seq - 1
            return list(events[max(0, from_seq - 1):])

    def get_header(self, incident_id: str) -> Optional[IncidentHeader]:
        return self._headers.get(incident_id)

    def last_seq(self, incident_id: str) -> int:
        lock = self._get_or_create_lock(incident_id)
        with lock:
            events = self._events.get(incident_id, [])
            return len(events)

    # ------------------------------------------------------------------
    # Lease
    # ------------------------------------------------------------------

    def acquire_lease(
        self, incident_id: str, worker_id: str, ttl_seconds: float
    ) -> Optional[LeaseToken]:
        lock = self._get_or_create_lock(incident_id)
        with lock:
            entry = self._leases.get(incident_id)
            now = time.monotonic()
            if entry is not None and entry.expires_at > now:
                if entry.worker_id != worker_id:
                    return None  # Lease held by another worker
            # Grant lease
            self._fencing_counter[incident_id] = self._fencing_counter.get(incident_id, 0) + 1
            fencing = self._fencing_counter[incident_id]
            import secrets
            tok = secrets.token_hex(16)
            self._leases[incident_id] = _LeaseEntry(
                worker_id=worker_id,
                token=tok,
                fencing_number=fencing,
                expires_at=now + ttl_seconds,
            )
            return LeaseToken(token=tok, fencing_number=fencing)

    def renew_lease(self, incident_id: str, token: LeaseToken, ttl_seconds: float) -> bool:
        lock = self._get_or_create_lock(incident_id)
        with lock:
            entry = self._leases.get(incident_id)
            now = time.monotonic()
            if entry is None or entry.token != token.token or entry.expires_at <= now:
                return False
            entry.expires_at = now + ttl_seconds
            return True

    def release_lease(self, incident_id: str, token: LeaseToken) -> None:
        lock = self._get_or_create_lock(incident_id)
        with lock:
            entry = self._leases.get(incident_id)
            if entry and entry.token == token.token:
                self._leases[incident_id] = None

    # ------------------------------------------------------------------
    # Blobs
    # ------------------------------------------------------------------

    def put_blob(self, data: bytes) -> str:
        ref = sha256_hex(data)
        with self._blob_lock:
            self._blobs[ref] = data
        return ref

    def get_blob(self, ref: str) -> bytes:
        with self._blob_lock:
            if ref not in self._blobs:
                raise KeyError(f"blob ref {ref!r} not found")
            data = self._blobs[ref]
        # Verify content integrity
        actual = sha256_hex(data)
        if actual != ref:
            raise ValueError(
                f"Blob integrity violation: hash={actual!r}, expected={ref!r}"
            )
        return data

    # ------------------------------------------------------------------
    # Chain verification (CS-08)
    # ------------------------------------------------------------------

    def verify_chain(self, incident_id: str) -> bool:
        lock = self._get_or_create_lock(incident_id)
        with lock:
            events = self._events.get(incident_id)
            if events is None:
                raise KeyError(f"incident_id {incident_id!r} not found")
            if not events:
                return True

            for i, ev in enumerate(events):
                # Verify seq sequence
                if ev.seq != i + 1:
                    return False
                # Verify prev_hash
                expected_prev = events[i - 1].hash if i > 0 else None
                if ev.prev_hash != expected_prev:
                    return False
                # Verify hash
                if ev.compute_hash() != ev.hash:
                    return False
            return True
