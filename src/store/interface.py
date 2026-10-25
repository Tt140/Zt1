"""
store/interface.py — EventStore interface (03-eventstore-contract.md §2)

Required operations:
- create_if_absent: Atomic under concurrency
- append:           CAS on expected_seq
- read:             Ordered events without gaps, strong consistency
- acquire_lease / renew / release: Advisory optimization
- put_blob / get_blob: Content-addressed blobs
- verify_chain: Tamper detection

Every implementation must pass conformance/suite.py (CS-01..11).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from ..domain.types import Event, IncidentHeader


@dataclass
class AppendConflict(Exception):
    """Append rejected because seq does not match expected_seq."""
    current_seq: int

    def __str__(self) -> str:
        return f"AppendConflict(current_seq={self.current_seq})"


@dataclass
class LeaseToken:
    token: str
    fencing_number: int  # Monotonically increasing — stale worker rejected if smaller


class EventStoreBase(ABC):
    """
    Abstract interface for EventStore.
    Every implementation inherits from this and passes ConformanceSuite.
    """

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    @abstractmethod
    def create_if_absent(
        self, dedupe_key: str, header: IncidentHeader
    ) -> tuple[str, bool]:
        """
        Creates a new incident if dedupe_key does not already exist.
        Returns (incident_id, created: bool).
        Under concurrency: exactly one succeeds and others receive the existing ID.
        """

    @abstractmethod
    def release_dedupe(self, dedupe_key: str) -> bool:
        """
        Releases/removes the dedupe_key from the deduplication index upon incident resolution.
        Enables immediate reception of subsequent alarms on the same resource.
        Returns True if removed, False otherwise.
        """

    @abstractmethod
    def append(
        self,
        incident_id: str,
        expected_seq: int,
        event: Event,
    ) -> Event:
        """
        Appends an event if the latest seq equals expected_seq.
        Returns the finalized event (with seq, hash, and prev_hash).
        Raises AppendConflict if seq has changed.
        Retrying with the same event_id after an ambiguous failure is idempotent.
        """

    @abstractmethod
    def read(self, incident_id: str, from_seq: int = 1) -> list[Event]:
        """
        Returns events ordered by seq without gaps starting from from_seq.
        Strong consistency: immediately returns newly written events.
        """

    @abstractmethod
    def get_header(self, incident_id: str) -> Optional[IncidentHeader]:
        """Returns the incident header or None if not found."""

    @abstractmethod
    def last_seq(self, incident_id: str) -> int:
        """Returns the latest seq or 0 if no events exist."""

    # ------------------------------------------------------------------
    # Lease (advisory optimization — 03 §2)
    # ------------------------------------------------------------------

    @abstractmethod
    def acquire_lease(self, incident_id: str, worker_id: str, ttl_seconds: float) -> Optional[LeaseToken]:
        """Acquires a worker lease. Returns None if already held."""

    @abstractmethod
    def renew_lease(self, incident_id: str, token: LeaseToken, ttl_seconds: float) -> bool:
        """Renews an active lease. Returns False if expired."""

    @abstractmethod
    def release_lease(self, incident_id: str, token: LeaseToken) -> None:
        """Releases the held lease."""

    # ------------------------------------------------------------------
    # Blobs (03 §2)
    # ------------------------------------------------------------------

    @abstractmethod
    def put_blob(self, data: bytes) -> str:
        """
        Stores a content-addressed blob.
        Returns the reference key (SHA-256 hex).
        """

    @abstractmethod
    def get_blob(self, ref: str) -> bytes:
        """Returns blob data by reference. Raises KeyError if not found."""

    # ------------------------------------------------------------------
    # Chain verification (03 §2, T-15)
    # ------------------------------------------------------------------

    @abstractmethod
    def verify_chain(self, incident_id: str) -> bool:
        """
        Verifies the cryptographic hash chain for tamper detection.
        Returns True if intact.
        """
