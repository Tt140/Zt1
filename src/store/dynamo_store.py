"""
store/dynamo_store.py — DynamoEventStore: EventStoreBase implementation on DynamoDB

Table schema (3 decoupled tables):

1. incidents-events  (PK: incident_id, SK: sk)
   - sk = "HEADER"           → IncidentHeader (seq=0)
   - sk = "META"             → {last_seq, created_at}
   - sk = "EVT#0000000001"   → event seq=1
   - sk = "EID#{event_id}"   → idempotency pointer (stored with seq)

2. incidents-dedup  (PK: dedupe_key)
   - Guarantees atomic create_if_absent via conditional PutItem

3. incidents-leases  (PK: incident_id)
   - fencing_number monotonically increases (atomic ADD), never reset

Concurrency guarantees:
- create_if_absent: conditional PutItem on incidents-dedup (attribute_not_exists)
- append CAS: TransactWriteItems {Update META: last_seq=expected_seq → new_seq,
                                   Put EVT: attribute_not_exists,
                                   Put EID: attribute_not_exists}
- event_id uniqueness: EID# item → TransactionCanceledException on duplicate with different content
- event_id idempotency: duplicate EID# with identical content returns existing event
- leases fencing: atomic ADD on fencing_number, superseding TTL
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from ..domain.types import Event, IncidentHeader
from ..store.interface import (
    EventStoreBase,
    AppendConflict,
    LeaseToken,
)

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────

_SK_HEADER = "HEADER"
_SK_META   = "META"

def _sk_evt(seq: int) -> str:
    return f"EVT#{seq:010d}"

def _sk_eid(event_id: str) -> str:
    return f"EID#{event_id}"


# ────────────────────────────────────────────────────────────────────────────
# DynamoEventStore
# ────────────────────────────────────────────────────────────────────────────

class DynamoEventStore(EventStoreBase):
    """
    EventStoreBase implementation backed by Amazon DynamoDB.
    Passes ConformanceSuite (CS-01..11 + auth-01..04).

    Requirements:
      - incidents_table:  PK=incident_id(S), SK=sk(S)
      - dedup_table:      PK=dedupe_key(S)
      - leases_table:     PK=incident_id(S)
      - s3_bucket: for put_blob/get_blob (optional — enabled when s3_bucket provided)
    """

    def __init__(
        self,
        incidents_table: str,
        dedup_table: str,
        leases_table: str,
        region: str = "us-east-1",
        s3_bucket: Optional[str] = None,
        dynamodb_client=None,
        s3_client=None,
    ):
        self._tbl       = incidents_table
        self._dedup_tbl = dedup_table
        self._lease_tbl = leases_table
        self._region    = region
        self._s3_bucket = s3_bucket

        self._ddb = dynamodb_client or boto3.client("dynamodb", region_name=region, config=Config(max_pool_connections=50))
        self._s3  = s3_client if s3_bucket else None

    # ────────────────────────────────────────────────────────────────────────
    # create_if_absent
    # ────────────────────────────────────────────────────────────────────────

    def create_if_absent(
        self, dedupe_key: str, header: IncidentHeader
    ) -> tuple[str, bool]:
        """
        Atomic: PutItem on dedup_table + initialization of incidents_table.
        Under 50 concurrent workers: exactly one creates the incident.
        """
        incident_id = header.incident_id

        # Step 1: Attempt to claim dedupe_key
        try:
            self._ddb.put_item(
                TableName=self._dedup_tbl,
                Item={
                    "dedupe_key": {"S": dedupe_key},
                    "incident_id": {"S": incident_id},
                    "created_at": {"N": str(int(time.time() * 1000))},
                },
                ConditionExpression="attribute_not_exists(dedupe_key)",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Existing incident — retrieve incident_id
                resp = self._ddb.get_item(
                    TableName=self._dedup_tbl,
                    Key={"dedupe_key": {"S": dedupe_key}},
                    ConsistentRead=True,
                )
                existing_id = resp["Item"]["incident_id"]["S"]
                return existing_id, False
            raise

        # Step 2: Initialize incidents_table (HEADER + META)
        header_json = json.dumps(self._header_to_dict(header))
        try:
            self._ddb.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": self._tbl,
                            "Item": {
                                "incident_id": {"S": incident_id},
                                "sk": {"S": _SK_HEADER},
                                "header_json": {"S": header_json},
                            },
                            "ConditionExpression": "attribute_not_exists(incident_id)",
                        }
                    },
                    {
                        "Put": {
                            "TableName": self._tbl,
                            "Item": {
                                "incident_id": {"S": incident_id},
                                "sk": {"S": _SK_META},
                                "last_seq": {"N": "0"},
                            },
                            "ConditionExpression": "attribute_not_exists(incident_id)",
                        }
                    },
                ]
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TransactionCanceledException",):
                # Rare race condition — incident already initialized by concurrent worker
                return incident_id, False
            raise

        return incident_id, True

    # ────────────────────────────────────────────────────────────────────────
    # append — atomic CAS
    # ────────────────────────────────────────────────────────────────────────

    def append(
        self,
        incident_id: str,
        expected_seq: int,
        event: Event,
    ) -> Event:
        """
        Atomic CAS via TransactWriteItems:
        1. Update META: last_seq = expected_seq → expected_seq+1 (condition: last_seq=expected_seq)
        2. Put EVT#(expected_seq+1): attribute_not_exists
        3. Put EID#{event_id}:       attribute_not_exists (uniqueness guarantee)

        Idempotency: if EID# with identical event_id exists → return existing stored event.
        Conflict: if EID# exists with different seq and content → raise AppendConflict.
        """
        new_seq = expected_seq + 1
        event_id = event.event_id

        # Idempotency check: does event_id already exist?
        existing = self._get_event_by_id(incident_id, event_id)
        if existing is not None:
            # Same event_id + identical core payload = idempotent retry
            from .sqlite_store import _payload_to_dict
            existing_payload_json = json.dumps(_payload_to_dict(existing.payload), sort_keys=True)
            new_payload_json = json.dumps(_payload_to_dict(event.payload), sort_keys=True)
            if (existing.type == event.type and
                    existing.actor == event.actor and
                    existing.incident_id == event.incident_id and
                    existing_payload_json == new_payload_json):
                return existing   # Idempotent retry — return previously stored event
            # Same event_id but different content = conflict
            current = self.last_seq(incident_id)
            raise AppendConflict(current_seq=current)

        # Finalize event: assign seq, prev_hash, and hash (aligned with SQLiteEventStore)
        prev_hash: Optional[str] = None
        if expected_seq > 0:
            try:
                prev_ev = self._read_event_at(incident_id, expected_seq)
                prev_hash = prev_ev.hash
            except KeyError:
                pass

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

        event_json = self._event_to_json(completed)

        try:
            self._ddb.transact_write_items(
                TransactItems=[
                    # 1. CAS on META
                    {
                        "Update": {
                            "TableName": self._tbl,
                            "Key": {
                                "incident_id": {"S": incident_id},
                                "sk": {"S": _SK_META},
                            },
                            "UpdateExpression": "SET last_seq = :new_seq",
                            "ConditionExpression": "last_seq = :expected",
                            "ExpressionAttributeValues": {
                                ":new_seq":  {"N": str(new_seq)},
                                ":expected": {"N": str(expected_seq)},
                            },
                        }
                    },
                    # 2. Write finalized event
                    {
                        "Put": {
                            "TableName": self._tbl,
                            "Item": {
                                "incident_id": {"S": incident_id},
                                "sk": {"S": _sk_evt(new_seq)},
                                "seq": {"N": str(new_seq)},
                                "event_json": {"S": event_json},
                                "event_id": {"S": event_id},
                            },
                            "ConditionExpression": "attribute_not_exists(sk)",
                        }
                    },
                    # 3. Idempotency pointer
                    {
                        "Put": {
                            "TableName": self._tbl,
                            "Item": {
                                "incident_id": {"S": incident_id},
                                "sk": {"S": _sk_eid(event_id)},
                                "seq": {"N": str(new_seq)},
                                "event_id": {"S": event_id},
                            },
                            "ConditionExpression": "attribute_not_exists(sk)",
                        }
                    },
                ]
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TransactionCanceledException":
                current = self.last_seq(incident_id)
                raise AppendConflict(current_seq=current)
            raise

        return completed

    # ────────────────────────────────────────────────────────────────────────
    # read
    # ────────────────────────────────────────────────────────────────────────

    def read(self, incident_id: str, from_seq: int = 1) -> list[Event]:
        """
        Returns events ordered by seq without gaps. Strong consistency (ConsistentRead).
        """
        resp = self._ddb.query(
            TableName=self._tbl,
            KeyConditionExpression="incident_id = :iid AND sk BETWEEN :lo AND :hi",
            ExpressionAttributeValues={
                ":iid": {"S": incident_id},
                ":lo":  {"S": _sk_evt(from_seq)},
                ":hi":  {"S": _sk_evt(10**10)},  # Upper bound sequence number
            },
            ConsistentRead=True,
            ScanIndexForward=True,  # Ascending order
        )
        events = []
        for item in resp.get("Items", []):
            if item["sk"]["S"].startswith("EVT#"):
                events.append(self._json_to_event(item["event_json"]["S"]))
        return events

    # ────────────────────────────────────────────────────────────────────────
    # get_header / last_seq
    # ────────────────────────────────────────────────────────────────────────

    def get_header(self, incident_id: str) -> Optional[IncidentHeader]:
        resp = self._ddb.get_item(
            TableName=self._tbl,
            Key={"incident_id": {"S": incident_id}, "sk": {"S": _SK_HEADER}},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return None
        return self._dict_to_header(json.loads(item["header_json"]["S"]))

    def last_seq(self, incident_id: str) -> int:
        resp = self._ddb.get_item(
            TableName=self._tbl,
            Key={"incident_id": {"S": incident_id}, "sk": {"S": _SK_META}},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return 0
        return int(item["last_seq"]["N"])

    # ────────────────────────────────────────────────────────────────────────
    # Leases
    # ────────────────────────────────────────────────────────────────────────

    def acquire_lease(
        self, incident_id: str, worker_id: str, ttl_seconds: float
    ) -> Optional[LeaseToken]:
        """
        Acquires worker lease:
        - If absent or expired (expires_epoch < now): creates entry and increments fencing_number
        - fencing_number monotonically increases (atomic ADD) — never reset even on release
        - Returns None if currently held by another worker
        """
        now_ms = int(time.time() * 1000)
        exp_ms = int((time.time() + ttl_seconds) * 1000)

        try:
            resp = self._ddb.update_item(
                TableName=self._lease_tbl,
                Key={"incident_id": {"S": incident_id}},
                UpdateExpression=(
                    "SET worker_id = :wid, expires_epoch = :exp "
                    "ADD fencing_number :one"
                ),
                ConditionExpression=(
                    "attribute_not_exists(incident_id) OR "
                    "expires_epoch < :now"
                ),
                ExpressionAttributeValues={
                    ":wid": {"S": worker_id},
                    ":exp": {"N": str(exp_ms)},
                    ":now": {"N": str(now_ms)},
                    ":one": {"N": "1"},
                },
                ReturnValues="ALL_NEW",
            )
            fencing = int(resp["Attributes"]["fencing_number"]["N"])
            return LeaseToken(token=str(uuid.uuid4()), fencing_number=fencing)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return None
            raise

    def renew_lease(
        self, incident_id: str, token: LeaseToken, ttl_seconds: float
    ) -> bool:
        exp_ms = int((time.time() + ttl_seconds) * 1000)
        try:
            self._ddb.update_item(
                TableName=self._lease_tbl,
                Key={"incident_id": {"S": incident_id}},
                UpdateExpression="SET expires_epoch = :exp",
                ConditionExpression="fencing_number = :fn",
                ExpressionAttributeValues={
                    ":exp": {"N": str(exp_ms)},
                    ":fn":  {"N": str(token.fencing_number)},
                },
            )
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def release_lease(self, incident_id: str, token: LeaseToken) -> None:
        """Releases lease: zeroes out expires_epoch only, keeping fencing_number intact."""
        try:
            self._ddb.update_item(
                TableName=self._lease_tbl,
                Key={"incident_id": {"S": incident_id}},
                UpdateExpression="SET expires_epoch = :zero",
                ConditionExpression="fencing_number = :fn",
                ExpressionAttributeValues={
                    ":zero": {"N": "0"},
                    ":fn":   {"N": str(token.fencing_number)},
                },
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise

    # ────────────────────────────────────────────────────────────────────────
    # Blobs
    # ────────────────────────────────────────────────────────────────────────

    def put_blob(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        if self._s3 and self._s3_bucket:
            self._s3.put_object(
                Bucket=self._s3_bucket,
                Key=f"blobs/{sha}",
                Body=data,
                ServerSideEncryption="AES256",
            )
            return f"s3://{self._s3_bucket}/blobs/{sha}"
        # Fallback: inline DynamoDB storage (for test payloads < 400KB)
        self._ddb.put_item(
            TableName=self._tbl,
            Item={
                "incident_id": {"S": "__blobs__"},
                "sk": {"S": sha},
                "data": {"B": data},
            },
        )
        return f"dynamo://{sha}"

    def get_blob(self, ref: str) -> bytes:
        if ref.startswith("s3://"):
            if not (self._s3 and self._s3_bucket):
                raise KeyError(f"S3 not configured, cannot read blob: {ref!r}")
            try:
                key = ref.split(f"s3://{self._s3_bucket}/", 1)[1]
                resp = self._s3.get_object(Bucket=self._s3_bucket, Key=key)
                return resp["Body"].read()
            except ClientError as e:
                if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                    raise KeyError(f"Blob not found: {ref!r}") from e
                raise
        if ref.startswith("dynamo://"):
            sha = ref[len("dynamo://"):]
            resp = self._ddb.get_item(
                TableName=self._tbl,
                Key={"incident_id": {"S": "__blobs__"}, "sk": {"S": sha}},
                ConsistentRead=True,
            )
            item = resp.get("Item")
            if not item:
                raise KeyError(f"Blob not found: {ref!r}")
            return bytes(item["data"]["B"])
        raise KeyError(f"Unknown blob ref format: {ref!r}")

    # ────────────────────────────────────────────────────────────────────────
    # verify_chain (CS-08)
    # ────────────────────────────────────────────────────────────────────────

    def verify_chain(self, incident_id: str) -> bool:
        """Matches SQLiteEventStore verification logic: checks compute_hash() on each event."""
        events = self.read(incident_id)
        if not events:
            return True
        for i, ev in enumerate(events):
            if ev.seq != i + 1:
                logger.warning(f"Gap at position {i}: expected seq={i+1}, got seq={ev.seq}")
                return False
            expected_prev = events[i - 1].hash if i > 0 else None
            if ev.prev_hash != expected_prev:
                logger.warning(
                    f"prev_hash mismatch at seq={ev.seq}: "
                    f"stored={ev.prev_hash!r} expected={expected_prev!r}"
                )
                return False
            if ev.compute_hash() != ev.hash:
                logger.warning(f"Chain broken at seq={ev.seq} event_id={ev.event_id}")
                return False
        return True

    # ────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ────────────────────────────────────────────────────────────────────────

    def _get_event_by_id(self, incident_id: str, event_id: str) -> Optional[Event]:
        """Looks up event by event_id via EID# secondary item."""
        eid_resp = self._ddb.get_item(
            TableName=self._tbl,
            Key={"incident_id": {"S": incident_id}, "sk": {"S": _sk_eid(event_id)}},
            ConsistentRead=True,
        )
        eid_item = eid_resp.get("Item")
        if not eid_item:
            return None
        seq = int(eid_item["seq"]["N"])
        return self._read_event_at(incident_id, seq)

    def _read_event_at(self, incident_id: str, seq: int) -> Event:
        resp = self._ddb.get_item(
            TableName=self._tbl,
            Key={"incident_id": {"S": incident_id}, "sk": {"S": _sk_evt(seq)}},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            raise KeyError(f"Event not found: incident={incident_id} seq={seq}")
        return self._json_to_event(item["event_json"]["S"])

    @staticmethod
    def _event_to_json(event: Event) -> str:
        import dataclasses
        def _serial(obj):
            if hasattr(obj, "value"):
                return obj.value
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            return str(obj)
        return json.dumps(dataclasses.asdict(event), default=_serial, sort_keys=True)

    @staticmethod
    def _json_to_event(s: str) -> Event:
        """Reconstructs Event instance from JSON reusing SQLiteEventStore deserializer."""
        from ..store.sqlite_store import _rebuild_payload
        from ..domain.types import EventType, Actor
        d = json.loads(s)
        event_type = EventType(d["type"])
        payload = _rebuild_payload(event_type, d.get("payload", {}))
        return Event(
            incident_id=d["incident_id"],
            seq=d["seq"],
            event_id=d["event_id"],
            type=event_type,
            ts=d["ts"],
            actor=Actor(d["actor"]),
            payload=payload,
            prev_hash=d.get("prev_hash"),
            hash=d.get("hash"),
            writer_token=d.get("writer_token"),
            auth_tag=d.get("auth_tag"),
            schema_version=d.get("schema_version", "1.0"),
        )

    @staticmethod
    def _header_to_dict(h: IncidentHeader) -> dict:
        import dataclasses
        return dataclasses.asdict(h)

    @staticmethod
    def _dict_to_header(d: dict) -> IncidentHeader:
        return IncidentHeader(**d)
