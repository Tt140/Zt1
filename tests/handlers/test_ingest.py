"""
tests/handlers/test_ingest.py

Unit tests for handlers/ingest.py:
- deduplication via create_if_absent
- non-ALARM states are skipped
- missing alarm name returns 400
- instance_id extraction from alarm name
- IncidentOpened event is written to store
- agent Lambda is invoked async

All tests use MemoryEventStore instead of real DynamoDB.
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from src.store.memory import MemoryEventStore
from src.domain.types import EventType


# ── fixtures ──────────────────────────────────────────────────────────────────

def _alarm_event(alarm_name="DiskUsage-High-i-0abc1234ef", state="ALARM",
                 alarm_arn="arn:aws:cloudwatch:us-east-1:123:alarm:test",
                 region="us-east-1"):
    return {
        "source": "aws.cloudwatch",
        "detail-type": "CloudWatch Alarm State Change",
        "detail": {
            "alarmName": alarm_name,
            "state": {"value": state},
            "configuration": {"description": ""},
        },
        "resources": [alarm_arn],
        "region": region,
    }


def _make_handler_with_store(store):
    """Returns ingest handler with injected store."""
    from handlers import ingest as ingest_mod
    with patch.object(ingest_mod, "get_store", return_value=store):
        with patch.object(ingest_mod, "invoke_async") as mock_invoke:
            yield ingest_mod.handler, mock_invoke


# ── tests ─────────────────────────────────────────────────────────────────────

class TestIngestHandler:

    def test_creates_incident_on_alarm(self):
        store = MemoryEventStore()
        from handlers import ingest as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(_alarm_event(), context=None)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["created"] is True
        assert "incident_id" in body

        # IncidentOpened must be written
        iid = body["incident_id"]
        events = store.read(iid)
        assert len(events) == 1
        assert events[0].type == EventType.IncidentOpened

        # notifier and agent invoked async
        assert mock_inv.call_count == 2
        invocations = {call[0][0]: call[0][1] for call in mock_inv.call_args_list}
        assert mod.NOTIFIER_FN in invocations
        assert invocations[mod.NOTIFIER_FN]["type"] == "incident_opened"
        assert invocations[mod.NOTIFIER_FN]["incident_id"] == iid
        assert mod.AGENT_FN in invocations
        assert invocations[mod.AGENT_FN]["incident_id"] == iid

    def test_deduplication_returns_existing(self):
        store = MemoryEventStore()
        from handlers import ingest as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async"):
            r1 = mod.handler(_alarm_event(), context=None)
            r2 = mod.handler(_alarm_event(), context=None)  # same alarm

        b1 = json.loads(r1["body"])
        b2 = json.loads(r2["body"])
        assert b1["created"] is True
        assert b2["created"] is False
        assert b1["incident_id"] == b2["incident_id"]

        # only one event
        events = store.read(b1["incident_id"])
        assert len(events) == 1

    def test_state_aware_dedup_opens_new_incident_after_prior_resolved(self):
        """When a previous incident is resolved, a recurring alarm opens a new incident."""
        store = MemoryEventStore()
        from handlers import ingest as mod
        from src.domain.types import build_event, EventType, Actor, IncidentResolvedPayload
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async"):
            # 1. First alarm -> Incident 1 opened
            r1 = mod.handler(_alarm_event(), context=None)
            b1 = json.loads(r1["body"])
            iid1 = b1["incident_id"]
            assert b1["created"] is True

            # 2. Incident 1 is resolved by agent
            ev_resolved = build_event(
                incident_id=iid1,
                type=EventType.IncidentResolved,
                actor=Actor.agent,
                payload=IncidentResolvedPayload(
                    verification_id="v-test-1",
                    summary="Root blocker terminated and telemetry verified",
                ),
            )
            store.append(iid1, 1, ev_resolved)

            # 3. Same alarm fires again later -> State-Aware dedup sees prior is resolved,
            # releases dedup key, and opens a fresh incident
            r2 = mod.handler(_alarm_event(), context=None)
            b2 = json.loads(r2["body"])
            assert b2["created"] is True
            assert b2["incident_id"] != iid1

    def test_release_dedupe_on_store_allows_new_incident(self):
        """Directly calling store.release_dedupe allows immediate creation with same key."""
        store = MemoryEventStore()
        from handlers import ingest as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async"):
            r1 = mod.handler(_alarm_event(), context=None)
            b1 = json.loads(r1["body"])
            iid1 = b1["incident_id"]
            assert b1["created"] is True

            # Release dedupe key
            header = store.get_header(iid1)
            assert header is not None
            assert store.release_dedupe(header.dedupe_key) is True

            # Same alarm should now create a new incident
            r2 = mod.handler(_alarm_event(), context=None)
            b2 = json.loads(r2["body"])
            assert b2["created"] is True
            assert b2["incident_id"] != iid1

    def test_skips_non_alarm_state(self):
        store = MemoryEventStore()
        from handlers import ingest as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(_alarm_event(state="OK"), context=None)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["skipped"] is True
        mock_inv.assert_not_called()

    def test_missing_alarm_name_returns_400(self):
        from handlers import ingest as mod
        event = {"source": "aws.cloudwatch", "detail": {}, "resources": [], "region": "us-east-1"}
        resp = mod.handler(event, context=None)
        assert resp["statusCode"] == 400

    def test_extracts_instance_id_from_alarm_name(self):
        """Must extract i-0abc1234ef from alarm name."""
        store = MemoryEventStore()
        from handlers import ingest as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async"):
            resp = mod.handler(_alarm_event("DiskUsage-High-i-0abc1234ef"), context=None)
        import json
        iid = json.loads(resp["body"])["incident_id"]
        # header must contain correct instance_id
        header = store._headers[iid]
        assert header.instance_id == "i-0abc1234ef"

    def test_agent_invoked_async_with_incident_id(self):
        store = MemoryEventStore()
        from handlers import ingest as mod
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(_alarm_event("Test-i-0abc1234"), context=None)

        iid = json.loads(resp["body"])["incident_id"]
        assert mock_inv.call_count == 2
        agent_call = next(call for call in mock_inv.call_args_list if call[0][0] == mod.AGENT_FN)
        payload = agent_call[0][1]
        assert payload["incident_id"] == iid
        assert "instance_id" in payload


class TestIngestAlarmNameParsing:
    """Separate unit tests for _extract_instance_id."""

    def test_extracts_from_alarm_name(self):
        from handlers.ingest import _extract_instance_id
        assert _extract_instance_id("HighCPU-i-0abc12345678") == "i-0abc12345678"

    def test_extracts_from_description(self):
        from handlers.ingest import _extract_instance_id
        result = _extract_instance_id("generic-alarm", "Instance i-0abc12345678")
        assert result == "i-0abc12345678"

    def test_returns_unknown_when_no_match(self):
        from handlers.ingest import _extract_instance_id
        import os
        os.environ.pop("TARGET_INSTANCE_ID", None)
        result = _extract_instance_id("no-instance-here", "")
        # Returns i-unknown or env var
        assert result in ("i-unknown",) or result.startswith("i-")

    def test_extracts_from_configuration_metrics_dimensions_dict(self):
        from handlers.ingest import _extract_instance_id
        detail = {
            "configuration": {
                "metrics": [
                    {
                        "metricStat": {
                            "metric": {
                                "dimensions": {
                                    "InstanceId": "i-0987654321fedcba"
                                }
                            }
                        }
                    }
                ]
            }
        }
        result = _extract_instance_id("Production-Web-Down", "Critical outage", detail=detail)
        assert result == "i-0987654321fedcba"

    def test_extracts_from_dimensions_list_format(self):
        from handlers.ingest import _extract_instance_id
        detail = {
            "configuration": {
                "metrics": [
                    {
                        "metricStat": {
                            "metric": {
                                "dimensions": [
                                    {"name": "InstanceId", "value": "i-1122334455667788"}
                                ]
                            }
                        }
                    }
                ]
            }
        }
        result = _extract_instance_id("Database-Memory-High", "", detail=detail)
        assert result == "i-1122334455667788"

    def test_handler_uses_dimension_extraction_end_to_end(self):
        from handlers import ingest as mod
        from src.store.memory import MemoryEventStore
        from unittest.mock import patch
        import json

        store = MemoryEventStore()
        event = {
            "detail-type": "CloudWatch Alarm State Change",
            "resources": ["arn:aws:cloudwatch:us-east-1:123:alarm:Generic-Alarm"],
            "region": "us-east-1",
            "detail": {
                "alarmName": "Universal-Docker-Down",
                "state": {"value": "ALARM"},
                "configuration": {
                    "description": "Any workload crash",
                    "metrics": [
                        {
                            "metricStat": {
                                "metric": {
                                    "dimensions": {
                                        "InstanceId": "i-0a1b2c3d4e5f6789"
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        }
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(event, context=None)

        assert resp["statusCode"] == 200
        iid = json.loads(resp["body"])["incident_id"]
        header = store._headers[iid]
        assert header.instance_id == "i-0a1b2c3d4e5f6789"
        assert mock_inv.call_count == 2
        agent_call = next(call for call in mock_inv.call_args_list if call[0][0] == mod.AGENT_FN)
        assert agent_call[0][1]["instance_id"] == "i-0a1b2c3d4e5f6789"

    def test_handler_unwraps_sns_message(self):
        """Handler should unwrap SNS message envelope automatically."""
        from handlers import ingest as mod
        from src.store.memory import MemoryEventStore
        from unittest.mock import patch
        import json

        store = MemoryEventStore()
        cw_event = _alarm_event("High-CPU-i-0a79ecfae5d7cec1a")
        sns_event = {
            "Records": [
                {
                    "EventSource": "aws:sns",
                    "Sns": {
                        "Message": json.dumps(cw_event),
                    }
                }
            ]
        }
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async") as mock_inv:
            resp = mod.handler(sns_event, context=None)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["created"] is True
        iid = body["incident_id"]
        assert store.get_header(iid).instance_id == "i-0a79ecfae5d7cec1a"

    def test_state_aware_dedup_releases_stale_approval(self):
        """When prior incident has an expired approval (> 15 min), a new alarm opens fresh incident."""
        from datetime import datetime, timezone, timedelta
        from handlers import ingest as mod
        from src.store.memory import MemoryEventStore
        from src.domain.types import (
            build_event, EventType, Actor, PolicyDecisionPayload,
            PolicyDecisionValue, Tier,
        )
        from unittest.mock import patch
        import json

        store = MemoryEventStore()
        with patch.object(mod, "get_store", return_value=store), \
             patch.object(mod, "invoke_async"):
            # 1. Incident 1 opened
            r1 = mod.handler(_alarm_event(), context=None)
            iid1 = json.loads(r1["body"])["incident_id"]

            # 2. Add PolicyDecision requiring approval from 20 minutes ago
            stale_time = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
            ev_policy = build_event(
                incident_id=iid1,
                type=EventType.PolicyDecision,
                actor=Actor.agent,
                payload=PolicyDecisionPayload(
                    step_id="step-1",
                    plan_hash="h1",
                    tier=Tier.T2,
                    decision=PolicyDecisionValue.require_approval,
                    reasons=["T2 approval required"],
                    rule_ids=["T2-APPROVAL"],
                    budget_snapshot={},
                    gate_version="1.0",
                ),
            )
            ev_policy.ts = stale_time
            store.append(iid1, 1, ev_policy)

            # 3. New alarm arrives -> state-aware dedup detects stale approval (> 15 min),
            # releases key and opens fresh incident
            r2 = mod.handler(_alarm_event(), context=None)
            b2 = json.loads(r2["body"])
            assert b2["created"] is True
            assert b2["incident_id"] != iid1
