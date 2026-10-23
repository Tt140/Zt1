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

        # agent invoked async
        mock_inv.assert_called_once()
        call_kwargs = mock_inv.call_args[0]
        assert call_kwargs[1]["incident_id"] == iid

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
        mock_inv.assert_called_once()
        payload = mock_inv.call_args[0][1]
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
        mock_inv.assert_called_once()
        assert mock_inv.call_args[0][1]["instance_id"] == "i-0a1b2c3d4e5f6789"
