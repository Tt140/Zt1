"""
policy/auth.py — auth_tag (HMAC-SHA256) for authoritative events (G3, 02 §1)

Events carrying auth_tag:
- ApprovalGranted (writer: slack_callback)
- LatchReleasedByHuman (writer: slack_callback)

Verified exclusively by executor.
Key is supplied via external configuration (AWS Secrets Manager in production).
"""
from __future__ import annotations

import hmac
import hashlib
from typing import Any

from ..domain.types import canonical_json

# Static HMAC key for local testing. Overridden via Secrets Manager in production environments.
TEST_AUTH_KEY = b"phase1-4-test-mac-key-NOT-FOR-PRODUCTION"


def compute_auth_tag(
    *,
    incident_id: str,
    event_type: str,
    payload_dict: dict[str, Any],
    key: bytes = TEST_AUTH_KEY,
) -> str:
    """
    Computes HMAC-SHA256 over {incident_id, type, payload}.
    Message is canonical JSON to ensure determinism.
    """
    msg = canonical_json({
        "incident_id": incident_id,
        "type": event_type,
        "payload": payload_dict,
    })
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_auth_tag(
    *,
    incident_id: str,
    event_type: str,
    payload_dict: dict[str, Any],
    claimed_tag: str,
    key: bytes = TEST_AUTH_KEY,
) -> bool:
    """
    Verifies auth_tag using constant-time comparison against timing attacks.
    Returns False if claimed tag is empty or invalid.
    """
    if not claimed_tag:
        return False
    expected = compute_auth_tag(
        incident_id=incident_id,
        event_type=event_type,
        payload_dict=payload_dict,
        key=key,
    )
    return hmac.compare_digest(expected, claimed_tag)
