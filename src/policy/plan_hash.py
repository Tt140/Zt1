"""
policy/plan_hash.py — SHA-256 plan_hash computation and verification (04 §8, G2)

plan_hash = SHA-256 over semantic plan fields (fields determining actual operational impact).
Recomputed by executor prior to execution to verify absence of post-decision tampering.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..domain.types import StepRecord, canonical_json


def _semantic_fields(step: StepRecord) -> dict[str, Any]:
    """
    Semantic fields included in plan_hash — everything determining operational impact.
    Excludes: step_id, incident_id, expires_at, risk_claim
    (descriptive metadata that does not alter execution semantics).
    """
    import dataclasses

    def _convert(v: Any) -> Any:
        from enum import Enum
        if isinstance(v, Enum):
            return v.value
        if dataclasses.is_dataclass(v) and not isinstance(v, type):
            return {k: _convert(val) for k, val in dataclasses.asdict(v).items()}
        if isinstance(v, list):
            return [_convert(i) for i in v]
        if isinstance(v, dict):
            return {k: _convert(val) for k, val in v.items()}
        return v

    return {
        "kind": _convert(step.kind),
        "target": step.target,
        "execution_spec": _convert(step.execution_spec),
        "declared_effects": _convert(step.declared_effects),
        "preconditions": _convert(step.preconditions),
        "success_criteria": _convert(step.success_criteria),
        "rollback_plan": _convert(step.rollback_plan),
        "idempotent": step.idempotent,
    }


def compute_plan_hash(step: StepRecord) -> str:
    """
    Computes plan_hash from semantic fields.
    Deterministic: identical plans always produce the identical hash.
    """
    fields = _semantic_fields(step)
    return hashlib.sha256(canonical_json(fields)).hexdigest()


def compute_plan_hash_from_dict(fields: dict[str, Any]) -> str:
    """
    Computes plan_hash directly from a dict representation
    (for lightweight recomputation in executor without full StepRecord reconstruction).
    """
    semantic = {
        k: fields[k]
        for k in [
            "kind", "target", "execution_spec", "declared_effects",
            "preconditions", "success_criteria", "rollback_plan", "idempotent",
        ]
        if k in fields
    }
    return hashlib.sha256(canonical_json(semantic)).hexdigest()


def verify_plan_hash(step: StepRecord, claimed_hash: str) -> bool:
    """
    Verifies that claimed plan_hash matches recomputed hash from the actual plan.
    Mismatch indicates plan tampering after policy decision was logged (G2).
    """
    return compute_plan_hash(step) == claimed_hash
