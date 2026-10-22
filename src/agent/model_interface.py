"""
agent/model_interface.py — Model Abstraction Layer (02 §10)

Single interface with two implementations:
1. RecordedModel  — Replays pre-recorded responses (for deterministic testing)
2. NovaModel      — Bedrock / Nova 2 Lite integration stub (Phase 5)

Rule: Single action per cycle. Output schema is strictly validated.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Model Outputs
# ---------------------------------------------------------------------------

VALID_TOOL_NAMES = frozenset([
    "observe",
    "query_metrics",
    "query_logs",
    "update_hypotheses",
    "propose_step",
    "verify",
    "escalate",
    "conclude",
])


@dataclass(frozen=True)
class ToolCall:
    """Single action emitted by the model in this cycle."""
    tool_name: str
    arguments: dict[str, Any]
    reasoning: str = ""  # Model reasoning (for audit trail only)

    def __post_init__(self) -> None:
        if self.tool_name not in VALID_TOOL_NAMES:
            raise ValueError(
                f"Invalid tool: {self.tool_name!r}. Valid: {sorted(VALID_TOOL_NAMES)}"
            )


@dataclass
class ModelResponse:
    """Model response for a single reasoning cycle."""
    tool_call: ToolCall
    raw_response: Optional[Any] = None  # For audit trail

    @property
    def is_valid(self) -> bool:
        return self.tool_call.tool_name in VALID_TOOL_NAMES


# ---------------------------------------------------------------------------
# Context Dispatched to Model
# ---------------------------------------------------------------------------

@dataclass
class ModelContext:
    """
    Context provided to the model in each reasoning cycle.
    Constructed from derived state + evidence summaries.
    Any raw text from the server is explicitly marked as untrusted (02 §10).
    """
    system_prompt: str
    incident_summary: str
    hypotheses_summary: str
    evidence_summaries: list[dict[str, Any]]
    available_tools: list[str]
    budget_remaining: dict[str, float]
    # Current cycle (for auditing)
    cycle: int = 0
    # RC-4: Consecutive failed tools count (consumed by EmbeddedStrandsDecider)
    consecutive_failed_tools: int = 0


# ---------------------------------------------------------------------------
# Base Interface
# ---------------------------------------------------------------------------

class ModelInterface(ABC):
    """
    Core model interface.
    Returns exactly one ToolCall per invocation — 02 §10 rule.
    """

    @abstractmethod
    def invoke(self, ctx: ModelContext, tool_hint: Optional[str] = None) -> ModelResponse:
        """
        Dispatches context to the model and returns a single action.
        tool_hint: Tool name selected by Strands Decider (enforced by ReasoningLoop).
          - Real models use it to constrain search space and generate suitable arguments.
          - RecordedModel/BranchingModel ignore it (backward compatibility).
          - ReasoningLoop enforces constraint adherence, not the model.
        Any unhandled exception -> ToolCall(escalate) from the higher layer.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Implementation name for audit logs."""
        ...


# ---------------------------------------------------------------------------
# RecordedModel — For Deterministic Testing
# ---------------------------------------------------------------------------

@dataclass
class RecordedModel(ModelInterface):
    """
    Replays recorded responses sequentially.
    When recording is exhausted: automatically emits escalate.

    Objective: Prove that the agent architecture reacts to actual evidence outcomes —
    each recorded trajectory represents a distinct reasoning branch based on different evidence.
    """
    _responses: list[dict[str, Any]] = field(default_factory=list)
    _index: int = field(default=0, init=False)
    _model_name: str = "recorded"

    def __init__(self, responses: list[dict[str, Any]], model_name: str = "recorded"):
        self._responses = responses
        self._index = 0
        self._model_name = model_name

    def invoke(self, ctx: ModelContext, tool_hint: Optional[str] = None) -> ModelResponse:
        if self._index >= len(self._responses):
            # Recording exhausted -> escalate
            return ModelResponse(
                tool_call=ToolCall(
                    tool_name="escalate",
                    arguments={"reason": "RecordedModel exhausted — no more responses"},
                    reasoning="auto-escalate: recording ended",
                ),
            )
        resp = self._responses[self._index]
        self._index += 1
        tool_call = ToolCall(
            tool_name=resp["tool_name"],
            arguments=resp.get("arguments", {}),
            reasoning=resp.get("reasoning", ""),
        )
        return ModelResponse(tool_call=tool_call, raw_response=resp)

    def reset(self) -> None:
        """Replay from start (for repeated test runs)."""
        self._index = 0

    @property
    def name(self) -> str:
        return f"recorded:{self._model_name}"

    @property
    def calls_made(self) -> int:
        return self._index

    @property
    def responses_remaining(self) -> int:
        return len(self._responses) - self._index


# ---------------------------------------------------------------------------
# BranchingModel — Recorded Model Branching on Latest Evidence
# Foundation: Proves the agent responds dynamically to actual evidence outcomes
# ---------------------------------------------------------------------------

@dataclass
class BranchingModel(ModelInterface):
    """
    Selects response branch based on the latest observable evidence in context.

    branches: dict[str, list[dict]] — Pattern key -> list of responses
    default_branch: list[dict] — Fallback if no pattern matches

    Objective: Prove that evidence outcomes dynamically alter agent decisions.
    """
    branches: dict[str, list[dict[str, Any]]]
    default_branch: list[dict[str, Any]]
    _indices: dict[str, int] = field(default_factory=dict)
    _last_branch: Optional[str] = field(default=None, init=False)

    def __init__(
        self,
        branches: dict[str, list[dict[str, Any]]],
        default_branch: list[dict[str, Any]],
    ):
        self.branches = branches
        self.default_branch = default_branch
        self._indices = {k: 0 for k in branches}
        self._indices["__default__"] = 0
        self._last_branch = None

    def invoke(self, ctx: ModelContext, tool_hint: Optional[str] = None) -> ModelResponse:
        branch_key, responses = self._select_branch(ctx)
        self._last_branch = branch_key
        idx = self._indices.get(branch_key, 0)

        if idx >= len(responses):
            return ModelResponse(
                tool_call=ToolCall(
                    tool_name="escalate",
                    arguments={"reason": f"Branch '{branch_key}' exhausted"},
                    reasoning="auto-escalate",
                ),
            )
        resp = responses[idx]
        self._indices[branch_key] = idx + 1
        return ModelResponse(
            tool_call=ToolCall(
                tool_name=resp["tool_name"],
                arguments=resp.get("arguments", {}),
                reasoning=resp.get("reasoning", f"branch={branch_key}"),
            ),
            raw_response=resp,
        )

    def _select_branch(self, ctx: ModelContext) -> tuple[str, list[dict]]:
        """
        Searches current evidence summaries for a pattern determining the branch.
        Prioritizes the latest evidence (added in the most recent cycle).
        """
        # Search in the latest evidence summary first, then across the remaining context
        search_text = " ".join([
            ev.get("summary", "") for ev in ctx.evidence_summaries
        ] + [ctx.hypotheses_summary, ctx.incident_summary]).lower()

        for pattern, responses in self.branches.items():
            if pattern.lower() in search_text:
                return pattern, responses
        return "__default__", self.default_branch

    @property
    def last_branch(self) -> Optional[str]:
        return self._last_branch

    @property
    def name(self) -> str:
        return "branching-recorded"


# ---------------------------------------------------------------------------
# NovaModel — Stub (Phase 5)
# ---------------------------------------------------------------------------

class NovaModel(ModelInterface):
    """
    Stub for Bedrock / Nova 2 Lite.
    Activated in Phase 5 following quota and availability verification.
    No AWS network calls in phases 1-4.
    """

    def __init__(self, model_id: str = "amazon.nova-lite-v1:0", region: str = "us-east-1"):
        self._model_id = model_id
        self._region = region

    def invoke(self, ctx: ModelContext, tool_hint: Optional[str] = None) -> ModelResponse:
        raise NotImplementedError(
            "NovaModel not available in phases 1-4. "
            "Use RecordedModel or BranchingModel for local testing."
        )

    @property
    def name(self) -> str:
        return f"nova:{self._model_id}"
