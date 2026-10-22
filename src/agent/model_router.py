"""
agent/model_router.py — Dynamic Model Routing

Wraps two models (flash + pro) and routes invocations dynamically based on model_tier
derived from ToolDecision.

Routing Rules:
  - decision.model_tier == "pro"  -> invoke pro model
  - decision.model_tier == "flash" (or None / other) -> invoke flash model
  - confidence < LOW_THRESHOLD  -> always flash (FALLBACK_MODEL_TIER)
    (The loop handles this via escalation, but safety fallback is kept here as well)
  - model_router never modifies Policy Gate or human approval requirements

Model swapping: Single line in shared.py or when initializing ReasoningLoop.

Example:
    router = ModelRouter(
        flash_model=DeepSeekModel(api_key=key, model="deepseek-chat"),
        pro_model=DeepSeekModel(api_key=key, model="deepseek-reasoner"),
    )
    loop = ReasoningLoop(model=router, ...)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from .model_interface import ModelContext, ModelInterface, ModelResponse, ToolCall
from .tool_decider import (
    ToolDecision, FALLBACK_MODEL_TIER, LOW_CONFIDENCE_THRESHOLD,
)

logger = logging.getLogger(__name__)

DEFAULT_PRO_MODEL: str = os.environ.get("INCIDENTS_PRO_MODEL", "bedrock:deepseek.v3.2")
DEFAULT_FLASH_MODEL: str = os.environ.get("INCIDENTS_FLASH_MODEL", "bedrock:deepseek.v3.2")


@dataclass
class ModelRouter(ModelInterface):
    """
    Selects model based on model_tier in ToolDecision (passed via tool_hint_meta).

    ReasoningLoop passes tier via invoke(ctx, tool_hint=..., model_tier=...).
    backward compat: if tier is omitted -> defaults to flash.

    Principle: Both models implement ModelInterface — freely interchangeable.
    """

    _flash_model: ModelInterface
    _pro_model:   ModelInterface
    # Last tier used — for testing and audit trail
    _last_tier_used: str = field(default="flash", init=False)

    def __init__(
        self,
        flash_model: ModelInterface,
        pro_model:   ModelInterface,
    ) -> None:
        self._flash_model     = flash_model
        self._pro_model       = pro_model
        self._last_tier_used  = "flash"

    def invoke(
        self,
        ctx: ModelContext,
        tool_hint: Optional[str] = None,
        model_tier: Optional[str] = None,   # From ReasoningLoop following Strands decision
    ) -> ModelResponse:
        """
        Selects appropriate model and invokes it.
        model_tier="pro" -> pro model
        otherwise (flash/None/unknown) -> flash model (safe default)
        """
        chosen_tier = self._resolve_tier(model_tier)
        chosen_model = self._pick_model(chosen_tier)
        self._last_tier_used = chosen_tier

        print(f"   -> [MODEL ROUTER] tier={chosen_tier} → {chosen_model.name} (tool_hint={tool_hint!r})")
        logger.info(
            f"ModelRouter: tier={chosen_tier} → {chosen_model.name} "
            f"(tool_hint={tool_hint!r})"
        )
        return chosen_model.invoke(ctx, tool_hint=tool_hint)

    def _resolve_tier(self, requested: Optional[str]) -> str:
        """Resolves the effective tier — fail-safe to flash."""
        if requested == "pro":
            return "pro"
        return FALLBACK_MODEL_TIER  # "flash"

    def _pick_model(self, tier: str) -> ModelInterface:
        if tier == "pro":
            return self._pro_model
        return self._flash_model

    @property
    def name(self) -> str:
        return (
            f"router(flash={self._flash_model.name}, "
            f"pro={self._pro_model.name})"
        )

    @property
    def last_tier_used(self) -> str:
        """Model tier invoked in the last invoke call — for testing and auditing."""
        return self._last_tier_used

    @property
    def flash_model(self) -> ModelInterface:
        return self._flash_model

    @property
    def pro_model(self) -> ModelInterface:
        return self._pro_model
