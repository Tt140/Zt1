"""
agent/nova_model.py — BedrockNovaModel: ModelInterface on Bedrock Converse API

Model ID:
  Nova 2 Lite (Hackathon): Read from NOVA_MODEL_ID or default below.
  
  Verify before deployment:
    aws bedrock list-foundation-models --region {region} \
      --query "modelSummaries[?contains(modelId,'nova')].[modelId,modelName]"
  
  Recommended defaults (subject to confirmation):
    - Nova Lite v1: "amazon.nova-lite-v1:0"   (widely available)
    - Nova 2 Lite:  "amazon.nova-lite-v2:0"   <- confirm in AWS console
  
  If the hackathon explicitly requires Nova 2 Lite, set:
    NOVA_MODEL_ID=amazon.nova-lite-v2:0
  in Lambda environment variables. If v2 is unavailable, use v1.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

from .model_interface import (
    ModelInterface, ModelContext, ModelResponse, ToolCall, VALID_TOOL_NAMES,
)

logger = logging.getLogger(__name__)

# Default Model ID — adjust after verifying in AWS console
_DEFAULT_MODEL_ID = os.environ.get("NOVA_MODEL_ID", "amazon.nova-lite-v1:0")

# Static system prompt suffix for tools
_SYSTEM_PROMPT_SUFFIX = (
    "\nYou are an incident diagnostics agent. Return JSON only in the format:\n"
    '{"tool_name": "<tool>", "arguments": {<params>}, "reasoning": "<reason>"}'
)


class BedrockNovaModel(ModelInterface):
    """
    Invokes Bedrock Converse API (Nova 2 Lite or Nova Lite).
    
    tool_hint: If provided, appended to system prompt as an advisory directive
    for the model to select this specific tool. ReasoningLoop enforces
    Strands selection — the model uses tool_hint to generate appropriate parameters.
    """

    def __init__(
        self,
        model_id: str = _DEFAULT_MODEL_ID,
        region: str = "us-east-1",
        max_tokens: int = 1024,
        temperature: float = 0.0,
        bedrock_client=None,
    ):
        self._model_id = model_id
        self._region = region
        self._max_tokens = max_tokens
        self._temperature = temperature

        if bedrock_client is not None:
            self._client = bedrock_client
        else:
            try:
                import boto3
                self._client = boto3.client(
                    "bedrock-runtime", region_name=region
                )
            except ImportError:
                raise ImportError("pip install boto3 for BedrockNovaModel")

    def invoke(
        self, ctx: ModelContext, tool_hint: Optional[str] = None
    ) -> ModelResponse:
        hint_instruction = ""
        if tool_hint:
            hint_instruction = (
                f"\n\nRequired tool now: {tool_hint!r}. "
                "Generate appropriate arguments based on context."
            )

        system_text = ctx.system_prompt + _SYSTEM_PROMPT_SUFFIX + hint_instruction
        user_text = self._build_user_message(ctx)

        try:
            resp = self._client.converse(
                modelId=self._model_id,
                messages=[{"role": "user", "content": [{"text": user_text}]}],
                system=[{"text": system_text}],
                inferenceConfig={
                    "maxTokens": self._max_tokens,
                    "temperature": self._temperature,
                },
            )
            raw_text = (
                resp["output"]["message"]["content"][0]["text"]
            )
            return self._parse_response(raw_text)

        except Exception as exc:
            logger.error(f"BedrockNovaModel error: {exc}")
            raise

    def _build_user_message(self, ctx: ModelContext) -> str:
        lines = [
            f"## Incident Summary\n{ctx.incident_summary}",
            f"## Hypotheses\n{ctx.hypotheses_summary}",
        ]
        if ctx.evidence_summaries:
            lines.append("## Evidence")
            for ev in ctx.evidence_summaries[-5:]:  # Last 5 only
                lines.append(f"- {ev}")
        lines.append(f"## Available Tools\n{', '.join(ctx.available_tools)}")
        lines.append(f"## Remaining Budget\n{ctx.budget_remaining}")
        return "\n\n".join(lines)

    @staticmethod
    def _parse_response(raw_text: str) -> ModelResponse:
        """Parse JSON from model response."""
        text = raw_text.strip()
        # Extract JSON from markdown code block if present
        if "```" in text:
            start = text.find("{", text.find("```"))
            end = text.rfind("}") + 1
            text = text[start:end]

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Fallback: escalate if parsing fails
            return ModelResponse(
                tool_call=ToolCall(
                    tool_name="escalate",
                    arguments={"reason": f"Failed to parse model response: {raw_text[:200]}"},
                    reasoning="parse-error-escalate",
                ),
                raw_response=raw_text,
            )

        tool_name = data.get("tool_name", "escalate")
        if tool_name not in VALID_TOOL_NAMES:
            tool_name = "escalate"
            data["arguments"] = {"reason": f"Invalid tool: {data.get('tool_name')}"}

        return ModelResponse(
            tool_call=ToolCall(
                tool_name=tool_name,
                arguments=data.get("arguments", {}),
                reasoning=data.get("reasoning", ""),
            ),
            raw_response=raw_text,
        )

    @property
    def name(self) -> str:
        return f"bedrock:{self._model_id}"
