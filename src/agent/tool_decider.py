"""
agent/tool_decider.py — Mandatory Tool Decision Interface (Strands Decider 2B)

Role: Strands selects the next tool name + confidence_score + model_tier.
ReasoningLoop enforces this selection and prevents the generative model from overriding it.
The generative model is responsible only for synthesizing arguments.

Confidence thresholds (calibrated for Strands Decider 2B — 5 options):
  Raw incident start: calibrated confidence for observe is roughly 0.23–0.38
  >= HIGH_THRESHOLD (0.35): Normal execution
  >= LOW_THRESHOLD  (0.15): Warning; T1 requires explicit human approval
  <  LOW_THRESHOLD:         Escalate (no unsafe autonomous execution)

model_tier (Dynamic Model Routing):
  "flash" — Routine, low-complexity situations (deepseek-chat / nova-lite)
  "pro"   — Complex or conflicting hypotheses (deepseek-reasoner / nova-pro)
  When confidence < LOW_THRESHOLD, fallback_tier is returned instead of pro.
"""
from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Any

from .model_interface import ModelContext, VALID_TOOL_NAMES

logger = logging.getLogger(__name__)

# Strands Decider 2B calibration — 5 tool classes (observe/query_metrics/update_hypotheses/propose_step/escalate)
# Calibrated confidence for observe in cycle 0: ~0.23 (raw: ~0.38)
# Previous values (HIGH=0.70, LOW=0.40) prematurely escalated valid cycle-0 decisions
HIGH_CONFIDENCE_THRESHOLD: float = 0.35
LOW_CONFIDENCE_THRESHOLD:  float = 0.15

VALID_MODEL_TIERS = frozenset(["flash", "pro"])
DEFAULT_MODEL_TIER = "flash"   # Default — cost-effective and sufficient for routine cycles
FALLBACK_MODEL_TIER = "flash"  # Low confidence -> fallback to flash (cautious)


@dataclass(frozen=True)
class ToolDecision:
    """
    Strands decision for a single reasoning cycle.

    tool_name:   Selected tool (binding)
    confidence:  Decision confidence [0.0 – 1.0]
    model_tier:  Recommended model tier: 'flash' (default) or 'pro'
                 Does not bypass Policy Gate — used for model routing only.
    """
    tool_name:   str
    confidence:  float
    model_tier:  str = DEFAULT_MODEL_TIER

    def __post_init__(self) -> None:
        if self.tool_name not in VALID_TOOL_NAMES:
            raise ValueError(
                f"ToolDecision: invalid tool={self.tool_name!r}. "
                f"Valid: {sorted(VALID_TOOL_NAMES)}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        # Correct unknown tier instead of failing (fail-safe)
        if self.model_tier not in VALID_MODEL_TIERS:
            logger.warning(
                f"ToolDecision: unknown model_tier={self.model_tier!r}, "
                f"falling back to {FALLBACK_MODEL_TIER!r}"
            )
            object.__setattr__(self, "model_tier", FALLBACK_MODEL_TIER)

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= HIGH_CONFIDENCE_THRESHOLD

    @property
    def is_low_confidence(self) -> bool:
        return self.confidence < LOW_CONFIDENCE_THRESHOLD

    @property
    def requires_human_review(self) -> bool:
        return LOW_CONFIDENCE_THRESHOLD <= self.confidence < HIGH_CONFIDENCE_THRESHOLD


class ToolDecider(ABC):
    """
    Mandatory tool decider interface.
    ReasoningLoop enforces its decision — model cannot override.
    """

    @abstractmethod
    def select(self, ctx: ModelContext) -> Optional[ToolDecision]:
        """
        Selects next tool. Returns None if unopinionated.
        None = generative model chooses freely.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


class NullToolDecider(ToolDecider):
    """
    No binding selection. Used for tests and backward compatibility.
    RecordedModel/BranchingModel and legacy test suites run with this.
    """

    def select(self, ctx: ModelContext) -> Optional[ToolDecision]:
        return None

    @property
    def name(self) -> str:
        return "null"


ToolDeciderPort = ToolDecider


class EmbeddedStrandsDecider(ToolDeciderPort):
    """
    Autonomous in-memory tool decider running entirely within process memory.
    Used as default mode for environments without a standalone Strands EC2 endpoint.
    Applies the same neural routing policy as Strands with hybrid Flash/Pro tiering:
    1. First cycle (cycle == 0) or when no evidence has been collected:
       Selects 'observe' with model_tier='pro' and confidence=0.85 (or available exploratory tool).
    2. When new evidence exists but no active hypotheses exist (or updating hypotheses)
       and 'update_hypotheses' is available:
       Selects 'update_hypotheses' with model_tier='flash' and confidence=0.82.
    3. When active hypotheses and sufficient evidence exist, and 'propose_step' or 'conclude' is available:
       Selects 'propose_step' (or best matching available tool) with model_tier='pro' and confidence=0.85.
    4. Constrains selection strictly to available_tools.
    """

    def select(self, ctx: ModelContext) -> Optional[ToolDecision]:
        avail = list(ctx.available_tools or [])
        if not avail:
            return None

        # Single available tool edge case
        if len(avail) == 1:
            only_tool = avail[0]
            tier = "flash" if only_tool in ("update_hypotheses", "verify") else "pro"
            return ToolDecision(
                tool_name=only_tool,
                confidence=1.0,
                model_tier=tier,
            )

        # RC-4: When >=2 consecutive tools fail, avoid recommending further exploratory observe tools
        #        -> recommend update_hypotheses (if hypotheses need adjustment) or escalate
        if getattr(ctx, "consecutive_failed_tools", 0) >= 2:
            logger.info(
                f"EmbeddedStrandsDecider: {ctx.consecutive_failed_tools} consecutive failures, "
                "switching away from exploratory tools"
            )
            if "update_hypotheses" in avail and self._has_active_hypotheses(ctx.hypotheses_summary):
                return ToolDecision(tool_name="update_hypotheses", confidence=0.80, model_tier="flash")
            if "escalate" in avail:
                return ToolDecision(tool_name="escalate", confidence=0.80, model_tier="flash")
            # fallback: first non-exploratory tool
            non_observe = [t for t in avail if t not in ("observe", "query_metrics", "query_logs")]
            if non_observe:
                return ToolDecision(tool_name=non_observe[0], confidence=0.75, model_tier="flash")

        evidence = ctx.evidence_summaries or []
        has_evidence = len(evidence) > 0
        is_cycle_zero = (ctx.cycle is not None and ctx.cycle == 0) or (not has_evidence)

        # 1. Cycle zero or no evidence collected yet -> observe with pro tier
        if is_cycle_zero:
            for exploratory_tool in ("observe", "query_metrics", "query_logs"):
                if exploratory_tool in avail:
                    return ToolDecision(
                        tool_name=exploratory_tool,
                        confidence=0.85,
                        model_tier="pro",
                    )
            # Fallback to first available tool
            first = avail[0]
            tier = "flash" if first in ("update_hypotheses", "verify") else "pro"
            return ToolDecision(tool_name=first, confidence=0.85, model_tier=tier)

        # Check for active hypotheses
        has_active_hypotheses = self._has_active_hypotheses(ctx.hypotheses_summary)

        # 2. New evidence available but no active hypotheses yet -> update_hypotheses with flash tier
        if not has_active_hypotheses:
            if "update_hypotheses" in avail:
                return ToolDecision(
                    tool_name="update_hypotheses",
                    confidence=0.82,
                    model_tier="flash",
                )
            if "observe" in avail:
                return ToolDecision(tool_name="observe", confidence=0.85, model_tier="pro")

        # 3. Active hypotheses with sufficient evidence -> propose_step or conclude with pro tier
        if "propose_step" in avail:
            return ToolDecision(tool_name="propose_step", confidence=0.85, model_tier="pro")
        if "conclude" in avail:
            return ToolDecision(tool_name="conclude", confidence=0.85, model_tier="pro")
        if "verify" in avail:
            return ToolDecision(tool_name="verify", confidence=0.85, model_tier="flash")
        if "update_hypotheses" in avail:
            return ToolDecision(tool_name="update_hypotheses", confidence=0.82, model_tier="flash")
        if "observe" in avail:
            return ToolDecision(tool_name="observe", confidence=0.85, model_tier="pro")

        # 4. Strict restriction to available_tools only
        chosen = avail[0]
        tier = "flash" if chosen in ("update_hypotheses", "verify") else "pro"
        conf = 0.82 if tier == "flash" else 0.85
        return ToolDecision(tool_name=chosen, confidence=conf, model_tier=tier)

    @staticmethod
    def _has_active_hypotheses(hyp_summary: Any) -> bool:
        if not hyp_summary:
            return False
        if isinstance(hyp_summary, list):
            for h in hyp_summary:
                if isinstance(h, dict):
                    status = str(h.get("status", "")).lower()
                    if status in ("active", "confirmed"):
                        return True
                elif isinstance(h, str) and ("active" in h.lower() or "confirmed" in h.lower()):
                    return True
            return False
        if isinstance(hyp_summary, str):
            text = hyp_summary.strip()
            if (text.startswith("[") and text.endswith("]")) or (text.startswith("{") and text.endswith("}")):
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, list):
                        return any(
                            isinstance(x, dict) and str(x.get("status", "")).lower() in ("active", "confirmed")
                            for x in parsed
                        )
                except Exception:
                    pass
            lower_text = text.lower()
            return "active" in lower_text or "confirmed" in lower_text
        return False

    @property
    def name(self) -> str:
        return "embedded-strands"


def _trim_incident_summary(raw_incident: Optional[str], max_chars: int = 400) -> str:
    """
    Trims incident_summary to max_chars (400 characters max).
    Preserves incident summary prefix (core incident attributes)
    and tail (most recent executed/failed command snippet).
    """
    if not raw_incident:
        return ""
    if len(raw_incident) <= max_chars:
        return raw_incident

    separator = "\n...\n"
    avail = max_chars - len(separator)
    if avail <= 0:
        return raw_incident[:max_chars]

    head_len = avail // 2
    tail_len = avail - head_len
    return f"{raw_incident[:head_len]}{separator}{raw_incident[-tail_len:]}"


def _trim_hypotheses_summary(hyp_summary: Any, max_chars: int = 350) -> Any:
    """
    Trims hypotheses_summary (whether list or string):
    Retains only the last two active or refuted hypotheses up to max_chars (350 characters total).
    """
    if not hyp_summary:
        return "" if hyp_summary is None else hyp_summary

    if isinstance(hyp_summary, list):
        active_or_refuted = [
            h for h in hyp_summary
            if isinstance(h, dict) and str(h.get("status", "")).lower() in ("active", "confirmed", "refuted")
        ]
        selected = list((active_or_refuted if active_or_refuted else hyp_summary)[-2:])
        copied = [dict(x) if isinstance(x, dict) else x for x in selected]
        if len(json.dumps(copied, ensure_ascii=False)) > max_chars:
            for item in copied:
                if isinstance(item, dict):
                    for k, v in list(item.items()):
                        if isinstance(v, str) and len(v) > 60:
                            item[k] = v[:60]
                        elif isinstance(v, list) and len(v) > 2:
                            item[k] = v[-2:]
        return copied

    if isinstance(hyp_summary, str):
        trimmed_str = hyp_summary.strip()
        if (trimmed_str.startswith("[") and trimmed_str.endswith("]")) or (
            trimmed_str.startswith("{") and trimmed_str.endswith("}")
        ):
            try:
                parsed = json.loads(trimmed_str)
                if isinstance(parsed, list):
                    active_or_refuted = [
                        h for h in parsed
                        if isinstance(h, dict) and str(h.get("status", "")).lower() in ("active", "confirmed", "refuted")
                    ]
                    selected = (active_or_refuted if active_or_refuted else parsed)[-2:]
                    dumped = json.dumps(selected, ensure_ascii=False)
                    if len(dumped) > max_chars:
                        dumped = json.dumps(selected, ensure_ascii=False, separators=(',', ':'))
                    if len(dumped) > max_chars:
                        copied = [dict(x) if isinstance(x, dict) else x for x in selected]
                        for item in copied:
                            if isinstance(item, dict):
                                for k, v in list(item.items()):
                                    if isinstance(v, str) and len(v) > 60:
                                        item[k] = v[:60]
                                    elif isinstance(v, list) and len(v) > 2:
                                        item[k] = v[-2:]
                        dumped = json.dumps(copied, ensure_ascii=False, separators=(',', ':'))
                    if len(dumped) > max_chars:
                        dumped = dumped[:max_chars]
                    return dumped
            except Exception:
                pass

        # Plain text
        text = trimmed_str
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if len(lines) > 2:
            matched = [
                l for l in lines
                if any(w in l.lower() for w in ("active", "confirmed", "refuted"))
            ]
            chosen = (matched if matched else lines)[-2:]
            text = "\n".join(chosen)
        elif "\n\n" in text:
            parts = [p.strip() for p in text.split("\n\n") if p.strip()]
            if len(parts) > 2:
                matched = [
                    p for p in parts
                    if any(w in p.lower() for w in ("active", "confirmed", "refuted"))
                ]
                chosen = (matched if matched else parts)[-2:]
                text = "\n\n".join(chosen)

        return text[:max_chars]

    return str(hyp_summary)[:max_chars]


class StrandsDeciderClient(ToolDecider):
    """
    Connects to remote Strands Decider 2B on EC2 over HTTP within VPC.
    If strands_url is "embedded", empty, or connection fails:
    uses EmbeddedStrandsDecider as an intelligent fallback to maintain hybrid flash/pro routing.

    Expected API on EC2:
      POST /select_tool
      Body: {incident_summary, hypotheses_summary, available_tools,
             budget_remaining, cycle, ...}
      Response: {tool_name: str, confidence: float, model_tier: str}
    """

    def __init__(
        self,
        strands_url: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        timeout_seconds: float = 30.0,
        fail_open: bool = True,
        fallback_to_embedded: bool = True,
    ):
        raw_url = endpoint_url if endpoint_url is not None else (strands_url or "")
        self._url = str(raw_url).strip().rstrip("/")
        self._timeout = timeout_seconds
        self._fail_open = fail_open
        self._fallback_to_embedded = fallback_to_embedded
        self._embedded = EmbeddedStrandsDecider()
        self._circuit_broken = False

        try:
            import httpx
            self._httpx = httpx
        except ImportError:
            self._httpx = None

    def select(self, ctx: ModelContext) -> Optional[ToolDecision]:
        # Circuit broken or URL is embedded/empty -> use EmbeddedStrandsDecider immediately
        if self._circuit_broken:
            return self._embedded.select(ctx)

        is_lambda = bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
        if self._url.lower() in ("", "embedded") or (is_lambda and "localhost" in self._url.lower()):
            logger.info("StrandsDeciderClient: using EmbeddedStrandsDecider directly.")
            return self._embedded.select(ctx)

        if len(ctx.available_tools) == 1:
            only_tool = ctx.available_tools[0]
            if only_tool in VALID_TOOL_NAMES:
                logger.info(
                    f"StrandsDeciderClient: single available tool {only_tool!r}; "
                    "returning deterministic decision without calling Strands."
                )
                tier = "flash" if only_tool in ("update_hypotheses", "verify") else DEFAULT_MODEL_TIER
                return ToolDecision(
                    tool_name=only_tool,
                    confidence=1.0,
                    model_tier=tier,
                )

        if self._httpx is None:
            if self._fallback_to_embedded:
                return self._embedded.select(ctx)
            if self._fail_open:
                return None
            raise RuntimeError("httpx is required for remote Strands calls")

        trimmed_evidence = []
        for ev in (ctx.evidence_summaries or [])[-2:]:
            if isinstance(ev, dict):
                text = ev.get("summary") or str(ev)
            else:
                text = str(ev)
            trimmed_evidence.append(text[:250])

        trimmed_incident = _trim_incident_summary(ctx.incident_summary, max_chars=400)
        trimmed_hypotheses = _trim_hypotheses_summary(ctx.hypotheses_summary, max_chars=350)

        payload = {
            "incident_summary":   trimmed_incident,
            "hypotheses_summary": trimmed_hypotheses,
            "evidence_summaries": trimmed_evidence,
            "available_tools":    ctx.available_tools,
            "budget_remaining":   ctx.budget_remaining,
            "cycle":              ctx.cycle,
        }
        try:
            resp = self._httpx.post(
                f"{self._url}/select_tool",
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            tool_name  = data.get("tool_name")
            confidence = float(data.get("confidence", 1.0))
            # model_tier is optional — use Strands response if provided, otherwise default to flash
            model_tier = data.get("model_tier", DEFAULT_MODEL_TIER)

            if tool_name not in VALID_TOOL_NAMES:
                logger.warning(f"Strands returned invalid tool={tool_name!r}")
                if self._fallback_to_embedded:
                    return self._embedded.select(ctx)
                return None

            decision = ToolDecision(
                tool_name=tool_name,
                confidence=confidence,
                model_tier=model_tier,
            )
            logger.info(
                f"Strands: tool={tool_name} confidence={confidence:.2f} "
                f"model_tier={decision.model_tier}"
            )
            return decision

        except Exception as exc:
            self._circuit_broken = True
            if self._fallback_to_embedded:
                logger.warning(
                    f"StrandsDeciderClient failed ({exc}); switching permanently to EmbeddedStrandsDecider for all future cycles."
                )
                return self._embedded.select(ctx)
            if self._fail_open:
                logger.warning(f"StrandsDeciderClient failed (fail_open): {exc}")
                return None
            raise

    @property
    def name(self) -> str:
        if self._url.lower() in ("", "embedded"):
            return "embedded-strands"
        return f"strands@{self._url}"
