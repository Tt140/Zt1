"""
agent/loop.py — Core Reasoning Loop (02 §10)

Executes a single reasoning cycle per iteration:
1. Builds context from current incident state
2. Invokes model -> returns single ToolCall
3. Executes tool -> appends events to EventStore
4. Reconstructs state via reducer fold
5. Checks termination condition (resolved / escalated / budget exhausted)

This is the core of Phase 3 — autonomous epistemic reasoning happens here.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional

from ..domain.types import IncidentState, IncidentPhase
from ..store.interface import EventStoreBase as EventStore
from .model_interface import ModelInterface, ToolCall, ModelResponse
from .context_builder import build_context
from .tool_executor import ToolExecutor, ToolResult
from .mock_backend import ObserveBackend
from .tool_decider import (
    ToolDecider, NullToolDecider, ToolDecision,
    LOW_CONFIDENCE_THRESHOLD, FALLBACK_MODEL_TIER,
)

logger = logging.getLogger(__name__)


def _invoke_model(
    model: ModelInterface,
    ctx,
    tool_hint=None,
    model_tier: str = FALLBACK_MODEL_TIER,
) -> "ModelResponse":
    """
    Invokes model in compatibility mode across ModelRouter and plain ModelInterface.

    - ModelRouter accepts model_tier kwarg and selects the appropriate model.
    - Standard ModelInterface (RecordedModel / DeepSeekModel / NovaModel)
      does not accept model_tier — invoked without it.
    Uses duck typing instead of isinstance to prevent circular imports.
    """
    # ModelRouter announces itself via last_tier_used attribute
    if hasattr(model, "last_tier_used"):
        return model.invoke(ctx, tool_hint=tool_hint, model_tier=model_tier)
    return model.invoke(ctx, tool_hint=tool_hint)



# ---------------------------------------------------------------------------
# Loop Termination States
# ---------------------------------------------------------------------------

class LoopTermination(Enum):
    MAX_CYCLES = "max_cycles"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    CONCLUDED = "concluded"
    ABORTED = "aborted"
    TOOL_ERROR = "tool_error"
    PROPOSED = "proposed"
    # Test only
    STEP_LIMIT = "step_limit"


@dataclass
class LoopResult:
    termination: LoopTermination
    cycles_completed: int
    final_state: IncidentState
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    error_message: Optional[str] = None
    strands_decision: Optional["ToolDecision"] = None  # Latest Strands decision if available

    @property
    def success(self) -> bool:
        return self.termination in (
            LoopTermination.RESOLVED,
            LoopTermination.CONCLUDED,
            LoopTermination.ESCALATED,
            LoopTermination.PROPOSED,
        )

    @property
    def policy_violations(self) -> list[str]:
        """Policy authorization violations (M5=0 invariant)."""
        return self.final_state.authorization_violations


def _is_arguments_valid_for_tool(tool_name: str, arguments: dict) -> bool:
    if not isinstance(arguments, dict) or not arguments:
        return False
    if tool_name == "observe":
        return bool(arguments.get("command"))
    if tool_name == "query_metrics":
        return bool(arguments.get("metric_name"))
    if tool_name == "query_logs":
        return bool(arguments.get("log_group"))
    if tool_name == "update_hypotheses":
        return bool(arguments.get("updates"))
    if tool_name == "propose_step":
        spec = arguments.get("execution_spec")
        return bool(isinstance(spec, dict) and spec.get("command")) or bool(arguments.get("command"))
    if tool_name == "conclude":
        return bool(arguments.get("root_cause"))
    if tool_name == "verify":
        return bool(arguments.get("step_id"))
    if tool_name == "escalate":
        return bool(arguments.get("reason"))
    return True


# ---------------------------------------------------------------------------
# Reasoning Loop
# ---------------------------------------------------------------------------

class ReasoningLoop:
    """
    Reasoning loop — runs continuously until termination.

    max_cycles: Circuit breaker against infinite loops (in addition to state budget)
    """

    def __init__(
        self,
        model: ModelInterface,
        store: EventStore,
        backend: ObserveBackend,
        instance_id: str,
        max_cycles: int = 30,
        tool_decider: Optional[ToolDecider] = None,
    ):
        self._model = model
        self._store = store
        self._backend = backend
        self._instance_id = instance_id
        self._max_cycles = max_cycles
        # NullToolDecider = backward compat (preserves existing test behavior)
        self._tool_decider: ToolDecider = tool_decider or NullToolDecider()
        self._executor = ToolExecutor(store, backend, instance_id)

    @staticmethod
    def _is_arguments_valid_for_tool(tool_name: str, arguments: dict) -> bool:
        return _is_arguments_valid_for_tool(tool_name, arguments)

    def _compute_effective_limit(self, state: IncidentState, max_steps: Optional[int] = None) -> int:
        hard_cap = max(self._max_cycles, 25)
        max_cmd = getattr(state.budgets, "max_commands", 30.0) if hasattr(state, "budgets") else 30.0

        if max_cmd <= 4.0:
            cmd_limit = 6
        elif max_cmd <= 8.0:
            cmd_limit = 12
        elif max_cmd <= 12.0:
            cmd_limit = 16
        elif max_cmd <= 18.0:
            cmd_limit = 25
        else:
            cmd_limit = hard_cap

        cycles_budget = int(getattr(state.budgets, "max_cycles", hard_cap))
        dynamic_limit = min(hard_cap, self._max_cycles, cmd_limit, cycles_budget)

        if max_steps is not None:
            return min(dynamic_limit, max_steps)
        return dynamic_limit

    def run(self, state: IncidentState, max_steps: Optional[int] = None) -> LoopResult:
        """
        Runs reasoning loop from the given state.
        max_steps: Test-only override — halts after N steps even if unfinished.
        """
        tool_calls: list[ToolCall] = []
        tool_results: list[ToolResult] = []
        cycle = int(state.budgets.cycles)

        seen_calls: set[tuple[str, str]] = set()
        seen_propose_cmds: set[str] = set()
        denied_commands: dict[str, str] = {}
        denied_command_attempts: dict[str, int] = {}
        if getattr(state, "steps", None):
            for s_id, s in state.steps.items():
                p_cmd = s.execution_spec.get("command", "") if isinstance(s.execution_spec, dict) else ""
                is_pol_denied = (s_id in state.policy_decisions and getattr(state.policy_decisions[s_id].decision, "value", "") == "deny")
                if p_cmd and (getattr(s, "status", None) == "rejected" or is_pol_denied):
                    p_clean = str(p_cmd).strip()
                    p_norm = re.sub(r"^sudo\s+", "", p_clean).strip()
                    p_pol = state.policy_decisions.get(s_id)
                    p_reasons = "; ".join(p_pol.reasons) if (p_pol and p_pol.reasons) else "PolicyGate rejection"
                    denied_commands[p_clean] = p_reasons
                    denied_commands[p_norm] = p_reasons
                    denied_command_attempts[p_clean] = 1
                    denied_command_attempts[p_norm] = 1

        executed_history: list[str] = []
        failed_history: list[str] = []
        failed_attempts: list[dict[str, Any]] = []
        last_tool: Optional[str] = None
        last_successful_tool: Optional[str] = None
        last_executed_tool: Optional[str] = None
        # RC-3: Counter for cycles without new successful evidence (detects stalled progress)
        no_new_evidence_cycles: int = 0
        # RC-4: Consecutive failed tools counter (passed to Decider)
        consecutive_failed_tools: int = 0
        evidence_count_before: int = len(state.evidence)
        # RC-5: Tracks tools forced via override that subsequently failed — avoids repeat forcing
        override_failures: dict[str, int] = {}
        was_overridden: bool = False

        for i in range(self._max_cycles):
            effective_limit = self._compute_effective_limit(state, max_steps)
            if max_steps is not None and i >= max_steps:
                return LoopResult(
                    termination=LoopTermination.STEP_LIMIT,
                    cycles_completed=i,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )

            if i >= effective_limit:
                self._escalate_to_store(
                    state,
                    f"Dynamic cycle budget limit ({effective_limit}) reached without resolution (04 §9)",
                )
                state = self._executor._rebuild_state(state.incident_id)
                return LoopResult(
                    termination=LoopTermination.MAX_CYCLES,
                    cycles_completed=i,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )

            # Check termination condition
            stop = self._check_termination(state)
            if stop:
                return LoopResult(
                    termination=stop,
                    cycles_completed=i,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )

            # Check cycle budget
            if state.budgets.cycles >= state.budgets.max_cycles:
                return LoopResult(
                    termination=LoopTermination.BUDGET_EXHAUSTED,
                    cycles_completed=i,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )

            # RC-3: Detect stalled investigation — escalate if 5 cycles elapse without new successful evidence
            # (Threshold raised from 3 to 5 to avoid premature escalation in deep exploration scenarios)
            if no_new_evidence_cycles >= 5 and i >= 3:
                logger.warning(
                    f"Stalled investigation: {no_new_evidence_cycles} consecutive cycles "
                    "without new successful evidence — escalating"
                )
                self._escalate_to_store(
                    state,
                    f"Investigation stalled: {no_new_evidence_cycles} consecutive cycles "
                    "without new successful evidence (RC-3 progress detection)",
                )
                state = self._executor._rebuild_state(state.incident_id)
                return LoopResult(
                    termination=LoopTermination.MAX_CYCLES,
                    cycles_completed=i,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )

            # Build reasoning context
            ctx = build_context(state, cycle=cycle + i)
            # RC-4: Pass consecutive failure count to Decider
            ctx.consecutive_failed_tools = consecutive_failed_tools

            # Prevent updating hypotheses in two consecutive cycles without another tool execution
            if last_successful_tool == "update_hypotheses":
                ctx.available_tools = [t for t in ctx.available_tools if t != "update_hypotheses"]

            # Append execution history summary to ctx.incident_summary
            if executed_history:
                ctx.incident_summary += f"\nexecuted_calls: {json.dumps(executed_history[-5:], ensure_ascii=False)}"
            if failed_history:
                ctx.incident_summary += f"\nfailed_calls: {json.dumps(failed_history[-5:], ensure_ascii=False)}"
            if failed_attempts:
                ctx.incident_summary += f"\n\nprevious_tool_failures:\n{json.dumps(failed_attempts[-5:], ensure_ascii=False, indent=2)}"

            # ── Step A: Strands Decider selects tool (binding) ─────────────────
            decision: Optional[ToolDecision] = self._tool_decider.select(ctx)

            if decision is not None and decision.is_low_confidence:
                # confidence < LOW_THRESHOLD -> immediate escalation (no unsafe execution)
                logger.warning(
                    f"Strands low confidence={decision.confidence:.2f} "
                    f"on tool={decision.tool_name} — escalating"
                )
                self._escalate_to_store(
                    state,
                    f"Strands Decider confidence={decision.confidence:.2f} below "
                    f"threshold={LOW_CONFIDENCE_THRESHOLD} for tool={decision.tool_name}"
                )
                state = self._executor._rebuild_state(state.incident_id)
                return LoopResult(
                    termination=LoopTermination.ESCALATED,
                    cycles_completed=i,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                    strands_decision=decision,
                )

            # tool_hint for model: informs parameter synthesis
            if decision is not None and decision.tool_name in ctx.available_tools:
                tool_hint = decision.tool_name
            elif not isinstance(self._tool_decider, NullToolDecider):
                has_active_hyps = any(
                    h.status in ("active", "confirmed")
                    for h in state.hypotheses.values()
                )
                if not state.evidence and "observe" in ctx.available_tools:
                    tool_hint = "observe"
                elif state.evidence and not has_active_hyps and "update_hypotheses" in ctx.available_tools:
                    tool_hint = "update_hypotheses"
                else:
                    tool_hint = None
            else:
                tool_hint = None

            # Protect agent from premature or low-confidence conclude hints
            has_confirmed_healthy_hyp = any(
                str(getattr(h, "status", "")).lower() in ("confirmed", "active", "hypothesisstatus.confirmed", "hypothesisstatus.active")
                and float(getattr(h, "confidence", 0.0)) >= 0.70
                and any(w in getattr(h, "statement", "").lower() for w in ("healthy", "normal", "nominal", "false alarm", "no fault", "false_alarm"))
                for h in state.hypotheses.values()
            )
            if tool_hint == "conclude" and decision is not None:
                if (decision.confidence < 0.65 or len(state.evidence) < 2) and not has_confirmed_healthy_hyp:
                    logger.info(
                        f"Guarding premature low-confidence conclude hint (conf={decision.confidence:.2f}, "
                        f"evidence_count={len(state.evidence)}). Switching effective tool_hint to 'observe'."
                    )
                    tool_hint = "observe" if "observe" in ctx.available_tools else None

            # Protect against cycle exhaustion via repetitive update_hypotheses hints
            has_no_new_evidence = bool(state.hypotheses) and len(state.evidence) <= len(state.hypotheses)
            if tool_hint == "update_hypotheses":
                if last_executed_tool == "update_hypotheses" or has_no_new_evidence:
                    if "observe" in ctx.available_tools:
                        logger.info(
                            f"Guarding redundant update_hypotheses hint (last_executed={last_executed_tool!r}, "
                            f"evidence_count={len(state.evidence)}, hyp_count={len(state.hypotheses)}). "
                            "Switching effective tool_hint to 'observe'."
                        )
                        tool_hint = "observe"

            # model_tier: from Strands decision — does not bypass Policy Gate
            model_tier = decision.model_tier if decision is not None else FALLBACK_MODEL_TIER

            # ── Step B: Generative model synthesizes arguments ──────────────────────
            try:
                # ModelRouter accepts model_tier as kwarg;
                # plain ModelInterface ignores it (signature handles **kwargs implicitly).
                response: ModelResponse = _invoke_model(
                    self._model, ctx,
                    tool_hint=tool_hint,
                    model_tier=model_tier,
                )
                tool_call = response.tool_call
            except Exception as exc:
                logger.error(f"Model error at cycle {i}: {exc}")
                tool_call = ToolCall(
                    tool_name="escalate",
                    arguments={"reason": f"Model invocation failed: {exc}"},
                    reasoning="auto-escalate on model error",
                )

            # ── Step C: Respect generative model selection or enforce Strands safety net ─
            is_model_failure = (
                tool_call.reasoning in ("auto-escalate on model error", "parse-error")
                or (tool_call.tool_name == "escalate" and "Model invocation failed" in tool_call.arguments.get("reason", ""))
            )
            model_choice_valid = bool(
                tool_call.tool_name
                and tool_call.tool_name in ctx.available_tools
                and not is_model_failure
            )

            # Validate arguments for tool selected by generative model
            if model_choice_valid and not self._is_arguments_valid_for_tool(tool_call.tool_name, tool_call.arguments):
                logger.info(
                    f"Model chose valid tool {tool_call.tool_name!r} but arguments are invalid/empty; "
                    f"re-invoking model with restricted_ctx=[{tool_call.tool_name!r}]"
                )
                try:
                    restricted_ctx = replace(ctx, available_tools=[tool_call.tool_name])
                    retry_resp = _invoke_model(
                        self._model,
                        restricted_ctx,
                        tool_hint=tool_call.tool_name,
                        model_tier=model_tier,
                    )
                    if self._is_arguments_valid_for_tool(tool_call.tool_name, retry_resp.tool_call.arguments):
                        tool_call = ToolCall(
                            tool_name=tool_call.tool_name,
                            arguments=retry_resp.tool_call.arguments,
                            reasoning=retry_resp.tool_call.reasoning or tool_call.reasoning,
                        )
                    else:
                        logger.warning(
                            f"Model re-invocation for {tool_call.tool_name!r} still produced invalid arguments: "
                            f"{retry_resp.tool_call.arguments}"
                        )
                        model_choice_valid = False
                except Exception as exc:
                    logger.warning(f"Model re-invocation for tool {tool_call.tool_name!r} failed: {exc}")
                    model_choice_valid = False

            is_tool_valid = model_choice_valid
            was_overridden = False

            # Anti-Hesitation & Decisive Remediation:
            # When Decider recommends transition to propose_step with high confidence (>= 0.70)
            # while model hesitates with update_hypotheses (or observe when budget is tight),
            # guide agent to propose_step to submit remediation instead of circling in theoretical analysis.
            if (
                is_tool_valid
                and decision is not None
                and decision.tool_name == "propose_step"
                and decision.confidence >= 0.70
                and "propose_step" in ctx.available_tools
            ):
                tight_budget = i >= (effective_limit - 4)
                repeat_update = (tool_call.tool_name == "update_hypotheses" and last_executed_tool == "update_hypotheses")
                has_solid_hypothesis = any(
                    (float(getattr(h, "confidence", 0.0)) >= 0.70 or str(getattr(h, "status", "")).lower() in ("confirmed", "active", "hypothesisstatus.confirmed", "hypothesisstatus.active"))
                    for h in state.hypotheses.values()
                )
                has_fresh_observation = (last_executed_tool == "observe" and len(state.evidence) > len(state.hypotheses))

                should_override = False
                if tool_call.tool_name == "update_hypotheses":
                    if repeat_update or tight_budget:
                        should_override = True
                    elif has_solid_hypothesis and not has_fresh_observation and len(state.evidence) >= 3:
                        should_override = True
                elif tool_call.tool_name == "observe" and tight_budget and len(state.evidence) >= 4:
                    should_override = True

                if should_override:
                    logger.info(
                        f"Anti-Hesitation triggered at cycle={i}: model chose {tool_call.tool_name!r} but "
                        f"propose_step is ready (conf={decision.confidence:.2f}, repeat_update={repeat_update}, "
                        f"tight_budget={tight_budget}, hypotheses_ready={has_solid_hypothesis}). "
                        f"Overriding to propose_step."
                    )
                    is_tool_valid = False

            if not is_tool_valid and decision is not None:
                override_tool = decision.tool_name

                # Defense: If model chose observe/propose_step (known tools)
                # but excluded from available_tools due to legacy phase gate, re-enable them
                # rather than forcing conclude or another unintended tool
                if (
                    tool_call.tool_name in ("observe", "propose_step")
                    and tool_call.tool_name not in ctx.available_tools
                ):
                    logger.info(
                        f"Safety net: re-enabling model's valid tool choice {tool_call.tool_name!r} "
                        f"(was incorrectly excluded from available_tools)"
                    )
                    override_tool = tool_call.tool_name

                if override_tool == "conclude" and (decision.confidence < 0.65 or len(state.evidence) < 2) and not has_confirmed_healthy_hyp:
                    override_tool = "observe" if "observe" in ctx.available_tools else "conclude"
                if override_tool == "update_hypotheses" and (last_executed_tool == "update_hypotheses" or has_no_new_evidence):
                    override_tool = "observe" if "observe" in ctx.available_tools else "update_hypotheses"

                # RC-5: Do not force an override on a tool that has already failed >=2 times as an override
                if override_tool in override_failures and override_failures[override_tool] >= 2:
                    logger.info(
                        f"RC-5: skipping override to {override_tool!r} — failed "
                        f"{override_failures[override_tool]} times as override. "
                        "Letting model choice stand or escalating."
                    )
                elif override_tool in ctx.available_tools:
                    was_overridden = True
                    logger.info(
                        f"Strands safety net override: model chose invalid/failed tool {tool_call.tool_name!r} "
                        f"→ enforcing {override_tool!r} (confidence={decision.confidence:.2f})"
                    )
                    # If arguments are empty or invalid for the forced tool, re-invoke the model
                    if not _is_arguments_valid_for_tool(override_tool, tool_call.arguments):
                        logger.info(
                            f"Strands override: arguments invalid/empty for {override_tool!r}; "
                            f"re-invoking model with tool_hint={override_tool!r}"
                        )
                        try:
                            restricted_ctx = replace(ctx, available_tools=[override_tool])
                            retry_resp = _invoke_model(
                                self._model,
                                restricted_ctx,
                                tool_hint=override_tool,
                                model_tier=decision.model_tier,
                            )
                            if _is_arguments_valid_for_tool(override_tool, retry_resp.tool_call.arguments):
                                tool_call = ToolCall(
                                    tool_name=override_tool,
                                    arguments=retry_resp.tool_call.arguments,
                                    reasoning=(
                                        f"[Strands override confidence={decision.confidence:.2f}] "
                                        + retry_resp.tool_call.reasoning
                                    ),
                                )
                            else:
                                new_args = retry_resp.tool_call.arguments if retry_resp.tool_call.arguments else {}
                                tool_call = ToolCall(
                                    tool_name=override_tool,
                                    arguments=new_args,
                                    reasoning=(
                                        f"[Strands override confidence={decision.confidence:.2f}] "
                                        + retry_resp.tool_call.reasoning
                                    ),
                                )
                        except Exception as exc:
                            logger.warning(f"Strands override model re-invocation failed: {exc}")
                            tool_call = ToolCall(
                                tool_name=override_tool,
                                arguments={},
                                reasoning=f"[Strands override confidence={decision.confidence:.2f}] " + tool_call.reasoning,
                            )
                    else:
                        tool_call = ToolCall(
                            tool_name=override_tool,
                            arguments=tool_call.arguments,
                            reasoning=f"[Strands override confidence={decision.confidence:.2f}] " + tool_call.reasoning,
                        )
                else:
                    logger.warning(
                        f"Strands chosen tool {decision.tool_name!r} not in available_tools {ctx.available_tools}, skipping override"
                    )
            elif is_tool_valid and decision is not None and tool_call.tool_name != decision.tool_name:
                logger.info(
                    f"Preserving generative model valid choice {tool_call.tool_name!r} (in available_tools); "
                    f"Strands suggestion {decision.tool_name!r} not overriding."
                )

            if decision is not None:
                logger.info(
                    f"cycle={i} strands={decision.tool_name} "
                    f"confidence={decision.confidence:.2f} "
                    f"model_tier={model_tier} "
                    f"final_tool={tool_call.tool_name}"
                )

            # Progress Guard: Clean, validate, and normalize observe command
            if tool_call.tool_name == "observe":
                cmd = tool_call.arguments.get("command", "").strip()
                had_operators = False
                if not cmd:
                    alarm_context = (
                        (getattr(state, "alarm_name", "") or "")
                        + " "
                        + (ctx.incident_summary or "")
                    ).lower()
                    if "disk" in alarm_context or "storage" in alarm_context or "space" in alarm_context:
                        cmd = "df -h"
                    elif "memory" in alarm_context or "ram" in alarm_context:
                        cmd = "free -m"
                    else:
                        cmd = "ps aux"
                    new_args = dict(tool_call.arguments)
                    new_args["command"] = cmd
                    tool_call = ToolCall(
                        tool_name="observe",
                        arguments=new_args,
                        reasoning=f"[Progress Guard default observe command] {tool_call.reasoning}".strip(),
                    )
                else:
                    # 1. Reject find commands with -exec or -delete: explicit rejection to prevent side effects or semantic corruption
                    has_find = cmd.startswith("find ") or cmd == "find" or cmd.startswith("sudo find ")
                    has_find_exec = has_find and bool(re.search(r"\bfind\b.*-(?:exec|execdir|delete)\b", cmd))
                    if has_find_exec:
                        logger.info(f"Progress Guard: rejecting find command with embedded actions: {cmd!r}")
                        result = ToolResult(
                            tool_name="observe",
                            success=False,
                            message=(
                                f"Command rejected: contains unsupported find embedded action (-exec/-delete): {cmd[:120]!r}. "
                                "Commands must not be altered silently. Rewrite as a pure observation search command "
                                "(e.g., 'find <path> -type f -size +100M') without embedding execution or deletion."
                            ),
                        )
                        tool_calls.append(tool_call)
                        tool_results.append(result)
                        failed_history.append(f"observe: find embedded action rejected in {cmd[:60]!r}")
                        failed_attempts.append({
                            "tool_name": "observe",
                            "arguments": tool_call.arguments,
                            "error_message": result.message,
                        })
                        last_tool = "observe"
                        consecutive_failed_tools += 1
                        no_new_evidence_cycles += 1
                        continue

                    # 2. Convert du commands ending in /* to safe depth syntax: du -h -d 1 <path>
                    cmd_stripped = cmd.strip()
                    if re.search(r"(?:^|\s)du\b", cmd_stripped) and re.search(r"/\*\s*$", cmd_stripped):
                        prefix = "sudo " if cmd_stripped.startswith("sudo ") else ""
                        m_du = re.search(r"\bdu\b.*?\s+([^\s*]+)/\*\s*$", cmd_stripped)
                        if m_du:
                            target_p = m_du.group(1).rstrip("/") or "/"
                            cleaned_du = f"{prefix}du -h -d 1 {target_p}"
                        elif re.search(r"\bdu\b.*?\s+/\*\s*$", cmd_stripped):
                            cleaned_du = f"{prefix}du -h -d 1 /"
                        else:
                            cleaned_du = re.sub(r"/\*\s*$", "", cmd_stripped).strip()
                        logger.info(
                            f"Progress Guard: converted du wildcard path {cmd!r} -> {cleaned_du!r}"
                        )
                        cmd = cleaned_du
                        had_operators = True

                    # 3. Reject shell operators and compound pipelines (|, ;, &&, ||, >, <, >>, &, $(), ``):
                    #    Explicit rejection to prevent semantic alteration and silent partial execution (Semantic Integrity Enforcement)
                    has_shell_operator = any(op in cmd for op in ("|", ";", "&&", "||", ">", "<", "$(", "`", "&"))
                    if has_shell_operator:
                        logger.info(
                            f"Progress Guard: rejecting compound command with shell operators: {cmd!r}"
                        )
                        result = ToolResult(
                            tool_name="observe",
                            success=False,
                            message=(
                                f"Command rejected: contains unsupported compound shell operators or pipeline: {cmd[:120]!r}. "
                                "Commands are executed directly via exec without a shell interpreter and must not be altered silently. "
                                "Please rewrite as a single direct command without operators "
                                "(e.g., use 'grep -E <pattern> <file>' directly instead of 'cat | grep', "
                                "or 'pgrep -a <name>' instead of 'ps aux | grep', or 'journalctl -u <service>' directly)."
                            ),
                        )
                        tool_calls.append(tool_call)
                        tool_results.append(result)
                        failed_history.append(f"observe: shell operators rejected in {cmd[:60]!r}")
                        failed_attempts.append({
                            "tool_name": "observe",
                            "arguments": tool_call.arguments,
                            "error_message": result.message,
                        })
                        last_tool = "observe"
                        consecutive_failed_tools += 1
                        no_new_evidence_cycles += 1
                        continue

                # Apply normalization for bare du and df commands so call_key matches executed command
                from .tool_executor import normalize_observation_command
                normalized_cmd = normalize_observation_command(cmd)
                if had_operators or normalized_cmd != tool_call.arguments.get("command"):
                    new_args = dict(tool_call.arguments)
                    new_args["command"] = normalized_cmd
                    reasoning = tool_call.reasoning
                    if had_operators:
                        reasoning = f"[Normalized path wildcard] {reasoning}".strip()
                    elif normalized_cmd != cmd:
                        reasoning = f"[Normalized command] {reasoning}".strip()
            # ── Prerequisite Readiness & Cross-Round Deduplication Gate ──
            # If the agent proposes a remediation step (propose_step):
            is_mock_backend = type(self._backend).__name__ == "MockObserveBackend"
            if tool_call.tool_name == "propose_step" and not is_mock_backend:
                args = tool_call.arguments if isinstance(tool_call.arguments, dict) else {}
                spec = args.get("execution_spec", {}) if isinstance(args, dict) else {}
                cmd = ""
                if isinstance(spec, dict) and spec.get("command"):
                    cmd = spec.get("command", "")
                elif isinstance(args, dict) and args.get("command"):
                    cmd = args.get("command", "")
                clean_cmd = str(cmd).strip()
                norm_cmd = re.sub(r"^sudo\s+", "", clean_cmd).strip()

                # ── Edge Case 1: Check whether target service is already active (running) ──
                target_unit = ""
                target_unit_base = ""
                is_active_running = False
                unit_failed = False
                latest_unit_status = None
                service_main_pid = None
                if norm_cmd.startswith(("systemctl start", "systemctl restart")):
                    parts = norm_cmd.split()
                    non_flags = [p for p in parts if not p.startswith("-")]
                    target_unit = non_flags[-1] if non_flags else ""
                    if target_unit and (target_unit.endswith(".service") or "." not in target_unit):
                        target_unit_base = target_unit.lower().replace(".service", "")
                        for ev in reversed(list(state.evidence.values())):
                            src = getattr(ev, "source", "").lower()
                            summ = getattr(ev, "summary", "")
                            full_text = (src + "\n" + summ).lower()
                            if f"status {target_unit_base}" in full_text or f"status {target_unit.lower()}" in full_text or f"is-active {target_unit_base}" in full_text:
                                latest_unit_status = full_text
                                mpm = re.search(r"main pid:\s*(\d+)", summ, re.IGNORECASE) or re.search(r"\bpid:\s*(\d+)", summ, re.IGNORECASE)
                                if mpm:
                                    service_main_pid = mpm.group(1)
                                break
                        if latest_unit_status:
                            if "active (running)" in latest_unit_status or "active: active" in latest_unit_status:
                                is_active_running = True
                            elif "is-active" in latest_unit_status and "active" in latest_unit_status and "inactive" not in latest_unit_status:
                                is_active_running = True

                        if not service_main_pid:
                            for ev in state.evidence.values():
                                ev_s = getattr(ev, "summary", "")
                                if target_unit_base in ev_s.lower():
                                    mpm = re.search(r"main pid:\s*(\d+)", ev_s, re.IGNORECASE)
                                    if mpm:
                                        service_main_pid = mpm.group(1)
                                        break

                        if not is_active_running:
                            if latest_unit_status:
                                unit_failed = any(kw in latest_unit_status for kw in (
                                    "failed", "inactive (dead)", "failed (result", "activating (auto-restart)", "deactivating", "address already in use"
                                ))
                            else:
                                evidence_text = " ".join((getattr(e, "summary", "") + " " + getattr(e, "source", "")).lower() for e in state.evidence.values())
                                unit_failed = bool(
                                    re.search(rf"\b{re.escape(target_unit_base)}(\.service)?\b[^\n]*\bfailed\b", evidence_text, re.IGNORECASE)
                                    or f"{target_unit_base}.service: failed" in evidence_text
                                    or f"{target_unit_base} failed" in evidence_text
                                    or (f"● {target_unit_base}" in evidence_text and "failed" in evidence_text)
                                )

                # ── Edge Case 2: Prevent repeating successful remediation commands across rounds and redirect to conclude ──
                already_succeeded_exact = any(
                    getattr(s, "status", "") in ("succeeded", "executed")
                    and re.sub(r"^sudo\s+", "", getattr(s, "execution_spec", {}).get("command", "")).strip() == norm_cmd
                    for s in state.steps.values()
                )

                already_succeeded_service = False
                if target_unit_base:
                    prior_service_success = any(
                        getattr(s, "status", "") in ("succeeded", "executed")
                        and any(kw in getattr(s, "execution_spec", {}).get("command", "").lower()
                               for kw in (f"start {target_unit_base}", f"restart {target_unit_base}"))
                        for s in state.steps.values()
                    )
                    if prior_service_success and (is_active_running or not unit_failed):
                        already_succeeded_service = True

                if (already_succeeded_exact or already_succeeded_service) and norm_cmd:
                    logger.warning(
                        f"Loop guard: Duplicate propose_step rejected across rounds for '{clean_cmd}'. "
                        f"Action was already executed and succeeded in a prior round. Redirecting to conclude."
                    )
                    tool_call = ToolCall(
                        tool_name="conclude",
                        arguments={
                            "root_cause": f"Action '{clean_cmd}' was already successfully executed and verified in a prior cycle.",
                            "confidence": 0.95,
                        },
                        reasoning=f"Step '{clean_cmd}' already succeeded and service is operational. Concluding incident as resolved.",
                    )

                elif norm_cmd.startswith(("systemctl start", "systemctl restart")):
                    unit = target_unit
                    unit_base = target_unit_base
                    if unit and (unit.endswith(".service") or "." not in unit):

                        # Thorough verification: Was the failure cause diagnosed beforehand?
                        has_status = any(
                            (f"status {unit_base}" in getattr(e, "source", "").lower() or
                             f"status {unit.lower()}" in getattr(e, "source", "").lower() or
                             f"status {unit_base}" in getattr(e, "summary", "").lower())
                            for e in state.evidence.values()
                        )
                        has_journal = any(
                            "journalctl" in (getattr(e, "source", "") + " " + getattr(e, "summary", "")).lower() and
                            unit_base in (getattr(e, "source", "") + " " + getattr(e, "summary", "")).lower()
                            for e in state.evidence.values()
                        )
                        has_port_triage = any(
                            any(p_kw in (getattr(e, "source", "") + " " + getattr(e, "summary", "")).lower()
                                for p_kw in ("ss -tulpn", "netstat", "lsof", "address already in use", "already in use", "errno 98"))
                            for e in state.evidence.values()
                        )
                        has_diagnosed = has_status or has_journal or has_port_triage

                        if unit_failed and not has_diagnosed:
                            logger.warning(
                                f"Loop guard: Premature service start rejected for failed unit '{unit}'. "
                                f"Must diagnose failure cause via status/journalctl first."
                            )
                            tool_call = ToolCall(
                                tool_name="observe",
                                arguments={"command": f"systemctl status {unit}"},
                                reasoning=f"Root-Cause Before Restart: Must inspect why {unit} failed before restarting.",
                            )
                        elif unit_failed:
                            # 1. If any prior remediation step succeeded, the blocker has already been eliminated
                            prior_remediation_succeeded = any(
                                getattr(s, "status", "") in ("succeeded", "executed")
                                for s in state.steps.values()
                                if getattr(s, "kind", "") == "mutate" or any(
                                    kw in getattr(s, "execution_spec", {}).get("command", "").lower()
                                    for kw in ("kill", "pkill", "truncate", "rm ", "rm -", ">", "sed", "systemctl reset-failed")
                                )
                            )

                            blocker_pid = None
                            if not prior_remediation_succeeded:
                                protected_daemons = (
                                    "systemd", "init", "sshd", "ssh", "amazon-ssm-agent", "ssm-agent",
                                    "dbus", "chronyd", "chrony", "rpcbind", "dhclient", "auditd",
                                    "systemd-resolved", "systemd-journald", "systemd-networkd", "rsyslog"
                                )
                                protected_ports = (":22 ", ":22\t", ":53 ", ":123 ", ":323 ", ":68 ", ":111 ")

                                for h in state.hypotheses.values():
                                    if getattr(h, "status", "") in ("active", "confirmed"):
                                        # Check if hypothesis references port/PID contention or blocker process
                                        htext = getattr(h, "statement", "")
                                        if any(kw in htext.lower() for kw in ("occup", "use", "port", "pid", "bind", "listen", "conflict", "block")):
                                            pm = re.search(r"\bpid\b[^\d]*(\d+)", htext, re.IGNORECASE)
                                            if pm and pm.group(1) not in ("0", "1"):
                                                candidate = pm.group(1)
                                                if candidate != service_main_pid:
                                                    blocker_pid = candidate
                                                    break

                                if not blocker_pid:
                                    for ev in state.evidence.values():
                                        ev_full = (getattr(ev, "summary", "") + "\n" + getattr(ev, "source", ""))
                                        for line in ev_full.splitlines():
                                            llow = line.lower()
                                            if any(pd in llow for pd in protected_daemons):
                                                continue
                                            if any(pt in line for pt in protected_ports):
                                                continue
                                            # Exclude lines for Main PID, CGroup, and Tasks belonging to the service itself
                                            if "main pid" in llow or "cgroup" in llow or "tasks:" in llow:
                                                continue
                                            pm = re.search(r"pid=(\d+)", line, re.IGNORECASE) or re.search(r"\bpid\s+(\d+)", line, re.IGNORECASE)
                                            if pm and pm.group(1) not in ("0", "1"):
                                                candidate = pm.group(1)
                                                if candidate != service_main_pid:
                                                    blocker_pid = candidate
                                                    break
                                        if blocker_pid:
                                            break

                                if blocker_pid and service_main_pid and blocker_pid == service_main_pid:
                                    blocker_pid = None

                            blocker_eliminated = prior_remediation_succeeded
                            if blocker_pid and not blocker_eliminated:
                                for step in state.steps.values():
                                    if getattr(step, "status", "") in ("succeeded", "executed"):
                                        scmd = getattr(step, "execution_spec", {}).get("command", "")
                                        if f"kill {blocker_pid}" in scmd or f"kill -9 {blocker_pid}" in scmd or "pkill" in scmd:
                                            blocker_eliminated = True
                                            break

                            if blocker_pid and not blocker_eliminated:
                                logger.warning(
                                    f"Loop guard: Premature service start rejected for '{unit}'. "
                                    f"Active blocker PID {blocker_pid} must be eliminated first."
                                )
                                cited_ev = [ev.evidence_id for ev in state.evidence.values() if blocker_pid in getattr(ev, "summary", "") or "ss -tulpn" in getattr(ev, "summary", "")]
                                if not cited_ev:
                                    cited_ev = list(state.evidence.keys())[-2:]
                                cited_hyps = [h.hypothesis_id for h in state.hypotheses.values() if getattr(h, "status", "") in ("active", "confirmed")][:1]

                                tool_call = ToolCall(
                                    tool_name="propose_step",
                                    arguments={
                                        "kind": "mutate",
                                        "execution_spec": {"command": f"kill {blocker_pid}"},
                                        "declared_effects": [{
                                            "category": "E1",
                                            "resource": f"process:{blocker_pid}",
                                            "description": f"Terminate rogue process {blocker_pid} occupying port",
                                        }],
                                        "based_on_evidence": cited_ev[:2],
                                        "based_on_hypotheses": cited_hyps,
                                        "rollback_plan": "none",
                                        "rollback_reason": "process termination",
                                        "risk_claim": "low",
                                    },
                                    reasoning=f"Prerequisite Readiness: Rogue process PID {blocker_pid} is occupying the port. Must eliminate blocker before starting {unit}.",
                                )

            # ── 4-Layer Production Triage Guard against Premature Conclude ──
            # Guard against premature conclude: runs unconditionally (even after successful remediations)
            # to ensure the agent inspected all core system pillars before concluding the incident.
            if tool_call.tool_name == "conclude" and not is_mock_backend:
                evidence_text = " ".join(
                    (getattr(e, "summary", "") + " " + getattr(e, "source", "")).lower()
                    for e in state.evidence.values()
                )

                # After executing a remediation step (kill/restart), inspecting a single service like
                # `systemctl status nginx` is insufficient to cover the service layer —
                # the agent must have inspected the overall list of failed services.
                has_executed_steps = any(
                    getattr(s, "status", "") in ("executed", "succeeded")
                    for s in state.steps.values()
                )
                if has_executed_steps:
                    # Post-remediation: require list-units or --failed check specifically, or verification that service is active (running)
                    has_services = any(w in evidence_text for w in ("list-units", "--failed", "systemctl --failed", "active (running)", "active: active"))
                else:
                    # Prior to remediation: general service check suffices
                    has_services = any(w in evidence_text for w in ("systemctl", "systemd", "failed unit", "loaded unit", "service"))

                has_network = any(w in evidence_text for w in ("ss ", "netstat", "port", "tcp", "listen", "curl", "socket", "lsof"))
                has_storage = any(w in evidence_text for w in ("df ", "df -h", "du ", "du -", "filesystem", "disk space", "disk usage"))
                has_processes = any(w in evidence_text for w in ("ps ", "top", "uptime", "load average"))

                missing_triage = []
                if not has_storage:
                    missing_triage.append("storage/disk (e.g. df -h)")
                if not has_network:
                    missing_triage.append("network/ports (e.g. ss -tulpn)")
                if not has_services:
                    missing_triage.append("services (e.g. systemctl list-units --state=failed)")
                if not has_processes:
                    missing_triage.append("processes/resources (e.g. ps aux)")

                if missing_triage and len(state.evidence) < 8:
                    if not has_storage:
                        next_cmd = "df -h"
                    elif not has_network:
                        next_cmd = "ss -tulpn"
                    elif not has_services:
                        next_cmd = "systemctl list-units --state=failed"
                    else:
                        next_cmd = "ps aux"

                    logger.warning(
                        f"Loop guard: Premature conclude rejected! Missing triage layers: {missing_triage}. "
                        f"Redirecting agent to run {next_cmd}."
                    )
                    tool_call = ToolCall(
                        tool_name="observe",
                        arguments={"command": next_cmd},
                        reasoning=f"4-Layer Production Triage: Must inspect {', '.join(missing_triage)} before declaring system healthy.",
                    )

            # ── PolicyGate Denial Re-planning & Semantic Remediation Deduplication Gate ──
            if tool_call.tool_name == "propose_step":
                p_args = tool_call.arguments if isinstance(tool_call.arguments, dict) else {}
                p_spec = p_args.get("execution_spec", {}) if isinstance(p_args, dict) else {}
                p_cmd = str(p_spec.get("command") or p_args.get("command") or "").strip()
                p_norm = re.sub(r"^sudo\s+", "", p_cmd).strip()

                # 1. Denied Commands Interception & Fast-Escalation
                if p_cmd in denied_commands or p_norm in denied_commands:
                    denied_reason = denied_commands.get(p_cmd) or denied_commands.get(p_norm) or "PolicyGate Hard Deny"
                    attempts = max(denied_command_attempts.get(p_cmd, 0), denied_command_attempts.get(p_norm, 0)) + 1
                    denied_command_attempts[p_cmd] = attempts
                    denied_command_attempts[p_norm] = attempts
                    logger.warning(
                        f"Loop guard: Repeated propose_step for denied command {p_cmd!r} (attempt {attempts}). "
                        f"Reason: {denied_reason}"
                    )
                    if attempts >= 2:
                        self._escalate_to_store(
                            state,
                            f"Fast Escalation: Agent repeatedly re-proposed command {p_cmd!r} which was hard-denied by PolicyGate ({denied_reason}). Escalating for human intervention.",
                        )
                        state = self._executor._rebuild_state(state.incident_id)
                        return LoopResult(
                            termination=LoopTermination.ESCALATED,
                            cycles_completed=i + 1,
                            final_state=state,
                            tool_calls=tool_calls,
                            tool_results=tool_results,
                        )
                    else:
                        result = ToolResult(
                            tool_name="propose_step",
                            success=False,
                            message=(
                                f"Command {p_cmd!r} was already REJECTED by PolicyGate: {denied_reason}. "
                                "You are strictly prohibited from repeating this command or altering only its description. "
                                "You must switch remediation strategy (e.g. terminate the offending process directly by its specific numeric PID with kill <pid>, without forbidden keywords) or call escalate."
                            ),
                        )
                        tool_calls.append(tool_call)
                        tool_results.append(result)
                        failed_history.append(f"propose_step: repeated denied command {p_cmd[:50]!r}")
                        failed_attempts.append({
                            "tool_name": "propose_step",
                            "arguments": tool_call.arguments,
                            "error_message": result.message,
                        })
                        last_tool = "propose_step"
                        consecutive_failed_tools += 1
                        no_new_evidence_cycles += 1
                        continue

                # 2. Semantic Remediation Deduplication (Across description variations)
                if p_norm:
                    if p_norm in seen_propose_cmds:
                        logger.warning(
                            f"Loop guard: duplicate propose_step command detected for '{p_norm}'. "
                            "Rejecting duplicate to prevent loop."
                        )
                        result = ToolResult(
                            tool_name="propose_step",
                            success=False,
                            message=(
                                f"Duplicate command rejected: propose_step with command '{p_norm}' was already executed or proposed. "
                                "Do not repeat identical remediation commands even with rephrased descriptions. "
                                "Switch remediation strategy or verify system status or conclude if resolved."
                            ),
                        )
                        tool_calls.append(tool_call)
                        tool_results.append(result)
                        failed_attempts.append({
                            "tool_name": "propose_step",
                            "arguments": tool_call.arguments,
                            "error_message": result.message,
                        })
                        failed_history.append(f"propose_step: duplicate command {p_norm[:50]!r} rejected")
                        last_tool = "propose_step"
                        consecutive_failed_tools += 1
                        no_new_evidence_cycles += 1
                        continue
                    seen_propose_cmds.add(p_norm)

            call_key = (tool_call.tool_name, json.dumps(tool_call.arguments, sort_keys=True))
            if call_key in seen_calls:
                # Exact literal duplicate of tool and arguments: prevent loop without imposing static fallback command
                logger.warning(
                    f"Loop guard: duplicate call detected for {tool_call.tool_name} with {tool_call.arguments}. "
                    "Rejecting duplicate to prevent loop."
                )
                is_budget_depleted = (
                    (tool_call.tool_name in ("observe", "verify") and state.budgets.commands >= state.budgets.max_commands)
                    or (tool_call.tool_name == "propose_step" and state.budgets.mutate_steps >= state.budgets.max_mutate_steps)
                )
                result = ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    message=(
                        "commands budget exhausted" if is_budget_depleted else
                        f"Duplicate call rejected: {tool_call.tool_name} with identical arguments was already executed. "
                        "Do not repeat identical calls. If root cause is identified in active hypotheses, proceed immediately to propose_step (e.g. systemctl start <service>), or conclude if healthy."
                    ),
                    budget_exhausted=is_budget_depleted,
                )
                tool_calls.append(tool_call)
                tool_results.append(result)
                failed_attempts.append({
                    "tool_name": tool_call.tool_name,
                    "arguments": tool_call.arguments,
                    "error_message": result.message,
                })
                if is_budget_depleted:
                    self._escalate_to_store(
                        state,
                        "Budget exhausted during agent loop (04 §9: escalate on budget depletion)",
                    )
                    state = self._executor._rebuild_state(state.incident_id)
                    return LoopResult(
                        termination=LoopTermination.BUDGET_EXHAUSTED,
                        cycles_completed=i + 1,
                        final_state=state,
                        tool_calls=tool_calls,
                        tool_results=tool_results,
                    )
                failed_history.append(f"{tool_call.tool_name}: duplicate arguments rejected")
                last_tool = tool_call.tool_name
                consecutive_failed_tools += 1   # RC-4: Rejected duplicate = consecutive failure
                no_new_evidence_cycles += 1     # RC-3: No new evidence
                continue

            seen_calls.add(call_key)
            tool_calls.append(tool_call)

            # Execute tool
            result, state = self._executor.execute(tool_call, state)
            tool_results.append(result)

            # Check if propose_step was denied by PolicyGate
            is_step_denied = False
            denied_reason_msg = ""
            if tool_call.tool_name == "propose_step":
                p_args = tool_call.arguments if isinstance(tool_call.arguments, dict) else {}
                p_spec = p_args.get("execution_spec", {}) if isinstance(p_args, dict) else {}
                p_cmd = str(p_spec.get("command") or p_args.get("command") or "").strip()
                p_norm = re.sub(r"^sudo\s+", "", p_cmd).strip()

                if result.data and result.data.get("policy_decision") == "deny":
                    is_step_denied = True
                    denied_reason_msg = "; ".join(result.data.get("policy_reasons", []))
                elif result.message and "PolicyGate REJECTED" in result.message:
                    is_step_denied = True
                    denied_reason_msg = result.message
                elif any(getattr(s, "status", None) == "rejected" for s in state.steps.values()):
                    latest_step = list(state.steps.values())[-1]
                    if getattr(latest_step, "status", None) == "rejected":
                        is_step_denied = True
                        pol = state.policy_decisions.get(latest_step.step_id)
                        denied_reason_msg = "; ".join(pol.reasons) if (pol and pol.reasons) else "PolicyGate Invariant rejection"

                if is_step_denied and (p_cmd or p_norm):
                    denied_commands[p_cmd] = denied_reason_msg or "PolicyGate Deny"
                    denied_commands[p_norm] = denied_reason_msg or "PolicyGate Deny"
                    denied_command_attempts[p_cmd] = max(denied_command_attempts.get(p_cmd, 0), 1)
                    denied_command_attempts[p_norm] = max(denied_command_attempts.get(p_norm, 0), 1)

            call_desc = f"{tool_call.tool_name}({tool_call.arguments.get('command') or tool_call.arguments.get('metric_name') or ''})"
            last_tool = tool_call.tool_name
            if not result.success or is_step_denied:
                err_msg = denied_reason_msg if is_step_denied else result.message
                failed_history.append(f"{call_desc}: {err_msg[:80]}")
                failed_attempts.append({
                    "tool_name": tool_call.tool_name,
                    "arguments": tool_call.arguments,
                    "error_message": err_msg,
                })
                last_successful_tool = None
                last_executed_tool = None
                consecutive_failed_tools += 1  # RC-4
                no_new_evidence_cycles += 1    # RC-3
                # RC-5: If tool was enforced via override -> record failure
                if was_overridden:
                    override_failures[tool_call.tool_name] = override_failures.get(tool_call.tool_name, 0) + 1
            else:
                executed_history.append(call_desc)
                last_successful_tool = tool_call.tool_name
                last_executed_tool = tool_call.tool_name
                consecutive_failed_tools = 0   # RC-4: Reset on success
                # RC-3: Was new evidence actually added?
                # update_hypotheses = reasoning progress (not counted against stagnation counter)
                evidence_count_after = len(state.evidence)
                if evidence_count_after > evidence_count_before:
                    no_new_evidence_cycles = 0
                    evidence_count_before = evidence_count_after
                elif tool_call.tool_name in ("update_hypotheses", "propose_step"):
                    pass  # Reasoning progress — not considered stagnation
                else:
                    no_new_evidence_cycles += 1

            # Stop investigation loop once a valid remediation step accepted by PolicyGate is proposed (Stop on Valid Proposal)
            valid_steps = [s for s in state.steps.values() if getattr(s, "status", None) != "rejected"]
            if tool_call.tool_name == "propose_step" and result.success and not is_step_denied and valid_steps:
                return LoopResult(
                    termination=LoopTermination.PROPOSED,
                    cycles_completed=i + 1,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )

            if result.budget_exhausted:
                self._escalate_to_store(
                    state,
                    "Budget exhausted during agent loop (04 §9: escalate on budget depletion)",
                )
                state = self._executor._rebuild_state(state.incident_id)
                return LoopResult(
                    termination=LoopTermination.BUDGET_EXHAUSTED,
                    cycles_completed=i + 1,
                    final_state=state,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )

            if not result.success:
                logger.warning(f"Tool {tool_call.tool_name} failed: {result.message}")
                # Tool failure does not necessarily terminate the loop — model will be re-invoked
                # but counts against budget (02 §10: verification failure = single retry then escalate)

        # Reached maximum cycles — 04 §9: Escalate with report, never fail silently
        self._escalate_to_store(
            state,
            f"Maximum cycles ({self._max_cycles}) reached without resolution (04 §9)",
        )
        state = self._executor._rebuild_state(state.incident_id)
        return LoopResult(
            termination=LoopTermination.MAX_CYCLES,
            cycles_completed=self._max_cycles,
            final_state=state,
            tool_calls=tool_calls,
            tool_results=tool_results,
        )

    def _escalate_to_store(self, state: IncidentState, reason: str) -> None:
        """
        Write Escalated event to EventStore if incident is not already escalated.
        04 §9: Any budget exhaustion = escalate with report.
        """
        if state.phase == IncidentPhase.escalated:
            return
        try:
            from ..domain.types import EscalatedPayload, build_event, EventType, Actor
            payload = EscalatedPayload(
                reason=reason,
                report_ref=None,
            )
            event = build_event(
                incident_id=state.incident_id,
                type=EventType.Escalated,
                actor=Actor.agent,
                payload=payload,
            )
            seq = self._store.last_seq(state.incident_id)
            self._store.append(state.incident_id, seq, event)
        except Exception as exc:
            logger.error(f"Failed to write Escalated event: {exc}")

    def _check_termination(self, state: IncidentState) -> Optional[LoopTermination]:
        if state.phase == IncidentPhase.resolved:
            return LoopTermination.RESOLVED
        if state.phase == IncidentPhase.concluded:
            return LoopTermination.CONCLUDED
        if state.phase == IncidentPhase.escalated:
            return LoopTermination.ESCALATED
        if state.phase == IncidentPhase.aborted:
            return LoopTermination.ABORTED

        pending_steps = [
            s for s in state.steps.values()
            if getattr(s, "status", "proposed") in ("proposed", None)
        ]
        if pending_steps:
            return LoopTermination.PROPOSED
        # conclusion_proposed terminates the loop — closure handled by verifier in Phase 4
        # Handled here as CONCLUDED awaiting verification
        for ev in self._store.read(state.incident_id):
            if ev.type == "ConclusionProposed" and not self._has_verification_after(state, ev.seq):
                # Agent proposed conclusion — terminate loop
                return LoopTermination.CONCLUDED
        return None

    def _has_verification_after(self, state: IncidentState, conclusion_seq: int) -> bool:
        """Check if there was a verification request after conclusion proposal."""
        for ev in self._store.read(state.incident_id):
            if ev.seq > conclusion_seq and ev.type == "VerificationRequested":
                return True
        return False
