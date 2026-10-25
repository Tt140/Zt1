"""
agent/deepseek_model.py — DeepSeekModel: ModelInterface for DeepSeek API

Used during development instead of Bedrock Nova to save cost.
Follows the exact same ModelInterface — swapping with BedrockNovaModel: one line.

Setup:
  DEEPSEEK_API_KEY=sk-...  (in .env or Lambda env vars)
  DEEPSEEK_MODEL=deepseek-chat  (default)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

from .model_interface import (
    ModelInterface, ModelContext, ModelResponse, ToolCall, VALID_TOOL_NAMES,
)

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
DEFAULT_FLASH_MODEL: str = os.environ.get("INCIDENTS_FLASH_MODEL", "bedrock:deepseek.v3.2")
_API_BASE      = "https://api.deepseek.com/v1"

_SYSTEM_PROMPT = """\
You are an autonomous diagnosis and investigation agent for Linux systems and servers, driven strictly by evidence-based reasoning.
In every response, return ONLY a valid JSON object matching the following format, with no preceding or trailing text:
{"reasoning": "<step-by-step analysis of evidence and hypotheses before tool selection>", "tool_name": "<tool>", "arguments": {<params>}}

Mandatory ordering rule for reasoning and response:
You MUST always write the "reasoning" field first at the beginning of the JSON object. In "reasoning", provide a proactive analysis and synthesis of your digital evidence, cross-referencing hypotheses and UNIX first principles, then choose "tool_name" based on that deductive reasoning, followed by "arguments".

## Environment Capabilities & Grammar:
1. Allowed observation binaries:
   Allowed read-only observation commands are strictly limited to:
   `df`, `du`, `ls`, `stat`, `cat`, `head`, `tail`, `grep`, `ps`, `top`, `free`, `uptime`, `uname`, `hostname`, `systemctl status`, `systemctl is-active`, `systemctl is-failed`, `journalctl`, `dmesg`, `netstat`, `ss`, `lsof`, `find`, `wc`, `curl`, `pgrep`, `mpstat`, `vmstat`, `pidstat`, `echo`, `date`, `id`, `whoami`.
2. Strict syntax restrictions of execution environment:
   - Commands are executed directly via exec without a Shell interpreter.
   - Shell expansion and chaining operators are strictly prohibited: `*`, `?`, `|`, `;`, `&&`, `||`, `>`, `<`, `$()`, `` ` ``, `2>`.
   - To pass options or paths, provide the parent path directly to the command (e.g. pass directory path directly to read or enumerate command without using `*` or globbing).

## Evidence-Driven Reasoning Principles & Scale-Invariant SRE First Principles:
1. Space Accounting Balance: df vs. du:
   - `df -h` measures filesystem blocks allocated at block-level, whereas `du -x -h -d 1 /` calculates total visible file sizes in directory-tree accounting.
   - Always compare consumed space in `df` against total visible space in `du`:
     a) Visible Directory Accounting:
        When the sum of directory sizes in `du` accounts for most consumed space in `df`, disk usage is held in real visible files. Recurse down dominant subdirectories using `du -h -d 1 <dir>` then `ls -lh` or `find <dir> -type f` to pinpoint offending large files. Then transition to `propose_step` to suggest an authorized surgical remediation step via `PolicyGate` to truncate or clean the identified file (category: "E3", risk_claim: "low").
     b) Unlinked Open File Descriptors Accounting:
        When a wide unexplained gap exists between space consumed in `df` and visible space in `du` (blocks allocated on disk but invisible in the directory tree), UNIX physics proves storage blocks are held by unlinked open file descriptors still held by active processes. In this case, run `lsof +L1` to isolate held deleted descriptors and their owning processes, then call `propose_step` for an authorized targeted action via `PolicyGate` to terminate or reload the owning process (category: "E1", risk_claim: "high").
2. Magnitude & Proportionality:
   - The remediation target (whether a file in directories, an active process in `ps`/`top`, or an open descriptor in `lsof +L1`) must proportionally match the actual magnitude and scope of the observed fault in alarms and metrics.
   - Never target peripheral resources or minor processes that cannot account for the outage (e.g. tiny system handles that do not explain disk deficit, or routine low-consumption daemons).
   - Remediation strictly targets the anomalous resource whose volume or consumption matches the drained resource and conclusively explains the failure, selecting the lowest-risk authorized action via `PolicyGate`.
3. CPU & Process Contention Triage:
   - When investigating elevated CPU alarms, immediately inspect active processes via `ps aux` or `top -b -n 1`.
   - Examine process list to isolate anomalous or runaway processes consuming high CPU explaining the alert.
   - Never call `conclude` on a high CPU alert without inspecting process tables and verifying absence of anomalous resource-draining processes. Once identifying the PID directly matching the observed impact, propose the lowest-risk proportionate remediation via `PolicyGate` (category: "E1", risk_claim: "high").
4. Service Availability, Network & Cryptographic Triage:
   - When investigating service availability, network connectivity, or health check failures:
     a) Check service status and system logs via `systemctl status`, `journalctl`, and `dmesg` to inspect operational state and error records.
     b) Inspect active sockets and ports via `ss` or `netstat` to verify listening ports, connection states, and port-binding anomalies.
     c) Inspect active processes via `ps aux` to isolate actual root cause and correlate service, port, and owning PID accurately.
     d) Choose the lowest-risk remediation proportionate to evidence and authorized by `PolicyGate` (e.g. restart stopped service or terminate conflicting rogue process), without assuming a cause before direct evidence.
     e) TLS/SSL Certificate & Handshake Triage:
        - When investigating TLS handshake failure or certificate expiration:
          * Inspect failure output or read certificate via `curl -v`, `cat <cert_file>`, or `stat <cert_file>` to verify validity dates.
          * Inspect certificate directory via `ls -la <cert_dir>` to discover renewed or alternative certificates present on disk.
          * If active certificate is expired and a renewed certificate exists on disk, the exact authorized remediation via PolicyGate is updating certificate path (e.g. `cp <renewed_cert> <active_cert>` with category "E2" and resource as active certificate path) and reloading/restarting service, rather than restarting service with the expired certificate.
5. Core OS Safeguards:
   - It is strictly forbidden to target core OS services or essential kernel/system daemons (`systemd`, `sshd`, `dbus`, `amazon-ssm-agent`) with termination or modification; they are critical infrastructure and never the root cause of application faults.
6. Decisive Transition from Evidence to propose_step:
   - As soon as observation output isolates the offending target (service name, PID, or file path), immediately cease redundant observation commands and transition in the next cycle to `propose_step` with a proportionate authorized action via `PolicyGate`.
7. Maximize Information Gain:
   - Choose the observation command that prunes search space in the fewest cycles, avoiding slow incremental checks to conserve observation budget.
8. Enumerate Before Targeting:
   - Never guess names of sub-entities (files, services, processes, units) not yet observed in collected evidence; inspect parent scope first with direct enumeration (`ls`, `du`, or `ps` on parent path), then target entities confirmed in output.
9. Epistemic Sufficiency & 4-Layer Production Triage:
   - You have complete freedom to guide investigation and order observation tools as appropriate for your hypotheses.
   - However, as a production rule for Safe Resolution (conclude): you may not conclude False Alarm unless core pillars have been verified clean with direct evidence:
     (a) Services layer: Ensure no failed units via `systemctl list-units --state=failed`.
     (b) Network & ports layer: Ensure sockets and ports healthy via `ss -tulpn` or `netstat -tulpn`.
     (c) Processes & resources layer: Ensure process health, CPU, and memory via `ps aux` or `top`.
     (d) Storage & disk layer: Ensure disk availability and no volume exhaustion via `df -h` or `du`.
   - Root Cause Resolution (propose_step): Upon detecting an anomaly in any layer (rogue process on port, stopped service, bloated file, expired cert), immediately focus on this anomaly, update active hypothesis, and propose authorized remediation via `PolicyGate`.
   - Causal Prerequisite Ordering & Root-Cause First:
     In any compound failure (Root Blocker -> Service Symptom):
     1. You MUST target removing the root blocker in step 1 first (e.g. terminate rogue process holding port `kill <pid>`, truncate full disk, or update expired cert `cp`).
     2. Never rush to propose `systemctl start/restart` for failed service before resolving root blocker.
     3. Terminating an evidenced rogue process holding a port with specific PID (risk_claim: low) is an authorized surgical action via PolicyGate; execute step 1 to free resource, then in step 2 start stopped service.
   - Escalate on Insufficient Evidence (escalate): If observation budget is exhausted before isolating confirmed cause, call escalate immediately.
10. Non-Repetition: Do not repeat a command already executed in prior evidence; select a check adding new information or transition to hypothesis/remediation.

## Argument Specifications per Tool:

observe:
  {"command": "<direct read-only command without shell expansion or chaining>", "timeout_seconds": 30}

query_metrics:
  {"metric_name": "<metric_name>", "period_seconds": 300}

query_logs:
  {"log_group": "<log_group>", "query": "", "minutes_back": 30}

update_hypotheses:
  {"updates": [{"statement": "...", "confidence": 0.8, "evidence_id": "<evidence_id from evidence>", "status": "active"}], "complexity": "low"}
  Note: On first update_hypotheses, assess problem complexity and set complexity field to ("low" for straightforward single-resource issues, or "medium"/"high" for compound/ambiguous issues) to adapt investigation budget. Set status to "refuted" if hypothesis is disproved by evidence.

propose_step:
  {"kind": "mutate",
   "execution_spec": {"command": "<specific direct remediation command without shell interpreter>"},
   "based_on_hypotheses": ["<hypothesis_id>"], "based_on_evidence": ["<evidence_id>"],
   "declared_effects": [{"category": "E3", "resource": "<target file or resource path>", "description": "<expected impact description>"}],
   "rollback_plan": "none", "risk_claim": "low"}
  Important propose_step guidelines:
  - kind: Must be strictly "mutate".
  - declared_effects: Category is "E3" for cleanup/truncation of logs/temp files, "E1" for process/service lifecycle (start/restart/terminate), or "E2" for configuration/certificate modifications; resource is path of affected file or target resource.
  - risk_claim: "low" for surgical non-destructive operations (e.g. truncating transient log or restarting standard service) for autonomous PolicyGate approval, or "high" for sensitive operations requiring human approval.

verify:
  {"step_id": "<step_id from propose_step>"}

conclude:
  {"root_cause": "...", "confidence": 0.85, "supporting_evidence": []}

escalate:
  {"reason": "..."}

## Strict Rules:
- observe: Read-only commands strictly from allowed whitelist without Shell interpreter; shell expansion or chaining operators (*, ?, |, ;, &&, >, 2>) are prohibited. Modifying commands (rm, dd, mkfs, reboot, halt) are strictly disallowed.
- Do not repeat a command already executed in prior evidence.
- propose_step: command must be a single direct command without shell interpreter and without chaining (&&, ;, | forbidden). When updated certificate is on disk (e.g. _renewed.crt), use cp to copy to active path with category="E2" and resource active cert path, or systemctl restart/start; private keys in /etc/ssl/private are security protected and prohibited from modification (I-15).
- propose_step: declared_effects and rollback_plan must be populated.
- propose_step PolicyGate compliance: If a proposed step was rejected by PolicyGate (status: rejected in remediation_history), you are STRICTLY PROHIBITED from re-proposing that command or altering only its description. Invariant I-02 strictly prohibits SSH keywords in execution specs; if an offending process runs under a unit with ssh in its name, do not stop the unit with systemctl, but terminate the specific rogue process directly by its numeric PID (e.g. `kill <pid>`) which contains no SSH keywords and is an authorized surgical action. If no alternative authorized remediation exists, call escalate immediately.
- evidence_id in update_hypotheses: Use the latest evidence_id from collected evidence.
"""
class DeepSeekModel(ModelInterface):
    """
    DeepSeek Chat API — Development alternative to Bedrock Nova.
    Integrates tool_hint in user message to steer parameter generation.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = _DEFAULT_MODEL,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        timeout_seconds: float = 60.0,
        http_client=None,
        api_base: Optional[str] = None,
        fallback_model: Optional[str] = None,
    ):
        self._api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not self._api_key:
            raise ValueError(
                "DEEPSEEK_API_KEY is required — set it as an environment variable or pass it directly"
            )
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._timeout_seconds = timeout_seconds
        self._http_client = http_client  # for tests (mock)
        self._api_base = api_base or os.environ.get("DEEPSEEK_BASE_URL", _API_BASE)
        if fallback_model:
            self._fallback_model = fallback_model
        elif self._model.startswith("deepseek.v3"):
            self._fallback_model = os.environ.get("INCIDENTS_FLASH_MODEL", "deepseek.v3.2").replace("bedrock:", "")
        elif self._model.startswith("deepseek-"):
            self._fallback_model = "deepseek-flash"
        elif "bedrock" in self._api_base:
            self._fallback_model = os.environ.get("INCIDENTS_FLASH_MODEL", "deepseek.v3.2").replace("bedrock:", "")
        else:
            self._fallback_model = "deepseek-flash"

    @staticmethod
    def _is_transient_error(exc: Exception) -> bool:
        try:
            import httpx
            if isinstance(exc, httpx.HTTPStatusError):
                if exc.response.status_code in (400, 401, 403, 422):
                    return False
                if exc.response.status_code in (408, 500, 502, 503, 504):
                    return True
            if isinstance(exc, (httpx.TimeoutException, httpx.TransportError)):
                return True
        except ImportError:
            pass
        if "timed out" in str(exc).lower():
            return True
        exc_name = type(exc).__name__.lower()
        if any(term in exc_name for term in ("timeout", "transporterror", "connecterror", "networkerror")):
            return True
        return False

    @staticmethod
    def _build_user_message(ctx: ModelContext, tool_hint: Optional[str] = None) -> str:
        advisory_hint = ""
        direct_hint = ""
        if tool_hint:
            if len(ctx.available_tools) > 1:
                advisory_hint = (
                    f"\n\n## Advisory Tool Hint\n"
                    f"Initial analyzer suggestion: {tool_hint!r}.\n"
                    "This suggestion is advisory and non-binding; the final tool selection among available tools must strictly follow the observed evidence in the Evidence section below without prior bias:\n"
                    "- If evidence confirms system health and fault hypotheses are refuted -> select conclude.\n"
                    "- If an active hypothesis is confirmed with a clear root cause in the hypotheses section (e.g. stopped service or resource exhaustion) and 'propose_step' is available -> immediately transition to propose_step for remediation (e.g. systemctl start <service> or truncate file) and stop redundant observation or hypothesis updates.\n"
                    "- If latest evidence isolated root cause accurately but hypothesis is not yet updated -> select update_hypotheses.\n"
                    "- If the active hypothesis specifically identifies the offending entity and is confirmed by evidence -> select propose_step (with kind=\"mutate\" and appropriate declared_effects like E3 for cleanup or E1 for processes with proper target/resource).\n"
                    "- If observation budget is exhausted without isolating a verified root cause -> select escalate (never propose remediation based on incomplete speculation).\n"
                    f"- In normal unresolved investigative situations, evaluate recommendation {tool_hint!r} and generate arguments after analyzing evidence in the reasoning field."
                )
            else:
                direct_hint = (
                    f"\n\nRequired tool: {tool_hint!r}. "
                    "Generate appropriate arguments for it."
                )

        # Build previous evidence section — displays evidence_id for each piece of evidence
        evidence_block = ""
        if ctx.evidence_summaries:
            lines = []
            for ev in ctx.evidence_summaries:
                eid  = ev.get("evidence_id", "?")
                src  = ev.get("source", "?")
                summ = ev.get("summary", "")
                lines.append(f"- [{eid}] {src}: {summ}")
            evidence_block = (
                "\n\n## Collected Evidence (evidence_id to use in update_hypotheses)\n"
                + "\n".join(lines)
            )

        return (
            f"## Incident\n{ctx.incident_summary}\n\n"
            f"## Hypotheses\n{ctx.hypotheses_summary}"
            + advisory_hint
            + evidence_block
            + f"\n\n## Available Tools\n{', '.join(ctx.available_tools)}\n\n"
            f"## Budget Remaining\n{ctx.budget_remaining}"
            + direct_hint
        )

    def _compute_dynamic_limits(
        self,
        messages: list[dict],
        requested_max_tokens: Optional[int] = None,
    ) -> tuple[int, float]:
        """
        Dynamically calculates max tokens and timeout based on actual context size and model tier:
        - Pro tier (deepseek.v3.2, pro, v4):
            * Starts at 4096 and scales with context size up to 8192 tokens (or uses requested_max_tokens if larger).
            * Timeout starts at max(self._timeout_seconds, 45.0) and dynamically extends up to 90.0s.
        - Flash tier (deepseek.v3.1, flash, or default models):
            * Starts at 2048 and scales with large contexts up to 4096 tokens.
            * Timeout starts at self._timeout_seconds and extends up to 45.0s when needed.
        """
        total_chars = sum(len(str(m.get("content", ""))) for m in messages)
        model_name = self._model.lower()
        is_pro = "pro" in model_name or "v3.2" in model_name or "v4" in model_name

        if is_pro:
            # Pro tier scaling: 4096 -> 8192 tokens, timeout: max(timeout, 45.0) -> 90.0s
            if total_chars > 8000:
                base_tokens = 8192
                base_timeout = 90.0
            elif total_chars > 3000:
                scale = (total_chars - 3000) / 5000.0
                base_tokens = int(4096 + scale * 4096)
                base_timeout = round(
                    max(self._timeout_seconds, 45.0)
                    + scale * max(0.0, 90.0 - max(self._timeout_seconds, 45.0)),
                    1,
                )
            else:
                base_tokens = 4096
                base_timeout = max(self._timeout_seconds, 45.0)

            effective_max_tokens = (
                max(base_tokens, requested_max_tokens)
                if requested_max_tokens is not None
                else base_tokens
            )
            effective_timeout = max(base_timeout, self._timeout_seconds)
            effective_timeout = (
                min(effective_timeout, 90.0)
                if self._timeout_seconds <= 90.0
                else self._timeout_seconds
            )
        else:
            # Flash tier scaling: 2048 -> 4096 tokens, timeout: timeout -> 45.0s
            if total_chars > 8000:
                base_tokens = 4096
                base_timeout = max(self._timeout_seconds, 45.0)
            elif total_chars > 3000:
                scale = (total_chars - 3000) / 5000.0
                base_tokens = int(2048 + scale * 2048)
                base_timeout = round(
                    self._timeout_seconds
                    + scale * max(0.0, 45.0 - self._timeout_seconds),
                    1,
                )
            else:
                base_tokens = 2048
                base_timeout = self._timeout_seconds

            effective_max_tokens = (
                max(base_tokens, requested_max_tokens)
                if requested_max_tokens is not None
                else base_tokens
            )
            effective_timeout = max(base_timeout, self._timeout_seconds) if self._timeout_seconds > 45.0 else base_timeout

        return effective_max_tokens, float(effective_timeout)

    def invoke(
        self, ctx: ModelContext, tool_hint: Optional[str] = None
    ) -> ModelResponse:
        user_content = self._build_user_message(ctx, tool_hint=tool_hint)

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_content},
        ]

        dyn_max_tokens, dyn_timeout = self._compute_dynamic_limits(messages)

        payload = {
            "model": self._model,
            "messages": messages,
            "max_tokens": dyn_max_tokens,
            "temperature": self._temperature,
            "response_format": {"type": "json_object"},
        }

        if self._http_client:
            # Mock for tests
            raw_text = self._http_client.post(payload)
            return self._parse_response(raw_text)

        def _call_api(target_payload: dict, timeout: float, allow_expansion: bool = True) -> str:
            import httpx
            resp = httpx.post(
                f"{self._api_base.rstrip('/')}/chat/completions",
                json=target_payload,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                return ""

            choice = choices[0]
            finish_reason = choice.get("finish_reason")
            content = choice.get("message", {}).get("content", "") if isinstance(choice.get("message"), dict) else ""

            # Auto-expansion protection on response truncation (Auto-Expansion on finish_reason == "length")
            if finish_reason == "length" and allow_expansion:
                current_tokens = target_payload.get("max_tokens", self._max_tokens)
                expanded_tokens = min(current_tokens * 2, 16384)
                expanded_timeout = min(timeout * 1.5, 120.0)
                logger.warning(
                    f"DeepSeekModel: finish_reason='length' (token truncation detected). "
                    f"Auto-expanding max_tokens from {current_tokens} to {expanded_tokens} "
                    f"and timeout to {expanded_timeout}s, retrying once..."
                )
                expanded_payload = dict(target_payload)
                expanded_payload["max_tokens"] = expanded_tokens
                return _call_api(expanded_payload, timeout=expanded_timeout, allow_expansion=False)

            return content

        try:
            raw_text = _call_api(payload, timeout=dyn_timeout)
            parsed = self._parse_response(raw_text)

            # If response is empty or parse-error occurred -> retry once using fallback_model
            if not (raw_text or "").strip() or parsed.tool_call.reasoning == "parse-error":
                logger.warning(
                    f"DeepSeek empty response or parse error on initial attempt; retrying once with {self._fallback_model}..."
                )
                retry_payload = dict(payload)
                retry_payload["model"] = self._fallback_model
                retry_payload["messages"] = list(payload["messages"]) + [
                    {"role": "assistant", "content": raw_text or ""},
                    {
                        "role": "user",
                        "content": (
                            "Warning: Previous response was not valid JSON or was empty/truncated. "
                            "You must retry and return ONLY a valid JSON object matching the required schema with no Markdown code fences or extra text:\n"
                            '{"reasoning": "<evidence analysis first>", "tool_name": "<name>", "arguments": {...}}'
                        ),
                    },
                ]
                fb_tokens, fb_timeout = self._compute_dynamic_limits(retry_payload["messages"])
                retry_payload["max_tokens"] = fb_tokens
                retry_raw_text = _call_api(retry_payload, timeout=fb_timeout)
                return self._parse_response(retry_raw_text)

            return parsed

        except Exception as exc:
            # If timeout or transient connection error occurs on non-fallback model -> fallback retry with fallback_model
            if self._model != self._fallback_model and self._is_transient_error(exc):
                logger.warning(
                    f"DeepSeekModel: transient error {exc} on {self._model!r}; "
                    f"falling back to {self._fallback_model} (timeout={dyn_timeout}s)..."
                )
                try:
                    fallback_payload = dict(payload)
                    fallback_payload["model"] = self._fallback_model
                    fb_tokens, fb_timeout = self._compute_dynamic_limits(fallback_payload["messages"])
                    fallback_payload["max_tokens"] = fb_tokens
                    fallback_raw_text = _call_api(fallback_payload, timeout=fb_timeout)
                    return self._parse_response(fallback_raw_text)
                except Exception as fb_exc:
                    logger.error(f"DeepSeekModel fallback to {self._fallback_model} failed: {fb_exc}")
                    raise

            logger.error(f"DeepSeekModel error: {exc}")
            raise

    @staticmethod
    def _parse_response(raw_text: str) -> ModelResponse:
        cleaned = (raw_text or "").strip()
        # Strip Markdown code fence wrapper such as ```json ... ``` or ``` ... ```
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()

        if not cleaned:
            logger.warning("DeepSeek response is empty or whitespace only")
            return ModelResponse(
                tool_call=ToolCall(
                    tool_name="escalate",
                    arguments={"reason": "Empty response from DeepSeek model"},
                    reasoning="parse-error",
                ),
                raw_response=raw_text,
            )

        try:
            data = json.loads(cleaned)
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning(
                f"Failed to parse DeepSeek response as JSON: {exc}. Snippet: {raw_text[:200]!r}"
            )
            return ModelResponse(
                tool_call=ToolCall(
                    tool_name="escalate",
                    arguments={"reason": f"JSON parse error: {raw_text[:200]}"},
                    reasoning="parse-error",
                ),
                raw_response=raw_text,
            )

        if not isinstance(data, dict):
            logger.warning(f"DeepSeek response JSON is not an object/dict: {data!r}")
            return ModelResponse(
                tool_call=ToolCall(
                    tool_name="escalate",
                    arguments={"reason": f"JSON root is not an object: {raw_text[:200]}"},
                    reasoning="parse-error",
                ),
                raw_response=raw_text,
            )

        tool_name = data.get("tool_name", "escalate")
        if tool_name not in VALID_TOOL_NAMES:
            tool_name = "escalate"

        raw_args = data.get("arguments")
        arguments = raw_args if isinstance(raw_args, dict) else {}
        reasoning = str(data.get("reasoning") or "")

        return ModelResponse(
            tool_call=ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                reasoning=reasoning,
            ),
            raw_response=raw_text,
        )

    def complete(self, ctx: ModelContext, tool_hint: Optional[str] = None) -> ModelResponse:
        """Alias for invoke() to ensure flexible caller compatibility."""
        return self.invoke(ctx, tool_hint=tool_hint)

    @property
    def model_id(self) -> str:
        return self._model

    @property
    def name(self) -> str:
        if "bedrock" in self._api_base:
            return f"bedrock:{self._model}"
        return f"deepseek:{self._model}"
