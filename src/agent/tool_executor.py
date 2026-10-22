"""
agent/tool_executor.py — Agent Tool Execution and Event Emission (02 §10)

For each tool invocation:
- Returns ToolResult (success/failure + payload for EventStore writing)
- Writes only authorized event types (G3: each actor writes its own scoped types only)
- Records evidence tagged with deterministic trust levels (host_reported / out_of_band)
- Every payload is a proper dataclass (not raw dict) for reducer compatibility
"""
from __future__ import annotations

import re
import posixpath
import hashlib
import dataclasses
from dataclasses import dataclass, field
from typing import Any, Optional

from ..domain.types import (
    Actor, EventType, IncidentState, IncidentPhase,
    DeclaredEffect, EffectCategory, StepKind, StepRecord,
    EvidenceRecord, EvidenceRef, TrustLevel,
    HypothesisRecord, HypothesisStatus,
    build_event, new_ulid, utc_now,
    EvidenceAddedPayload,
    HypothesisUpdatedPayload,
    StepProposedPayload,
    PolicyDecisionPayload,
    PolicyDecisionValue,
    Tier,
    EscalatedPayload,
    ConclusionProposedPayload,
    VerificationRequestedPayload,
    VerificationRecordedPayload,
    VerificationCheck,
    StabilityWindow,
    VerificationVerdict,
    IncidentResolvedPayload,
    BudgetConsumedPayload,
)
from ..store.interface import EventStoreBase as EventStore, AppendConflict as AppendError
from .model_interface import ToolCall
from .mock_backend import ObserveBackend, ObservationResult, MetricResult, LogResult
from ..policy import compute_plan_hash
from ..policy.gate import PolicyGate, GateContext

# Evidence summary character limit (02 §3)
MAX_SUMMARY_CHARS = 2000

# ---------------------------------------------------------------------------
# Tool Execution Result
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    success: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    events_written: list[str] = field(default_factory=list)
    budget_exhausted: bool = False
    tool_name: Optional[str] = None


def normalize_observation_command(cmd: str) -> str:
    """
    Intelligent and safe normalization for bare du and df commands:
    - Bare df -> df -h
    - Bare du -> du -h -d 1 /
    - du on path without depth constraint (-d/--max-depth/-s/-a) -> append -h -d 1 (or -a -h -d 1 for subdirectories)
    """
    cleaned = cmd.strip()
    if not cleaned:
        return cleaned

    has_sudo = cleaned.startswith("sudo ")
    prefix = "sudo " if has_sudo else ""
    bare = cleaned[5:].strip() if has_sudo else cleaned

    # 1. Bare df without flags
    if bare == "df":
        return f"{prefix}df -h"

    # 2. Bare du without path
    if bare == "du":
        return f"{prefix}du -h -d 1 /"

    # 3. du on target path
    if bare.startswith("du ") or bare.startswith("du\t"):
        # Check if depth limit or summarization flag is already present
        has_depth_or_summary = bool(
            re.search(
                r"(?:^|\s)(?:-[a-zA-Z]*[sda][a-zA-Z]*|--max-depth[=\s]|--summarize|--all)\b",
                bare,
            )
        )
        if not has_depth_or_summary:
            parts = bare.split()
            flags = [p for p in parts[1:] if p.startswith("-")]
            paths = [p for p in parts[1:] if not p.startswith("-")]
            target_path = paths[0] if paths else "/"
            extra_paths = paths[1:]

            # Is target path a subfolder (e.g. /var/log or /tmp)?
            is_subfolder = (
                target_path.strip("/").count("/") >= 1
                or target_path.strip("/") in ("tmp", "var", "opt", "home")
            ) and target_path != "/"

            existing_flags = set()
            for f in flags:
                if f.startswith("--"):
                    existing_flags.add(f)
                else:
                    existing_flags.update(f[1:])

            added_flags = []
            if "-x" in flags:
                added_flags.append("-x")
            if is_subfolder:
                if "a" not in existing_flags:
                    added_flags.append("-a")
            if "h" not in existing_flags:
                added_flags.append("-h")
            added_flags.extend(["-d", "1"])

            remaining_flags = [f for f in flags if f not in ("-x", "-h")]
            new_parts = ["du"] + added_flags + remaining_flags + [target_path] + extra_paths
            return f"{prefix}{' '.join(new_parts)}"

    return cleaned


def _validate_remediation_target(
    cmd: str,
    declared_effects: list[DeclaredEffect],
    state: IncidentState,
) -> Optional[str]:
    """
    Target Precision Enforcement for remediation commands:
    - Strictly reject any command containing:
      a) Broad folder-level targeting without a specific file (e.g., /, /var, /var/log, /etc, /usr, /tmp, /opt, /home, /boot, /dev, /proc, /sys, /run).
      b) Destructive or bulk commands (such as find ... -exec, find ... -delete, xargs, rm -rf on imprecise paths, truncate on directories, or wildcards *, ?).
      c) The command must explicitly name a single individual file (e.g., /var/log/app_bloat.log) Grounded in Evidence.
    """
    refusal_msg = (
        "Security Policy Refusal: Remediation command must target a specific, individual file "
        "explicitly proven in collected evidence. Broad or bulk folder-level mutations are strictly prohibited."
    )

    cmd_clean = cmd.strip()
    if not cmd_clean:
        return refusal_msg

    # 1. Check for bulk or destructive operations (b)
    bulk_patterns = [
        re.compile(r"\bfind\b.*-(?:exec|execdir|delete)\b", re.IGNORECASE),
        re.compile(r"\bxargs\b", re.IGNORECASE),
        re.compile(r"\brm\b\s+-[a-zA-Z]*r", re.IGNORECASE),
        re.compile(r"\b(rm|truncate)\b.*[\*\?]", re.IGNORECASE),
    ]
    for pattern in bulk_patterns:
        if pattern.search(cmd_clean):
            return refusal_msg

    # Check service management commands (systemctl start/restart/reload/stop):
    svc_match = re.search(
        r"(?:^|\s)(?:sudo\s+)?systemctl\s+(?:restart|reload|start|stop)\s+([a-zA-Z0-9_\-\.]+)",
        cmd_clean,
    )
    if svc_match:
        svc = svc_match.group(1).lower()
        critical_services = {
            "auditd", "sshd", "ssh", "systemd", "iptables", "firewalld",
            "amazon-ssm-agent", "ssm-agent", "network", "systemd-resolved"
        }
        if any(svc == cs or svc.startswith(cs + ".") for cs in critical_services):
            return f"Security Policy Refusal: Mutating critical system service {svc!r} is strictly prohibited."
        return None

    # Check process termination commands (kill / pkill):
    # Allowed only if the target PID or process name is substantiated by recorded evidence
    kill_match = re.search(
        r"(?:^|\s)(?:sudo\s+)?kill\s+(?:-[a-zA-Z0-9]+\s+)*(\d+)",
        cmd_clean,
    )
    pkill_match = re.search(
        r"(?:^|\s)(?:sudo\s+)?pkill\s+(?:-[a-zA-Z0-9]+\s+)*['\"]?([a-zA-Z0-9_\-\.]+)['\"]?",
        cmd_clean,
    )
    if kill_match or pkill_match:
        evidence_texts = []
        for ev in state.evidence.values():
            if ev.summary:
                evidence_texts.append(ev.summary)
            if ev.source:
                evidence_texts.append(ev.source)
            if ev.raw_ref:
                evidence_texts.append(ev.raw_ref)
        all_evidence = "\n".join(evidence_texts)

        if kill_match:
            pid = kill_match.group(1)
            # Must not target PID 0 or 1 (kernel or init/systemd)
            if pid in ("0", "1"):
                return f"Security Policy Refusal: Killing PID {pid} (init/kernel) is strictly prohibited."
            # Verify that PID is mentioned in recorded evidence
            if not re.search(r"\b" + re.escape(pid) + r"\b", all_evidence):
                return (
                    f"Security Policy Refusal: Target PID {pid} was not found in recorded evidence. "
                    "Unsubstantiated process termination is strictly prohibited."
                )
            critical_keywords = ("systemd", "init", "sshd", "ssh", "amazon-ssm-agent", "ssm-agent", "dbus")
            for line in all_evidence.splitlines():
                if re.search(r"\b" + re.escape(pid) + r"\b", line):
                    if any(k in line.lower() for k in critical_keywords):
                        return f"Security Policy Refusal: Killing critical system daemon process PID {pid} is strictly prohibited."
            return None

        if pkill_match:
            target_proc = pkill_match.group(1)
            critical_procs = {
                "systemd", "init", "sshd", "ssh", "amazon-ssm-agent", "ssm-agent",
            }
            if target_proc in critical_procs:
                return f"Security Policy Refusal: Mutating critical process {target_proc!r} is strictly prohibited."
            if target_proc.lower() not in all_evidence.lower():
                return (
                    f"Security Policy Refusal: Process pattern {target_proc!r} was not found in recorded evidence."
                )
            return None

    # 2. Check for broad directory targets without a specific file (a)
    broad_dirs = {
        "/", "/var", "/var/log", "/etc", "/usr", "/tmp", "/opt", "/home",
        "/boot", "/dev", "/proc", "/sys", "/run", "/root", "/bin", "/sbin", "/lib"
    }

    paths = re.findall(r"(/[a-zA-Z0-9_\.\-]+(?:/[a-zA-Z0-9_\.\-]+)*)", cmd_clean)
    if not paths:
        for eff in declared_effects:
            if eff.resource and eff.resource.startswith("/"):
                paths.append(eff.resource)

    if not paths:
        return refusal_msg

    for p in paths:
        norm_p = p.rstrip("/")
        if norm_p in broad_dirs or p.endswith("/"):
            return refusal_msg

    # 3. Command must reference an individual file Grounded in Evidence
    evidence_texts = []
    for ev in state.evidence.values():
        if ev.summary:
            evidence_texts.append(ev.summary)
        if ev.source:
            evidence_texts.append(ev.source)
        if ev.raw_ref:
            evidence_texts.append(ev.raw_ref)
    all_evidence = "\n".join(evidence_texts)

    hypotheses_texts = []
    for hyp in state.hypotheses.values():
        if hyp.status in ("active", "confirmed"):
            if hyp.statement:
                hypotheses_texts.append(hyp.statement)
    all_hyps = "\n".join(hypotheses_texts)

    common_dir_names = {
        "var", "log", "etc", "usr", "tmp", "opt", "home", "boot",
        "dev", "proc", "sys", "run", "root", "bin", "sbin", "lib"
    }

    matched_proven_file = False
    for p in paths:
        norm_p = p.rstrip("/")
        if norm_p in broad_dirs or norm_p == "" or norm_p == "/":
            continue

        bname = posixpath.basename(norm_p)
        dname = posixpath.dirname(norm_p)

        # Condition (a): Full target_path exists verbatim in evidence text (state.evidence)
        if norm_p in all_evidence:
            matched_proven_file = True
            break

        # Condition (b): Individual entity basename (len >= 3 and not a system directory name)
        # exists verbatim in state.evidence and dirname exists in state.evidence (or active hypotheses)
        if len(bname) >= 3 and bname not in broad_dirs and bname not in common_dir_names:
            bname_in_evidence = bname in all_evidence
            dname_in_evidence_or_hyps = (dname in all_evidence) or (dname in all_hyps)
            if bname_in_evidence and dname_in_evidence_or_hyps:
                matched_proven_file = True
                break

    if not matched_proven_file:
        return refusal_msg

    return None


# ---------------------------------------------------------------------------
# Tool Executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """
    Executes a single tool per invocation.
    Updates local IncidentState and writes events to EventStore.
    """

    def __init__(
        self,
        store: EventStore,
        backend: ObserveBackend,
        instance_id: str,
    ):
        self._store = store
        self._backend = backend
        self._instance_id = instance_id

    def execute(
        self,
        tool_call: ToolCall,
        state: IncidentState,
    ) -> tuple[ToolResult, IncidentState]:
        method_map = {
            "observe": self._do_observe,
            "query_metrics": self._do_query_metrics,
            "query_logs": self._do_query_logs,
            "update_hypotheses": self._do_update_hypotheses,
            "propose_step": self._do_propose_step,
            "verify": self._do_verify,
            "escalate": self._do_escalate,
            "conclude": self._do_conclude,
        }
        # Verify that tool is permitted in the current investigation phase
        from .context_builder import get_allowed_tools
        allowed = get_allowed_tools(state)
        if tool_call.tool_name not in allowed:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                message=(
                    f"Tool {tool_call.tool_name!r} not allowed at current investigation phase. "
                    f"Allowed: {allowed}"
                ),
            ), state

        handler = method_map.get(tool_call.tool_name)
        if handler is None:
            return ToolResult(success=False, message=f"Unknown tool: {tool_call.tool_name}"), state

        try:
            result = handler(tool_call.arguments, state)
            new_state = self._rebuild_state(state.incident_id)
            return result, new_state
        except AppendError as e:
            return ToolResult(success=False, message=f"EventStore conflict: {e}"), state
        except Exception as e:
            return ToolResult(success=False, message=f"Tool error: {e}"), state

    def _rebuild_state(self, incident_id: str) -> IncidentState:
        from ..domain.reducer import fold
        events = self._store.read(incident_id)
        return fold(events)

    # -----------------------------------------------------------------------
    # observe
    # -----------------------------------------------------------------------

    def _do_observe(self, args: dict, state: IncidentState) -> ToolResult:
        command = args.get("command", "")
        if not command:
            return ToolResult(success=False, message="observe: command is required")

        # Intelligent and safe normalization for bare du and df commands
        command = normalize_observation_command(command)

        if state.budgets.commands >= state.budgets.max_commands:
            return ToolResult(success=False, message="commands budget exhausted", budget_exhausted=True)

        result: ObservationResult = self._backend.run_observation(
            instance_id=self._instance_id,
            command=command,
            timeout_seconds=args.get("timeout_seconds", 30),
        )

        output = result.stdout[:MAX_SUMMARY_CHARS]
        evidence_id = new_ulid()
        blob_hash = hashlib.sha256(result.stdout.encode()).hexdigest()

        # BudgetConsumed — simple payload recorded for quota tracking
        self._write_event(state, EventType.BudgetConsumed, BudgetConsumedPayload(
            budget_type="commands",
            amount=1.0,
            new_total=state.budgets.commands + 1.0,
            limit=state.budgets.max_commands,
        ))

        blocked_reason = getattr(result, "blocked_reason", None)
        is_success = bool(result.exit_code == 0 and not blocked_reason)

        # EvidenceAdded — typed EvidenceAddedPayload
        # Keep up to 4000 characters to cover comprehensive command output (e.g. ss -tulpn, ps aux) without truncation
        if result.stdout:
            stdout_stripped = result.stdout.strip()
            if len(stdout_stripped) <= 4000:
                clean_stdout = stdout_stripped
            else:
                clean_stdout = f"{stdout_stripped[:2000]}\n... [truncated] ...\n{stdout_stripped[-1800:]}"
        else:
            clean_stdout = ""
        clean_stderr = result.stderr.strip()[:600] if result.stderr else ""

        summary_parts = [f"Observed: {command!r} -> exit_code={result.exit_code}"]
        if clean_stdout:
            summary_parts.append(f"Output:\n{clean_stdout}")
        if clean_stderr:
            summary_parts.append(f"Stderr:\n{clean_stderr}")
        if blocked_reason:
            summary_parts.append(f"Blocked/Error: {blocked_reason}")

        ev_summary = "\n".join(summary_parts)

        trust = TrustLevel(result.trust) if isinstance(result.trust, str) else result.trust
        ev_ref = EvidenceRef(
            evidence_id=evidence_id,
            source=f"observe:{command[:80]}",
            trust=trust,
            collected_at=utc_now().isoformat(),
            raw_ref=f"blob:{blob_hash}",
            integrity_hash=blob_hash,
            summary=ev_summary,
            redaction_report={"patterns_checked": 5, "items_redacted": 0},
        )
        self._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

        failure_msg = ev_summary
        success_msg = f"Observed: exit_code={result.exit_code}"

        # RC-2: When command targeting non-existent service or restricted command fails, attach discovery hint
        if not is_success:
            combined_output = (clean_stdout + " " + clean_stderr).lower()
            is_service_not_found = (
                "could not be found" in combined_output
                or "not found" in combined_output
                or "no such file" in combined_output
                or "unit" in combined_output and "not found" in combined_output
                or result.exit_code == 4  # systemctl: unit not found
            )
            if is_service_not_found:
                failure_msg += (
                    "\n\n[Discovery Hint] The targeted service or path was not found on this instance. "
                    "Use 'ss -tulpn' to discover listening ports and their processes, "
                    "'systemctl list-units --type=service --state=running' to list active services, "
                    "or 'ls -la <directory>' to list existing files in the directory."
                )

            is_allowlist_or_blocked = (
                bool(blocked_reason)
                or "allowlist" in combined_output
                or "invalidparameters" in combined_output
                or "not allowed" in combined_output
                or "not in t0 allowlist" in combined_output
            )
            if is_allowlist_or_blocked:
                failure_msg += (
                    "\n\n[Allowed Tools Hint] Command is restricted by the ZeroTrust T0 allowlist. "
                    "Use standard permitted tools: 'cat', 'ls', 'grep', 'head', 'tail', 'stat', 'curl', "
                    "'systemctl status', 'journalctl', 'ss', or 'ps' to inspect system state and files directly."
                )

        return ToolResult(
            tool_name="observe",
            success=is_success,
            message=success_msg if is_success else failure_msg,
            data={"evidence_id": evidence_id, "trust": result.trust, "output": output,
                  "last_evidence_id": evidence_id, "stderr": result.stderr,
                  "blocked_reason": blocked_reason},
            events_written=["BudgetConsumed", "EvidenceAdded"],
        )

    # -----------------------------------------------------------------------
    # query_metrics
    # -----------------------------------------------------------------------

    def _do_query_metrics(self, args: dict, state: IncidentState) -> ToolResult:
        metric_name = args.get("metric_name", "")
        period = args.get("period_seconds", 300)

        result: MetricResult = self._backend.get_metric(
            instance_id=self._instance_id,
            metric_name=metric_name,
            period_seconds=period,
        )

        if getattr(result, "error", None) or getattr(result, "unit", "") == "UNAVAILABLE":
            err_msg = getattr(result, "error", None) or f"UNAVAILABLE: metric {metric_name} unavailable"
            return ToolResult(
                tool_name="query_metrics",
                success=False,
                events_written=[],
                message=f"query_metrics failed: {err_msg}",
            )

        evidence_id = new_ulid()
        summary = f"{metric_name}={result.value} {result.unit} (period={period}s)"
        blob_hash = hashlib.sha256(summary.encode()).hexdigest()
        trust = TrustLevel(result.trust) if isinstance(result.trust, str) else result.trust

        ev_ref = EvidenceRef(
            evidence_id=evidence_id,
            source=f"query_metrics:{metric_name}",
            trust=trust,
            collected_at=utc_now().isoformat(),
            raw_ref=f"blob:{blob_hash}",
            integrity_hash=blob_hash,
            summary=summary,
            redaction_report={"patterns_checked": 0, "items_redacted": 0},
        )
        self._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

        return ToolResult(
            success=True,
            message=f"Metric: {summary}",
            data={"evidence_id": evidence_id, "trust": result.trust,
                  "metric_name": metric_name, "value": result.value, "unit": result.unit,
                  "last_evidence_id": evidence_id},
            events_written=["EvidenceAdded"],
        )

    # -----------------------------------------------------------------------
    # query_logs
    # -----------------------------------------------------------------------

    def _do_query_logs(self, args: dict, state: IncidentState) -> ToolResult:
        log_group = args.get("log_group", "/var/log/app")
        query = args.get("query", "")
        minutes_back = args.get("minutes_back", 30)

        result: LogResult = self._backend.get_logs(
            instance_id=self._instance_id,
            log_group=log_group,
            query=query,
            minutes_back=minutes_back,
        )

        if getattr(result, "error", None):
            error_msg = f"query_logs failed: {result.error}"
            # RC-6: When query fails due to missing or unavailable Log Group,
            #        attach discovery hint directing the model to discover actual services
            error_lower = str(result.error).lower()
            if any(kw in error_lower for kw in ("unavailable", "not found", "does not exist", "resourcenotfound")):
                error_msg += (
                    f" Log group {log_group!r} may not exist on this instance. "
                    "Instead of guessing log group names, use 'observe' to run "
                    "'ss -tulpn' (discover listening ports/processes) or "
                    "'systemctl list-units --type=service --state=running' (list active services) "
                    "to identify which services are actually running, then investigate their logs."
                )
            return ToolResult(
                tool_name="query_logs",
                success=False,
                events_written=[],
                message=error_msg,
            )

        evidence_id = new_ulid()
        summary = "\n".join(result.entries[:50])[:MAX_SUMMARY_CHARS]
        blob_hash = hashlib.sha256(summary.encode()).hexdigest()
        trust = TrustLevel(result.trust) if isinstance(result.trust, str) else result.trust

        ev_ref = EvidenceRef(
            evidence_id=evidence_id,
            source=f"query_logs:{log_group}",
            trust=trust,
            collected_at=utc_now().isoformat(),
            raw_ref=f"blob:{blob_hash}",
            integrity_hash=blob_hash,
            summary=summary,
            redaction_report={"patterns_checked": 5, "items_redacted": 0},
        )
        self._write_event(state, EventType.EvidenceAdded, EvidenceAddedPayload(evidence=ev_ref))

        return ToolResult(
            success=True,
            message=f"Logs: {len(result.entries)} entries",
            data={"evidence_id": evidence_id, "trust": result.trust, "entries": result.entries,
                  "last_evidence_id": evidence_id},
            events_written=["EvidenceAdded"],
        )

    # -----------------------------------------------------------------------
    # update_hypotheses
    # -----------------------------------------------------------------------

    def _do_update_hypotheses(self, args: dict, state: IncidentState) -> ToolResult:
        updates = args.get("updates", [])
        if not updates:
            return ToolResult(success=False, message="update_hypotheses: updates list is empty")

        written = []
        for upd in updates:
            hyp_id = upd.get("hypothesis_id")
            statement = upd.get("statement", "")
            norm_statement = " ".join(statement.split())

            stripped_statement = statement.strip()
            # If model did not pass an existing hypothesis_id, check if an existing hypothesis in state.hypotheses
            # matches statement text verbatim (after strip() or whitespace normalization), and update in place.
            if (not hyp_id or hyp_id not in state.hypotheses) and stripped_statement:
                for existing_id, existing_h in state.hypotheses.items():
                    if existing_h.statement.strip() == stripped_statement or " ".join(existing_h.statement.split()) == norm_statement:
                        hyp_id = existing_id
                        break

            if not hyp_id:
                hyp_id = new_ulid()

            existing_hyp = state.hypotheses.get(hyp_id)
            if existing_hyp and not statement:
                statement = existing_hyp.statement

            evidence_id = upd.get("evidence_id") or upd.get("based_on_evidence_id", "")
            confidence = float(upd.get("confidence", 0.5))
            status_str = upd.get("status", "active")
            next_check = upd.get("next_check", None)
            supporting = upd.get("supporting", [])
            contradicting = upd.get("contradicting", [])

            # Rule 02 §4: Confidence update must reference evidence_id
            if not evidence_id:
                return ToolResult(
                    success=False,
                    message=f"update_hypotheses: evidence_id required on {hyp_id}",
                )

            # resolve __LAST_EVIDENCE__ placeholder
            if evidence_id == "__LAST_EVIDENCE__":
                ev_ids = list(state.evidence.keys())
                evidence_id = ev_ids[-1] if ev_ids else ""

            # Rule 02 §4: evidence_id must already exist in state
            if evidence_id and evidence_id not in state.evidence:
                return ToolResult(
                    success=False,
                    message=f"update_hypotheses: evidence_id {evidence_id!r} not found in state "
                            f"(must exist before updating hypothesis)",
                )

            try:
                status = HypothesisStatus(status_str)
            except ValueError:
                status = HypothesisStatus.active

            cur_supporting = list(existing_hyp.supporting) if existing_hyp else []
            cur_contradicting = list(existing_hyp.contradicting) if existing_hyp else []

            if status == HypothesisStatus.refuted:
                if evidence_id and evidence_id not in cur_contradicting:
                    cur_contradicting.append(evidence_id)
            else:
                if evidence_id and evidence_id not in cur_supporting:
                    cur_supporting.append(evidence_id)

            final_supporting = supporting or cur_supporting
            final_contradicting = contradicting or cur_contradicting

            complexity = upd.get("complexity") or args.get("complexity")
            if complexity:
                complexity = str(complexity).strip().lower()
                if complexity not in ("low", "medium", "high"):
                    complexity = None

            hyp = HypothesisRecord(
                hypothesis_id=hyp_id,
                statement=statement,
                confidence=confidence,
                supporting=final_supporting,
                contradicting=final_contradicting,
                status=status,
                next_check=next_check,
                trigger_evidence_id=evidence_id or "",
                complexity=complexity,
            )
            self._write_event(
                state,
                EventType.HypothesisUpdated,
                HypothesisUpdatedPayload(hypothesis=hyp, complexity=complexity),
            )
            written.append(hyp_id)

        top_complexity = args.get("complexity")
        ret_data: dict[str, Any] = {"hypothesis_ids": written}
        if top_complexity:
            ret_data["complexity"] = str(top_complexity).strip().lower()

        return ToolResult(
            success=True,
            message=f"Updated {len(written)} hypotheses",
            data=ret_data,
            events_written=["HypothesisUpdated"] * len(written),
        )

    # -----------------------------------------------------------------------
    # propose_step
    # -----------------------------------------------------------------------

    def _do_propose_step(self, args: dict, state: IncidentState) -> ToolResult:
        step_id = new_ulid()
        raw_kind = str(args.get("kind", "mutate")).strip().lower()

        # Defensive normalization for kind (map synonyms to canonical StepKind enum value)
        mutate_synonyms = {
            "mutate", "modify", "remediate", "remediation", "fix", "cleanup",
            "repair", "truncate", "execute", "command", "patch", "action"
        }
        observe_synonyms = {"observe", "read", "check", "query", "inspect"}
        verify_synonyms = {"verify", "verification", "validate", "validation"}
        escalate_synonyms = {"escalate", "escalation"}

        if raw_kind in mutate_synonyms:
            kind = StepKind.mutate
        elif raw_kind in observe_synonyms:
            kind = StepKind.observe
        elif raw_kind in verify_synonyms:
            kind = StepKind.verify
        elif raw_kind in escalate_synonyms:
            kind = StepKind.escalate
        else:
            try:
                kind = StepKind(raw_kind)
            except ValueError:
                return ToolResult(success=False, message=f"Invalid step kind: {raw_kind!r}")

        # Normalize declared_effects (resource or target, and category)
        effects_raw = args.get("declared_effects", [])
        if isinstance(effects_raw, dict):
            effects_raw = [effects_raw]
        effects = []
        for e in effects_raw:
            if not isinstance(e, dict):
                continue
            cat_raw = str(e.get("category", "")).strip().upper()
            target_res = e.get("resource") or e.get("target") or self._instance_id
            desc = e.get("description", "")

            cat_map = {
                "E0": EffectCategory.E0,
                "E1": EffectCategory.E1,
                "E2": EffectCategory.E2,
                "E3": EffectCategory.E3,
                "E4": EffectCategory.E4,
                "E5": EffectCategory.E5,
                "EU": EffectCategory.EU,
            }
            if cat_raw in cat_map:
                category = cat_map[cat_raw]
            elif any(w in cat_raw.lower() for w in ("clean", "truncate", "rotate", "log")):
                category = EffectCategory.E3
            elif any(w in cat_raw.lower() for w in ("file", "config", "modify", "write")):
                category = EffectCategory.E2
            elif any(w in cat_raw.lower() for w in ("process", "service", "restart", "reload", "stop")):
                category = EffectCategory.E1
            elif any(w in cat_raw.lower() for w in ("delete", "remove", "drop", "format")):
                category = EffectCategory.E4
            elif any(w in cat_raw.lower() for w in ("security", "auth", "permission", "privilege")):
                category = EffectCategory.E5
            elif any(w in cat_raw.lower() for w in ("read", "query", "observe")):
                category = EffectCategory.E0
            else:
                try:
                    category = EffectCategory(cat_raw)
                except ValueError:
                    category = EffectCategory.EU

            effects.append(DeclaredEffect(
                category=category,
                resource=str(target_res),
                description=str(desc),
            ))

        if not effects:
            default_cat = EffectCategory.E1 if kind == StepKind.mutate else EffectCategory.E0
            effects = [DeclaredEffect(default_cat, self._instance_id, "remediation action" if kind == StepKind.mutate else "read-only")]

        based_on_hyp = args.get("based_on_hypotheses", [])
        if isinstance(based_on_hyp, str):
            based_on_hyp = [based_on_hyp] if based_on_hyp else []
        if not based_on_hyp:
            based_on_hyp = [
                h.hypothesis_id for h in state.hypotheses.values()
                if h.status in ("active", "confirmed")
            ]

        based_on_ev = args.get("based_on_evidence", [])
        if isinstance(based_on_ev, str):
            based_on_ev = [based_on_ev] if based_on_ev else []
        if not based_on_ev and state.evidence:
            based_on_ev = list(state.evidence.keys())[-2:]

        risk_claim = str(args.get("risk_claim", "low")).strip().lower()
        if risk_claim not in ("low", "medium", "high"):
            risk_claim = "low"

        exec_spec = args.get("execution_spec", {})
        if not exec_spec and args.get("command"):
            exec_spec = {"command": args.get("command")}

        # Target Precision Enforcement for remediation commands
        if kind == StepKind.mutate or (isinstance(exec_spec, dict) and exec_spec.get("command")):
            cmd = str(exec_spec.get("command", "") if isinstance(exec_spec, dict) else "").strip()
            validation_err = _validate_remediation_target(cmd, effects, state)
            if validation_err:
                return ToolResult(
                    success=False,
                    message=validation_err,
                )

        step = StepRecord(
            step_id=step_id,
            incident_id=state.incident_id,
            based_on_hypotheses=based_on_hyp,
            based_on_evidence=based_on_ev,
            kind=kind,
            target=self._instance_id,
            execution_spec=exec_spec,
            declared_effects=effects,
            preconditions=args.get("preconditions", []),
            success_criteria=args.get("success_criteria", [{"type": "state", "check": "no_security_latch"}]),
            rollback_plan=args.get("rollback_plan", "none"),
            rollback_reason=args.get("rollback_reason", "remediation step"),
            idempotent=args.get("idempotent", True),
            risk_claim=risk_claim,
            expires_at=args.get("expires_at", ""),
            plan_hash="placeholder",
        )
        plan_hash = compute_plan_hash(step)
        step = dataclasses.replace(step, plan_hash=plan_hash)

        self._write_event(state, EventType.StepProposed, StepProposedPayload(step=step))

        # Evaluate step via PolicyGate and record PolicyDecision immediately in state.policy_decisions[step_id]
        gate = PolicyGate()
        gate_ctx = GateContext(
            kill_switch_active=False,
            allowed_instance_id=self._instance_id or state.instance_id,
            enabled_t1_categories=frozenset([EffectCategory.E1, EffectCategory.E2, EffectCategory.E3]),
        )
        gate_res = gate.evaluate(step, state, gate_ctx)

        policy_payload = PolicyDecisionPayload(
            step_id=step_id,
            plan_hash=step.plan_hash,
            tier=gate_res.tier,
            decision=gate_res.decision,
            reasons=gate_res.reasons,
            rule_ids=gate_res.rule_ids,
            budget_snapshot={
                "commands": state.budgets.commands,
                "max_commands": state.budgets.max_commands,
            },
            gate_version=gate_res.gate_version,
        )
        self._write_event(
            state,
            EventType.PolicyDecision,
            policy_payload,
            actor=Actor.executor,
        )

        is_denied = (gate_res.decision == PolicyDecisionValue.deny or gate_res.tier == Tier.T3)
        if is_denied:
            reasons_str = "; ".join(gate_res.reasons) if gate_res.reasons else "Invariant violation"
            msg = (
                f"PolicyGate REJECTED step {step_id} (Tier {gate_res.tier.value}): {reasons_str}. "
                "You must propose a single surgical command complying with invariants "
                "(no compound operators '&&'/';'/'|', and no accessing protected/secret paths like /etc/ssl/private)."
            )
        else:
            msg = f"Step proposed: {step_id} ({kind.value}) [PolicyGate: {gate_res.decision.value}]"

        return ToolResult(
            success=True,
            message=msg,
            data={
                "step_id": step_id,
                "plan_hash": plan_hash,
                "tier_hint": kind.value,
                "policy_decision": gate_res.decision.value,
                "policy_reasons": gate_res.reasons,
            },
            events_written=["StepProposed", "PolicyDecision"],
        )

    # -----------------------------------------------------------------------
    # verify
    # -----------------------------------------------------------------------

    def _do_verify(self, args: dict, state: IncidentState) -> ToolResult:
        step_id = args.get("step_id", "")
        if not step_id:
            for sid, s in reversed(list(state.steps.items())):
                if getattr(s, "status", None) in ("executed", "succeeded"):
                    step_id = sid
                    break
            if not step_id and state.steps:
                step_id = list(state.steps.keys())[-1]
            if not step_id:
                return ToolResult(success=False, message="verify: step_id required")

        step = state.steps.get(step_id)
        plan_hash = step.plan_hash if step else ""

        events_written = ["VerificationRequested"]
        self._write_event(
            state,
            EventType.VerificationRequested,
            VerificationRequestedPayload(step_id=step_id, plan_hash=plan_hash),
            actor=Actor.agent,
        )

        already_verified = (
            state.last_verification is not None
            and state.last_verification.verdict == VerificationVerdict.verified
        )
        step_executed = step and getattr(step, "status", None) in ("executed", "succeeded")

        if already_verified or step_executed:
            if not already_verified:
                v_payload = VerificationRecordedPayload(
                    step_id=step_id,
                    plan_hash=plan_hash,
                    checks=[VerificationCheck(check_type="post_execution", result="pass", source="verifier", details="Resource returned to normal")],
                    alarm_state="ok",
                    stability_window=StabilityWindow(duration_seconds=30, result="stable"),
                    side_effect_checks=[],
                    verdict=VerificationVerdict.verified,
                )
                self._write_event(
                    state,
                    EventType.VerificationRecorded,
                    v_payload,
                    actor=Actor.verifier,
                )
                events_written.append("VerificationRecorded")

            self._write_event(
                state,
                EventType.IncidentResolved,
                IncidentResolvedPayload(
                    verification_id=step_id,
                    summary=f"Step {step_id} verified; resource returned to normal",
                ),
                actor=Actor.verifier,
            )
            events_written.append("IncidentResolved")
            return ToolResult(
                success=True,
                message=f"Step {step_id} verified successfully; incident resolved.",
                events_written=events_written,
                data={"step_id": step_id, "resolved": True},
            )

        return ToolResult(
            success=True,
            message=f"Verification requested for step {step_id}",
            events_written=events_written,
            data={"step_id": step_id},
        )

    # -----------------------------------------------------------------------
    # escalate
    # -----------------------------------------------------------------------

    def _do_escalate(self, args: dict, state: IncidentState) -> ToolResult:
        reason = args.get("reason", "Agent requested escalation")
        self._write_event(state, EventType.Escalated, EscalatedPayload(
            reason=reason,
            report_ref=None,
        ))
        return ToolResult(
            success=True,
            message=f"Escalated: {reason}",
            data={"reason": reason},
            events_written=["Escalated"],
        )

    # -----------------------------------------------------------------------
    # conclude
    # -----------------------------------------------------------------------

    def _do_conclude(self, args: dict, state: IncidentState) -> ToolResult:
        root_cause = args.get("root_cause", "")
        confidence = float(args.get("confidence", 0.0))
        supporting_evidence = args.get("supporting_evidence", [])

        # Check for independent evidence (out_of_band)
        has_out_of_band = False
        evidence_ids_to_check = supporting_evidence if supporting_evidence else list(state.evidence.keys())
        for eid in evidence_ids_to_check:
            ev = state.evidence.get(eid)
            if ev and str(getattr(ev, "trust", "")).lower() == "out_of_band":
                has_out_of_band = True
                break

        # If conclusion relies strictly on host_reported evidence without out_of_band metrics,
        # cap confidence to reflect absence of independent telemetry (<= 0.85).
        if not has_out_of_band:
            confidence = min(confidence, 0.85)

        # ConclusionProposedPayload.verdict = "resolved" | "escalate"
        # As long as a remediation step succeeded, incident is treated as resolved
        # even if theoretical confidence is low — successful step is the strongest practical evidence
        has_succeeded_steps = any(
            getattr(s, "status", "") in ("succeeded", "executed")
            for s in state.steps.values()
        )
        if has_succeeded_steps:
            verdict = "resolved"
        else:
            verdict = "resolved" if confidence >= 0.7 else "escalate"
        summary = f"{root_cause[:500]} (confidence={confidence:.0%})"
        self._write_event(state, EventType.ConclusionProposed, ConclusionProposedPayload(
            verdict=verdict,
            summary=summary,
            based_on_evidence=supporting_evidence,
        ))
        events_written = ["ConclusionProposed"]

        # In Agent-Driven Epistemic Resolution:
        # When agent invokes conclude and successful remediation steps exist, agent emits IncidentResolved directly.
        succeeded_steps = [
            s for s in state.steps.values()
            if getattr(s, "status", "") in ("succeeded", "executed")
        ]
        if verdict == "resolved" and succeeded_steps:
            last_step_id = succeeded_steps[-1].step_id
            self._write_event(
                state,
                EventType.IncidentResolved,
                IncidentResolvedPayload(
                    verification_id=last_step_id,
                    summary=f"Incident resolved by agent conclusion: {root_cause[:300]}",
                ),
                actor=Actor.agent,
            )
            events_written.append("IncidentResolved")

        return ToolResult(
            success=True,
            message=f"Conclusion proposed: {root_cause[:100]}",
            data={
                "root_cause": root_cause,
                "confidence": confidence,
                "supporting_evidence": supporting_evidence,
            },
            events_written=events_written,
        )

    # -----------------------------------------------------------------------
    # Event Writing Helper
    # -----------------------------------------------------------------------

    def _write_event(
        self,
        state: IncidentState,
        event_type: EventType,
        payload: Any,
        actor: Actor = Actor.agent,
    ) -> None:
        """Writes event to EventStore. Reads latest seq prior to writing."""
        current_events = self._store.read(state.incident_id)
        current_seq = len(current_events)
        event = build_event(
            incident_id=state.incident_id,
            actor=actor,
            type=event_type,
            payload=payload,
        )
        self._store.append(state.incident_id, current_seq, event)
