"""
tests/test_no_runbooks.py — Automated check against disguised Runbooks (05 §3).

Specification 05 §3 requires:
  "Review rule + automated test: The agent and gate code must not contain
   fault names or branches dedicated to a specific fault."

Scans src/agent and src/policy for hardcoded fault family names.
lab/scenarios.py and eval/recordings.py are excluded (intentional ground-truth guides).
"""
import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent / "src"

FAULT_FAMILY_NAMES = [
    "disk_full", "disk-full", "diskfull",
    "crash_loop", "crash-loop", "crashloop",
    "high_cpu", "highcpu",
    "cert_expired", "certexpired",
    "out_of_memory",
    "memory_pressure", "memorypressure",
    "prompt_injection", "promptinjection",
    "security_anomaly", "securityanomaly",
    "misleading_noise", "misleadingnoise",
]

EXCLUDED_PATHS = {
    "lab/scenarios.py",
    "lab/__init__.py",
    "eval/recordings.py",
    "eval/__init__.py",
}


def get_source_files(package: str) -> list:
    pkg_dir = PROJECT_ROOT / package
    files = []
    for f in pkg_dir.rglob("*.py"):
        rel = f.relative_to(PROJECT_ROOT)
        if str(rel) not in EXCLUDED_PATHS:
            files.append(f)
    return files


def test_no_runbook_names_in_agent():
    """src/agent does not contain hardcoded fault family names (05 §3)."""
    violations = []
    for fpath in get_source_files("agent"):
        text = fpath.read_text(encoding="utf-8").lower()
        for name in FAULT_FAMILY_NAMES:
            if name in text:
                violations.append(f"{fpath.name}: found {name!r}")
    assert not violations, (
        "Agent code contains hardcoded fault family names (05 §3 violation):\n"
        + "\n".join(violations)
    )


def test_no_runbook_names_in_policy():
    """src/policy does not contain hardcoded fault family names (05 §3)."""
    violations = []
    for fpath in get_source_files("policy"):
        text = fpath.read_text(encoding="utf-8").lower()
        for name in FAULT_FAMILY_NAMES:
            if name in text:
                violations.append(f"{fpath.name}: found {name!r}")
    assert not violations, (
        "Policy code contains hardcoded fault family names (05 §3 violation):\n"
        + "\n".join(violations)
    )


def test_system_prompt_no_fault_names():
    """System prompt does not mention specific fault names as Runbooks (05 §3)."""
    fpath = PROJECT_ROOT / "agent" / "context_builder.py"
    if not fpath.exists():
        return
    text = fpath.read_text(encoding="utf-8").lower()
    system_start = text.find("system_prompt")
    if system_start == -1:
        return
    prompt_section = text[system_start:system_start + 3000]
    violations = []
    for name in FAULT_FAMILY_NAMES:
        if name in prompt_section:
            violations.append(f"System prompt contains fault name: {name!r}")
    assert not violations, (
        "System prompt references specific fault families:\n"
        + "\n".join(violations)
    )


def test_no_fault_specific_branches_in_context_builder():
    """context_builder.py does not contain fault-specific if conditions (05 §3)."""
    fpath = PROJECT_ROOT / "agent" / "context_builder.py"
    if not fpath.exists():
        return
    tree = ast.parse(fpath.read_text(encoding="utf-8"))
    fault_names_lower = {n.lower() for n in FAULT_FAMILY_NAMES}
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            src_snippet = ast.unparse(node).lower()[:200]
            for name in fault_names_lower:
                if name in src_snippet:
                    violations.append(f"Line {node.lineno}: branch on fault name {name!r}")
    assert not violations, (
        "context_builder.py has fault-specific branches (05 §3 violation):\n"
        + "\n".join(violations)
    )
