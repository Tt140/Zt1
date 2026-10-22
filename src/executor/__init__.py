"""
executor/ — Phase 4: Executor + PolicyGate + Verifier + Rollback + Reconciler

Components:
- executor.py:   ExecutorLoop — executes T0/T1/T2 steps through gate + lab backend
- docker_lab.py: DockerLab    — isolated execution sandbox (Docker container or bounded subprocess)
- verifier.py:   Verifier     — validates success_criteria against independent metrics
- reconciler.py: Reconciler   — crash recovery (resolves ExecutionIntent without matching Result)
"""
from .executor import ExecutorLoop, ExecutorResult, ExecutorTermination
from .docker_lab import DockerLab, DockerBackend, SubprocessBackend, LabResult
from .verifier import Verifier, VerificationResult
from .reconciler import Reconciler

__all__ = [
    "ExecutorLoop", "ExecutorResult", "ExecutorTermination",
    "DockerLab", "DockerBackend", "SubprocessBackend", "LabResult",
    "Verifier", "VerificationResult",
    "Reconciler",
]
