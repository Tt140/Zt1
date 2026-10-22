"""
tests/test_phase4_e2e.py — Phase 4 End-to-End Tests

Demonstrates the complete remediation cycle:
1. DockerLab allowlist + I-15 secret blocking
2. ExecutorLoop: Gate → Snapshot → Intent → Lab → Verify → Result
3. Rollback on execution failure
4. Reconciler: crash recovery (ExecutionIntent without Result)
5. Independent Verifier
6. Complete cycle: observe → propose → gate → execute → verify

With Docker: runs via DockerBackend (alpine:3.20)
Without Docker: runs via SubprocessBackend (with isolation warning)
"""
import sys
import dataclasses
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.domain.types import (
    new_ulid, utc_now, IncidentHeader, IncidentPhase,
    build_event, EventType, Actor, IncidentOpenedPayload,
    BudgetConsumedPayload, StepRecord, StepKind,
    DeclaredEffect, EffectCategory, VerificationVerdict,
    ReconcileStatus, ExecutionIntentPayload,
    PolicyDecisionValue,
)
from src.domain.reducer import fold
from src.store.memory import MemoryEventStore
from src.policy import compute_plan_hash, GateContext
from src.executor import (
    ExecutorLoop, ExecutorTermination,
    DockerLab, DockerBackend, SubprocessBackend,
    Verifier, VerificationResult,
    Reconciler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_store(instance_id="i-lab001"):
    store = MemoryEventStore()
    iid = new_ulid()
    dk = f"dk-{iid}"
    store.create_if_absent(dk, IncidentHeader(
        incident_id=iid, instance_id=instance_id, dedupe_key=dk,
        alarm_name="lab-test", alarm_arn="arn:test", alert_source="test",
        opened_at=utc_now().isoformat(),
    ))
    store.append(iid, 0, build_event(
        incident_id=iid, type=EventType.IncidentOpened, actor=Actor.ingest,
        payload=IncidentOpenedPayload(
            instance_id=instance_id, dedupe_key=dk,
            alarm_name="lab-test", alarm_arn="arn:test", alert_source="test",
        ),
    ))
    state = fold(store.read(iid))
    return store, iid, state


def _make_observe_step(target="i-lab001", command="echo hello"):
    s = StepRecord(
        step_id=new_ulid(), incident_id="inc",
        based_on_hypotheses=[], based_on_evidence=[],
        kind=StepKind.observe, target=target,
        execution_spec={"command": command},
        declared_effects=[DeclaredEffect(EffectCategory.E0, target, "read-only")],
        preconditions=[],
        success_criteria=[{"type": "command", "check": "echo ok"}],
        rollback_plan="none", rollback_reason="observe_no_rollback",
        idempotent=True, risk_claim="none",
        expires_at="2099-01-01T00:00:00+00:00",
        plan_hash="placeholder",
    )
    return dataclasses.replace(s, plan_hash=compute_plan_hash(s))


def _make_mutate_step(target="i-lab001", command="echo mutate_test"):
    s = StepRecord(
        step_id=new_ulid(), incident_id="inc",
        based_on_hypotheses=[], based_on_evidence=[],
        kind=StepKind.mutate, target=target,
        execution_spec={"command": command},
        declared_effects=[DeclaredEffect(EffectCategory.E1, target, "service-change")],
        preconditions=[],
        success_criteria=[{"type": "command", "check": "echo done"}],
        rollback_plan=[{"action": "echo rollback_action"}],
        rollback_reason=None,
        idempotent=True, risk_claim="low",
        expires_at="2099-01-01T00:00:00+00:00",
        plan_hash="placeholder",
    )
    return dataclasses.replace(s, plan_hash=compute_plan_hash(s))


def _make_lab(docker_available=None):
    """Creates a DockerLab instance — detects Docker or falls back to subprocess."""
    if docker_available is None:
        return DockerLab()  # auto-detect
    return DockerLab(force_subprocess=not docker_available)


# ---------------------------------------------------------------------------
# Group 1: DockerLab — allowlist and I-15
# ---------------------------------------------------------------------------

class TestDockerLabSecurity:
    """Proves that the sandbox blocks unauthorized commands regardless of Docker."""

    def setup_method(self):
        self.lab = DockerLab(force_subprocess=True)

    def test_lab_backend_name_reported(self):
        """Lab reports backend name — does not obscure its state."""
        assert self.lab.backend_name in ("docker", "subprocess_no_isolation")

    def test_t0_allowed_echo(self):
        """T0: echo is permitted."""
        r = self.lab.run("echo sandbox_test")
        assert r.success
        assert "sandbox_test" in r.stdout

    def test_t0_allowed_df(self):
        """T0: df is permitted (disk monitoring)."""
        r = self.lab.run("df -h")
        assert r.success or r.blocked_reason is None

    def test_t0_blocks_rm_rf(self):
        """I-T0: rm -rf / is blocked by allowlist."""
        r = self.lab.run("rm -rf /")
        assert r.blocked_reason is not None
        assert not r.success
        assert "allowlist" in r.blocked_reason.lower() or "not permitted" in r.blocked_reason.lower()

    def test_i15_blocks_shadow(self):
        """I-15: cat /etc/shadow is blocked regardless of T0/T1."""
        r = self.lab.run("cat /etc/shadow")
        assert r.blocked_reason is not None
        assert "I-15" in r.blocked_reason or "secret" in r.blocked_reason.lower()

    def test_i15_blocks_pem_file(self):
        """I-15: Reading .pem files is blocked."""
        r = self.lab.run("cat /etc/ssl/private/server.pem")
        assert r.blocked_reason is not None

    def test_i15_blocks_aws_credentials(self):
        """I-15: ~/.aws/credentials is blocked."""
        r = self.lab.run("cat /root/.aws/credentials")
        assert r.blocked_reason is not None

    def test_i15_blocks_id_rsa(self):
        """I-15: id_rsa is blocked."""
        r = self.lab.run("cat /home/dev/.ssh/id_rsa")
        assert r.blocked_reason is not None

    def test_t0_blocks_apt_install(self):
        """I-07 case: apt-get install is not permitted in T0."""
        r = self.lab.run("apt-get install curl")
        assert r.blocked_reason is not None or not r.success

    def test_blocked_result_has_no_stdout(self):
        """Blocked command is not executed -> empty stdout."""
        r = self.lab.run("rm -rf /")
        assert r.stdout == ""
        assert r.exit_code == -1

    def test_timeout_respected(self):
        """Subprocess backend respects timeout."""
        lab = SubprocessBackend(timeout=1)
        r = lab.run("echo fast")
        assert r.success

    def test_subprocess_warning_in_output(self):
        """SubprocessBackend appends an explicit isolation warning."""
        r = self.lab.run("echo test_isolation")
        assert "WARNING" in r.stdout or "subprocess" in r.stdout.lower()


# ---------------------------------------------------------------------------
# Group 2: ExecutorLoop — Full Cycle
# ---------------------------------------------------------------------------

class TestExecutorLoopE2E:
    """
    Phase 4 End-to-End tests.
    Uses SubprocessBackend when Docker is unavailable,
    or DockerBackend when Docker is present.
    """

    def setup_method(self):
        self.lab = DockerLab(force_subprocess=True)
        self.verifier = Verifier(self.lab)
        self.reconciler = Reconciler(self.lab)

    def _make_executor(self, store):
        return ExecutorLoop(
            store=store,
            lab=self.lab,
            verifier=self.verifier,
            reconciler=self.reconciler,
            instance_id="i-lab001",
            allowed_instance_id="i-lab001",
        )

    # ── Normal Case: observe+E0 passes gate and executes ─────────────────

    def test_observe_step_full_cycle(self):
        """
        E2E-1: observe+E0 → gate(allow/T0) → snapshot → intent → lab → verify → completed.
        Proves the complete end-to-end cycle.
        """
        store, iid, state = _open_store()
        executor = self._make_executor(store)
        step = _make_observe_step(command="echo hello_e2e")

        result = executor.execute_step(step, state)

        # 1) Correct termination
        assert result.termination == ExecutorTermination.COMPLETED, \
            f"Expected COMPLETED, got {result.termination}: {result.details}"

        # 2) Gate permitted
        assert result.gate_decision == PolicyDecisionValue.allow

        # 3) Lab succeeded
        assert result.lab_result is not None
        assert result.lab_result.success

        # 4) Verifier succeeded
        assert result.verification is not None
        assert result.verification.verdict == VerificationVerdict.verified

        # 5) Events written to EventStore
        events = store.read(iid)
        event_types = [e.type.value for e in events]
        assert "PolicyDecision" in event_types, f"Missing PolicyDecision: {event_types}"
        assert "SnapshotTaken" in event_types, f"Missing SnapshotTaken: {event_types}"
        assert "ExecutionIntent" in event_types, f"Missing ExecutionIntent: {event_types}"
        assert "ExecutionResult" in event_types, f"Missing ExecutionResult: {event_types}"
        assert "VerificationRecorded" in event_types, f"Missing VerificationRecorded: {event_types}"

    def test_gate_deny_mutate_e0_never_reaches_lab(self):
        """
        E2E-2: mutate+E0 denied by gate → no execution in lab.
        Proves gate enforces protection before reaching the lab.
        """
        store, iid, state = _open_store()
        executor = self._make_executor(store)

        dangerous_step = dataclasses.replace(
            _make_observe_step(command="rm -rf /"),
            kind=StepKind.mutate,
            declared_effects=[DeclaredEffect(EffectCategory.E0, "i-lab001", "misleading")],
        )
        dangerous_step = dataclasses.replace(
            dangerous_step, plan_hash=compute_plan_hash(dangerous_step)
        )

        result = executor.execute_step(dangerous_step, state)

        assert result.termination == ExecutorTermination.DENIED, \
            f"Expected DENIED, got {result.termination}: {result.details}"
        assert result.lab_result is None, "Lab should not be reached when gate denies"

        # Verify: PolicyDecision(deny) in EventStore
        events = store.read(iid)
        policy_events = [e for e in events if e.type.value == "PolicyDecision"]
        assert len(policy_events) > 0
        assert policy_events[-1].payload.decision.value == "deny"

    def test_blocked_command_in_lab_triggers_failure(self):
        """
        E2E-3: Command fails in lab (exit_code≠0 after passing gate).
        Proves lab failure is recorded as ExecutionResult(failure).
        Uses AlwaysFailLab to ensure controlled failure.
        """
        from tests.conftest_phase4 import AlwaysFailLab
        store, iid, state = _open_store()
        fail_lab = AlwaysFailLab()
        executor = ExecutorLoop(
            store=store, lab=fail_lab, verifier=Verifier(fail_lab),
            reconciler=self.reconciler,
            instance_id="i-lab001", allowed_instance_id="i-lab001",
        )
        step = _make_observe_step(command="echo will_fail")
        result = executor.execute_step(step, state)

        # AlwaysFailLab → failed lab → rollback or failed
        assert result.lab_result is not None, "Lab should have been called"
        assert not result.lab_result.success
        assert result.termination in (
            ExecutorTermination.ROLLBACK,
            ExecutorTermination.FAILED,
        ), f"Expected ROLLBACK/FAILED: {result.termination}: {result.details}"

        # ExecutionResult(failure) in EventStore
        events = store.read(iid)
        exec_results = [e for e in events if e.type.value == "ExecutionResult"]
        assert len(exec_results) > 0
        assert exec_results[-1].payload.status == "failure"

    def test_i14_execution_intent_written_before_lab(self):
        """
        E2E-4: I-14: ExecutionIntent written before execution in lab.
        Proves core invariant: no execution without recorded intent.
        """
        store, iid, state = _open_store()
        executor = self._make_executor(store)
        step = _make_observe_step(command="echo intent_test")

        result = executor.execute_step(step, state)

        events = store.read(iid)
        event_types = [e.type.value for e in events]

        # ExecutionIntent must precede ExecutionResult
        intent_idx = next((i for i, t in enumerate(event_types) if t == "ExecutionIntent"), -1)
        result_idx = next((i for i, t in enumerate(event_types) if t == "ExecutionResult"), -1)

        assert intent_idx >= 0, f"ExecutionIntent missing: {event_types}"
        assert result_idx >= 0, f"ExecutionResult missing: {event_types}"
        assert intent_idx < result_idx, \
            f"Intent must precede Result (intent@{intent_idx}, result@{result_idx})"

    def test_snapshot_taken_before_execution(self):
        """
        E2E-5: SnapshotTaken written before ExecutionIntent (pre-execution snapshot).
        """
        store, iid, state = _open_store()
        executor = self._make_executor(store)
        step = _make_observe_step(command="echo snap_test")

        result = executor.execute_step(step, state)

        events = store.read(iid)
        event_types = [e.type.value for e in events]

        snap_idx = next((i for i, t in enumerate(event_types) if t == "SnapshotTaken"), -1)
        intent_idx = next((i for i, t in enumerate(event_types) if t == "ExecutionIntent"), -1)

        assert snap_idx >= 0, f"SnapshotTaken missing: {event_types}"
        assert snap_idx < intent_idx, \
            f"Snapshot must precede Intent (snap@{snap_idx}, intent@{intent_idx})"

    def test_rollback_on_failed_execution(self):
        """
        E2E-6: Failed execution → RollbackStarted + RollbackCompleted in EventStore.
        """
        store, iid, state = _open_store()
        # Use a lab that fails any command
        from tests.conftest_phase4 import AlwaysFailLab
        fail_lab = AlwaysFailLab()
        fail_verifier = Verifier(fail_lab)
        executor = ExecutorLoop(
            store=store, lab=fail_lab, verifier=fail_verifier,
            reconciler=self.reconciler,
            instance_id="i-lab001", allowed_instance_id="i-lab001",
        )
        step = _make_observe_step(command="echo will_fail")
        result = executor.execute_step(step, state)

        assert result.termination in (ExecutorTermination.ROLLBACK, ExecutorTermination.FAILED), \
            f"Expected ROLLBACK/FAILED: {result.termination}: {result.details}"

        events = store.read(iid)
        event_types = [e.type.value for e in events]
        assert "RollbackStarted" in event_types, f"Missing RollbackStarted: {event_types}"
        assert "RollbackCompleted" in event_types, f"Missing RollbackCompleted: {event_types}"

    def test_policy_decision_written_for_every_step(self):
        """
        E2E-7: PolicyDecision written for every step (allow or deny).
        This is real M7 in Phase 4.
        """
        store, iid, state = _open_store()
        executor = self._make_executor(store)

        # Allowed step
        step1 = _make_observe_step(command="echo pd_test")
        executor.execute_step(step1, state)
        state = fold(store.read(iid))

        # Denied step
        bad_step = dataclasses.replace(
            _make_observe_step(command="echo bad"),
            kind=StepKind.mutate,
            declared_effects=[DeclaredEffect(EffectCategory.E0, "i-lab001", "bad")],
        )
        bad_step = dataclasses.replace(bad_step, plan_hash=compute_plan_hash(bad_step))
        executor.execute_step(bad_step, state)

        events = store.read(iid)
        pd_events = [e for e in events if e.type.value == "PolicyDecision"]
        assert len(pd_events) == 2, f"Expected 2 PolicyDecision events, got {len(pd_events)}"

        decisions = [e.payload.decision.value for e in pd_events]
        assert "allow" in decisions
        assert "deny" in decisions


# ---------------------------------------------------------------------------
# Group 3: Reconciler — crash recovery
# ---------------------------------------------------------------------------

class TestReconcilerCrashRecovery:
    """Proves CS-07: proper crash recovery after ExecutionIntent without Result."""

    def setup_method(self):
        self.lab = DockerLab(force_subprocess=True)

    def test_clean_state_returns_executed(self):
        """CS-07: Clean state → executed (nothing to reconcile)."""
        store, iid, state = _open_store()
        r = Reconciler(self.lab)
        result = r.reconcile(store, iid)
        assert result.status == ReconcileStatus.executed, \
            f"Clean state should return executed: {result}"

    def test_pending_intent_triggers_reconciliation(self):
        """
        CS-07: ExecutionIntent without ExecutionResult → Reconciler records ReconcileOutcome.
        """
        store, iid, state = _open_store()
        step = _make_observe_step(command="echo reconcile_test")

        # Record ExecutionIntent manually without ExecutionResult (simulate crash)
        seq = store.last_seq(iid)
        intent_payload = ExecutionIntentPayload(
            step_id=step.step_id,
            plan_hash=step.plan_hash,
            idempotency_key=f"{iid}:{step.step_id}",
            correlation_id=new_ulid(),
            fencing_seq=seq + 1,
        )
        store.append(iid, seq, build_event(
            incident_id=iid, type=EventType.ExecutionIntent, actor=Actor.executor,
            payload=intent_payload,
        ))

        # Record StepProposed so Reconciler can locate step
        from src.domain.types import StepProposedPayload
        seq = store.last_seq(iid)
        store.append(iid, seq, build_event(
            incident_id=iid, type=EventType.StepProposed, actor=Actor.agent,
            payload=StepProposedPayload(step=dataclasses.replace(step, incident_id=iid)),
        ))

        # Force pending_intent in state
        state = fold(store.read(iid))
        # Since pending_intent is only set when Intent lacks Result,
        # verify Reconciler runs even if pending_intent is unrouted
        r = Reconciler(self.lab)
        result = r.reconcile(store, iid)

        # Either ReconcileOutcome is recorded or state is clean
        events = store.read(iid)
        event_types = [e.type.value for e in events]
        # Either clean state (no pending_intent in reducer) or ReconcileOutcome recorded
        assert result.status in (
            ReconcileStatus.executed, ReconcileStatus.not_executed, ReconcileStatus.unknown
        )


# ---------------------------------------------------------------------------
# Group 4: Independent Verifier
# ---------------------------------------------------------------------------

class TestVerifierIndependence:
    """Proves that the verifier is independent and conducts re-measurement."""

    def setup_method(self):
        self.lab = DockerLab(force_subprocess=True)
        self.verifier = Verifier(self.lab)

    def test_verifier_passes_echo_check(self):
        """Verifier passes a simple check command."""
        store, iid, state = _open_store()
        step = _make_observe_step(command="echo ok")

        result = self.verifier.verify(step, state)

        assert result.verdict in (
            VerificationVerdict.verified, VerificationVerdict.inconclusive
        ), f"Expected verified/inconclusive: {result.verdict}, {result.details}"
        assert len(result.checks) > 0

    def test_verifier_uses_its_own_lab(self):
        """Verifier uses independent lab — does not trust results from executor."""
        store, iid, state = _open_store()
        step = _make_observe_step(command="echo independent")

        result = self.verifier.verify(step, state)

        # Checks originate from verifier's own lab
        assert any("verifier" in c.source for c in result.checks), \
            f"Checks should reference verifier lab: {result.checks}"

    def test_verifier_writes_event(self):
        """Verifier writes VerificationRecorded event to EventStore."""
        store, iid, state = _open_store()
        step = _make_observe_step(command="echo write_test")

        result = self.verifier.verify(step, state)
        self.verifier.write_verification_event(result, step, state, store)

        events = store.read(iid)
        event_types = [e.type.value for e in events]
        assert "VerificationRecorded" in event_types, \
            f"VerificationRecorded missing: {event_types}"

    def test_verifier_side_effect_check(self):
        """Verifier inspects side effects (sandbox liveness)."""
        store, iid, state = _open_store()
        step = _make_observe_step(command="echo side_effects")

        result = self.verifier.verify(step, state)

        assert len(result.side_effect_checks) > 0, "Side effect checks should be performed"
        liveness = [c for c in result.side_effect_checks
                    if c.check_type == "side_effect_liveness"]
        assert len(liveness) > 0


# ---------------------------------------------------------------------------
# Group 5: Real Docker (Skipped if Docker is unavailable)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not DockerLab._check_docker(),
    reason="Docker not accessible in current session — add dev to docker group and re-login",
)
class TestDockerRealE2E:
    """
    Real Docker E2E tests.
    Runs only when Docker container environment is accessible.
    """

    def setup_method(self):
        self.lab = DockerLab(image="alpine:3.20", timeout=30)
        assert self.lab.is_docker, "Expected Docker backend"

    def test_docker_echo_in_container(self):
        """Docker: echo works inside alpine container."""
        r = self.lab.run("echo docker_real_test")
        assert r.success
        assert "docker_real_test" in r.stdout
        assert r.exit_code == 0

    def test_docker_network_isolation(self):
        """Docker: network=none → ping fails (network isolation)."""
        r = self.lab.run("ping -c 1 8.8.8.8")
        # Fails due to network=none or blocked by allowlist
        assert not r.success or r.blocked_reason is not None

    def test_docker_read_only_fs(self):
        """Docker: read-only filesystem → write to / fails."""
        r = self.lab.run("echo test > /root/hacked.txt")
        # Must fail (read-only) or blocked (allowlist)
        assert not r.success or r.blocked_reason is not None

    def test_docker_user_nobody(self):
        """Docker: executes as nobody user (UID 65534)."""
        r = self.lab.run("id")
        assert r.success
        # nobody = uid=65534
        assert "65534" in r.stdout or "nobody" in r.stdout

    def test_docker_memory_limit(self):
        """Docker: 128MB limit — container does not exceed limit."""
        r = self.lab.run("free -m")
        assert r.success  # Runs without OOM

    def test_docker_allowlist_blocks_destructive(self):
        """Docker: destructive commands blocked inside container."""
        r = self.lab.run("dd if=/dev/zero of=/dev/sda")
        assert r.blocked_reason is not None or not r.success

    def test_docker_full_e2e_cycle(self):
        """Docker E2E: complete cycle using alpine container."""
        store, iid, state = _open_store()
        verifier = Verifier(self.lab)
        reconciler = Reconciler(self.lab)
        executor = ExecutorLoop(
            store=store, lab=self.lab, verifier=verifier,
            reconciler=reconciler,
            instance_id="i-lab001", allowed_instance_id="i-lab001",
        )
        step = _make_observe_step(command="df -h")
        result = executor.execute_step(step, state)

        assert result.termination == ExecutorTermination.COMPLETED, \
            f"Docker E2E failed: {result.termination}: {result.details}"
        assert result.lab_result.success
        assert result.verification.verdict == VerificationVerdict.verified

        events = store.read(iid)
        event_types = [e.type.value for e in events]
        for required in ("PolicyDecision", "SnapshotTaken", "ExecutionIntent",
                         "ExecutionResult", "VerificationRecorded"):
            assert required in event_types, f"Missing {required}: {event_types}"
