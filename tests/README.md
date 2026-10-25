# 569-Test Verification & Conformance Matrix (`tests/`)

[![Pytest Suite](https://img.shields.io/badge/pytest-569%20passed%20(100%25)-brightgreen?style=for-the-badge&logo=pytest)](#)
[![Zero Failures](https://img.shields.io/badge/failures-0-brightgreen?style=for-the-badge)](#)
[![Pass Rate](https://img.shields.io/badge/pass%20rate-100%25-brightgreen?style=for-the-badge)](#)

This directory contains the comprehensive, multi-layer verification test suite for the **Autonomous Cloud Incident Remediation System**.

The test suite comprises **569 automated tests** spanning unit testing, pure-domain reducer validation, zero-trust security invariant enforcement, storage backend conformance, serverless Lambda handler simulation, anti-hesitation guards, socket mode lifecycle, dual asynchronous Slack notifications, Zero-Touch SSM reconciliation, and end-to-end incident lifecycle testing.

---

## 1. Test Suite Architecture (`569 Tests`)

The verification matrix is structured across 6 dedicated test directories and 3 specialized root integration suites:

```text
tests/
├── agent/                  <── 149 Tests: Reasoning Loop, Anti-Hesitation, Socket Mode, PID Isolation & Conclude
├── unit/                   <── 110 Tests: Domain Reducer, Onboarding CLI & IAM/SSM Reconciliation, Observer & Router
├── policy/                 <──  98 Tests: PolicyGate, Invariants I-01..I-16 & Cryptographic HMAC Auth
├── handlers/               <──  62 Tests: Serverless Handlers, Dual Async Notifications & Slack Lifecycle
├── conformance/            <──  52 Tests: Cross-Backend EventStore Conformance (DynamoDB/SQLite/Memory)
├── test_regression_fixes.py<──  51 Tests: Subprocess Isolation & Shell Operator Defense
├── test_phase4_e2e.py      <──  32 Tests: Multi-Phase Autonomous Incident E2E Lifecycles
├── eval/                   <──  11 Tests: Replay Benchmark Scenarios & MTTR Verification
└── test_no_runbooks.py     <──   4 Tests: Proof of Zero-Runbook Dynamic Reasoning
───────────────────────────────────────────────────────────────────────────
Total:                          569 Tests (100% Pass Rate - 0 Failures)
```

### Detailed Suite Breakdown & Architectural Objectives

| Suite Path | Test Count | Primary Target Modules | Architectural Objective & Verification Scope |
|---|---|---|---|
| **`tests/agent/`** | **149** | `src/agent/` | **Autonomous Reasoning Loop & Anti-Hesitation**:<br/>• Tests `ReasoningLoop.step()` state progressions, hypothesis updates, and cycle limits.<br/>• Verifies **Anti-Hesitation Engine** breaking analysis paralysis at confidence $\ge 0.70$.<br/>• Verifies **Slack Socket Mode** lifecycle and live interactive approvals.<br/>• Validates **Target Process Isolation** protecting system daemons and preventing rogue kills.<br/>• Tests **Cross-Round Deduplication** ensuring executed repairs fast-path directly to `conclude`. |
| **`tests/unit/`** | **110** | `src/domain/`<br/>`scripts/aws_onboard.py` | **Core Unit & IAM/SSM Engine Verification**:<br/>• Verifies pure domain event sourcing reducer (`fold`) determinism and immutability.<br/>• Tests `aws_onboard.py` 7-layer audit discovery, delta planner, and brownfield/greenfield options.<br/>• Tests IAM eventual consistency backoff retry logic and CloudFormation dead-stack self-healing.<br/>• Verifies 7-role IAM core engine reconciliation, Zero-Touch SSM Document bootstrap & drift repair, S3 snapshot access, and expanded SSM command permissions.<br/>• Validates strictly matched PID parsing and invariant I-15 TLS certificate compliance. |
| **`tests/policy/`** | **98** | `src/policy/` | **Security Boundary Validation**:<br/>• Tests all 16 security invariants (`I-01` to `I-16`) individually and in combination.<br/>• Validates tier classification (`T0` Read-Only, `T1` Autonomous Safe, `T2` Require Human Approval, `T3` Reject).<br/>• Verifies canonical JSON serialization and deterministic `plan_hash` generation.<br/>• Tests cryptographic `HMAC-SHA256` authorization tag validation (`compute_auth_tag`). |
| **`tests/handlers/`** | **62** | `handlers/` | **Serverless Function Verification**:<br/>• Simulates EventBridge CloudWatch alarm events for `ingest.py` and verifies dual async dispatch (`NOTIFIER_FN` for `incident_opened` + `AGENT_FN`).<br/>• Tests `agent.py` async dispatching, `action_proposed` T1 Slack notification, and lease release in `finally:` blocks.<br/>• Verifies state-aware and on-resolution deduplication release allowing recurring alarms on resolved resources.<br/>• Verifies `observer.py` T0 SSM invocation and telemetry retrieval.<br/>• Tests `executor_fn.py` STS AssumeRole credential scoping and HMAC token validation.<br/>• Verifies `slack_callback.py` Slack signature validation (`X-Slack-Signature`) and 5-minute replay window defense.<br/>• Tests `notifier.py` resilient Slack webhook delivery and graceful fallback. |
| **`tests/conformance/`** | **52** | `src/store/` | **Storage Backend Parity Verification**:<br/>• Executes identical conformance test suites against `DynamoDBEventStore`, `SQLiteEventStore`, and `InMemoryEventStore`.<br/>• Validates strict monotonic event append-only ordering and version concurrency checks.<br/>• Tests atomic alarm deduplication (`create_if_absent`) and dynamic release (`release_dedupe`).<br/>• Tests distributed lease acquisition, heartbeats, TTL expiration, and release semantics.<br/>• Verifies transparent S3 offload for event payloads exceeding 300 KB. |
| **`tests/test_regression_fixes.py`** | **51** | `src/executor/`<br/>`src/policy/` | **Defensive Shell & Subprocess Hardening**:<br/>• Proves strict blocking of command chaining and shell expansion operators (`;`, `&&`, `\|\|`, `` ` ``, `$()`, `\|`).<br/>• Verifies subprocess backend isolation ensuring mutating tiers (`T1`/`T2`) cannot run outside isolated lab sandboxes.<br/>• Tests boundary handling for case sensitivity, empty inputs, and unknown tier codes. |
| **`tests/test_phase4_e2e.py`** | **32** | Full System | **End-to-End Incident Lifecycle**:<br/>• Simulates full multi-cycle incident resolutions without live cloud dependencies.<br/>• Tests incident opening -> hypothesis formulation -> T0 inspection -> T2 approval -> T1 execution -> verification -> incident resolution.<br/>• Tests escalation on unrecoverable failures or denied approvals. |
| **`tests/eval/`** | **11** | `src/eval/` | **Benchmark & Evaluation Engine**:<br/>• Replays recorded incident traces (`recordings.py`) through the reasoning engine.<br/>• Measures Mean Time To Resolution (MTTR), hypothesis accuracy, and false-alarm resistance. |
| **`tests/test_no_runbooks.py`** | **4** | `src/agent/` | **Zero-Runbook Proof**:<br/>• Statically and dynamically verifies that the engine contains zero hardcoded remediation scripts, static decision trees, or brittle playbooks. |

---

## 2. Running the Test Suite

All tests are managed via `pytest`. The environment requires Python 3.10+ and standard dev dependencies.

### 1. Run the Entire Test Suite (569 Tests)
```bash
python3 -m pytest -q
```
*Expected Output:*
```text
============================= 569 passed in 29.64s =============================
```

### 2. Run Specific Subsystems

#### Run Agent Reasoning, Anti-Hesitation & Socket Mode (149 tests)
```bash
python3 -m pytest tests/agent/ -v
```

#### Run Core Domain, Onboarding CLI & IAM/SSM Reconciliation (108 tests)
```bash
python3 -m pytest tests/unit/ -v
```

#### Run Security Policy & Invariant Tests (98 tests)
```bash
python3 -m pytest tests/policy/ -v
```

#### Run Serverless Handlers, Dual Notifications & Slack Lifecycle (60 tests)
```bash
python3 -m pytest tests/handlers/ -v
```

#### Run Storage Conformance Tests across DynamoDB, SQLite & Memory (52 tests)
```bash
python3 -m pytest tests/conformance/ -v
```

#### Run Defensive Shell Regression Tests (51 tests)
```bash
python3 -m pytest tests/test_regression_fixes.py -v
```
