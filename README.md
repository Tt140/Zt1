# 🛡️ Autonomous Zero-Trust SecOps Agent for AWS

[![AWS Hackathon](https://img.shields.io/badge/AWS%20Hackathon-Strands%20Decider%202B%20%7C%20Amazon%20Bedrock-orange?style=for-the-badge)](#)
[![YouTube Demo](https://img.shields.io/badge/YouTube%20Demo-Live%20Remediation-red?style=for-the-badge&logo=youtube)](https://www.youtube.com/watch?v=572k45RA4yo)
[![Pattern Tags](https://img.shields.io/badge/Pattern%20Tags-%23strands--decider--2b%20%7C%20%23tool--selection-blue?style=for-the-badge)](#-mandatory-hackathon-tags)
[![Pytest Suite](https://img.shields.io/badge/pytest-541%20passed%20(100%25)-brightgreen?style=for-the-badge&logo=pytest)](tests/README.md)
[![License](https://img.shields.io/badge/License-Apache--2.0-green?style=for-the-badge)](LICENSE)
[![Zero Runbooks](https://img.shields.io/badge/Zero--Runbooks-100%25%20Dynamic%20Reasoning-blue?style=for-the-badge)](tests/test_no_runbooks.py)
[![Security Invariants](https://img.shields.io/badge/Security%20Invariants-16%20Enforced%20(I--01..I--16)-red?style=for-the-badge)](src/README.md#4-the-16-security-invariants)
[![AWS Serverless](https://img.shields.io/badge/AWS%20SAM%20Serverless-6%2F6%20Lambdas-orange?style=for-the-badge&logo=amazon-aws)](handlers/README.md)

> **Autonomous Cloud SRE & SecOps Incident Remediation on AWS**  
> An autonomous, event-sourced, self-healing system designed to detect, investigate, and remediate production incidents on AWS EC2 without hardcoded runbooks. Powered by **Strands Decider 2B** for sub-millisecond tactical tool selection, **Amazon Bedrock (Amazon Nova / DeepSeek)** for generative reasoning, formal **Zero-Trust Tiered Governance (T0–T3)**, and cryptographic **HMAC-SHA256 human-in-the-loop authorization** via Slack Socket Mode.

> ⚡ **Architectural Highlight: Full Machine-Speed Autonomy vs. Zero-Trust Enterprise Governance**  
> This agent is engineered for **100% hands-free, autonomous end-to-end self-healing**—it can discover outages, hypothesize root causes, and execute verified remediations at machine speed with zero human intervention (via `--auto-approve` or automated recovery pipelines).  
> **Human-in-the-Loop (Tier T2) is NOT an operational crutch for an incomplete agent**—it is a deliberate, enterprise-grade **Defense-in-Depth** security guardrail designed for mission-critical production (SOC2, ISO 27001, and FedRAMP compliance). The platform completely decouples *Cognitive Synthesis* (fully autonomous reasoning) from *Execution Authority* (configurable: instant automated execution vs. cryptographic HMAC-SHA256 human authorization).

---

## 📺 Live Video Demonstration
> **Continuous, Zero-Cut Autonomous Incident Investigation on Live AWS Infrastructure:**  
> Watch the autonomous agent discover the outage, reason through root-cause hypotheses, interact with Slack, execute surgical remediation, and verify recovery live on real AWS infrastructure:

[![Autonomous SecOps Agent Live Demo](https://img.youtube.com/vi/572k45RA4yo/hqdefault.jpg)](https://www.youtube.com/watch?v=572k45RA4yo)  
*▶️ [Click to watch the full demonstration on YouTube](https://www.youtube.com/watch?v=572k45RA4yo)*

---

## 🏷️ Mandatory Hackathon Tags
* `#strands-decider-2b`
* `#tool-selection`

---

## 🧩 Reusable Strands Decider 2B Decision Pattern (`#tool-selection`)
> **Judging Fast-Track:** For hackathon evaluators seeking the mandatory reusable decision asset, navigate directly to:  
> 📁 **[`patterns/strands_secops_tool_selection/`](patterns/strands_secops_tool_selection/)**  
> 📄 **[`pattern.py`](patterns/strands_secops_tool_selection/pattern.py)** (Standalone Drop-in Recipe)  
> 📖 **[`README.md`](patterns/strands_secops_tool_selection/README.md)** (Full Asset Documentation & Quickstart)

### 1. The Typed Question & Option Contract
```python
TYPED_QUESTION = (
    "Given the current incident triage state, collected evidence, active hypotheses, "
    "and reasoning cycle, which tool should the autonomous agent execute next?"
)

DECISION_OPTIONS = ["observe", "query_metrics", "update_hypotheses", "propose_step", "escalate"]
```

### 2. The `SecOpsToolSelectionInterventionHandler`
Implements the standard Strands `InterventionHandler` recipe. Wired directly in the agent's path before Bedrock:
1. Intercepts incoming cycle telemetry (`cycle`, `evidence`, `hypotheses`).
2. Evaluates the tactical choice via **Strands Decider 2B** in **~115ms** (or sub-millisecond in embedded mode).
3. If calibrated confidence drops below `0.15`, enforces an immediate **Fail-Closed Safe Escalation** (`escalate`).
4. Passes the choice as a pinned `tool_hint` to **Amazon Bedrock**, which only generates arguments, slashing token costs and preventing tool hallucinations.

### 3. Empirical Measured Benchmark (Strands Decider 2B vs Frontier LLM)
Measurements collected via `python3 patterns/strands_secops_tool_selection/pattern.py` over 100 decision cycles:

| Metric | Strands Decider 2B | Frontier LLM (Bedrock) | Improvement |
| :--- | :--- | :--- | :--- |
| **Decision Latency (Average)** | **0.002 ms** (Embedded) / **~115 ms** (Remote) | **2,450.0 ms** | **>20x – 1,000,000x Faster** ⚡ |
| **Cost per Tool Selection** | **$0.000008** | **$0.006150** | **99.9% Token Cost Savings** 💰 |
| **Hallucination Surface** | **0%** (Constrained Enum) | ~3-5% (Syntax/Tool Drift) | Strict Mathematical Contract |
| **Low-Confidence Handling** | **Automated Fail-Closed Escalation** | Variable / Hesitant | Provable Safety Guarantee |

---

## 🧭 Modular Documentation Navigation Hub

This repository is strictly structured into modular, self-documenting subsystems:

| Documentation Pillar | Directory / Module | Architectural Scope & Key Artifacts |
|---|---|---|
| **Reusable Strands Pattern** | [`patterns/strands_secops_tool_selection/`](patterns/strands_secops_tool_selection/README.md) | Official Hackathon Reusable Asset: Typed Question, `SecOpsToolSelectionInterventionHandler`, Live Benchmark & Drop-in Recipe. |
| **Core Reasoning Engine** | [`src/README.md`](src/README.md) | Pure Domain Reducer (`fold`), Embedded Strands Decider, Dual-Tier Model Router (`Flash` vs `Pro`), Unified EventStore Interface & the **16 Security Invariants (`I-01` to `I-16`)**. |
| **Serverless Handlers** | [`handlers/README.md`](handlers/README.md) | The 6 decoupled AWS Lambda functions (`ingest`, `agent`, `observer`, `executor_fn`, `notifier`, `slack_callback`), least-privilege IAM roles, Lambda Function URL & End-to-End Sequence. |
| **Infrastructure as Code** | [`infra/README.md`](infra/README.md) | AWS SAM `template.yaml`, Zero-Trust SSM Documents (`incidents-observe-readonly`, `incidents-repair-restricted`), conditional provisioning, and SCP-immune architecture. |
| **Onboarding & Delta CLI** | [`scripts/README.md`](scripts/README.md) | 7-Layer Deep Discovery Engine (`aws_onboard.py`), Greenfield vs Brownfield Delta Planning, IAM propagation retry backoff, dead-stack self-healing, and CFN failure forensic extraction. |
| **Universal Live Investigation** | [`demos/README.md`](demos/README.md) | Zero-scripted dynamic incident investigation (`run_live_incident.py`), auto-discovery via `IncidentsAgent=true`, and Slack Socket Mode interactive approval. |
| **Verification & Tests** | [`tests/README.md`](tests/README.md) | **541 automated tests** (100% pass rate), cross-backend storage conformance (`DynamoDB`, `SQLite`, `InMemory`), defensive shell injection hardening, and E2E simulation. |

---

## 🏛️ End-to-End System Architecture

The entire remediation lifecycle operates serverlessly on AWS, triggered by CloudWatch alarms via EventBridge, coordinated through an immutable DynamoDB event ledger, and enforced via Zero-Trust SSM documents:

```mermaid
flowchart TD
    %% ALARM TRIGGER
    CW[CloudWatch Metric Alarm] -->|ALARM State Change| EB[Amazon EventBridge Rule]
    EB --> Ingest[incidents-ingest Lambda]

    %% INGEST & EVENTSTORE
    subgraph EventStoreLayer [Immutable DynamoDB EventStore Layer]
        Dedup[(incidents-dedup)]
        Events[(incidents-events - Append Only)]
        Leases[(incidents-leases - Distributed Locks)]
        S3Blobs[(S3 Blobs Bucket - Payloads > 300KB)]
    end

    Ingest -->|1. Atomic Deduplication| Dedup
    Ingest -->|2. Append IncidentOpened| Events
    Ingest -.->|3. InvokeAsync| Agent[incidents-agent Lambda]

    %% AGENT REASONING LOOP
    subgraph AgentLoop [Autonomous Reasoning Sandbox - Zero SSM Permissions]
        Agent -->|Acquire & Renew Lease| Leases
        Agent <-->|Event Stream / fold| Events
        
        %% Model & Tool Routing
        Agent <-->|Tactical Tool Decision ~115ms| Strands[Strands Decider 2B / Embedded Handler]
        Agent <-->|Generative Parameter Synthesis| Router[Amazon Bedrock: Nova Pro / DeepSeek]
        
        %% Policy Gate
        Agent --> Gate[Zero-Trust Policy Gate: 16 Invariants I-01..I-16]
    end

    %% OBSERVATION (T0)
    subgraph ObservationPerimeter [Zero-Trust Observation Perimeter]
        Agent -->|InvokeSync T0 Request| Observer[incidents-observer Lambda]
        Observer -->|ssm:SendCommand| SSM_Obs[SSM Doc: incidents-observe-readonly]
        SSM_Obs --> TargetEC2[EC2 Target Instance - Tag: IncidentsAgent=true]
        TargetEC2 -.->|Read-Only Telemetry| SSM_Obs
        SSM_Obs -.->|Inspection Result| Observer
        Observer -.->|Return Output| Agent
    end

    %% GOVERNANCE & APPROVAL
    Gate -->|Tier T1: Autonomous Safe| ExecDirect[Dispatch Execution]
    Gate -->|Tier T2: High Impact Mutation| Notif[incidents-notifier Lambda]
    Gate -->|Tier T3: Violation| Reject[Abort / Re-plan Action]

    subgraph HumanGovernance [Human-in-the-Loop Cryptographic Approval]
        Notif -->|Interactive Socket Mode / BlockKit| Slack[Slack Channel / SecOps Lead]
        Slack -->|Approve & Execute| SlackCB[incidents-slack-callback Lambda]
        SlackCB -->|HMAC-SHA256 APPROVAL_MAC_KEY| AuthTag[Generate Cryptographic auth_tag]
        AuthTag -->|Append ApprovalGranted| Events
        SlackCB -.->|Resume Execution| Agent
    end

    %% EXECUTION (T1/T2)
    subgraph RemediationPerimeter [Zero-Trust Execution Perimeter]
        Agent -.->|InvokeAsync Approved Step| Executor[incidents-executor Lambda]
        ExecDirect -.->|InvokeAsync| Executor
        Executor -->|Validate HMAC auth_tag| Executor
        Executor -->|sts:AssumeRole| STS[Assume RemediationOperatorRole]
        STS -->|Scoped Credentials| Executor
        Executor -->|ssm:SendCommand| SSM_Repair[SSM Doc: incidents-repair-restricted]
        SSM_Repair --> TargetEC2
        
        %% Verification & Resolution
        Executor --> Verifier[Independent Health Verifier]
        Verifier -->|Telemetry Confirms Recovery| Resolved[Append VerificationPassed & IncidentResolved]
        Resolved --> Events
        Executor -.->|Notify Resolution| Notif
    end
```

---

## 🚀 Key Engineering Highlights

### 1. Zero-Runbook Dynamic Reasoning
Unlike legacy automation platforms that rely on brittle, static playbooks, this system operates on **first-principles systems engineering**:
* Formulates competing hypotheses based on real-time telemetry (`order-gateway.service failed` vs `port 8088 contention` vs `routing configuration error`).
* Gathers targeted diagnostic evidence using read-only inspections (`systemctl status`, `cat config`, `ss -tulpn`, `df -h`, `journalctl`).
* Adapts its investigation path autonomously when symptoms evolve, completely free of pre-scripted branching.

### 2. Zero-Trust Policy Gate & 16 Immutable Security Invariants
Every proposed action is intercepted by an independent, deterministic [`PolicyGate`](src/policy/gate.py) before reaching the execution layer:
* **`Tier.T0` (Pure Observation)**: Safe shell inspections (`ps`, `df`, `systemctl status`). Autonomous execution via read-only SSM document.
* **`Tier.T1` (Surgical Safe Remediation)**: Low-risk, reversible operations (`systemctl start/restart <unit>`, `truncate -s 0 <file>`). Autonomous by default.
* **`Tier.T2` (High-Impact Mutation)**: Modifying configuration files or stopping services. Blocked until a cryptographic **HMAC-SHA256 authorization tag** is computed and verified by an authorized human operator via Slack.
* **`Tier.T3` (Absolute Rejection)**: Immediate blocking of unsafe commands violating any of the **16 Security Invariants** (`I-01` to `I-16`), including IMDS queries (`169.254.169.254`), shell injection operators (`;`, `&&`, `||`, `` ` ``), access to secret paths (`/etc/shadow`), and targeting critical system daemons (`PID 1`, `sshd`, `systemd`).

### 3. Fail-Closed Governance & Safe Escalation
* Under Slack Interactive Socket Mode, human operators have an explicit window (`SLACK_APPROVAL_TIMEOUT=300` seconds / 5 minutes) to authorize high-risk T2 actions.
* If the engineer is away or the request expires: **The system halts safely in a Fail-Closed posture**. It appends an `EventType.Escalated` event to DynamoDB and leaves the infrastructure untouched.

---

## 🧪 Quickstart: Running the Agent & Tests

### 1. Running the Automated Test Suite (541 Tests - 100% Pass Rate)
Install dependencies and run the complete test suite:
```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

Verify specific architectural domains:
```bash
# Verify the 16 Security Invariants (93 tests)
python3 -m pytest tests/policy/ -v

# Verify Autonomous Reasoning Loop, Anti-Hesitation & Socket Mode (149 tests)
python3 -m pytest tests/agent/ -v

# Verify Storage Conformance across DynamoDB, SQLite & Memory (52 tests)
python3 -m pytest tests/conformance/ -v
```

---

### 2. Running Live Autonomous Incident Remediation (`demos/run_live_incident.py`)
Run a live, end-to-end autonomous investigation on any tagged EC2 host (`IncidentsAgent=true`):
```bash
python3 -u demos/run_live_incident.py "CloudWatch-ALB-5XX-Spike: Order gateway upstream routing failure detected on instance"
```

**Common Flags:**
* `--auto-approve`: Enable simulated T2 auto-approval for non-interactive automated testing.
* `--allow-healthy`: Run full 4-layer diagnostic triage even if the host is currently healthy (false alarm verification).
* `--instance-id <ID>`: Target a specific EC2 instance explicitly.
* `--max-cycles <N>`: Adjust the reasoning cycle budget (default: 20).

---

## 📄 License & Compliance

This project is licensed under the **Apache License 2.0** (an approved OSI Open Source License). Designed for mission-critical enterprise AWS environments with strict SOC2, HIPAA, and GDPR isolation boundaries.
