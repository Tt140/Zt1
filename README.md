# 🛡️ Autonomous Zero-Trust SecOps Agent for AWS

[![AWS Hackathon](https://img.shields.io/badge/AWS%20Hackathon-Strands%20Decider%202B%20%7C%20Amazon%20Bedrock-orange?style=for-the-badge)](#)
[![YouTube Demo](https://img.shields.io/badge/YouTube%20Demo-Live%20Remediation-red?style=for-the-badge&logo=youtube)](https://youtu.be/aHZh-q39Zik?si=u7Z483rJQfceuCBe)
[![Pattern Tags](https://img.shields.io/badge/Pattern%20Tags-%23strands--decider--2b%20%7C%20%23tool--selection-blue?style=for-the-badge)](#-mandatory-hackathon-tags)
[![Pytest Suite](https://img.shields.io/badge/pytest-575%20passed%20(100%25)-brightgreen?style=for-the-badge&logo=pytest)](tests/README.md)
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

[![Autonomous SecOps Agent Live Demo](https://img.youtube.com/vi/aHZh-q39Zik/hqdefault.jpg)](https://youtu.be/aHZh-q39Zik?si=u7Z483rJQfceuCBe)  
*▶️ [Click to watch the full demonstration on YouTube](https://youtu.be/aHZh-q39Zik?si=u7Z483rJQfceuCBe)*

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
| **Verification & Tests** | [`tests/README.md`](tests/README.md) | **575 automated tests** (100% pass rate), cross-backend storage conformance (`DynamoDB`, `SQLite`, `InMemory`), defensive shell injection hardening, and E2E simulation. |

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

### 4. Universal Autonomous Sentinel & 5-Alarm Production Suite (IaC)
The system eliminates brittle distro-specific or application-specific monitoring via a universal 5-alarm CloudWatch suite defined in `template.yaml` (863 lines of AWS SAM):
* **`High-CPU` (AWS/EC2)**: CPUUtilization > 85% (catches infinite loops & runaway processes across ANY OS).
* **`StatusCheckFailed` (AWS/EC2)**: Hypervisor & OS deadlock detection from AWS infrastructure directly.
* **`High-Disk` (CWAgent)**: Root filesystem consumption > 85% with unified `"aggregation_dimensions": [["InstanceId"]]` to eliminate device name fragmentation (`nvme` vs `xvda`).
* **`High-Memory` (CWAgent)**: Physical RAM pressure > 85% to mitigate OOM kills before system crash.
* **`System-Degraded` (CWAgent)**: Generic service failure alarm driven by a native **Linux Systemd Timer** (`cwsys_health.timer`) running every 60s via IMDSv2. Detects both abnormal process crashes (`systemctl --failed`) AND stopped enabled critical services (`! is-active`) with zero `cron`/`cronie` dependency across Ubuntu, Debian, AL2023, and RHEL.
* **Architectural Decoupling**: Crucially, `SystemDegradedAlarm` is **100% decoupled** from disk metrics in `template.yaml` (`Condition: ShouldCreateAlarms`), guaranteeing that daemon crashes and dead services trigger immediate self-healing on any server regardless of disk telemetry status.

### 5. Omni-Ingestion Sentinel Layer (`handlers/ingest.py`)
`incidents-ingest` operates as a decoupled, multi-source ingestion sentinel:
* Parses CloudWatch alarm state transitions via EventBridge with zero reliance on alarm naming conventions.
* Extracts the target instance directly from `configuration.metrics[*].metricStat.metric.dimensions`, allowing custom enterprise alarms (`Prod-API-Down`, `Payment-Gateway-Failure`) to seamlessly route to the autonomous agent.

### 6. Universal Workload & Distro-Agnostic Masterclass (Quiet Engineering Flex)
Most automated SRE tools break when confronted with real-world enterprise infrastructure: they mandate custom golden AMIs, reboot running instances, rely on specific package managers, or only monitor pre-configured web servers. 

This platform was engineered from first principles to be **100% non-intrusive, workload-agnostic, and distro-agnostic**:
* **Universal Distro Agnosticism**: Functions out of the box across **Ubuntu (20.04/22.04/24.04), Debian (11/12), Amazon Linux 2023/2, RHEL (8/9), Rocky Linux, and CentOS**. The onboarding engine dynamically inspects package managers (`dnf`, `yum`, `apt-get`) and falls back to architecture-aware official AWS binaries if needed.
* **Workload-Agnostic Process Sentinel**: Operates universally across **Docker, Nginx, Node.js, Python/Gunicorn, Go, PM2, PostgreSQL, MySQL, Redis**, or any custom systemd daemon.
* **Zero-Downtime Brownfield In-Place Bootstrap**: Adopting an existing production server (`--instance-id <ID>`) executes entirely in-place via AWS SSM RunCommand. **No reboots, no downtime, and zero disruption to live customer traffic**. The CLI inspects existing IAM profiles, safely attaches `CloudWatchAgentServerPolicy`, deploys the native systemd timer, and immediately activates the full 5-alarm production suite.
* **SCP-Immune Regional Independence**: By decoupling generative reasoning from cross-region IAM policies and leveraging BYOK HTTPS Bearer authentication via AWS Secrets Manager, the system operates seamlessly in restricted regions (such as `eu-north-1`) where Service Control Policies (SCPs) strictly block foundation model API activations.

| Architectural Dimension | Legacy / Typical Agent Approach | Autonomous Zero-Trust Sentinel (Our IaC) |
| :--- | :--- | :--- |
| **Client Server Adoption** | Demands newly baked AMIs, agent rebuilds, or server restarts | **Zero-Downtime In-Place Bootstrap** via AWS SSM on any live server |
| **Linux Distribution Scope** | Hardcoded for Amazon Linux or single package manager | **100% Multi-Distro Agnostic** (Ubuntu, Debian, AL2023/2, RHEL, Rocky) |
| **Service Crash Detection** | Brittle `cron` jobs or hardcoded scripts for specific processes | **Universal Native Systemd Timer Pulse** (Dual-detects crashes & clean stops) |
| **Disk Device Fragmentation** | Alarms break across instance types (`nvme0n1p1` vs `xvda1`) | **Unified Aggregation Dimensions** (`aggregation_dimensions: [["InstanceId"]]`) |
| **Alarm Decoupling** | Service degradation suppressed if disk metrics absent | **Fully Decoupled `SystemDegradedAlarm`** evaluating 100% independently |
| **Regional SCP & IAM Constraints** | Cross-region IAM roles triggering SCP `AccessDenied` | **SCP-Immune BYOK Architecture** with zero cross-region dependencies |
| **Core IAM Role Gaps & Collision Drift** | Missing roles cause `AccessDenied`; duplicate CloudFormation `Add` triggers `ResourceExistenceCheck` | **Self-Healing Core IAM & Zero-Collision IaC Engine** (7-role idempotent reconciliation, `CreateCoreIamRoles=false` on apply, SAM `!If` conditional linkage, ordered principal generation, wildcard `incidents-*` invocation, 12s STS propagation delay) |

### 7. Triple-Defense Deduplication Lifecycle (Production Self-Healing)
In mission-critical AWS environments, alarm deduplication must balance two competing requirements: **preventing alert storms** during an active outage, while **instantly unblocking new alerts** as soon as an issue is remediated. The system implements a triple-defense architecture:
1. **Immediate Post-Resolution Release (`store.release_dedupe`)**: The instant an incident reaches `RESOLVED` or `CONCLUDED`, the agent automatically calls `release_dedupe(dedupe_key)` on DynamoDB `incidents-dedup`. The lock is cleared within milliseconds, enabling immediate re-triggering if the server degrades again.
2. **State-Aware Ingestion Fallback (`handlers/ingest.py`)**: When an alarm fires for an existing deduplication key, the ingest sentinel checks the prior incident's terminal state in the EventStore. If the earlier incident reached `resolved` or `escalated`, the stale lock is automatically purged in-flight, preventing dropped alerts.
3. **Automated 24h DynamoDB TTL Safety Net (`expires_epoch`)**: Every record written to `incidents-dedup` carries an epoch TTL timestamp. DynamoDB native Time-To-Live continuously reclaims orphaned entries in the background, guaranteeing that no host can ever enter an unrecoverable suppression deadlock.

### 8. Intelligent Anti-Repetition & PolicyGate Denial Interception (Fast-Fail Circuit Breaker)
Autonomous LLM agents commonly suffer from "prompt paralysis" when a proposed action is rejected: they modify cosmetic wording (e.g., tweaking descriptions or rollback justifications) while stubbornly repeating the exact same prohibited command. The platform eliminates this vulnerability with five coordinated safeguards:
* **Zero-Trust Invariant Interception**: Evaluates commands against all 16 Security Invariants (`I-01` to `I-16`) at Step 6—**before** Tier classification or human approval. Invariant violations (such as `I-02` prohibiting SSH keyword tampering) trigger an immediate, non-bypassable `Tier.T3 Hard Deny`.
* **Semantic Remediation Deduplication**: Normalizes commands across rounds (`command` and `resource`), stripping leading `sudo` and whitespace. Duplicate remediation commands are intercepted even when the LLM generates entirely new narrative text.
* **Prohibited Commands Blacklist (`denied_commands`)**: Every command rejected by PolicyGate is permanently blacklisted for that incident. The registry persists across reasoning cycles and agent invocations.
* **Fast-Fail Escalation Circuit Breaker**: If an agent attempts to re-propose a hard-denied command, the loop intercepts the call and immediately escalates the ticket to Slack (`LoopTermination.ESCALATED`). It refuses to waste token budget spinning across remaining cycles.
* **Dynamic Denial Steering**: Injects explicit `ACTION FORBIDDEN` directives and policy rejection reasons into `remediation_history`, dynamically steering the LLM toward viable alternative tactics (e.g., executing evidence-backed surgical process termination via specific numeric PID `kill <pid>` rather than attempting protected service stops).

### 9. Multi-Tier Governance Matrix (Machine-Speed T1 vs. Human T2 vs. Hard-Deny T3)
The system decouples **Reasoning Autonomy** from **Execution Authority**, enforcing a formal 4-tier risk classification:

| Governance Tier | Operational Scope | Autonomous Execution? | Human Approval Required? | Example Scenarios |
| :--- | :--- | :---: | :---: | :--- |
| **Tier T0** | Read-Only Inspection | ✅ **Machine Speed** | ❌ None | `ps aux`, `df -h`, `journalctl -u <svc>`, `ss -tulpn` |
| **Tier T1** | Safe Surgical Remediation | ✅ **Machine Speed** | ❌ None (Pre-Approved) | `truncate -s 0 /var/log/app.log`, `systemctl restart <normal-svc>`, surgical `kill <pid>` (PID > 100, non-sensitive) |
| **Tier T2** | High-Impact Mutation | ⏸️ **Awaiting Approval** | ✅ **Mandatory (Slack BlockKit)** | `systemctl stop <svc>`, process termination linked to core infrastructure daemons, unknown risk claims |
| **Tier T3** | Security Invariant Violation | 🚫 **Hard Denied** | 🚫 **Cannot be Approved** | Tampering with SSH (`/etc/ssh`, `sshd`), cloud credentials, IMDS metadata, audit logs, or PID 1 |

---

## 🧪 Quickstart: Running the Agent & Tests

### 1. Zero-Touch Onboarding & Environment Injection (`-E` / `--env-file`)
Adopt an existing production EC2 instance or deploy a dedicated sandboxed environment in a single command, automatically injecting credentials from your local `.env` into AWS Secrets Manager and operational parameters into CloudFormation:
```bash
python3 scripts/aws_onboard.py --mode apply --instance-id <INSTANCE_ID> -E .env --yes
```
* **Strict Security Segregation**: Sensitive credentials (`DEEPSEEK_API_KEY`, `APPROVAL_MAC_KEY_HEX`, `SLACK_WEBHOOK_URL`, Slack tokens) are routed directly and securely into **AWS Secrets Manager** via HTTPS API.
* **Operational Configuration**: Model identifiers and routing parameters (`DEEPSEEK_FLASH_MODEL`, `DEEPSEEK_BASE_URL`, `STRANDS_URL`, `SLACK_CHANNEL`, etc.) are passed as SAM parameter overrides to update the Lambda environment.
* **Self-Healing IAM Layer**: Automatically reconciles all 7 core execution roles (`agent`, `observer`, `ingest`, `executor`, `notifier`, `slack-callback`, `RemediationOperatorRole`), grants forensic S3 snapshot storage, expands SSM document boundaries to AWS default documents, and sets `CreateCoreIamRoles=false` during apply to guarantee zero CloudFormation name collision errors.
* **Git Safe**: `template.yaml` remains 100% free of secrets, and `.env` is strictly protected inside `.gitignore`.

---

### 2. 1-Click Reproducible Deployment via AWS SAM
Deploy the complete production stack (6 Serverless Lambdas, 3 DynamoDB Tables, 5 CloudWatch Alarms, and Least-Privilege IAM Boundaries) into any AWS account within two minutes:
```bash
sam build
sam deploy --guided
```

---

### 3. Running the Automated Test Suite (575 Tests - 100% Pass Rate)
Install dependencies and run the complete test suite:
```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

Verify specific architectural domains:
```bash
# Verify the 16 Security Invariants (98 tests)
python3 -m pytest tests/policy/ -v

# Verify Autonomous Reasoning Loop, Anti-Hesitation & Socket Mode (153 tests)
python3 -m pytest tests/agent/ -v

# Verify Core Domain, Onboarding CLI & IAM/SSM Reconciliation (110 tests)
python3 -m pytest tests/unit/ -v

# Verify Serverless Handlers & Dual Notifications (64 tests)
python3 -m pytest tests/handlers/ -v

# Verify Storage Conformance across DynamoDB, SQLite & Memory (52 tests)
python3 -m pytest tests/conformance/ -v
```

---

### 3. Running Live Autonomous Incident Remediation (`demos/run_live_incident.py`)
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
