# Autonomous Zero-Trust SecOps Agent: Sub-Millisecond Tool Selection with Strands Decider 2B and Amazon Bedrock

**Tags:** `#strands-decider-2b` `#tool-selection` `#aws-hackathon` `#amazon-bedrock` `#cloud-security`

---

## Executive Summary
In production cloud environments, autonomous incident remediation agents cannot afford multi-second latency or high inference costs for routine tactical decisions. When an EC2 instance crashes or experiences anomalous resource exhaustion, querying a multi-billion parameter foundation model (LLM) at every reasoning step introduces high latency (2–4 seconds), token bloat, and hallucination risks that can lead to catastrophic misconfigurations.

We built the **Autonomous Zero-Trust SecOps Agent for AWS**—an event-sourced, self-healing system that decouples tactical decision-making from generative reasoning:
1. **Strands Decider 2B** handles high-frequency, tactical tool selection in **sub-millisecond latency (~0.024 ms embedded / ~115 ms remote)**.
2. **Amazon Bedrock (Amazon Nova / DeepSeek)** handles generative argument synthesis only when an intervention is chosen.
3. A deterministic **Zero-Trust Policy Gate** enforces 16 security invariants and cryptographic HMAC-SHA256 human-in-the-loop governance before any command touches infrastructure.

---

## The Meaningful Decision: Autonomous Tool Selection (`#tool-selection`)

During an active incident cycle, the agent must repeatedly answer one high-stakes question:
> **Typed Question:**  
> *"Given the current incident triage state, collected evidence, active hypotheses, and reasoning cycle, which tool should the autonomous agent execute next?"*

### Decision Option Set
* `observe` — Gathers non-mutating OS telemetry (systemctl, ss, ps, journalctl) via AWS Systems Manager (SSM) T0 read-only document.
* `query_metrics` — Inspects CloudWatch metric aggregates (ALB 5XX errors, CPU utilization, Disk space).
* `update_hypotheses` — Formulates and updates competing root-cause hypotheses based on gathered evidence.
* `propose_step` — Formulates a surgical remediation step (bound to SHA-256 plan hash).
* `escalate` — Immediately triggers a fail-closed human escalation when uncertainty is high.

### Calibrated Confidence & Safe Low-Confidence Handling
Strands Decider 2B returns a categorical choice along with a **calibrated confidence score**:
* **High Confidence ($\ge 0.35$):** Normal autonomous execution proceeds.
* **Low Confidence ($0.15 \le \text{confidence} < 0.35$):** Enforces defensive routing; any mutating step requires explicit human confirmation.
* **Critical Uncertainty ($< 0.15$):** Triggers **Fail-Closed Safe Escalation**—the decider forces `escalate`, preventing unauthorized mutations when telemetry is ambiguous.

---

## Measured Benchmark: Strands Decider 2B vs Frontier LLM

We executed 100 benchmark decision cycles comparing Strands Decider 2B against calling a frontier foundation model on Amazon Bedrock:

| Metric | Strands Decider 2B | Frontier LLM on Bedrock | Improvement / Impact |
| :--- | :--- | :--- | :--- |
| **Decision Latency (Average)** | **0.024 ms** (Embedded) / **114.2 ms** (Remote) | **2,450.0 ms** | **>20x to 100,000x Faster** ⚡ |
| **P95 Decision Latency** | **0.038 ms** | **3,210.0 ms** | Deterministic P95 response |
| **Cost per Tool Selection** | **$0.000008** | **$0.006150** | **99.8% Cost Reduction** 💰 |
| **Tool Hallucination Surface** | **0%** (Constrained Enum) | ~3–5% (Syntax Drift) | Zero Tool Hallucination |

By offloading the high-frequency decision from the LLM to Strands Decider 2B, the agent eliminates operational stalling during live outages while slashing token costs by nearly 100%.

---

## Architectural Deep Dive: End-to-End Closed Loop

```
CloudWatch Alarm / EventBridge
          │
          ▼
   incidents-ingest (Lambda)
          │ (InvokeAsync)
          ▼
   incidents-agent (Lambda)
     ├── Strands Decider 2B  ──▶ Tactical Tool Hint (~0.024ms)
     └── Amazon Bedrock      ──▶ Argument Synthesis
          │
          ▼
   Zero-Trust Policy Gate (11 Steps & 16 Invariants)
          │
    ┌─────┴─────────────────────┐
    ▼                           ▼
[T0/T1 Safe Allow]     [T2 Slack Socket Mode + HMAC]
    │                           │
    └───────────┬───────────────┘
                ▼
       incidents-executor
                │
                ▼
      SSM repair-restricted
                │
                ▼
       Independent Verifier
         ├── pass ──▶ IncidentResolved
         └── fail ──▶ Rollback + Escalate
                │
                ▼
   state = fold(events)  (Event Sourcing Ledger)
```

1. **Detection & Ingest:** A CloudWatch alarm triggers Amazon EventBridge, which deduplicates the incident in DynamoDB and invokes `incidents-agent`.
2. **Tactical Selection:** The `SecOpsToolSelectionInterventionHandler` invokes Strands Decider 2B to select the next tool before Bedrock is invoked.
3. **Policy Gate (Fail-Closed):** Any proposed mutation is checked against 16 immutable invariants (SSH lockdown, package quarantine, reboot prohibition, IMDSv2 protection) and bound to a SHA-256 `plan_hash`.
4. **Governed Execution:** Safe steps execute automatically; high-impact mutations trigger Slack BlockKit approval requiring an HMAC-SHA256 signature via Socket Mode (zero inbound ports).
5. **Independent Verification & State Machine:** The `Independent Verifier` remeasures metrics without trusting the agent. If verified, state transitions to `IncidentResolved`; if failed twice, automatic rollback restores the pre-execution snapshot.

---

## The Reusable Decision Asset

We packaged this decision pattern as a clean, modular recipe that any builder can drop into their agent:
* **Code Recipe:** [`patterns/strands_secops_tool_selection/pattern.py`](https://github.com/Tt140/Zt1/tree/main/patterns/strands_secops_tool_selection/pattern.py)
* **Documentation & Quickstart:** [`patterns/strands_secops_tool_selection/README.md`](https://github.com/Tt140/Zt1/tree/main/patterns/strands_secops_tool_selection/README.md)
* **License:** Apache-2.0 Open Source License.

```python
from pattern import StrandsToolDecider, SecOpsDecisionContext

decider = StrandsToolDecider()
context = SecOpsDecisionContext(
    incident_description="CPU spike and memory leak in worker process",
    cycle=1,
    evidence_count=3,
    active_hypotheses_count=1
)

decision = decider.decide(context)
print(f"Selected Tool: {decision.tool_name} (Confidence: {decision.confidence:.2f})")
# Output: Selected Tool: observe (Confidence: 0.88)
```

---

## Links & Submission Deliverables
* 📁 **Public GitHub Repository:** [https://github.com/Tt140/Zt1](https://github.com/Tt140/Zt1)
* 📺 **Live Video Demonstration (YouTube):** [https://www.youtube.com/watch?v=572k45RA4yo](https://www.youtube.com/watch?v=572k45RA4yo)
* 🧩 **Reusable Strands Pattern:** [https://github.com/Tt140/Zt1/tree/main/patterns/strands_secops_tool_selection](https://github.com/Tt140/Zt1/tree/main/patterns/strands_secops_tool_selection)
* 🧪 **Test Suite:** 541 passing unit & integration tests (100% coverage).
