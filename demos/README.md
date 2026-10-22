# Live Autonomous Incident Investigation (`demos/`)

This directory provides the unified, real-world execution harness for running autonomous incident investigations on live AWS infrastructure.

The core philosophy of this engine is **Zero Pre-Scripted Outages**: production outages do not follow predictable, scripted runbooks. The agent investigates, formulates hypotheses, collects telemetry, navigates security policy boundaries, and remediates dynamically based on first principles.

---

## 1. Directory Structure

```text
demos/
├── _harness.py             <── Core live investigation harness, SSM executor & Slack Socket Mode
└── run_live_incident.py    <── Universal CLI entrypoint for dynamic live incident investigation
```

---

## 2. Universal Incident Runner (`run_live_incident.py`)

The runner accepts any CloudWatch alarm description, automatically discovers the target EC2 host, establishes a cryptographic event stream in DynamoDB, and launches the autonomous reasoning loop:

```bash
python3 -u demos/run_live_incident.py "CloudWatch-ALB-5XX-Spike: Order gateway upstream routing failure detected on instance"
```

### Key CLI Options:
| Flag | Description | Default |
|---|---|---|
| `incident_description` | Positional string describing the incident or CloudWatch alarm. | Required |
| `--instance-id <ID>` | Explicit EC2 instance ID. If omitted, dynamically discovers host tagged `IncidentsAgent=true`. | Auto-discovered |
| `--region <REGION>` | AWS region for SSM, CloudWatch, and DynamoDB operations. | `us-east-1` (or `$AWS_REGION`) |
| `--max-cycles <N>` | Maximum reasoning cycles before halting or concluding. | `20` |
| `--auto-approve` | Simulate automated T2 approval for unattended lab testing. | `False` (Interactive Slack) |
| `--allow-healthy` | Run full 4-layer diagnostic triage even if the server is healthy (false alarm verification). | `False` |
| `--channel <CHANNEL>` | Slack channel for interactive BlockKit approval dialogs. | `#incidents-approval` |

---

## 3. Dynamic Target Resolution (`_harness.py`)

All live operations are 100% free of hardcoded instance IDs, account IDs, or static IPs. The harness dynamically resolves target EC2 instances:

```python
def resolve_target_instance_id(region: Optional[str] = None) -> str:
    # 1. Environment variable override
    env_id = os.environ.get("TARGET_INSTANCE_ID", "").strip()
    if env_id:
        return env_id

    # 2. Query EC2 API for running instances with security tag
    ec2 = boto3.client("ec2", region_name=region or os.environ.get("AWS_REGION", "us-east-1"))
    res = ec2.describe_instances(
        Filters=[
            {"Name": "instance-state-name", "Values": ["running"]},
            {"Name": "tag:IncidentsAgent", "Values": ["true"]},
        ]
    )
    for r in res.get("Reservations", []):
        for inst in r.get("Instances", []):
            if inst.get("InstanceId"):
                return inst["InstanceId"]
    return "i-placeholder"
```

---

## 4. Human-in-the-Loop Governance via Slack Socket Mode

When a remediation step is classified by the `PolicyGate` as **Tier T2 (High-Impact Mutation)**:
1. The execution halts immediately.
2. An interactive BlockKit card is dispatched to the Slack channel with step details, proposed command, and blast radius.
3. The harness opens a real-time, outbound-only **Slack Socket Mode** connection (requiring zero public ingress IPs or firewall holes).
4. An authorized SecOps engineer reviews and clicks **Approve & Execute** or **Deny**.
5. Upon approval, an HMAC-SHA256 signature is verified, recorded in the DynamoDB EventStore, and execution resumes.

### Fail-Closed Safe Escalation
If the engineer does not respond within the configured approval timeout (`SLACK_APPROVAL_TIMEOUT=300` seconds / 5 minutes):
* The system enforces a **Fail-Closed** safety posture.
* It does **not** execute any unapproved mutation.
* It appends an `EventType.Escalated` event to DynamoDB, transition the incident phase to `escalated`, and alerts the on-call team.

---

## 5. End-to-End Investigation Walkthrough

A typical live execution progresses through 3 autonomous rounds:

1. **Round 1: Initial Discovery & Triage**
   * Discovers failed units via `systemctl list-units --state=failed`.
   * Queries status and logs (`systemctl status <unit>`, `journalctl`).
   * Proposes surgical config restoration (classified as Tier T2).
   * Prompts human engineer via Slack and waits for approval.
2. **Round 2: Remediation & Service Verification**
   * Executes approved file restoration via SSM document `incidents-repair-restricted`.
   * Proposes and auto-executes `systemctl start <unit>` as Tier T1.
   * Confirms service transition to `active (running)`.
3. **Round 3: 4-Layer Post-Remediation Verification & Conclusion**
   * Verifies absence of corrupt tokens (`grep`).
   * Verifies socket listening ports (`ss -tulpn`).
   * Verifies disk and resource health (`df -h`, `ps aux`).
   * Invokes `conclude` with high confidence ($\ge 0.90$), closing the incident as `resolved` and notifying Slack.
