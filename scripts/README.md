# Autonomous AWS Onboarding & Delta Provisioning CLI (`scripts/`)

This directory houses [`aws_onboard.py`](aws_onboard.py), a production-grade, multi-stage AWS environment discovery, planning, and delta-provisioning CLI engineered to automate onboarding client AWS accounts onto the **Autonomous SecOps Incident Remediation Engine**.

The tool operates with zero intrusive assumptions, enforcing a strict separation between **Read-Only Discovery (`audit`)**, **Idempotent Parameter Planning (`plan`)**, and **Governed Remediation & Deployment (`apply`)**.

---

## 1. Onboarding & Provisioning Lifecycle (Mermaid Flowchart)

```mermaid
flowchart TD
    Start([Run aws_onboard.py]) --> ModeCheck{Select Mode}

    %% AUDIT MODE
    ModeCheck -->|--mode audit| Audit[7-Layer Deep Discovery Engine]
    Audit --> L1[1. STS Caller Identity]
    Audit --> L2[2. EC2 & SSM Fleet Connectivity]
    Audit --> L3[3. DynamoDB EventStore Tables]
    Audit --> L4[4. S3 Blobs Bucket Discovery]
    Audit --> L5[5. Zero-Trust SSM Documents & Drift]
    Audit --> L6[6. IAM Core Roles & Profiles]
    Audit --> L7[7. Secrets Manager & Stack Status]
    L1 & L2 & L3 & L4 & L5 & L6 & L7 --> Report[Generate Audit Report & Global View]
    Report --> EndAudit([Exit 0: Complete Audit])

    %% PLAN MODE
    ModeCheck -->|--mode plan| Plan[Calculate Delta vs template.yaml]
    Plan --> Choice{Resource Policy Choice}
    Choice -->|Option A: Adopt Existing| Adopt[Use --instance-id & --existing-bucket]
    Choice -->|Option B: Greenfield -T| Greenfield[Plan Dedicated VPS + Bucket]
    Adopt & Greenfield --> ParamGen[Generate SAM Parameter Overrides]
    ParamGen --> EndPlan([Exit 0: Ready for Review])

    %% APPLY MODE
    ModeCheck -->|--mode apply| Apply[Governed Execution & Self-Healing]
    Apply --> CleanCheck{Stack in ROLLBACK_COMPLETE?}
    CleanCheck -->|Yes| AutoClean[ensure_clean_stack_before_deploy: Purge Dead Stack]
    CleanCheck -->|No| PreDeploy[Execute Pre-Deploy Remediations]
    AutoClean --> PreDeploy

    PreDeploy --> IAMProp{New Instance Profile Created?}
    IAMProp -->|Yes| RetryBackoff[IAM Eventual Consistency Retry Backoff: 5-15s]
    IAMProp -->|No| Tagging[Apply IncidentsAgent=true Security Tag]
    RetryBackoff --> Tagging

    Tagging --> SecretsCheck[Provision Missing HMAC & DeepSeek Secrets]
    SecretsCheck --> SAMCheck{Skip SAM Deploy?}
    SAMCheck -->|--skip-sam| Receipts[Write onboarding_report.json & .env.onboarded]
    SAMCheck -->|Deploy| SAMDeploy[sam build && sam deploy --region ...]
    
    SAMDeploy --> DeployResult{CFN Deploy Success?}
    DeployResult -->|Success| Receipts
    DeployResult -->|Failed| Forensics[extract_cfn_failure_root_causes: Parse Events]
    Forensics --> Abort([Exit 1: Print Root Cause Failure])
    Receipts --> EndApply([Exit 0: System Online])
```

---

## 2. The 7-Layer Deep Discovery Engine (`--mode audit`)

When invoked in `--mode audit`, `aws_onboard.py` performs a read-only interrogation across 7 distinct AWS infrastructure layers. It makes zero mutations and returns an architectural assessment of the target environment.

| Layer | Audit Function | Target Resources & API Invocations | Architectural Discovery Objective |
|---|---|---|---|
| **1. Identity** | `audit_identity` | `sts:GetCallerIdentity` | Validates active AWS credentials, captures Account ID, IAM User/Role ARN, and verifies regional API connectivity. |
| **2. Compute & SSM** | `audit_ec2` | `ec2:DescribeInstances`<br/>`ssm:DescribeInstanceInformation`<br/>`cloudwatch:ListMetrics` | Enumerates running EC2 instances, inspects attached IAM instance profiles, checks SSM Fleet Manager `PingStatus == "Online"`, checks for the `IncidentsAgent=true` security tag, and probes for CloudWatch Agent disk metrics (`CWAgent`). Detects running Strands Decider instances. |
| **3. EventStore** | `audit_dynamodb` | `dynamodb:DescribeTable` | Inspects core EventStore tables: `incidents-events`, `incidents-dedup`, and `incidents-leases`. Validates primary key schemas (`incident_id`, `dedupe_key`), partition keys, and billing modes (`PAY_PER_REQUEST`). |
| **4. Storage Blobs** | `audit_s3_bucket` | `s3:GetBucketEncryption`<br/>`s3:ListBuckets` | Checks for the default large-blob offload bucket `incidents-blobs-<account_id>` and validates AES256 server-side encryption. Discovers existing customer S3 buckets to support zero-footprint adoption. |
| **5. Zero-Trust SSM** | `audit_ssm` | `ssm:DescribeDocument`<br/>`ssm:GetDocument` | Audits Zero-Trust documents `incidents-observe-readonly` and `incidents-repair-restricted`. Performs **Regex Drift Detection** to verify that parameter validation patterns match the exact repository specification. |
| **6. IAM Security** | `audit_iam` | `iam:GetRole`<br/>`iam:GetInstanceProfile` | Validates existence of `IncidentsSSMExecutionRole` (`RemediationOperatorRole`) and `IncidentsTargetSSMInstanceProfile`. |
| **7. Secrets & Stack** | `audit_secrets_and_stack` | `secretsmanager:DescribeSecret`<br/>`cloudformation:DescribeStacks` | Audits required encryption and LLM keys (`/incidents/approval-mac-key`, `/incidents/deepseek-api-key`, Slack tokens). **Detects placeholder secrets** transparently. Inspects CloudFormation stack `autonomous-secops-agent` and verifies associated Lambda functions and EventBridge rules. |

---

## 3. Universal Client Resource Choice Policy

To prevent unintended modifications to existing production workloads, `aws_onboard.py` enforces a **Universal Client Resource Choice Policy**. The CLI never auto-selects or mutates existing customer instances or buckets without explicit instruction:

### Option A: Adopt Existing Client Resources (Non-Intrusive Brownfield)
Designed for enterprise clients integrating the agent into an existing environment without deploying new servers or storage:
* **Target EC2 Instance**: Pass `--instance-id <INSTANCE_ID>`. The CLI inspects the server, verifies SSM connectivity, and attaches the `IncidentsAgent=true` tag.
* **Brownfield Telemetry Auto-Bootstrap**: In `--mode apply`, the CLI uses AWS Systems Manager (`AWS-RunShellScript`) to automatically bootstrap `amazon-cloudwatch-agent` and the native systemd health timer (`cwsys_health.timer`) on the existing server in-place with **Zero Downtime and Zero Reboot**. It automatically attaches `CloudWatchAgentServerPolicy` to any existing IAM profile and enables all 5 production alarms (`High-CPU`, `StatusCheckFailed`, `High-Disk`, `High-Memory`, and decoupled `System-Degraded`).
* **Storage Bucket**: Pass `--existing-bucket <BUCKET_NAME>`. The tool sets SAM parameter `CreateBlobsBucket=false` and configures the agent to use the client's existing bucket for large incident telemetry blobs.
* **LLM Secrets**: Pass `--deepseek-api-key <KEY>` to securely store credentials into the client's AWS Secrets Manager (`/incidents/deepseek-api-key`).

### Option B: Greenfield Isolated Environment via `-T` (Zero-Touch Dedicated)
Designed for rapid proof-of-concept testing, training, or isolated sandboxing:
* Passing `-T` or `--create-target-vps` provisions a completely isolated, standalone environment:
  1. Creates an EC2 instance (`t3.micro` / `t4g.micro`) with automated multi-distro package manager detection (`dnf`, `apt-get`, `yum`).
  2. Creates and attaches `IncidentsTargetSSMInstanceProfile` with dual least-privilege IAM policies:
     * `AmazonSSMManagedInstanceCore` (Zero-Trust SSM execution & observation).
     * `CloudWatchAgentServerPolicy` (CloudWatch Agent and `put-metric-data` telemetry ingestion).
  3. Installs and enables the `nginx` web server as a sample production workload.
  4. Automatically configures and launches `amazon-cloudwatch-agent` with unified `"aggregation_dimensions": [["InstanceId"]]` to eliminate EBS/NVMe disk device name fragmentation (`nvme` vs `xvda`).
  5. Deploys the **Universal Native Systemd Health Pulse** (`cwsys_health.service` & `cwsys_health.timer`), running every 60 seconds with zero `cron`/`cronie` dependency across Ubuntu, Debian, AL2023, and RHEL.
  6. Automatically tags the instance with `IncidentsAgent=true`.
  7. Waits for SSM Fleet Manager to report the instance status as `Online`.
  8. Directs CloudFormation to create a dedicated S3 blobs bucket (`CreateBlobsBucket=true`) and automatically enables all 5 CloudWatch alarms (`EnableAlarms=true`, `EnableDiskAlarm=true`).

---

## 4. Production Self-Healing & CloudFormation Resilience

During `--mode apply`, `aws_onboard.py` incorporates autonomous self-healing routines to eliminate common real-world deployment blockers:

### 1. IAM Eventual Consistency Retry Backoff
When creating `IncidentsTargetSSMInstanceProfile` in distant AWS regions (e.g. `eu-north-1`), IAM metadata propagation to the regional EC2 API can take 5 to 15 seconds. If `ec2.run_instances` or `ec2.associate_iam_instance_profile` is called immediately, AWS throws `InvalidParameterValue (iamInstanceProfile.name is invalid)`.
* **Remediation**: The CLI implements exponential retry backoff with jitter, catching `ClientError` and re-attempting profile association up to 5 times until IAM propagation converges.

### 2. Dead Stack Self-Healing (`ensure_clean_stack_before_deploy`)
If a prior CloudFormation deployment failed during initial stack creation, AWS places the stack in `ROLLBACK_COMPLETE` or `DELETE_FAILED`. In this state, subsequent `sam deploy` calls immediately fail because CloudFormation cannot update a failed-creation stack.
* **Remediation**: The CLI inspects the stack status before invoking SAM. If stuck in `ROLLBACK_COMPLETE`, it automatically executes `cloudformation.delete_stack`, polls until deletion completes, and provisions a clean stack.

### 3. Forensic Root-Cause Failure Extraction (`extract_cfn_failure_root_causes`)
When `sam deploy` fails, standard tooling frequently outputs generic errors like `Waiter StackCreateComplete failed: ROLLBACK_COMPLETE`.
* **Remediation**: The CLI intercepts stack creation failures, queries `describe_stack_events`, filters for `ResourceStatus.endswith('FAILED')` (excluding generic cancellation messages), and prints the exact logical resource and AWS service error message (e.g., `[AgentFunction (AWS::Lambda::Function)] -> Specified ReservedConcurrentExecutions decreases unreserved concurrency below minimum`).

### 4. Strict `.env` Isolation & Placeholder Detection
The CLI inspects environment configurations and AWS Secrets Manager for unpopulated placeholder values (e.g. `YOUR_KEY_HERE`, `placeholder`). It flags unconfigured Slack webhooks or LLM tokens transparently and outputs a sanitized `.env.onboarded` file with zero secrets leaked.

### 5. Universal Native Systemd Health Pulse (Crash & Dynamic Clean Stop Detection)
Traditional monitoring scripts either fail on distributions lacking `cronie` (such as Amazon Linux 2023) or only detect abnormal crashes via `systemctl --failed` while ignoring manual or administrative service stops (`systemctl stop`).
* **Remediation**: `aws_onboard.py` automatically injects and activates a native Linux Systemd Timer (`cwsys_health.timer`) running every 60 seconds with IMDSv2 token security. In `--mode apply`, this injection is **unconditional and self-healing**—even if `/opt/incidents` was wiped or disk metrics existed previously. It calculates:
  $$\text{Failed Services} = \text{failed units count} + \text{stopped daemons count (dynamic discovery + core services + /etc/incidents/services.conf)}$$
  This dynamic multi-layer inspection checks:
  1. All crashed/failed units across the entire operating system (`systemctl list-units --state=failed`).
  2. Dynamic discovery of all enabled daemons configured with a systemd restart policy (`Restart != no`).
  3. Universal core production workloads (`nginx`, `docker`, `containerd`, `databases`, `microservices`, `workers`).
  4. Optional customer overrides via `/etc/incidents/services.conf`.
  This emits `FailedServicesCount` directly to the `CWAgent` CloudWatch namespace, guaranteeing that both unhandled application crashes and stopped services trigger an immediate `ALARM` state within 60 seconds.

### 6. Universal OS & Workload Compatibility Matrix (Quiet Engineering Flex)
`aws_onboard.py` was architected to be the ultimate non-intrusive onboarding engine for enterprise AWS accounts. It requires **zero changes** to existing client application architectures:

| Target Operating System | Detection & In-Place Bootstrap Mechanism | Workload & Process Coverage |
| :--- | :--- | :--- |
| **Ubuntu 20.04 / 22.04 / 24.04 LTS** | Automatic `apt-get` detection + official AWS `.deb` fallback | Any systemd service (`docker`, `nginx`, `node`, `pm2`, `python`) |
| **Debian 11 / 12** | Universal Debian package manager detection + IMDSv2 token security | Core daemons, web servers, databases (`postgres`, `redis`, `mysql`) |
| **Amazon Linux 2023 / 2** | Native `dnf` / `yum` package resolution + CloudWatch agent integration | Microservices, enterprise apps, Java, Go, container runtimes |
| **RHEL 8 / 9 & Rocky Linux** | RPM-based architecture inspection + systemd timer daemon | Heavy enterprise workloads, SAP, database clusters, custom daemons |

#### Why This Is an Engineering Flex:
1. **Zero Client Compromises**: The client doesn't have to launch a new EC2 instance, change their AMI, or configure SSH keys. Everything is governed through IAM and AWS Systems Manager.
2. **Zero Downtime**: The telemetry injection, CWAgent daemon start, and systemd timer enablement run in milliseconds in the background without restarting the instance or interrupting active TCP connections.
3. **Fail-Safe Decoupling**: In `template.yaml`, `SystemDegradedAlarm` is decoupled from disk metrics. Even before disk metrics are collected, CloudFormation deploys `SystemDegradedAlarm`, `High-CPU`, and `StatusCheckFailed` immediately, guaranteeing immediate protection.

### 7. Dual-Policy IAM Role Auto-Reconciliation (`ensure_instance_ssm_profile`)
When adopting an existing EC2 instance (Brownfield), `aws_onboard.py` inspects attached policies via `iam.list_attached_role_policies`. If either `AmazonSSMManagedInstanceCore` (Zero-Trust SSM execution & observation) or `CloudWatchAgentServerPolicy` (`cloudwatch:PutMetricData` and CWAgent metric reporting) is missing, the CLI attaches the missing policy automatically and idempotently. This eliminates `AccessDenied` errors during telemetry injection and guarantees continuous systemd health pulse reporting without manual IAM policy editing.

### 8. Zero-Touch Deployment with Environment Injection (`-E` / `--env-file`)

To eliminate manual credential extraction, shell parsing, and the accidental persistence of `PLACEHOLDER` secrets in AWS Secrets Manager, `aws_onboard.py` supports direct environment file injection via `-E` or `--env-file`:

```bash
# One-Command Zero-Touch Deployment with automatic environment injection:
python3 scripts/aws_onboard.py --mode apply --instance-id <INSTANCE_ID> -E .env --yes
```

#### Dual-Topology Architecture (Secrets vs Configuration Parameters)
`aws_onboard.py` parses the target `.env` file and strictly segregates variables into two isolated deployment paths:

| `.env` Key | Target Destination in AWS | Architectural Role & Security Guarantee |
|---|---|---|
| `DEEPSEEK_API_KEY` | `AWS Secrets Manager` (`/incidents/deepseek-api-key`) | Live Bedrock Mantle / DeepSeek Bearer Token. Automatically overwrites any previous `PLACEHOLDER` secret via `sm.put_secret_value`. Never logged or passed via SAM CLI. |
| `APPROVAL_MAC_KEY_HEX` | `AWS Secrets Manager` (`/incidents/approval-mac-key`) | 32-byte HMAC-SHA256 signing secret for Tier 2 autonomous remediation approvals. |
| `SLACK_WEBHOOK_URL` | `AWS Secrets Manager` (`/incidents/slack-webhook-url`) | Slack Webhook URL for autonomous incident alerting. |
| `SLACK_APP_TOKEN` | `AWS Secrets Manager` (`/incidents/slack-app-token`) | Slack App-level token for Socket Mode incident investigation. |
| `SLACK_REFRESH_TOKEN` | `AWS Secrets Manager` (`/incidents/slack-refresh-token`) | Slack token rotation secret. |
| `DEEPSEEK_BASE_URL` | `CloudFormation / SAM Parameter` (`DeepSeekBaseUrl`) | Bedrock Mantle API endpoint passed as a parameter override to update Lambda environment variables. |
| `DEEPSEEK_FLASH_MODEL` | `CloudFormation / SAM Parameter` (`DeepSeekFlashModel`) | Fast observation and triage model (`deepseek.v3.1` or `deepseek.v3.2`). |
| `DEEPSEEK_PRO_MODEL` | `CloudFormation / SAM Parameter` (`DeepSeekProModel`) | Deep reasoning and root cause synthesis model (`deepseek.v3.2`). |
| `NOVA_FLASH_MODEL_ID` | `CloudFormation / SAM Parameter` (`NovaFlashModelId`) | Fallback fast model (`amazon.nova-lite-v1:0`). |
| `NOVA_PRO_MODEL_ID` | `CloudFormation / SAM Parameter` (`NovaProModelId`) | Fallback deep model (`amazon.nova-pro-v1:0`). |
| `STRANDS_URL` | `CloudFormation / SAM Parameter` (`StrandsUrl`) | Strands Decider routing endpoint (or `embedded`). |
| `SLACK_AUTHORIZED_APPROVERS` | `CloudFormation / SAM Parameter` (`SlackAuthorizedApprovers`) | Comma-separated list of approved Slack user IDs for Tier 2 cryptographic actions. |
| `SLACK_CHANNEL` | `CloudFormation / SAM Parameter` (`SlackChannel`) | Target Slack channel for security alerts. |

#### Security & Git Hygiene Invariants:
1. **Zero Git Leaks**: `template.yaml` remains 100% free from private credentials. `.env` files remain strictly ignored by `.gitignore`.
2. **Zero Plaintext Logs**: Secrets are sent directly to AWS Secrets Manager using boto3 HTTPS API calls; they are never appended to `sam deploy --parameter-overrides` commands or echoed in terminal logs.
3. **Automatic Placeholder Overwrite**: If `/incidents/deepseek-api-key` was previously initialized as a `PLACEHOLDER`, passing `-E` automatically overwrites it with the valid active credential.

### 9. Self-Healing Core IAM Roles Engine & STS Eventual Consistency Delay

When adopting brownfield environments where IAM roles may have been partially deleted, misconfigured, or left without appropriate service trust relationships, `aws_onboard.py` includes a **Self-Healing Core IAM Roles Engine** (`ensure_core_iam_roles`):

1. **Idempotent 5-Role Lifecycle**: Automatically inspects, creates (`iam.create_role` on `NoSuchEntity`), and reconciles all core execution roles:
   - `incidents-agent-role` (Lambda reasoning loop & orchestration)
   - `incidents-observer-role` (SSM read-only observation & CloudWatch telemetry)
   - `incidents-ingest-role` (CloudWatch Alarm event ingestion & agent triggering)
   - `incidents-executor-role` (Policy Gate enforcement & STS AssumeRole for remediation)
   - `RemediationOperatorRole` (Zero-Trust surgical repair on tagged instances)
2. **Wildcard Inter-Lambda Invocation Policy**: Grants `lambda:InvokeFunction` on `arn:aws:lambda:${reg}:${account_id}:function:incidents-*` across all execution roles, eliminating `AccessDeniedException` across internal micro-Lambdas (`incidents-observer`, `incidents-executor`, `incidents-notifier`).
3. **Complete Observer Permissions**: Attaches both `AWSLambdaBasicExecutionRole` and `AmazonSSMReadOnlyAccess` to `incidents-observer-role`, alongside inline permissions for `incidents-observe-readonly`.
4. **AWS STS Regional Propagation Delay**: Regional STS endpoints in `us-east-1` exhibit eventual consistency. Whenever a role is newly created or a trust policy is updated (`roles_mutated = True`), `aws_onboard.py` automatically pauses for a safe 12-second propagation window before starting SAM build/deploy, preventing `The role defined for the function cannot be assumed by Lambda` errors.
5. **Resilient Secrets Resolution (Silenced 404s)**: Runtime secret resolution in `handlers/shared.py` catches `ResourceNotFoundException` at `DEBUG` level and returns empty strings cleanly for unconfigured optional secrets (such as Slack webhooks), preventing false alarms in CloudWatch logs.

---

## 5. CLI Reference & Command Examples

### CLI Options

| Argument | Flag | Description | Default |
|---|---|---|---|
| `--mode` | N/A | Execution mode: `audit` (read-only discovery), `plan` (calculate SAM parameters), `apply` (remediate & deploy). | `audit` |
| `--region` | N/A | Target AWS Region. | `$AWS_REGION` or `us-east-1` |
| `--create-target-vps` | `-T` | Provisions a dedicated greenfield EC2 instance (AL2023 + Nginx + SSM) with tag `IncidentsAgent=true`. | `False` |
| `--instance-id` | N/A | Adopts an existing EC2 instance ID for autonomous remediation. | `""` |
| `--existing-bucket` | N/A | Adopts an existing customer S3 bucket for incident blobs (disables automatic bucket creation). | `""` |
| `--deepseek-api-key` | N/A | Stores a DeepSeek API key into Secrets Manager (`/incidents/deepseek-api-key`). | `""` |
| `--env-file` | `-E` | Path to `.env` configuration file (defaults to `.env` if `-E` is passed without path). Automatically injects secrets into Secrets Manager and parameters into CloudFormation. | `""` |
| `--stack-name` | N/A | CloudFormation / SAM stack name. | `autonomous-secops-agent` |
| `--strands-url` | N/A | URL for external Strands Decider service or `embedded` for in-memory router. | `embedded` |
| `--global-view` | N/A | Scans all enabled AWS regions for running EC2 instances and EventStore tables. | `False` |
| `--skip-sam` | N/A | Executes pre-deploy remediation and generates receipts without invoking `sam deploy`. | `False` |
| `--yes` | N/A | Automatically proceeds with apply actions without interactive confirmation. | `False` |
| `--json-out` | N/A | Path to write machine-readable JSON audit report or deployment receipt. | `""` |
| `--env-out` | N/A | Path to generate sanitized environment variables configuration file. | `""` |

---

### Command Examples

#### 1. Full Multi-Region Read-Only Discovery
```bash
python3 scripts/aws_onboard.py --mode audit --region us-east-1 --global-view
```

#### 2. Brownfield Inspection on Existing EC2 Instance
```bash
python3 scripts/aws_onboard.py --mode audit \
    --region us-east-1 \
    --instance-id <TARGET_INSTANCE_ID> \
    --json-out audit_report.json
```

#### 3. Greenfield Deployment with Dedicated Target Server (`-T`)
```bash
python3 scripts/aws_onboard.py --mode apply \
    --region us-east-1 \
    -T \
    --deepseek-api-key "sk-proj-xxxx" \
    --yes
```

#### 4. Brownfield Governed Deployment (Adopt Existing Server & Bucket)
```bash
python3 scripts/aws_onboard.py --mode apply \
    --region eu-north-1 \
    --instance-id <TARGET_INSTANCE_ID> \
    --existing-bucket my-company-audit-logs \
    --deepseek-api-key "sk-proj-xxxx" \
    --yes
```

#### 5. Generate Pre-Deploy Remediation Receipts Without Deploying SAM
```bash
python3 scripts/aws_onboard.py --mode apply \
    --region us-east-1 \
    -T \
    --skip-sam \
    --env-out .env.onboarded
```
