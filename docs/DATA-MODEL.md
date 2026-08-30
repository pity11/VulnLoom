# 数据模型

## 1. 聚合关系

```text
Engagement
├── Scope (versioned)
├── Target*
│   ├── Signal*
│   ├── Candidate*
│   │   ├── ValidationRun*
│   │   └── EvidenceBundle*
│   └── Finding*
│       └── Report*
└── ApprovalRequest*
```

## 2. 核心对象

### Scope

```yaml
scope_id: uuid
version: integer
authority_reference: string
valid_from: datetime
valid_until: datetime
repositories: []
artifacts: []
network_targets: []
allowed_identities: []
allowed_test_classes: []
denied_actions: []
rate_limits: {}
approval_requirements: []
approved_by: string
```

### Artifact 与 Target Snapshot

```yaml
artifact:
  artifact_id: sha256
  engagement_id: uuid
  kind: source_archive | iac_bundle | git_repository | oci_image
  source_name: string
  source_ref: string
  original_size: integer
  detected_format: zip | tar | git | oci-manifest
  quarantine_ref: string | null

target_snapshot:
  target: Target
  artifact: Artifact
  manifest:
    manifest_id: sha256
    target_version: string
    files:
      - path: normalized/path
        size: integer
        sha256: string
        category: enum
    total_size: integer
  root_ref: string | null
```

Artifact 进入 quarantine 不代表它已在 Scope 内；只有名称、类型和 digest（或 Git URL 与 commit）匹配已批准 Scope 后，才可以生成 Target Snapshot。

### SourceGraph 与 StaticSignal

```yaml
source_graph:
  graph_id: sha256
  target_id: uuid
  target_version: string
  scope_id: uuid
  scope_version: integer
  manifest_id: sha256
  analyzer_version: string
  files_analyzed: []
  functions: []
  routes: []
  calls: []
  guards: []
  sinks: []
  flows: []
  signals: []
  parse_failures: []
```

`StaticSignal` 保存规则、位置、置信度和局限性，是静态假设而不是漏洞结论。Signal ID 与 Candidate 中的引用均为内容摘要。`SourceGraph` 绑定生成时的 Scope 身份和版本，不保存源码片段、凭据或完整工具输出，也不存在直接转成 `Finding` 的状态迁移。

### Candidate

```yaml
candidate_id: uuid
target_id: uuid
target_version: string
source_graph_id: sha256
scope_id: uuid
scope_version: integer
title: string
cwe: string
entry_point: SourceLocation
sink: SourceLocation
code_path: []
preconditions: []
security_invariant: string
hypothesis: string
signals: []
cheapest_disproof: string
duplicate_fingerprint: string
confidence: 0.0-1.0
state: enum
```

`CandidateSet` 是确定性的内容寻址产物，保存 Candidate 以及未提升 signal 的 ID。Candidate
必须绑定生成它的 Target、SourceGraph 和 Scope 版本；最便宜反证仅是后续验证规划输入，
不能触发工具调用或状态迁移。

### ValidationRun

```yaml
run_id: uuid
candidate_id: uuid
target_version: string
scope_version: integer
sandbox_image_digest: string
policy_digest: string
plan: []
started_at: datetime
finished_at: datetime
result: reproduced | not_reproduced | inconclusive | policy_stopped
side_effects: []
evidence_refs: []
resource_usage: {}
```

### SandboxProfile 与 SandboxRun

```yaml
sandbox_profile:
  kind: static | validation | report
  image_digest: sha256
  run_as_uid: non-root integer
  read_only_root: true
  no_new_privileges: true
  capabilities: []
  network_mode: none | target_only
  network_grants: []
  mounts: []
  allowed_tools: []
  execute_target_code: boolean
  max_attempts: 1-3
  limits: {}

sandbox_run_request:
  task: TaskEnvelope
  profile: SandboxProfile
  invocation: ToolInvocation
  environment: explicit secret-free map
  attempt: integer
  resume_from: RunnerCheckpoint | null
  idempotency_key: string
```

Task、Checkpoint 和 Run Result 均绑定 Profile 摘要；checkpoint 还绑定 Target、Scope、Policy
和 tool invocation 摘要。任何一个版本变化都必须从新任务开始，不能直接 resume。

### Tool Registry 与 BrokerCall

```yaml
tool_registration:
  tool_id: http.request
  version: string
  capability: http_request
  allowed_profiles: [validation]
  requires_network: true
  accepts_credential_ref: true
  side_effect_mode: conditional
  implementation_digest: sha256

broker_call:
  task: TaskEnvelope
  profile: SandboxProfile
  tool_id: http.request
  http:
    method: enum
    url: normalized credential-free URL
    test_class: string
    headers: safe non-secret headers
    credential_ref: sha256 | null
    body_ref: sha256 | null
    body_bytes: integer
    limits: {}
  idempotency_key: string
```

`BrokerResult` 不保存响应 body、原始 header 或 URL，只记录 URL digest、Policy decision、
实际 peer IP、Evidence ID 与预算使用量。Task 同时绑定 Policy、Sandbox Profile 和 Tool
Registry digest，任一变化都使 preflight fail-closed。

### Evidence

```yaml
evidence_id: sha256
kind: source | http | log | screenshot | test | policy
source_ref: string
captured_at: datetime
producer: string
target_version: string
redaction_policy: string
content_ref: string
summary: string
```

### Finding

```yaml
finding_id: uuid
candidate_id: uuid
root_cause: string
affected_versions: []
preconditions: []
impact: string
severity_assessment: {}
validation_runs: []
evidence_bundle_id: uuid
duplicate_family_id: uuid
state: verified | withdrawn | fixed
```

### CriticPlan 与 CriticReview

`CriticPlan` 以 SHA-256 绑定 Candidate、一个成功 Validation Run、Evidence Bundle、Scope 版本、验证上下文、独立审查上下文和固定 ruleset。四个必选反证角度分别是安全控制、路径可达性、环境一致性和版本绑定；确定结论必须引用完整性通过且 Target 版本一致的 Evidence。

`CriticReview` 保存确定性 verdict、plan/run/bundle 身份、独立上下文、ruleset digest 和已确认的 counterevidence refs。它不携带工具权限，不能自行创建 Finding；`INCONCLUSIVE` 不推进 Candidate，`REJECTED` 关闭 Candidate，只有 `ACCEPTED` 才允许进入后续 Finding 门禁。

### Report

```yaml
report_id: uuid
finding_id: uuid
channel: generic | edusrc | cnvd | vendor | cve-draft
version: integer
title: string
summary: string
reproduction: []
impact: string
remediation: string
evidence_refs: []
redaction_status: passed | failed
review_status: draft | changes_requested | rejected | human_approved | exported | submitted
```

M5.2 的 `ReportDraftPlan` 额外绑定 Finding/Candidate/EvidenceBundle 内容摘要、Scope 身份与版本、渠道、截止时间和逐节引用。`Report.sections` 明确区分 summary、code location、request/response、reproduction、impact 和 remediation；除摘要与修复建议外的事实性章节必须引用 Finding Bundle 内的 Evidence ID。新建 Report 的确定性 UUID 来自 plan digest，并且只能以 `draft`/`passed` 状态落盘。

M5.3 增加稳定的 `report_family_id`、连续 version/previous digest、`ReportDiff`、`ReportReviewPlan`、`ReportReviewCommand`、`ReportReviewRecord` 与 `ReportExportPlan`。批准记录同时绑定被审阅的 draft digest 和状态变化后的 digest，并设置明确过期时间；`EXPORTED` 只能由仍有效的 `HUMAN_APPROVED` 记录产生。不存在到 `SUBMITTED` 的领域转换。

### Benchmark

`BenchmarkSuite` 封存本地 case、Target version 与 ground-truth Finding identity；
`BenchmarkObservationSet` 记录 Candidate/Finding 身份、duplicate fingerprint、Validation/Critic
结果、Evidence 计数、策略违规、时间和成本。Observation 模型禁止未复现、未通过 Critic、未晋升或
Evidence 不完整的 Candidate 携带 Finding identity。

`BenchmarkPlan` 绑定 suite/observation 的完整摘要、回归策略、可选 `BenchmarkBaseline`、截止时间和
幂等键。`BenchmarkResult` 保存确定性指标、`passed|failed` 门禁和稳定 violation code；
`BenchmarkArtifact` 只引用本地内容寻址 JSON/Markdown。Baseline 自身内容寻址并绑定 exact suite，
不能跨数据集比较。

## 3. 领域事件

- `ScopeApproved`
- `TargetIngested`
- `SignalObserved`
- `CandidateProposed`
- `CandidateRejected`
- `ValidationPlanned`
- `ApprovalGranted`
- `ValidationStarted`
- `EvidenceCaptured`
- `ValidationCompleted`
- `CandidateMarkedDuplicate`
- `FindingVerified`
- `ReportDrafted`
- `ReportApproved`
- `ReportExported`

事件只记录已经发生的领域事实。模型的自然语言输出先经过 schema 校验和命令处理，不能直接写事件流。

## 4. 不变量

- 一个 Finding 必须属于一个 Candidate。
- 一个 Finding 至少引用一个成功 Validation Run。
- Validation Run 的 Scope 和 Target 版本不可为空。
- Report 只能引用 Finding 已批准的 Evidence Bundle。
- Submission 必须引用未过期 ApprovalRequest。
- 相同 `duplicate_fingerprint` 的 Finding 必须先进行人工根因确认。
