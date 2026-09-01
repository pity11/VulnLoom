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

### ExternalBenchmarkSnapshot

`ExternalBenchmarkSnapshot` 绑定 benchmark kind、上游完整 revision、SPDX license 声明以及按路径排序的
`SnapshotFile(path,size,sha256)`。`ExternalBenchmarkImportPlan` 再绑定 snapshot 完整摘要、adapter
ID/digest、资源限制、deadline 和幂等键。`ExternalCaseExclusion` 只允许安全 source ref 与稳定 reason
code，不保存上游 task、flag、prompt、报告或 exploit 内容。

`ExternalBenchmarkImportOutcome` 包含规范化 `BenchmarkSuite`、exclusion 列表与只读 suite artifact。
Suite source 明确区分 `local_fixture`、`bountybench_snapshot` 和 `autopenbench_snapshot`；所有外部 case
都绑定 snapshot revision 或上游 vulnerable version。

### AnalyzerObservationSet

`AnalyzerResultSnapshot` 绑定 analyzer kind、Target/版本、工具版本、规则摘要、预计算输出文件的大小与
SHA-256，以及可选 CWE sidecar。`AnalyzerImportPlan` 绑定 snapshot/adapter 完整摘要、资源上限、deadline
和幂等键。

`AnalyzerObservation` 只保存 analyzer、Target 绑定、规则 ID 摘要、规则版本指纹、规范化 CWE、严重度、
消息摘要和安全相对位置。`AnalyzerExclusion` 只保存 source ref 摘要与 reason code。原始工具消息、Secret
match、资源对象名称和规则文本不进入模型。

`AnalyzerObservationSet` 与 `BenchmarkObservationSet` 是不同协议：前者只是静态工具命中的规范化投影，
没有 Candidate/Finding/Validation/Critic/Evidence 字段，不能表示或触发领域状态变化。

### AnalyzerToolRegistration 与 AnalyzerExecutionPlan

`AnalyzerToolRegistration` 内容寻址绑定 analyzer/tool 版本、exact image ID、规则与 adapter 摘要、固定绝对
入口、完整 argv、显式安全环境和固定输出模式。execution mode 只允许 `source_only` 或 CodeQL 的
`prebuilt_database_query_only`；两者都不能表示 Target build。

`AnalyzerExecutionPlan` 再绑定 Target Snapshot/Manifest 摘要、Scope 版本、Registration/Registry 摘要、
静态 `SandboxRunRequest`、deadline 和幂等键。`OfflineAnalyzerExecutionOutcome` 只保存 Runner 生命周期和
清理证明，成功值是 `protocol_completed`，且 `analyzer_result_snapshot` 类型固定为 null；它不能冒充 M6.3a
的预计算结果，也没有 Observation、Candidate、Validation、Critic、Finding 或 Report 字段。

`TrivyDatabaseSnapshot` 内容寻址绑定 Trivy 0.73.0、DB schema v2、精确的
`db/metadata.json`/`db/trivy.db` 文件清单、大小和 SHA-256。真实 Trivy Registration 必须引用该对象，
并令 `rules_digest` 等于 DB snapshot ID；Task/Profile 还必须以同一 ID 绑定只读 `analyzer-data` 挂载。
它不包含 URL、registry、下载命令、credential 或运行时追加参数。

`CodeQLSnapshot` 内容寻址绑定 CodeQL 2.26.2、Target/version/Manifest、database language、query pack、
suite、预编译 `.qlx`、全部文件大小/SHA-256 和总大小。它拒绝旧 `database/results`、空目录、路径碰撞、
symlink、特殊文件、可写 entry 与资源超限。真实 Registration 的 `rules_digest`、Task input 和只读
`analyzer-data` mount 必须使用同一 snapshot ID；可写数据库只存在于 Runner 有界 tmpfs 的临时副本。

### AnalyzerTruthAlignment 与 AnalyzerEvaluation

`AnalyzerCaseBinding` 将 benchmark case 精确绑定到一个 analyzer 的 ObservationSet 完整摘要；同一
case/analyzer 只能绑定一个 set。`AnalyzerTruthMatch` 显式列出 Observation、truth 和双方共有的 CWE。
`AnalyzerTruthAlignment` 封存 suite 摘要、固定 ruleset、provenance、producer、全部 binding/match，且禁止
一个 Observation 匹配多个 truth。

`AnalyzerEvaluationMetrics` 保存总体计数与比率，并包含按 analyzer 排序的 `AnalyzerMetricSlice`。
`AnalyzerEvaluationBaseline` 绑定 exact suite；`AnalyzerEvaluationPlan` 再绑定 alignment、policy、limits、
baseline、deadline 和幂等键。`AnalyzerEvaluationResult` 使用 plan 派生的稳定 UUID，gate 状态必须与
violation 列表一致；artifact 只引用本地内容寻址 JSON/Markdown。

### AnalyzerExecutionEvidenceBinding 与 AnalyzerQualificationPlan

`AnalyzerExecutionEvidenceBinding` 封存一个 benchmark case/analyzer cell 的 execution plan、exact
registration、Docker outcome、ObservationSet、Target/version/Manifest 与 Scope version 摘要。只有
`COMPLETED`、清理完备且已完成 M6.3a import 的 outcome 可以创建 binding。

`AnalyzerQualificationPlan` 绑定 exact suite/alignment/evaluation plan、显式 required analyzers 和排序后的
完整执行矩阵。`AnalyzerQualificationOutcome` 只包装既有 M6.3b evaluation outcome、执行数和一致的 gate
状态；同一 case 的所有 cell 必须共享 Target ID/version、Manifest 与 Scope ID/version。它不包含新的工具
调用、Observation 变换或领域状态迁移。

### AgentModelRegistration、AgentRunPlan 与 AgentRunOutcome

`AgentModelRegistration` 是 provider/model/adapter 实现、支持 Worker role 和输出上限的内容摘要；M7.1a
的 adapter kind 固定为 `offline_replay`，对象没有 endpoint 或 credential 字段。`AgentRunPlan` 绑定完整
`TaskEnvelope` 及其摘要、registration 摘要、输入引用摘要、固定 decision schema、步数/token/墙钟预算、
deadline 与幂等键。

`AgentStepRequest` 只包含 plan/task ID、role、上下文摘要、Task 工具白名单和剩余预算。模型临时响应只有在
通过 `AgentDecisionPayload` 后才能形成 `AgentRunOutcome`。工具提案被归一为 `AgentToolIntent`：保存 tool ID、
完整 invocation 摘要、逐参数摘要和逻辑工作目录，不保存原始参数，也不表示工具已经执行。终态 outcome 只
保存摘要、稳定错误码、预算使用与逻辑清理证明；原始模型输出不属于持久化数据模型。

### ModelCredentialReference 与 ModelCredentialLease

`ModelCredentialReference` 是一个环境变量名称及其内容摘要，不是 credential。它可以存在于 Control Plane
provider 配置和 local-fake registration 绑定中，但不会进入 Worker request。`ModelCredentialLease` 不是
Pydantic/JSON 对象，只在可信 adapter 的一次调用作用域内持有 UTF-8 字节；关闭后缓冲区归零且不可再次读取。
原始 credential、lease 和 local-fake turn 都不属于 checkpoint 或领域事件数据模型。

### AgentContextFragment 与 AgentContextSnapshot

`AgentContextSource` 只存在于 assembler 调用栈，不是 schema/存储对象。`AgentContextFragment` 保存 ordinal、
source ref 摘要、source kind、脱敏文本、文本摘要、UTF-8 字节数和固定 `untrusted=true`。它不能携带权限、
Approval、工具参数或原始 Evidence 身份。

`AgentContextSnapshot` 内容寻址绑定 Task 摘要、Target/version、Scope/version、完整有序 input-ref 摘要、
redaction policy、fragment 列表、总字节和装配时间。`AgentRunPlan.context_snapshot_id` 可进一步绑定该对象，
此时 `context_digest` 必须等于 snapshot ID；StepRequest 仍只复制摘要。

### AgentPromptTemplateRegistration 与 AgentMessageEnvelope

`AgentPromptTemplateRegistration` 只表达 `builtin-v1`、Worker role 和可信 system message 摘要。
`AgentProviderMessage` 保存 role、正文、摘要、UTF-8 字节数和 untrusted-context 标记；system 固定为 trusted，
user 固定包含 untrusted context。

`AgentMessageEnvelope` 内容寻址绑定 plan/task/task digest、step、role、context snapshot、Target/Scope 摘要、
model registration、template、decision schema、工具白名单、tool-call/output 预算、消息和总字节。
`AgentStepRequest.message_envelope_id` 只保存 envelope 摘要；消息正文不属于运行 checkpoint/outcome。

### AgentProviderTransportAdmission、Request、Attempt 与 Receipt

`AgentProviderTransportAdmission` 内容寻址绑定 provider、canonical hostname、TLS 443、单一路径、credential
reference、adapter digest 和传输上限。M7.4 只允许 `admission_fake`，且固定无网络、无 redirect/proxy、要求
DNS revalidation、不持久化 raw response、attempt limit 为一。

`AgentProviderTransportRequest` 绑定 exact StepRequest、Message Envelope、admission、model registration 与
credential reference，并只保存瞬时请求 body 的 SHA-256、字节数、响应上限和 timeout。它没有 header、token、
正文或可执行 endpoint。`AgentProviderTransportAttempt` 保存终态、稳定错误码、捕获字节数和 request/response/
credential 清理证明；`AgentProviderTransportReceipt` 仅在成功时保存响应摘要、identity、token 计数和 latency。
原始请求、credential lease、raw response 与 fake turn 都不是持久化数据模型。

M7.5 扩展同一 Admission 为互斥的 `live_https` 和 `loopback_https_probe` mode，并增加 IP policy、CA bundle
摘要、process-isolation 标记、TLS minimum 和每分钟请求上限。`AgentModelRegistration` 的
`subprocess_https_provider` kind 必须绑定 exact admission 与 credential reference。

网络 attempt 只额外保存 `peer_ip_digest`、`tls_version`、process started/terminated、stderr discarded 与
network-proof 标记；不保存 hostname、numeric IP、证书、Authorization header 或响应正文。
`ProviderProcessResult`、stdin frame、CA bytes、credential view 和 child response buffer 都是瞬时对象，不是
Pydantic schema、checkpoint、领域事件或普通日志。

### AgentProviderEgressIssuerPolicy、Grant 与 Revocation

M7.6 的 issuer policy 内容寻址绑定本地受信签发者、允许的 provider/mode 与最长生命周期。
`AgentProviderEgressGrant` 绑定 exact transport Admission、credential reference、adapter、用途、issuer policy、
签发/过期时间和幂等键；`AgentModelRegistration.egress_grant_id` 对 live adapter 必填，对所有 offline/fake
adapter 禁止。

Grant 与 `AgentProviderEgressRevocation` 是只读内容寻址对象。SQLite ledger 只保存对象 ID、Admission ID、
幂等键、STARTED/COMPLETED 和 active/revoked 状态，不保存 hostname、credential、消息或响应。`expired` 由 grant
的不可变时间窗在读取时计算；任何未决 revocation 会让 active 读取 fail-closed。

### AgentProviderCodecRegistration

M7.7 的 codec registration 内容寻址绑定 provider、`openai-responses-v1` protocol、exact
`/v1/responses` path、固定 implementation/decision-schema digest 和 codec byte/wall limits，并将
streaming、storage、provider tools 与 arbitrary parameters 固定为 false。
`AgentModelRegistration.provider_codec_id` 对 subprocess HTTPS adapter 必填，对 offline/fake adapter 禁止。
codec registration 不包含 endpoint hostname、credential、消息、响应或可执行代码。

wire request/response 都是瞬时可归零缓冲，不进入 Pydantic checkpoint schema。解码后只产生既有
`AgentModelReply`：typed structured output、provider/model identity、token counts 与 latency；response ID、
provider message ID、raw text、annotation、refusal 和 provider-native tool call 都不持久化。

### AgentToolHandoffPlan、Outcome 与 Observation

M7.8 的 handoff plan 内容寻址封存完整 `AgentRunPlan`、权威 Agent outcome 摘要、exact `BrokerCall` 与摘要、
call commitment、预期 intent invocation 摘要、固定最多两次 attempt、前序 handoff、deadline 和幂等键。
attempt 1 不得有前序；attempt 2 必须由 store 证明唯一前序为 completed `approval_required`。

handoff checkpoint 只保存 handoff/Agent outcome ID、attempt、前序、状态、时间和 typed outcome，不保存 plan、
Broker URL、Agent commitment 原文或响应正文。`AgentToolHandoffOutcome` 包含现有 digest-only `BrokerResult`、
明确终态与 cleanup；只有 completed 才允许且必须携带一个 `AgentToolObservation`。

`AgentToolObservation` 内容寻址绑定 handoff、Task/Target/version、Scope、tool、Broker result 摘要、HTTP 状态、
final URL 摘要、response byte/body SHA-256 和排序去重的 Evidence refs。它没有 URL、header、credential、body、
Agent 原始参数、Candidate/Finding 字段或状态转换能力。

### AgentContinuationPlan、BudgetLedger 与 Outcome

M7.9 的 `AgentContinuationPlan` 内容寻址绑定 root `AgentRunPlan`/tool-proposed outcome、completed
`AgentToolHandoffOutcome`、exact `AgentToolObservation`、派生 continuation `AgentRunPlan`、只读 context
snapshot 和累计 `AgentContinuationBudgetLedger`。派生 Task 使用新 identity，但 engagement、Target/version、
Scope/version、Policy/Profile/Registry、Validator role、model registration 与绝对 deadline 必须继承；input refs
固定来自 Observation/Evidence，allowed tools 为空且 tool-call budget 为零。

budget ledger 保存原始/已用/剩余 model tokens、已用 Agent steps、Broker tool calls 和剩余 wall seconds，不保存
prompt、Evidence 或 provider 内容。SQLite continuation checkpoint 只保存 continuation/root/Observation/child-run
ID、幂等键、状态、时间和 typed outcome；Observation ID 与 child plan ID 均唯一，防止同一工具结果被并发或
重复消费。

`AgentContinuationOutcome` 只能映射 child Agent run 的 completed、blocked、failed 或 timed-out 状态，且不允许
tool intent。cleanup 显式证明 Evidence 临时缓冲释放、context 复核、raw provider response 缺失、未执行工具和
未改变 VulnLoom 领域状态。

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
