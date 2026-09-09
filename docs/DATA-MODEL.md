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

### OpenAIChatCompletionsFeatureGate 与 OpenAIChatCompletionsCodecRegistration

P1 的通用 Chat Completions codec 使用独立、内容寻址的功能开关；未显式启用时构造 codec 即拒绝。
registration 绑定 Provider ID、固定 `/v1/chat/completions`、请求模型、允许的响应模型别名、实现摘要、
Agent decision schema、字节/时间限制，以及逐层审核过的空扩展字段。stream、原生 tool call 和任意请求参数
固定关闭。Provider 返回的 content 必须是严格 JSON `AgentDecisionPayload`；其中 tool proposal 仍只是无权限的
类型化建议，不能越过 Broker、Scope 或 Approval Gate 执行。

响应必须是单个 `stop` assistant choice，模型身份在 allowlist 中，usage 为相加一致的有界非负整数。
未知字段、非空兼容扩展、refusal、Provider 原生 tools、重复 JSON key、身份漂移、usage 漂移、超时或超限均
fail-closed。wire request/response 仍是瞬时可归零缓冲，codec 不持有 endpoint 或 secret。

### CucChatCompatibilityBaseline

P1 迁移基线内容寻址固定已验收 CUC PONG 与固定 JSON 探针的 codec ID、实现摘要、固定请求摘要、允许的响应
模型、PONG 完成摘要、已接受的内容分类和失败语义。`assert_current()` 对当前旧路径重新计算这些身份；任何
未伴随显式新基线的变化都会拒绝迁移。该对象不保存网关、凭据、响应正文或性能值，也不把旧探针与通用
Agent response 误当成相同业务输出。

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

### AgentSessionPlan、AuthorizedCallSet 与 SessionBudgetLedger

M7.10 的 `AgentSessionPlan` 内容寻址绑定已完成的首个 Agent/handoff/Observation 链、第二轮 context snapshot、
派生 `AgentRunPlan`、`AgentAuthorizedCallSet`、累计预算、固定轮次上限、绝对 deadline 和幂等键。派生 Task
继承 exact engagement、Target/version、Scope/version、Policy/Profile/Registry/model，且只保留一个 tool-call
budget。

`AgentAuthorizedCallSet` 最多包含八个排序去重的 opaque commitment；每项都封存控制面预构造的 exact read-only
`BrokerCall`，并绑定派生 Task 摘要。commitment 进入可信 message control，但完整 URL/HTTP 参数不进入 Session
checkpoint 或模型生成字段。

`AgentSessionBudgetLedger` 累计原始/已用/剩余 model token、Agent step、tool call、provider attempt、Broker
attempt 和 wall time。总成功 tool call 固定不超过二；Approval-required 的显式 attempt-2 retry 作为额外 Broker
attempt 计数。SQLite Session 状态为 started、waiting-approval、resuming 或 completed；遗留 started/resuming
拒绝自动恢复。typed outcome 只保存摘要、计数、handoff/continuation outcome 与 cleanup proof，不保存 Evidence
正文、URL、credential、provider raw response 或领域状态命令。

### AgentSessionAuditPlan、AuditBundle 与 Recommendation

M7.11 的 `AgentSessionAuditPlan` 只保存 Session plan/outcome 摘要、Target/Scope 绑定、资源上限、deadline 与
幂等键，不嵌入可能含 URL 的 Session Plan。执行时由可信服务接收瞬时 Session Plan，并从 Session、Agent run、
handoff、continuation 与 Evidence store 逐项重读权威对象；随后重算 round 顺序、call commitment、Approval
decision digest、预算单调性、deadline 与 cleanup 链。

`AgentSessionAuditBundle` 只保存上述对象的 ID/摘要、排序 Observation/Evidence refs、typed budget/cleanup 和
确定性 recommendation。recommendation 只能是 completed、blocked、failed 或 timed-out 及固定 reason code，
没有 Candidate/Finding/Report 字段或领域命令。JSON/Markdown artifact 内容寻址且只读，不复制 Evidence 正文、
URL、credential、provider request/response 或工具参数。独立 SQLite 只保存 plan/outcome 与摘要化 bundle；遗留
STARTED 拒绝自动重放。

### AgentValidationIntakePlan、Command 与 Record

M8.1 的 `AgentValidationIntakePlan` 只保存 M7.11 Audit Bundle/artifact/recommendation、CandidateSet/Candidate、
Target/version、Scope/version 与一个由可信控制面独立构造的完整 `ValidationPlan` 的 ID 和摘要。完整
`ValidationPlan` 是瞬时 typed 输入；Agent summary、tool intent、Evidence 正文不能进入或派生 Runner request、
BrokerCall、URL、HTTP 参数、credential、assertion 或 Approval。

`AgentValidationIntakeCommand` 只允许人工 `accept|reject|defer`，并以固定 reason code、reviewer、decision time
绑定 exact Intake/Audit/Candidate/ValidationPlan。`AgentValidationIntakeRecord` 是同一绑定的不可变、digest-only
决定；accepted 不代表已执行、已批准副作用或已改变 Candidate。SQLite checkpoint 只保存摘要、稳定决定、
reason code 和 reviewer，不保存 Agent prose、Evidence 正文、URL、credential 或工具参数。

### AgentValidationOutcomeBindingPlan 与 Binding

M8.2 的 `AgentValidationOutcomeBindingPlan` 只保存 accepted Intake Record、Audit Bundle、CandidateSet/Candidate、
Target/version、Scope/version、exact ValidationPlan、已完成 ValidationOutcome/ValidationRun、typed result 与排序
Evidence refs 的 ID 和摘要。完整 ValidationPlan 与 ValidationOutcome 仍是瞬时 typed 输入，并从各自权威 store
重读；Binding plan 不包含 Runner/Broker request、URL、HTTP body、credential、Approval 或 Evidence 正文。

`AgentValidationOutcomeBinding` 保存同一来源链的摘要、最终 Candidate 状态/摘要、ValidationRun ID、可选
EvidenceBundle ID/摘要和完成时间。`reproduced` 必须对应 `VALIDATED`，其余结果必须对应 `INCONCLUSIVE`；这只是
已发生 Validation 的不可变来源证明，不会迁移权威 CandidateSet 中仍为 `PROPOSED` 的原始 Candidate。独立
SQLite checkpoint 唯一消费 Intake Record、ValidationPlan 和 outcome digest，并只保存 digest-only binding；
遗留 STARTED、重复消费或冲突 key 不会触发 Validation 重放。

### AgentCriticIntakePlan、Command 与 Record

M8.3 的 `AgentCriticIntakePlan` 内容寻址绑定 M8.2 binding、Audit Bundle、原始 `PROPOSED` Candidate、完成后的
`VALIDATED` Candidate、reproduced ValidationRun、EvidenceBundle、Scope/version 与 exact `CriticPlan` 摘要。
完整 Validation outcome、CriticPlan 和 artifact 是瞬时 typed 输入；持久化计划不包含 Evidence 正文、Agent
prose、Runner/Broker 参数、URL、credential 或 Approval。

`AgentCriticIntakeCommand` 只允许人工 `accept|reject|defer`，绑定 exact binding/Candidate/CriticPlan、reviewer
和 decision time。`AgentCriticIntakeRecord` 只记录 digest、typed decision、稳定 reason code 和 expiry；accepted
不表示 Critic 已执行或 Candidate 已迁移。独立 SQLite 唯一消费 binding 与 CriticPlan，遗留 STARTED 不会重放
Critic。

### AgentCriticOutcomeBindingPlan 与 Binding

M8.4 的 `AgentCriticOutcomeBindingPlan` 内容寻址绑定 accepted M8.3 record、M8.2 outcome binding、完成后的
ValidationRun/EvidenceBundle、exact CriticPlan、CriticOutcome/CriticReview、typed verdict、最终 Candidate state
及全部摘要。计划不携带 assessment prose、Evidence 正文、Runner/Broker 参数、URL、credential 或 Approval。

`AgentCriticOutcomeBinding` 是同一来源链的 digest-only 完成事实。模型强制 verdict/终态映射：`accepted` 只能
对应 `CRITIC_REVIEWED`，`rejected` 只能对应 `REJECTED`，`inconclusive` 只能保持 `VALIDATED`。独立 SQLite
唯一消费 Intake record、CriticPlan 和 Critic outcome digest；它不会执行 Critic、修改 CandidateSet 中的原始
`PROPOSED` Candidate，或产生 Finding/Report/Submission。

### FindingDuplicateCheck、FindingPromotionPlan 与 AgentFindingIntake

M8.5 的 `FindingDuplicateCheck` 内容寻址绑定 Candidate/Target/Scope、typed `clear|duplicate` 结果、可选 duplicate
family、reviewer 与有效期；权威 store 只允许唯一最新的 `clear` 且无 duplicate family 证明进入晋升 Intake，
任何更晚检查都会使旧 clear 失效。

`FindingPromotionPlan` 是可信控制面构造的完整瞬时 typed 对象，绑定 accepted M8.4 binding、
`CRITIC_REVIEWED` Candidate、reproduced ValidationRun、EvidenceBundle、accepted CriticReview、duplicate proof、
预分配 Finding ID，以及 root cause、affected versions、impact 和 severity assessment。其内容摘要密封后，Agent
文本不能补充或修改字段。

`AgentFindingIntakePlan/Command/Record` 只持久化上述对象的 ID/摘要、人工 `accept|reject|defer`、reviewer、
时间和 Scope。accepted record 不代表 Candidate 已 `PROMOTED` 或 Finding 已存在；SQLite 不保存 PromotionPlan
正文，并唯一消费 Critic binding、promotion、duplicate proof、Finding ID 与 command。

### FindingPromotionApprovalAction、ExecutionPlan 与 Outcome

M8.6 的 `FindingPromotionApprovalAction` 是内容寻址的本地状态变更描述，绑定 accepted Intake record、
PromotionPlan、`CRITIC_REVIEWED` Candidate、预分配 Finding ID、Engagement/Target/Scope 和固定的两个效果。
对应 `ApprovalRequest` 必须是人工 granted 的 `MUTATE_TARGET_STATE`，且 action digest、target、policy version、
效果、决定人、决定时间和有效期全部匹配。

`FindingPromotionExecutionPlan` 只保存上述对象与 Approval 的 ID/摘要、执行窗口和幂等键，不保存 Approval
摘要正文、Agent 输出、工具参数或网络位置。`FindingPromotionOutcome` 原子绑定输入 Candidate 摘要、不可变的
`PROMOTED` Candidate 和 `verified` Finding；Finding 继续引用 reproduced ValidationRun 与 EvidenceBundle。
独立 SQLite 唯一消费 Intake、PromotionPlan、Finding ID 和 Approval，同一 completed plan 只读幂等返回，
冲突或遗留 STARTED 不会自动重新执行。

### AgentReportIntakePlan、Command 与 Record

M8.7 的 `AgentReportIntakePlan` 内容寻址绑定 completed `FindingPromotionOutcome`、promoted Candidate、
verified Finding、EvidenceBundle，以及 exact `ReportDraftPlan` 的 ID/摘要、report family、channel、Scope
和人工决策窗口。它不包含报告 title、sections、text 或 Evidence 正文。

`AgentReportIntakeCommand` 只允许人工 `accept|reject|defer`，并精确绑定 promotion outcome、draft plan、
report family、Finding、reviewer 与 decision time。`AgentReportIntakeRecord` 保存同一来源链的摘要和 typed
决定；accepted 不表示 Report 已生成、审阅、批准、导出或提交。独立 SQLite 唯一消费 ReportDraftPlan、
report family 与 command，遗留 STARTED 不会调用报告服务或自动恢复。

### AgentReportDraftExecutionPlan 与 OutcomeBinding

M8.8 的 `AgentReportDraftExecutionPlan` 内容寻址绑定 accepted M8.7 record、M8.6 promotion
execution/outcome、exact `ReportDraftPlan`、有序 typed Evidence catalog 的摘要、report family/version、
Finding、Candidate、EvidenceBundle、channel、Scope 和执行窗口。它不包含 title、sections、text、Agent
输出、Runner/Broker 参数、URL、credential、Approval 或 Submission 字段。

`AgentReportDraftOutcomeBinding` 绑定 completed `ReportOutcome`、本地 immutable artifact、Report、
Finding、Candidate、EvidenceBundle 和原 draft plan 的摘要，并强制 `review_status=DRAFT`。独立 SQLite
唯一消费 Intake record 与 ReportDraftPlan，只保存 digest-only binding；完整脱敏正文只存在既有
Report artifact/store 边界。completed replay 不重新 drafting，冲突、预存在未绑定 draft 或遗留 STARTED
不会自动恢复，也不会批准、导出或提交报告。

### AgentReportReviewIntakePlan、Command 与 Record

M8.9 的 `AgentReportReviewIntakePlan` 内容寻址绑定 completed M8.8 execution/binding、`ReportOutcome`、
仍为 `DRAFT` 的 Report、immutable artifact、EvidenceBundle、与 drafting 相同的有序 typed Evidence
catalog、exact `ReportReviewPlan`、Scope 和人工决策窗口。持久化计划不含报告正文、Evidence 正文、
Agent 输出、工具参数、Approval 或 Submission。

`AgentReportReviewIntakeCommand` 只表示人工 `accept|reject|defer` 是否进入后续 review，并绑定 exact
M8.8 binding、Report、ReviewPlan、reviewer 与 decision time。`AgentReportReviewIntakeRecord` 保存同一
来源链的摘要和 typed 决定；accepted 不等于 `HUMAN_APPROVED`，Report 仍为 `DRAFT`。独立 SQLite
唯一消费 draft binding、Report、ReviewPlan 与 command，遗留 STARTED 不会调用 review service。

### ReportReviewApprovalAction、ExecutionPlan 与 OutcomeBinding

M8.10 的 `ReportReviewApprovalAction` 内容寻址绑定 accepted M8.9 record、exact `ReportReviewPlan`、
独立人工 `ReportReviewCommand`、DRAFT Report/artifact、Scope、typed decision 与唯一效果。对应
`ApprovalRequest` 必须是人工 granted 的 `REVIEW_REPORT`，且 action digest、policy version、效果、
决定人、决定时间和有效期全部匹配。

`AgentReportReviewExecutionPlan` 只保存上述对象和 Approval 的 ID/摘要、执行窗口与幂等键，不保存
报告正文、review rationale、Approval 摘要、Agent 输出或工具参数。`AgentReportReviewOutcomeBinding`
绑定 authoritative `ReportReviewOutcome`、来源 DRAFT、resulting Report/artifact、review record、typed
decision/status 与 Approval 摘要；完整 Report 只在既有 review store/artifact 中持久化。

独立 SQLite 唯一消费 Intake、ReviewPlan、ReviewCommand、Report 和 Approval；completed replay 只读，
预存在未绑定 review、冲突或遗留 STARTED 不会自动执行。该绑定不表示 Report 已导出或提交。

### AgentReportExportIntakePlan、Command 与 Record

M8.11 的 `AgentReportExportIntakePlan` 内容寻址绑定 completed M8.10 execution/binding、权威
`ReportReviewOutcome`、`HUMAN_APPROVED` Report、immutable artifact、approve review record、Scope 和
可信控制面构造的 exact `ReportExportPlan`。它不含报告正文、review rationale、路径、URL、Agent 输出、
工具参数、Approval 或 Submission。

`AgentReportExportIntakeCommand` 只表示人工 `accept|reject|defer` 是否进入后续本地 export，并绑定
exact M8.10 binding、Report、ExportPlan、reviewer 与 decision time。`AgentReportExportIntakeRecord`
保存同一来源链的摘要和 typed 决定；accepted 不等于 Report 已 `EXPORTED`，也不构成 Submission 授权。
独立 SQLite 唯一消费 review binding、Report、ExportPlan 与 command，遗留 STARTED 不会调用 exporter
或自动恢复。

### ReportExportApprovalAction、ExecutionPlan 与 OutcomeBinding

M8.12 的 `ReportExportApprovalAction` 内容寻址绑定 accepted M8.11 record、completed M8.10 binding、
exact `ReportExportPlan`、`HUMAN_APPROVED` Report/artifact、approve review、Scope 和固定的本地 Report/
artifact 效果。对应 `ApprovalRequest` 必须是人工 granted 的 `EXPORT_REPORT`，且 action digest、policy
version、效果、决定人、决定时间和有效期全部匹配。

`AgentReportExportExecutionPlan` 只保存上述对象与 Approval 的 ID/摘要、执行窗口和幂等键，不保存
报告正文、review rationale、Approval 摘要、路径、URL、Agent 输出或工具参数。
`AgentReportExportOutcomeBinding` 绑定 authoritative `ReportExportOutcome`、来源 `HUMAN_APPROVED`
Report、完成后的 `EXPORTED` Report/artifact、review 与 Approval 摘要；完整 Report 只存在既有本地
artifact/export store 边界。

独立 SQLite 唯一消费 Intake、ExportPlan、Report 与 Approval；completed replay 只读，预存在未绑定
export、冲突、写入失败或遗留 STARTED 不会自动执行。该绑定不是 Submission，也不包含外部目的地。

### AgentWorkflowRegressionObservation、Plan 与 Outcome

M9.1 的 `AgentWorkflowRegressionObservation` 内容寻址保存固定 M7.11–M8.12 十三个阶段的有序
`AgentWorkflowCheckpoint` 摘要、Evidence refs、六个人工 Intake record 摘要、三个精确 Approval 摘要、
Validation/Critic/Candidate/Report typed 状态、M8.2 与 M8.12 两个副作用计数快照，以及最终本地 artifact
摘要。它不保存 Agent prose、报告正文、Evidence 正文、URL、路径、凭据或 Runner/Broker 参数。

`AgentWorkflowRegressionPolicy` 固定完整阶段顺序、人工门禁数量与零副作用增量；公网访问、Target 构建、
自动 Approval 和 Submission 的上限不可放宽。`AgentWorkflowRegressionPlan` 绑定 exact observation 摘要、
policy、执行窗口和幂等键。

纯 evaluator 生成 `AgentWorkflowRegressionMetrics` 和稳定的 typed violation code；
`AgentWorkflowRegressionResult` 只表示资格 PASS/FAIL，不改变任何领域状态。独立 SQLite 保存
STARTED/COMPLETED checkpoint，结果以内容寻址、大小受限、no-follow 复核的 JSON/Markdown artifact
持久化，遗留 STARTED 不会自动重放。

### AgentWorkflowRegressionCorpus 与 ScenarioResult

M9.2 的 `AgentWorkflowRegressionCorpus` 内容寻址绑定 M9.1 base observation、固定安全 policy 和完整
`AgentWorkflowMutation` 序列。`AgentWorkflowRegressionScenario` 的 mutation、预期 gate status 与 exact
ordered violation codes 共同内容寻址；预期由 contract 固定，不能通过 fixture 修改。

`AgentWorkflowRegressionScenarioResult` 保存 mutation 的实际 status、实际 violation codes 和是否匹配；
`AgentWorkflowRegressionCorpusResult` 绑定 corpus、场景总数、匹配数、逐场景结果和总体 PASS/FAIL。结果
只有在全部 23 个场景匹配时才为 PASS，不是 Approval、领域事件或生产状态。

### LocalSourceSuite、ObservationSet 与 QualityResult

M9.3 的 `LocalSourceSuite` 内容寻址绑定固定案例、相对 Python 文件路径与 SHA-256、预期 CWE 多重集；
路径只允许规范化的非绝对 `.py` 文件。`LocalSourceObservationSet` 绑定 exact suite，并为每个案例保存
Target version、SourceGraph/CandidateSet 摘要和最小 `LocalCandidateObservation`。观察只含 Candidate ID、
CWE、重复指纹、signal IDs、entry/sink 相对位置与 code-path 节点数，不含源码正文、Agent prose、URL、
凭据、HTTP 内容或 Runner/Broker 参数。

`LocalSourceEffectCounters` 显式记录 Runner、Broker、provider、Target 进程、公网、构建、自动 Approval
与 Submission；门禁要求全部为零。`LocalSourceQualityPolicy` 除静态 recall/precision/trace 阈值外，
还绑定一个 exact M6.1 `BenchmarkBaseline` identity。`LocalSourceQualityResult` 联合静态指标与该 baseline
中已通过完整工作流约束的 Finding precision/Evidence completeness，只表示 PASS/FAIL，不是 Candidate、
Finding、Approval 或领域事件。

### LocalSourceRobustnessProfile 与 Result

M9.4 为 `LocalCandidateObservation` 增加从 exact signal/route/flow 推导的 `framework` 与
`call_chain_length`，并在 `LocalSourceCaseObservation` 中绑定 `files_analyzed` 与
`parse_failure_count`。这些是静态 provenance，不是漏洞复现或 Finding Evidence。

`LocalSourceRobustnessRequirement` 逐案例绑定 case ID、名称、framework、正/负 disposition、是否跨文件、
最小文件数、最小调用链长度和 expected CWE；完整 requirements 必须逐项等于代码内固定的
`M9_4_CASE_CONTRACT`。`LocalSourceRobustnessProfile` 内容寻址绑定 exact suite 与 M6.1 baseline。

`LocalSourceRobustnessMetrics` 记录正例、负例、跨文件、框架、解析失败、framework mismatch、跨文件
trace failure 和负例 Candidate 数量。`LocalSourceRobustnessResult` 绑定基础 M9.3 quality result，并以
稳定 violation code 表示只读 PASS/FAIL；它不能改变 Candidate/Finding 或授予任何执行、Approval、导出、
网络与 Submission 权限。

### AuthorizedPilotManifest、ReadinessPlan 与 Result

M9.5 的 `AuthorizedPilotManifest` 内容寻址绑定当前授权 engagement/target/version、Target manifest/artifact、
Scope identity/version/digest、SourceGraph identity/digest/analyzer version，以及 CandidateSet identity/digest/
generator version 和排序后的 exact Candidate IDs。它只保存文件数与总字节数，不保存源码、授权正文、Agent
prose、凭据、路径、URL 或 Runner/Broker 参数；`selected_candidate_ids` 的长度固定为零。

`PilotHumanGate` 代码内固定人工 Candidate selection、六个 M8 Intake 和三个精确 Approval。
`PilotForbiddenCapability` 固定 Agent Runner/Broker 参数、自动 Validation、Candidate 自动变更、自动
Approval、Target build、公网与 Submission 八类禁区。manifest 和 `AuthorizedPilotReadinessPolicy` 都必须
逐项保持完整顺序，资源上限和零副作用上限不可放宽。

`AuthorizedPilotReadinessPlan` 绑定 exact manifest、M9.4 quality profile/result 的 identity 与完整 digest、
policy、八类 `LocalSourceEffectCounters`、窗口和幂等键。`AuthorizedPilotReadinessMetrics` 仅记录文件、字节、
Candidate、`PROPOSED` Candidate、人工门禁、禁止能力和禁止副作用计数；
`AuthorizedPilotReadinessResult` 以稳定 violation 表示资格 PASS/FAIL，不是领域事件或 Approval。

`AuthorizedPilotReadinessStore` 只保存 digest-only STARTED/COMPLETED checkpoint；artifact store 将 result
写入大小受限、no-follow 验证、只读的内容寻址 JSON/Markdown。遗留 STARTED 不自动恢复，重复完成只读复核
artifact；任何 Scope、Snapshot、静态产物、quality input 或 plan 漂移都在 checkpoint 前 fail-closed。

### M9.6 local shadow pilot composition

M9.6 不增加领域实体、状态或事件。`shadow-pilot-local` 只从已安全导入的 `TargetSnapshot` 与 exact approved
`Scope` 重建既有 `SourceGraph`、`CandidateSet`、`AuthorizedPilotManifest`、`AuthorizedPilotReadinessPlan`
和 `AuthorizedPilotReadinessResult`。它只输出这些内容寻址对象的 identity、路径与 Candidate 人工审阅摘要，
不持久化 Agent prose、源码正文、授权正文、凭据、Runner/Broker 参数或网络目标。

`AuthorizedPilotManifest.candidate_ids` 可以为空，以表达“可信静态流程完成但没有 Candidate”；
`selected_candidate_ids` 仍必须为空，所有非空 Candidate 仍必须是 `PROPOSED`。空集合不是 Finding、无漏洞证明、
人工选择、Validation 计划、Approval 或任何状态迁移。

### PilotCandidateSelectionCommand 与 Record

M9.7 的 `PilotCandidateSelectionCommand` 内容寻址绑定 completed passing readiness result/artifact、重构后的
pilot manifest、exact CandidateSet/SourceGraph/Snapshot/Scope、唯一 Candidate digest、human reviewer、带时区
decision time、Scope 截止时间与幂等键。它不包含 ValidationPlan、Runner/Broker 参数、工具调用、URL、凭据、
源码、Approval 或 Submission。

`PilotCandidateSelectionRecord` 保存同一 identity chain 的 digest-only 选择事实。独立 SQLite 对
readiness plan 唯一消费并提供 completed replay；记录不会改变 Candidate 的 `PROPOSED` 状态，也不是
Validation Intake、Validation authority、Approval 或领域事件。后续 M8.1 必须单独验证本记录并绑定可信控制面
构造的 exact ValidationPlan。

### PilotValidationIntakePlan 与 Binding

M9.8 的 `PilotValidationIntakePlan` 内容寻址绑定 exact M9.7 selection record/digest、M8.1 IntakePlan 与
human accept command 的 ID/digest、独立构造的 ValidationPlan ID/digest、CandidateSet/Candidate/Scope、执行
窗口与幂等键。它不保存 Agent prose、源码、Audit 正文、Runner/Broker 参数、HTTP 数据、凭据或 Approval。

`PilotValidationIntakeBinding` 绑定 completed M8.1 `AgentValidationIntakeRecord` 与来源 selection、Candidate、
ValidationPlan 和 Scope。独立 SQLite 对 selection、IntakePlan 与 ValidationPlan 唯一消费；completed replay
只读，遗留 STARTED fail-closed。Binding 不是 ValidationRun、Evidence、Candidate 状态转换、Approval、领域
事件或 Submission。

### PilotValidationApprovalAction、ExecutionPlan 与 Binding

M9.9 的 `PilotValidationApprovalAction` 内容寻址绑定 completed M9.8 binding、accepted M8.1 record、exact
ValidationPlan、CandidateSet/Candidate、Scope 和固定 `validation:run`/`candidate:validation_result` 效果。
对应 `ApprovalRequest` 必须由人工以 `RUN_VALIDATION` action 单独 granted，且 action digest、Target、Scope、
policy version、effects、决定人、决定时间和截止时间全部匹配。

`PilotValidationExecutionPlan` 保存 Approval identity/digest、上述 provenance、窗口和幂等键，不复制
ValidationPlan 内的 Runner 参数，也不包含 Agent prose、源码、URL、凭据或 Submission 数据。首版只接受
`broker_calls=()` 的网络隔离 ValidationPlan。

`PilotValidationExecutionBinding` 内容寻址绑定一次 completed Validation outcome/run、原始及结果 Candidate
digest、result 和 Evidence identity。独立 SQLite 唯一消费 M9.8 plan、ValidationPlan 与 Approval；completed
replay 只读，遗留 STARTED fail-closed。原始 Candidate 保持不可变，binding 不代表 Critic、Finding promotion、
报告 Approval 或 Submission。

### PilotValidationOutcomePlan 与 Binding

M9.10 的 `PilotValidationOutcomePlan` 内容寻址绑定 completed M9.9 execution plan/binding 的 ID 与完整
摘要、exact M8.2 outcome binding plan 的 ID/完整摘要、ValidationPlan ID、Validation outcome 摘要和窗口。
执行来源字段没有可选或空值路径，不保存 Agent prose、操作参数、URL、凭据、Approval 正文或 Evidence 正文。

`PilotValidationOutcomeBinding` 保存 execution binding、completed M8.2 binding 的 ID/完整摘要及共同的
Validation outcome identity。独立 SQLite 唯一消费 execution binding、M8.2 plan 与 ValidationPlan；不写领域
事件、不修改 Candidate，不赋予执行、Approval 或 Submission 权限。原 M8.2 binding 仍使用既有模型与 store。
completed replay 重查上游来源及 M8.2 binding，STARTED 与预先存在的裸 M8.2 checkpoint 均 fail-closed。

### PilotCriticIntakePlan 与 Binding

M9.11 的 `PilotCriticIntakePlan` 内容寻址绑定 M9.10 plan/binding ID 与完整摘要、M8.3 IntakePlan 与人工
command ID/完整摘要、独立 CriticPlan ID/完整摘要、Candidate ID/validated digest、Scope 和有界决策窗口。
`PilotCriticIntakeBinding` 保存同一来源链和 authoritative accepted M8.3 record 的 ID/完整摘要。

计划和 binding 均不保存 assessments、rationale、Evidence 正文、Agent 输出、操作参数、凭据、Approval 或
Submission。SQLite 以 STARTED/COMPLETED 唯一消费 M9.10 binding、M8.3 IntakePlan、CriticPlan 和 command；
完整 record 仍由既有 M8.3 store 管理。绑定只证明人工接纳来源，不是 CriticReview、Candidate 状态迁移或 Finding。

### PilotCriticApprovalAction、ExecutionPlan 与 Binding

M9.12 的 `PilotCriticApprovalAction` 内容寻址绑定 completed M9.11 binding、accepted M8.3 record、exact
CriticPlan、有序 typed Evidence catalog 摘要、Candidate、Engagement/Target/Scope 和固定的两个效果。
独立 `ApprovalRequest` 必须是人工 granted 的 `RUN_CRITIC`，完整 identity、digest、效果与窗口精确匹配。

`PilotCriticExecutionPlan` 再封存 Approval ID/完整摘要、来源链和执行窗口，不持久化 assessments、Evidence
正文、Approval summary、Agent 输出或操作参数。`PilotCriticExecutionBinding` 绑定 completed CriticOutcome/
Review、M8.4 plan/binding ID/完整摘要、typed verdict、结果 Candidate 状态/摘要和原 validated Candidate 摘要。
accepted/rejected/inconclusive 分别只对应 CRITIC_REVIEWED/REJECTED/VALIDATED。

独立 SQLite 唯一消费 M9.11 plan、CriticPlan 与 Approval，完成重放只读；裸上游执行记录与 STARTED 拒绝自动
恢复。完整 CriticOutcome 与 M8.4 binding 保持在既有 stores，pilot ledger 不保存正文，也不代表 Finding 或 Submission。

### PilotFindingIntakePlan 与 Binding

M9.13 `PilotFindingIntakePlan` 封存精确 M9.12 execution plan/binding ID 和摘要、M8.5 Intake、
独立人工 command、PromotionPlan、duplicate check 的 ID/完整摘要，以及 Finding/Candidate/Scope 身份、
Candidate 摘要、创建时间、截止时间和幂等键。仅接受 completed accepted Critic 与 ACCEPT Intake。

`PilotFindingIntakeBinding` 保存上述接纳关系和完整 M8.5 record 摘要、完成时间；两种协议均由规范化
摘要封存且禁止额外字段，不携带 Evidence 正文、影响说明、批准命令或 Runner/Broker 参数。
独立 ledger 唯一消费执行结果、Intake、晋升计划、去重证明、Finding ID 和人工命令；Finding ID 只是
计划身份，不代表 Finding 已创建。STARTED 不自动重试，COMPLETED 重放复核完整 record 和 ledger。

### PilotFindingPromotionPlan 与 Binding

M9.14 `PilotFindingPromotionPlan` 封存 M9.13 plan/binding ID 及完整摘要、M8.6 execution plan ID
及完整摘要、精确晋升 Approval 身份及摘要、M8.5 record、PromotionPlan、去重证明、Finding/Candidate/Scope
身份、Candidate 摘要、时间窗口和幂等键。晋升 Approval 独立于上游 Critic 执行 Approval。

`PilotFindingPromotionBinding` 绑定执行结果的 outcome ID/完整摘要、Finding 和晋升后 Candidate 摘要，
并保留上游 pilot Intake、执行计划、Approval、接纳记录、晋升计划和 Scope 身份及完成时间。
两种协议均禁止额外字段并校验规范化内容摘要，不携带 Evidence 正文、影响描述或执行参数。
完整 Finding 及 promoted Candidate 仍由既有 M8.6 outcome store 保存；来源 CandidateSet 不被覆盖。
独立 ledger 使用唯一约束防止重复消费，STARTED 要求显式恢复，完成重放只读验证全部结果与当前授权。

### ProviderProbeConfig、Plan 与 Result

M9.15 `ProviderProbeConfig` 包含互相精确绑定的 model registration、transport admission、credential
reference 与 codec registration。只接受有界 live HTTPS、固定 reporter role 和已签发的 grant 引用；
不携带 Key、自定义 prompt、Target、工具或源码。

`ProviderProbePlan` 封存 config 完整摘要、grant、代码固定 fixture 摘要、创建/截止时间和幂等键。
窗口不超过 300 秒且必须在 grant 有效期内。`ProviderProbeResult` 保存计划身份、passed/rejected/timed_out、
已校验 usage 计数、process_started/cleanup_verified、attempt/receipt 摘要及完成时间，禁止响应正文。
两种记录都有内容摘要校验。STARTED/COMPLETED ledger 唯一消费 plan、幂等键和 grant；失败也不能自动重试。
这些协议不产生研究领域事件，也不能改变 Candidate/Finding 或批准其他操作。

### CucChatProbeCodecRegistration 与 CUC 结果身份

M9.16 为独立 probe 添加密封 CUC 专用 codec：固定 `cuc/deepseek`、Chat Completions path、
PONG 请求以及两个精确后端响应名，禁止修改为其他别名或通配符。`ProviderProbeConfig.codec` 允许
该专用类型或原 Responses 类型；CUC 配置另须匹配固定网关和真实 Key 的环境变量引用。

`ProviderProbePlan.fixture_digest` 区分 Responses 固定结构化消息与 CUC PONG 消息。
`ProviderProbeResult.response_model` 仅允许上述两个后端名或空值；空值不参与摘要，保留 M9.15
结果身份。CUC 成功重放必须有响应模型记录，Responses 结果不得带该 CUC 字段。
新 schema 不增加研究目标、工具执行、授权签发或领域状态变更能力。

### ProviderDiagnostic

`ProviderProbeResult.diagnostic` 为可选封闭类型，参与非空结果摘要；缺失或空值不改变旧结果身份。
核心字段为 `failure_stage`、`error_code`、`http_status`、`network_opened`、
`captured_response_bytes` 和 `tls_version`。错误码及阶段为固定枚举，HTTP 状态为严格整数
100–599，TLS 仅接受 1.2/1.3，字节数有上限。未知字段、异常原文和动态字符串均拒绝。
`network_opened` 表示观察到 TCP 连接成功；`null` 表示未知（例如父进程强制超时），不等同于
传输 attempt 的完整网络证明。HTTP 状态需要 TLS 观察，codec 阶段需要 HTTP 200；成功结果不能
带失败诊断。旧记录不会补造观测值。诊断不代替可信响应回执、模型身份校验或真实用量证据。

`error_code` 进一步区分 JSON、顶层缺失/额外字段、choices 数量/类型、choice 字段/索引/结束原因、
message 字段/角色/refusal/reasoning 类型等分支。可选 `shape_observations` 仅包含有界固定枚举，
观察已知可选字段是否为 null；未知字段只记录 `root_other_fields` / `message_other_fields`，不复制字段名。
空观察在序列化中省略，保持原有诊断结果摘要兼容；观察不能放宽任何接受条件。

CUC codec 实现 v2 的摘要包含精确空扩展字段及其类型策略。顶层识别 `prompt_logprobs`、
`prompt_token_ids`、`prompt_text`、`kv_transfer_params`、`ec_transfer_params`、`metrics`；
choice 识别 `stop_reason`、`token_ids`、`routed_experts`；message 识别 `annotations`、
`audio`、`function_call`、`tool_calls`、`reasoning`；usage 识别 `prompt_tokens_details`。
只接受 null 或对应类型的空值，function_call 仅为 null；0/false 等错误类型不能伪装成空值。
`shape_observations` 最多 32 个固定枚举，额外包含 choice/usage 字段观察；没有自由文本字段。
新策略改变 codec 身份，旧配置不能隐式升级；旧结果的观察枚举及摘要保持兼容。

CUC codec v3 把 exact/strip PONG 策略、usage details 字段及有界计数规则纳入实现摘要。
`ProviderDiagnostic.content_classification` 是可选闭集枚举：type/exact/trimmed/casefold/punctuation/
empty/other。缺失时不参与序列化，保持旧结果摘要；字段不携带内容、前缀或内容摘要。
usage 观察增加 completion details、reasoning/cached tokens 及已知 details 字段是否存在；不保留
细节值。总量不一致使用 `usage_total_mismatch`，未知字段使用 `usage_unknown_fields`，details
类型、字段或计数错误使用 `usage_details_mismatch`；这些诊断均不能替代有效用量和响应回执。

CUC codec v4 摘要封存去除首尾空白后的四个精确接受字符串（PONG、PONG.、PONG!、反引号包裹 PONG）。
usage 的两个缓存字段必须为非负整数且不超过 prompt_tokens；同时存在时二者之和必须等于 prompt_tokens。
新增闭集错误码 `usage_cache_mismatch` 和两个缓存字段的 null/non_null 观察。未知 usage 字段仍拒绝，
总 token 等式未改变；新观察不包含缓存计数或任意字段名，旧结果缺省字段的摘要规则不变。

`UsageKeyObservation` 仅允许 candidate（八个固定名称）或 name_sha256（二者恰好一个），以及
null/int/dict/other 类型枚举。`ProviderDiagnostic.usage_key_observations` 最多 32 条，超过时
`usage_keys_truncated=true`；缺省空数组和 false 在序列化时省略，保持历史结果摘要。
未知键哈希不代表允许该字段；匹配必须先对本地审阅词典计算 SHA-256，随后再定义明确验证规则。

codec v5 将已匹配的三种计量字段及范围封存到实现摘要：time_per_output_token_ms 和
time_to_first_token_ms 为 0..10000 的严格整数，tokens_per_second 为 0..1000000 的严格整数。
类型或范围不满足时使用 `usage_metrics_mismatch`；这些字段不改变 core token 等式，也不赋予
工具、研究目标或状态变更权限。边界是当前本地策略，并非对服务端字段约定的实测断言。

codec v6 更正上述三个性能指标为有限 int/float（明确排除 bool），范围不变；token 计数仍须为
严格整数。类型元数据将指标声明为 (int, float)，摘要支持类型元组，性能指标不经空扩展验证。
`ProviderDiagnostic.metric_issues` 最多三条 `MetricIssue`：field 仅允许三个明确指标名，reason
仅允许 type/non_finite/negative/above_limit，不携带数值。空列表在序列化中省略以保持旧摘要。
超大整数先作整数范围判断，避免浮点转换溢出。

### ProviderProfile、CapabilityManifest 与 ModelRoute

多模型控制面使用独立于执行期 `AgentModelRegistration` 的产品级领域协议：

- `ProviderProfile` 只保存 Provider、协议、数据类别和 Endpoint/Credential 引用摘要，不包含 URL 或秘密；
- `profile_digest` 固定配置身份，生命周期变化只递增 `lifecycle_sequence` 并更新带证据的
  `lifecycle_digest`，因此 Capability Manifest 不会因状态变化失去绑定；
- `CapabilityManifest` 把模型能力区分为 unknown、declared、probed 和 failed，角色准入只接受 probed；
- `FallbackPolicy` 只允许限流、超时、不可用和空响应等封闭触发原因，并固定在提交副作用之前；
- `ModelRoute` 绑定 Engine、Agent Role、主模型、能力、数据类别、预算和 Fallback Policy；
- `FlowModelSnapshot` 在创建 Flow 时固定路由、Provider 生命周期、模型能力、Prompt 合同、工具 schema 和预算。

`build_flow_model_snapshot` 是 fail-closed 的纯领域函数。Provider 未达到 `role_admitted`、Capability 没有
探测证据、数据类别不允许、Fallback 跨 Provider 未授权、尝试预算不足或摘要绑定不一致时均拒绝生成快照。
现有 CUC 执行合同暂不依赖这些新对象，后续通过旁路 adapter 完成差分验收后接入。

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
- `ProviderSecretBound`
- `ProviderConnectivityVerified`
- `ProviderCapabilitiesProbed`
- `ProviderRoleAdmitted`
- `ProviderDisabled`
- `ProviderRevoked`
- `FlowModelSnapshotCreated`

事件只记录已经发生的领域事实。模型的自然语言输出先经过 schema 校验和命令处理，不能直接写事件流。

## 4. 不变量

- 一个 Finding 必须属于一个 Candidate。
- 一个 Finding 至少引用一个成功 Validation Run。
- Validation Run 的 Scope 和 Target 版本不可为空。
- Report 只能引用 Finding 已批准的 Evidence Bundle。
- Submission 必须引用未过期 ApprovalRequest。
- 相同 `duplicate_fingerprint` 的 Finding 必须先进行人工根因确认。
- Provider 状态转换必须绑定 Evidence 摘要，`revoked` 为终态。
- 未经实际探测的模型能力不能满足角色路由要求。
- Flow 创建后固定模型路由快照；工作区默认模型变化不修改该快照。
- Endpoint、API Key 和 Provider 认证响应不得出现在 ProviderProfile 或 FlowModelSnapshot。
