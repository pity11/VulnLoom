# 工作流与编排

## 1. 状态机

```text
DRAFT_SCOPE → SCOPE_APPROVED → INGESTED → MAPPED → CANDIDATE
                                                   ├─ REJECTED
                                                   ├─ DUPLICATE
                                                   └─ VALIDATION_PENDING
                                                            ↓
                                         VALIDATED ← VALIDATION_RUNNING
                                              │             └─ INCONCLUSIVE
                                              ↓
                                       CRITIC_REVIEWED
                                              ├─ REJECTED
                                              └─ FINDING
                                                   ↓
                                             REPORT_DRAFTED
                                                   ↓
                                            HUMAN_APPROVED
                                                   ↓
                                           EXPORTED/SUBMITTED
```

首期只实现到 `REPORT_DRAFTED`。`SUBMITTED` 是为了保留未来状态语义，不代表系统应自动提交。

## 2. 典型编排

### 目标导入链

```text
Local Artifact
  → Quarantine + SHA-256
  → Scope 草稿引用名称、类型和摘要
  → Human Scope Approval
  → Archive/Git Member Validation
  → Atomic Read-only Target Snapshot + Manifest
  → TargetIngested
```

Quarantine 只接收和标识输入，不授予分析权限。Git 目标直接以 Scope 中的 URL+commit 固定；OCI 目标首期只注册 Scope 中的 image reference+digest，不拉取镜像。

### 仓库分析链

```text
Ingest
  → Source Mapper
  → [Auth Analyzer | Dataflow Analyzer | Config Analyzer]
  → Candidate Merger
  → Duplicate Classifier
```

### 候选验证链

```text
Candidate
  → Validation Planner
  → Human Gate（有状态变化或外部回连时）
  → Environment Builder
  → Validator
  → Evidence Normalizer
  → Critic
  → Deterministic Verdict
```

### 报告链

```text
Finding
  → Secret/PII Redactor
  → Reporter
  → Evidence Consistency Check
  → Human Review
  → Channel Export
```

## 3. 结构化结果

每个 Worker 返回统一信封：

```yaml
task_id: string
worker_role: string
status: completed | partial | blocked | failed
confidence: 0.0-1.0
claims: []
evidence_refs: []
candidate_refs: []
checkpoint_ref: null
budget_used: {}
policy_decisions: []
errors: []
```

`confidence` 只表示 Worker 对自身输出的信心，不能触发 `Finding` 状态。

## 4. 裁决优先级

当多个 lane 返回不一致结果时，使用固定优先级，避免结果顺序影响状态：

```text
POLICY_VIOLATION / SAFETY_STOP
> REJECTED_BY_EVIDENCE
> VALIDATED_WITH_REPRODUCTION
> NEEDS_HUMAN_REVIEW
> INCONCLUSIVE
> CONTINUE
```

### Finding 门禁

Candidate 转为 Finding 必须同时满足：

- Scope 已批准且在有效期内。
- Target 版本和环境可唯一定位。
- 至少一个 Validation Run 可重复成功。
- Evidence Bundle 包含入口、影响路径和观测结果。
- Critic 没有给出成功反证。
- Duplicate Family 已完成检查。
- 验证动作没有违反速率、网络或副作用策略。

M5.1 中 Critic 使用固定优先级：任一反证角度 `confirmed` 即拒绝；否则任一角度 `inconclusive` 即保持 `VALIDATED`；只有四个角度均有 Evidence 支持地 `ruled_out` 才进入 `CRITIC_REVIEWED`。Critic 计划与验证计划必须使用不同上下文和 producer，普通 Worker 文本或 confidence 不能设置这些 disposition。

M5.2 只允许 `PROMOTED` Candidate 对应的 verified Finding 进入报告草稿服务。代码位置、请求/响应、复现和影响章节都必须引用 Finding 的 Evidence Bundle；缺失、越界、损坏或 Target 版本不一致时不创建 Report。

M5.3 的报告状态机是 `DRAFT → HUMAN_APPROVED | CHANGES_REQUESTED | REJECTED` 和 `HUMAN_APPROVED → EXPORTED`。修订版必须紧邻前一版并有确定性 Diff；审批绑定精确内容与 artifact digest，任何修改都要求新计划。`EXPORTED` 只表示本地输出，状态机没有 `SUBMITTED` 迁移。

### M6.1 离线评测链

```text
Sealed local ground truth + sealed pipeline observations
  → workflow-integrity validation
  → deterministic metric reducer
  → absolute and baseline regression checks
  → immutable local result
  → CI exit gate
```

评测 observation 只是已完成流水线状态的类型化投影，不能触发 Candidate 或 Finding 状态变化。
Finding identity 必须同时绑定 reproduced Validation、accepted Critic、PROMOTED Candidate 和完整
Evidence。语义引用、suite 摘要、baseline 摘要或 deadline 任一不匹配均 fail-closed；回归失败是
正常的类型化结果，不会开启重试、网络或外部动作。

### M6.2 外部快照规范化链

```text
Pre-obtained local directory
  → bounded no-follow manifest scan
  → exact adapter/snapshot plan binding
  → whitelist metadata normalization
  → second full integrity scan
  → immutable BenchmarkSuite + typed exclusions
```

Adapter 不运行 benchmark：BountyBench 的 shell、Docker、exploit、verify 和 patch 文件仅参与摘要复核；
AutoPenBench 的 task/flag 只在可信解析函数内出现并立即丢弃。缺少显式 CWE 的 case 不猜测标签，进入
exclusion；重复 JSON key、陈旧 sidecar、身份歧义和 snapshot 漂移均拒绝整个 import。

### M6.3a 预计算分析器 Observation 链

```text
Precomputed local SARIF/JSON + optional sealed CWE map
  → no-follow byte manifest
  → exact Target/tool/rules/adapter plan binding
  → strict versioned parser
  → rule/message digest + CWE/severity/location normalization
  → second byte-integrity check
  → immutable AnalyzerObservationSet + typed exclusions
```

该链不启动 CodeQL、Trivy、Checkov 或 Kubesec，也不下载规则/数据库/镜像。Analyzer Observation 只是一条
静态工具观察；它不能进入 Finding 状态机，也不能冒充 M6.1 中已经通过 Validation/Critic/Evidence 门禁的
pipeline observation。M6.3b 的 ground-truth 对齐只计算指标，不改变这一领域边界。

### M6.3b 显式跨工具评测链

```text
BenchmarkSuite + exact AnalyzerObservationSets
  + explicit reviewed Observation→truth alignment
  → case / Target / digest / truth / CWE validation
  → aggregate and per-analyzer deterministic reducer
  → threshold + required matrix + exact-suite baseline checks
  → immutable local result + CI exit gate
```

alignment 中没有列出的 Observation 即使 CWE 相同也不算命中。评测 gate 失败返回类型化 violation 和非零
CLI 状态，但不重试工具、不生成 Candidate/Finding、不改变报告状态，也不产生网络或外部副作用。

### M6.4a source-only 分析器执行协议

```text
Verified Target Snapshot + active Scope
  + sealed AnalyzerToolRegistration
  + exact static Sandbox/Profile/Registry binding
  → pre-check all target/policy/image/rules/argv/deadline digests
  → transactional STARTED checkpoint
  → Offline Runner lifecycle only
  → protocol_completed | failed | timed_out | cancelled
  → proven cleanup + COMPLETED checkpoint
```

`protocol_completed` 不代表工具已执行，也不产生 `AnalyzerResultSnapshot`。真实执行的输出未来只能先封存为
M6.3a 输入，再规范化成 Observation；Observation 后续仍须经过单独的确定性 Candidate 投影以及既有
Validation/Critic/Finding 门禁。当前链没有网络、Broker、credential、目标 build、Approval 消费或 Submission。

### M6.4b 固定 Checkov/Kubesec 执行链

```text
Verified Target + exact admitted registration + sealed CWE map
  → pre-check Scope/Policy/Profile/Registry/adapter bindings
  → Docker-execution STARTED checkpoint
  → exact image ID + pull=never + network=none source-only Worker
  → bounded attached stdout + immutable digest object + container cleanup
  → M6.3a snapshot/import transaction
  → completed typed outcome containing redacted Observations only
```

Checkov 只接受 exit 0；Kubesec 的 0/2 成功语义固定在其注册项。其他退出码、超时、OOM、输出超限、
损坏或导入失败均 fail-closed。该链没有公开 CLI，也不负责安装镜像、执行 Target build、联网、产生
Candidate/Finding 或触发 Submission。

### M6.4c Trivy 密封 DB 执行链

```text
Verified Target + exact Trivy 0.73.0 image ID + sealed read-only DB v2
  → verify exact DB tree/digests + Scope/Policy/Profile/Registry bindings
  → Docker-execution STARTED checkpoint
  → pull=never + network=none + read-only source/DB + scanners=vuln
  → bounded attached JSON + container cleanup
  → reverify unchanged DB snapshot
  → mandatory M6.3a Trivy import
  → completed typed outcome containing redacted Observations only
```

DB 和镜像只由 operator/CI 在执行路径之外预置。执行协议没有下载入口，也不能添加 secret scanner、
misconfiguration/license scanner、运行时参数、目标 build、Broker、Candidate/Finding 或 Submission。

### M6.4d CodeQL 预建 DB 查询链

```text
Verified Target + exact CodeQL 2.26.2 image ID
  + target-bound sealed read-only DB/query snapshot
  → verify tree/digests + Scope/Policy/Profile/Registry bindings
  → Docker-execution STARTED checkpoint
  → exact wrapper copies DB into bounded output tmpfs
  → pull=never + network=none + one fixed database analyze over the copy
  → bounded SARIF stdout + container/tmpfs cleanup
  → reverify unchanged original DB/query snapshot
  → mandatory M6.3a CodeQL import
  → completed typed outcome containing redacted Observations only
```

wrapper 不下载 bundle/pack，不运行 `database create`，不执行 Target build，也不输出 source contents、
snippets 或 query help。真实 CodeQL bundle、许可、query pack 和预建 DB 由 operator 在运行边界外资格审查；
Phase 3 行为 fixture 只证明 rootless Docker、tmpfs 写边界、原始输入不变、Observation 导入和清理。

### M6.5 分析器执行资格链

```text
Exact BenchmarkSuite + reviewed truth alignment + M6.3b evaluation plan
  + authoritative completed M6.4 execution plan/registration/outcome for every case×analyzer cell
  → reverify lifecycle + cleanup + Target/Manifest/Scope + all content digests
  → require the exact ObservationSet/alignment matrix
  → existing M6.3b deterministic reducer and regression policy
  → PASS|FAILED qualification outcome + transactional checkpoint
```

缺少一个 cell、失败/超时/取消、清理不完整或任何摘要漂移都会在资格 checkpoint 前拒绝。该链不重跑
分析器，不修改 alignment，不自动匹配 CWE，也不拥有 Runner、Broker、网络、Target build、Candidate/Finding
或 Submission 权限。

### M6.6 rootless 四分析器资格组合

```text
One verified Target/Manifest/Scope
  → exact Checkov + Kubesec + sealed-DB Trivy + sealed-copy CodeQL
  → four authoritative completed execution checkpoints + mandatory M6.3a imports
  → reject missing cell; reject drifted outcome; stores remain empty
  → exact four-cell M6.5 matrix → M6.3b → PASS qualification
```

逐工具 probe 与组合 probe 同时保留。组合测试只证明现有能力的真实拼接，不增加下载、联网、构建、secret
scanner、状态变更测试、Candidate/Finding promotion 或外部提交。

### M7.1a 离线 Agent 决策链

```text
Exact TaskEnvelope + offline model registration + fixed decision schema
  → preflight role/registration/deadline/content digests
  → transactional STARTED checkpoint
  → bounded offline replay step with remaining token/wall budget
  → strict terminal decision | typed tool proposal
  → digest raw tool arguments; execute nothing
  → discard raw response → completed typed outcome
```

结构错误只能在 `max_steps` 和同一总 token/墙钟预算内重试。越权工具、超限、身份漂移或无效参数产生稳定
fail-closed outcome；adapter 异常保留 STARTED，后续调用必须显式恢复而不能静默重放。该链没有 live provider、
Runner、Broker、领域状态机、Approval 消费或 Submission。

### M7.1b 本地凭据租约链

```text
Sealed credential reference + local-fake registration
  → resolve exactly one Control Plane environment entry
  → acquire non-serializable byte lease
  → verify sealed request and credential inside no-socket fake adapter
  → zero lease on success or exception
  → M7.1a structured validation and checkpoint outcome
```

缺失/错误凭据在 STARTED 后失败并要求显式恢复；模型超时结果也必须先释放 lease。该链不把 credential
reference 或值放入 `AgentStepRequest`，不继承环境到 Worker，也没有 live endpoint、工具执行或状态变化。

### M7.2 密封上下文装配链

```text
Exact TaskEnvelope.input_refs + transient typed sources
  → require complete ordered one-to-one binding
  → normalize + reject controls + builtin-v2 redact
  → enforce raw/redacted/total/count/wall budgets
  → immutable untrusted fragments + content-addressed snapshot
  → atomic read-only store + no-follow/digest revalidation
  → AgentRunPlan/StepRequest bind snapshot ID only
```

缺失、额外、替换或重排 source、凭据/PII 未脱敏、超限、超时、可写对象、链接或内容漂移均在模型调用前
拒绝。snapshot 的 `untrusted` 标记不会因文本内容变化；上下文不能授权工具、Approval 或状态迁移。

### M7.3 固定消息渲染链

```text
Verified AgentRunPlan + reloaded context snapshot + builtin role template
  → fixed trusted system message
  → canonical strict-JSON user message
     ├─ trusted typed control: tools/schema/budgets/can_execute=false
     └─ escaped untrusted_context fragments
  → enforce system/user/total/wall budgets
  → content-addressed message envelope
  → seal envelope ID into AgentStepRequest
  → transient adapter call; retain digest only
```

模板、system、JSON shape、control、Task/Scope/Target、fragment ordinal/trust 或摘要任一漂移都拒绝。模型仍只能
返回工具提案；prompt 文字不能执行工具、授予 Approval 或触发 Candidate/Finding/Submission 状态变化。

### M7.4 Provider 传输 Admission 链

```text
Exact StepRequest + Message Envelope + model registration
  → sealed provider transport admission
     ├─ exact DNS hostname / TLS 443 / canonical path
     ├─ redirects=false / proxy=false / DNS revalidation=true
     └─ network_enabled=false / one attempt / byte + wall limits
  → transient provider-shaped request buffer + scoped credential lease
  → in-memory admission fake (no DNS/socket/HTTP/SDK)
  → bounded raw response buffer
  → strict JSON + exact identity + typed reply
  → zero request/response/credential buffers
  → digest-only attempt and receipt
```

Admission、registration、credential、StepRequest 或 Envelope 任一摘要/语义漂移都 fail-closed。响应超限、畸形、
身份不一致和 timeout 分别产生稳定拒绝或超时 outcome；原始消息、响应与凭据不进入 checkpoint。真实 HTTPS
传输尚不可表示，后续必须另行证明隔离出口、DNS rebinding、TLS、流式捕获、速率和日志边界。

### M7.5 独立进程 HTTPS 调用链

```text
Exact live/loopback Admission + registration + Message Envelope
  → re-resolve exact hostname and validate every IP
  → rate slot + scoped credential lease
  → bounded binary stdin frame (credential + provider message + optional CA)
  → fixed `python -I` one-shot child, empty allowlisted env, no shell
  → numeric-IP TCP + admitted-hostname TLS SNI/certificate verification
  → exact POST path; no redirect/proxy/compression
  → bounded headers + streaming response capture
  → bounded parent stdout capture + forced process-group cleanup
  → peer/TLS proof + strict typed response validation
  → zero transient buffers; persist digest-only attempt/receipt
```

生产 `live_https` 与 `loopback_https_probe` 的 host/port/IP/CA 规则在 schema 层互斥。DNS 混入 forbidden address、
peer 漂移、TLS/CA 失败、非 200/redirect、畸形/超限响应、rate exhaustion 和 timeout 均 fail-closed。没有自动
retry，且该 adapter 仍只返回 Agent decision/tool proposal；它不能执行工具或改变领域状态。

### M7.6 Provider Egress 签发与撤销链

```text
Trusted issuer policy + exact networked transport Admission
  → validate provider/mode/purpose/lifetime/deadline
  → STARTED issuance checkpoint
  → atomic read-only content-addressed grant publication
  → COMPLETED active lifecycle record
  → bind exact grant ID into model registration
  → before every call: reopen grant + ledger, verify active/time/Admission
  → only then DNS → rate slot → credential lease → fixed child

Exact issuer + active grant
  → STARTED revocation checkpoint
  → atomic read-only revocation publication
  → transactionally mark grant revoked + COMPLETED
  → subsequent calls stop before DNS and credential access
```

未知 issuer、policy 越权、purpose/mode 不匹配、超长期限、deadline、幂等冲突、遗留 STARTED、到期、撤销、
可写/链接/畸形对象或 Admission 漂移均 fail-closed。grant/revocation 不包含 secret；该 lifecycle 不签发任意 URL，
也不提供公网调用入口。

### M7.7 密封 Responses 编解码链

```text
Exact codec registration + model registration + Message Envelope
  → verify provider / codec ID / exact request path binding
  → fixed Responses JSON: store=false, stream=false, truncation=disabled
  → strict AgentDecision JSON Schema; no tools or arbitrary parameters
  → existing egress grant → DNS pin → credential lease → fixed HTTPS child
  → bounded raw response capture
  → completed + exact model + one assistant output_text
  → strict nested JSON → AgentDecisionPayload
  → zero request/response/credential buffers
  → digest-only attempt and receipt
```

incomplete、refusal、native tool call、annotation、多输出、重复 key、未知协议字段、identity drift、大小或
codec wall timeout 全部拒绝。codec 不执行结构化 `propose_tool`；它仍必须经过 Runtime 的预算/白名单检查和
Broker/Sandbox 权限边界。常规测试完全离线，Admission 只连接 loopback TLS fixture。

### M7.8 Agent Tool Intent Handoff

```text
Authoritative completed Agent run (`tool_proposed`, cleanup complete)
  + digest-only AgentToolIntent
  + independently constructed exact BrokerCall
  → verify precommitted call digest and invocation digest
  → verify Validator Task / Scope / Policy / Profile / Registry / budget / deadline
  → Broker static preflight
  → STARTED handoff checkpoint
  → Tool Broker execute (Scope + DNS pin + credential + Approval enforced again)
  ├─ approval_required → one exact, prior-bound retry allowed
  ├─ denied / timed_out / failed → terminal, no Observation
  └─ completed → digest-only AgentToolObservation + Evidence refs
  → COMPLETED handoff checkpoint
```

同一 intent 不能并发或无限重放；只有首次 `approval_required` 可以形成 attempt 2。遗留 STARTED 必须人工恢复，
不会自动再次触发外部动作。Observation 不含 URL/response/credential/原始参数，也不能触发 Candidate/Finding
转换。Agent 始终不持有 Broker transport、Runner、Docker socket 或 Approval 决策权。

### M7.9 Tool Observation Continuation

```text
Authoritative root Agent run (`tool_proposed`)
  + authoritative completed handoff + AgentToolObservation
  → reread exact Evidence refs (no-follow + size + SHA-256)
  → fixed redaction + bounded untrusted Observation/Evidence context
  → derive new Validator Task with inherited authority/deadline
  → allowed_tools = [] and tool_calls = 0
  → verify cumulative token/step/tool/wall budget
  → re-open root/handoff/context/Evidence before STARTED checkpoint
  → run exactly one Agent step
  ├─ complete / blocked → terminal continuation
  ├─ provider timeout / rejection → typed timed_out / failed
  └─ propose_tool → terminal tool_proposal_not_allowed failure
  → COMPLETED continuation checkpoint
```

同一 Observation 只能被唯一 continuation 消费；completed 可幂等读取，冲突或遗留 STARTED 不会自动重放
provider/Broker 动作。context object 可以保存已脱敏的 untrusted fragment，但 continuation SQLite 只保存摘要和
typed outcome，不保存 Evidence 正文、URL、credential 或 raw provider response。该闭环不触发领域状态变化。

### M7.10 固定双工具 Session

```text
Authoritative completed tool round 1 + Observation 1
  → claim Session + cumulative budget ledger
  → derive Validator Task 2 with one tool call remaining
  → bind finite exact read-only AgentAuthorizedCallSet into trusted control
  → provider turn 2
  ├─ complete / blocked / failed / timed_out → terminal Session
  ├─ unlisted commitment → failed, no Broker call
  └─ listed commitment → ordinary M7.8 handoff 2
       ├─ approval_required → durable wait; one explicit Approval-bound retry
       ├─ denied / failed / timed_out → terminal Session
       └─ completed → Observation 2 → ordinary M7.9 zero-tool continuation
            ├─ complete / blocked → terminal Session
            └─ propose_tool → terminal tool_proposal_not_allowed failure
```

Session 最多产生三个 provider turn、两个成功 tool call；显式 Approval retry 的额外 Broker attempt 单独计入账本。
每轮都重新验证 Scope/Policy/Profile/Registry、Evidence/context、deadline、cleanup 和剩余预算。completed 可幂等
读取，遗留 STARTED/RESUMING 不自动重放。模型不能构造调用参数，Session 也不能改变 Candidate/Finding、导出
报告或触发 Submission。

## 5. 重试与恢复

- 模型或 Worker 失败最多 fallback 一次。
- 工具瞬时失败使用指数退避，但不跨过任务截止时间。
- Validation Run 不自动重试可能产生副作用的步骤。
- checkpoint 必须记录输入版本、策略版本和沙盒镜像摘要；任一变化都不能直接 resume。
- 自动续跑有预算上限，超过后转入人工处理，不无限自唤醒。

## 6. 人工门禁

首期必须审批的动作：

- 启动包含未知构建脚本的仓库。
- 执行会创建、修改或删除业务数据的验证。
- 使用真实身份凭据。
- 开启互联网出口或 OAST 回连。
- 将 Report 发送到任何外部平台。
