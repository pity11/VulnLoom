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
