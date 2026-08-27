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
