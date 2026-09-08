# Candidate Recommendation 接纳边界

Candidate Recommendation 是对一个已存在、仍处于 `PROPOSED` 状态的 Candidate 的只读建议。它可以保存
优先级、复核理由、最多三个问题和对既有代码位置的引用，但不能创建 Candidate、修改 Candidate 字段、
选择 Candidate 或触发 Validation。

## 已实现的边界

`CandidateRecommendation` 是内容寻址对象，精确绑定：

- `CandidateSet`、Candidate ID 与 Candidate 内容摘要；
- `SourceGraph`、Target/version、Scope/version；
- Candidate 的完整有序 Signal ID 集合和其 `code_path` 内的引用位置；
- Provider 结果、计划、receipt，以及固定的 `candidate-recommendation-v1` 协议摘要；
- `requires_human_review=true`。

接纳服务从权威 `SourceGraphStore` 和 `CandidateSetStore` 重新读取对象并重算摘要。只有当前 Scope 为
`APPROVED`、时间窗口有效、Candidate 唯一且仍为 `PROPOSED`、Provider 结果通过且清理完成时，才能准备
接纳计划。接纳只生成 `CandidateRecommendationRecord`；记录固定
`candidate_unchanged=true`、`requires_human_selection=true`、
`producer_content_binding_verified=false` 和 `eligible_for_validation_intake=false`。

SQLite 账本以 plan、recommendation 和幂等键作唯一约束，采用 `started → completed` checkpoint。
完成结果可只读重放；遗留 `started`、完成记录篡改或身份冲突均要求显式恢复，不自动重试。

## 本地命令

以下两个命令都不读取模型凭据、不联网，也不调用 Runner、Broker 或目标：

```bash
vulnloom candidate-recommendation-prepare-local \
  --scope-file scope.json \
  --recommendation-file recommendation.json \
  --provider-result-file provider-result.json \
  --graph-store .vulnloom/graphs \
  --candidate-store .vulnloom/candidates \
  --recommendation-db .vulnloom/recommendations.db \
  --idempotency-key recommendation-001 > recommendation-plan.json

vulnloom candidate-recommendation-admit-local \
  --scope-file scope.json \
  --recommendation-file recommendation.json \
  --provider-result-file provider-result.json \
  --plan-file recommendation-plan.json \
  --graph-store .vulnloom/graphs \
  --candidate-store .vulnloom/candidates \
  --recommendation-db .vulnloom/recommendations.db
```

CLI 对普通错误只输出固定的 `recommendation_rejected` 或 `recommendation_timed_out`，避免把不可信正文
或异常内容写入日志。

## 专用模型生成链

`cuc-candidate-recommendation-v1` 已提供独立的无工具 codec、单次调用服务和权威账本。发送给模型的
`CandidateRecommendationProjection` 只包含 Candidate/Target/Scope 摘要、CWE、置信度、静态 Signal
类型与规则摘要，以及路径摘要和行号索引。源码、原始路径、Candidate 标题、假设、前置条件和反证文本
均不进入模型上下文。

模型必须返回精确 `projection_id`、优先级、简短理由、最多三个复核问题和投影内的位置索引。未知字段、
越界或重复索引、敏感文本、错误模型、工具调用、截断结果及超预算用量均拒绝。成功结果把投影、结构化
响应、Recommendation、Provider result/plan/receipt 和清理证明封存在一个
`CandidateRecommendationGenerationOutcome` 中，并固定
`producer_content_binding_verified=true`、`eligible_for_validation_intake=false`。

操作顺序是：

```bash
vulnloom candidate-recommendation-preview ...
vulnloom candidate-recommendation-generate-prepare ... > generation-plan.json
vulnloom candidate-recommendation-generate-approval-request \
  --scope-file scope.json --plan-file generation-plan.json > approval-request.json
vulnloom candidate-recommendation-generate-run ... --allow-provider-network
```

preview 和 prepare 不读取凭据、不联网；run 必须具备精确 `USE_REAL_CREDENTIALS` 人工批准、有效的
`MODEL_INFERENCE` egress grant 和显式联网选项。账本对 plan、幂等键、grant、approval 作唯一消费，
遗留 `started` 不自动重试。

## 当前限制与下一边界

专用生成结果尚未接入前述本地 admission ledger，也没有人工 Candidate selection 绑定，所以类型固定禁止
进入 M8.1。下一阶段是让 admission 只接受权威 completed generation outcome，再记录独立人工选择；现有
Validation Intake 与 Approval Gate 保持不变。首次真实 Candidate 投影调用仍需对 preview 的精确内容另行授权。

2026-09-08 本地验收：34 项定向测试通过；全量 1199 passed、23 skipped，覆盖率 86.59%。
`ruff check src tests scripts`、CLI 注册、Schema 重复导出、JSON 解析和 diff 空白检查均通过。

专用生成链新增 25 项测试；合并后全量 1224 passed、23 skipped，覆盖率 86.51%。测试覆盖成功、
内容/传输拒绝、审批和 Scope 漂移、超时、清理失败、只读重放、账本中断/篡改，以及 preview 不披露
源码与原始路径。
