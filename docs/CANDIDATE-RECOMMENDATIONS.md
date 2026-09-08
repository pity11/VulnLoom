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

## 当前限制与下一边界

本阶段建立的是确定性接纳边界，还没有实现生成 Candidate Recommendation 的专用 Provider codec、调用服务
和权威结果账本。当前 `ProviderProbeResult` 只能证明一次受控 Provider 调用完成并清理，不能证明
`CandidateRecommendation` 的正文来自该响应。因此这项能力尚不能称为“LLM 已参与 Candidate 排序”。

下一阶段需要让专用 codec 将发给模型的最小 Candidate 投影、响应正文摘要和解析后的 Recommendation
绑定在同一个密封结果中。任何真实调用仍需单独预览披露内容、精确人工审批、有效 egress grant 和显式
联网选项。模型结果接纳后仍只供人工选择，现有 M8.1 Validation Intake 与 Approval Gate 保持不变。

2026-09-08 本地验收：34 项定向测试通过；全量 1199 passed、23 skipped，覆盖率 86.59%。
`ruff check src tests scripts`、CLI 注册、Schema 重复导出、JSON 解析和 diff 空白检查均通过。
