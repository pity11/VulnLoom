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
`CandidateRecommendationGenerationOutcome` 中。只有 `recommendation_ready` 才标记
`producer_content_binding_verified=true`；拒绝和超时结果为 false。所有结果均固定
`eligible_for_validation_intake=false`。

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

成功生成后只能通过权威 generation ledger 接纳，不能把调用方提供的 Recommendation 或 Provider result
冒充为正文绑定证明：

```bash
vulnloom candidate-recommendation-generated-prepare-local \
  --scope-file scope.json --generation-db generations.db \
  --generation-plan-id GENERATION_PLAN_ID \
  --graph-store .vulnloom/graphs --candidate-store .vulnloom/candidates \
  --recommendation-db .vulnloom/recommendations.db \
  --idempotency-key generated-admission-001 > admission-plan.json

vulnloom candidate-recommendation-generated-admit-local \
  --scope-file scope.json --generation-db generations.db \
  --plan-file admission-plan.json \
  --graph-store .vulnloom/graphs --candidate-store .vulnloom/candidates \
  --recommendation-db .vulnloom/recommendations.db
```

该路径重新校验 generation plan、completed outcome、投影、Provider receipt、清理证明与当前权威
Candidate/SourceGraph。成功记录绑定 generation plan/outcome ID 与摘要，并标记
`producer_content_binding_verified=true`；Candidate 仍保持 `PROPOSED`，记录仍要求独立人工选择且不能进入
Validation Intake。旧的本地 advisory admission 仍可读取和重放，但其正文绑定标记保持 false。

generated admission 新增 4 项成功、拒绝、超时、重放及 CLI 回归；合并后全量 1237 passed、23 skipped，
覆盖率 86.48%。真实成功 generation outcome 的离线接纳验收也通过，账本只有一个 completed 记录。

## 人工选择与本地 Web UI

人工选择只消费权威 generated admission record，并从 generation ledger 重新核对 Recommendation、outcome、
Provider result 与当前 Candidate/SourceGraph。`accept`、`reject` 是终态；`defer` 可由后续新命令继续处理。
所有决定使用独立 `started → completed` SQLite checkpoint。`accept` 只令选择记录具备
`eligible_for_validation_intake=true`，不会修改 Candidate 或启动 Validation，后续仍需独立 Validation
计划与 Approval Gate。

CLI 支持分离的 prepare/record：

```bash
vulnloom candidate-recommendation-selection-prepare-local \
  --scope-file scope.json --generation-db generations.db \
  --recommendation-db recommendations.db --selection-db selections.db \
  --graph-store .vulnloom/graphs --candidate-store .vulnloom/candidates \
  --admission-record-id ADMISSION_RECORD_ID --decision accept \
  --reviewer-id workspace-owner --idempotency-key selection-001 > selection-command.json

vulnloom candidate-recommendation-selection-record-local \
  --scope-file scope.json --generation-db generations.db \
  --recommendation-db recommendations.db --selection-db selections.db \
  --graph-store .vulnloom/graphs --candidate-store .vulnloom/candidates \
  --command-file selection-command.json
```

本地 UI 使用同一领域服务，可通过以下命令启动：

```bash
vulnloom candidate-recommendation-review-web \
  --scope-file scope.json --generation-db generations.db \
  --recommendation-db recommendations.db --selection-db selections.db \
  --graph-store .vulnloom/graphs --candidate-store .vulnloom/candidates \
  --reviewer-id workspace-owner --port 8765
```

服务固定监听 `127.0.0.1`，不接受自定义监听地址，不加载外部脚本、字体或资源。页面使用 CSRF、Host、Origin、
请求大小和闭集字段校验，禁用缓存并设置 CSP。决定采用两步确认：先显示 exact command digest，再写账本。
浏览器不接触模型凭据或网关配置。

2026-09-08 本地验收：新增 7 项默认回归通过、1 项真实 loopback socket 集成回归通过；全量
1244 passed、24 skipped，覆盖率 86.14%。桌面与 375px 移动视口均完成实际浏览器检查，过程中未提交决定。

## 当前限制与下一边界

专用生成结果已经可以接入本地 admission ledger，并由独立人工选择记录 accept/reject/defer。现有
Validation Intake 尚未接受这类选择记录；下一阶段是增加只读 intake adapter，重新核对 accepted selection
及其完整来源。动态执行仍必须经过现有 Validation 与 Approval Gate。

2026-09-08 本地验收：34 项定向测试通过；全量 1199 passed、23 skipped，覆盖率 86.59%。
`ruff check src tests scripts`、CLI 注册、Schema 重复导出、JSON 解析和 diff 空白检查均通过。

专用生成链新增 25 项测试；合并后全量 1224 passed、23 skipped，覆盖率 86.51%。测试覆盖成功、
内容/传输拒绝、审批和 Scope 漂移、超时、清理失败、只读重放、账本中断/篡改，以及 preview 不披露
源码与原始路径。

## 首次真实 Candidate 推荐验收（2026-09-08）

用户明确授权将 `projection_id=b21fa340a44f607e70c9027aaa7147d8dd5753ca0279f7a0501a971366048b37`
的合成 CWE-639 最小投影发送到固定 CUC 端点一次。调用无工具、无重试；HTTP 200、TLSv1.3，
但模型正文未通过严格响应协议，闭集诊断为 `response_content_other`，因此结果正确拒绝且没有生成
Recommendation。Result ID 为 `fda33e50ab216f3d374468f66bacc88ff7a9b3af7aafac9eac082dcf3442663c`，
Outcome ID 为 `0fb313ddc7ec06dd248291e8a1aa51817e23d80470b5b889b2be1c2d84d0ee7c`。
`cleanup_verified=true`，账本只有一个 completed 条目，grant 已撤销，凭据未进入验收 artifacts。

该 v1 拒绝 artifact 在字段命名修正前生成，历史 JSON 中的
`producer_content_binding_verified=true` 表示当时启用了绑定协议，并不表示正文校验通过。后续实现已改为
仅在 `recommendation_ready` 时写 true；判断历史结果必须同时检查 `status`。

首次拒绝后新增闭集内容结构诊断。诊断只能保存代码定义的类别，例如 JSON 无效、根对象类型、必需或
额外字段、projection ID 类型/不匹配、priority 类型/取值、理由为空/超长/未裁剪/不安全、问题列表
类型/数量/条目安全，以及位置索引类型/数量/顺序/越界。未知字段名、字段值、正文和 reasoning 均不会
进入诊断。该诊断只解释拒绝分支，不参与接受判定，也不允许重放或自动重试。

闭集诊断新增 9 项回归测试；合并后全量 1233 passed、23 skipped，覆盖率 86.49%。
`ruff check src tests scripts`、Schema 重复导出和 diff 空白检查均通过。
