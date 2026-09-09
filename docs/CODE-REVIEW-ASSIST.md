# 只读代码审阅助手

本入口将人工选定的 Python 代码片段发送给密封计划选择的模型 Provider，返回代码解释和待核查建议。
结果始终是未经人工确认的审阅材料，不是 Candidate、Finding 或漏洞验证结果。
实现位于 `src/vulnloom/review_assist/`，不接入 Agent 的工具选择、Validation 或 Submission。

当前 CLI 保留 CUC/DeepSeek 默认配置。服务层同时支持由已准入 `ProviderProfile`、`CapabilityManifest` 和
`FlowModelSnapshot` 组装的通用 Profile 路径；Provider Center CLI/API 完成前，该路径只供可信应用装配，
不接受用户在计划内直接填写 URL、API Key 或任意模型参数。

## 输入和隐私边界

- 仅接受当前有效 Scope 中已导入的 Target Snapshot；操作方明确指定一个 `.py` 文件和行号范围。
- 源文件必须是 UTF-8、语法可解析的 Python，最多 64 KiB。片段最多 80 行、12,000 UTF-8 字节。
- 只读校验清单大小和 SHA-256，拒绝路径穿越、文件及中间目录符号链接、非普通文件和越界选择。
- AST 和 tokenizer 只解析文件，不导入或执行目标代码。发送前移除全部字面量和注释，包括多行字符串、
  f-string 与数字，再使用现有 Redactor 处理剩余文本。保留原始行号。
- 脱敏会损失常量值、字符串内容和注释语义。变量名、函数名和代码结构仍然可见，可能含业务机密；
  人工必须检查预览并确认允许向指定 Provider 披露。脱敏规则不是通用个人信息识别器。
- 模型只接收脱敏行、输入摘要、固定审阅说明和响应 Schema，不接收原始路径、完整项目或原始认证响应。

## 操作流程

先通过已有导入流程准备授权 Scope 和 Snapshot，然后仅本地预览：

```bash
vulnloom code-review-preview \
  --scope-file scope.json --store .vulnloom/targets \
  --snapshot-id REVIEW_SNAPSHOT_ID --source-path app.py \
  --start-line 10 --end-line 25
```

运营方通过既有 Control Plane 授权流程签发 `MODEL_INFERENCE` grant，绑定计划中的 exact transport
Admission 及预算。默认 CLI 使用 `cuc_probe_admission()` 和 `CUC_DEEPSEEK_API_KEY` 引用；通用装配只接受
Profile 中的 Endpoint/Credential reference。设置 Key、生成预览或创建计划均不会签发授权，命令不解析
`.env`。

准备与指定片段、Scope、模型配置和 grant 绑定的密封计划：

```bash
vulnloom code-review-prepare \
  --scope-file scope.json --store .vulnloom/targets \
  --snapshot-id REVIEW_SNAPSHOT_ID --source-path app.py \
  --start-line 10 --end-line 25 \
  --egress-store AUTHORITATIVE_EGRESS_STORE --grant-id ISSUED_GRANT_ID \
  --idempotency-key human-review-001 --ttl-seconds 60 > review-plan.json
```

检查命令退出码为 0。计划包含实际将被发送的脱敏片段；审批必须针对这份计划的 `plan_id`。
可生成尚未批准的审批请求：

```bash
vulnloom code-review-approval-request \
  --scope-file scope.json --plan-file review-plan.json > approval-request.json
```

审批动作是 `USE_REAL_CREDENTIALS`，`expected_side_effects` 明确说明：发送精确片段到所选 Provider、
消费模型 tokens、在本地保存人工审阅材料。请求默认 `pending`；没有自动批准命令。
运营方在现有人工审批流程中确认请求，提供带决定人、决定时间和有效期的 `ApprovalRequest`。
它必须匹配 Engagement、Target、Scope 版本和计划摘要，决定时间不得早于计划创建时间。

随后执行一次已批准调用：

```bash
vulnloom code-review-run \
  --scope-file scope.json --store .vulnloom/targets --source-path app.py \
  --plan-file review-plan.json --approval-file approved-review.json \
  --egress-store AUTHORITATIVE_EGRESS_STORE --review-db .vulnloom/code-reviews.db \
  --allow-provider-network
```

执行前会重新核验源码、Scope、审批、grant 和期限。请求只含固定的系统说明与当前片段，
没有工具定义或任何执行接口；模型输出不能改变领域状态。最多一次 Provider 调用，输出上限
512 tokens，输入输出合计超过 8192 tokens 时拒绝结果；复用现有 10 秒传输和 32 KiB 字节限制。
短时 grant 的撤销仍由现有运营方授权流程负责，本入口不会自行创建、批准或续期授权。

## 输出、重放和失败

结果状态为 `review_ready`、`rejected` 或 `timed_out`，固定包含 `requires_human_review=true`。
只有传输身份、内容结构、用量和清理证明均通过，才保存最多四条带行号的解释/建议。
每条引用必须有序、唯一，且落在本次实际提供的非空行中；输入摘要也必须完全一致。
额外字段、工具调用、错误模型、截断回复、重复 JSON 键、已知敏感文本和控制字符均拒绝。

引用校验只证明行号属于输入，不能证明模型解释与代码的语义一致，也不能证明代码没有问题。
不执行模型文本中的任何建议；系统说明用于约束输出风格，实际权限由无工具接口、审批和类型校验强制。

SQLite 账本使用事务完成 `未领取 → started → completed` 转移，计划、幂等键、grant 和审批 ID
均有唯一约束。重放只读取并复核完成结果，不再调用 Provider；仍要求当前 Scope、审批及 grant 有效。
写入中断保留 `started`，要求人工核查，不自动恢复或重试。必须始终使用同一权威 review 账本，
不得通过更换数据库或幂等键绕过单次执行限制。

普通错误只输出固定状态码。账本保存脱敏输入和经过校验的审阅文本，不保存原始响应、reasoning、
原始凭据或异常正文。缺少最终 attempt 记录或清理证明时不得返回 `review_ready`。

## 验收范围

本轮使用合成代码与 fake DNS/process 验证成功、拒绝、超时、清理、CLI 和重放路径。
此前真实固定 JSON 探针的通过记录不等于本功能的真实模型验收。首次真实代码审阅验收记录见下节。

2026-09-08 本地验证：新增 43 项审阅测试通过；全量 1165 passed，23 项集成测试排除，
覆盖率 86.49%。`ruff check src tests scripts`、Schema 重复导出一致性和 diff 空白检查通过。

2026-09-09 增加 Profile-routed 只读审阅纵切。通用 task codec registration 与既有 Profile preparation、
当前 Provider lifecycle、Flow binding、Worker role、模型、预算和 active Grant 精确绑定；运行适配器只依赖
`ProviderWireCodec` 协议。使用第二个合成 Provider 验证了成功、模型身份拒绝、传输超时、清理失败、只读
重放以及 credential/request/response 清理。CUC 专用 codec 与默认 CLI 行为保持兼容。

## 首次真实代码审阅验收（2026-09-08）

用户明确授权将已预览的 VulnLoom `source.py` 第 28–46 行脱敏片段发送到固定 CUC 网关。
目标是已提交并导入的 `43710b8d13fc47837ade68c00bcc26710b38da90` 快照；发送内容中的
字符串、数值和注释均已掩蔽。调用未携带工具、完整项目、原始路径或凭据。

- 执行一次，无自动重试；`status=review_ready`，`requires_human_review=true`。
- HTTP 200、TLSv1.3，响应模型 `deepseek-v4-flash-0731`，输入/输出 890/303 tokens。
- `content_classification=response_content_exact`，响应 1845 bytes，行号与输入摘要校验通过。
- Result ID：`2cc496c7d2626d2fa145922b611d827bd2c4c56cfbf5ccd28636bf5e45b75f93`。
- Receipt digest：`67a54548fe8118aeaebaa2c73f14fbe8e74d9fe6f4aee344bdcd828ee88cb47f`。
- `cleanup_verified=true`；短时 grant 已撤销。离线复核确认一个 completed ledger 条目、
  密封结果一致且本地记录不含原始凭据。

人工质量核查发现：模型对 `O_NOFOLLOW`、逐级目录打开、普通文件/大小检查和二次长度检查的解释
基本准确；但“`finally` 可能重复关闭描述符”的建议不符合该片段的实际控制流。目标文件描述符由
`fdopen` 管理，`finally` 关闭的是当前目录描述符。这次结果证明真实只读审阅链可以工作，
也证明结构和引用校验不能替代语义核查，输出必须继续由人工审阅。
