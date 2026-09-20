# Hybrid Validation and Finding Promotion

R10 的可信离线纵切建立源码到 Live Target 的统一证据链和 Finding 晋升门禁，但不新增网络执行入口。

## 当前合同

- `DeploymentProof` 只保存源码 Target/version、manifest digest、部署产物 digest、Live Target ID、精确 endpoint URL digest、限时操作员证明和 Evidence 引用。它不保存 URL、发布系统凭据或原始发布响应。
- `HybridValidationPlan` 将一个源码 `Candidate`、一份 `DeploymentProof` 和一个既有 Live `ValidationPlan` 固定绑定到当前 Scope/version。初验固定期待 `reproduced`；修复复测必须引用前一条 confirmed chain，并额外绑定一条独立、无 Broker call 和 HTTP assertion 的源码回归 `ValidationPlan`。
- `HybridValidationService` 只读取 `ValidationStore` 中权威的 completed outcome。动态 Validation 必须恰好包含一个指向封存 endpoint digest 的 Broker HTTP call，成功结果的 final URL digest 也必须相同。
- 修复复测要求源码回归和精确 Live Validation 独立完成且都得到 `not_reproduced`。源码侧 Evidence 必须与源码 Validation Bundle 完全一致，随后封存为 `SourceRemediationProof`；失败、超时、无 Evidence 或单边通过均 fail-closed，不能生成 `remediated` chain。
- `HybridEvidenceChain` 合并源码、部署和 HTTP Evidence 为一个共享 `EvidenceBundle`。所有引用在封存前都经过内容寻址完整性复核。
- SQLite 账本提供 `started/completed/timed_out/failed` 状态、幂等重放、显式恢复和最多三次 attempt。超时或 Evidence 完整性失败以 cleanup proven 的 terminal outcome 关闭。
- `LiveEndpointReference` 只定位权限受限的本地配置槽。可信 adapter 在内存中解析并复核规范 URL、Scope 和 `DeploymentProof` endpoint digest；Worker、Route outcome 和公共 schema 不包含解析后的 endpoint。
- `HybridRouteService` 从 Source Candidate 和 Deployment Proof 自动生成单一精确 Live `ValidationPlan`。首版固定为无凭据、无 Header、无 body、禁重定向的单次 GET，且 Runner 环境仍为显式白名单。
- Route 账本只保存脱敏 outcome；完整 `ValidationPlan` 原子写入权限 `0600` 的可信本地计划仓，供后续 Validation Orchestration 读取。超时、拒绝或恢复耗尽不会留下可执行计划。
- `HybridFindingPromotionService` 只接受权威 completed、initial、confirmed 的 `HybridEvidenceChain`。Critic 必须针对该链的完整合并 `EvidenceBundle` 独立复核，不能复用只看过源码证据的旧裁决。
- Finding 晋升还要求当前 Scope、clear duplicate check 和内容绑定的人工 Approval。事务账本提供幂等重放、显式恢复、三次 attempt 上限、超时和清理证明；生成的 Finding 直接引用 Hybrid Chain 的 Evidence Bundle。
- `HybridReportService` 只从权威 completed Hybrid Finding 生成本地 Draft，并复用共享的确定性 Report 服务。代码位置必须引用 Source Evidence，请求响应和影响必须引用 HTTP Evidence，复现章节必须同时引用 Deployment 与 HTTP Evidence。
- Hybrid Report 账本只绑定 digest 和既有本地 Report outcome，支持幂等、显式恢复、超时和清理。标题与章节拒绝完整 endpoint；本纵切不批准、导出或提交 Report。
- `HybridReleaseGateService` 只从权威 Hybrid 账本读取一条已知缺陷链，并重新核对当前 Scope、Deployment Proof、源码版本、manifest、Live Target 和 endpoint digest。只有带一致 `SourceRemediationProof` 的 `remediated` chain 才得到 `passed`；原始 confirmed chain 得到 `blocked`。
- `HybridCiGateAdapter` 将门禁结果投影为稳定的 `pass/block/error` 与退出码 `0/1/2`。输出只包含 plan/result digest 和固定 reason code；输入漂移、超时、恢复要求或账本异常都返回非零，不暴露 endpoint、异常文本或认证材料。
- Release Gate 使用独立 SQLite checkpoint，覆盖幂等重放、显式恢复、三次 attempt 上限、预算超时和 cleanup proof。它不执行部署、不调用 CI 平台 API，也不授予 Submission 或其他外部副作用。

## 安全边界

当前 R10 服务不调用 Runner、Broker、模型或网络。Evidence admission、双重复测协调、Finding promotion、Report drafting 和 Release Gate 只接纳已有可信账本结果；Route materialization 只生成计划，不执行计划。普通输出和 JSON Schema 不包含完整 endpoint、Header、Cookie、API Key、认证响应或响应正文。Scope、部署证明、Candidate、源码/Live Validation、Critic、Approval、Finding、Report、endpoint digest、retest lineage 或门禁输入任一漂移均 fail-closed。

## R10 验收状态

R10 计划内纵切已完成。隔离预发布验收使用显式 `VULNLOOM_HYBRID_E2E_INTEGRATION=1` 开关，仅在本机私网地址启动临时 HTTP fixture，并通过 pinned peer allowlist 访问单一固定路径。验收覆盖源码分析和 Candidate 生成、精确 Live 初验、Critic、人工批准后的 Finding、本地 Report Draft、修复源码静态回归、同一 endpoint Live 复测、`SourceRemediationProof`、Release Gate PASS，以及 fixture 进程清理；默认测试不会打开 socket。

本地离线验证：1478 项通过、28 项显式集成测试跳过，总覆盖率 85.77%；Ruff、396 个 JSON Schema 解析和 `git diff --check` 通过。隔离预发布验收另以显式开关完成 1 项真实本机私网 socket 测试；未进行真实模型调用、公网访问或外部提交。
