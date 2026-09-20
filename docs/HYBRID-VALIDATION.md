# Hybrid Validation

R10 的首个可信纵切建立源码到 Live Target 的统一证据链，但不新增网络执行入口。

## 当前合同

- `DeploymentProof` 只保存源码 Target/version、manifest digest、部署产物 digest、Live Target ID、精确 endpoint URL digest、限时操作员证明和 Evidence 引用。它不保存 URL、发布系统凭据或原始发布响应。
- `HybridValidationPlan` 将一个源码 `Candidate`、一份 `DeploymentProof` 和一个既有 `ValidationPlan` 固定绑定到当前 Scope/version。初验固定期待 `reproduced`；修复复测固定期待 `not_reproduced` 并必须引用前一条 confirmed chain。
- `HybridValidationService` 只读取 `ValidationStore` 中权威的 completed outcome。动态 Validation 必须恰好包含一个指向封存 endpoint digest 的 Broker HTTP call，成功结果的 final URL digest 也必须相同。
- `HybridEvidenceChain` 合并源码、部署和 HTTP Evidence 为一个共享 `EvidenceBundle`。所有引用在封存前都经过内容寻址完整性复核。
- SQLite 账本提供 `started/completed/timed_out/failed` 状态、幂等重放、显式恢复和最多三次 attempt。超时或 Evidence 完整性失败以 cleanup proven 的 terminal outcome 关闭。
- `LiveEndpointReference` 只定位权限受限的本地配置槽。可信 adapter 在内存中解析并复核规范 URL、Scope 和 `DeploymentProof` endpoint digest；Worker、Route outcome 和公共 schema 不包含解析后的 endpoint。
- `HybridRouteService` 从 Source Candidate 和 Deployment Proof 自动生成单一精确 Live `ValidationPlan`。首版固定为无凭据、无 Header、无 body、禁重定向的单次 GET，且 Runner 环境仍为显式白名单。
- Route 账本只保存脱敏 outcome；完整 `ValidationPlan` 原子写入权限 `0600` 的可信本地计划仓，供后续 Validation Orchestration 读取。超时、拒绝或恢复耗尽不会留下可执行计划。

## 安全边界

当前 R10 服务不调用 Runner、Broker、模型或网络。Evidence admission 只接纳已有可信账本结果；Route materialization 只生成计划，不执行计划。普通输出和 JSON Schema 不包含完整 endpoint、Header、Cookie、API Key、认证响应或响应正文。Scope、部署证明、Candidate、Validation、endpoint digest 或 retest lineage 任一漂移均 fail-closed。

## 尚未完成的 R10 工作

- Hybrid Finding promotion 与同时引用源码/HTTP Evidence 的报告模板；
- 修复后源码静态验证与 Live Validation 的双重自动复测编排；
- CI/CD 发布门禁 adapter；
- 对隔离预发布应用的完整 R10 端到端验收。

本地离线验证：1465 项通过、27 项显式集成测试跳过，总覆盖率 85.78%；Ruff、386 个 JSON Schema 解析和 `git diff --check` 通过。验证未进行真实模型调用或网络请求。
