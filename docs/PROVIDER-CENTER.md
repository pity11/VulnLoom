# P2 Provider Center：可信本地控制面

Provider Center 首个纵切提供一个供 CLI 和未来 Web API 共用的 `ProviderCenterService`。它管理
Provider Profile 修订、能力探测结果、默认 Route 和脱敏审计，不读取或保存 API Key、完整 endpoint、
Authorization header 或 Provider 原始响应。

## 配置合同

所有变更都通过严格、内容寻址的 JSON command。Provider 配置只包含：

- `ModelEndpointReference.configuration_key`：可信 Control Plane 的 endpoint 配置槽；
- `ModelCredentialReference.environment_variable`：可信 Control Plane 的凭据槽；
- `ProviderProfile` 的协议、adapter、数据策略和允许的数据分类；
- 操作员的不可逆 `actor_ref` 摘要，不保存姓名或账号。

未知字段会被拒绝，因此不能在 command 中附加 `api_key`、URL、header 或响应正文。数据库默认位于被
Git 忽略的 `.vulnloom/provider-center.db`；即使如此，它仍只保存引用和脱敏状态。

## 生命周期和事务

注册把 canonical draft 原子推进到 `SECRET_BOUND`，只证明两个引用完整。更新总是创建新 revision，并把
生命周期重新置于 `SECRET_BOUND`，旧 Flow 仍可继续引用旧 revision。能力 probe 成功后依次封存
connectivity、catalog 和 capability 证据；失败或超时不会提升 lifecycle。

`enable` 必须携带至少一条将成为默认值的 `ModelRoute` 及其 `FallbackPolicy`。服务先用现有
`build_flow_model_snapshot` 对拟启用 Profile 执行 lifecycle、probed capability、data class、预算、
fallback 和引用校验，再在同一 SQLite 事务中写入 `ROLE_ADMITTED`、Route 和审计。禁用后，旧 Route
可以供审计查看，但新 Flow 的领域准入会因 Profile 非 `ROLE_ADMITTED` 而 fail-closed。

配置变更使用唯一 idempotency key；相同命令重放只读返回，冲突身份拒绝。Capability probe 在调用 adapter
前写入 `STARTED`，任何未知中断都要求显式恢复；通过、拒绝和超时都写入 terminal 结果与固定诊断码。
adapter 返回期间若 Profile lifecycle 漂移，完成事务拒绝写入。

## CLI

```text
vulnloom provider --provider-db PATH add --command-file FILE
vulnloom provider --provider-db PATH update --command-file FILE
vulnloom provider --provider-db PATH probe-offline --request-file FILE --fixture-file FILE
vulnloom provider --provider-db PATH enable --command-file FILE
vulnloom provider --provider-db PATH disable --command-file FILE
vulnloom provider --provider-db PATH list
vulnloom provider --provider-db PATH audit
vulnloom model-route --provider-db PATH set --command-file FILE
vulnloom model-route --provider-db PATH list
```

`probe-offline` 只使用类型化 fixture adapter，不创建 socket。真实 Provider 连通性仍只能通过已有的
`provider-probe-prepare` / `provider-probe-run --allow-provider-network`，需要独立有效 Egress Grant 和用户
明确授权。Provider Center 不会自动签发 Grant，也不会把 probe 结果解释为漏洞研究能力。

现有 CUC/DeepSeek probe、代码审阅和 Candidate Recommendation CLI 默认路径未改变；因此迁移期间的默认
CUC 路由保持兼容。Provider Center 中的默认 Route 只影响显式使用该 registry 创建的新 Flow，不会静默接管
旧入口，也不会在失败时跨 Provider 降级。

## 当前边界

本纵切不包含 Web UI、HTTP server、模型目录同步、Keychain 写入、真实 capability probe adapter、自动健康
轮询、fallback 执行或成本统计。未来 API 应直接调用同一 application service，并继续只接收已导出的严格
command/query schema，不得新增接收明文 Key 或 endpoint URL 的旁路。
