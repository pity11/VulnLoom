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
vulnloom provider --provider-db PATH bind-probe \
  --command-file FILE --probe-config-file LOCAL_FILE --probe-db AUTHORITATIVE_DB
vulnloom provider --provider-db PATH catalog-sync-offline \
  --request-file FILE --fixture-file FILE
vulnloom provider --provider-db PATH catalog-list
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

`bind-probe` 本身同样不联网、不读取 Provider token。它从既有权威 probe ledger 只读加载 completed
plan/result，并用本地 `ProviderProbeConfig` 复核 config digest、Provider、模型、credential ref、deadline、
attempt、receipt 和 cleanup。EndpointRef 只在可信 adapter 内临时解析，用来核对原 probe admission；完整
hostname 不写入 Provider Center command、binding、audit 或查询结果。CLI 以 SQLite `mode=ro` 打开 probe
ledger；错误路径或缺失文件会拒绝且不会创建一个看似权威的空数据库。

首个固定能力映射是保守闭集：CUC PONG 只证明 `chat` 与 `usage_accounting`；CUC 固定结构化 JSON probe
证明 `chat`、`strict_structured_output` 与 `usage_accounting`。调用方必须在 command 中声明完全相同的能力集，
少报或 overclaim 都拒绝。只有 source result 为 passed 且 process/attempt/receipt/cleanup 证明完整时才生成
Capability Manifest 并推进 lifecycle；rejected、timed_out 和 cleanup 未证明只形成脱敏 terminal binding。

`catalog-sync-offline` 支持 `manual` 与 `offline_fixture` 两种本地来源，并且 adapter 必须与 request 声明的
provenance 完全一致；它不会把本地 fixture 冒充为 Provider API 结果。目录条目仅包含安全字符集内的模型 ID、
显示名、别名、声明限制和可选价格元数据，不包含 endpoint、credential 或原始响应。每个不可变 snapshot 都绑定
确切 `provider_profile_digest` 和 receipt digest；Profile 更新 revision 后，旧 snapshot 不再出现在当前目录查询。

目录同步有独立 STARTED/completed checkpoint、超时和 cleanup 判定。跨 Provider/Profile 条目、重复或冲突别名、
条目超限、无 cleanup 证明、错误时间和不允许的 lifecycle 都会 fail-closed。成功同步可以把
`CONNECTIVITY_VERIFIED` 推进到 `CATALOG_DISCOVERED`，但目录声明本身不会生成 Capability Manifest、授予角色
或改变现有默认 Route。`provider list` 与 `provider catalog-list` 通过同一应用查询返回当前 revision 的目录。

现有 CUC/DeepSeek probe、代码审阅和 Candidate Recommendation CLI 默认路径未改变；因此迁移期间的默认
CUC 路由保持兼容。Provider Center 中的默认 Route 只影响显式使用该 registry 创建的新 Flow，不会静默接管
旧入口，也不会在失败时跨 Provider 降级。

## 当前边界

本纵切不包含 Web UI、HTTP server、Provider API 联网目录拉取、Keychain 写入、直接从 Provider Center 发起的真实 probe、
自动健康轮询、fallback 执行或成本统计。未来 API 应直接调用同一 application service，并继续只接收已导出的
严格 command/query schema，不得新增接收明文 Key 或 endpoint URL 的旁路。
