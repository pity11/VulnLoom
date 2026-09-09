# VulnLoom 多模型 Provider Center 设计

状态：`DRAFT_FOR_REVIEW`

版本：`0.1`

日期：`2026-09-08`

## 1. 目标

VulnLoom 必须允许用户像管理开发工具模型配置一样添加、检测和切换多个 LLM，同时保留安全研究所需的可复现性、
数据边界和审计能力。用户体验参考 CC Switch 的 Provider 管理与一键切换思路，但内部不能把配置文件替换当成
完整模型治理。

Provider Center 需要回答五个问题：

1. 用户可以把哪些模型接入 VulnLoom；
2. 每个模型实际支持哪些协议与能力；
3. Source Hunt、Red Team、Validator、Critic 等角色分别使用哪个模型；
4. 切换或故障转移后，进行中的安全调查是否仍可复现；
5. 源码、Evidence、凭据和目标信息会发送到哪里。

## 2. 产品原则

### 2.1 统一体验，不伪造统一能力

平台提供统一的添加、探测、路由、预算和审计界面。不同 Provider 的结构化输出、工具调用、流式传输、推理模式、
图像输入、上下文长度和计费语义并不相同，必须由 adapter 和 Capability Manifest 显式表达。

Provider 品牌或模型名称不能直接证明能力。只有对应探测通过后，模型才能被分配到需要该能力的角色。

### 2.2 VulnLoom 协议是规范层

领域层只接受 VulnLoom 的类型化 `AgentTurnRequest`、`AgentTurnResult`、`ToolProposal` 和 Usage 数据。Provider
adapter 负责把它们转换为外部协议。Provider 原生工具调用只能生成待审查的 `ToolProposal`，不能直接调用工具、
改变领域状态或绕过 Broker。

### 2.3 模型切换必须可复现

工作区的“一键切换”改变新 Flow 的默认模型。一个 Flow 创建时生成不可变 `FlowModelSnapshot`，固定：

- Provider Profile 版本；
- 模型标识和协议 adapter；
- 能力清单版本；
- 角色路由和 Fallback Policy；
- Prompt/Tool schema 版本；
- 数据处理策略；
- Token、成本、轮数和超时预算。

进行中的 Flow 不随全局默认值漂移。操作员可以发起显式迁移，但迁移会形成新 checkpoint、记录原因并重新执行
能力与数据策略准入。

### 2.4 密钥与私有端点不进入项目文件

仓库只保存 schema、无秘密示例和公开 Provider 模板。以下内容不得写入受版本控制的配置、普通日志、Evidence、
FTS 或模型上下文：

- API Key、Session Token 和刷新凭据；
- 私有模型网关地址和租户路径；
- Provider 完整认证响应；
- 能反推出凭据的请求头或诊断转储。

Control Plane 将秘密写入操作系统 Keychain、部署 Secret Manager 或权限受限且被 Git 忽略的本地存储。领域对象
只保留 `CredentialRef` 和 `EndpointRef`。Worker 不获得引用和值，Provider transport 通过短生命周期租约读取。

### 2.5 数据去向先于模型选择

每个 Provider Profile 声明数据处理标签，例如：

- `local_only`；
- `organization_approved`；
- `external_standard`；
- `no_source_code`；
- `no_auth_material`；
- `retention_unknown`。

Flow 创建页面必须显示目标数据将发送到哪个 Provider。Context Builder 先按数据分类生成允许投影，Router 再选模型。
如果没有同时满足能力与数据策略的模型，任务 fail-closed，而不是偷偷降级到另一个外部 Provider。

## 3. 支持的协议族

首期以协议 adapter 为单位接入，不为每个模型品牌复制业务逻辑：

| Adapter | 用途 | 首期状态目标 |
| --- | --- | --- |
| OpenAI Responses | 支持 Responses 风格服务 | 合约与假服务准入 |
| OpenAI Chat Completions | 兼容广泛的 Chat API 与网关 | 首个通用实时 adapter |
| Anthropic Messages | Claude 与兼容服务 | 通用实时 adapter |
| Gemini GenerateContent | Gemini 原生协议 | 后续 adapter |
| Local OpenAI-compatible | Ollama、vLLM、LM Studio 等本地部署 | 本地模型路径 |

CUC/DeepSeek 从固定实现迁移为一个普通 `ProviderProfile`，继续作为已知兼容性 fixture。Provider 与模型必须分开：
同一个 Provider 可以提供多个模型，同一个模型系列也可能通过不同 Provider 或网关提供。

在产品早期，CUC/DeepSeek 是默认开发、联调和显式实时验收 Provider。多模型改造必须保留现有固定 PONG、固定
结构化 JSON、人工代码审阅和 Candidate 建议调用路径；新 adapter 未完成等价验收前，不删除、不改写其凭据引用，
也不让未准入的通用 Router 接管这些路径。默认 CI 继续使用假 Provider，真实 CUC 调用只在操作员显式授权后运行。

首期不建设常驻的通用协议转换代理。adapter 在 Control Plane 边界内完成转换，可以减少额外网络监听面、认证复制和
单点故障。若以后确有多个客户端共享代理的需求，再以独立 Threat Model 和 ADR 评估。

## 4. 领域模型

### 4.1 ProviderProfile

```text
ProviderProfile
├── provider_id
├── display_name
├── protocol_adapter_id
├── endpoint_ref
├── credential_ref
├── data_policy_id
├── organization_scope
├── enabled
└── revision
```

Profile 是非秘密配置与秘密引用的组合。修改端点、凭据、协议或数据策略必须增加 revision；旧 Flow 继续引用旧版本，
直至完成、取消或显式迁移。

### 4.2 ModelCatalogEntry

```text
ModelCatalogEntry
├── provider_id
├── provider_model_id
├── display_name
├── aliases
├── declared_limits
├── pricing_metadata
└── catalog_observed_at
```

模型目录可以由 Provider 拉取或人工登记。拉取结果只是目录信息，不能自动成为已准入模型。

### 4.3 CapabilityManifest

能力清单至少包括：

- 普通对话与系统指令；
- 严格 JSON 或 schema 约束输出；
- 原生工具提案；
- 流式传输；
- 推理参数；
- 图像输入；
- 最大上下文与输出；
- usage 和成本字段；
- stop、timeout 和 cancellation 行为；
- 并发和速率限制。

每项记录 `declared | probed | failed | unknown`、探测版本和时间。需要结构化输出的 Agent 角色只能使用
`probed` 的模型能力。

### 4.4 ModelRoute

```text
ModelRoute
├── route_id
├── engine
├── agent_role
├── primary_model_ref
├── fallback_policy_ref
├── required_capabilities
├── data_policy_constraint
└── budget_profile
```

首期角色路由建议：

| 角色 | 关注能力 | 典型路由策略 |
| --- | --- | --- |
| Planner | 长上下文、稳定结构化输出、推理 | 优先高可靠模型 |
| Recon / Extractor | 工具 schema、吞吐和成本 | 可使用较快模型 |
| Source / Web Agent | 代码或页面理解、工具提案 | 按 Engine 独立配置 |
| Validator | 精确实验设计、低幻觉 | 使用强模型并限制温度与重试 |
| Critic | 独立反证 | 可配置不同模型或不同上下文 |
| Reporter | 长文本与证据引用 | 只接收可披露投影 |

Critic 使用不同模型可以增加视角差异，但不能作为独立性的唯一证明。它仍必须使用不同上下文、反证任务和确定性
Finding Gate。

### 4.5 FallbackPolicy

Fallback 必须声明：

- 允许触发的错误类型；
- 最大尝试次数和总时间；
- 可选模型的优先序；
- 能力与数据策略的交集；
- 是否允许跨 Provider；
- 预算上限；
- 是否需要操作员批准。

仅在模型调用没有提交外部副作用时允许自动 Fallback。超时、限流和明确的临时服务错误可以重试；协议解析失败、
含糊响应或已执行工具后的重试不得自动换模型重复整个步骤。每次选择、跳过和失败都写入脱敏审计事件。

## 5. Provider 生命周期与准入

Provider 和模型使用显式状态，不用一个“已连接”覆盖所有能力：

```text
DRAFT
  → SECRET_BOUND
  → CONNECTIVITY_VERIFIED
  → CATALOG_DISCOVERED
  → CAPABILITIES_PROBED
  → ROLE_ADMITTED
  → DISABLED | DEGRADED | REVOKED
```

- `SECRET_BOUND`：只证明有不透明凭据引用；
- `CONNECTIVITY_VERIFIED`：固定、无敏感内容的请求成功；
- `CATALOG_DISCOVERED`：可以获取或人工登记模型目录；
- `CAPABILITIES_PROBED`：目标能力完成结构化探测；
- `ROLE_ADMITTED`：满足指定角色的能力、数据、预算和传输策略；
- `DEGRADED`：近期健康或能力探测失败，新 Flow 可按策略拒绝；
- `REVOKED`：凭据或 Provider 被撤销，不能创建新租约。

连接测试只发送合成内容。真实源码、Evidence 和目标信息不得用于 Provider 配置探测。

## 6. 路由顺序

模型选择由可信 Router 确定，Agent 文本无权指定 Provider：

```text
Flow 固定快照
  → Task 显式且已批准的模型选择
  → Engine + AgentRole 路由
  → Workspace 默认模型
  → 无可用模型则拒绝
```

Router 依次校验：

1. Provider 与凭据处于可用状态；
2. adapter 和 transport 已准入；
3. Capability Manifest 满足角色要求；
4. 数据策略允许当前 Context Projection；
5. Token、成本、并发和时间预算允许；
6. Provider Egress Grant 精确匹配；
7. 模型未被 Flow 或组织策略禁止。

最终选择写入 `ModelSelectionDecision`，包含理由、被排除选项和配置摘要，但不包含密钥或私有端点。

## 7. 用户体验

### 7.1 Provider Center

Provider Center 主页面展示卡片：

- Provider 名称、协议与状态；
- 已登记模型数量；
- 最近一次连接与能力探测；
- 延迟、错误率和用量摘要；
- 数据处理标签；
- 当前承担的 Engine/角色；
- 添加、编辑、禁用、复制、测试、同步模型和设为默认操作。

用户可以从公开模板添加 Provider，也可以选择“自定义兼容接口”。表单流程为：

```text
选择协议
  → 输入显示名称
  → 在受限秘密控件中输入端点和 Key
  → 保存为 EndpointRef / CredentialRef
  → 连接测试
  → 获取或登记模型
  → 能力探测
  → 分配角色
```

保存后 UI 不重新读取或显示完整 Key 和私有端点。更新凭据使用替换操作，撤销会终止尚未发放的租约。

### 7.2 Model Routing

路由页面同时支持简单模式与高级模式：

- 简单模式：选择 Source Hunt 默认模型和 Red Team 默认模型；
- 高级模式：按 Planner、Agent、Validator、Critic、Reporter 分配模型与 Fallback；
- 任务覆盖：创建 Flow 时在策略允许范围内临时选择；
- 预览：在运行前显示每个角色、Provider、模型、数据标签和预算；
- 固定：创建 Flow 后显示快照摘要，默认值变化不会影响它。

### 7.3 健康与成本

健康页只使用合成探测与脱敏指标，显示：

- 首 Token 和总响应延迟；
- 成功率、限流、超时和协议错误；
- 输入/输出 Token 与估算成本；
- 每个 Engine、角色和 Flow 的预算消耗；
- 当前降级、禁用和凭据即将失效状态。

价格元数据允许人工覆盖，并标记观察时间。缺少可靠价格时显示 usage，不伪造成本。

## 8. API 与 CLI 草案

首期资源：

```text
/providers
/providers/{id}/credentials:replace
/providers/{id}/connectivity-probes
/providers/{id}/models:sync
/models/{id}/capability-probes
/model-routes
/flows/{id}/model-snapshot
```

CLI 对应提供：

```text
vulnloom provider add
vulnloom provider test
vulnloom provider models
vulnloom provider disable
vulnloom model probe
vulnloom model route set
vulnloom model route explain
```

CLI 不接受在命令行参数中直接传 Key，避免 shell history 和进程列表泄漏。Key 通过交互式秘密输入、stdin 的专用
受限通道或部署 Secret Manager 绑定。

## 9. 测试与完成标准

每个 adapter 必须通过同一套 Provider Contract Suite：

- 成功、认证拒绝、限流、超时、断流和畸形响应；
- JSON/schema、工具提案、usage 与 cancellation；
- 凭据不进入 Worker 环境、错误文本、checkpoint 或事件；
- 私有端点不进入普通日志、Evidence 和报告；
- 切换后新 Flow 使用新快照，旧 Flow 保持原快照；
- Fallback 不跨越能力、数据政策和预算；
- 重试幂等且有上限；
- transport 和临时租约完成清理。

测试分层：

1. 纯领域测试：路由、状态机、能力匹配和快照；
2. adapter 合约测试：本地假 HTTP 服务；
3. 隔离集成测试：本地 TLS、代理、取消和失败注入；
4. 显式启用的实时探测：只发送合成内容，不在默认 CI 运行；
5. 角色准入测试：结构化 Agent 回合和无副作用工具提案。

Provider 只有同时具备成功、拒绝、超时、取消、清理和秘密泄漏回归测试，才能标记为 `ROLE_ADMITTED`。

## 10. 从当前 CUC 路径迁移

### 10.1 兼容性不变量

迁移期间必须始终满足：

- `CUC_DEEPSEEK_API_KEY` 的现有凭据引用继续有效；
- 固定 PONG 和固定结构化 JSON 探测继续产生相同的密封计划、准入结果与清理证明；
- 已准入的人工代码审阅和 Candidate 建议路径继续使用原有固定合同；
- 新 Provider 类型、Router 或 UI 不能改变现有 CUC 请求，除非等价合约和显式实时回归均已通过；
- 默认离线测试不访问 CUC，实时验收仍需有效 Egress Grant 和用户明确授权；
- 任一迁移验收失败时，默认路由保持在现有 CUC 路径，不能以降级方式静默发送到其他 Provider。

### 10.2 旁路迁移步骤

迁移顺序：

1. 冻结现有 CUC 行为、摘要和拒绝路径作为兼容基线；
2. 增加通用 ProviderProfile、CredentialRef、EndpointRef 和 adapter 协议，不改现有调用路径；
3. 将现有固定 CUC 合同包装为第一个 Profile adapter，同时保留原入口作为回退；
4. 在功能开关后实现 OpenAI-compatible adapter，先只连接假 Provider；
5. 用同一组固定合成请求对旧路径与新路径进行差分合约测试；
6. 经用户明确授权，对新路径执行一次真实 CUC PONG 和结构化 JSON 验收；
7. 只有旧路径与新路径的成功、拒绝、超时、清理、身份和 usage 结果等价时，才把开发默认路由切到新 adapter；
8. 实现 Provider Center 的本地 API、CLI、Capability Probe 与 ModelRoute；
9. 接入第二种协议 adapter，证明设计没有被首个 Provider 绑死；
10. 加入 UI、成本、健康视图和受约束 Fallback。

旧入口的删除不属于 P1。新路径至少完成一个发布周期的回归且有独立 ADR 后才能移除；在此之前，它是明确的兼容
回退，不是两套业务逻辑长期分叉。

现有 CUC 实时调用通过，只代表一个固定 Profile 的传输与响应准入，不代表通用多模型能力已完成。

## 11. 里程碑

### P0：领域协议（已完成离线实现）

完成 ProviderProfile、EndpointRef、CredentialRef、CapabilityManifest、ModelRoute、FallbackPolicy、
FlowModelSnapshot 和状态机。已导出版本化 JSON Schema，并通过成功、非法状态跳转、摘要篡改、能力不足、
数据策略拒绝、跨 Provider Fallback 拒绝、预算不足和秘密字段缺失测试。此状态不表示通用实时 adapter 已完成。

### P1：通用 OpenAI-compatible adapter

在不改变现有 CUC 调用的前提下增加统一 Profile adapter，通过本地假服务、旧新路径差分测试和经明确授权的 CUC
合成实时探测；增加第二个假 Provider 验证路由与切换。P1 完成时，CUC/DeepSeek 仍是默认开发与前期测试 Provider。

当前已完成 P1 的首个离线纵切：旧 CUC PONG/固定 JSON codec 身份由内容寻址基线冻结；新的
OpenAI-compatible Chat Completions codec 位于显式功能开关后，只发送密封 messages、模型、输出上限与
`stream=false`，并把严格 JSON 决策归一化为既有 `AgentModelReply`。本地 fake transport 已覆盖成功、401、
429、超时、畸形响应与缓冲清理。它尚未替换任何 CUC 入口。

可信 adapter service 的首版也已离线完成。它通过显式 allowlist 的 Control Plane 配置槽解析 Endpoint，
先无网络准备内容寻址的 transport Admission 与 codec registration；运行绑定时重新核对当前 Provider
lifecycle 与 Flow Snapshot，并仅在权威 Egress Store 证明 Grant active 后生成 `AgentModelRegistration`。
固定 Agent Role→Worker Role、能力、路径和 route 预算都在代码中检查。测试使用两个不同的假 Provider 配置
证明切换不会复用模型、codec 或 registration 身份，并用真实本地 Egress ledger 证明撤销后拒绝绑定。

组装结果驱动的完整 fake transport Agent turn 现已通过两套不同 Provider/model 配置。相同纵切还覆盖 401、
429、transport timeout 和畸形 JSON；所有失败都没有 receipt，credential lease、请求缓冲和已取得的响应缓冲
均完成清理。该测试没有发起 DNS 或网络连接，也没有创建工具调用、Candidate 或 Finding。

P1 离线范围已经完成。原剩余发布门禁是经用户明确授权后执行新路径的固定 CUC 实时验收；该门禁已由下述
2026-09-09 验收通过。默认开发路由迁移仍是独立改动，在完成现有入口回归前继续使用原 CUC 路径。

### P1 通用新路径 CUC 实时验收（2026-09-09）

用户延续此前真实模型调用授权后，通用 Profile adapter 使用固定合成上下文执行两次单请求验收。第一次请求
到达 Provider 并返回合法 JSON，但字段未遵循 `AgentDecisionPayload`，因此 codec fail-closed、无 receipt，
凭据及 wire buffers 均完成清理，Grant 随后撤销。该次失败还发现异常链可能携带 Pydantic 输入摘要；codec
现已使用无原始 cause/context 的稳定拒绝异常，并增加回归测试，Provider 内容不再进入控制台异常链。

固定 prompt template 升级为 v2，明确 exact JSON decision shape；reviewed usage extensions 作为 registration
绑定开关加入，默认仍关闭。第二次单请求验收通过：response model 为配置的 CUC alias，626 input tokens、
64 output tokens，产生内容寻址 receipt；credential lease、请求缓冲和响应缓冲均归零，零工具权限。短期
Grant 在 finally 路径撤销。验收记录仅位于被忽略的 `.vulnloom/`，没有保存响应正文、凭据或完整认证响应。

该结果通过 P1 的真实 CUC 新路径门禁，但不自动切换现有代码审阅、Candidate 建议或固定探针入口。默认路由
迁移应作为独立改动进行回归；CUC/DeepSeek 继续作为前期默认 Provider。

### P1.5：业务入口运行绑定

已增加 Provider-neutral `ProviderWireCodec` 协议和 task codec binding：业务输出协议可复用同一个 Profile
preparation，但必须重新绑定当前 Provider lifecycle、Flow、模型、Worker role、预算和 active inference Grant。
只读代码审阅和 Candidate Recommendation 两个现有模型业务入口均已迁移。服务层可装配任意已准入的
OpenAI-compatible Provider；CUC 专用 config 和 CLI 默认行为保留。第二个合成 Provider 覆盖两条链的成功、
身份拒绝、超时、清理失败、只读重放、敏感缓冲归零及 Candidate 不变性。通用结果使用独立
`ModelInvocationResult`，没有放宽 CUC probe 的响应模型闭集。

P1.5 服务层迁移已经完成。Provider Center CLI/API 将负责向可信服务提供当前 Profile/Flow，而不是让业务
计划接受 URL 或 Key；在此之前，通用路径只供可信应用装配。

### P2：Provider Center CLI/API

完成添加、替换凭据、连接测试、同步目录、能力探测、禁用和审计。秘密不落入项目配置。

### P3：角色路由与 Flow 固定

Source Hunt 和 Authorized Red Team 可以选择不同模型；Planner、Validator、Critic 可单独路由；Checkpoint 能恢复
精确快照。

### P4：第二协议与 UI

接入 Anthropic Messages 或 Gemini 原生协议，证明协议可扩展性；实现 Provider 卡片、路由矩阵和运行前数据去向预览。

### P5：健康、成本与受约束 Fallback

加入脱敏健康指标、预算、限流反馈和有界故障转移。所有实时网络测试保持显式启用。

## 12. 非目标

首期不实现：

- 通用 API Key 交易或共享；
- Provider 账号注册、充值或代付；
- 在 Worker 中直连 Provider；
- 让模型自行选择不在 Route 中的 Provider；
- 自动把敏感源码发送给未知外部服务；
- 为追求兼容性而接受任意 URL、任意证书或任意协议字段；
- 以一个 PONG 响应宣称某模型可以承担完整 Agent 角色。
