# 安全与沙盒设计

## 1. 威胁模型

VulnLoom 假定以下内容都可能恶意：

- 被测仓库、依赖、构建脚本和附件。
- 网页、API 响应、错误信息和日志。
- LLM 输出以及网页中的 Prompt Injection。
- Worker 生成的脚本、路径和工具参数。
- 伪装成 Evidence 的模型叙述。

需要保护的资产包括宿主机、个人文件、模型密钥、披露平台账号、其他 Engagement 数据、原始 Evidence 和授权方隐私信息。

威胁模型明确假设 Worker 可能因目标提供的源码、二进制、解析器输入、构建产物或工具链漏洞而取得沙盒内任意
代码执行。Prompt、工具参数预检和模型服从都不能降低这个假设。安全资格必须从“Worker 已经被攻陷”出发，证明
其仍无法获得宿主或 Provider 秘密、扩大网络范围、访问 Docker daemon、修改权威状态或跨任务持久化。

### 1.1 Shared Assurance S1

S1 将上述假设转为共享准入门禁：

- 使用无真实攻击载荷的 canary fixture 验证环境、挂载、网络、daemon socket、进程和清理边界；
- 使用假秘密验证 stdout/stderr、异常、Evidence、报告、CLI/API 和模型上下文不会泄漏；
- 为不可信执行固定并复核版本化 seccomp 合同，覆盖资源耗尽和进程组回收；
- 为权威审计建立 hash-chain 和回滚/分叉检测，同时保持查询输出脱敏；
- 默认测试离线，真实容器和本机私网资格测试显式 opt-in，不访问公网或真实模型。

S1 不引入 crawler、字典枚举、外部回连、真实凭据、持久化、横向移动或新的攻击目标。详细开发顺序和完成标准见
`docs/DEVELOPMENT-PLAN.md`。

S1.1 首个实现纵切已增加版本化、内容寻址的敌对 Worker probe 合同。资格结果必须同时绑定固定镜像、七类 probe、
每次 run/task、Sandbox Profile、调用摘要和期望终态；缺项、重复、绑定漂移、过期、错误终态、容器仍存在或清理
无法证明都会得到显式 `denied`，不能被记录为安全终态。资格 schema 不包含 stdout、stderr、环境、payload 或 secret
字段。Docker 创建后复核也已从“只核对只读挂载”收紧为完整挂载集合相等，并拒绝设备、端口发布、额外 host
映射和继承卷。

普通测试使用纯离线 observation 覆盖成功、拒绝、超时、清理未知和防篡改路径。专用 rootless Admission 使用本地
Alpine、假 Provider token、假 SSH agent、宿主 canary 和无攻击性的 shell 断言，组合验证秘密隔离、`network=none`、
daemon socket/宿主资源不可见、权威输入只读、匿名 tmpfs 不跨任务、崩溃与超时后容器缺失。该测试继续由
`VULNLOOM_ROOTLESS_QUALIFICATION=1` 显式启用，不连接公网、不调用模型，也不生成真实逃逸或外传载荷。

S1.1 已由 commit `4363236151e67e04022b926cbdccf0fffd223412` 的 rootless Linux Phase 3 run
`35549659248` 证明并关闭。该 run 使用 Docker Engine 29.7.2 rootless user service，生产 probe 三批均通过，新增
hostile Worker canary 未跳过。

S1.2 的首个合同使用仓库内 `worker-seccomp-v1.json`。它不是提示词声明，也不允许 `unconfined`：每个 Sandbox
Profile 都绑定合同内容摘要；生产 Engine 必须是合同准入的 29.7.2 并报告 builtin seccomp，创建后 inspection 拒绝
unconfined override，rootless 容器再从 `/proc/self/status` 证明 mode 2。Docker Desktop 的显式版本例外只用于本地
回归，不能形成生产资格。commit `5fd74a385a4493baddb31526f876e8e77935a10b` 的 rootless Phase 3 run
`35550502151` 已通过上述真实配置复核。资源压力与进程组回收仍属于后续 S1.2 纵切。

第二个 S1.2 纵切新增内容寻址的六 probe 资源压力资格协议。PID、FD 和临时盘 canary 必须在固定上限内自行
观察拒绝后正常退出；输出、内存和超时 canary 必须分别精确终止为 `output_capture_failed`、
`memory_limit_exceeded` 和 `wall_time_budget_exceeded`。每个 observation 同时绑定 run/task/Profile/调用摘要，
要求边界已观察、cleanup 完整且容器不存在。probe 载荷全部有界、无网络且不包含真实攻击：PID 饱和最多创建
64 个短进程，其他载荷也有固定字节或时间上限。本地协议、拒绝回归和 canary 脚本已通过；只有专用 rootless
Admission 通过后才可把该纵切提升为生产资格。该六 probe 合同不包含运行中取消，取消由后续独立纵切证明。

commit `d8dc12d614736decf32ffab35dcafb968639497b` 的 rootless Phase 3 run `35551489391` 已通过六 probe
资源压力资格，CI run `35551489390` 同时通过三版本回归。资源压力纵切现为 `isolated_integration_tested`。

后续取消纵切使用 run-bound `RunnerCancellation`，不接受跨 run 信号。预取消在任何 Engine/container 分配前
结束；活动取消由 Docker CLI 的有界轮询观察，随后同时终止 attach 客户端和容器 cgroup，并继续执行强制删除与
absence verification。有界输出捕获在取消时丢弃临时/部分输出。本地无网络 Docker 已验证普通和 capture 两条
路径；commit `55769eb3c6fe6f276b0efcc1270c9b6dc915c77f` 的 rootless Phase 3 run `35553231582`
已通过两条取消 canary，取消纵切现为 `isolated_integration_tested`。

S1.2 Profile matrix 将类型层的权限差异落实到真实容器：Static/Validation 只能看到只读 source，Report/
Post-exploitation 只能看到只读 evidence；四类均为非 root、零 capability、NoNewPrivs、seccomp mode 2、
network-none 和只读根。只有明确执行目标代码的 Validation 输出 tmpfs 可执行，其余输出区为 noexec。四个本地
Docker canary 与 rootless Phase 3 run `35553910680` 均已通过，CI run `35553910683` 同时通过三版本回归。
S1.2 的 seccomp、资源压力、超时、取消、进程组回收、残留对象清理和 Profile 差异已经形成真实隔离证据，
S1.2 关闭。

B5.2 将上述共享隔离合同与单个 B5.1 Adaptive Flow 做精确扇入。该 Flow 必须额外运行 network-none 的正常边界与
timeout-cleanup 两个实际 Post-exploitation 容器探针；Observation 仅保存绑定摘要和布尔边界事实，不保存原始
inspection、环境值或输出。本地 Docker Desktop 与版本化 rootless production assurance 分开建模，因此本地
canary 不能把 `production_runner_admitted` 置为 true。

B5.3 把至少两条已完成的 B5.2 Flow 资格扇入一份有限 A4 Campaign 结构，但资格服务不调用 Runner、Broker、模型
或网络 adapter。目标集合只能从已封存 Flow 推导，六阶段 DAG 与全局预算均内容寻址且不可在运行时扩张；Scope
撤销、预算/期限耗尽、清理失败、连续失败与目标达成都必须停止。每个阶段转换仍要求操作员批准，Outcome 固定不
启动 Campaign、不授予执行/扩域/凭据/Submission 权限，也不能创建 Candidate 或 Finding。只有后续独立的隔离
Runtime 纵切实际证明阶段调度、停止、恢复和清理后，才可以声明 A4 Runtime 资格。

S1.3 已将秘密泄漏回归收敛为内容寻址的八表面资格合同：Worker output、Provider transport、exception chain、
event log、Evidence、Report、CLI/API 和 model context 缺一不可。计划与 observation 只保存表面、测试产物摘要、
布尔安全结论和有界错误码，schema 无法承载 canary、stdout、stderr、payload 或 environment；缺失、重复、摘要
漂移、过期、canary 命中、出口/大小/清理未证明均确定性 `denied`。

统一 `builtin-v3` Redactor 可由可信控制面注入已知秘密，只生成纯文本、URL、Base64/Base64URL、hex 和 JSON
escape 的确定性变体，不依赖模型或语义 DLP。分段 Evidence 先按原始字节限额收集，再以 strict UTF-8 解码并
一次性脱敏，成功或失败都会清零内部缓冲；畸形、超限和复用均拒绝。Worker 结构化输出不做可能破坏 JSON 的
静默改写：发现敏感内容或畸形 UTF-8 时不发布对象，Runner 返回 `output_capture_failed` 并照常验证容器清理。

Git、Semgrep、Docker 和 Provider subprocess 的外部 stderr、响应解析内容及底层异常不再进入可见异常链；
Provider 仍使用固定 subprocess、空白名单环境、丢弃 stderr、受限响应缓冲并在终态清零 credential/request/wire/
response 临时缓冲。Event、Evidence、Report 与 Agent context 的普通和编码 canary 均有持久化回归；CLI 继续只
输出稳定错误码。当前没有 HTTP API 实现，因此 API 是零运行表面，未来实现必须复用同一应用服务和本合同。

本机 Docker 的无网络 synthetic canary 已证明真实 Worker 输出秘密时不会发布对象，终态为失败、临时目录为空、
容器完成删除；安全输出成功路径同时通过。全量离线测试、Ruff、437 份 schema 解析和 diff check 通过，未访问
公网、未调用真实模型、未执行真实攻击。S1.3 关闭，下一项为 S1.4 防篡改审计骨架。

S1.4 首个纵切已经建立共享权威审计链。固定合同要求每条记录绑定前序摘要和 Scope、Policy、Sandbox Profile、
Context、Tool Registry、Provider revision、状态迁移及关键输入摘要；同一 stream 不得跨 Engagement。SQLite
事务原子提交记录与 head，幂等只保存调用方 key 的摘要。过期新写入、绑定漂移、并发冲突或链完整性未知均拒绝。

本地验证可检测删除、插入、改写、重排和 head 漂移。由于自洽的旧数据库副本无法靠自身识别，类型化外部
checkpoint 固定 sequence/head；checkpoint 超前判定为 rollback，相同位置摘要不同判定为 fork，未来或其他 stream
的 checkpoint 也拒绝。checkpoint 允许验证后的后继记录，不把正常增长误判为篡改。检测异常后禁止追加和查询，
也不自动截断或重算；唯一恢复路径是从独立边界恢复完整副本，再用原 checkpoint 验证。

查询只返回 `AuditRecordProjection`：包含必要的事件名、状态和控制面摘要，不包含 payload、输入摘要列表、
Engagement、幂等材料、stdout/stderr 或 secret。

S1.4 第二个 `offline_tested` 纵切增加 `EventStore.append_authoritative`：领域事件先脱敏，再与审计记录和 head 在
同一个 `BEGIN IMMEDIATE` 中提交。调用方必须提供可信 checkpoint；追加和权威读取都会在事务内验证链，并逐条
核对 Engagement 专用 stream 与领域事件的幂等摘要、aggregate 摘要和完整 transition 摘要。事件或审计任一侧
缺失、领域 payload 被改写、完整双边回滚、checkpoint 分叉/超前、过期或 SQL 中断都拒绝且不留部分写入；不允许
用后续 backfill 掩盖单边提交。离线矩阵和全量门禁为 1596 passed、39 skipped、85.54% coverage，443 份 schema、
Ruff 和 diff check 通过。

S1.4 最终纵切提供本地可信 checkpoint 保管：digest-only 文件名、16 KiB 上限、拒绝符号链接与宽松权限，使用
owner-only 文件、per-stream lock、临时文件 `fsync`、原子替换和单调 compare-and-swap。写入后 checkpoint 推进
失败不会回滚已提交状态；精确幂等重试会验证既有 event/audit 对并安全推进 anchor。非空数据库缺少 checkpoint
时拒绝自动 backfill，必须从可信副本恢复或执行独立审计迁移。

主 CLI 的全部 9 个事件写入点——Engagement、Scope、Artifact/Target、Source Graph、Candidate、Validation、
Report review/export——以及 `status` 已迁移到 `CheckpointedEventStore`。旧 `EventStore.append` 只保留兼容和单元
测试用途，不再由主 CLI 调用；其他内容寻址业务账本不在共享事件链声明内。默认 checkpoint 目录与数据库相邻，
只能检测数据库侧回滚；部署时必须用 `--audit-checkpoint-store` 放到独立受保护路径。远程签名、WORM 与透明日志
继续延后。本轮全量门禁为 1604 passed、39 skipped、85.51% coverage，443 份 schema、Ruff 和 diff check 通过。
S1.4 与 Shared Assurance S1 至此达到 `offline_tested` 并关闭，未访问公网、未调用真实模型、未执行真实攻击。

### 1.2 A1 Project Recipe Registry

A1.1 把项目构建入口收窄为可信 Registry 中的内容寻址 recipe。每个 step 固定绝对非 Shell executable、完整 argv、
显式环境、工具 ID 和预算；recipe 固定版本、镜像 digest、构建系统要求及 Build→Test 顺序。包含 URL、模板占位、
换行、NUL、Shell 入口或疑似凭据环境名的注册拒绝。Agent 仅能选择 recipe ID，不能携带命令或运行时参数。

物化的 Runner 请求逐步只开放一个工具，Snapshot 只读、网络关闭、模型预算为零。执行必须具备针对完整 plan 的
`RUN_UNTRUSTED_BUILD` Approval，并从可信 Registry 重建计划后逐字段比对；Registry/image/argv/environment/
Scope/Manifest/Policy 任一漂移均 fail-closed。每步结果持久化，timeout/failure/cancel 为非成功终态；Runner 无法
证明容器清理时记录 `cleanup_unverified`，不保存伪造成功结果。A1.1 仅使用离线 Runner，尚未声明真实项目或 Docker
集成已通过；该声明留给下一纵切的显式本地、无网络 Admission。

A1.2 已在本地 Docker 上验证该边界。首次运行因官方 Python image metadata 带有未显式声明的 `GPG_KEY` 被 Runner
正确拒绝；没有通过扩大环境白名单绕过。最终 Admission image 从摘要固定的本地 Python filesystem 进入
`scratch` final stage，仅声明 `PATH/LANG/LC_ALL`。成功 Build→Test 与真实一秒 timeout 均使用 `--pull never`、
`network=none`、UID/GID 65532、只读 root/source、cap-drop ALL、`NoNewPrivileges` 和有界资源/tmpfs；所有创建的
容器最终均不存在。本机 daemon 非 rootless，不能替代 S1 的独立 rootless 生产资格。

A1.3 防止把“项目能构建”误当成“漏洞已复现”。内容寻址 binding 精确绑定成功 Recipe outcome 和 Candidate
provenance，并由独立持久化表保存。Source Execution 在任何 Runner 调用前从权威 store 重读；仅由调用方提供、
缺失、篡改或与 Index/Manifest/Target/Scope/Candidate 不一致的 binding 一律拒绝。通过 binding 仍必须执行完整
Validation receipt 链，Candidate 不会由 Recipe 直接提升。非 fixture 验收使用当前仓库只读 Snapshot、本地清洁
Python 3.12 image、`network=none` 和完整 cleanup proof；未安装依赖、未访问公网、未调用模型或执行攻击。

### 1.3 B1 Replanning authority confinement

B1 的 Agent-facing 数据只包含短期有限 Tool View 和 Observation 摘要引用，不包含原始 Target URL、凭据、请求正文
或可执行命令。Proposal 不能声明新 Target；Control Plane 必须从原 Plan 重建 Action，并重新核对 Scope、Policy、
checkpoint 和权威 Observation provenance。每个准入在事务中占用一个 Action 预算，并要求与该 Action ID 精确绑定的
人工 Approval。并发超额、陈旧视图、Observation 替换、Scope/Policy 漂移和 Approval 重用均 fail-closed；取消或
到期只能释放未消费的预留。该边界仍只开放已有的低影响 Recon kind，不允许 crawler、枚举或任意请求脚本。

### 1.4 B2.1 sealed-path GET confinement

`HTTP_GET` 只接受权威 `EndpointSeedSet` 中的精确 canonical path，不能通过通用 Recon 或 B1 Proposal 构造。
adapter 必须处于显式 URL-digest allowlist 模式且 redirects=0；请求协议不允许 header、credential 或 body，响应
最多 64 KiB。原始响应正文只写入脱敏 Evidence Store，普通 Observation/outcome 仅保存正文摘要和大小。
requested/final URL digest 不相等、缺失 Evidence、原始正文混入 schema、通用执行绕过或成功结果缺少类型化
Web Snapshot 时均拒绝。失败、超时和 cleanup unknown 不返还已经发出的请求预算。

### 1.5 B2.2 OpenAPI discovery confinement

OpenAPI reducer 没有网络、resolver、模型或执行接口，只能消费一条权威 sealed GET 的已脱敏、内容寻址 Evidence。
Plan 绑定 Endpoint outcome、Flow checkpoint、Observation、Web Snapshot、Scope/version 和原始响应摘要；来源漂移、
过期、缺失 Evidence 或非成功/未清理 GET 均拒绝。解析只接受预算内 OpenAPI 3.0/3.1 JSON，重复 key、结构炸弹、
非规范 path 和 operation 超额 fail-closed。所有 `servers` 与 `$ref` 均不解析、不输出、不访问。Discovery schema
固定 `execution_authorized=false`，Observation 固定 `target_expansion_authorized=false`，因此解析结果不能成为隐式
Target、Seed 或 Action。STARTED checkpoint 只在完整解析成功后写入，超时/拒绝不留下部分权限或部分结果。

### 1.6 B2.3 reviewed discovery promotion confinement

OpenAPI discovery 只有经操作员逐项选择并将 path template 具体化后，才可成为 Endpoint Seed。Promotion Plan 绑定
权威 completed Observation、当前 checkpoint、Target 与 Scope/version；未知/未选 discovery、模板错配、非规范
path、外部 URL、重复选择和没有 GET/HEAD 的 operation 均 fail-closed。文档 `servers` 和 `$ref` 不在协议中，
无法成为 authority。Promotion 的 STARTED ledger 与 Seed publication 共用 Endpoint Recon SQLite 边界，完成事务
原子写入 Seed Set 与 Outcome；超时或崩溃时不会暴露部分 Seed。新 Seed 不等于 Action，执行仍必须重新经过预算、
Scope/Policy、Endpoint Plan 和 Broker。

### 1.7 B2.4 sealed GraphQL SDL observation confinement

GraphQL reducer 与 OpenAPI reducer 一样没有网络、resolver、模型或执行接口；它只读取一条权威、成功且
cleanup-proven 的 sealed GET Evidence。Plan 内容寻址地绑定 Endpoint outcome、当前 Flow checkpoint、Observation、
Web Snapshot、Scope/version 与响应正文摘要，任一来源漂移、过期或缺失都 fail-closed。解析器仅接受 64 KiB 内、
token/type/field/嵌套/墙钟预算内的 SDL；可执行 query/mutation/subscription/fragment、畸形定界符、重复类型/字段、
保留字段和无有效 Query root 均拒绝。它不会发送 introspection、POST 或 operation。

输出只保留 Query field 名和命名返回类型的内容寻址摘要；参数、默认值、描述、directive 内容均不披露，Mutation 与
Subscription field 只计数后丢弃。Field Discovery 固定 `execution_authorized=false`，Observation 固定
`operation_execution_authorized=false` 与 `target_expansion_authorized=false`，不能成为隐式 Action、Seed、Target 或
Finding。完整解析后才写 STARTED checkpoint；超时和拒绝没有部分结果，遗留 STARTED 只能在三次上限内显式恢复。

### 1.8 B3.1 vulnerability Evidence Requirement confinement

首个漏洞类别合同只覆盖未认证敏感数据暴露的 read-only Evidence qualification，不包含 detector、payload、请求参数、
凭据、字段名、样本值或网络 adapter。Requirement 的事实集合、版本、CWE 和权限位均内容寻址且固定；Assertion 必须
引用 Evidence Store 中完整可读的脱敏对象。Validation 与 Critic 的 producer、context 和 Evidence 集合必须完全
分离，不能用同一结果自证并自行排除反证。

Assessment 只有 Candidate 资格、负例和不确定三种结果。缺少独立 replay、redaction proof、任一反证结论或
no-state-change/no-artifact Cleanup proof 时均不能取得 Candidate 资格；access control、生成为公开内容、synthetic
fixture 或环境/版本错配任一反证成立则记录负例。协议固定禁止 Finding 与测试执行权，不能触发请求或改变 Candidate
状态。解析/校验在 STARTED 前完成；超时、Scope 漂移、Evidence 缺失和重复事实无部分结果，遗留 STARTED 最多恢复
三次。

### 1.9 B3.2 authoritative Assertion materialization confinement

Assertion materializer 没有网络、模型、请求或 Candidate/Finding 写接口，只能消费一条成功、无凭据、禁重定向且
cleanup-proven 的权威 sealed GET。Plan 封存 Endpoint outcome、最新 checkpoint、Observation、Web Snapshot、
Evidence/body digest、Target、Scope/version 和固定 classifier digest；任一来源、Scope、Evidence 或正文漂移均在
写 STARTED 前拒绝。

分类器只处理预算内 JSON，并且只有固定敏感字段的值已经是精确 `[REDACTED]` 时才产生 supported presence；字段
缺失保持 inconclusive，非空未脱敏值直接拒绝且绝不进入异常文本或输出。Materialization schema 固定
`raw_values_retained=false`、`field_names_retained=false`、`request_execution_authorized=false`、
`candidate_proposal_eligible=false` 和 `finding_authorized=false`。它最多证明 sealed GET、无认证请求、redaction
边界、只读与无残留来源事实，不能生成独立 replay 或 Critic Assertion。超时/拒绝无部分 batch，遗留 STARTED 仅
允许最多三次显式恢复。

### 1.10 B3.3 independent replay Validation confinement

Replay validator 不持有网络、Runner、Broker、模型或攻击 adapter，只读取两个已完成的 B3.2
materialization 和对应内容寻址 Evidence。两份来源必须同 Scope/version、同 requirement、同精确 URL digest，且
materialization plan、Flow、Observation、Web Snapshot、Evidence 全部互异；同一次执行不能冒充独立 replay。
Evidence 缺失、来源漂移、顺序错误和 Scope 失效均在 STARTED 前拒绝。

比较只使用正文 digest 和三态 sensitive-presence，不把正文、字段名或样本值复制到 Validation。只有两份 supported
敏感类别结果且 digest 完全一致才支持 replay；不一致或不足保持 inconclusive。schema 固定
`request_execution_authorized=false`、`candidate_proposal_eligible=false`、`finding_authorized=false`，因此不能触发
新请求或自行提升结果。超时/拒绝无部分 Assertion，遗留 STARTED 最多三次显式恢复。

### 1.11 B3.4 independent Critic Assertion materialization confinement

Critic materializer 没有网络、Runner、Broker、模型、凭据或 Candidate/Finding 写接口。它只接受一份完整、内容寻址
且恰好覆盖四类反证的 `CriticEvidenceReview`，以及一个已完成 B3.3 Validation。Review 与 Validation 的 producer、
context 和 Evidence 集合必须完全分离；requirement、Target/version、Scope/version、时间顺序和 Evidence 完整性在
prepare、execute 与 complete 重验。

服务不会自行作出反证判断，只原样物化 supported/refuted/inconclusive。schema 固定 `review_executed=false`、
`request_execution_authorized=false`、`candidate_proposal_eligible=false` 和 `finding_authorized=false`；即使随后 B3.1
Assessment 给出 Candidate 资格，也没有创建或提升状态的权限。缺项、Evidence 复用/缺失、绑定漂移、Scope 失效和
超时均 fail-closed，无部分 Assertion；遗留 STARTED 最多三次显式恢复。

## 2. Sandbox Profile

### Static Profile

- 无网络。
- 源码只读挂载到固定路径。
- 根文件系统只读；`/tmp` 和输出目录使用限额 tmpfs/volume。
- 非 root，`cap-drop=ALL`，`no-new-privileges`。
- 禁止挂载 Docker socket、SSH agent 和用户主目录。
- 默认不执行目标代码。

### Validation Profile

- 每次 Validation Run 创建新容器。
- 只加入该 Target 的专用网络。
- 默认无 DNS、无互联网出口、不能访问宿主网关和云元数据地址。
- 只开放 Scope 声明的目标地址、端口、协议和速率。
- 限制 CPU、内存、PID、文件大小、打开文件数和墙钟时间。
- 结束后销毁可写层；Evidence 经 Broker 单向导出。

### Report Profile

- 无目标网络和互联网。
- 只读挂载脱敏 Evidence Bundle。
- 不能读取原始 Cookie、Authorization 和身份数据。
- 输出只能写到该 Report 的临时目录。

M4.1 已将这些要求编码为类型化 Profile 与 Runner preflight。M4.3 的 Docker adapter 已在真实
rootless Linux 容器中证明 network-none Profile 的非 root、只读根、只读源码、cap-drop、
NoNewPrivs、限额 tmpfs、无默认路由、无 Docker socket、超时终止与容器清理。生产门禁同时
要求 seccomp、cgroup v2 与可执行的内存、CPU quota、PID 控制。Target-only egress 不在 Worker
中实现，Runner 会 fail-closed 拒绝该模式。

## 3. 网络策略

网络允许规则以解析后的 IP 和端口执行，而不仅是 URL 字符串：

1. Tool Broker 验证 URL 属于 Scope。
2. 独立解析 DNS，拒绝未授权地址范围。
3. Runner 在网络层配置 egress allowlist。
4. 发起连接后记录实际对端 IP。
5. 重定向每一跳重新判定。

OAST、Webhook 或外部回连使用一次性 Approval 和一次性 callback 标识，不能开放通用互联网出口。

M4.2 的 Broker 已实现逐跳 Scope/Profile 判定、DNS pin、peer IP 一致性、危险地址拒绝和
redirect 重新授权。M4.3 新增 Broker-owned live HTTP/HTTPS adapter：只连接策略选择的数字 IP，
不读取代理环境，TLS 仍校验授权 hostname，实际 peer 回传 Broker 复核，响应经过大小限制和脱敏
后才进入 Evidence Store。真实 socket 测试已证明 Host 与 pinned peer 分离以及单向脱敏 Evidence
数据流。专用 rootless Linux 准入测试进一步证明 Worker 无法访问 live sibling container 或 daemon
gateway，Broker 在 transport 前拒绝实际 gateway，并在 redirect 第二跳阻止 DNS 漂移到 metadata。

M4.4 将 Runner 与 Broker 接入事务性 Validation Orchestrator。所有绑定在 `STARTED` checkpoint
之前重新验证；Runner 未完成时不会继续 Broker，Broker 的拒绝、缺审批和超时不能被 judge
覆盖。执行成功默认仍是 `INCONCLUSIVE`，judge 引用非本次采集 Evidence 时整个流程 fail-closed。
未完成 checkpoint 不自动重放，避免重复副作用。

M4.5 的确定性 HTTP 裁决要求人工计划提前绑定确切 call、状态码和最终原始正文 SHA-256。
正文不进入 Broker result；普通路径只接收摘要与脱敏 Evidence。裁决前 Evidence Store 使用
`O_NOFOLLOW`、常规文件/大小检查和内容摘要复核，损坏、缺失或符号链接对象都会 fail-closed。
任何断言不匹配都保持 `INCONCLUSIVE`，不能由状态码单独触发复现结论。
Judge 默认只接受 live pinned HTTP Registry 摘要；offline Registry 只能在测试代码显式注入其摘要，
不能使用生产默认配置形成复现结论。

M5.2 报告服务不读取或复制 Evidence 正文，只在状态变化前用 `O_NOFOLLOW`、大小和摘要复核对象。
报告文本统一经过内置脱敏器，Markdown 进一步转义 HTML 与图片/链接控制字符，避免本地预览触发
嵌入式外部资源。Markdown/JSON 写入随机临时目录后原子发布为只读内容寻址对象；失败会清理临时
目录。checkpoint 只保存 plan digest 和已脱敏 outcome，不保存原始报告计划文本。该路径没有网络、
披露凭据或 Submission adapter。

M5.3 的人工审批不是自由文本或模型结论，而是绑定 reviewer、Report/artifact/Evidence/Scope/Diff
摘要和期限的类型化命令。SQLite 对每个 review plan 只接受一个决定，内容变化、并发冲突、过期批准
和损坏 artifact 均 fail-closed。本地导出只在受控 Report Store 内生成新内容对象，不接受任意路径；
CLI 不包含网络调用。`SUBMITTED` 仍不可达，平台 token 也未引入任何 Worker 或 Report 流程。

M6.1 benchmark 服务只读取严格 schema 校验、内容寻址的本地 suite、observation、baseline 和
policy，不拥有 Runner、Broker、Disclosure adapter 或任何 credential provider。评测协议再次编码
Candidate→Finding 门禁，无法表示绕过 Validation、Critic、promotion 或 Evidence 完整性的 Finding。
结果在受控 store 中经临时目录原子发布，读取使用 `O_NOFOLLOW`、常规文件与大小/摘要检查；写入失败
清理临时目录，遗留 STARTED checkpoint 必须人工恢复。普通 CI 只重建本地 fixture 并离线计算指标，
不下载外部 benchmark。

M6.2 不提供外部数据获取器。目录 snapshot 在 manifest 生成与 import 时都拒绝 symlink、特殊文件、
非归一化/碰撞路径和资源超限；所有读取使用 `O_NOFOLLOW`，规范化之后再次全量复核以阻止 TOCTOU。
ZIP/TAR 不由该 adapter 处理，不能把未检查归档直接当作 snapshot。BountyBench adapter 不读取脚本和
报告正文；AutoPenBench 的 flag、task 与潜在凭据不会写入 suite、artifact、checkpoint、事件或 CLI
摘要。adapter 没有 Runner/Broker/Docker/网络依赖，ImportPlan 也没有 URL、token 或 Submission 字段。

M6.3a 只导入预先生成的本地 CodeQL/Trivy/Checkov/Kubesec JSON/SARIF。输入使用 `O_NOFOLLOW` 打开，
限制大小与解析时间，对实际解析字节复核 SHA-256，并在规范化后再次复核文件以关闭 TOCTOU 窗口。
重复 JSON key、非法 UTF-8、symlink、特殊文件、陈旧 CWE map、数量超限与超时均 fail-closed。

工具原始 message、Trivy Secret match、Kubesec object/selector/reason 和原始 rule ID 不进入只读 artifact、
checkpoint 或 CLI 摘要；只保留消息/规则摘要和必要的安全相对位置。Observation schema 不含执行、网络、
凭据、Approval、Candidate、Finding、Validation 或 Critic 权限，因此工具命中不能绕过生产门禁。

M6.4d 的 CodeQL 查询不会直接写入密封数据库。`CodeQLSnapshot` 绑定 Target/version/Manifest、预建 DB、
query pack、suite、预编译查询和全部文件摘要；原始对象只读挂载并在容器清理后复核。精确 wrapper 使用
no-follow 复制并核对文件数、entry 数和总字节，只把副本放入 Runner 有容量上限的 output tmpfs。
CodeQL cache 只能写 `/tmp`；SARIF 禁止 file contents、snippets 和 query help，并在成功退出后才送入
有界 attached capture。复制/查询/捕获/导入/复核/容器删除任一步失败，外层执行都不能完成。

M6.4d 不提供 CodeQL 下载、pack 安装或 database create API。数据库构建和任何 Target 编译继续要求
独立 `RUN_UNTRUSTED_BUILD` Approval；Admission 行为 fixture 只证明隔离和清理，不冒充真实 CodeQL
bundle、许可、query pack 或预建数据库的运营资格。

M6.5 只聚合权威 Docker store 中已完成的 M6.4 执行证明，不启动分析器。资格服务要求完整 case×analyzer 矩阵，并在 checkpoint
前重新计算 execution plan、registration、outcome、ObservationSet、suite、alignment 与 evaluation plan
摘要；同时复核 Target/version/Manifest、Scope、完成状态和 cleanup。失败、超时、取消、清理不完整、缺项、
重复或漂移均拒绝，且不会留下 qualification/evaluation checkpoint。

资格 outcome 只能携带既有 M6.3b gate 结果，不能创建 Candidate/Finding 或改变报告状态。该层没有 Runner、
Docker、Broker、socket、credential、Target build、secret scanner、Approval 消费或 Submission 字段。

M6.6 在 rootless Admission 中复核完整四工具组合。一个 case 的全部 execution binding 必须共享 Target
ID/version、Manifest 与 Scope ID/version；任一 analyzer 缺失或 completed outcome 与权威 store 不一致时，
qualification 和 evaluation store 都必须保持为空。完整组合仍只产出评测指标，不授予工具命中任何
Candidate/Finding、报告或 Submission 权限。

M7.1a 的 Agent Runtime 只接受离线 replay adapter。模型注册和运行计划不携带 endpoint、API key、token
或任意环境变量；请求只包含摘要、role、显式工具白名单和预算。模型输出被视为不可信数据，必须满足固定
schema、身份、token、墙钟和字节上限。工具提案只产生参数摘要，不执行 Runner/Broker，也不能消费 Approval
或触发领域状态。原始响应与原始参数不落 checkpoint；adapter 中断后的 STARTED 记录拒绝自动重放。

M7.1b 新增的 credential reference 只允许 Control Plane provider 读取启动时显式准入的精确环境变量；未注册
引用在访问环境前拒绝，且 provider 不复制完整宿主
环境。读取值进入不可序列化的 lease 缓冲，正常、错误和超时路径都在返回前归零；缺失/错误凭据只产生通用
adapter failure 并保留 STARTED checkpoint。local-fake adapter 无 socket/URL/SDK，凭据、引用和无关环境值
不进入 Worker request、outcome、SQLite 或错误消息。此处不声称 Python 进程内存可抵御宿主级取证；live
provider 仍需独立进程/网络/日志与响应捕获 Admission。

M7.2 只允许与 Task `input_refs` 完整同序匹配的瞬时 source 进入 assembler，并由可信代码执行规范化、控制
字符拒绝和 `builtin-v2` 脱敏。原始/脱敏单片、总字节、fragment 数和墙钟都有独立上限。snapshot 中所有
内容固定标记为 untrusted，因此 prompt injection 文本不能修改工具白名单、Approval 或 Scope；真正工具
授权仍只在 Broker/Sandbox。上下文对象只读、no-follow、内容寻址并绑定 Task/Target/Scope/redaction policy。
M7.2 不读取完整认证响应或原始 Evidence body，也不声称脱敏器能替代上游最小化；未知敏感格式仍应在加入
context 前由人工或专用 normalizer 排除。绑定 snapshot 的 Runtime 如果没有显式 context store，或重读时发现
对象不可写性/内容/Task 绑定漂移，会在 STARTED checkpoint 前拒绝。

M7.3 的 system message 来自固定内置模板，user message 是重复键拒绝的确定性 JSON。脱敏 context 只能位于
`untrusted_context` 字符串字段；即使正文包含伪造 control JSON 或“忽略前文”，也不能修改 envelope 的
工具白名单、预算、schema 或 `can_execute_tools=false`。Runtime 继续独立验证工具提案，Broker/Sandbox 才是
真正权限边界。renderer 对 system/user/总字节和墙钟分别设限，并在 checkpoint 前拒绝首步渲染失败。
adapter 和 SQLite 只保留 envelope digest，不持久化 message/context 正文。

M7.4 将 provider 出口配置收缩为内容寻址的 Admission 对象：exact canonical DNS hostname、TLS 443、单一
path、credential reference、adapter digest、请求/响应上限和 timeout。当前 schema 固定
`network_enabled=false`、redirect/proxy 关闭、DNS revalidation 开启、raw response 不持久化且只允许一个
attempt。StepRequest 与 Message Envelope 的 Task/step/context/schema/tools/output 任一绑定漂移，都在凭据读取
前拒绝。瞬时 provider request、credential lease 和 raw response 使用可归零缓冲；正常、拒绝和超时路径均
强制清理。attempt/receipt 与 SQLite 只含摘要、计数、稳定错误码和清理证明。

M7.4 的 `admission_fake` 不解析或连接 hostname，不创建 DNS/socket/HTTP/SDK/proxy，也不声称真实 TLS、DNS
rebinding、速率限制或进程级隔离已经通过生产准入。真实 provider 出口仍必须通过独立 Admission；不得通过
修改 schema 或替换 adapter 绕过该里程碑。

M7.5 的 live adapter 只存在于可信 Control Plane。生产 Admission 固定 exact hostname:443、global-only DNS、
固定 implementation digest、单次 POST、单 attempt 和每分钟请求上限；loopback Admission probe 则固定
`.test`、loopback-only、exact port 与 sealed CA。每次调用都重解析 hostname，并要求全部 DNS answer 满足同一
IP policy，阻止私网/metadata 混入。子进程连接 numeric IP，同时以 admitted hostname 做 TLS SNI/certificate
校验并复核实际 peer，因此连接阶段不会再次按 hostname 解析。

provider child 使用固定 module、Python `-I`、空白名单环境、`/` cwd、close-fds、无 shell、新进程组、资源
上限、stderr 丢弃和父层 bounded stdout。credential 不进入环境或 argv，只在 parent lease 和 stdin frame 中
短暂存在；frame 在写入后归零，child 退出即销毁其地址空间。超时、overflow 和异常路径强制杀死/回收进程组。
response 在 child 流式设限，并由 parent 再次限长、验证 peer/TLS、strict JSON 与 provider/model identity，随后
归零。日志/checkpoint 只保留 endpoint-free digests、peer IP digest、TLS version、计数、状态和 cleanup proof。

该边界不允许 arbitrary URL/header/method、redirect、proxy、compression、自动 retry 或 SDK。Phase 3 只用
loopback TLS fixture 证明进程与 socket 行为，不证明任何公网 provider 的可用性、服务条款、数据驻留或运营
授权；生产 exact-host Admission 必须由运营方单独签发。

M7.6 将“单独签发”变为代码边界。只有本地受信 `AgentProviderEgressIssuerPolicy` 明确允许的 provider、networked
mode 和期限才能产生 grant；no-network fake、错误用途、未知 issuer 与超期申请不能进入 STARTED checkpoint。
grant 精确绑定 Admission、credential reference 与 adapter digest，并由 model registration 绑定其 ID。

grant/revocation 对象原子发布、内容寻址且只读，每次读取执行 no-follow、常规文件、不可写、大小、schema、ID
和摘要复核。ledger 对签发/撤销使用独立 STARTED/COMPLETED；遗留操作、冲突、到期或 revocation 全部拒绝。
live adapter 在每次 DNS、速率计数、凭据读取和子进程创建之前重读 lifecycle，因此撤销不会依赖长驻内存缓存。
本地 SQLite authority 是可信 Control Plane 状态，不是跨主机密码学签名系统；M7.6 不引入远程 signer key、
provider SDK、公开调用入口或新的 Worker 权限。

M7.7 把 live wire protocol 收缩到内容寻址的 `openai-responses-v1` codec。live registration 必须绑定 exact
codec ID 和 Admission path；offline/fake adapter 不能携带 codec。encoder 没有任意参数入口，固定关闭 store、
stream 与 provider tools，并只发送已验证的 system/user envelope 和 strict decision schema。

decoder 只接受 exact model 的 completed assistant `output_text`，并拒绝 incomplete、refusal、native tool
call、annotation、多输出、重复 JSON key、未知字段、超限与超时。嵌套文本必须再次通过
`AgentDecisionPayload`；任何工具提案仍无执行权。codec 不记录 raw request/response，继续复用 M7.5 的缓冲
归零、bounded capture 和 digest-only receipt。该里程碑不授权公网 Provider、真实密钥、SDK、流式会话或
Submission。

M7.8 不把模型输出提升为可执行调用。Agent 只能提交一个预承诺 Broker call 的 digest；可信 Control Plane
独立构造完整 typed `BrokerCall`，handoff 在 checkpoint 前从权威 Agent store 重读 `tool_proposed` outcome，
验证 exact Task/Scope/Policy/Profile/Registry/tool/budget/deadline 和 commitment。任何摘要、role、call 或
checkpoint 漂移都在 DNS、凭据与 transport 前拒绝。

实际执行继续进入既有 Tool Broker，因此 network grant、DNS/peer pinning、metadata 拒绝、credential admission、
状态变化 Approval 与请求预算不会由 Agent 绕过。handoff 不接收 socket、Docker、adapter 或 secret。首次
`approval_required` 仅允许一次绑定前序结果的重试；completed、denied、failed、timed-out 或遗留 STARTED
均不能自动重放。

成功只产生 digest-only `AgentToolObservation` 和 Evidence refs；URL、header、body、credential、完整响应与
Agent 原始参数不进入 handoff checkpoint。Observation 没有 Candidate/Finding/Submission 字段，不能改变领域
状态。Phase 3 的 live composition 只连接临时授权 fixture，不增加公网能力。

M7.9 只允许 completed handoff 的 Observation 进入一次后续 Agent run。可信服务从 root Agent store、handoff
store、Evidence Store 和只读 context store 逐项重读；调用方不能提供 transcript、Evidence 正文或新的授权
字段。派生 Task 继承 exact engagement/Target/Scope/Policy/Profile/Registry/model/deadline，allowed tools 为空、
tool-call budget 为零，model/wall budget 只能减少。

Evidence 按 exact ref 使用 no-follow、大小和 SHA-256 校验读取，并再次经过固定脱敏器；即使响应正文包含
prompt injection，它仍只作为 `untrusted_context`。缺失/链接/摘要漂移、context 可写或漂移、预算耗尽、
deadline、非 completed handoff、cleanup 不完整、Observation 重放和遗留 STARTED 都在 provider 调用前
fail-closed。continuation 不能产生可执行 tool intent、Approval、Candidate/Finding 或 Submission；再次工具提案
只会形成稳定失败。

M7.10 只在 M7.9 之外增加一个固定第二工具轮次，不提供通用 Agent loop。第二轮 Task 的权限、绝对 deadline
和剩余预算从权威首轮链派生；模型只看到可信 control 中有限、内容寻址的 opaque call commitments。每个
commitment 对应控制面预构造且经 Broker preflight 的 exact read-only 调用，模型不能生成 URL、HTTP 参数、
credential、Scope 或 network grant。

Session 在每个外部动作前重读 Agent/handoff/Observation/Evidence/context checkpoint 并扣减累计预算；未列
commitment、重复消费、跨轮漂移、第三次工具提议、超时、清理不完整和遗留 STARTED/RESUMING 均 fail-closed。
Approval-required 只进入持久等待，不自动审批或轮询；唯一恢复路径是带有效 Approval 的 M7.8 attempt-2，且
不会扩大两次成功 tool-call 上限。Session outcome 没有 Candidate/Finding/Report/Submission 状态转换能力。

M7.11 在离线路径中重新打开 completed Session 及其全部 Agent、handoff、continuation 和 Evidence checkpoint，
并独立重算轮次顺序、exact call commitment、Approval decision digest、Target/Scope 绑定、累计预算和 cleanup。
调用方不能提供 transcript、Evidence 正文或模型摘要；缺失、分叉、重复、跨 Session 重放、摘要漂移、预算回增、
未清理或 Evidence 完整性失败都会在审计 artifact 发布前 fail-closed。

审计 bundle、SQLite 与只读 JSON/Markdown 只含 digest、ID、计数、稳定终态和 Evidence ref，不含 URL、credential、
provider request/response、工具参数或 Evidence 正文。确定性 recommendation 没有领域状态命令，不得替代
Validation、Critic、Finding promotion、人工 Approval 或 Submission。

M6.3b 的 alignment 是评测标签，不是领域授权。只有显式列出的 match 才参与 recall；同 CWE 不自动匹配。
服务在 checkpoint 前复核 suite/case/Target/ObservationSet/truth/CWE 全部绑定，并限制 set、Observation、
match 数量和墙钟时间。跨 case、摘要漂移、一个 Observation 多 truth、CWE 不相容和不完整输入均拒绝。

评测结果只有指标、violation 和内容摘要，不包含原始分析器消息或执行权限。required-analyzer、完整矩阵、
逐工具阈值和 baseline 防止聚合指标掩盖单工具退化。整个路径没有 Target 文件访问、Runner、Broker、
Docker、socket、credential、Approval 或状态机调用，无法创建 Candidate/Finding 或触发 Submission。

M6.4a 新增的是 source-only 执行协议，不是新的任意命令入口。Registration 必须固定绝对可执行文件、完整
argv、exact image ID、规则和 adapter 摘要；argv 禁止占位符、URL 和运行时追加参数。Analyzer Worker 使用
只读源码、无网络、非 root、无 capability、只读根和显式空基线环境，Profile/Registry/Policy/Target 任一
摘要漂移都会在 checkpoint 前拒绝。

M6.4a concrete service 只接受 Offline Runner，因此不会启动进程、容器、Docker 或 socket，也不会生成
分析器输出。未来真实执行必须复用 M4.3 rootless 准入并证明输出提取与清理；任何目标 build script 都不
属于 source-only 模式，必须新增精确 `RUN_UNTRUSTED_BUILD` Approval 校验后才能分配 Runner 资源。

M6.4b 的真实执行只准入固定 Checkov/Kubesec factory，并复用 M4.3 Docker 强制边界。镜像必须由控制面
预先解析为 exact ID；运行期固定 `--pull never` 和 `network=none`，不持有 Docker socket、宿主凭据或
Broker 权限。attached stdout 先进入有界可信临时文件，再经 no-follow、常规文件、大小/摘要复核和原子
只读发布；失败、超时、OOM、超限或非准入退出码都不返回输出引用。只有 M6.3a 导入和脱敏 artifact 完成
后外层 checkpoint 才完成。Phase 3 Admission 在 rootless Linux 上真实运行两种工具；本地 rootful
Docker Desktop 结果只算功能回归。

M6.4c 只增加固定 Trivy 0.73.0 vulnerability filesystem scan。离线 DB 必须先在执行边界之外获取，
再密封为只含 `db/metadata.json` 与 `db/trivy.db` 的只读内容寻址对象；schema、路径、文件类型、权限、
大小和摘要在 checkpoint 前及容器清理后各复核一次。Worker 只能看到只读 `/workspace/analyzer-data`，
argv 固定 `--scanners vuln` 以及 offline/update/version/telemetry 禁用参数，因此 secret、misconfiguration
和 license scanner 均不可启用。DB 下载、Target build、Broker、Docker socket 和 Submission 仍不在执行 API 中。

R11 的 Attack Graph 是操作员封存的有限 DAG，不是模型可动态扩展的队列。每个 Action 都要求绑定自身摘要的
`EXECUTE_RED_TEAM_ACTION` Approval；Initial Access 与最终 Cleanup 还要求绑定同一 Policy request 的
`MUTATE_TARGET_STATE` Approval。服务在 adapter 调用前重新读取 Scope、父 Flow、Kill Switch、checkpoint、
依赖和批准。拒绝也写入 digest-only 审计，不能因失败路径绕过可追踪性。

首个 R11 RoE 继续禁止真实凭据、外部回连、横向移动和持久化，Action schema 不存在 payload、shell、callback、
header、Cookie、credential 或响应正文字段。Post-exploitation Worker Profile 无网络、不可执行 Target、无
capability、只读根且只读 Evidence；所有真实传输必须留在受信任 adapter/Broker 边界。R11.2 的 live admission
只准入显式私网非回环 fixture、封存的 method/URL/result digest、单一 target-only grant 和 exact pinned peer；
请求不含 body、header、credential 或 redirect。Objective 证据不会提前结束链，只有最终 Cleanup 成功才进入成功态。
非 Cleanup 动作失败或超时后只允许独立获批的封存 Cleanup，原失败/超时结果会延迟到清理完成后终结；清理无法
证明时以 `cleanup_unproven` fail-closed。
默认测试不创建 socket；显式 opt-in 的本机私网进程测试已证明多步链、目标清理、进程清理与敏感 header 脱敏。

R11.3 Attack Path Report 只从权威 `goal_reached` 且 Cleanup 已证明的 checkpoint 生成。Evidence 在报告 claim 前
执行 no-follow、大小和内容摘要复核；报告只保存 Action/Observation/Evidence 摘要与有限枚举，不包含路径、完整
endpoint、请求响应或凭据。Detection Opportunity 表示应观测的位置，不等同于已部署告警；Defensive Improvement
是有限控制类别，不会执行修复。产物发布失败必须清理临时目录并留下需显式恢复的 STARTED checkpoint。

R11.4 将 Attack Chain 的动作数先以 chain digest 在父 Flow 账本持久化预留。普通 Recon 与其他 Chain 都在立即写
事务中读取同一预留总数，不能分别通过预检后超卖 `max_actions`；Chain ledger 仍执行第二层校验。跨库创建若中断，
父预留保留并允许同一内容寻址 plan 重试，选择可用性损失而不是预算失守。每个 Chain 还封存独立 Cleanup deadline，
它严格晚于普通动作 deadline、最长相差 300 秒且不超过 Scope/Flow。父 Flow Kill、Cancel 或 checkpoint 漂移后，
已经成功或执行状态不确定的 state-change 不得直接标成 cleaned/killed，而是进入 `cleanup_required`；只有仍有效的
Scope、逐动作 Approval、可追溯且单调的父账本和未过期清理窗口能放行原图中的 Cleanup。

## 4. 凭据策略

- Worker 环境从空环境开始，仅注入显式白名单变量。
- 模型密钥只存在于 Control Plane 的 Model Adapter。
- 平台 token 只存在于未来的 Submission Adapter。
- 测试身份通过 Broker 中的 opaque credential reference 使用，Agent 看不到原始值。
- `Test Identity Record` 只保存 identity/credential reference、custody proof 摘要、Scope/Target、用途、角色和
  有效期，不保存用户名、密码、Cookie、Token 或 Vault 路径。`Test Identity Admission` 仍固定不授予 credential
  access、authentication、Session 或状态变更；后续使用至少重新要求 `USE_REAL_CREDENTIALS` Approval，状态变化
  还必须同时要求 `MUTATE_TARGET_STATE` Approval。身份撤销会让已完成 Admission 的权威读取立即 fail-closed。
- Credential Session 的 Action Approval 摘要必须同时绑定 Admission、identity、purpose 和 role；同一 Admission 在
  ledger 中只能消费一次。离线认证只发布无秘密 Observation 和 Logout Proof，后者必须证明 Session released、
  zeroed 且不可复用。角色差异只是 Signal，不能绕过 Evidence Requirement、Validation 和 Critic 形成 Finding。
- 日志和 Evidence 写入前统一清理 Header、Cookie、Token、私钥和 PII。
- secret scanner 只是补充门禁，不能替代凭据不下发的架构。

## 5. 不可信附件

附件先进入 quarantine：

- 按流下载并限制原始大小。
- 计算 SHA-256 和 MIME/格式识别。
- 解压前枚举成员；拒绝绝对路径、`..`、设备文件和越界符号链接。
- 限制成员数量、单文件大小、总展开大小和压缩比。
- 解压目录使用 `noexec,nodev,nosuid`。
- 分析前生成 manifest；未知二进制不得在宿主机执行。

M1 实现采用逐成员解压，不调用 `extractall()`；拒绝符号链接、硬链接、设备文件、命名管道、路径大小写/Unicode 归一化冲突和加密 ZIP。成功结果通过原子重命名发布为只读 Target Snapshot，失败或超时清除未完成目录。

## 6. Evidence 安全

- Evidence 采用内容寻址，记录来源、时间、Target 版本、工具版本和策略版本。
- 原始 Evidence 与模型可见摘要分离。
- 普通 SQLite/FTS 只索引脱敏摘要，不保存完整 HTTP 包。
- 报告引用 Evidence ID，不复制隐私数据。
- Evidence 变更会产生新对象，不能原地覆盖。

## 7. 安全测试清单

- 子 Agent 无法读取父进程密钥。
- Worker 无法访问宿主文件、Docker socket 或其他 Target 网络。
- DNS rebinding、重定向和 IPv6 不能绕过 Scope。
- 恶意 tar/zip 不能写出 quarantine。
- Prompt Injection 不能改变工具白名单或 Approval 状态。
- 超时会终止整个进程组并清理容器、网络和 volume。
- 原始凭据不进入日志、FTS、报告或错误消息。

M8.1 的人工 Validation Intake 只持久化 Audit/Candidate/ValidationPlan 摘要、稳定决定和 reviewer identity。
它不依赖 Runner 或 Broker，不能从 Agent summary、tool intent 或 Evidence 正文生成执行参数，也不能把 accepted
解释为 Approval、Candidate 状态迁移或已执行 Validation。所有权威对象在 checkpoint 前重新打开并复核。
