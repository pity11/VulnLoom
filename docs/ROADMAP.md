# 开发路线图

## Phase 0：领域与安全骨架

目标：在没有 LLM、没有 Docker、没有网络的情况下证明核心状态机正确。

- Pydantic 领域模型与 JSON Schema。
- Candidate/Finding 状态机。
- Scope 编译与策略判定接口。
- 事件日志、Evidence 元数据和脱敏器。
- CLI：创建 Engagement、批准 Scope、查看状态。

验收：非法状态迁移、过期 Scope、缺失 Evidence 和无 Approval 的动作全部被拒绝。

## Phase 1：静态分析纵切

目标：对一个本地 Python Web 仓库生成可解释 Candidate。

- 仓库导入、commit 固定和只读源码视图。
- tree-sitter/Python AST、Semgrep Adapter。
- Source Mapper 和 Hypothesis Worker。
- 调用链与源汇位置 Evidence。
- Candidate 去重指纹。

验收：在固定小型基准集上重复运行结果稳定；每个 Candidate 都能定位入口、危险点和最便宜反证实验。

### M1：安全目标导入（已完成首版）

- ZIP/TAR quarantine、格式识别和内容摘要。
- 路径、链接、特殊文件、数量、大小、展开总量和压缩比门禁。
- 本地 Git 精确 commit 的无 checkout 快照。
- IaC Bundle 文件分类和 OCI digest 注册。
- 原子、只读、内容寻址 Target Snapshot 与 Manifest。
- Scope 拒绝、超时、清理和重复导入回归测试。

M1 不执行目标构建脚本、不拉取远程 Git、不拉取 OCI 镜像，也不连接 Docker 或 Kubernetes。远程获取必须在后续独立 adapter 中增加协议、地址和下载预算约束。

### M2：Python Web Source Mapper（已完成首版）

- 对 M1 只读 Target Snapshot 做文件级完整性复核后，以 Python AST 离线分析。
- 识别 Flask/FastAPI/Starlette 装饰器路由和 Django `urlpatterns`。
- 建立函数、跨文件调用、输入源、guard、sink 与有限深度数据流图。
- 产生确定性的 `SourceGraph` 和可解释 `StaticSignal`，不产生 Candidate 或 Finding。
- 通过 adapter 接入预注册的本地 Semgrep 规则集；不下载规则、不继承完整环境。
- 图对象内容寻址、只读持久化，事件日志只记录不含源码的统计摘要。
- 固定微型基准覆盖跨文件对象查询、FastAPI dependency、Django ownership、SSRF 输入源和语法失败。

M2 的 guard 与 taint 是保守启发式线索，不声称完整的控制流支配或运行时可利用性。下一里程碑将以这些图和 signal 为输入实现 Candidate 合并、反证任务与重复指纹。

### M2.1：静态链路稳定化（已完成）

- 测试 Scope 使用运行时基准时间，不随日历日期失效。
- `StaticSignal` 与 `Candidate.signal_ids` 统一使用内容摘要。
- `SourceGraph` 绑定 `scope_id` 和 `scope_version`，分析前重新检查 Scope 有效期与 Snapshot 归属。
- Validation queue 同样拒绝过期 Scope。
- guard 传播排除返回后的不可达代码和非支配的可选分支。
- Semgrep adapter 在解析前拒绝符号链接，输出落临时文件并限制读取大小。
- GitHub Actions 覆盖 Python 3.12、3.13、3.14 的 lint、schema drift 和测试门禁。

### M3：确定性 Candidate 生成（已完成首版）

- 仅消费完整性通过、绑定当前已批准且仍有效 Scope 的 `SourceGraph`。
- 将同一路由与 sink 的互补 `StaticSignal` 合并为一个 Candidate。
- 为已支持 sink 映射 CWE、安全不变量、前置条件和最便宜反证任务。
- Candidate 绑定 Target 版本、SourceGraph 摘要和 Scope 版本，不能脱离来源图流转。
- 使用稳定 UUID 和 SHA-256 重复指纹，重复运行产生相同 `CandidateSet`。
- 解析失败、受 guard 保护的对象查询和无法可靠归类的外部规则命中不会被提升为 Candidate。
- `CandidateSet` 内容寻址、只读持久化；普通事件只保存统计摘要。
- 覆盖成功、拒绝、超时、资源上限、幂等、符号链接拒绝和临时文件清理路径。

M3 仍只生成待人工选择的静态假设，不排队验证、不执行目标代码，也不会把 Candidate
直接升级为 Finding。下一里程碑进入 Phase 2，先实现 Sandbox Profile、Tool Broker 协议和
可离线验证的 Runner 边界，再连接 Docker。

## Phase 2：受控动态验证

目标：在本地 Docker 测试应用中验证一个人工选择的 Candidate。

- rootless Docker Runner Service。
- Static/Validation/Report 三类 Sandbox Profile。
- Tool Broker、网络 allowlist 和资源预算。
- HTTP typed tool；后续再加入 browser tool。
- Evidence Bundle 和 Critic Worker。

验收：Worker 不能访问宿主密钥、其他容器和互联网；超时后没有残留容器、进程、网络和 volume。

### M4.1：Sandbox 协议与离线 Runner（已完成首版）

- `TaskEnvelope` 绑定 Target 版本、Scope 身份和 Sandbox Profile 摘要。
- Static、Validation、Report Profile 以不可变类型表达镜像摘要、非 root 身份、挂载、网络和资源上限。
- Profile 在模型层拒绝可写根文件系统、capability、宿主路径挂载、未注册写入目录和不符合用途的网络/源码访问。
- `ToolInvocation` 只接受注册工具 ID、参数数组和逻辑工作目录，不接受 Shell 字符串或宿主路径。
- `SandboxRunner` adapter 协议与不启动进程、不访问网络的 `OfflineSandboxRunner`。
- 离线生命周期覆盖成功、拒绝、取消、墙钟/资源超限、checkpoint/resume、重试上限、幂等冲突和完整清理结果。
- Worker 环境继续从空环境和显式白名单构造，凭据型变量在请求解析与 Runner preflight 两层拒绝。

M4.1 证明的是协议、状态与 fail-closed 门禁，不声称已经实现进程、文件系统或网络隔离。
这些隔离声明必须等 M4.3 的 rootless Docker adapter 通过真实容器、网络、进程和 volume
清理测试后才能成立。M4.2 将先实现 Tool Broker 注册表与 typed HTTP tool。

### M4.2：Tool Broker 与 typed HTTP（已完成首版）

- 不可变 Tool Registry 保存 capability、版本、Profile 范围、副作用模式和 implementation digest；任务绑定 Registry digest。
- Broker 在执行前重新验证整个 Call，并同时核对 Registry、Task allowlist、Sandbox Profile、Scope/Policy 与 Worker role。
- HTTP 输入只接受固定 method、规范化 URL、安全 header、opaque credential/body digest 和显式预算；不接受原始凭据或 body。
- GET/HEAD/OPTIONS 之外的方法由可信代码标记为状态变更并进入 Approval Gate；opaque credential 使用同样需要精确 Approval。
- 每个 redirect hop 都重新检查 Scope、Profile network grant、DNS 结果和连接 peer IP；带凭据请求禁止自动 redirect。
- 默认拒绝 loopback、link-local/云元数据、multicast、unspecified、混合危险 DNS 结果和 Control Plane 指定的宿主网关地址。
- Broker 输出只包含 URL digest、状态、peer IP、预算统计、Policy 记录和 Evidence ID，不返回响应 body 或敏感 header。
- `StaticResolver` 与 `OfflineHttpTransport` 覆盖成功、拒绝、Approval、DNS rebinding、redirect、超时、大小、预算、幂等和 adapter 失败路径，全程不联网。

M4.2 证明的是 Broker 决策、typed HTTP 数据流和离线网络策略。真实 socket pinning、容器
egress、防宿主网关访问和资源清理由后续 M4.3 rootless Docker/HTTP 准入测试证明。

### M4.3：临时 Docker Runner（已完成首版）

- 已实现可信 Docker CLI adapter；Worker 不获得 Docker socket、宿主环境、镜像 tag 或宿主路径。
- 镜像绑定 exact image ID 且禁止 pull；内容挂载只由可信 object registry 解析并强制只读。
- 已实现并在创建后复核非 root、只读根、cap-drop、NoNewPrivs、network-none、CPU/内存/PID/
  open-files 限额，以及有界 `noexec,nosuid,nodev` tmpfs。
- 已用真实 Alpine 容器验证无默认路由、无 Docker socket、无宿主密钥继承、只读边界、scratch
  写入、正常清理，以及墙钟超时后的 kill 与清理。
- 已实现 Broker-owned live HTTP/HTTPS adapter：系统解析结果经现有策略筛选后固定数字 IP，连接
  不使用代理环境，Host/TLS hostname 保持授权域名，实际 peer 再由 Broker 复核。
- offline/live resolver 与 transport 使用不同 implementation digest，Broker preflight 要求两者
  同时匹配 Task 绑定的 Tool Registry，禁止排队后静默替换网络实现。
- request body 从 O_NOFOLLOW 的内容寻址对象读取，凭据从独立 opaque provider 注入；原始数据
  不进入 Broker result。响应预算、redirect shape、超时/失败和脱敏 Evidence 路径已有离线测试。
- 已用真实 loopback socket 验证固定 IP 连接、Host 保留，以及敏感 header、JSON secret、邮箱和
  raw URL 不进入普通 Evidence 内容。
- 生产默认同时要求 rootless、seccomp、cgroup v2 和可执行的内存、CPU quota、PID 控制；仅报告
  部分 capability、但无法真实启动受限容器的 daemon 会 fail-closed。
- Docker Worker 的直接 `TARGET_ONLY` 仍 fail-closed 拒绝，授权网络访问由可信 Broker 承担。
- Ubuntu 24.04 准入工作流以 systemd 用户服务运行固定 Docker Engine 29.7.2，真实验证 Worker
  无默认路由且无法访问 live sibling container 与 daemon gateway；Broker 使用实际 gateway denylist
  并在 socket 前拒绝，redirect 第二跳 DNS 漂移到 metadata 地址同样在第二次连接前拒绝。
- 同一准入工作流覆盖正常执行、超时 kill、容器与匿名存储清理，以及 Docker Runner、pinned
  Broker、Evidence、确定性裁决和 Candidate 状态转换的完整组合。M4.3 已满足进入 Phase 3 的门禁。

### M4.4：事务性 Validation Orchestrator（已完成首版）

- 人工选择、Candidate/Target/Scope 来源、network-none Runner 请求和有界 Broker 调用封装为内容寻址 `ValidationPlan`。
- 执行前重查 Candidate 状态、Scope 有效期、Policy/Profile digest、Validator role 和 Candidate input binding。
- SQLite 以 `STARTED/COMPLETED` 保存权威 checkpoint；完成结果幂等返回，未完成任务拒绝自动重放。
- Runner 非成功时不进入 Broker；Broker 拒绝、缺审批、超时和失败分别映射为 fail-closed 领域结果。
- 执行成功不等于漏洞复现。默认 judge 只返回 `INCONCLUSIVE`；可信确定性 judge 只能引用本次采集的 Evidence ID。
- 生成 `ValidationRun`/`EvidenceBundle` 并通过既有状态机更新 Candidate，但不包含 Critic、Finding promotion 或外部提交。
- 离线 CLI 只验证 Control Plane 编排，不执行目标代码、不调用 Broker、不联网，也不宣称复现。

### M4.5：确定性 HTTP 断言（已完成首版）

- 人工在执行前封存 `HttpResponseAssertion`，并绑定一个确切 Broker call。
- 复现判据必须同时匹配状态码和最终原始响应正文 SHA-256；只匹配状态码不能得到 `REPRODUCED`。
- Broker result 只增加正文摘要，不携带原始正文；正文仍只经过脱敏后写入 Evidence Store。
- `DeterministicHttpJudge` 默认只信任 live pinned HTTP Registry；精确匹配时返回预先选择的 `REPRODUCED`/`NOT_REPRODUCED`，离线 Registry 或不匹配时固定为 `INCONCLUSIVE`。
- 编排层在裁决和封装 Evidence Bundle 前，以 no-follow、大小上限和内容摘要校验每个 Evidence 对象。
- opt-in 组合测试已串通真实临时 Docker Validator、Broker-owned pinned HTTP、本机授权夹具、Evidence、裁决、状态转换和清理。
- 本机 Docker Desktop 组合测试仍使用 rootful 测试例外，不能单独提供生产准入；同一组合已在专用 rootless Linux 准入工作流中通过。

## Phase 3：报告闭环

目标：把 Finding 转换为一致、脱敏、可人工提交的报告。

- 通用报告模板。
- EduSRC/CNVD/厂商字段映射。
- 证据一致性检查。
- 人工审阅界面或 CLI diff。
- 导出 Markdown/JSON，不联网提交。

验收：报告中的代码位置、请求响应和影响结论都能反向解析到 Evidence ID；凭据脱敏测试通过。

### M5.1：确定性 Critic 与独立反证审查（已完成首版）

- `CriticPlan` 内容寻址绑定 Candidate、成功 Validation Run、Evidence Bundle、Scope 版本、验证上下文与独立审查上下文。
- 验证与审查 producer 必须不同；固定覆盖安全控制、路径可达性、环境一致性和版本绑定四个反证角度。
- 固定裁决优先级为反证成立、信息不足、反证排除；信息不足保持 `VALIDATED`，不得进入 Finding 门禁。
- 每个确定性角度必须引用 Evidence；状态变化前再次执行 no-follow、大小、摘要和 Target 版本完整性检查。
- SQLite 保存 STARTED/COMPLETED checkpoint；完成结果幂等返回，未完成执行拒绝自动重放。
- Critic 不执行目标、不调用 Broker、不联网、不生成 Finding 或提交报告；Finding promotion 仍要求当前有效 Scope、成功复现、完整 Evidence、绑定的 Critic 通过和 duplicate check。

M5.1 的反证 disposition 是可信控制面封存的类型化观察，不从 Worker prose、模型置信度或普通日志推导。M5.2 在此门禁之后消费已验证 Finding，不回写 Critic 结论。

### M5.2：Evidence 一致的离线报告草稿（已完成首版）

- `ReportDraftPlan` 内容寻址绑定 Finding、已提升 Candidate、Finding 的 Evidence Bundle、Scope 版本、渠道、受限文本和逐节 Evidence 引用。
- 代码位置、请求/响应、复现和影响章节必须引用 Bundle 内 Evidence；生成前复核全部 Bundle 对象的 no-follow、大小、摘要和 Target 版本。
- 文本在持久化前统一脱敏；Markdown 转义 HTML 和可触发外部资源的图片/链接语法，不复制 Evidence 正文。
- 通用、EduSRC、CNVD、厂商和 CVE 草稿使用确定性标题映射，输出内容寻址且只读的本地 Markdown/JSON。
- SQLite 保存 STARTED/COMPLETED checkpoint；完成结果幂等返回，未完成执行拒绝自动重放，写入失败清理临时目录。
- 新报告固定为 `draft`，不包含人工批准、平台凭据、网络 adapter 或 Submission；发送到外部平台仍必须经过独立 Approval Gate。

M5.2 的“本地导出”只表示生成供人工审阅的文件，不把 Report 状态提升为 `exported`，也不产生任何外部副作用。下一里程碑将实现人工审阅/diff 与显式批准状态机。

## Phase 4：评测与扩展

- 接入 BountyBench、AutoPenBench 和自建 ground truth。
- 指标：Candidate recall、验证后 precision、重复率、证据完整度、单 Finding 成本、运行时间和策略违规数。
- 增加 Agent/MCP 安全和本地云原生配置分析。
- 评估 CodeQL、Trivy、Checkov、Kubesec、Playwright。

## 延后事项

- 公网资产自主发现。
- 自动化漏洞平台提交。
- 自动申请 CVE。
- 通用任意 Shell。
- 多租户 SaaS。
- 直接连接生产 Kubernetes 集群。

这些能力会显著扩大授权、隔离和运维边界，不应在本地研究 MVP 中提前引入。
