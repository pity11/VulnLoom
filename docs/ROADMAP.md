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

M5.2 的“本地导出”只表示生成供人工审阅的文件，不把 Report 状态提升为 `exported`，也不产生任何外部副作用。M5.3 在此草稿上执行显式人工决策。

### M5.3：人工审阅、版本 Diff 与批准后本地导出（已完成首版）

- 相同 Finding/渠道使用稳定 report family；第 2 版起必须绑定紧邻前一版的完整 Report digest。
- 结构化 Diff 确定性比较标题、逐节文本和 Evidence 引用；拒绝无变化、跨 family、跳版和未脱敏输入。
- `ReportReviewPlan`/`Command`/`Record` 绑定 Report、只读 artifact、Evidence Bundle、Scope、reviewer、Diff、决策截止时间和批准过期时间。
- 显式状态机只允许 `DRAFT → HUMAN_APPROVED | CHANGES_REQUESTED | REJECTED`，以及 `HUMAN_APPROVED → EXPORTED`。
- Report 内容、引用或 artifact 任一变化都会使旧审阅计划失效；同一计划的冲突决定 fail-closed，未完成 checkpoint 不自动重放。
- 批准前重新验证 Scope、Evidence 和 artifact；批准过期后拒绝本地导出。
- `report-review-diff`、`report-review-offline` 和 `report-export-local` 均为离线路径，不包含网络、平台 token 或 Submission。

M5.3 的 `EXPORTED` 仅表示批准后的本地 Markdown/JSON 产物。`SUBMITTED` 没有可达状态迁移；未来任何外部发送仍必须增加独立 adapter，并验证精确、未过期的 `SUBMIT_REPORT` Approval。

## Phase 4：评测与扩展

- 接入 BountyBench、AutoPenBench 和自建 ground truth。
- 指标：Candidate recall、验证后 precision、重复率、证据完整度、单 Finding 成本、运行时间和策略违规数。
- 增加 Agent/MCP 安全和本地云原生配置分析。
- 评估 CodeQL、Trivy、Checkov、Kubesec、Playwright。

### M6.1：确定性离线评测基线与回归门禁（已完成首版）

- `BenchmarkSuite`、ground truth、观察集、策略和 baseline 均为严格类型化、内容寻址的本地对象。
- 观察到的 Finding 必须显式满足 reproduced Validation、accepted Critic、Candidate promotion 和完整 Evidence；否则 schema 直接拒绝，不能用评测数据绕过生产门禁。
- 纯 reducer 计算 Candidate recall、Finding precision、重复率、Evidence 完整度、策略违规数、运行时间、总成本和单 Finding 成本。
- 回归策略同时支持绝对阈值与绑定 exact suite 的 baseline 差值，输出稳定 violation code；失败 CLI 返回非零状态供 CI 使用。
- SQLite 使用 STARTED/COMPLETED checkpoint，完成结果幂等返回，未完成任务拒绝自动重放；JSON/Markdown 结果内容寻址、只读、大小受限且 no-follow 校验。
- 仓库内 `benchmarks/m6_1` 微型 ground truth 可重复生成；常规 CI 检查 fixture/schema 漂移并运行离线回归门禁。
- M6.1 不获取 BountyBench/AutoPenBench，不启动 Runner，不调用 Broker，不联网，也没有 Submission 或凭据字段。

### M6.2：外部 Benchmark 本地快照 Adapter（已完成首版）

- BountyBench 与 AutoPenBench 使用各自固定 ID/version/digest 的 adapter；ImportPlan 精确绑定 snapshot、adapter、limits、deadline 和幂等键。
- 输入只接受预先获得的本地目录，不接受 URL、不下载数据、不解压归档、不执行上游 setup/exploit/verify/Docker 文件。
- snapshot manifest 覆盖每个常规文件的 NFC 归一化相对路径、大小和 SHA-256；导入前后均全量复核，并拒绝 symlink、特殊文件、路径碰撞、数量/大小超限、超时和并发内容变化。
- BountyBench 只消费官方 `bounty_metadata.json` 的 CWE/CVE/vulnerable_commit；缺失或 unsupported CWE 形成显式 exclusion。
- AutoPenBench `games.json` 中的 task/flag 不进入 suite、artifact 或 CLI 输出；CWE 必须来自同一 snapshot 内封存的显式 sidecar，缺失映射形成 exclusion，陈旧/非法映射整体拒绝。
- 规范化 suite 内容寻址并只读落盘；SQLite STARTED/COMPLETED checkpoint 支持幂等完成、冲突拒绝和显式恢复，失败清理临时对象。
- `benchmark-snapshot-manifest-local` 与 `benchmark-import-offline` 均为离线命令，没有 Runner、Broker、credential、Submission 或公网能力。

M6.2 不声称执行或复现外部 benchmark。M6.3 再以统一 Observation 协议评估本地 CodeQL、Trivy、Checkov、Kubesec 等 adapter。

### M6.3a：预计算分析器结果的统一 Observation Adapter（已完成首版）

- CodeQL SARIF 2.1.0、Trivy JSON、Checkov JSON 与 Kubesec JSON 使用固定 adapter ID/version/digest。
- 输入是预先生成的本地常规文件；VulnLoom 不启动分析器、不下载规则/数据库/镜像、不读取 URL，也不连接 Docker 或网络。
- `AnalyzerResultSnapshot` 精确绑定 Target、版本、工具版本、规则摘要、输出摘要和可选 CWE sidecar；ImportPlan 再绑定 adapter、资源上限、deadline 与幂等键。
- 输出统一为只含规则摘要、CWE、严重度、消息摘要和安全相对位置的 `AnalyzerObservationSet`；原始消息、Secret match、Kubernetes object 名称和规则原文不进入 artifact、checkpoint 或 CLI 摘要。
- 原生缺少 CWE 的 Checkov/Kubesec 观察必须使用同一 snapshot 封存的显式 sidecar；缺失映射形成 typed exclusion，非法或陈旧映射整体拒绝。
- 输入在解析前后都执行 no-follow、常规文件、大小与 SHA-256 复核；重复 JSON key、symlink、特殊文件、内容漂移、超限和超时 fail-closed。
- SQLite STARTED/COMPLETED checkpoint 与只读内容寻址 artifact 支持幂等 replay、冲突拒绝、显式恢复和失败清理。
- Analyzer Observation 没有 Candidate/Finding/Validation/Critic 字段，不能成为 Finding，也不能替代 M6.1 的完整工作流 Observation。

### M6.3b：显式 Ground Truth 对齐与跨工具回归门禁（已完成首版）

- `AnalyzerTruthAlignment` 绑定 exact BenchmarkSuite、case、ObservationSet 摘要和逐条 Observation→truth match；alignment provenance 只允许固定 fixture 或人工审查。
- CWE 相同不会自动形成 match。显式 match 仍须满足同 case、同 Target version、truth 属于该 case，且 matched CWE 同时存在于 truth 与 Observation。
- 同一 Observation 不得匹配多个 truth；同一 truth 的多条 match 作为重复命中统计，不隐式丢弃。
- reducer 同时计算总体与逐 analyzer 的 truth recall、observation precision、duplicate rate、exclusion rate，以及原始计数。
- policy 支持总体与逐 analyzer 阈值、必需 analyzer、完整 case×analyzer 矩阵，以及 exact suite baseline 的 recall/precision/duplicate/exclusion 回归限制。
- `AnalyzerEvaluationPlan` 绑定 suite/alignment/policy/limits/baseline/deadline/幂等键；语义或资源校验在 STARTED checkpoint 前完成。
- SQLite checkpoint、只读内容寻址 JSON/Markdown artifact、幂等 replay、冲突/遗留恢复和失败清理均为离线路径。
- 仓库内 `benchmarks/m6_3` 固定覆盖 CodeQL、Trivy、Checkov、Kubesec；常规 CI 检查 fixture/schema 漂移并运行 M6.3 gate。
- `analyzer-evaluate-offline` 只读取 sealed suite、ObservationSet、alignment 和 plan，不执行 analyzer，不改变 Candidate/Finding，不调用 Runner/Broker，也不联网。

M6.3 至此完成离线导入与跨工具评测首版。受控执行分析器属于后续独立里程碑，必须复用 Runner/Tool Broker 并固定本地工具、规则数据库或镜像摘要。

### M6.4a：分析器执行协议与离线 Runner（已完成首版）

- `AnalyzerToolRegistration` 固定 analyzer/tool 版本、exact image ID、规则摘要、Observation adapter、绝对入口、完整 argv、空基线环境和唯一输出位置；不接受 Shell 字符串、占位符、URL 或运行时追加参数。
- `AnalyzerExecutionPlan` 精确绑定 Target Snapshot/Manifest、Scope/Policy、Tool Registry、Registration、Sandbox Profile、Runner Request、deadline 和幂等键。
- 新增独立 `ANALYZER` Worker role；专用 Profile 只读挂载源码、使用非 root 身份、无 capability、只读根、`network=none` 和有界临时/输出目录，并禁止执行目标代码。
- Tool Registry 直接从 sealed argv 生成 Docker Runner 注册项，避免真实 adapter 手工重组命令；镜像仍为 exact ID 且禁止 pull。
- `OfflineAnalyzerExecutionService` 只验证控制面协议并调用不启动进程/容器/网络的 Offline Runner；成功状态明确为 `protocol_completed`，结果固定不含 `AnalyzerResultSnapshot`，不伪称真实分析器已运行。
- SQLite STARTED/COMPLETED checkpoint 覆盖完成幂等返回、冲突拒绝和遗留任务显式恢复；测试覆盖成功、拒绝、超时、失败、取消与完整清理。
- `analyzer-execution-check-offline` 只加载已验证本地 Target Snapshot 和密封 JSON，不安装/运行分析器、不连接 Docker/Broker/网络，也不产生 Observation、Candidate、Finding 或 Submission。

M6.4a 只证明类型化协议和离线编排。

### M6.4b：真实 Checkov/Kubesec source-only 执行（已完成首版）

- 仅准入两个精确 factory：Checkov 3.3.15 与 Kubesec 2.14.2；Registration 固定镜像 ID、绝对入口、完整 argv、镜像声明环境和 M6.3a adapter/CWE map 摘要。
- Docker 运行期使用 exact image ID、`--pull never`、`network=none`、只读源码/根文件系统、非 root、无 capability、`no-new-privileges` 和有界资源；不执行 Target build script。
- Runner 通过 attached stdout 有界捕获 JSON，在容器删除前做 no-follow、常规文件、大小和 SHA-256 校验，再原子发布只读内容寻址对象；超限、超时、非准入退出码和捕获错误均不发布输出引用。
- 工具成功码属于密封注册项：Checkov 只接受 `0`；Kubesec 精确接受 `0/2`，其中 `2` 表示产生安全发现，而非放宽全局 Runner。
- `DockerAnalyzerExecutionService` 完成 Scope/Target/Policy/Profile/Registry/CWE 预检和独立 SQLite checkpoint 后执行容器；只有成功输出通过既有 M6.3a 导入并生成脱敏 ObservationSet，外层状态才可为 `COMPLETED`。
- 常规测试覆盖成功、拒绝、超时、捕获失败、清理、幂等冲突与遗留 checkpoint；Phase 3 Admission 在 rootless Linux 上预置版本化官方镜像并真实运行两条禁网执行/导入链。

M6.4b 不新增 CLI、镜像拉取器、网络能力、Target build、Candidate/Finding promotion 或 Submission。Trivy 的密封离线数据库执行由 M6.4c 独立增加；CodeQL database build 等会执行目标构建脚本的模式必须使用独立 `RUN_UNTRUSTED_BUILD` Approval。

### M6.4c：Trivy 密封离线数据库执行（已完成首版）

- 仅准入 Trivy 0.73.0 的精确 factory；Registration 固定 exact image ID、完整 argv、空白名单环境、M6.3a Trivy adapter 和密封 DB 摘要。
- `TrivyDatabaseSnapshot` 只接受只读 `db/metadata.json` 与 `db/trivy.db`，要求 DB schema v2，并对路径、符号链接、特殊文件、单文件大小、总内容摘要、重复 JSON key、超时和内容漂移 fail-closed。
- DB snapshot ID 同时作为 Registration 的 `rules_digest` 和 Task 的 `analyzer-data` 输入；专用 `/workspace/analyzer-data` 内容挂载只读，并由 Docker inspect 与可信 Object Store 复核。
- 固定 argv 只启用 `--scanners vuln`，显式关闭 DB/Java/check/VEX 更新、version check 和 telemetry，并使用 `--offline-scan`；secret、misconfiguration 与 license scanner 均不可表示。
- Docker 运行继续使用 exact image ID、`--pull never`、`network=none`、只读根/源码/DB、非 root、无 capability、no-new-privileges 和有界 attached stdout。
- 执行前及容器清理后再次全量复核 DB；只有输出通过 M6.3a 导入并生成脱敏 `AnalyzerObservationSet` 后外层 checkpoint 才能完成。
- 常规测试覆盖成功、非准入参数、可写/链接/额外文件、大小与 schema 拒绝、执行前/中漂移、超时、输出捕获和清理；Phase 3 Admission 在 rootless Linux 上于执行外预置 DB 后运行真实禁网链。

M6.4c 不包含 DB/镜像下载 API、secret scanner、Target build、Broker、Candidate/Finding promotion 或 Submission。CodeQL database construction 仍留待独立且要求 `RUN_UNTRUSTED_BUILD` Approval 的里程碑。

### M6.4d：CodeQL 预建数据库查询执行（已完成首版）

- 固定 CodeQL CLI 2.26.2，Registration 只表达 `database analyze`、一个密封预编译查询包和 SARIF 输出；不表达 `database create`、查询包下载、Target build、Shell 或网络位置。
- `CodeQLSnapshot` 将预建 `database/` 与 `queries/` 作为一个只读内容对象密封；固定 Target/version/Manifest、database/query-pack metadata、`.qls` 与预编译 `.qlx`，并对归一化路径、文件/entry 数量、大小、空目录、符号链接、特殊文件、权限、内容漂移和超时 fail-closed。
- snapshot 禁止携带旧 `database/results`，其 ID 同时绑定 Registration `rules_digest`、Task `analyzer-data` 输入与只读挂载；错误 Target 数据库在 checkpoint 前拒绝。
- Offline Runner 可以验证完整 Scope/Target/Policy/Profile/Registry 协议，但结果仍明确为 `protocol_completed`，不生成分析结果或 Observation。
- 精确 wrapper 在 Runner 的有界 `/workspace/output` tmpfs 中 no-follow 复制数据库，核对精确文件/entry/byte 数后才调用 `/opt/codeql/codeql database analyze`；CodeQL 的 `results` 写入仅发生在该副本，原始 DB/查询包始终只读并在容器清理后全量复核。
- 固定参数只允许一个 sealed `.qls`、SARIF 2.1.0、单线程和 `/tmp` cache；显式禁止 SARIF file contents、snippets 与 query help，且不含 `database create`、`--download`、URL、shell 或运行时参数。
- Docker 继续强制 exact image ID、`--pull never`、`network=none`、只读根/源码/原始 analyzer-data、非 root、无 capability、no-new-privileges、有界 tmpfs/attached stdout 和容器清理；成功 SARIF 必须经过 M6.3a CodeQL adapter 才能完成外层 checkpoint。
- Phase 3 Admission 使用不构建 Target 的 CodeQL 行为 fixture，在真实 rootless 容器中证明 wrapper 只能改写有界副本、原始 DB 不产生 `results`、输出被导入 Observation 且容器被删除；它不替代运营方对真实 CodeQL bundle、许可与预建数据库兼容性的单独资格审查。

M6.4d 运行期不下载 CodeQL、数据库或查询包，不执行 Target build，不启用公网、secret scanner、Candidate/Finding promotion 或 Submission。数据库构建继续要求独立 `RUN_UNTRUSTED_BUILD` Approval。

### M6.5：分析器执行资格闭环（已完成首版）

- `AnalyzerExecutionEvidenceBinding` 将 benchmark case 精确绑定到一个已完成的 M6.4 Docker execution plan、admitted registration、清理完备 outcome 与 M6.3a ObservationSet 的完整摘要。
- `AnalyzerQualificationPlan` 同时封存 exact suite、显式 truth alignment、M6.3b evaluation plan、required-analyzer 集合和完整 case×analyzer 执行矩阵；同一 registration 可跨 case 复用，但 execution plan 与 ObservationSet 不可复用。
- 资格服务要求 outcome 存在于权威 M6.4 Docker `COMPLETED` checkpoint，并在任何新 checkpoint 前复核全部 Target/version/Manifest、Scope、registration、execution outcome、cleanup、ObservationSet、alignment 和 evaluation 摘要；失败、超时、取消、清理不完整、缺项或内容漂移均 fail-closed。
- 只有完整执行证明链才能调用既有 M6.3b reducer；评测 PASS/FAILED 均作为类型化资格 outcome 保存，不会把指标失败误报为执行失败。
- SQLite 使用独立 STARTED/COMPLETED checkpoint；相同计划幂等返回，冲突 key 和未完成 replay 均拒绝。语义拒绝发生在 qualification/evaluation checkpoint 之前。
- M6.5 不增加 Runner、Docker、Broker、网络、credential、Target build、secret scanner、Candidate/Finding promotion 或 Submission 能力，也不改变 M6.4 的 rootless Phase 3 Admission 结论。

### M6.6：四分析器端到端资格准入（已完成首版）

- 同一授权 Target/Manifest/Scope 上依次执行 exact-image Checkov、Kubesec、Trivy 与 CodeQL，四个 outcome 写入同一权威 Docker execution store，并全部强制完成 M6.3a Observation 导入和容器清理。
- M6.5 逐 case 不变量进一步要求所有 analyzer cell 使用相同 Target ID/version、Manifest ID 与 Scope ID/version，禁止只靠相同版本字符串混合不同目标。
- rootless Phase 3 Admission 将四个真实 execution plan/registration/outcome 封存为完整 case×analyzer 资格矩阵，再调用既有 M6.3b deterministic reducer。
- 真实组合测试先证明缺少任一 outcome 与篡改 completed outcome 都在 qualification/evaluation checkpoint 前拒绝，再证明完整四工具矩阵产生 PASS outcome。
- 单工具 Admission probe 仍独立保留，便于定位 image、DB、wrapper、输出、导入或清理失败；campaign probe 不替代 M6.4 的逐工具隔离证据。
- M6.6 没有新增 analyzer 参数、网络、Target build、secret scanner、credential、Candidate/Finding promotion、报告状态变化或 Submission。

## Phase 5：类型化 Agent Runtime

目标：在引入任何实时模型服务前，把模型调用、结构化决策、预算、工具提案与恢复语义固化为可离线测试的可信控制面协议。

### M7.1a：离线类型化 Agent Runtime（已完成首版）

- `AgentModelRegistration` 只准入内容寻址的 `offline_replay` adapter，并固定 provider/model 身份、支持的 Worker role 和单步输出预算；不包含 endpoint、API key 或 token。
- `AgentRunPlan` 精确绑定 `TaskEnvelope`、模型注册、上下文摘要、决策 schema、步数/token/墙钟预算、deadline 与幂等键；Task 自身继续绑定 Scope/Policy/Profile/Tool Registry。
- 每一步只向 adapter 暴露摘要、role、显式工具白名单和剩余预算；模型响应必须通过严格 `AgentDecisionPayload`，无效结构只能在总预算内有界重试。
- 工具决策只生成参数摘要化的 `AgentToolIntent`，Runtime 不调用 Runner/Broker、不执行工具；Task 工具预算或白名单不允许时 fail-closed。
- 结构化响应有独立字节上限；token、墙钟、model identity、schema、参数大小与 NUL 校验均在完成 checkpoint 前强制执行。
- SQLite 使用 STARTED/COMPLETED checkpoint；完成结果幂等返回，adapter 中断保留 STARTED 并拒绝自动重放。原始响应和原始工具参数不落库。
- 常规测试覆盖完成、blocked、越权提案、结构重试、token/超时/输出超限、过期计划、幂等冲突、中断恢复和清理。

M7.1a 不接入公网模型、provider SDK、模型凭据、真实工具执行、Target build、Candidate/Finding 状态变化、Approval 消费或 Submission。后续 live adapter 必须作为独立里程碑增加网络、凭据、速率、响应捕获和 Admission 边界。

### M7.1b：Control Plane 凭据租约与本地假 Provider（已完成首版）

- `ModelCredentialReference` 只封存允许读取的单个环境变量名称及内容摘要，不携带凭据值，也不导出父进程环境。
- `EnvironmentModelCredentialProvider` 只解析启动时显式准入的精确引用；未注册引用在读取环境前拒绝。凭据进入非序列化 `ModelCredentialLease` 字节缓冲，并在上下文退出、异常和超时结果前归零。
- `ModelProviderConfig` 不再直接返回 API key 字符串，只持有 credential reference；Worker `TaskEnvelope`、`AgentStepRequest` 和环境白名单均不包含该引用或密钥。
- 新增内容绑定的 `local_fake_provider` registration 与 adapter。它只在内存中校验请求/credential 摘要并返回固定结构化 turn，不创建 socket、不解析 URL、不调用 SDK。
- Agent Runtime 同时准入 offline replay 与 local fake 两个无网络 adapter；registration/credential reference 任一漂移均在调用前拒绝。
- 原始 credential、无关环境变量、原始响应与工具参数均不进入 request、outcome、checkpoint 或 schema；错误消息只返回稳定边界错误。
- 测试覆盖成功、缺失凭据、错误凭据、超时后清零、STARTED 恢复拒绝、引用篡改、registration 漂移和 Worker 环境不继承。

M7.1b 只证明 Control Plane 内的凭据生命周期和 adapter 绑定，不声称进程级隔离，也不增加 live endpoint、DNS、HTTP、proxy、provider SDK、真实工具执行或任何领域状态变化。实时模型出口仍需独立 Admission。

### M7.2：密封、脱敏且有界的模型上下文（已完成首版）

- `AgentContextSource` 是不可序列化的瞬时输入；source ref 必须与 `TaskEnvelope.input_refs` 完整、同序、一一对应，缺失、插入、替换和重排均在读取模型前拒绝。
- 可信 assembler 统一执行 NFC/换行规范化、控制字符拒绝和 `builtin-v2` 凭据/Cookie/PII 脱敏，不接受调用方“已经脱敏”的声明。
- `AgentContextLimits` 同时限制 fragment 数、原始单片字节、脱敏单片字节、总字节和墙钟时间；截止时间或装配中超时均 fail-closed。
- snapshot 只保存 source ref 摘要、类型、明确的 `untrusted=true`、脱敏文本及其摘要，并绑定 Task/Target/Scope/input refs/redaction policy。
- `AgentContextStore` 原子发布只读内容寻址 JSON；读取强制 no-follow、常规文件、不可写、大小、schema、对象 ID 与内容摘要复核，发布失败清理临时文件。
- `AgentRunPlan` 可绑定 exact context snapshot ID；Runtime 在 STARTED checkpoint 前必须从显式 context store 重读并复核 Task/对象完整性。`AgentStepRequest` 只携带该摘要，不复制脱敏文本，更不包含原始 source。
- 测试覆盖成功、凭据/邮箱脱敏、prompt-injection 文本不改变 untrusted 标记、引用注入、资源超限、超时、Task/内容漂移、symlink、可写对象、存储上限和清理。

M7.2 不读取原始 Evidence Store 正文、不自动选择上下文、不把上下文当授权，也不增加 live provider、网络、工具调用或领域状态变化。后续 prompt rendering 必须从已复核 snapshot 构造固定角色消息。

### M7.3：固定模板 Provider Message Envelope（已完成首版）

- 每个 `WorkerRole` 只对应一个内容寻址的 `builtin-v1` template；system message 由可信代码生成，调用方不能提供、替换或版本漂移。
- user message 使用确定性 strict JSON，把 Task/Target/Scope 摘要、工具白名单、tool-call/output 预算和 decision schema 放在独立 control 区，把脱敏 fragment 放在 `untrusted_context` 数组。
- context 中伪造的 `allowed_tools`、`can_execute_tools` 或 prompt 指令只是 JSON string 数据；envelope control 固定 `can_execute_tools=false`，真实权限仍由 Runtime/Broker 强制。
- `AgentMessageLimits` 分别限制 system/user/总字节与渲染墙钟；重复 JSON key、字段增删、ordinal/trust 漂移、未脱敏 fragment 和超限/超时均拒绝。
- `AgentMessageEnvelope` 内容寻址绑定 plan/task/context/model/template/schema/工具/预算和两条消息；schema 反序列化时重新验证 builtin system 与 strict user JSON。
- context-bound Runtime 在 STARTED 前重新渲染首步 envelope，并把其 ID 封入 `AgentStepRequest`；后续重试按 step/剩余预算生成新 envelope。
- offline replay 与 local-fake adapter 接收 envelope，但仅记录 request 与 envelope ID；消息正文和 context 不进入 Agent checkpoint/outcome。
- 测试覆盖七种 Worker role、system/template 篡改、control 注入、重复键、trust 漂移、请求绑定、字节/超时门禁、adapter 摘要匹配和 SQLite 无正文。

M7.3 不把 system prompt 当安全边界；它没有 live provider、HTTP/SDK、网络、凭据扩散、工具执行、Approval 消费、Candidate/Finding 转换或 Submission。实时 adapter 仍需独立出口与响应捕获 Admission。

### M7.4：Provider 传输 Admission 协议（已完成首版）

- `AgentProviderTransportAdmission` 内容寻址绑定 exact provider hostname、TLS 443、canonical path、credential reference、adapter digest、请求/响应字节上限和墙钟。
- 当前 mode 只能是 `admission_fake`，并强制 redirect/proxy 关闭、DNS revalidation 开启、raw response 不持久化、单次 attempt 和 `network_enabled=false`；任何放宽都在 schema 层拒绝。
- `AgentProviderTransportRequest` 只保存 StepRequest/Envelope/admission/registration/credential reference 和瞬时请求正文的摘要、字节数与预算；不保存 endpoint URL、header、token 或正文。
- no-network adapter 从 exact Message Envelope 构造瞬时请求缓冲，完成凭据租约、响应字节捕获、strict JSON、provider/model identity 和类型化 reply 校验，并在所有路径归零请求/响应/credential 缓冲。
- `AgentProviderTransportAttempt` 与成功 receipt 只记录内容摘要、计数、稳定状态和 cleanup 证明；Runtime 将传输拒绝/超时分别归一为 FAILED/TIMED_OUT outcome。
- 测试覆盖成功、network/redirect/proxy 放宽、registration/admission/credential 漂移、StepRequest/Envelope 漂移、超限、畸形响应、身份漂移、超时、清理和 SQLite 无正文/密钥。

M7.4 是 live transport 的离线 Admission 协议，不是实时 provider 实现；没有 DNS、socket、HTTP、SDK、proxy、自动 retry、工具执行、Approval 消费、Candidate/Finding 转换或 Submission。真实 HTTPS 出口仍需独立进程/网络隔离、DNS/rebinding、TLS 和生产日志 Admission。

### M7.5：独立进程 pinned HTTPS Provider Transport（已完成首版）

- `subprocess_https_provider` registration 绑定固定实现摘要；调用方不能提供 executable、argv、header、URL、proxy、SDK 或 retry 策略。
- `live_https` 只接受 canonical hostname、443、全局地址策略和显式 `network_enabled=true` Admission；`loopback_https_probe` 只能使用 `.test` hostname、loopback 地址、exact 动态端口和摘要绑定的测试 CA。两种模式不可互换。
- Control Plane 每次调用重新解析 exact hostname；空、超量、私网/loopback/metadata/混合地址在凭据读取前拒绝。子进程只连接选定 numeric IP，并复核 socket peer。
- 固定子进程使用 Python isolated mode、`/` cwd、close-fds、新进程组、最小环境、无 shell、stderr 丢弃、资源上限、父层 bounded stdout 和 timeout kill；credential/message/CA 通过有界二进制 stdin frame 传递。
- 子进程强制 TLS 1.2+、SNI/hostname 校验、exact POST path、identity encoding、无 redirect、64 KiB header 上限和有界流式 response；父层再次复核 peer/TLS/响应 shape/provider/model。
- admission 固定单 attempt，并以内容绑定的每分钟请求上限拒绝突发；没有自动 retry。attempt/receipt 只增加 peer IP 摘要、TLS version、process/network cleanup 证明，不保存 endpoint URL、credential、message 或 raw response。
- 默认测试不创建 socket；opt-in/Phase 3 probe 用 self-signed sealed CA 和 loopback TLS server 证明真实进程、空环境、numeric pinning、timeout kill 与完整 Runtime composition。

M7.5 不提供 provider-specific SDK/response mapping、CLI/API 默认入口、任意 URL、Target 网络访问、工具执行、Approval 消费、Candidate/Finding 转换或 Submission。CI 不连接公网 provider；生产 `live_https` 仍需运营方对 exact provider hostname、credential reference、CA/出口和配额单独签发 Admission。

### M7.6：Provider Egress Admission 签发与生命周期（已完成首版）

- `AgentProviderEgressIssuerPolicy` 内容寻址绑定受信 issuer、允许的 provider/mode 和最长 grant 生命周期；fake/no-network mode 不可签发。
- `AgentProviderEgressGrant` 精确绑定 transport Admission、provider、mode、credential reference、adapter digest、issuer policy、用途、签发/过期时间和幂等键；live inference 与 loopback probe 用途互斥。
- 可信 Authority 在任何 checkpoint 前验证 issuer policy、provider/mode、用途、期限和 deadline；未知 issuer、越权 provider/mode、超期或错误用途均拒绝。
- grant/revocation 使用原子发布的只读内容寻址对象；读取强制 no-follow、常规文件、不可写、大小、schema、对象 ID 与摘要复核。
- SQLite lifecycle ledger 对签发和撤销分别使用 `STARTED/COMPLETED` checkpoint；相同内容幂等返回，冲突 key、遗留 STARTED 和并发未决撤销 fail-closed。
- 状态显式为 `active/revoked/expired`。`AgentModelRegistration` 绑定 exact grant ID；live adapter 每次调用在 DNS、rate slot、credential lease 和子进程之前重新读取对象与 ledger，并复核 exact Admission 绑定。
- 常规测试覆盖签发、幂等、拒绝、deadline timeout、发布清理、冲突、STARTED 恢复、到期、撤销、symlink/可写对象、Admission 漂移和 pre-DNS/pre-credential 拒绝；Phase 3 loopback TLS composition 使用真实签发 grant。

M7.6 不增加 cryptographic remote signer、provider SDK/codec、默认 live CLI/API、公网 provider 调用、任意 URL、Target 网络访问、工具执行、Approval 消费或 Submission。issuer policy 与 lifecycle ledger 属于可信本地 Control Plane；跨主机签名和密钥管理必须另立里程碑。

### M7.7：密封 OpenAI Responses 协议编解码（已完成首版）

- `AgentProviderCodecRegistration` 内容寻址绑定 provider、固定 `openai-responses-v1` 实现摘要、exact `/v1/responses` path、decision schema 与独立字节/墙钟上限；live model registration 必须绑定 exact codec ID，offline/fake registration 禁止绑定。
- 请求只由已验证 Message Envelope 构造，固定 `store=false`、`stream=false`、`truncation=disabled` 和 strict JSON Schema；调用方不能增加 metadata、tools、tool choice、previous response、任意参数或 provider SDK 行为。
- 响应只接受 `status=completed`、exact model、单个 completed assistant message 和单个无 annotation 的 `output_text`；incomplete、refusal、provider-native tool call、多输出、身份漂移、未知字段和重复 JSON key 全部 fail-closed。
- `output_text` 再次通过 strict JSON 与既有 `AgentDecisionPayload` 校验；provider-native tool execution 不可表示，结构化 `propose_tool` 仍只是由 Runtime/Broker 独立验证的意图。
- live adapter 在 DNS 前编码瞬时请求，在有界 subprocess capture 后解码响应；请求、raw response 和 credential 缓冲继续在成功、拒绝与超时路径归零，持久层仍只接收摘要、计数与 cleanup proof。
- 常规 CI 使用离线 golden fixtures 验证协议形状、内容摘要、漂移拒绝、大小和 codec timeout；Phase 3 仍只使用 loopback TLS fixture，不连接公网 Provider 或使用真实密钥。

M7.7 不提供默认 live CLI/API、provider SDK、流式输出、会话续接、任意 provider 参数、真实工具执行、Approval 消费、Candidate/Finding 转换或 Submission。公网 provider 资格、数据驻留、配额与生产 credential 仍需独立运营 Admission。

### M7.8：Agent Tool Intent → Tool Broker 类型化 Handoff（已完成首版）

- `AgentToolHandoffPlan` 内容寻址绑定权威 `AgentRunPlan`/completed outcome 摘要、exact typed `BrokerCall`、call commitment、attempt、deadline、预算和幂等键；只准入 `VALIDATOR` Worker。
- Agent 不提供 Broker 参数映射器。模型只能返回一个预承诺 call digest；handoff 从权威 Agent checkpoint 重读 digest-only `AgentToolIntent`，并要求它与控制面独立构造的 Broker call 在 Task/Scope/Policy/Profile/Registry/tool/HTTP 语义上精确一致。
- 静态 Broker preflight 在 handoff STARTED checkpoint 前完成；实际执行仍完全由 Tool Broker 重新实施 Scope、network grant、DNS pinning、tool budget、credential 与 Approval Gate，不把 prompt 或 Agent 输出当权限。
- 独立 SQLite checkpoint 提供完成幂等返回、冲突拒绝和遗留 STARTED 恢复拒绝。同一 intent 默认只允许一次 handoff；仅 `approval_required` 结果可绑定前序 handoff 进行一次且仅一次重试。
- `AgentToolHandoffOutcome` 显式映射 Broker completed/denied/approval-required/timed-out/failed 状态。成功必须同时生成 digest-only `AgentToolObservation`，只包含 Target/Scope、状态码、URL/body 摘要、字节数和 Evidence refs，不包含 URL、响应正文、credential 或 Agent 原始参数。
- 常规测试覆盖真实离线 Agent Runtime 产出 intent 后的成功、Scope 拒绝、Approval 重试、timeout、transport failure、commitment drift、checkpoint 冲突/恢复、重试上限、清理和无原文持久化。
- Phase 3 composition 使用临时授权测试服务、真实 pinned Broker transport 和 Evidence Store，证明 handoff 后仍由 Broker 连接精确 Scope 目标并只把 Evidence 摘要导入 Observation。

M7.8 不允许 Agent 直接调用 Runner、socket、Docker 或工具 adapter，不新增 Provider 公网调用、任意 URL、自动 Approval、Target build、Candidate/Finding 状态变化、报告导出或 Submission。Observation 只是后续可信工作流输入，不能自行提升为 Candidate/Finding。

### M7.9：密封 Tool Observation 续跑状态机（已完成首版）

- 新增内容寻址的 `AgentContinuationPlan`，精确绑定原始 `AgentRunPlan`/completed `tool_proposed` outcome、completed handoff outcome、`AgentToolObservation`、后续 context snapshot、model registration 和派生 continuation Task；所有对象都从权威 store 重读，不接受调用方拼接的 transcript。
- continuation Task 使用新 task/idempotency identity，但必须继承 exact engagement、Target/version、Scope/version、Policy/Profile/Registry、Validator role 和绝对 deadline；其 `input_refs` 只能是绑定的 Observation/Evidence refs，`allowed_tools` 固定为空且 `tool_calls=0`，model/wall budget 只能收缩。
- 可信 Control Plane 只从 Observation 的 exact Evidence refs 经 Evidence Store 的 no-follow、大小和内容摘要校验读取已脱敏正文，再通过既有 `AgentContextAssembler` 形成带 `OBSERVATION_SUMMARY` 标记的有界 untrusted fragment；缺失、链接、摘要/Target/version 漂移、超限或二次脱敏失败均在 provider 调用前拒绝。
- 首版只允许一次成功 handoff 后的一次续跑，并要求续跑产出 `complete` 或 `blocked`；再次 `propose_tool` fail-closed，避免递归自唤醒。后续多工具循环必须另立里程碑并先引入跨轮次预算账本。
- continuation ledger 使用独立 SQLite `STARTED/COMPLETED` checkpoint，绑定唯一 Observation 和幂等键；完成结果可幂等返回，冲突、重复消费、遗留 STARTED 和跨 Task/Scope/Target/version 重放拒绝，不自动重放 provider 或 Broker 外部动作。
- continuation ledger 依据原始 Agent outcome 的 tokens/steps、Broker result 的 tool calls、当前时间和原绝对 deadline 计算剩余预算；剩余预算不足、deadline 到期、Approval 未决、handoff 非 completed 或 cleanup 不完整时不得创建续跑 checkpoint。
- 后续 Message Envelope 明确区分可信 control 与 untrusted Observation context；持久层只保存 plan/outcome/envelope/context/evidence 摘要、稳定状态和 cleanup proof，不保存 provider 请求、raw response、URL、credential 或未脱敏 Evidence 正文。
- 常规测试覆盖成功终止、blocked、二次工具提议拒绝、Evidence/Observation/Task 漂移、预算耗尽、deadline、provider timeout/failure、幂等冲突、STARTED 恢复、清理与 SQLite 无正文；Phase 3 仅使用现有 loopback provider fixture 和临时授权 Broker 服务组合完整 propose → handoff → Observation → continue 链。

M7.9 不增加公网 provider/目标能力、任意 provider 参数、Agent 直连工具、自动 Approval、无限 Agent loop、Target build、Candidate/Finding 转换、报告导出或 Submission。它只完成一次有界、可审计的 Observation 反馈闭环；任何领域状态变化仍由后续独立的确定性服务和门禁负责。

### M7.10：跨轮次密封 Session Ledger 与固定双工具闭环（已完成首版）

- 新增内容寻址的 `AgentSessionPlan` 与权威 Session Ledger，绑定根 Validator Task、model/context registration、绝对 deadline、总 token/step/tool/provider-attempt/Broker-attempt 预算，以及有序的 round identity；所有后续轮次只能从权威 store 重读前序 outcome、handoff、Observation 和 cleanup proof。
- 首版 session 固定最多两个工具轮次和三个 provider turn，不提供通用递归循环。每个工具轮次仍最多一个 `propose_tool`；第二次成功 handoff 后的 provider turn 必须终止为 `complete` 或 `blocked`，第三次提议、round fork/cycle、重复 Observation 或重复 call commitment 一律 fail-closed。
- 可信控制面为每轮构造有限、内容寻址的 `AgentAuthorizedCallSet`。每个选项都是已经通过静态 preflight 的 exact typed `BrokerCall` commitment；模型只能选择被展示的 opaque commitment，不能生成或修改 URL、方法、header、body、credential、Scope、Policy、Profile、Registry 或网络参数。
- 每次 provider/Broker 动作前，Session Ledger 事务性保留对应 attempt 并计算累计消耗与剩余预算；token、step、tool-call、attempt 和 wall-time 只能单调减少。预算不足、deadline 到期、前序 cleanup 不完整、未完成 handoff、未决 Approval 或账本漂移必须在下一外部动作前拒绝。
- 每个 completed Broker result 都必须经既有 Evidence Store 与 `AgentToolObservation` 路径落盘，再以 no-follow、摘要校验、二次脱敏和有界 `OBSERVATION_SUMMARY` 进入下一轮 untrusted context；模型文本、provider transcript 或调用方拼接对象不得成为轮次权威状态。
- Approval-required 只把 session 停在显式等待状态；后续必须由既有 Approval Gate 提供有效决定并走既有一次性 handoff retry，Session 不得自动批准、轮询、扩权或重放 provider/Broker 外部动作。
- SQLite checkpoint 记录 session/round 的 `STARTED`、等待和终态，提供完成幂等返回、唯一消费、冲突拒绝和遗留 STARTED 恢复拒绝；恢复只允许读取已完成结果，不自动重放可能已产生外部效果的 provider 或 Broker 调用。
- 常规测试覆盖双工具成功、首轮/次轮 blocked、第三次提议、未列 commitment、重复调用、跨轮 Observation/Task/Scope/Target/version 漂移、累计预算耗尽、deadline、Approval 等待、provider/Broker timeout/failure、checkpoint 冲突、崩溃恢复、清理和 SQLite 无正文。
- Phase 3 composition 仅使用隔离 loopback provider 和临时授权 Broker 服务，证明三个 provider turn 最多触发两个 exact read-only 请求、两个 Observation 都从 Evidence Store 重建、第三次工具调用被拒绝，且 provider/Broker 子进程与临时资源全部清理。

M7.10 不增加公网 provider/目标能力、动态 URL 或参数、Agent 直连网络/Runner/Docker、自动 Approval、写目标、Target build、任意 shell、无限循环、Candidate/Finding 状态变化、报告导出或 Submission。固定双工具上限不是权限来源；每次执行仍由独立的 Scope、Policy、Broker、network grant、credential 与 Approval 边界重新裁决。

### M7.11：会话审计封包与确定性终态投影（已完成首版）

- 新增内容寻址、只读的 `AgentSessionAuditBundle`，精确绑定 Session Plan/outcome、各轮 Agent outcome、Authorized Call Set、handoff、Observation、Evidence refs、Approval 决定、累计预算与 cleanup proof；封包只从权威 store 重建，不接受调用方提供 transcript 或模型摘要。
- 独立纯验证器按 round 顺序重算全部对象摘要、唯一消费、call commitment、预算单调性、deadline、Scope/Target/version、Approval 和 cleanup 链；任何缺失、额外对象、分叉、循环、跨会话重放、可写/链接 artifact 或内容漂移都 fail-closed。
- 只允许把终态投影为受限的 `AgentSessionRecommendation`：`completed`、`blocked`、`failed` 或 `timed_out`，并携带稳定 reason code、已验证 Observation/Evidence 引用和预算摘要；模型 prose、置信度或未绑定引用不能决定领域状态。
- recommendation 只是后续确定性 Validation/Critic 工作流的输入，不创建或迁移 Candidate/Finding/Report，不排队工具，不消费 Approval，也不执行网络、Runner、Docker、Target build 或 Submission。
- 审计 JSON/Markdown 使用固定 schema 与模板，内容先脱敏且不得复制 Evidence 正文、URL、credential、provider request/response 或工具参数；只输出 digest、计数、稳定状态和可追溯 Evidence ID。
- SQLite 使用独立 `STARTED/COMPLETED` checkpoint；相同计划幂等返回，冲突 key、遗留 STARTED、写入中断和 artifact 发布失败拒绝自动重放并清理临时文件。
- 常规测试覆盖完整双工具封包、blocked/failed/timed-out、Approval retry、缺失/重复/乱序轮次、预算回增、引用/Scope/Target/version 漂移、symlink/可写/超限 artifact、幂等冲突、失败清理和 SQLite/导出无正文。
- Phase 3 Admission 从 M7.10 真实 loopback 会话生成审计封包和 recommendation，并通过篡改一个 handoff、Observation、预算或 cleanup proof 证明投影前拒绝；该准入不新增任何运行期权限。

M7.11 用可独立复核的不可变审计链收束 Phase 5 首版。它不把 Agent 输出升级为授权或事实，不增加公网 provider/目标、动态工具、自动 Approval、Target build、Candidate/Finding 转换、报告导出或 Submission。

## Phase 6：Agent 建议的确定性工作流接入

目标：在不把模型输出当作授权或事实的前提下，将已审计的 Agent recommendation 接入现有人工选择、Validation、Critic 与报告闭环。

### M8.1：人工 Validation Intake 与密封计划绑定（已完成首版）

- 新增内容寻址的 `AgentValidationIntakePlan`，精确绑定一个已完成且通过完整性复核的 M7.11 Audit Bundle/recommendation、一个不可变 Candidate/CandidateSet、当前 Scope/Target 版本，以及由可信控制面预构造的 exact `ValidationPlan` 摘要。
- Intake 不从 Agent summary、tool intent 或 Evidence 正文生成 Runner request、BrokerCall、URL、HTTP 参数、assertion、credential 或 Approval；完整 `ValidationPlan` 必须作为独立 typed 对象输入，并继续满足现有 M4.4/M4.5 preflight。
- 显式 `AgentValidationIntakeCommand` 只允许人工 `accept`、`reject` 或 `defer`，绑定 reviewer、decision time、plan digest、Audit Bundle 和 Candidate digest；`completed` recommendation 也不能自动 accept，blocked/failed/timed-out recommendation 不得进入 accepted 状态。
- accepted 只生成不可变 `AgentValidationIntakeRecord`，表示人工允许该 exact ValidationPlan 进入后续现有执行入口；它不调用 `ValidationService`，不把 Candidate 从 `PROPOSED` 改为 `VALIDATION_PENDING`，也不产生 ValidationRun、EvidenceBundle、Finding 或 Report。
- 执行前从权威 Audit artifact store、CandidateSet store 和当前 Scope 重新读取全部对象，复核 no-follow、只读、大小、摘要、Target/version/Scope、recommendation、Candidate 状态和 ValidationPlan provenance；任一漂移、跨 Candidate/Target/Scope 重放或过期决定均 fail-closed。
- SQLite 使用独立 `STARTED/COMPLETED` checkpoint；相同决定幂等返回，冲突决定、重复消费、遗留 STARTED 与写入中断拒绝自动重放。持久层只保存 digest、稳定 decision/reason code 和 reviewer identity，不复制 Evidence 正文、Agent prose、URL、credential 或工具参数。
- 常规测试覆盖 accept/reject/defer、非 completed recommendation、Candidate/Set/Audit/Scope/ValidationPlan 漂移、过期、幂等冲突、重复消费、恢复拒绝、失败清理及 schema/SQLite 无敏感内容。
- Phase 3 Admission 使用 M7.11 loopback 审计产物和本地不可执行 Validation fixture，证明 accepted record 仅绑定计划且 Runner/Broker 调用计数保持为零；篡改 Candidate 或 ValidationPlan 时在 Intake checkpoint 前拒绝。

M8.1 是人工选择记录，不是 Validation 执行器或新的 Approval。后续执行仍必须显式调用既有 `ValidationService`，并重新通过 Scope、Policy、Sandbox、Tool Broker、预算、Evidence 与必要 Approval 门禁。

### M8.2：accepted Intake 与完成 Validation Outcome 的确定性绑定（已完成首版）

- 新增内容寻址的 `AgentValidationOutcomeBindingPlan`，精确绑定一个仍有效的 accepted M8.1 Intake Record、原始 Audit/CandidateSet/Candidate、exact `ValidationPlan`，以及同一 plan 在权威 `ValidationStore` 中已经完成的 `ValidationOutcome` 摘要。
- Binding Service 只在 Validation 已由现有显式入口完成后运行；它不得调用 `ValidationService`、Runner、Broker、Docker、网络或 Approval，不得排队、恢复或重放 Validation，也不得再次改变 Candidate。
- `ValidationStore` 与 Intake Store 增加只读 completed lookup；遗留 STARTED、缺失 outcome、plan/record digest 漂移、非 accepted/过期 record、跨 Candidate/Target/Scope 重放和重复消费均 fail-closed。
- 绑定时重新读取 Audit artifact、CandidateSet、Intake Record、Validation checkpoint 和当前 Scope，复核 no-follow、只读、大小、摘要、原始 Candidate 为 `PROPOSED`、ValidationRun/Outcome provenance、Evidence refs 与最终 Candidate 状态的一致性。
- 只生成 digest-only 的 `AgentValidationOutcomeBinding`：保存 Audit/Intake/Candidate/Validation plan/outcome/run/bundle 的 ID/摘要、typed result 和完成时间；不复制 Runner/Broker 参数、URL、HTTP body、credential、Agent prose 或 Evidence 正文。
- SQLite 使用独立 `STARTED/COMPLETED` checkpoint；相同绑定幂等返回，冲突 key、重复 outcome/record 消费和遗留 STARTED 拒绝自动重放。失败发生在 checkpoint 前，或留下需显式处理的 STARTED，不触发外部清理动作。
- 常规测试覆盖 reproduced/not-reproduced/inconclusive/policy-stopped/timed-out 结果、非 accepted/过期 Intake、缺失/STARTED Validation、Candidate/Scope/Target/plan/outcome/Evidence 漂移、幂等冲突、重复消费和 SQLite/schema 无正文。
- Phase 3 Admission 复用已完成的本地 Validation composition outcome 做只读绑定，证明 Binding 前后 Runner/Broker/target 调用计数不变；篡改 Intake 或 Validation outcome 时在 binding checkpoint 前拒绝。

M8.2 是已发生 Validation 的来源证明，不是执行授权、自动重试或 Critic verdict。后续 Critic 接入仍需独立里程碑，并继续从权威 Evidence/Validation store 重读全部对象。

### M8.3：人工 Critic Intake 与密封计划绑定（已完成首版）

- 新增内容寻址的 `AgentCriticIntakePlan`，绑定一个已完成且 result 为 `reproduced` 的 M8.2 Outcome Binding、原始 Audit/CandidateSet/Candidate、权威 ValidationRun/EvidenceBundle，以及可信控制面独立构造的 exact `CriticPlan`。
- Intake 不从 Agent prose、recommendation、Evidence 正文或 Validation rationale 生成 Critic assessment；四个反证角度、独立 context/producer 和 Evidence refs 必须已在 typed `CriticPlan` 中封存。
- 人工命令只允许 `accept`、`reject` 或 `defer`；accepted 仅生成 digest-only record，不调用 `DeterministicCritic`，不迁移 Candidate，不产生 CriticReview、Finding、Report 或 Submission。
- 决策前重读 M8.2 binding、Audit artifact、CandidateSet、Validation checkpoint、当前 Scope 与 Evidence objects；非 reproduced、缺失 bundle、Scope/Target/Candidate/run/plan/Evidence 漂移或过期均 fail-closed。
- 独立 SQLite 使用 STARTED/COMPLETED checkpoint，唯一消费 binding 和 CriticPlan；相同决定幂等返回，冲突与遗留 STARTED 拒绝自动恢复。
- 常规测试覆盖三类人工决定、非 reproduced、CriticPlan 漂移、超时、重复消费、恢复和 schema/SQLite 无执行参数或正文。
- Phase 3 Admission 从真实 M8.2 reproduced outcome 构造 CriticPlan 并记录人工 accept，证明 Critic Intake 前后 Runner、Broker、provider、target 调用计数与 Candidate 状态不变。

M8.3 是进入独立反证审查前的人工选择记录，不是 Critic verdict。后续 M8.4 只读绑定已完成 Critic Outcome，仍不得自动创建 Finding。

### M8.4：accepted Critic Intake 与完成 Critic Outcome 的确定性绑定（已完成首版）

- 新增内容寻址的 `AgentCriticOutcomeBindingPlan`，精确绑定仍有效的 accepted M8.3 Intake Record、M8.2 Validation binding、权威 Validation outcome、exact `CriticPlan` 与已完成 `CriticOutcome`。
- Binding Service 只读权威 completed checkpoint；它不持有或调用 `DeterministicCritic`，不恢复或重放 Critic，不迁移原始 Candidate，也不创建 Finding、Report 或 Submission。
- 绑定前复核 Scope、accepted/expiry、Validation run/EvidenceBundle、CriticPlan 四角度与独立 context、CriticReview 身份/时间/ruleset/rationale/counterevidence，以及 verdict 到终态的唯一映射：accepted→`CRITIC_REVIEWED`、rejected→`REJECTED`、inconclusive→保持 `VALIDATED`。
- `AgentCriticOutcomeBinding` 只保存 Intake、Validation binding/run/bundle、Critic plan/outcome/review、verdict/final state 的 ID、摘要与时间，不复制 Evidence 正文、Agent prose、Runner/Broker 参数、URL、credential 或 Approval。
- 独立 SQLite 使用 STARTED/COMPLETED checkpoint，唯一消费 Critic Intake Record、CriticPlan 和 outcome digest；幂等 completed replay只读，冲突、漂移与遗留 STARTED fail-closed。
- 常规测试覆盖三种 Critic verdict、完成态篡改、过期/非 accepted/缺失 checkpoint、幂等、恢复以及 schema/SQLite digest-only；绑定前后 Runner、Broker 与原始 Candidate 状态保持不变。

M8.4 只是已发生独立反证审查的来源证明。它不把 `CRITIC_REVIEWED` Candidate 自动晋升为 Finding，后续 Finding admission 仍需单独的显式状态机和人工门禁。

### M8.5：人工 Finding Promotion Intake 与密封晋升计划绑定（已完成首版）

- 新增内容寻址的 `FindingDuplicateCheck` 与权威本地 store，把查重结果、Candidate/Target/Scope 摘要、reviewer 与有效期封存为 typed proof；只有唯一最新且当前有效的 `clear` 结果可进入 Intake，旧 clear 会被后续检查作废，裸 `duplicate_checked=True` 不再作为 Agent 接入边界。
- 新增由可信控制面独立构造的 exact `FindingPromotionPlan`，绑定 accepted M8.4 outcome binding、`CRITIC_REVIEWED` Candidate、reproduced ValidationRun、EvidenceBundle、accepted CriticReview、查重证明、预分配 Finding ID，以及 root cause/affected versions/impact/severity 字段。
- Agent prose、recommendation、Critic rationale 或 Evidence 正文不得构造或修改晋升字段；完整 PromotionPlan 作为瞬时 typed 输入，Intake 只持久化其 ID/摘要。
- 人工命令只允许 `accept`、`reject` 或 `defer`。accepted 仅生成 digest-only `AgentFindingIntakeRecord`，不导入或调用 `promote_candidate()`，不把 Candidate 改为 `PROMOTED`，不创建 Finding、Report 或 Submission。
- 决策前重读 M8.4 binding、M8.2 Validation binding、Validation/Critic completed checkpoint、当前 Scope 与 Evidence object，复核 accepted verdict、唯一终态、run/bundle/review、查重和 PromotionPlan 全链摘要；rejected/inconclusive Critic、duplicate、过期或漂移均在 checkpoint 前 fail-closed。
- 独立 SQLite 使用 STARTED/COMPLETED checkpoint，唯一消费 M8.4 binding、PromotionPlan、duplicate check、Finding ID 与 command；相同决定幂等返回，冲突与遗留 STARTED 拒绝自动恢复，且不保存晋升正文。
- 常规测试覆盖三种人工决定、非 accepted Critic、duplicate、PromotionPlan 漂移、超时、幂等、恢复、无状态变化和 schema/SQLite digest-only；Phase 3 Admission 证明 Intake 前后 Critic、Runner、Broker、provider、target 调用计数不变。

M8.5 只是人工选择 exact Finding 晋升输入，不是 Finding 创建。

### M8.6：accepted Intake、精确 Approval 与确定性 Finding 晋升（已完成首版）

- 晋升必须同时持有仍有效的 accepted M8.5 record 与人工 granted `MUTATE_TARGET_STATE`
  Approval；Approval 精确绑定 Intake record、PromotionPlan、Candidate、预分配 Finding ID、Scope、
  Target 以及 `candidate:promoted`/`finding:created` 两个预期效果。
- 执行前重新读取 M8.4/M8.2、Validation、Evidence、Critic、最新 duplicate-clear 和 M8.5 completed
  checkpoint；任何拒绝、过期、替换、跨 Target/Scope 漂移都在晋升 checkpoint 前 fail-closed。
- 只有完成全部来源与授权校验后，事务服务才调用现有纯 `promote_candidate()` 状态机；
  `duplicate_checked=True` 仅由已验证的权威 typed proof 导出，不接受 Agent 布尔值。
- `FindingPromotionExecutionPlan` 不含 Agent prose、Runner/Broker 参数、URL、credential 或 Submission；
  Approval 的摘要正文也不会持久化到晋升 ledger。
- 独立 SQLite 使用唯一 STARTED/COMPLETED checkpoint，原子绑定 promoted Candidate 与 verified
  Finding；相同执行幂等读取，重复消费与遗留 STARTED 拒绝自动重放。
- 常规测试覆盖精确授权、pending/denied/revoked 拒绝、篡改、超时、幂等和恢复；Phase 3 Admission
  证明实际晋升前后 Runner、Broker、provider 与 target 调用计数不变，原始 Candidate 仍不可变。

M8.6 首次形成经过 Validation、Critic、人工选择和精确 Approval 的 verified Finding，但不生成报告、
不访问公网、不构建目标，也不创建或发送 Submission。后续工作应从该 sealed Finding outcome 开始建立
人工报告 Intake，而不能回读 Agent 输出构造报告事实。

### M8.7：人工 Report Intake 与 sealed Finding outcome 绑定（已完成首版）

- 新增内容寻址的 `AgentReportIntakePlan`，绑定 completed M8.6 execution/outcome、promoted Candidate、
  verified Finding、reproduced ValidationRun、EvidenceBundle，以及可信控制面独立构造的 exact
  version 1 `ReportDraftPlan`、报告家族与渠道；修订版 Intake 留待后续绑定 predecessor/diff 后开放。
- ReportDraftPlan 的标题、完整章节和 Evidence citations 只作为瞬时 typed 输入；Agent prose、Critic
  rationale 或 Evidence 正文不得补写报告事实，Intake SQLite 不保存任何报告正文。
- 人工命令只允许 `accept`、`reject` 或 `defer`。accepted 仅产生 digest-only record，不调用
  `DeterministicReportService`，不创建 Report/Artifact，不进入 review/export，更不创建 Submission。
- 决策前重读 M8.6 promotion、M8.4 Critic binding、M8.2 Validation binding、Validation completed
  checkpoint 和 Evidence objects；完成态缺失、篡改、Scope/Target/Candidate/Finding/bundle 漂移、
  越界 citation 或过期均在 Intake checkpoint 前 fail-closed。
- 独立 SQLite 使用 STARTED/COMPLETED checkpoint，唯一消费 ReportDraftPlan、report family、command
  和幂等键；同一决定幂等返回，冲突与遗留 STARTED 拒绝自动恢复。
- 常规测试覆盖三种人工决定、plan 漂移、超时、幂等、冲突、恢复和 schema/SQLite digest-only；
  Phase 3 Admission 证明 Report Intake 前后 Runner、Broker、provider、target 调用计数不变。

M8.7 只是人工选择 exact 报告输入，不是报告生成或披露授权。后续 M8.8 才能从 accepted record 与
权威 Evidence 重读结果，通过确定性服务生成本地 draft Report；review、export 和 Submission 仍保持独立。

### M8.8：accepted Intake 的确定性本地报告草稿与结果绑定（已完成首版）

- 新增内容寻址的 `AgentReportDraftExecutionPlan`，只接受仍有效且人工 accepted 的 M8.7 record，绑定
  M8.6 promotion outcome、exact `ReportDraftPlan`、有序 typed Evidence catalog、report family/version、
  Finding、Candidate、EvidenceBundle、Scope 与执行窗口。
- 执行前重新读取 M8.7/M8.6/M8.4/M8.2、Validation、Evidence 和 promotion completed checkpoint，
  并重算全部摘要；非 accepted、过期、缺失、篡改、Evidence catalog 漂移或预先存在的未绑定报告
  checkpoint 均 fail-closed。
- 通过既有 `DeterministicReportService` 生成唯一的本地 immutable Report artifact；结果强制保持
  `DRAFT`，另存 digest-only `AgentReportDraftOutcomeBinding`，不把 title、sections 或 Evidence 正文
  写入 Agent execution ledger。
- 独立 SQLite 使用 STARTED/COMPLETED checkpoint；completed replay 只读幂等，重复消费、冲突和遗留
  STARTED 拒绝自动执行，失败不会重试报告服务或触发外部清理动作。
- 常规测试覆盖成功、非 accepted、plan/Evidence 漂移、超时、预存在 draft、幂等、冲突、恢复和
  schema/SQLite 无正文；Phase 3 Admission 证明本地 drafting 前后 Runner、Broker、provider、target
  调用计数不变，原始 Candidate 与 sealed Finding 不变。

M8.8 只生成本地 DRAFT 和来源绑定，不批准或导出报告，不构建目标，不访问公网，也不创建或发送
Submission。后续 review/export 必须继续走既有独立人工流程；Submission 仍不在 Agent 路径内。

### M8.9：人工 Report Review Intake 与 M8.8 DRAFT 绑定（已完成首版）

- 新增内容寻址的 `AgentReportReviewIntakePlan`，绑定 completed M8.8 execution/binding、权威
  `ReportOutcome`、immutable artifact、仍为 `DRAFT` 的 Report、EvidenceBundle、与 M8.8 完全一致的
  有序 typed Evidence catalog，以及可信控制面独立构造的 exact `ReportReviewPlan`。
- 人工命令只允许 `accept`、`reject` 或 `defer` 是否进入后续 review；accepted 仅生成 digest-only
  record，不调用 `HumanReportReviewService`，不执行 approve/request-changes/reject 状态转换。
- 决策前重新读取 M8.8 completed checkpoint、Report draft store、artifact 与每个 Evidence object，
  重算 Report/artifact/bundle/catalog/review plan 摘要；非 DRAFT、缺失、篡改、过期或跨 Scope/Candidate
  漂移均在 Intake checkpoint 前 fail-closed。
- 独立 SQLite 使用 STARTED/COMPLETED checkpoint，唯一消费 M8.8 binding、Report、ReviewPlan 与
  command；同一决定幂等返回，冲突和遗留 STARTED 拒绝自动恢复，且不保存报告正文。
- 常规测试覆盖三种人工决定、plan 漂移、超时、artifact 损坏、幂等、冲突、恢复和 schema/SQLite
  digest-only；Phase 3 Admission 证明 Intake 前后 Runner、Broker、provider、target 调用计数不变，
  Report 仍为 `DRAFT`。

M8.9 只是人工选择 exact review 输入，不是报告批准。后续 M8.10 必须要求 accepted M8.9 record 与
独立人工 `ReportReviewCommand`，并重新验证全部来源后才可调用既有 review 状态机；export 与 Submission
仍保持独立且不在本里程碑权限内。

### M8.10：accepted Intake、精确 Approval 与确定性 Report Review（已完成首版）

- 新增 `REVIEW_REPORT` Approval action 与内容寻址的 `ReportReviewApprovalAction`，精确绑定 accepted
  M8.9 record、exact `ReportReviewPlan`、独立人工 `ReportReviewCommand`、DRAFT Report、artifact、Scope、
  typed decision 和唯一预期状态效果；M8.9 accept 不能充当 review decision 或 Approval。
- `approve`、`request_changes`、`reject` 三种实际状态转换都要求人工 granted 且仍有效的 exact
  Approval；pending/denied/revoked、action/effect/Scope/时间漂移均在 execution checkpoint 前拒绝。
- 执行前重新读取 M8.9/M8.8、Report draft、artifact、EvidenceBundle 与相同 Evidence catalog，确认
  Report 仍为 `DRAFT` 后才调用既有 `HumanReportReviewService` 与纯状态机。
- 新增 digest-only `AgentReportReviewExecutionPlan` 和 `AgentReportReviewOutcomeBinding`；完整 reviewed
  Report 只进入既有本地 review artifact/store，Agent execution ledger 不保存报告正文或 Approval 摘要。
- 独立 STARTED/COMPLETED ledger 唯一消费 Intake、ReviewPlan、ReviewCommand、Report 与 Approval；
  completed replay 幂等，预存在未绑定 review、冲突、失败和遗留 STARTED 不自动重放。
- 常规测试覆盖三种决定、授权拒绝、plan 漂移、超时、失败清理、预存在 review、幂等、冲突、恢复和
  schema/SQLite 无正文；Phase 3 Admission 以显式人工 `request_changes` 证明实际转换前后 Runner、
  Broker、provider、target 调用计数不变，原始 DRAFT 仍不可变。

M8.10 只执行本地人工报告审阅状态机，不自动选择或批准决定，不导出报告，不访问公网，也不创建或
发送 Submission。后续 M8.11 应从 `HUMAN_APPROVED` 的 completed binding 开始建立独立本地 export Intake。

### M8.11：人工本地 Report Export Intake（已完成首版）

- 新增内容寻址的 `AgentReportExportIntakePlan`，绑定 completed M8.10 execution/binding、权威
  `ReportReviewOutcome`、`HUMAN_APPROVED` Report、immutable artifact、人工 review record、Scope，以及
  可信控制面独立构造的 exact `ReportExportPlan`。
- 人工命令只允许 `accept`、`reject` 或 `defer` 是否进入后续本地 export；accepted 只生成 digest-only
  record，不调用 `LocalReportExportService`，不把 Report 改为 `EXPORTED`。
- 决策前重新读取 M8.10 completed checkpoint、review outcome 与 artifact，重算 execution/binding、
  Report、artifact、review 和 export plan 摘要；非 `HUMAN_APPROVED`、篡改、过期或跨 Scope 漂移均在
  Intake checkpoint 前 fail-closed。
- 独立 STARTED/COMPLETED SQLite 唯一消费 M8.10 binding、Report、ExportPlan 与 command；同一决定
  幂等返回，冲突和遗留 STARTED 拒绝自动恢复，且不保存报告正文或 review rationale。
- 常规测试覆盖三种人工决定、非批准状态、plan 漂移、超时、artifact 损坏、幂等、冲突、恢复与
  schema/SQLite digest-only；Phase 3 Admission 证明 Intake 前后 Runner、Broker、provider、target 调用
  计数不变，Report 仍为 `HUMAN_APPROVED` 且没有 export artifact。

M8.11 只是人工选择 exact local export 输入，不是导出授权或导出执行，也不接受路径/URL。后续 M8.12
必须要求 accepted M8.11 record 与独立、精确且仍有效的 Approval，重新验证全部来源后才可调用既有
local export 状态机；Submission 继续保持独立且不在 Agent 路径内。

### M8.12：accepted Intake、精确 Approval 与确定性本地 Report Export（已完成首版）

- 新增 `EXPORT_REPORT` Approval action 与内容寻址的 `ReportExportApprovalAction`，精确绑定 accepted
  M8.11 record、completed M8.10 binding、exact `ReportExportPlan`、`HUMAN_APPROVED` Report、artifact、
  review、Scope，以及固定的 `report:exported`/`report_artifact:created` 效果。
- 只有人工 granted 且仍有效的 exact Approval 才可进入导出；pending/denied/revoked、action/effect/
  Scope/时间漂移均在 execution checkpoint 前拒绝。
- 执行前重新读取 M8.11/M8.10 completed checkpoint、review outcome 与 immutable artifact，全部匹配后
  才调用既有 `LocalReportExportService`；该服务只写预配置的内容寻址 artifact store，不接受路径或 URL。
- 新增 digest-only `AgentReportExportExecutionPlan` 与 `AgentReportExportOutcomeBinding`；源
  `HUMAN_APPROVED` Report/artifact 保持不可变，完成结果为本地 `EXPORTED` Report/artifact。
- 独立 STARTED/COMPLETED ledger 唯一消费 Intake、ExportPlan、Report 与 Approval；completed replay
  幂等只读，预存在未绑定 export、冲突、失败和遗留 STARTED 不自动重放。
- 常规测试覆盖精确授权、pending/denied/revoked、plan 漂移、超时、artifact 写入失败、预存在 export、
  幂等、冲突、恢复和 schema/SQLite 无正文；Phase 3 Admission 证明实际本地导出前后 Runner、Broker、
  provider、target 调用计数不变。

M8.12 使 Agent 工作流最多到达受控本地 `EXPORTED` artifact。它不包含任意目的地、公网、披露平台
token 或 Submission；`SUBMITTED` 仍无可达状态迁移。后续工作应进入端到端质量/安全回归评测，而不是
把本地 export 隐式扩展为外部提交。

### M9.1：Agent 闭环端到端质量与安全回归门禁（已完成首版）

- 新增内容寻址的 `AgentWorkflowRegressionObservation`，按固定顺序绑定 M7.11 Audit 与 M8.1–M8.12
  的 13 个 checkpoint 摘要、Evidence、六次人工 Intake 决定、三次精确 Approval、关键状态和副作用计数。
- 固定安全策略要求 Validation `REPRODUCED`、Critic `ACCEPTED`、原始 `PROPOSED` Candidate、独立
  `CRITIC_REVIEWED`/`PROMOTED` Candidate，以及 `DRAFT → HUMAN_APPROVED → EXPORTED` 三份不可变报告。
- 以 M8.2 Validation 完成后的 provider/Broker/Runner/target 计数为基线；直到 M8.12 export 完成都不得
  增长。公网访问、Target 构建、自动 Approval 和 Submission 计数必须始终为零，策略模型禁止放宽这些上限。
- 纯 evaluator 输出 typed metrics、稳定 violation code 与 PASS/FAIL；输入 drift 和过期在 checkpoint 前
  拒绝，独立 SQLite 的 STARTED 不自动恢复，完成结果以有界、no-follow、只读的 JSON/Markdown artifact
  内容寻址保存并幂等复核。
- 常规 CI 覆盖成功、质量/安全失败、超时、输入漂移、恢复、artifact 符号链接和无操作参数；Phase 3
  Admission 从真实本地 provider/Broker/Validation 到本地 export 的完整组合现场构造 observation 并要求 PASS。

M9.1 是只读资格评测，不是新的 Agent 权限或生产状态机。它不执行 Validation、不改变 Candidate、不批准
操作、不构建 Target、不访问公网，也不创建或发送 Submission。

### M9.2：密封负向场景语料与 violation baseline（已完成首版）

- `AgentWorkflowRegressionCorpus` 内容寻址绑定一个 M9.1 已知成功 observation、不可放宽 policy，以及
  23 个固定 mutation scenario；所有 mutation 必须各出现一次并保持规范顺序。
- 场景覆盖阶段缺失/重复、人工决定/Approval/Evidence 缺失、Candidate/Report 状态漂移、Validation/
  Critic 失败、provider/Broker/Runner/target 增量和计数回退，以及公网、构建、自动 Approval、Submission。
- 每个 scenario 的预期 PASS/FAIL 与 exact ordered violation codes 固定在 typed contract 中；删除场景、
  改写预期或放宽 policy 均在评测前 fail-closed，不能用“更新 baseline”掩盖安全回归。
- 纯 corpus evaluator 只变换内存中的 typed observation，输出内容寻址的逐场景实际结果和总体 PASS/FAIL；
  fixture 生成漂移与 23/23 expectation match 已加入 Python 3.12/3.13/3.14 常规 CI。

M9.2 不调用任何生产 adapter，不执行 Validation、不改变领域状态、不访问网络，也不授予构建、审批、导出
或 Submission 权限。

### M9.3：多漏洞类型本地源码基准与联合质量门禁（已完成首版）

- 仓库内密封 9 个最小 Python Web 源码案例，覆盖 SQL 注入、命令注入、路径遍历、SSRF、模板注入、
  不安全反序列化、开放重定向、对象级授权缺失，以及一个 ownership guard 负例。
- fixture 只经现有安全归档导入、Python AST Source Mapper 和确定性 Candidate Generator；源码从不导入或
  执行，不启动 Target、Runner、Broker 或 provider，也不访问网络。
- `LocalSourceSuite`、逐案例 SourceGraph/CandidateSet 摘要和 Candidate 溯源观察均内容寻址；读取前验证
  规范化相对路径、常规文件、no-follow、大小、SHA-256 和总预算，超时或漂移 fail-closed 并清理临时目录。
- 纯 reducer 评估 Candidate recall、Candidate precision 和 entry/sink/code-path/signal 静态溯源完整度；
  guarded 负例不得产生 Candidate，额外或遗漏 CWE 都会触发稳定 violation code。
- Finding precision 与 Evidence 完整度不从静态 Candidate 推断，而是精确绑定既有 M6.1 完整工作流 baseline；
  baseline 身份漂移在评测前拒绝，避免评测数据绕过 Validation、Critic、promotion 或 Evidence gate。
- 8 类禁止副作用计数固定覆盖 Runner、Broker、provider、Target 进程、公网、构建、自动 Approval 和
  Submission；任一非零即失败。fixture/schema 漂移和 M9.3 gate 已加入 Python 3.12/3.13/3.14 常规 CI。

M9.3 是离线静态分析质量与既有闭环质量的联合准入，不执行 Validation、不改变 Candidate/Finding、
不批准操作、不构建 Target、不访问公网，也不创建、导出或发送 Submission。

### M9.4：跨框架/跨文件静态鲁棒性与安全负例门禁（已完成首版）

- 新增 13 个密封本地源码案例：5 个 Flask/FastAPI/Django 正例覆盖跨文件调用、Django URL dispatch
  和 FastAPI dependency，8 个负例覆盖 ownership guard 及 SQL、命令、文件、网络、模板、反序列化、
  redirect sink 使用固定可信值的相似安全路径。
- M9.3 的 Candidate 观察扩展为记录实际 Web framework、调用链长度、分析文件清单和解析失败计数；
  这些字段由可信 SourceGraph/Candidate binding 推导，不接受 Agent 声明。
- code-owned `M9_4_CASE_CONTRACT` 固定案例顺序、正负标签、expected CWE、framework、最小文件数与调用链
  深度；`LocalSourceRobustnessProfile` 再内容寻址绑定 exact suite 和 M6.1 workflow baseline。
- 纯 reducer 要求基础质量门禁通过、Flask/FastAPI/Django 三种框架完整、跨文件 entry/sink 分离、调用链
  达到案例下限、零解析失败且所有安全负例零 Candidate；产生稳定 violation code。
- 常规 CI 在 Python 3.12/3.13/3.14 重新生成 M9.3/M9.4 fixture、检查 schema/fixture 漂移并运行两个门禁；
  资源上限、超时、digest/symlink、清理和八类零副作用约束继续由共享可信静态 harness 强制执行。

M9.4 不执行 fixture 或 Validation，不改变 Candidate/Finding，不调用 Runner/Broker/provider，不自动批准、
不构建 Target、不访问公网，也不创建、导出或发送 Submission。

### M9.5：人工授权本地项目 pilot 与发布就绪门禁（已完成首版）

- 新增内容寻址 `AuthorizedPilotManifest`，从当前有效 `Scope`、安全导入的 exact `TargetSnapshot`、可信
  `SourceGraph` 和 `CandidateSet` 构造，不接受 Agent 声明的目标、路径、Candidate 或执行参数。
- manifest 固定记录 6 个 M8 Intake、3 个精确 Approval 和前置人工 Candidate selection；同时固定禁止
  Agent Runner/Broker 参数、自动 Validation、Candidate 自动变更、自动 Approval、Target build、公网和
  Submission，且 `selected_candidate_ids` 必须为空。
- `AuthorizedPilotReadinessPlan` 密封 exact manifest、通过的 M9.4 profile/result、不可放宽的资源与零副作用
  policy、执行窗口及幂等键。评估前重新授权 Scope、完整复核本地 Snapshot、静态产物和所有 digest binding。
- repository-owned admission pilot 将 18 个 M9.4 Python 文件合并为一个确定性本地源码归档，经真实安全
  ingestion、AST mapper 和 Candidate generator 产生 5 个仍为 `PROPOSED` 的 Candidate；fixture 从不执行。
- 纯 readiness reducer 输出文件/字节/Candidate/人工门禁/禁止副作用计数和稳定 violation code；结果仅是
  PASS/FAIL，不选择 Candidate，也不创建 Validation、Finding、Report、Approval 或 Submission。
- 独立 SQLite 使用 STARTED/COMPLETED checkpoint；结果以有界、no-follow、只读 JSON/Markdown 内容寻址
  保存。常规 CI 重新生成 manifest/plan/result，并覆盖成功、拒绝、超时、清理、恢复、冲突和 symlink。

M9.5 是真实授权项目接入前的离线发布就绪协议与 repository-owned admission pilot。接入具体项目仍需人工
提供 exact Scope 和本地 Snapshot；本阶段不扫描其他仓库、不执行 Validation、不改变 Candidate/Finding、
不批准操作、不构建 Target、不访问公网，也不创建、导出或发送 Submission。

### M9.6：人工授权本地 shadow pilot 操作入口（已完成首版）

- 新增单一 `shadow-pilot-local` CLI，只接受已由安全 ingestion 保存的 exact local Snapshot、当前有效的
  approved Scope，以及预配置的本地内容寻址存储；不在同一命令中接收或获取 Target。
- SourceGraph 与 CandidateSet 均由可信 AST mapper/generator 从复核后的 Snapshot 重新构造；入口不接受
  Agent 提供的 Candidate、源码路径、质量阈值、Runner/Broker 参数或 benchmark 路径。
- 入口精确锁定 repository-owned 且已准入的 M9.4 profile/result，随后复用 M9.5 manifest、plan、纯 reducer、
  SQLite checkpoint 和只读 artifact store；基线 identity 或结果漂移时 fail-closed。
- 输出只包含本地 artifact identity/path、readiness PASS/FAIL 和仍为 `PROPOSED` 的 Candidate 人工审阅摘要；
  `selected_candidate_ids` 固定为空，不写 Validation、Finding、Approval、Report、领域事件或 Submission。
- 允许零 Candidate 的安全项目形成可复核 readiness 结果；这只表示静态流程安全完成且没有候选待审阅，
  不构成“无漏洞”结论。
- 定向回归覆盖成功、幂等重放、撤销 Scope 拒绝和零 Candidate；既有 M9.5 测试继续覆盖超时、写入失败、
  清理、遗留 STARTED、冲突、digest/symlink 与全部八类禁止副作用。

M9.6 是人工审阅前的本地静态 shadow 入口，不是自动漏洞验证 Agent。它不执行 Validation、不选择或改变
Candidate、不调用 Runner/Broker/provider、不自动批准、不构建 Target、不访问公网，也不导出或提交报告。

### M9.7：人工 Candidate 选择与 Validation Intake 身份衔接（已完成首版）

- 新增内容寻址 `PilotCandidateSelectionCommand` 与 `PilotCandidateSelectionRecord`；命令只接受 human reviewer、
  exact Candidate ID、明确带时区的 decision time 和幂等键，不含 ValidationPlan 或操作参数。
- 选择前重新打开 completed M9.6/M9.5 readiness checkpoint 与只读 artifact，要求 gate 为 PASS、零 violation，
  并重新验证 exact SourceGraph、CandidateSet、Snapshot、Scope 和重构后的 pilot manifest identity。
- 只有 CandidateSet 中唯一且仍为 `PROPOSED` 的 Candidate 可被选择；零 Candidate、未知 Candidate、失败
  readiness、撤销/过期 Scope、artifact 或 digest drift 均在 selection checkpoint 前拒绝。
- 独立 SQLite 以 STARTED/COMPLETED 唯一消费 readiness plan；同一 pilot 最多选择一个 Candidate，完成重放
  幂等，冲突和遗留 STARTED fail-closed。持久化内容不含源码、Runner/Broker 参数、凭据或 ValidationPlan。
- 新增 `pilot-candidate-select-local` 人工 CLI；输出明确标记 Candidate 仍为 `PROPOSED` 且
  `validation_planned=false`，不写领域事件，也不调用 M8.1、ValidationService 或任何外部 adapter。

M9.7 只提供后续 M8.1 可重新验证的人工选择 identity。ValidationPlan 仍必须由可信控制面独立构造，再经
既有 M8.1 人工 Intake；选择记录本身不是 Approval，也不执行 Validation、改变 Candidate、构建 Target、
访问网络、导出报告或 Submission。

### M9.8：pilot Candidate selection 强制绑定 M8.1 Intake（已完成首版）

- 新增内容寻址 `PilotValidationIntakePlan`，精确绑定 completed M9.7 selection record、既有 M8.1
  `AgentValidationIntakePlan`/human accept command、独立预构造的 exact ValidationPlan、CandidateSet/Candidate
  和 Scope；不从 Agent 输出或 selection record 派生任何执行参数。
- pilot service 在调用 M8.1 前重新读取 authoritative selection 和 CandidateSet，要求 Candidate 唯一且仍为
  `PROPOSED`，并复核 selection、M8.1 plan/command、ValidationPlan 的全部 ID/digest/Scope/时间关系。
- 只允许显式 `accept` 的 M8.1 command 进入 pilot binding；未知 Candidate、选择/计划漂移、非 accept、过期或
  超出任一上游 deadline 均在 M8.1 checkpoint 前拒绝。
- 独立 STARTED/COMPLETED ledger 唯一消费 selection、M8.1 IntakePlan 和 ValidationPlan；成功后生成
  digest-only `PilotValidationIntakeBinding`。完成重放只读，冲突或遗留 STARTED 不自动恢复。
- 新增 `pilot-validation-intake-bind-local`，只读取人工提供的既有 typed files 和本地 authoritative stores；
  输出明确标记 `validation_executed=false`，不调用 ValidationService、Runner、Broker 或外部 adapter。
- 回归覆盖成功、幂等、错误 selection、超时和 M8.1 authoritative artifact 失败；失败最多留下 fail-closed
  bridge STARTED，不产生 ValidationRun、Evidence、Candidate 状态变化或临时执行资源。

M9.8 使 pilot 的 accepted M8.1 Intake 可证明来自 exact M9.7 人工选择，但它仍不是 Validation 授权或执行。
任何动态验证必须在后续独立阶段重新消费该 binding，并继续服从 Scope、Approval、Runner/Broker 和清理门禁。

### M9.9：Approval-gated offline pilot Validation execution（已完成首版）

- 新增 `RUN_VALIDATION` Approval action 与内容寻址 `PilotValidationApprovalAction`，精确绑定 completed M9.8
  binding、accepted M8.1 record、既有 ValidationPlan、CandidateSet/Candidate、Scope 和固定预期效果。
- `PilotValidationExecutionPlan` 再绑定独立 human-granted Approval 的完整 digest、执行窗口与幂等键；pending、
  denied、revoked、过期、错误 action/digest/Target/Scope/effects 均在执行 checkpoint 前拒绝。
- 执行前重新打开 M9.8/M8.1/CandidateSet，要求 Candidate 仍为 `PROPOSED`，复核全部 ID/digest，并调用既有
  `ValidationService.preflight`；已经绕过本门禁形成的 Validation checkpoint 被拒绝。
- 首版严格限定 offline、零 Broker call 的 ValidationPlan；CLI 使用 `OfflineSandboxRunner`，不开放网络、
  外部回连、状态变更 HTTP 或 Target build。顶层 Approval 不能替代未来 Broker 自身的逐调用 Approval。
- 独立 STARTED/COMPLETED ledger 唯一消费 M9.8 plan、ValidationPlan 与 Approval；成功生成 digest-only
  `PilotValidationExecutionBinding`，完成重放不重复 Runner，遗留 STARTED 或执行中断需显式恢复。
- 回归覆盖成功/重放、非 granted Approval、超时、门禁前既有 Validation 和 Runner 结果漂移；原 Candidate
  对象保持不可变，执行结果中的 Candidate 只能按既有状态机成为 `VALIDATED` 或 `INCONCLUSIVE`。

M9.9 是人工批准后的本地离线 Validation 执行入口，不是 Agent 自动验证。它不从 Agent 输出构造 Runner/Broker
参数，不调用 Broker/provider，不访问网络、不构建 Target、不自动批准、不提升 Candidate 为 Finding，也不进行
报告导出或 Submission。

### M9.10：pilot M8.2 outcome 强制消费 execution binding（已完成首版）

- 新增 digest-only `PilotValidationOutcomePlan`/`Binding`，强制绑定 completed M9.9 execution plan/
  binding 与 exact M8.2 outcome binding plan；不从 Agent 输出构造任何操作参数。
- 在 M8.2 checkpoint 前重开 M9.9、M9.8、accepted M8.1、Audit、CandidateSet、Validation outcome 和
  Evidence，逐项核对 Scope、时间、Candidate、run/result、最终 Candidate digest 与 Evidence identity。
- 加强 M9.9 store 的 plan/row/Approval identity/时间一致性校验；未知或 STARTED execution 拒绝消费。
- 独立 STARTED/COMPLETED ledger 唯一消费 execution binding、M8.2 plan 和 ValidationPlan；已经存在的裸
  M8.2 checkpoint 不可追认为 pilot 来源，完成重放重新检查 M8.2 authoritative binding，失败不自动恢复。
- `pilot-validation-outcome-bind-local` 只读取预封存的 typed plan files 和本地 authoritative stores；
  不执行 Validation、改变 Candidate、批准操作、构建 Target、访问网络或 Submission。
- 离线回归覆盖成功、CLI 幂等、来源漂移、重封摘要篡改、超时、拒绝、完成写入失败和清理路径。

M9.10 是 pilot 专用的 M8.2 provenance gate，通用非 pilot M8.2 协议保持兼容。生成的 M8.2 binding 继续
保存在原 store，pilot ledger 保存其精确摘要。后续 pilot Critic 消费端仍须显式要求该 pilot binding；
本阶段不执行 Critic，也不把现有通用 Critic 入口自动变为 pilot 门禁。CI `34041988283` 与 Phase 3
Admission `34041988318` 已在 exact implementation commit `fe0c96b` 上通过。

### M9.11：pilot Critic Intake 强制消费 M9.10 outcome binding（已完成首版）

- 新增内容寻址 `PilotCriticIntakePlan`/`Binding`，精确绑定 completed M9.10 plan/binding、既有 M8.3
  IntakePlan、独立 human accept command、预构造 CriticPlan、Candidate 和 Scope；不包含 assessments 正文。
- M9.10 提供不 claim、不 execute 的 `load_verified`：重开 execution、M9.8/M8.1、M8.2、Audit、CandidateSet、
  Validation outcome 和 Evidence，核对上游窗口、摘要及 ledger identity；缺失或 STARTED 不自动恢复。
- M8.3 新增纯 preflight，在 pilot/M8.3 checkpoint 之前同时检查当前权限、完整来源及 exact human command。
  仍只允许 `REPRODUCED`、`VALIDATED`、完整 Evidence 和独立 CriticPlan；`INCONCLUSIVE` 不可进入。
- 独立 SQLite 唯一消费 M9.10 binding、IntakePlan、CriticPlan 和 command；预存在的裸 M8.3 checkpoint 拒绝
  追认，完成重放重读并精确比较人工 record，失败保留 STARTED 并要求显式恢复。
- 新增 `pilot-critic-intake-bind-local`，只记录 accepted Intake 来源，不执行 Critic/Validation、改变 Candidate、
  批准操作、构建 Target、联网、生成 Finding 或 Submission。
- 本地 702 项测试通过、19 项 opt-in 跳过，覆盖率 85.92%；新增测试包含合成离线成功路径、拒绝、超时、
  写入失败/清理、CLI 幂等、摘要重封及 ledger 篡改。exact implementation commit `ca32734` 的
  CI `34075541729` 与 Phase 3 Admission `34075541690` 已于 2026-09-07 UTC 通过。

当前默认 offline pilot 的 `INCONCLUSIVE` 判据保持不变。成功测试使用专门的合成 Evidence 和可信测试 judge，
不代表真实目标已复现。后续 pilot Critic execution/outcome 阶段仍须显式消费本 binding；本里程碑不提供该执行入口。

### M9.12：精确 Approval 下的 pilot Critic 执行与 M8.4 结果绑定（已完成首版）

- 新增 `RUN_CRITIC` Approval action 和 digest-only `PilotCriticApprovalAction`/`ExecutionPlan`，绑定
  completed M9.11、accepted M8.3 record、exact CriticPlan、有序 typed Evidence catalog、Candidate、Scope
  与固定 `critic:review`/`candidate:critic_result` 效果；人工 Intake 不可替代该独立 Approval。
- 执行前只读复核 M9.11–M9.8/M8.1/M8.2 来源链和当前窗口，并以既有 DeterministicCritic preflight 验证
  reproduced Validation、validated Candidate、完整 Evidence、独立评估及全部输入摘要。
- 批准后调用一次本地 DeterministicCritic，再由既有 M8.4 verifier 重算裁决并生成 outcome binding；
  `PilotCriticExecutionBinding` 保存精确 Approval、CriticOutcome/Review、M8.4 plan/binding 和最终 Candidate 摘要。
- 独立 STARTED/COMPLETED ledger 唯一消费 M9.11 plan、CriticPlan 与 Approval；预存在的裸 Critic 或 M8.4
  checkpoint 被拒绝，完成重放只读，Critic/M8.4/wrapper 任一写入失败均不自动重放。
- 新增 `pilot-critic-run-local`，只接受预封存计划、独立人工 Approval、typed catalog 和本地 stores；不执行
  Validation、目标代码或 Agent，不生成 Finding、不访问网络、不构建 Target、不批准操作或 Submission。
- 三类裁决分别产生 `CRITIC_REVIEWED`、`REJECTED`、`VALIDATED` 结果 Candidate；来源 CandidateSet 不变。
  本地 737 项测试通过、19 项 opt-in 跳过，覆盖率 85.92%；exact implementation commit `a8c2c2b` 的
  CI `34079581413` 与 Phase 3 Admission `34079581400` 已于 2026-09-07 UTC 通过。

成功路径使用合成离线 Evidence 验证协议，不代表真实目标已复现。默认 offline Validation 仍为 INCONCLUSIVE，
不会因本阶段而进入 Critic。后续 pilot Finding Intake 必须显式消费本结果绑定并继续要求去重和独立晋升门禁。

### M9.13：pilot Finding Intake 消费精确 Critic execution binding（已完成首版）

- 新增 digest-only `PilotFindingIntakePlan`/`Binding` 和独立 STARTED/COMPLETED ledger，
  将 completed M9.12、exact M8.4、M8.5 Intake、PromotionPlan、去重证明与独立人工命令绑定。
- 只读验证完整上游来源链；仅 accepted Critic/CRITIC_REVIEWED Candidate、当前最新 CLEAR 去重证明
  和精确 ACCEPT 命令可接纳。复核当前 Scope、Evidence、窗口与完整摘要，所有检查先于 checkpoint。
- 历史 RUN_CRITIC Approval 证明已完成执行当时的授权，不作为新的晋升授权；执行窗口结束后，
  只要当前下游与上游来源窗口仍有效即可读取结果。
- 唯一消费 Critic execution binding、Intake、PromotionPlan、去重证明、Finding ID 和命令；拒绝预存
  裸 M8.5 checkpoint，未完成写入要求显式恢复，完成重放只读并复核完整 record 与 ledger。
- 新增 `pilot-finding-intake-bind-local`，只记录人工晋升计划接纳结果，不创建 Finding、改变 Candidate、
  执行 Critic/Validation、构建目标、批准操作、访问网络或 Submission。

本阶段成功测试只使用合成离线 Evidence。Finding 晋升仍须独立 Approval Gate；本地验证结果见
`docs/PHASE3-ADMISSION.md`。实现提交 `204f1ab` 的 CI `34088676591` 与 Phase 3 Admission
`34088676621` 已于 2026-09-07 UTC 通过。

### M9.14：精确 Approval 下的 pilot Finding 晋升与结果绑定（已完成首版）

- 新增 digest-only `PilotFindingPromotionPlan`/`Binding`，强制消费精确 completed M9.13 plan/binding、
  M8.5 record、预封存 M8.6 execution plan 和独立人工晋升 Approval；审批时间不得早于 pilot Intake 完成。
- 执行前只读重验 M9.13 到上游 Critic/Validation/Evidence 的来源链，以及当前 Scope、最新 CLEAR 去重证明、
  PromotionPlan、人工命令和授权窗口。历史 Critic Approval 不可替代晋升 Approval。
- 复用 M8.6 纯状态机及持久化服务；完整比对 Finding、晋升后 Candidate 与 outcome 摘要，结果写入独立 ledger。
  唯一消费 pilot Intake binding、execution plan、Approval、M8.5 record、PromotionPlan 和 Finding ID。
- 拒绝预存裸 M8.6 checkpoint；任何写入中断保留 STARTED 并要求显式恢复。完成重放只读复核完整结果，
  不再调用晋升执行服务。M8.6 通用重放也新增完整结果和 ledger 校验。
- 新增 `pilot-finding-promote-local`，只执行批准后的本地域记录晋升，原始 CandidateSet 保持不变。
  不执行 Critic/Validation/目标代码、生成 Runner/Broker 参数、构建目标、批准操作、访问网络或 Submission。

本地验证详情见 `docs/PHASE3-ADMISSION.md`；成功案例仅使用合成离线 Evidence，不代表真实目标复现。
实现提交 `ea110e1` 的 CI `34089910194` 与 Phase 3 Admission `34089910201` 已通过。
后续 pilot Report Intake 和报告链仍保留各自门禁；M9.15 优先完成独立 Provider 最小接入。

### M9.15：独立真实 Provider 最小接入与固定消息验收（已完成首版）

- 新增 `ProviderProbeConfig`/`Plan`/`Result` 和 `provider-probe-prepare`/`provider-probe-run`。
  只允许固定合成消息，零工具、无 Target/源码/Evidence 输入，不接入漏洞研究工作流。
- 复用既有 live HTTPS adapter、凭据引用、Responses codec 和独立签发的 inference egress grant；
  prepare 不读 Key 或联网，run 必须显式选择 Provider 联网且重新检查当前 grant。
- 固定单次请求、输出 token/请求响应字节/超时上限；独立 ledger 对 plan、幂等键和 grant 唯一消费，
  完成重放只读，失败不自动重试，STARTED 要求显式恢复。命令不签发/批准/续期任何授权。
- 只有精确固定测试响应和完整清理证明可通过；模型工具建议及任意其他工作流输出不能触发操作。
  普通结果只保存摘要、计数和稳定状态，CLI 不打印原始响应、异常正文或密钥。
- 使用 fake DNS/process 完成本地成功、拒绝、超时、清理、撤销和 CLI 回归；不声称已完成真实 Provider
  调用或真实漏洞研究验收。操作及剩余验收要求见 `docs/PROVIDER-PROBE.md`。

实现提交 `dc245e2` 的 CI `34091685590` 与 Phase 3 Admission `34091685606` 已通过；
这些运行没有使用真实 Provider Key。

报告链的 pilot 绑定继续待办。Provider smoke 通过也不授予研究目标网络访问、Validation、Candidate 变更、
Target build 或 Submission 权限。

### M9.16：CUC 固定 Chat probe 适配与真实连通性验收（固定 PONG 真实验收已通过）

- 运营方明确提供逻辑 `EndpointRef`、请求模型 `cuc/deepseek`
  和真实凭据引用 `CUC_DEEPSEEK_API_KEY`；本地 shim 的占位 Key 不可替代 CUC Key。
- 新增仅用于独立 probe 的 `CucChatProbeCodecRegistration`/codec；固定发送 `Reply with exactly PONG.`，
  只接受单个 assistant `PONG`、`finish_reason=stop`、有效用量和两个精确响应模型名：
  `deepseek-v4-flash` / `deepseek-v4-flash-0731`。请求别名本身、通配符、前缀匹配均不接受。
- 直连复用既有 pinned HTTPS subprocess，端点、凭据变量、请求模型、固定内容和资源预算在代码中绑定；
  不启用本地明文 shim，不放宽通用 Responses 身份检查，不提供通用 Chat 工作流。
- 新增只读 `provider-cuc-probe-config`，仅消费运营方已经签发的 inference grant；不签发、批准或续期授权。
  实际响应模型名进入密封结果；旧 M9.15 结果的内容摘要保持兼容。
- 本地成功、拒绝、模型别名漂移、超时、清理、CLI 重放和写入中断回归已完成；测试不调用真实 CUC。

2026-09-07 已按运营方明确授权完成两次独立、各一次的真实固定 PONG 测试。第一次被拒绝且缺少
安全诊断；补齐诊断后的第二次确认 HTTP 200、TLSv1.3、响应 772 字节，随后以
`response_codec / response_shape_mismatch` 拒绝。两次均完成清理并撤销短时出口授权；没有自动重试。
目前无须据此更换 Key，但仍未取得通过协议校验的响应，M9.16 的真实 Provider 验收继续待办。

新增 `ProviderProbeResult.diagnostic` 保存封闭错误码、HTTP 状态、已观察网络状态、响应字节数和 TLS
版本；旧结果缺失该字段时保持摘要兼容。原始正文、响应头、异常文本和凭据不进入结果或日志。
后续结构诊断及 vLLM 官方字段审查形成 codec v2 空扩展白名单：顶层六个字段、choice 三个字段、
message 五个字段和 usage 的 `prompt_tokens_details`；只接受 null 或对应类型的空值，function_call
仅接受 null。非空工具调用、未知字段、错误模型、非精确 PONG 和无效用量继续拒绝。实现摘要已更新，
旧 codec 配置和计划须重新准备，旧密封结果可只读验证。

2026-09-07 修复后的单次 live-005 确认根级六个扩展、choice 三个扩展及 message 的
annotations/audio/function_call/reasoning 均为 null，先前根级和 message 的未知字段已被识别。
但实际内容仍不是精确 PONG，结果以 `response_content_mismatch` 拒绝，另观察到 `usage_other_fields`。
因此结构兼容补丁完成，真实 Provider 准入仍未完成；未追加调用或放宽内容/用量规则。

随后 codec v3 增加闭集内容分类和受限 usage details。验收仅允许 exact/trimmed PONG；大小写、标点、
任意文本仍拒绝，token 总量等式不变。按本阶段仅一次新 grant 的限制执行 live-006，实际分类为
`response_content_punctuation_match`，因此正确拒绝；还观察到 `usage_other_fields`。清理通过并撤销授权，
未重试。PONG 准入和第二阶段无工具真实调用验收均未完成，不能宣称 `cuc/deepseek` 已可用于研究任务。

codec v4 按运营方明确要求仅增加 `PONG.`、`PONG!`、反引号包裹 PONG 三种闭集变体，以及
DeepSeek 的 prompt_cache_hit_tokens / prompt_cache_miss_tokens 有界整数与缓存分量等式。
实测 live-007 已通过内容校验，但仍因 `usage_unknown_fields` 拒绝，且未观察到两个缓存字段。
这否定了它们解释本次 usage 未知字段的假设。已完成本轮唯一调用及授权清理，未追加请求；
PONG 准入继续受阻于真实网关 usage 字段定义，第二阶段真实验收仍未完成。

单次 live-008 指纹诊断及本地词典匹配已确认未知 usage 字段为 time_per_output_token_ms、
time_to_first_token_ms、tokens_per_second，类型观察均为整数。codec v5 增加这三个明确字段和
有界整数校验。最终单次 live-009 返回精确 PONG 且无未知 usage 字段，但因 `usage_metrics_mismatch`
拒绝。具体计量字段及类型/范围失败分支尚未确定，不能宣称 PONG 准入完成；本轮两次授权均已撤销，
未进一步调用。后续需要计量字段约定或更细的闭集范围诊断，不能猜测负数哨兵或放宽计数规则。

最终 codec v6 将三个性能指标改为有限、非负、有界 JSON 数值（int 或 float，排除 bool），并新增
闭集 metric_issues（字段名与 type/non_finite/negative/above_limit）诊断。2026-09-07 live-010
单次验证通过：status=passed、response_model=deepseek-v4-flash-0731、receipt_digest 非空、
cleanup_verified=true，已校验输入 10 / 输出 4 tokens，授权已撤销。固定 PONG 准入现已完成。

本地 1080 passed、23 skipped、覆盖率 86.41%。这项结论仅适用于固定、无工具 PONG 探针；
通用 CucChatCodec 和独立结构化调用验收仍未实现，不代表研究任务的 provider 准入。

### 后续：独立固定 JSON 兼容探针（固定 JSON 真实验收已通过）

- 新增独立 `cuc-chat-structured-probe-v1` 协议、固定合成输入和严格 JSON 响应模型。
- `provider-cuc-probe-config --structured` 选择该协议，复用已有 prepare/run、单次授权、
  幂等 ledger、超时与清理机制；不自动签发授权或进行重试。
- 不接受任意提示词、源码、研究目标或工具调用。测试覆盖成功、拒绝、超时、清理失败、
  中断恢复要求、CLI 重放以及旧 PONG 协议兼容。
- 修复请求已建立但最终 attempt 记录缺失时，空记录集合错误证明清理完成的问题；
  PONG 和结构化探针均有拒绝路径回归。
- 本地验证：1122 passed、23 项集成测试排除，覆盖率 86.45%；
  `ruff check src tests scripts` 和 Schema 重复导出一致性检查通过。
- 2026-09-08 按用户明确授权执行一次 `cuc-structured-live-001`：status=passed，
  HTTP 200 / TLSv1.3，模型 `deepseek-v4-flash-0731`，输入/输出 34/10 tokens，
  receipt 非空且清理通过。复用既有权威账本，结束后撤销授权，无重试；持久化结果已离线核验。
- 通用 CUC Chat 适配与研究任务端到端接入仍未完成；此探针不能作为这些能力的验收证明。

### 独立只读代码审阅助手（首个真实代码审阅验收已完成）

- 人工选择已授权快照的 Python 文件与行号；只读解析、掩蔽全部字面量与注释，保留原始行号。
- 新增 preview / prepare / approval-request / run 操作入口；计划摘要绑定输入、Scope 和 Provider。
  真实调用同时要求有效 inference grant、精确人工审批与显式联网选项。
- 新增独立 `cuc-code-review-v1` 协议，只输出需要人工核查的解释和建议；检查内容结构、输入摘要、
  行号范围、用量与清理证明，无工具调用或 Candidate/Finding 状态变更接口。
- 单次调用使用事务性账本，完成重放只读，中断必须人工核查；不自动重试或自动授权。
- 2026-09-08 已对提交 `43710b8` 中人工选择并脱敏的 19 行代码执行一次真实 CUC 审阅：
  `review_ready`、HTTP 200 / TLSv1.3、模型 `deepseek-v4-flash-0731`、890/303 tokens，
  receipt 非空、清理通过且授权已撤销，无重试。人工复核同时发现一条错误建议，证明结果仍须审阅。
  详见 `docs/CODE-REVIEW-ASSIST.md`。
- 本地验证：43 项新增审阅测试；全量 1165 passed、23 项集成测试排除，覆盖率 86.49%；
  lint 与 Schema 重复导出一致性检查通过。

### Candidate Recommendation 确定性接纳边界（本地首版已完成）

- 新增内容寻址的 `CandidateRecommendation`，只为一个既有 `PROPOSED` Candidate 保存优先级、
  人工复核理由、问题和 Candidate `code_path` 内引用，不创建或修改 Candidate。
- 接纳计划重新读取权威 SourceGraph/CandidateSet，精确绑定 Target/version、Scope/version、Candidate
  内容摘要、完整 Signal 集合，以及通过并完成清理的 Provider result/plan/receipt。
- SQLite 使用唯一 `started → completed` checkpoint；完成态可只读重放，遗留开始态、篡改和身份冲突
  均 fail-closed。接纳记录固定 `candidate_unchanged=true`、`requires_human_selection=true`。
- 类型同时固定 `producer_content_binding_verified=false` 和 `eligible_for_validation_intake=false`，
  防止下游把尚未绑定模型正文的本地记录当作 M8.1 来源证明。
- 新增两个无网络本地 CLI 和三份 JSON Schema；成功、拒绝、超时、清理证明、重放、恢复与安全文本
  回归已覆盖。新增 34 项定向测试；全量 1199 passed、23 skipped，覆盖率 86.59%。详见
  `docs/CANDIDATE-RECOMMENDATIONS.md`。
- 新增 `cuc-candidate-recommendation-v1` 无工具 codec、最小 Candidate 投影、单次调用服务和权威
  generation ledger。投影不含源码、原始路径、标题、假设、前置条件或反证文本；输出绑定 projection、
  response、Recommendation、Provider receipt 和 cleanup proof。
- generation outcome 固定 `producer_content_binding_verified=true`，同时固定
  `eligible_for_validation_intake=false`。下一步是把 completed generation outcome 接入 admission 与独立
  人工选择边界；首次真实 Candidate 投影披露仍需对 preview 另行精确审批。
- 生成链新增 25 项定向测试；全量 1224 passed、23 skipped，覆盖率 86.51%。普通测试使用 fake
  DNS/process，不进行真实 Provider 或目标网络访问。
- 2026-09-08 首次真实最小投影调用返回 HTTP 200 / TLSv1.3，但正文分类为
  `response_content_other`，因此正确拒绝；清理通过、单条账本完成、grant 已撤销且未重试。随后修正
  outcome 标志语义：只有 `recommendation_ready` 才写 `producer_content_binding_verified=true`。
- 补充 Candidate 推荐正文的闭集结构诊断，只记录代码定义的 JSON/字段/类型/范围/安全类别；未知键和值、
  正文及 reasoning 不落盘。诊断不放宽 Schema、不改变接受结果，也不触发自动重试或新 Provider 调用。
- 闭集诊断新增 9 项回归测试；全量 1233 passed、23 skipped，覆盖率 86.49%。
- 第二次精确授权的最小投影调用通过严格正文协议，生成的 Recommendation 与投影、receipt 和清理证明完整
  绑定；调用一次、无工具、无重试，grant 已撤销，凭据未进入 artifact。运行材料位于已忽略且仅所有者可
  访问的 `.vulnloom/`，未新增网关或凭据信息到 Git。
- 新增 generated admission：只从权威 generation ledger 读取 completed `recommendation_ready` outcome，
  重新核对生成计划和静态来源后绑定 outcome ID/摘要。成功记录正文绑定已验证，但 Candidate 保持
  `PROPOSED`，仍需独立人工选择且不可进入 Validation Intake。
- generated admission 新增 4 项回归；全量 1237 passed、23 skipped，覆盖率 86.48%。真实成功 outcome 的
  离线接纳记录也已验证为单条 completed，未产生模型、目标网络或 Validation 调用。
- 新增 Recommendation 人工选择 command/record、独立 checkpoint ledger、离线 CLI 和 loopback-only Web
  UI。两步确认记录 accept/reject/defer；只有 accept selection 标记可供后续 Intake 核验，Candidate 始终
  不变且动态 Validation 仍需单独 Approval。UI 无外部资源，执行 Host/Origin/CSRF/大小/字段闭集检查。
- 新增 Recommendation Validation Intake plan/record 与独立 checkpoint ledger。它只消费权威 accept
  selection 和预构造的 exact 离线 ValidationPlan，拒绝 Broker/网络计划，保持 Candidate 为 `PROPOSED`，
  并固定要求后续独立 `RUN_VALIDATION` Approval；本阶段不调用 ValidationService 或任何执行 adapter。

### 通用 Model Profile P1（真实 CUC 新路径验收已完成）

- 通用 OpenAI-compatible Chat codec、两阶段 Profile prepare/bind、Endpoint 引用解析、Capability/Flow/Role/
  budget 校验及权威 Egress Grant 绑定已完成；双假 Provider 的完整 Agent turn 覆盖成功、401、429、超时、
  畸形响应和全部敏感缓冲清理。
- 2026-09-09 经用户既有真实模型调用授权，使用固定合成上下文、零工具权限和短期 Grant 执行通用 Profile
  路径验收。首次因输出不符合 `AgentDecisionPayload` 正确拒绝、无 receipt；据此将 prompt 升级为 v2，并
  消除 JSON/Pydantic 原始响应在异常链中的保留。
- 第二次调用通过严格结构、模型身份和有界 usage 校验：626 input / 64 output tokens，receipt 非空，凭据、
  请求和响应缓冲均归零；Grant 在 finally 路径撤销。验收材料只在已忽略的 `.vulnloom/` 中保存稳定诊断和
  摘要，不保存 Provider 正文、凭据或完整认证响应。
- 当前全量验证为 1315 passed、24 skipped，覆盖率 86.29%；lint、294 份 JSON Schema 解析及 Grant 撤销账本
  检查通过。P1 新路径门禁已经满足，默认路由切换与 Provider Center CLI/API 属于后续独立变更。
- P1.5 两个业务入口迁移已完成：只读代码审阅和 Candidate Recommendation 均可把专用输出 codec 绑定到
  可信 Profile/Flow/Grant，并使用 Provider-neutral invocation result；第二个合成 Provider 覆盖成功、
  拒绝、超时、清理失败、只读重放和 Candidate 不变性。CUC 配置仍是 CLI 默认。下一阶段进入 Provider
  Center CLI/API。

### Provider Center P2（可信本地首个纵切）

- 新增供 CLI 与未来 API 共用的 `ProviderCenterService`，严格 command/query 只接收
  `EndpointRef`/`SecretRef` 等引用，不接收 Key、完整 endpoint、Authorization header 或原始响应。
- SQLite registry 事务保存 Provider revision、Capability Manifest、默认 Route、probe checkpoint 和脱敏审计；
  配置命令幂等，冲突拒绝，未知 probe 中断保留 `STARTED` 并要求显式恢复。
- Provider 更新重置 lifecycle trust。启用必须原子绑定至少一条默认 Route，并复用既有 Flow snapshot 准入检查
  lifecycle、引用完整性、probed capability、数据类别、fallback 和预算；禁用后新 Flow fail-closed。
- CLI 支持 Provider 查看、添加、更新、离线 probe、启用、禁用、审计，以及默认 Route 查看与切换。查询包含
  `unknown/healthy/failed/timed_out/disabled` 健康摘要，且不显示秘密或完整 endpoint。
- capability probe 使用可注入 adapter；本阶段 CLI 仅开放无 socket fixture adapter。真实 Provider 调用仍保留
  在既有显式 Egress Grant 与联网开关之后，本次实现和测试均未联网。
- CUC/DeepSeek 固定 probe、代码审阅和 Candidate Recommendation 默认入口保持不变；Provider Center Route
  只供显式采用 registry 的新 Flow 使用，不会静默接管旧入口或失败后跨 Provider 降级。

操作合同与剩余 P2 边界见 `docs/PROVIDER-CENTER.md`。下述 P2.1 接入既有真实 capability probe 的结果；
模型目录同步、权限受限的凭据替换 adapter 和薄 HTTP API 继续后置，Web UI 不在当前阶段。

### Provider Center P2.1（权威 Probe 结果绑定）

- 新增只含摘要/引用的 `BindProviderProbeCommand` 与 `ProviderProbeBindingRecord`，Provider Center 不保存
  `ProviderProbeConfig`、hostname、认证响应或 Provider token。
- 复用既有 probe ledger 的只读 completed loader，重新验证 plan/result、config digest、Provider/模型、
  credential ref、EndpointRef 临时解析、deadline、attempt、receipt 和 cleanup；STARTED 或篡改记录拒绝。
- CUC PONG 只能证明 chat/usage，固定结构化 JSON 只能证明 chat/strict structured output/usage；调用方必须声明
  exact 闭集，不能把 connectivity overclaim 为工具、推理或其他能力。
- passed source 结果在单一事务中写入 binding、Manifest、lifecycle 与审计；rejected、timed_out 和 cleanup
  未证明只保存脱敏 terminal binding，不提升 Profile。写入失败整体回滚并可安全重试。
- `provider bind-probe` 只读本地 config/ledger 并复用应用服务，不联网、不取得 Key；现有真实 probe 仍要求
  独立 Egress Grant、显式网络开关和用户授权。probe ledger 使用 SQLite read-only 模式，错误路径不会创建
  空账本。本轮测试没有真实 Provider 调用。

### Provider Center P2.2（Revision-bound Model Catalog）

- 新增纯领域 `ModelCatalogEntry`、声明限制、价格元数据和不可变 `ModelCatalogSnapshot`；所有条目绑定确切
  Provider ID、Profile digest 和 observed time，模型 ID/显示名/别名使用受限字符集。
- 新增类型化 catalog sync request/observation/result、独立幂等 checkpoint、超时/cleanup 判定与事务性 snapshot
  替换。跨 Profile/Provider、条目超限、重复模型、冲突别名、错误时间和 lifecycle 漂移均 fail-closed。
- 首个 `catalog-sync-offline` CLI 只允许 `manual` / `offline_fixture` adapter，不访问网络或凭据，也不能冒充
  `provider_api` 来源；`catalog-list` 和 Provider Center view 为未来 API 提供同一查询合同。
- 成功目录同步只把 `CONNECTIVITY_VERIFIED` 推进到 `CATALOG_DISCOVERED`；目录声明不会自动生成 Manifest、能力、
  角色准入或默认 Route。Profile 更新 revision 后，旧 snapshot 不再作为当前目录返回。
- 已覆盖成功、幂等、生命周期/来源拒绝、身份/别名/数量拒绝、超时、cleanup、事务回滚恢复和输出脱敏。本轮没有
  真实 Provider 调用。

下一步是权限受限的凭据替换 adapter，然后实现薄 HTTP API；Provider API 联网目录拉取仍需独立显式授权和网络门禁。

### Source Hunt V1（可信本地纵切已完成）

- 新增统一的 `source-hunt` 应用服务与 CLI：对已授权 Snapshot 建立 Python、JavaScript/TypeScript 导航索引，
  以文件数、总字节、单文件、分区、查询、观察和 deadline 多重预算限制调查，并持久化可恢复 checkpoint。
- Agent 循环只接受类型化 query/propose/abandon 决策；按需源码窗口逐级禁止符号链接、复核 manifest 大小与
  SHA-256、限制行数/字节并在进入观察账本或模型边界前脱敏。Provider 凭据不进入 Source Hunt 或 Worker。
- Source Candidate 只能落为共享 `PROPOSED` Candidate；固定 Build→Harness→Fuzz→Sanitizer→PoV replay 计划
  绑定 Candidate、Snapshot、Scope、Policy、tool registry 和精确工具 ID，默认无网络并要求
  `RUN_UNTRUSTED_BUILD` Approval。
- 执行支持中断恢复、超时/失败/取消 fail-closed、Runner 输出脱敏 Evidence 化和清理证明；完成结果复用共享
  Validation、Critic、Finding 与 Report。Finding promotion 重新读取权威 Validation/Critic ledger，并要求独立
  `MUTATE_TARGET_STATE` Approval。
- 每个成功阶段必须提供唯一的内容寻址 typed receipt，并从 Candidate digest 串成摘要链；Fuzz receipt 必须包含
  正覆盖边数和 Crash 指纹，Sanitizer 与 PoV 必须维持同一指纹，普通日志或合成 `completed` 文本不能冒充结果。
- 默认测试只使用 fake adapter；opt-in Docker 验收已实际证明五阶段容器非 root、无 capability、
  `NoNewPrivs`、源码只读、无默认路由、无 Docker socket、无模型 Key 继承和无残留容器。
- 本里程碑完成的是安全控制面和端到端证据链。专用 C/C++ toolchain、coverage-guided fuzzer、ASAN/UBSAN
  解析、Crash 去重、自动 Harness/Patch 和 blind holdout 仍属于 R9 深化，不能用合成阶段输出冒充真实结果。

详细操作与边界见 `docs/SOURCE-HUNT.md`。

### Authorized Red Team R0.1–R3（可信控制与隔离本地 HTTP Recon 已完成）

- 新增共享 `WorkflowMode`，将四入口、Visibility、Execution Profile 与自治等级分开表达；红队首版固定为
  `black_box/grey_box + red_team + A2 bounded execution`，不冒充未来 A4 Campaign。
- 新增内容寻址的 URL Target、Rules of Engagement、Stop Conditions、Flow Plan、Recon Command、Observation
  和显式状态机。RoE 精确绑定 Scope/version、目标、阶段、测试类别、影响分区、deadline、动作/连续失败预算和
  opaque emergency-contact ref。
- 当前只准入 `recon + read_only`；状态变更、真实凭据、外部回连、横向移动和持久化全部显式禁止。URL 必须
  已规范化且无凭据/query/fragment，并由既有 Policy Engine 精确匹配 Scope host/scheme/port。
- SQLite 事务保存 Plan、checkpoint、action claim 和脱敏 Observation；幂等键冲突拒绝。Adapter 中断要求下一
  attempt，最多三次；第三次仍中断则以 cleanup unproven 关闭。完成态重放不再次调用 adapter。
- 本地 CLI 支持 start、prepare-recon、run-recon-offline、status、cancel、kill 和 expire；执行命令只接离线 fake
  adapter，不开放联网开关、任意工具、Header、Cookie、Key、Provider token 或响应正文。
- Kill Switch 在 Scope 被撤销或过期后仍可收窄并终止同一绑定 Flow。成功、越界拒绝、中断恢复、attempt
  耗尽、超时、清理失败、预算完成、连续失败、取消、过期、Kill Switch、CLI 和敏感字段回归均有离线测试。
- R3 复用 pinned live HTTP Broker 增加只接受 `HTTP_HEAD` 的可信 adapter；内容寻址、限时的 local admission
  精确绑定一个私有非回环 IPv4、host、port、scheme，Profile 只能有同一条 network grant，Broker 再强制 exact
  resolved-IP set。每跳重新检查 Scope/Policy/DNS/peer，另一个私网 IP 的 DNS drift 也会在 socket 前拒绝。
- 成功调用产生内容寻址 `AttackSurfaceSnapshot`，只保存 URL/Policy 摘要、已验证 peer、状态、重定向计数和
  Evidence refs；不保存原始 URL、Cookie、Authorization、响应 header/body。socket timeout、Flow cancel、幂等
  replay、脱敏和真实本机临时 HTTP 进程清理已有测试。

R3 没有普通 CLI 联网开关；真实 socket 验收必须显式设置 `VULNLOOM_RED_TEAM_INTEGRATION=1`，且仅启动本机
隔离夹具。下一步先在这些可信 Observation 上构建有界 Attack Surface reducer；公网扫描和主动利用仍不可用。
详见 `docs/AUTHORIZED-RED-TEAM.md`。

## 延后事项

- 公网资产自主发现。
- 自动化漏洞平台提交。
- 自动申请 CVE。
- 通用任意 Shell。
- 多租户 SaaS。
- 直接连接生产 Kubernetes 集群。

这些能力会显著扩大授权、隔离和运维边界，不应在本地研究 MVP 中提前引入。
