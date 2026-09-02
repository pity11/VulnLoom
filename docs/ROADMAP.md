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

## 延后事项

- 公网资产自主发现。
- 自动化漏洞平台提交。
- 自动申请 CVE。
- 通用任意 Shell。
- 多租户 SaaS。
- 直接连接生产 Kubernetes 集群。

这些能力会显著扩大授权、隔离和运维边界，不应在本地研究 MVP 中提前引入。
