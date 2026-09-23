# VulnLoom 当前开发总纲

状态：`ACTIVE`

更新日期：`2026-09-23`

## 1. 文档作用与权威顺序

本文是 VulnLoom 后续开发、里程碑选择和跨聊天交接的首要导航页。它不复制每个历史里程碑的实现细节，
而是回答四个问题：当前已经完成什么、下一步先做什么、两条核心能力线如何推进、哪些能力明确延后。

发生冲突时按以下顺序处理：

1. 仓库根目录 `AGENTS.md`：不可破坏的安全与工程约束；
2. 本文：当前开发顺序、里程碑状态和下一阶段范围；
3. `PRODUCT-ARCHITECTURE-ROADMAP.md`：长期产品边界、四入口和目标架构；
4. `ROADMAP.md`：已经完成的细粒度里程碑及验收记录；
5. `ARCHITECTURE.md`、`SECURITY.md` 和各专项文档：实现合同与安全边界。

新聊天不得只根据聊天摘要判断进度。开始编码前必须读取 `AGENTS.md`、本文、相关专项文档，检查
`git status`、最近提交和现有测试，避免重复已经关闭的工作。

## 2. 产品结构

VulnLoom 保留四个入口，但只维护一套共享平台：

| 类别 | 入口或能力线 | 作用 |
| --- | --- | --- |
| 核心能力线 A | Source Hunt | 源码调查、Candidate、Build/Fuzz/Sanitizer/PoV、独立验证与复测 |
| 核心能力线 B | Authorized Red Team | 授权 Web/API Recon、动态验证、受控攻击链、检测与防御报告 |
| 交付工作流 C | 上线前安全验收 | 组合 Source、Deployment 和 Live Evidence，形成发布门禁 |
| 交付工作流 D | 生产环境定期巡检 | 在 `production_safe` 策略下执行精确路径检查、差异和历史复测 |

四个入口共用 Scope、Policy、Approval、Provider、Runner、Broker、Evidence、Candidate、Validation、
Critic、Finding、Report 和 Audit。它们不共用完整 Prompt、工具白名单或执行强度，也不得各自复制安全底座。

## 3. 当前基线

截至 2026-09-21，以下限定能力已经关闭首版里程碑：

- Provider/Profile/Route 控制面和 Provider Center P2.0-P2.2：可信本地 CLI、生命周期、能力探测绑定、
  revision-bound model catalog 和默认 Route；真实 Provider 调用仍必须显式授权，薄 HTTP API 和 Web UI 尚未完成；
- Source Hunt V1 与 R9 固定 Benchmark：可恢复源码调查、共享 Candidate-to-Report 链、固定五阶段
  Build/Harness/Fuzz/Sanitizer/PoV，以及真实 rootless/Docker 隔离准入；
- Hybrid R10：源码、部署和精确 Live Endpoint Evidence Chain、Finding、双重复测、报告和 CI/CD Release Gate；
- Authorized Red Team R0.1-R11.4：封存 Endpoint Seed Set、定期精确检查、受控多步攻击链、Cleanup、
  Attack Path Report，以及预算、并发、Kill/Cancel 和 deadline 压力加固；
- 共享底座：类型化 Agent Runtime、Provider token 边界、Worker 环境白名单、Tool Broker、Evidence Store、
  Approval Gate、Validation、Critic、Finding 和报告。

这些结论只适用于相应文档中限定的离线或隔离验收范围。当前没有通用公网扫描、Crawler、字典枚举、
任意 Shell、自动披露提交、真实凭据攻击、横向移动或持久化能力。

## 4. 当前优先级：共享安全资格 S1

下一重大里程碑是 `S1 Hostile Worker Security Qualification`。S1 是两条核心能力线共同依赖的安全门禁，
不是新的产品入口，也不扩大目标、网络或攻击能力。它放在更丰富的自动规划、工具和漏洞类别之前完成。

长期路线中的 `R12` 已保留给团队化和分布式部署；S1 不占用或重编号 R12。

### S1.1 敌对 Worker 准入

在完全本地、无公网和无真实秘密的 fixture 中，假设 Worker 已获得容器内任意代码执行，验证它仍然不能：

- 读取 Provider、披露平台、宿主或其他 Engagement 的秘密；
- 连接公网、宿主网关、云元数据地址、同级容器或未授权目标；
- 访问 Docker socket、SSH agent、用户主目录或 Control Plane 文件；
- 修改 Source Snapshot、Context、Skill、Policy、Tool Registry、Evidence 或权威账本；
- 通过后台进程、可写层或遗留容器跨任务持久化；
- 在超时、取消、崩溃和清理失败时伪装成安全终态。

测试使用 canary 文件、假凭据和本地拒绝端点，不实现真实反弹 Shell、外传或逃逸载荷。隔离声明必须由真实
rootless 容器、进程和网络配置证明；普通 CI 继续使用离线 fake，真实准入保持显式 opt-in。

### S1.2 执行隔离和资源压力

- 为执行不可信代码的 Profile 增加仓库版本化的 seccomp 合同，并在容器创建后复核实际配置；
- 保持 Static、Validation、Post-exploitation 和 Report Profile 的最小权限差异；
- 覆盖 fork bomb、PID/FD/输出/磁盘/内存耗尽、超时、进程组回收和残留对象清理；
- 保留 Runner adapter 接口，使后续可在不改变领域层的前提下评估 gVisor、Kata 或独立 VM；
- 本阶段不强制迁移新运行时，除非现有 rootless Docker 无法满足验收。

### S1.3 秘密泄漏与出口安全回归

- 用 canary secret 覆盖 Worker、Provider transport、异常链、stdout/stderr、Evidence、报告、CLI/API 和模型上下文；
- 所有出站网络继续由可信 Broker 或 Provider transport 控制，Worker 不持有 Provider token；
- 统一敏感字段最小化和脱敏合同，并验证分段、编码、超长和畸形输出不会绕过大小与清理边界；
- 本阶段完善确定性规则和结构化出口门禁，不引入未经验证的“智能 DLP”作为安全判定依赖。

### S1.4 防篡改审计骨架

- 审计记录绑定前一记录摘要，检测删除、插入、回滚和分叉；
- 状态变化绑定 Scope、Policy、Profile、Context、Tool Registry、Provider revision 和关键输入摘要；
- 查询和未来 API 只返回脱敏投影；
- 本阶段固定 schema、hash-chain 和恢复语义，外部签名、WORM 和远程透明日志延后到部署边界明确后。

### S1 完成标准

除 `AGENTS.md` 的通用完成标准外，S1 必须证明：即使一个 Worker 在其沙盒内被完全控制，也只能破坏自己的
短生命周期执行环境，不能取得秘密、扩大网络范围、修改权威状态、跨任务持久化或掩盖清理失败。

S1 完成后停止横向扩张安全基础设施，回到两条核心能力线。发现阻断性问题时修复底座；非阻断的分布式、
企业化或高成本隔离方案记录到延后项。

## 5. 核心能力线 A：Source Hunt 后续计划

当前状态：可信本地 V1 和固定 native Benchmark 已完成；它证明了协议、隔离和固定 C fixture，尚不能外推为
通用项目自动构建或广泛漏洞发现能力。

S1 之后按以下顺序推进：

1. **A1 通用 Project Recipe Registry**：版本化、内容寻址的构建/测试 recipe；只允许预注册工具和镜像，项目
   构建步骤必须作为封存输入在 `RUN_UNTRUSTED_BUILD` Approval 下进入隔离 Runner，Agent 不能提交任意宿主
   Shell；覆盖成功、拒绝、超时、漂移和清理；
2. **A2 语言与框架深度**：在现有 Python Web 基础上补强 JavaScript/TypeScript 调用图、路由、身份和数据流，
   再依据基准结果决定下一语言，不以工具数量作为完成标准；
3. **A3 Harness 与运行时证据扩展**：受限 Harness proposal/admission，增加 UBSAN 等独立 adapter；任何生成物
   仍需固定计划、Approval 和独立 PoV 重放；
4. **A4 Blind Holdout 与质量门禁**：测量相对固定 AST 基线的增益、Precision、复现率、人工否决率、Critic
   分歧和到首个有效 Finding 的时间；安全违规是独立否决项；
5. **A5 修复建议与双重回归**：先生成只读 Patch proposal，再由独立源码和动态复测证明，不允许模型直接修改
   用户仓库或把建议当作已修复事实。

重大正向里程碑：在至少一个非固定真实本地项目快照上，通过版本化 recipe 完成可重复 Candidate→Validation→
Critic→Finding/Unresolved Candidate，并在 Blind Holdout 中不降低既定 Precision 门槛。

## 6. 核心能力线 B：Authorized Red Team 后续计划

当前状态：R11 已完成单一隔离私网 fixture 上的封存多步链和防御报告；这属于 A2 bounded execution，不能描述
为 A4 自主 Campaign。生产路径检查仍只访问操作员精确封存的 Endpoint Seed Set。

S1 之后按以下顺序推进：

1. **B1 Observation-driven bounded replanning**：Agent 可在既有 Scope 和有限工具视图内提出下一步，但每个新
   Action 必须重新封存、预算、策略判定和必要 Approval；不得由 Agent 文本或 Observation 直接扩展 Target；
2. **B2 Web/API 只读面深化**：针对已明确列出的路径增加类型化 HTTP、OpenAPI/GraphQL 等观察 adapter；仍不加入
   crawler、字典枚举、CIDR/端口扫描或任意请求脚本；
3. **B3 漏洞类别纵切**：按版本化 Evidence Requirement 逐类实现正例、负例、最小 Validation、Critic 和 Cleanup，
   优先低影响 Web/API 类别；Scanner 命中只能形成 Signal/Candidate；
4. **B4 授权派生资产与测试身份**：B4.0 先以 FOFA/Quake/Shodan/被动 DNS/证书透明度/ICP 等受约束来源发现
   `DiscoveredAsset`，只有确定性归属和授权策略接受后才发布无主动测试权的 `AuthorizedAsset`；B4.1 起只使用
   控制方测试身份和 opaque reference，登录、角色和状态变化分别经过 Vault、Session 隔离与 Approval，不测试
   真实第三方账户；
5. **B5 Lab A3/A4 资格**：只在隔离靶场评估更长攻击图、恢复、Refiner 和 Coverage Ledger；达到 A4 前不得对外称为
   自主红队 Campaign。

重大正向里程碑：在隔离靶场中，系统根据 Observation 至少两轮调整有界计划，完成一个可清理的 Web/API
Candidate→Validation→Critic→Finding 或明确的 Unresolved Candidate，同时证明越界、预算耗尽、取消和失败路径。

## 7. 两类交付工作流

### C：上线前安全验收

R10 已关闭首个 Hybrid 纵切。后续只复用已经准入的 A/B 能力，重点是 Deployment Proof、源码与 Live 双重复测、
Release Gate 和覆盖账本；不在该工作流内另造分析器、Runner 或 Finding 状态机。

### D：生产环境定期巡检

当前已有精确 Endpoint Seed Set、预算化 Schedule、差异和恢复合同。下一阶段只接入已通过 B 线准入的
`production_safe` 动作，默认只读、低速、固定窗口和熔断。新发现资产先记录为 `DiscoveredAsset`；只有命中当前
任务的确定性授权派生规则，才能发布为仍无主动测试权的 `AuthorizedAsset`。模糊归属、跨独立法人和供应链资产
分别进入审批或拒绝，不能由模型或指纹相似度直接升级为可执行目标。

## 8. 共享控制面后续

- **Provider Center**：下一步是权限受限的凭据替换 adapter 和复用相同应用服务的薄 HTTP API；Web UI 后置。
  CUC/DeepSeek 保持前期默认路由，真实外部调用仍逐次要求明确授权；
- **CLI/API 合同**：CLI 和未来 API 必须调用同一应用服务，不能通过表面层绕过状态机；
- **质量与能力状态**：统一使用 `designed`、`offline_tested`、`isolated_integration_tested`、`lab_admitted`、
  `authorized_pilot`、`production_supported`，不把组件测试写成产品入口完成；
- **Web UI**：等应用服务和稳定 API 合同完成后再开发，不在当前阶段提前实现。

## 9. 明确延后

- 面向未授权公网的资产发现、Crawler、字典枚举和未封存路径探索；授权实体范围内的被动测绘发现按 B4.0 管理；
- 通用任意 Shell、Worker 直接网络和 Worker 持有 Provider/平台 token；
- 自动披露平台提交、自动申请 CVE；
- 真实第三方账号攻击、撞库、钓鱼、社工、横向移动、持久化和真实数据外传；
- 全面迁移 gVisor/Kata/Firecracker；
- 大型语义 DLP 平台、远程 WORM/透明日志；
- R12 团队化和分布式部署，包括 PostgreSQL、远程 Runner、OIDC/RBAC、HA 和多租户。

延后不等于永不实现。只有对应 Threat Model、ADR、类型化协议、隔离环境和验收标准完成后才能进入当前计划。

## 10. 新聊天接续清单

切换聊天后，新的开发 Agent 应依次：

1. 读取根目录 `AGENTS.md` 和本文；
2. 检查 `git status --short --branch`、最近提交和 `origin/main` 差异；
3. 根据当前里程碑读取专项文档：S1 读 `SECURITY.md`，A 线读 `SOURCE-HUNT.md`，B 线读
   `AUTHORIZED-RED-TEAM.md`，Hybrid 读 `HYBRID-VALIDATION.md`，Provider 读 `PROVIDER-CENTER.md`；
4. 在 `ROADMAP.md` 确认该纵切是否已经完成，禁止重复实现；
5. 先汇报真实状态和准备实现的最小完整纵切，再直接编码；
6. 默认只运行离线测试。真实 Docker、私网 fixture 或模型调用必须使用既有显式开关和独立授权；
7. 完成后更新本文状态、专项文档和 `ROADMAP.md` 验收记录，并运行相称的测试、Ruff、schema 解析和
   `git diff --check`；
8. 检查 diff 不含凭据、私有 endpoint、完整认证响应或原始敏感数据；未经授权不 push。

当前下一项工作固定为 **B4.2 Vault credential lease、Approval binding 与隔离 Session contract 纵切**。A1 通用 Project Recipe
Registry、B1 Observation-driven bounded replanning、B2 Web/API 只读面深化与 Shared Assurance S1 已关闭；
B3.1-B3.4、B4.0 与 B4.1 已达到 `offline_tested`。B4.0 尚无真实测绘平台 adapter、公网查询或主动探测；B4.1
只固定控制方测试身份的 opaque reference、用途、Target/Scope、撤销和过期边界，没有获取凭据或创建 Session。
B4.2 先实现完全离线的短期 credential lease、Approval 绑定和 Session 生命周期；不接入真实登录、状态变更测试或
第三方账户。只有出现新的用户优先级决定，才从其他
里程碑开始。

进展记录（2026-09-21）：S1.1 的类型化七 probe 资格协议、Docker 完整挂载/host 资源复核、离线拒绝与清理回归、
以及 rootless 组合 canary 已实现。commit `4363236151e67e04022b926cbdccf0fffd223412` 的专用 rootless Linux
Admission run `35549659248` 已通过，生产准入批次为 8 passed、9 passed、5 passed/9 deselected；新增 hostile
Worker canary 所在批次无 skip，S1.1 关闭。

S1.2 已开始首个纵切：仓库内版本化、内容寻址的 `docker-builtin-worker-v1` seccomp 合同绑定到每个 Sandbox
Profile；生产默认只接受准入的 Docker Engine 29.7.2 builtin profile，版本漂移与 `seccomp=unconfined` fail-closed，
rootless probe 从容器内复核 Linux `Seccomp: 2`。本地全量门禁为 1534 passed、31 skipped、覆盖率 85.42%；
commit `5fd74a385a4493baddb31526f876e8e77935a10b` 的 Phase 3 run `35550502151` 已通过真实 rootless 复核。
同提交的 CI run `35550502111` 已在 Python 3.12/3.13/3.14 全部通过。后续继续覆盖 PID/FD/输出/磁盘/内存
压力与进程组回收。

S1.2 第二个纵切已完成本地实现：新增内容寻址的六类 resource-pressure probe/plan/observation/outcome 协议，
固定 PID、FD、输出、临时盘、内存和超时进程组的终态与错误码；缺失、摘要漂移、边界未证明、容器残留或
cleanup unknown 均 fail-closed。rootless opt-in canary 仅使用最多 64 个短进程、有限 FD、64 KiB 输出、2 MiB
写入和 64 MiB 分段分配等有界本地载荷。Ruff、全量离线测试、433 份 schema 解析和 diff check 已通过；本地
Docker Desktop 仅验证了 canary 自身能触发 PID/FD/tmpfs/OOM 边界，不构成生产资格。专用 rootless Admission
run `35551489391` 已通过，资源压力纵切提升为 `isolated_integration_tested`；同提交 CI run `35551489390`
在 Python 3.12/3.13/3.14 全部通过。

S1.2 第三个纵切已达到本地集成测试：新增绑定唯一 run id 的线程安全 `RunnerCancellation`，跨运行取消在容器
创建前 fail-closed，预取消不分配资源，活动取消会终止 Docker attach 客户端、kill 容器并验证 remove/absence。
普通执行与有界输出捕获的本地无网络 Docker canary 均返回 `CANCELLED`、不发布部分输出并回收两个后台进程及
匿名存储。commit `55769eb3c6fe6f276b0efcc1270c9b6dc915c77f` 的 rootless Phase 3 run
`35553231582` 已通过，取消纵切提升为 `isolated_integration_tested`；CI run `35553231580` 在 Python
3.12/3.13/3.14 全部通过。

S1.2 最后一个关闭项已进入本地集成测试：四类 Profile 的 live Docker matrix 逐一验证 exact source/evidence
只读槽、非 root、零 capability、NoNewPrivs、seccomp mode 2、network-none、只读根与清理；仅 Validation 的
输出 tmpfs 允许执行，其余 Static/Report/Post-exploitation 均为 noexec。四个本地 canary 已通过，rootless
Phase 3 run `35553910680` 已通过，生产批次为 8 passed、16 passed、5 passed/9 deselected；CI run
`35553910683` 在 Python 3.12/3.13/3.14 全部通过。S1.2 至此关闭，下一项固定为 S1.3。

S1.3 已完成：内容寻址的八表面资格协议覆盖 Worker output、Provider transport、exception chain、event log、
Evidence、Report、CLI/API 与 model context；缺项、重复、漂移、过期、canary 命中或出口/大小/清理未证明均
fail-closed。`builtin-v3` Redactor 支持可信注入的已知秘密及确定性编码变体，分段输入具有原始/输出双字节限额、
strict UTF-8 和终态清零；Worker 输出发现敏感内容时不发布对象，外部工具与 Provider 的原始 stderr/解析异常不
进入异常链。全量离线回归、437 份 schema 和本机无网络 Docker 的成功/拒绝/清理路径通过；没有公网访问、真实
模型调用或真实攻击。S1.3 关闭，下一项固定为 S1.4。

S1.4 首个纵切已达到 `offline_tested`：共享权威审计合同和 SQLite append-only hash chain 强制每条记录绑定前序
摘要、Scope/Policy/Profile/Context/Tool Registry/Provider revision、状态迁移与关键输入摘要；同 stream 不能跨
Engagement。类型化外部 checkpoint 区分本地 corruption、完整 rollback 和有效替代 fork；验证失败后禁止追加和
digest-only 投影，不会自动截断或重算，恢复必须来自通过同一 checkpoint 的外部完整副本。删除、插入、改写、
重排、head 漂移、回滚、分叉、过期、事务失败、幂等、恶意记录膨胀和恢复路径已覆盖。全量门禁为 1586 passed、
39 skipped、85.51% coverage，443 份 schema 通过。

S1.4 第二个纵切已达到 `offline_tested`：`EventStore.append_authoritative` 在单个 SQLite `BEGIN IMMEDIATE` 内共同
提交脱敏领域事件、审计记录和 head，写入与权威读取均要求可信外部 checkpoint，并验证 Engagement 专用 stream
中的每条 event/audit 在幂等、aggregate 和 transition 摘要上一一对应。单边缺失、领域 payload 改写、完整双边
回滚、链损坏、跨 Engagement、过期和 SQL 中断均 fail-closed，不允许 backfill 伪装原子提交。全量门禁为
1596 passed、39 skipped、85.54% coverage，443 份 schema、Ruff 和 diff check 通过。

S1.4 最终纵切已达到 `offline_tested`：本地 checkpoint custody 强制 digest 路径、大小、普通文件和 owner-only
权限，使用 per-stream lock、`fsync`、原子替换和单调 compare-and-swap；拒绝符号链接、宽松权限、回退、分叉与
非空数据库的无 anchor backfill。checkpoint 推进失败可由同一幂等事件重试恢复。主 CLI 的 9 个真实事件写入口与
`status` 已全部迁移到 `CheckpointedEventStore`，旧裸 `EventStore.append` 不再出现在生产 CLI 路径。默认 anchor
只与数据库分文件，部署时可通过 `--audit-checkpoint-store` 放入独立受保护路径；远程签名、WORM、透明日志以及
其他独立内容寻址账本的风险驱动迁移仍按计划延后。最终全量门禁为 1604 passed、39 skipped、85.51% coverage，
443 份 schema、Ruff 和 diff check 通过；无公网、真实模型或真实攻击。S1.4 与 Shared Assurance S1 至此关闭，
下一项固定为 A1 通用 Project Recipe Registry。

进展记录（2026-09-21）：A1.1 达到 `offline_tested`。新增版本化、内容寻址的 `ProjectRecipe`/Step/Run Plan，
可信 Registry 只接受绝对非 Shell 固定 argv、显式无密钥环境和精确镜像 digest，并派生唯一 Docker tool 注册。
计划器只接受 recipe ID，在已批准 Scope 和匹配 RepositoryIndex 上生成单工具、无运行时参数、无网络、只读
Snapshot 的确定性请求；执行前重新物化计划，并要求精确 `RUN_UNTRUSTED_BUILD` Approval。SQLite store 支持
逐步 checkpoint、幂等重放与冲突拒绝；成功、审批拒绝、构建系统不匹配、超时、计划漂移和 cleanup unknown
均有离线回归。本纵切未运行 Docker、未执行真实项目或依赖安装、未联网、未调用模型。下一步 A1.2 使用预构建
本地镜像和非固定项目 fixture 做显式无网络 Docker Admission；通过前不关闭 A1。
全量离线门禁为 1611 passed、39 skipped、85.45% coverage，448 份 schema、Ruff 和 diff check 通过。

进展记录（2026-09-21）：A1.2 达到 `isolated_integration_tested`。摘要固定的本地 Python filesystem 经
`scratch` final stage 重封装，剔除上游 `GPG_KEY` 等隐式镜像环境；首次带该变量的官方镜像已被 Runner 正确
拒绝，未扩大白名单。显式 Admission 使用 `--network none --pull=false` 构建，并由生产 Docker Runner 实际执行
dependency-free Python 项目的 Build→Test 与一秒 timeout。两条路径均复核 UID/GID 65532、只读 root/source、
无 capability、`NoNewPrivileges`、无网络、无 Docker socket、资源/tmpfs 限制和容器最终不存在。本机 Docker
Desktop 不冒充 rootless，生产继续要求 S1 已验证的 rootless policy。本轮无镜像拉取、依赖安装、公网访问、
真实模型或攻击。A1 尚未关闭；下一步 A1.3 必须在非 fixture 本地项目上绑定 Recipe outcome 至完整 Source Hunt
Candidate→Validation 链。
最终默认离线门禁为 1612 passed、42 skipped、85.45% coverage；显式 Docker Admission 为 3 passed；448 份
schema、Ruff 和 diff check 通过。

进展记录（2026-09-21）：A1.3 达到 `isolated_integration_tested` 并关闭 A1。新增内容寻址的
`ProjectRecipeCandidateBinding`，精确绑定成功 Recipe plan/outcome、Registry、Recipe、Index、Manifest、Target、
Scope 与 `PROPOSED` Candidate。Source Execution 可封存 binding ID，但执行前必须从权威 Recipe store 重读并逐项
核对；缺失、伪造、Candidate/Index/Manifest 漂移均 fail-closed，五阶段 Validation 与后续 Critic/Finding Gate
没有被 Recipe 成功替代。显式验收把当前 VulnLoom 的 `pyproject.toml` 和全部 Python package 源码物化为只读
Snapshot，在无网络、无依赖安装的本地清洁 Python 3.12 容器中完成 Compile→结构检查、持久化 Candidate binding
并证明容器清理；离线端到端回归消费同类权威 binding 完成 Candidate→Validation，同时覆盖缺失与伪造拒绝。
本轮未访问公网、未调用真实模型、未执行真实攻击。默认门禁为 1615 passed、43 skipped、85.53% coverage；显式 A1.3 Docker
Admission 为 1 passed；449 份 schema、Ruff 和 diff check 通过。下一项按双线轮转进入 B1.1。

进展记录（2026-09-21）：B1 达到 `offline_tested` 并关闭。新增内容寻址的 `RedTeamReplanToolView`、Proposal 和
Admission：有限视图绑定最新 checkpoint、权威 Observation、原 Target 摘要、Scope、允许的 Action/test class 和
剩余预算，但不暴露原始 URL；Proposal 协议没有 Target、命令或任意请求参数。Control Plane 从封存 Plan 重建每个
Action，重新执行 Policy，并用 SQLite `BEGIN IMMEDIATE` 原子预留预算；每次执行仍要求针对精确 Action ID 的
`EXECUTE_RED_TEAM_ACTION` Approval。相同 Proposal 跨 checkpoint 重放只返回原 Admission；并发超额、陈旧视图、
Observation/Scope/Policy/Approval 漂移均 fail-closed，取消与到期可释放未消费预留。离线验收完成两轮
`TLS_INSPECT → HTTP_HEAD` 调整且 Target 不变，并覆盖成功、拒绝、超时、cleanup unknown、取消、到期和重放。
本轮未访问公网、未调用真实模型、未执行真实攻击。全量离线门禁为 1621 passed、43 skipped、覆盖率 85.44%；452 份 schema、
Ruff 和 diff check 通过。下一项按 B 线进入 B2.1。

进展记录（2026-09-21）：B2.1 达到 `offline_tested`。R7/R8 的 operator-sealed Endpoint Plan 现可选择同质
`HEAD` 或 `GET` step；GET 只能从权威 Seed Set 的 canonical path 派生，通用 Recon、直接 execute 和 B1 Tool
View 均不能准入。pinned Broker 要求精确 URL digest allowlist、redirects=0、空 header/credential/body 和 64 KiB
响应上限。内容寻址 `WebResponseSnapshot` 及 Endpoint outcome 仅保存状态码、Peer、响应大小、正文 SHA-256、
Policy 摘要和 Evidence ID，原始 URL/正文不会进入普通 Observation。离线纵切覆盖成功、幂等重放、未封存路径、
通用绕过、缺失 Snapshot、重定向绑定漂移、原始正文 schema 注入、超时和 cleanup-unproven；已发出请求始终消费
预算。本轮未访问公网、未调用真实模型、未执行真实攻击，也未新增 live CLI 开关。全量门禁为 1627 passed、
43 skipped、85.46% coverage；453 份 schema、Ruff 和 diff check 通过。B2 尚未关闭，下一项为 B2.2。

进展记录（2026-09-21）：B2.2 达到 `offline_tested`。新增内容寻址的 OpenAPI Observation Plan、Path Discovery、
Outcome 与独立 SQLite STARTED/COMPLETED ledger；服务只接受一条已成功、已清理的 operator-sealed GET 及其当前
Flow checkpoint、`WebResponseSnapshot` 和脱敏 Evidence。离线 reducer 仅解析 64 KiB 内的 OpenAPI 3.0/3.1
JSON，拒绝重复 key、非规范 path、未知结构、超深/超量文档和超时；`servers` 与所有 `$ref` 只计数后丢弃，
从不解析、访问或转为 Target。输出只含 canonical path、有限 HTTP method 和摘要，且
`execution_authorized=false`、`target_expansion_authorized=false`。幂等重放、最多三次恢复、来源漂移与无部分
结果语义由事务 ledger 约束。本轮未访问公网、未调用真实模型、未执行真实攻击，也未新增 live CLI 开关。
全量门禁为 1637 passed、43 skipped、85.47% coverage；458 份 schema、Ruff 和专项红队回归通过。B2 保持进行中，
下一项为 B2.3 reviewed discovery promotion gate。

进展记录（2026-09-22）：B2.3 达到 `offline_tested`。新增领域术语 `OpenAPI Discovery Promotion`，明确它只授予
seed 资格而非请求执行权。内容寻址 Promotion Plan 绑定 completed OpenAPI Observation、当前 Flow checkpoint、
Target、Scope/version、操作员和逐项 selection；模板参数必须由操作员具体化为 canonical exact path，未选路径、
未知 discovery、模板错配和只含状态变更 method 的 discovery 均拒绝。Promotion ledger 与 `endpoint_seed_sets`
共享同一 SQLite 事务：STARTED 阶段不发布 Seed，完成时 Seed Set 与 Outcome 原子写入；超时留下可恢复 checkpoint
但没有部分可用 Seed，恢复最多三次，完成态重放不重复发布。新 Seed Set 仍需另行生成有预算 Endpoint Plan，测试
证明 promoted path 可进入 HEAD 计划且没有新增网络调用。本轮未访问公网、未调用真实模型、未执行真实攻击。
全量门禁为 1643 passed、43 skipped、85.50% coverage；462 份 schema、Ruff、红队专项和 diff check 通过。
B2 保持进行中，下一项为 B2.4 sealed GraphQL schema observation。

进展记录（2026-09-22）：B2.4 达到 `offline_tested`，B2 至此关闭。新增 `GraphQL Schema Observation` 领域术语与
内容寻址 Plan/Observation/Outcome；服务只消费一条权威、成功且 cleanup-proven 的 sealed GET Evidence，不持有
网络或模型 adapter。64 KiB 有界 SDL lexer/parser 对 token、type、Query field、嵌套与墙钟设置上限，拒绝 executable
query/mutation/subscription/fragment、畸形定界符、重复定义、保留 field、来源漂移和无 Query root。输出仅包含
Query field 名与 named return type；参数、默认值、描述和 directive 内容不披露，Mutation/Subscription 只计数后
丢弃，所有执行与 Target 扩展权限固定为 false。独立 STARTED/COMPLETED ledger 覆盖幂等、三次有界恢复和 cleanup
proof；拒绝/超时不产生部分结果。本轮未访问公网、未调用真实模型、未发送 introspection/POST/query、未执行真实
攻击。全量门禁为 1652 passed、43 skipped、85.37% coverage；467 份 schema、Ruff（`src/ tests/ scripts/`）、
红队专项和 diff check 通过。下一项为 B3.1 首个低影响 Web/API Evidence Requirement。

进展记录（2026-09-22）：B3.1 达到 `offline_tested`。新增 `Vulnerability Evidence Requirement` 与
`Evidence Assessment` 领域术语；首个 v1 合同固定为未认证敏感数据暴露/CWE-200/read-only，以 11 个类型化事实覆盖
sealed GET、未认证证明、敏感类别存在、独立 replay、redaction、access control/public-by-design/synthetic/version
四项反证，以及 no-state-change/no-artifact Cleanup。Assertion 只含事实、三态结论、Evidence ID 和 opaque
producer/context，不含响应正文、字段名、样本值、凭据或执行步骤。Validation 与 Critic 必须使用互异 producer、
context 和 Evidence。确定性 reducer 输出 Candidate 资格、负例或不确定；缺项/不确定/Cleanup 未证明均不授予资格，
所有结果固定禁止 Finding 和测试执行。独立 STARTED/COMPLETED ledger 覆盖幂等、身份冲突、最多三次恢复、超时与
cleanup proof；Scope 漂移和 Evidence 缺失 fail-closed。本轮未访问公网、未调用真实模型、未执行请求或攻击。
全量门禁为 1659 passed、43 skipped、85.39% coverage；473 份 schema、Ruff、红队专项和 diff check 通过。
B3 保持进行中，下一项为 B3.2 authoritative Evidence Assertion materialization。

进展记录（2026-09-22）：B3.2 达到 `offline_tested`。新增 `Evidence Assertion Materialization` 领域术语与内容
寻址 Plan/Materialization/Outcome；服务从权威 Endpoint Plan/outcome、最新 Flow checkpoint、Observation、
Web Snapshot 和 Evidence 重建单一成功、无凭据、禁重定向、cleanup-proven 的 GET 来源，不持有网络 adapter。
固定 classifier 仅解析 64 KiB 内的 JSON，限制节点、深度、object key 和墙钟；只有固定敏感字段的值已经精确脱敏
为 `[REDACTED]` 才支持 sensitive-presence，未命中保持 inconclusive，非空未脱敏值、重复 key、摘要漂移与结构超限
均拒绝。输出只含计数、digest 和六项 Observation/redaction/Cleanup Assertion，固定不保留字段名/值、不授予请求、
Candidate 或 Finding 权限。端到端回归证明该 batch 进入 B3.1 Assessment 后仍因缺少独立 replay 与 Critic 而保持
inconclusive。独立 ledger 覆盖幂等、来源漂移、超时无部分结果、STARTED 恢复和 cleanup proof。本轮未访问公网、
未调用真实模型、未执行新请求或攻击。全量门禁为 1664 passed、43 skipped、85.38% coverage；477 份 schema、
Ruff、红队专项和 diff check 通过。B3 保持进行中，下一项为 B3.3 independent sealed replay Validation Assertion。

进展记录（2026-09-22）：B3.3 达到 `offline_tested`。新增 `Independent Replay Validation` 领域术语与内容寻址
Plan/Validation/Outcome；服务只比较两份已完成 B3.2 materialization，不持有 HTTP、模型或攻击 adapter。Plan 要求
两份来源具有相同 Scope/version、requirement、精确 URL digest 和固定 classifier，同时 materialization plan、Flow、
Observation、Web Snapshot 与 Evidence 全部不同且 baseline 早于 current；同执行、缺失 Evidence、来源漂移均在写
STARTED 前拒绝。两个正文 digest 且敏感类别结论均一致支持时才产生 supported replay；内容变化或证据不足保持
inconclusive，不伪造负例。输出两项同 context/producer、双 Evidence 引用的 Validation Assertion，并固定禁止请求、
Candidate 与 Finding 权限。接入 B3.1 后独立 replay/redaction 已满足，但 Critic 四项仍缺失，因此仍为 inconclusive。
ledger 覆盖幂等、超时无部分结果、STARTED 显式恢复与 cleanup proof。本轮未访问公网、未调用真实模型、未新增请求
或执行真实攻击。全量门禁为 1668 passed、43 skipped、85.40% coverage；481 份 schema、Ruff、红队专项和 diff
check 通过。B3 保持进行中，下一项为 B3.4 independent Critic Assertion materialization。

进展记录（2026-09-23）：B3.4 达到 `offline_tested`，B3 首个漏洞类别纵切关闭。新增 `Critic Assertion
Materialization` 领域术语，以及内容寻址的四角度 `CriticEvidenceReview`、Plan/Materialization/Outcome。服务只消费
已完成 B3.3 Validation 和一份完整的类型化反证审查；Critic producer、context 与 Evidence 必须同 Validation 全部分离，
review 必须晚于 Validation，Scope、Target/version、requirement 和全部 Evidence 在 prepare/execute/complete 重验。
四项结论的 supported/refuted/inconclusive 原样物化，不执行审查、模型调用或测试。完整 B3.2+B3.3+B3.4 Assertion
链可让 B3.1 reducer 得到 `candidate_eligible`，但物化结果自身固定禁止 Candidate 创建、Finding、请求和审查执行；
反证成立仍得到 negative，不确定仍保持 inconclusive。独立 ledger 覆盖幂等、缺项/证据复用/缺失/漂移拒绝、超时无
部分结果、STARTED 恢复和 cleanup proof。本轮未访问公网、未调用真实模型、未新增请求或执行真实攻击。全量门禁为
1672 passed、43 skipped、85.40% coverage；487 份 schema、Ruff、红队专项和 diff check 通过。B3 关闭，下一项为
B4.1 opaque test-identity admission contract。

进展记录（2026-09-23）：B4.0 达到 `offline_tested` 并关闭。新增内容寻址的 `AssetDiscoveryAuthorization`、typed
selector/query Plan、`DiscoveredAsset`、归属 Evidence、三态 Admission Decision、`AuthorizedAsset` 和 Outcome。
授权模式区分 exact assignment、entity bound、platform category 与 supply-chain-with-approval；查询只接受由当前
Scope 和权威材料摘要派生的 domain、exact host 或 ICP selector，不接受自由 FOFA DSL。FOFA、Quake、Shodan、
被动 DNS、证书透明度、ICP registry 和 operator import 被建模为可信 Control Plane Adapter 来源，Plan、Worker
和模型协议均没有平台 token 字段。

确定性 reducer 允许原 Scope 的精确 scheme/host/port、授权根域加匹配归属证据、授权 ICP 或操作员资产清单自动
准入；纯证书、官方链接或产品指纹不足以证明归属，只进入 `approval_required`。每个完成的来源查询保存独立、已
校验且不含 raw response 的 checkpoint，多来源恢复不会重复查询已经完成的来源。明确排除后缀、跨独立法人和 exact
assignment 外资产拒绝，供应链关联资产固定待报备。完成事务只原子发布 admitted `AuthorizedAsset`；它只授予后续
Target materialization 资格，仍固定 `active_testing_authorized=false` 和 `finding_authorized=false`。离线 fake
覆盖成功、拒绝、待审批、预算、Scope/selector 漂移、查询注入、端口扩权、中断、三次恢复、超时、cleanup/凭据
边界与无部分发布。本轮没有访问公网、调用真实测绘 API、使用真实 token、调用模型或执行攻击。下一项为 B4.1。
最终全量门禁为 1685 passed、43 skipped、85.43% coverage；498 份 schema、Ruff 和 diff check 通过。

进展记录（2026-09-23）：B4.1 达到 `offline_tested` 并关闭。领域词汇表明确区分 `Test Identity`、
`Credential Reference` 与 `Test Identity Admission`。新增内容寻址、无秘密的 Record/Plan/Admission/Outcome/
Revocation：Record 绑定 custody proof、issuer、Scope/version、精确 Target、用途、opaque role 和有效期，且
`controlled_test_identity`、非第三方账号与无秘密材料由 schema 强制。Admission 只声明未来单次 Session 的资格，
credential access、authentication、Session、state change 和 third-party account 权限全部固定为 false；所有用途
声明后续需要 `USE_REAL_CREDENTIALS` Approval，state-change 额外需要 `MUTATE_TARGET_STATE` Approval。

SQLite Registry/ledger 覆盖内容冲突、原子发布、幂等、STARTED、三次恢复、超时和无部分 Admission；digest-only
撤销只收窄权限，`active_admission` 会重读 active Record、Scope、Target 和有效期，使已完成 Admission 在撤销后
立即失效。Outcome 证明未获取 credential material、未持久化秘密、未创建 Session 且 cleanup complete。离线回归
覆盖成功、Scope/Target/用途/角色拒绝、第三方账号与权限升级 schema 拒绝、撤销、过期、漂移、超时、恢复和存储
冲突。本轮没有 Vault adapter、真实凭据、登录请求、网络、模型调用或状态变更。下一项为 B4.2。
最终全量门禁为 1694 passed、43 skipped、85.45% coverage；505 份 schema、Ruff 和 diff check 通过。
