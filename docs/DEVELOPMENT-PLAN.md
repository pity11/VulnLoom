# VulnLoom 当前开发总纲

状态：`ACTIVE`

更新日期：`2026-09-21`

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
   Action 必须重新封存、预算、策略判定和必要 Approval；不得动态扩展 Target；
2. **B2 Web/API 只读面深化**：针对已明确列出的路径增加类型化 HTTP、OpenAPI/GraphQL 等观察 adapter；仍不加入
   crawler、字典枚举、CIDR/端口扫描或任意请求脚本；
3. **B3 漏洞类别纵切**：按版本化 Evidence Requirement 逐类实现正例、负例、最小 Validation、Critic 和 Cleanup，
   优先低影响 Web/API 类别；Scanner 命中只能形成 Signal/Candidate；
4. **B4 测试身份与业务流程**：只使用控制方测试身份和 opaque reference；登录、角色和状态变化分别经过 Vault、
   Session 隔离与 Approval，不测试真实第三方账户；
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
`production_safe` 动作，默认只读、低速、固定窗口和熔断。新发现资产只能记录为 `DiscoveredAsset`，不能自动
升级为可执行目标。

## 8. 共享控制面后续

- **Provider Center**：下一步是权限受限的凭据替换 adapter 和复用相同应用服务的薄 HTTP API；Web UI 后置。
  CUC/DeepSeek 保持前期默认路由，真实外部调用仍逐次要求明确授权；
- **CLI/API 合同**：CLI 和未来 API 必须调用同一应用服务，不能通过表面层绕过状态机；
- **质量与能力状态**：统一使用 `designed`、`offline_tested`、`isolated_integration_tested`、`lab_admitted`、
  `authorized_pilot`、`production_supported`，不把组件测试写成产品入口完成；
- **Web UI**：等应用服务和稳定 API 合同完成后再开发，不在当前阶段提前实现。

## 9. 明确延后

- 公网资产自主发现、Crawler、字典枚举和未封存路径探索；
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

当前下一项工作固定为 **A1 通用 Project Recipe Registry**。Shared Assurance S1 已关闭；只有出现新的用户优先级
决定，才从其他里程碑开始。

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
