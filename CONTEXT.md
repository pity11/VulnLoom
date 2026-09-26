# VulnLoom 漏洞研究上下文

本上下文定义从授权目标到可提交漏洞报告的统一语言。它刻意区分模型生成的判断、经过验证的安全事实和最终披露材料。

## 授权与目标

**Engagement**：
一次有明确授权方、目标、时间窗和测试约束的漏洞研究活动。
_Avoid_: Project, Scan

**Scope**：
某个 Engagement 内允许访问的仓库、域名、服务、身份、测试类型和时间边界。
_Avoid_: Target list, Prompt instruction

**Target**：
Scope 中一个可独立标识和版本化的被测对象，例如仓库提交、容器镜像或测试服务。
_Avoid_: Host, Victim

**Test Identity**：
由控制方或目标授权方专门提供、仅用于当前授权测试的主体；它不是第三方真实用户，也不包含用户名、密码、Cookie 或 Token。
_Avoid_: Account, User, Credential

**Credential Reference**：
Control Plane 用于让可信 Vault/Broker 边界定位 Test Identity 秘密材料的内容寻址 opaque 引用；它不是秘密本身，也不向 Worker 或模型提供解析能力。
_Avoid_: Password, Token, Vault path

**Test Identity Admission**：
将一个 Test Identity 限定到精确 Scope 版本、Target、用途、角色和时间窗的不可变准入决定；它不授予凭据读取、登录、Session 或状态变更权限。
_Avoid_: Login permission, Session, Credential grant

**Credential Lease**：
可信 Control Plane 在 Test Identity Admission 与精确 Action Approval 均有效后，从 Vault 取得的一次性短期秘密租约；租约不可序列化、不可交给 Worker 或模型，结束、拒绝和超时路径都必须清零。
_Avoid_: Credential, Token, Secret record

**Isolated Test Session**：
绑定一个 Test Identity、Target、角色、用途、Action digest 和单次 Credential Lease 的短生命周期执行边界；Session receipt 只证明隔离、使用次数和清理，不保存认证材料，也不自行授权网络、登录或状态变化。
_Avoid_: Login state, Cookie jar, Browser profile

**Local Authentication Observation**：
受控 Test Identity 在明确的本地隔离环境中完成认证并对一个精确动作得到允许或拒绝结果的无秘密事实；它不是生产目标登录证明，也不包含认证响应或 Session 材料。
_Avoid_: Login result, Auth response, Session token

**Session Logout Proof**：
证明一次 Isolated Test Session 已释放、材料已清零且不可再次使用的不可变事实；它证明清理，不证明目标端全局会话状态。
_Avoid_: Logout response, Cookie deletion, Account state

**Role Differential Observation**：
两个不同受控 Test Identity 在同一隔离环境中对同一精确动作所得访问决定的类型化比较；差异本身只是 Signal，不自动构成 Candidate、Finding 或漏洞结论。
_Avoid_: Privilege escalation, Authorization vulnerability, Finding

**Business Flow Invariant**：
对一个版本化业务流程在变更前、变更后和恢复后状态关系的类型化约束；违反约束只形成 Signal，不自动构成 Candidate、Finding 或漏洞结论。
_Avoid_: Vulnerability rule, Agent judgment, Finding

**Controlled State Mutation**：
由精确 Scope、Target、Test Identity、Action digest 和双 Approval 共同约束的一次性测试状态转换；它必须绑定恢复义务，不能扩展为任意目标写操作。
_Avoid_: Write access, Exploit, Unbounded workflow action

**State Restoration Proof**：
证明一次 Controlled State Mutation 已通过补偿动作恢复到变更前语义状态、同时保持修订序列单调递增的不可变事实；它不证明生产目标或外部系统已回滚。
_Avoid_: Transaction rollback, Cleanup attempt, Production recovery

**Replan Execution Receipt**：
证明一个由 Observation 驱动的下一步已被 Control Plane 重新封存、获得精确 Approval、产生权威 Observation 并完成清理的不可变事实；它不授予再次执行或后续动作权限。
_Avoid_: Action token, Replay permission, Agent claim

**Adaptive Flow Trace**：
同一 Scope 和 Target 内，至少两个按 checkpoint 顺序衔接的 Replan Execution Receipt 所组成的有限事实链；每一轮必须消费前序 Observation，且不能扩展目标或遗留未清理工作。
_Avoid_: Agent transcript, Campaign, Free-form plan

**Coverage Ledger**：
对一个已完成研究流程实际覆盖的动作类别、测试类别、Observation 和清理状态所作的内容寻址事实投影；它不表示未覆盖部分安全，也不授予新增测试。
_Avoid_: Security score, Scan completeness, Action budget

**Adaptive Flow Qualification**：
Control Plane 对一条权威 Adaptive Flow Trace 是否达到 A3 多轮自适应要求所作的限域资格决定；它不是 A4 Campaign 资格，也不是执行权限。
_Avoid_: Autonomy grant, Campaign admission, Model capability claim

**Runtime Isolation Evidence**：
可信控制面从实际短生命周期容器取得的内容寻址事实，证明精确镜像、Sandbox Profile、调用、硬化边界、终态和资源清理；模拟结果、配置声明和提示词不能成为该证据。
_Avoid_: Sandbox configuration, Unit-test fixture, Isolation claim

**Adaptive Runtime Qualification**：
把既有 Adaptive Flow Qualification、共享隔离准入合同与该流程专属 Runtime Isolation Evidence 扇入后形成的 A3 运行资格；它不授予动作执行权，也不构成 A4 Campaign 资格或生产环境准入。
_Avoid_: Runtime permission, Production admission, Campaign qualification

**Campaign Goal**：
一次授权研究 Campaign 希望获得的有限、内容寻址 Evidence 条件；它约束“证明什么”，不描述命令、载荷或如何执行。
_Avoid_: Free-form objective, Agent prompt, Attack command

**Campaign Phase Graph**：
把 Campaign 拆成有限、有向无环阶段及其预算、前置阶段和人工转换门禁的封存结构；运行时不得增加阶段、目标或预算。
_Avoid_: Agent plan, Dynamic queue, Execution trace

**Goal-driven Campaign Qualification**：
Control Plane 对多个已完成 A3 Runtime Qualification、Campaign Goal、目标集合、阶段图和停止条件所作的 A4 结构资格决定；它不启动 Campaign，也不授予任何动作、网络、凭据或 Submission 权限。
_Avoid_: Campaign run, Autonomous execution, Blanket approval

**Campaign Phase Admission**：
操作员对封存 Campaign 中一个精确阶段转换作出的一次性、内容绑定决定；它只允许该阶段进入隔离资格运行，不授予阶段内动作、网络、凭据或目标扩展权限。
_Avoid_: Campaign approval, Action approval, Execution token

**Campaign Runtime Qualification**：
Control Plane 依据实际隔离阶段运行、预算停止、超时回收与完整清理事实，对一份既有 Goal-driven Campaign Qualification 作出的 A4 运行边界资格；它仍不启动真实 Campaign 或授予攻击执行权。
_Avoid_: Campaign execution, Production authorization, Autonomous attack

**Artifact**：
进入 quarantine 的原始研究输入，以内容摘要唯一标识；它尚未获得可分析、可执行或属于 Scope 的承诺。
_Avoid_: Target, Workspace, Attachment

**Target Snapshot**：
从已授权 Artifact 或固定 Git commit 生成的不可变、带 Manifest 的只读目标视图。
_Avoid_: Repository, Extraction Directory, Working Copy

**Target Manifest**：
描述 Target Snapshot 中每个文件的归一化路径、大小、内容摘要和静态类别的不可变清单。
_Avoid_: File listing, Agent summary

## 发现与验证

**Signal**：
静态工具、代码索引、运行日志或人工观察产生的原始安全线索，不带漏洞成立的承诺。
_Avoid_: Finding, Vulnerability

**Candidate**：
由一个或多个 Signal 支撑、具有漏洞类型、入口、危险点和前置条件的待证伪假设。
_Avoid_: Finding, Confirmed bug

**Candidate Recommendation**：
模型针对一个既有 Candidate 生成的优先级和人工复核建议；它不能创建或修改 Candidate，也不能直接进入 Validation Run。
_Avoid_: Candidate Draft, Model Finding, Auto-selected Candidate

**Validation Run**：
在确定版本、确定沙盒和确定策略下，对一个 Candidate 进行的一次可重复实验。
_Avoid_: Exploit, Attack

**Finding**：
通过规定验证门禁、具备可追溯证据且未被 Critic 证伪的安全缺陷。
_Avoid_: Candidate, Model conclusion

**Duplicate Family**：
共享同一根因、修复点或安全不变量的一组 Candidate 或 Finding。
_Avoid_: Same payload

**Crash Signature**：
由 sanitizer、故障类别和去地址化的稳定栈帧构成的内容寻址崩溃身份；触发输入和原始日志不属于身份。
_Avoid_: Crash log hash, Input hash, Process address

**Proof of Vulnerability (PoV)**：
绑定触发输入摘要与 Crash Signature、并在独立无网络沙盒中重复得到同一签名的最小复现证据。
_Avoid_: Fuzzer finding, Crash input, Unverified reproducer

## 证据与披露

**Evidence**：
支持或反驳 Candidate 的不可变事实记录，包括代码定位、请求响应、日志、截图和回归测试结果。
_Avoid_: Agent narrative, Chain of thought

**Evidence Bundle**：
围绕一个 Candidate 或 Finding 组织的、带哈希和来源信息的 Evidence 集合。
_Avoid_: Workspace, Chat history

**Service Identity**：
在已授权端点上经 CA、hostname 与固定网络 peer 校验后得到的 TLS 会话身份摘要；它不包含证书原文、主体或 SAN 文本。
_Avoid_: Banner, Raw certificate, Service fingerprint

**Attack Surface Drift**：
同一授权 Target 的两份已封存 Attack Surface Inventory 之间、可回溯到 Evidence 的事实差异；它不表示漏洞已经成立。
_Avoid_: Finding, Vulnerability, Model assessment

**Endpoint Seed Set**：
由操作员封存、绑定精确 Flow checkpoint 和 Scope 版本的有限规范路径集合；它不是 crawler、字典或资产发现输入。
_Avoid_: Crawl frontier, Wordlist, Discovered URLs

**OpenAPI Discovery Promotion**：
操作员把已封存 OpenAPI Observation 中明确选中的 path discovery 具体化并重新封存为 Endpoint Seed Set 的决定；它只赋予 seed 资格，不授予请求执行权或 Target 扩展权。
_Avoid_: Auto-enrollment, Crawl expansion, Executable discovery

**GraphQL Schema Observation**：
从权威、已脱敏的 GraphQL SDL Evidence 生成的内容寻址 schema 摘要；它描述 query field，不代表已执行 introspection、operation 或漏洞验证。
_Avoid_: Introspection run, Executable query, GraphQL Finding

**Vulnerability Evidence Requirement**：
某一漏洞类别的版本化判定合同，定义 Candidate 资格所需的正证据、独立复核、反证和清理证明；它不是扫描规则，也不授予测试或 Finding 权限。
_Avoid_: Exploit recipe, Scanner signature, Finding template

**Evidence Assessment**：
把一组脱敏 Evidence Assertion 对照一个 Vulnerability Evidence Requirement 得到的内容寻址结论；结论只能是 Candidate 资格、负例或不确定，不能直接成为 Finding。
_Avoid_: Vulnerability confirmation, Auto-promotion, Model verdict

**Evidence Assertion Materialization**：
可信控制面从权威 Observation 和已脱敏 Evidence 生成有限 Evidence Assertion 的过程；它证明来源与结构事实，不替代独立 Validation 或 Critic。
_Avoid_: Finding extraction, Self-validation, Exploit result

**Independent Replay Validation**：
对两个不同执行上下文产生的权威 Evidence Assertion Materialization 做同端点、同 Scope 的确定性一致性复核；它只生成 Validation Assertion，不执行请求或替代 Critic。
_Avoid_: Automatic retest, Same-run replay, Vulnerability confirmation

**Critic Assertion Materialization**：
把一份完整、类型化且 Evidence 与 Validation 分离的反证审查结论物化为 Critic Assertion；它不执行审查或测试，也不批准 Candidate 或 Finding。
_Avoid_: Automated critic, Candidate approval, Finding confirmation

**Campaign Orchestration Run**：
在固定 Scope、Target 集和六阶段图内，由 Control Plane 按精确阶段 Approval 推进并持久化 checkpoint 的一次有限运行；阶段准入不授予阶段内 Action 权限。
_Avoid_: Agent loop, Autonomous attack, Phase qualification

**Campaign Evidence Closure**：
Campaign 完成 Observation、Validation、独立 Critic 与 Cleanup 后，对一份权威 Evidence Assessment 做出的内容寻址终态；它可以明确记录未解决、反证成立或不确定，但不是 Finding。
_Avoid_: Vulnerability confirmation, Finding promotion, Model verdict

**Unresolved Campaign Candidate**：
Evidence 已满足 Candidate 提议资格、但尚未创建 Candidate 且未经过 Candidate 生命周期与 Finding 晋升门禁的 Campaign 终态。
_Avoid_: Candidate, Finding, Confirmed vulnerability

**Campaign Candidate**：
由人工批准的 Campaign Candidate Intake 从一个 unresolved Campaign Evidence Closure 原子创建的 Web/API Candidate；它以 `PROPOSED` 进入独立 Validation 与 Critic 生命周期，不伪造源码位置，也不继承 Finding 权限。
_Avoid_: Source Candidate, Evidence closure, Confirmed vulnerability

**Campaign Candidate Intake**：
把一个精确 unresolved Campaign Evidence Closure 封存为 Candidate 创建计划并交由人工 Approval 决定的门禁；拒绝、超时或中断不得留下部分 Candidate。
_Avoid_: Automatic promotion, Finding intake, Agent decision

**Campaign Candidate Lifecycle Checkpoint**：
记录 Campaign Candidate 当前权威生命周期状态及其前序状态的内容寻址事实；不可变 Candidate 快照只证明创建时为 `PROPOSED`，不能替代生命周期推进记录。
_Avoid_: Mutable candidate, Worker state, Agent memory

**Campaign Candidate Validation Intake**：
将一个仍为 `PROPOSED` 的 Campaign Candidate 与全新 Validation 要求封存，并经精确人工 Approval 推进到 `VALIDATION_PENDING` 的门禁；它不执行 Validation，也不复用 Campaign 前置 Evidence 作为 ValidationRun。
_Avoid_: Validation run, Evidence replay, Automatic queue

**Campaign Candidate Validation Execution**：
对一个已进入 `VALIDATION_PENDING` 的 Campaign Candidate，在精确 `RUN_VALIDATION` Approval 下执行两次相互独立、无网络且候选绑定的验证，并由 Control Plane 判定是否推进到 `VALIDATED`；它不能完成 Critic 或创建 Finding。
_Avoid_: Validation intake, Worker verdict, Finding promotion

**Fresh Validation Evidence**：
由当前 Campaign Candidate 的独立 Validation Execution 新产生、绑定同一 validation context 且不与 Campaign 前置 Evidence 重合的脱敏事实集合；旧 Evidence、单次输出或 Worker 声明都不能替代它。
_Avoid_: Campaign evidence, Reused evidence, Worker claim

**Endpoint Recon Plan**：
从一个 Endpoint Seed Set 确定性生成的有预算只读计划，每个 seed 恰好对应一次禁重定向的 HEAD 步骤。
_Avoid_: Crawler plan, Scan campaign, Dynamic queue

**Endpoint Recon Reservation**：
Endpoint Recon Plan 在一个精确 Flow checkpoint 上占用的动作预算；取消或过期只释放未消费部分，已进入 Flow 账本的动作不可回退。
_Avoid_: Request estimate, Retry counter, Reversible action

**Endpoint Check Schedule**：
由操作员封存、在固定授权窗口内周期性物化新 Flow 的精确 Endpoint 检查模板；它是 Control Plane 触发器，不直接执行工具或网络请求。
_Avoid_: Cron scanner, Background crawler, Long-running Flow

**Attack Graph**：
在一份有效 Rules of Engagement 内，由操作员封存的有限有向无环动作图；每个节点绑定精确目标、前置节点、影响类别和独立 Approval，运行时不得增加节点或目标。
_Avoid_: Agent plan, Exploit queue, Autonomous campaign

**Attack Objective**：
一次授权红队活动允许证明的有限目标，以及达到该目标所需的脱敏 Evidence 条件；它不授权横向移动、持久化或真实数据外传。
_Avoid_: Free-form goal, Shell access, Compromise

**Attack Action**：
Attack Graph 中一个内容寻址、可单独批准和审计的原子动作；对其他节点的批准不能授权它。
_Avoid_: Agent step, Command, Payload

**Attack Chain Cleanup**：
Attack Graph 中用于撤销链内测试状态的最终原子动作；目标 Evidence 已获得但 Cleanup 未成功时，攻击目标仍不算完成。
_Avoid_: Best-effort teardown, Process exit, Manual follow-up

**Attack Path Report**：
从已完成且已清理的 Attack Chain 及其脱敏 Evidence 确定性生成的防御侧事实投影；它不晋升 Candidate/Finding，也不授权新动作。
_Avoid_: Exploit write-up, Finding, Agent narrative

**Detection Opportunity**：
Attack Path 中一个可由防御方观测的 Evidence 绑定点；它表示应当具备的检测位置，不声称现有遥测已经覆盖。
_Avoid_: Detection finding, Alert, Coverage claim

**Defensive Improvement**：
由 Detection Opportunity 确定性关联的有限控制改进类别；它不是自动修复或未经验证的自由文本建议。
_Avoid_: Patch, Remediation execution, Model recommendation

**Deployment Proof**：
将一个不可变源码版本和构建产物绑定到一个精确 Live Endpoint 摘要的限时脱敏证明。
_Avoid_: Deployment claim, Raw release metadata, Endpoint URL

**Live Endpoint Reference**：
Control Plane 用于定位权限受限本地 endpoint 配置的 opaque 引用；它不是 URL，也不向 Worker、普通 API 或审计投影暴露解析值。
_Avoid_: Endpoint URL, Target string, Worker configuration

**Hybrid Evidence Chain**：
把源码路径、Deployment Proof 和精确 Live Validation 的 Evidence 封存为同一条可追溯事实链；修复复测通过引用前一条链表达版本演进。
_Avoid_: Correlation guess, Combined report, Agent conclusion

**Source Remediation Proof**：
修复版本在独立、无网络的源码回归 Validation 中得到 `not_reproduced` 结论后封存的内容寻址证明；执行失败、没有新 Candidate 或 Live 复测单独通过都不能替代它。
_Avoid_: Missing signal, Build success, Live-only retest

**Hybrid Release Gate**：
针对一条已知 Hybrid 缺陷链的发布资格判断；只有当前部署版本的源码和 Live 双重复测均已封存为修复事实时才通过，它不把“没有发现新线索”解释为安全。
_Avoid_: Clean scan, No findings, CI success

**Hybrid Finding**：
由已确认的 Hybrid Evidence Chain 支撑，并且 Critic 已针对该链的完整源码、部署和 HTTP Evidence Bundle 完成独立反证后，经人工 Approval 晋升的 Finding。
_Avoid_: Tagged Source Finding, Correlated Finding, Model-confirmed vulnerability

**Hybrid Report**：
由 Hybrid Finding 生成的本地 Report Draft；其代码位置、部署复现和请求响应章节分别引用同一 Hybrid Evidence Chain 中的源码、部署与 HTTP Evidence。
_Avoid_: Combined narrative, Correlation summary, Submitted report

**Report**：
基于 Finding 和脱敏 Evidence Bundle 生成的披露载体，可以有多个渠道和版本。
_Avoid_: Finding, Raw evidence

**Submission**：
人工批准后，将一个 Report 交付给指定披露渠道的外部动作。
_Avoid_: Export, Draft

**Product Identity**：
用于披露协调的产品身份，包括厂商、产品、组件和版本生态；它决定 Finding 是否适合进入 CVE 协调路径。
_Avoid_: Target, Website

**Disclosure Case**：
围绕一个 Finding 与厂商、CNA 或漏洞平台进行协调的记录，可关联多个渠道版本的 Report 和外部编号。
_Avoid_: Report, Submission, CVE

## 执行与治理

**Control Plane**：
拥有工作流状态、预算、策略判定和人工审批记录的可信协调边界。
_Avoid_: Main Agent

**Worker**：
在有限工具、有限数据和临时执行环境中完成单一职责的 Agent 运行实例。
_Avoid_: Trusted process, Orchestrator

**Tool Broker**：
将 Worker 的结构化工具请求转换为受策略约束的实际操作并记录证据的唯一通道。
_Avoid_: Shell wrapper

**Sandbox**：
为一次 Worker 或 Validation Run 创建的临时计算、文件系统和网络隔离环境。
_Avoid_: Working directory, Child process

**Approval Gate**：
必须由授权人员明确决定才能跨越的工作流边界。
_Avoid_: Model confirmation
