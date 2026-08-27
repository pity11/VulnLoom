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

## 发现与验证

**Signal**：
静态工具、代码索引、运行日志或人工观察产生的原始安全线索，不带漏洞成立的承诺。
_Avoid_: Finding, Vulnerability

**Candidate**：
由一个或多个 Signal 支撑、具有漏洞类型、入口、危险点和前置条件的待证伪假设。
_Avoid_: Finding, Confirmed bug

**Validation Run**：
在确定版本、确定沙盒和确定策略下，对一个 Candidate 进行的一次可重复实验。
_Avoid_: Exploit, Attack

**Finding**：
通过规定验证门禁、具备可追溯证据且未被 Critic 证伪的安全缺陷。
_Avoid_: Candidate, Model conclusion

**Duplicate Family**：
共享同一根因、修复点或安全不变量的一组 Candidate 或 Finding。
_Avoid_: Same payload

## 证据与披露

**Evidence**：
支持或反驳 Candidate 的不可变事实记录，包括代码定位、请求响应、日志、截图和回归测试结果。
_Avoid_: Agent narrative, Chain of thought

**Evidence Bundle**：
围绕一个 Candidate 或 Finding 组织的、带哈希和来源信息的 Evidence 集合。
_Avoid_: Workspace, Chat history

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
