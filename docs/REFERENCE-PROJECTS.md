# 参考项目映射

## ctf-agents

来源：`https://gitee.a101e.lab/huangwei/ctf-agents`。初始设计分析基线 `d2b90b5`；Phase 0 实现前复核基线 `56df053`（2026-08-27）。仓库未发现许可证文件，因此只借鉴设计，不复制代码。

### 继承

- 平台无关领域协议和 adapter 边界。
- Orchestrator 独占平台写操作和 token。
- 一个主 lane、有限 side lane 的轻并行结构。
- 长任务 checkpoint 与 resume。
- `solved/candidate/partial/impossible` 式结构化回收。
- 成功后再启动离线报告 lane。

### 不直接继承

- 工作目录不等于 Sandbox。
- 子 Agent 不应获得任何可执行提交的 write handle。
- 附件不能直接使用无成员策略的 `extractall()`。
- CTF 的“flag 验证”不能直接映射为真实漏洞成立；Finding 需要更严格的证据和反证门禁。

## my-pi-agent

来源：`https://gitee.a101e.lab/huangwei/my-pi-agent`。初始设计分析基线 `229b762`；Phase 0 实现前复核基线 `570b03a`（2026-08-27，MIT）。

### 继承

- `single/parallel/chain` 的任务表达。
- 子任务 JSON 事件流、用量统计和渐进更新。
- 每个 Agent 的工具 allowlist 和模型 fallback。
- 工具调用前代码门禁，而不是仅靠提示词。
- SQLite+FTS5 的可检索任务摘要。
- 自动续跑预算和防无限循环设计。

### 不直接继承

- 普通子进程不是安全边界。
- 子 Agent 不能继承完整 `process.env`。
- Build 模式不能等价于无限制执行。
- 浏览器在容器中运行仍需目标网络 allowlist、身份隔离和副作用门禁。
- FTS 不应索引原始工具参数、Cookie、token 或完整错误响应。
- 仅通过工具名称正则判断副作用不够，工具能力必须由注册表和 policy schema 定义。

## 其他开源项目

### Shannon

借鉴源码预侦察、攻击面建模、并行专用 Agent 和动态复现；不把官方演示成功率当作本地精度保证。

### Vulnhuntr

借鉴按需跨文件上下文获取、沿调用链补全证据和漏洞类别化；首期 Python Web 方向与其最接近。

M2 具体继承的是“先定位入口和危险点，再补跨文件路径”的工作方式；实现采用 VulnLoom 自有类型化 `SourceGraph`，没有复制其 Agent 或提示词代码。

M3 延续其“围绕一条可解释调用链形成假设”的思路，但 Candidate 合并、CWE 映射、反证任务、
重复指纹和 Scope 绑定均由 VulnLoom 的确定性代码完成，不依赖模型自由文本。

### Semgrep

作为成熟规则引擎的可选 adapter，复用其规则生态和 JSON 输出，而不是自研全部模式匹配。VulnLoom 只允许预注册本地规则、关闭联网功能、限制资源，并把命中降级为 `StaticSignal`。

### Strix

借鉴浏览器、代理、代码与动态工具的协作，以及以验证结果生成报告；其主动测试能力只应放进 Validation Sandbox。

M4.1 只继承“工具必须通过隔离边界”的架构方向；Profile、Runner、checkpoint 和 typed
invocation 协议为 VulnLoom 自有实现，尚未复用或声称具备 Strix 的动态执行能力。

M4.2 继续采用窄工具面思想，但 Registry digest 绑定、三重 allowlist、opaque body/credential
引用、逐跳 Policy/DNS/IP 判定和离线 transport 均为 VulnLoom 自有实现，没有复制其网络工具。

M4.4 延续“验证结果驱动报告”的分层方向，但明确拆开执行完成与漏洞裁决：事务性 checkpoint、
Candidate 状态变化、Evidence 子集校验和默认 `INCONCLUSIVE` judge 均由 VulnLoom 的可信领域层实现。

M4.5 继续只借鉴动态复现的工作流目标；精确状态/正文摘要断言、预执行内容寻址绑定、Evidence
完整性复核与 mismatch 固定 `INCONCLUSIVE` 是 VulnLoom 自有的确定性安全边界。

### PentAGI

借鉴长期任务、记忆、可观测性和多模型支持；不在 MVP 中引入其完整重型平台。

## 设计归纳

VulnLoom 不 Fork 上述任一项目。它把参考能力收敛为四个可替换边界：

```text
Domain Workflow
    + Agent Runtime
    + Tool/Sandbox Broker
    + Evidence/Reporting
```

这样既能更换 LLM 和分析器，也能在不改领域状态机的情况下把 rootless Docker 升级为 gVisor 或 Firecracker。
