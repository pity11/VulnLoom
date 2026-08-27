---
status: accepted
---

# 分离可信控制面与不可信 Worker

VulnLoom 将状态机、Scope、策略、预算和人工审批放在 Control Plane，把 LLM 和工具执行放进不可信 Worker。虽然同进程 Agent 更容易开发，但无法可靠隔离提示注入、恶意仓库和工具副作用；分离后 Worker 只能通过 Tool Broker 请求有限能力，代价是增加协议和 Runner 的实现成本。
