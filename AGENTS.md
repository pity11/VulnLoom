# AGENTS.md

本仓库用于开发授权漏洞研究系统。任何编码 Agent 在修改代码前必须遵守以下约束。

## 不可破坏的安全不变量

1. 不得增加面向未授权公网目标的扫描、利用或自动提交能力。
2. Worker 不得继承父进程的完整环境变量；环境必须从显式白名单构造。
3. Worker 不得直接获得披露平台 token、模型 provider token 或宿主 Docker socket。
4. 所有状态变更测试、外部回连和 Submission 必须经过 Approval Gate。
5. `Candidate` 不得绕过验证与反证流程直接写为 `Finding`。
6. 所有归档解压必须验证归一化路径、符号链接、文件数量、单文件大小和总展开大小。
7. 任何工具权限必须在 Tool Broker 或 Sandbox 边界代码中强制执行；提示词不是安全边界。
8. 原始凭据、Cookie、个人信息和完整认证响应不得进入普通日志、FTS 索引或模型上下文。

## 工程规则

- 先实现显式状态机和类型化协议，再接入 LLM。
- 领域状态变化由纯函数或事务性服务完成，不由 Agent 文本触发。
- 每个外部系统通过 adapter 接入；领域层不依赖 Docker、模型 SDK 或披露平台。
- Runner、Broker、Policy Engine 和 Evidence Store 必须支持离线单元测试。
- 网络集成测试默认关闭，仅在显式标记和隔离环境中运行。
- 失败采用 fail-closed：无法判断 Scope、策略或目标地址时拒绝执行。
- 观察性组件可以 fail-open，但不得影响安全判定，也不得记录未脱敏内容。
- 重要工作流写 checkpoint；重试必须幂等并有上限。

## 开发顺序

1. 领域模型和状态机。
2. Scope/Policy Engine。
3. Evidence Store 与脱敏。
4. 本地静态分析纵切。
5. 临时 Docker Runner 与 Tool Broker。
6. 动态 Validation Run。
7. Critic 与报告生成。
8. 基准评测和回归门禁。

## 完成标准

一个功能只有同时具备成功路径、拒绝路径、超时路径、清理路径和安全回归测试时才算完成。任何声称“已隔离”的功能必须由实际容器、进程和网络配置测试证明，而不是由文档或提示词证明。
