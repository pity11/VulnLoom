# VulnLoom

VulnLoom 是一个面向**明确授权目标**的漏洞研究 Agent：从源码、接口和云原生配置中生成候选，经过隔离环境中的动态验证与独立反证，最终形成可审计、可人工复核的漏洞报告草稿。

它的首要目标不是“自主打站”，而是提高白盒漏洞研究的召回率、证据质量和报告效率，同时把授权范围、网络边界、凭据隔离与人工审批固化在系统中。

## 首期范围

- Python Web/API 项目的白盒分析。
- 本地 Docker Compose 测试环境中的受控动态验证。
- IDOR/BOLA、SSRF、路径穿越、注入、反序列化、鉴权与敏感信息暴露。
- 生成适合厂商、EduSRC、CNVD/CNNVD 等渠道进一步人工整理的报告草稿。
- 不扫描未授权公网目标，不自动提交平台，不自动申请 CVE。

## 核心原则

1. **Candidate 不是 Finding**：模型只能提出候选，动态证据和反证门禁通过后才能成为 Finding。
2. **控制面独占权限**：子 Agent 不持有平台凭据，不直接改变授权范围，也不直接提交报告。
3. **每次验证使用临时沙盒**：验证结束即销毁；源码只读、输出单独保存、网络默认拒绝。
4. **工具调用经过 Broker**：Agent 获得的是有类型、有限权、可审计的能力，不是任意宿主 Shell。
5. **证据先于叙述**：报告中的每个影响结论都必须追溯到代码、请求响应或可重复测试。
6. **人工批准不可省略**：状态变更测试、外部回连和报告提交都需要人工审批。

## 文档入口

- [CONTEXT.md](./CONTEXT.md)：领域术语与统一语言。
- [AGENTS.md](./AGENTS.md)：后续使用编码 Agent 开发时必须遵守的工程约束。
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)：系统分层、组件与部署拓扑。
- [docs/WORKFLOW.md](./docs/WORKFLOW.md)：Agent 编排、状态机与裁决规则。
- [docs/SECURITY.md](./docs/SECURITY.md)：沙盒、网络、凭据、附件与证据安全。
- [docs/DATA-MODEL.md](./docs/DATA-MODEL.md)：核心实体和事件模型。
- [docs/ROADMAP.md](./docs/ROADMAP.md)：分阶段开发计划与验收指标。
- [docs/REFERENCE-PROJECTS.md](./docs/REFERENCE-PROJECTS.md)：参考项目的继承点与避坑项。

## 建议代码布局

```text
VulnLoom/
├── apps/                   # CLI/API 等入口，首期只实现 CLI
├── src/vulnloom/
│   ├── domain/             # 领域对象、状态机、策略
│   ├── orchestrator/       # DAG 调度、预算、裁决、人工门禁
│   ├── agents/             # Agent 角色定义与结构化输出协议
│   ├── broker/             # 有类型的工具代理与权限检查
│   ├── runners/            # Docker/rootless sandbox runner
│   ├── analyzers/          # Semgrep、AST、CodeQL 等适配器
│   ├── validators/         # HTTP/browser/测试脚本验证器
│   ├── evidence/           # 脱敏、哈希、证据索引
│   ├── reporting/          # 报告模板与导出器
│   └── adapters/           # 目标、模型和披露渠道适配器
├── policies/               # scope、网络、工具与资源策略
├── prompts/                # 版本化提示词
├── schemas/                # JSON Schema/Pydantic schema
├── sandboxes/              # 镜像与运行配置
├── benchmarks/             # 靶场、ground truth、评测脚本
├── tests/
└── docs/
```

## 第一条可运行纵切

首个里程碑应只完成一条窄链路：

```text
授权清单
→ 导入一个 Python Web 仓库
→ 静态工具产生候选
→ Source Mapper 补全调用链
→ 人工选择一个 Candidate
→ Docker 中启动测试应用并验证
→ Critic 反证
→ 生成 Markdown 报告草稿
```

在这条链路的精确率、隔离和证据留存没有达标前，不扩展公网资产发现、自动提交或通用自主 Shell。

## 当前实现

Phase 0 已具备第一版可运行骨架：

- 不可变 Pydantic 领域模型与 JSON Schema。
- 分离的 Candidate 状态机和 Candidate → Finding 确定性门禁。
- Scope Policy Engine 与绑定具体动作摘要的 Approval。
- Evidence 脱敏、内容寻址和完整性检查。
- SQLite 事件日志与幂等冲突检测。
- Control Plane/Worker 类型化协议和显式 Worker 环境白名单。
- `engagement-create`、`scope-approve` 和 `status` CLI。
- OpenAI-compatible 模型 provider 配置边界；尚未发起网络模型调用。

### 本地开发

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest --cov=vulnloom --cov-report=term-missing
.venv/bin/python scripts/export_schemas.py
```

### 模型密钥边界

模型 API Key 通过 `ModelProviderConfig.api_key_env` 在 Control Plane 请求前解析。密钥不出现在 `TaskEnvelope`、Worker 环境、事件日志或 Evidence 摘要中。`.env.example` 只列变量名，真实 `.env` 已被 Git 忽略。
