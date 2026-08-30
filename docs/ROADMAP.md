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

## Phase 2：受控动态验证

目标：在本地 Docker 测试应用中验证一个人工选择的 Candidate。

- rootless Docker Runner Service。
- Static/Validation/Report 三类 Sandbox Profile。
- Tool Broker、网络 allowlist 和资源预算。
- HTTP typed tool；后续再加入 browser tool。
- Evidence Bundle 和 Critic Worker。

验收：Worker 不能访问宿主密钥、其他容器和互联网；超时后没有残留容器、进程、网络和 volume。

## Phase 3：报告闭环

目标：把 Finding 转换为一致、脱敏、可人工提交的报告。

- 通用报告模板。
- EduSRC/CNVD/厂商字段映射。
- 证据一致性检查。
- 人工审阅界面或 CLI diff。
- 导出 Markdown/JSON，不联网提交。

验收：报告中的代码位置、请求响应和影响结论都能反向解析到 Evidence ID；凭据脱敏测试通过。

## Phase 4：评测与扩展

- 接入 BountyBench、AutoPenBench 和自建 ground truth。
- 指标：Candidate recall、验证后 precision、重复率、证据完整度、单 Finding 成本、运行时间和策略违规数。
- 增加 Agent/MCP 安全和本地云原生配置分析。
- 评估 CodeQL、Trivy、Checkov、Kubesec、Playwright。

## 延后事项

- 公网资产自主发现。
- 自动化漏洞平台提交。
- 自动申请 CVE。
- 通用任意 Shell。
- 多租户 SaaS。
- 直接连接生产 Kubernetes 集群。

这些能力会显著扩大授权、隔离和运维边界，不应在本地研究 MVP 中提前引入。
