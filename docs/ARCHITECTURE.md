# 架构设计

## 1. 架构目标

VulnLoom 采用可信控制面与不可信 Worker 分离的架构。LLM 输出、被测源码、网页内容、工具输出和附件都被视为不可信输入。只有 Control Plane 可以改变领域状态、批准权限和生成外部副作用。

## 2. 总体拓扑

```text
                           Human Console / CLI
                                   │
                                   ▼
┌──────────────────────────── Control Plane ────────────────────────────┐
│ Engagement + Scope │ Workflow │ Scheduler │ Budget │ Approval Ledger │
│ Policy Engine      │ Reducer  │ Adapter   │ Audit  │ Report Review    │
└───────────────┬──────────────────────┬──────────────────────┬─────────┘
                │ TaskEnvelope         │ ToolRequest          │ Event
                ▼                      ▼                      ▲
        ┌──────────────┐       ┌───────────────┐       ┌──────────────┐
        │ Agent Worker │──────▶│  Tool Broker  │──────▶│Evidence Store│
        └──────────────┘       └───────┬───────┘       └──────────────┘
                                      │
                       ┌──────────────┼──────────────┐
                       ▼              ▼              ▼
                 Static Sandbox  Validation     Report Sandbox
                 no network      target-only    no target network
```

## 3. Control Plane

### Workflow Engine

- 实现 `Candidate` 到 `Finding` 的显式状态机。
- 接收结构化 Worker 结果，通过确定性 reducer 产生下一状态。
- 拒绝缺少 Scope、版本、Evidence 或 Approval 的迁移。
- 所有命令带 `engagement_id`、`target_id`、`task_id` 和幂等键。

### Scheduler

- 支持 `single`、`parallel` 和 `chain`，但将它们表达成有类型 DAG。
- 每个 Target 同时最多一个主要分析 lane。
- 默认最多两个 side lane，全局 Worker 并发首期限制为四。
- 长任务保存 checkpoint；相同幂等键不能产生第二个 Validation Run。
- 每个任务有时间、token、请求次数和计算资源预算。

### Policy Engine

- 编译 Scope 为可执行策略：仓库、commit、地址、端口、身份、方法、速率和允许的测试等级。
- 工具调用前判定，而不是完成后审计。
- 域名解析后再次校验实际 IP，防止 DNS rebinding 和私网范围漂移。
- 策略不明确时 fail-closed。

### Approval Service

人工审批对象不是聊天文本，而是不可变 `ApprovalRequest`：包含请求动作、目标、预期副作用、证据摘要、过期时间和策略版本。批准只对该对象生效，不能泛化为后续动作。

## 4. Worker 角色

### Scope Interpreter

把授权材料转换成待人工确认的 Scope 草稿；它无权自行扩大范围。

### Source Mapper

构建路由、入口、身份、权限检查、数据流、危险点和部署配置之间的图。输出 `Signal`，不直接输出 Finding。

M2 的首版 mapper 只读取 M1 已验证的文件系统 Snapshot，并在读取时复核 Manifest。每次映射还会重新检查 Scope 有效期、Engagement、Artifact digest 或 Git commit，并把 Scope 身份和版本写入图。它使用标准库 AST，绝不 import 目标模块；跨文件调用解析和 taint 均设置深度、文件大小、总量与墙钟限制。完整 `SourceGraph` 内容寻址保存，事件流只写统计摘要。

### Recon Worker

只对测试环境进行低影响、只读表面收集，输出接口、技术栈和身份边界。

### Hypothesis Worker

把 Signal 合并为 Candidate，必须填写 CWE、入口、危险点、调用链、前置条件、最便宜的反证实验和预期安全不变量。

### Validator Worker

只处理一个 Candidate。通过 Tool Broker 在 Validation Sandbox 中运行有限实验，输出 Evidence Bundle 和复现结论。

### Critic Worker

与 Validator 使用独立上下文，优先寻找安全检查、不可达路径、环境特例、版本偏差和重复根因。它没有新增攻击面的任务权限。

M5.1 先实现不依赖 LLM 的可信确定性 reducer。封存的 `CriticPlan` 必须使用不同的验证/审查上下文与 producer，并完整覆盖安全控制、可达性、环境一致性和版本绑定。Critic 只读取已脱敏的本地 Evidence，不获得 Runner、Broker、网络或提交权限。反证成立时拒绝 Candidate，任一角度不确定时保持 `VALIDATED`，只有全部角度有 Evidence 支持地排除后才进入 `CRITIC_REVIEWED`。

### Reporter Worker

只接收 Finding 和脱敏 Evidence Bundle，生成报告草稿；不连接目标，不持有提交凭据。

M5.2 先由可信离线服务完成一致性门禁和确定性渲染。`ReportDraftPlan` 绑定 Finding、Candidate、Evidence Bundle、Scope 和逐节引用；代码位置、请求/响应、复现及影响结论均必须反向解析到 Bundle 内的 Evidence ID。服务只读取已脱敏 Evidence 并输出内容寻址的本地 Markdown/JSON，不向 Reporter 暴露 Evidence 正文、网络、披露凭据或状态提升权限。

M5.3 将人工决定建模为内容寻址的 ReviewPlan 与 ReviewCommand，而不是聊天文本。Control Plane 在决定前复核精确 Report/artifact/Evidence/Scope/Diff 绑定，并以事务 checkpoint 防止并发决定。批准记录带有效期；本地导出只接受完全匹配且仍有效的 `HUMAN_APPROVED` 记录。该 adapter 仍只写受控内容存储，不接受任意目标路径或外部 URL。

## 5. Tool Broker

Worker 不直接调用宿主 Shell。首期工具接口应保持狭窄：

- `source.read(path, line_range)`
- `source.search(query, path)`
- `analyzer.run(rule_set, target)`
- `http.request(method, scoped_url, headers_ref, body, limits)`
- `browser.action(session, typed_action)`
- `sandbox.exec(tool_id, args, cwd_ref, limits)`
- `evidence.capture(kind, source_ref, redaction_policy)`

`sandbox.exec` 只允许镜像中注册过的 `tool_id`，不接收一段任意 Shell 字符串。确有必要的实验脚本先作为 Artifact 保存、静态检查并经策略批准，再在沙盒中执行。

## 6. Adapter 边界

- `TargetAdapter`：Git 仓库、容器镜像、Docker Compose、测试 URL。
- `AnalyzerAdapter`：Semgrep、CodeQL、tree-sitter、Trivy 等。
- `ModelAdapter`：模型调用、结构化输出、成本和重试。
- `SandboxAdapter`：本地 rootless Docker；以后可替换为 gVisor/Firecracker。
- `DisclosureAdapter`：首期只负责把 Report 导出成渠道格式，不实现网络提交。

Semgrep adapter 只接受 Control Plane 预注册的本地规则集，不接受 Agent 提供任意配置路径；禁用 metrics 和版本检查，以显式最小环境启动，并校验输出路径仍位于 Snapshot 内。

## 7. 部署建议

第一阶段使用单机 Linux：Control Plane 运行在普通用户进程，Runner 使用 rootless Docker。Control Plane 不进入目标网络，Worker 不挂载 Docker socket。Docker 操作由一个最小权限 Runner Service 代理。成熟后再将 Validation Sandbox 移到独立 VM 或 gVisor/Firecracker。

## 8. M4.1 Runner contract

`SandboxRunner` receives a typed `SandboxRunRequest`. The request binds a `TaskEnvelope`, an
immutable Sandbox Profile, one registered `ToolInvocation`, an explicit secret-free environment,
an attempt number, and an optional content-addressed checkpoint. The Runner rejects mismatched
Scope/Target/Profile provenance before allocating resources.

The current `OfflineSandboxRunner` is a lifecycle test double. It never starts a process or opens a
socket. Its cleanup report validates orchestration semantics only; it is not evidence of operating
system or container isolation.

## 9. M4.2 Tool Broker contract

The Tool Broker owns an immutable capability registry. `TaskEnvelope` binds the registry digest so
queued work cannot silently pick up a changed tool implementation. A call proceeds only when its
tool is present in the Registry, Task allowlist, and Sandbox Profile and when its Scope/Policy and
Worker-role bindings still match.

The first typed tool is `http.request`. Request bodies and credentials cross the boundary only as
opaque content digests. Each redirect is treated as a new policy decision and DNS resolution; the
transport must connect to the pinned IP and report the actual peer. The current resolver and
transport are deterministic offline adapters and never open a socket.

## 10. M4.3 Docker Runner boundary

`DockerSandboxRunner` is a trusted adapter: only this process talks to the Docker daemon. A Worker
never receives the Docker socket, host environment, image tag, host mount path, or an arbitrary
entrypoint. Image IDs, content objects, and absolute in-image tool prefixes come from Control
Plane-owned registries.

The adapter currently supports network-disabled runs. It creates the container without starting it,
inspects the resulting Docker configuration, and only then starts the registered tool. Rootless mode
and seccomp are engine preconditions by default. A terminal result is returned only after the
container is removed and an inspection confirms absence.

Direct Worker `TARGET_ONLY` networking is deliberately rejected. A Docker bridge alone is not a
destination egress policy. Instead, the trusted Broker now owns a live HTTP/HTTPS adapter: policy
resolves and selects an IP, the transport connects to that numeric address without proxy discovery,
retains the authorized hostname for Host/TLS verification, records the actual peer, applies response
budgets, and writes only a redacted transcript to Evidence Store.

Offline (`StaticResolver` + `OfflineHttpTransport`) and live (`SystemResolver` +
`PinnedHttpTransport`) adapter pairs have distinct implementation digests. Broker preflight requires
both adapters to match the Tool Registry bound into the queued Task.

M4.3 is qualified by a dedicated Ubuntu 24.04 workflow that runs Docker Engine 29.7.2 as a delegated
rootless systemd user service. It requires seccomp, cgroup v2, and enforceable memory, CPU-quota, and
PID controls; proves that a `--network none` Worker cannot reach a live sibling container or the
daemon gateway; denies the discovered gateway before Broker transport; and stops redirect-time DNS
rebinding before a second socket is opened.

## 11. M4.4 transactional Validation Orchestrator

The Control Plane seals a human selection, Candidate content digest, and typed Runner/Broker requests into a content-addressed
`ValidationPlan`. It revalidates Candidate, Target, Scope, policy, profile, role, and input bindings
before claiming a SQLite `STARTED` checkpoint. A completed plan is returned idempotently; a stranded
`STARTED` plan fails closed for explicit recovery instead of replaying possible side effects.

Execution and verdict are separate trust boundaries. Runner completion or HTTP success never proves
a vulnerability. The default judge returns `INCONCLUSIVE`; another deterministic judge may return
`REPRODUCED` only with Evidence IDs collected by that execution. The Orchestrator creates a
`ValidationRun`, optionally seals an `EvidenceBundle`, and uses the existing Candidate state machine.
It has no path to create a Finding or submit a report.

## 12. M4.5 deterministic HTTP assertion

`HttpResponseAssertion` is sealed into the plan before execution and identifies one exact Broker
call, expected status, expected final raw-body SHA-256, and the result to record on an exact match.
The raw body never enters `BrokerResult`; only its digest and the redacted Evidence reference do.

`DeterministicHttpJudge` trusts only the live pinned HTTP Registry by default and returns the
precommitted `REPRODUCED` or `NOT_REPRODUCED` only when both status and body digest match. Offline
registries, missing calls, incomplete calls, and mismatches are `INCONCLUSIVE`.
Before invoking any judge, the Orchestrator opens every referenced Evidence object with no-follow,
checks its size, and recomputes its content digest.

An opt-in composition probe runs a network-disabled ephemeral Docker Validator, then lets
the Broker contact a temporary authorized fixture, captures Evidence, evaluates the exact assertion,
updates Candidate state, and verifies container cleanup. It passes both with the local Docker Desktop
test exception and under the production-default rootless Linux admission policy.

## 13. M6.1 offline benchmark boundary

The benchmark layer consumes two sealed local inputs: a suite containing ground-truth identities and
an observation set describing already-completed pipeline states. It does not execute analyzers,
Workers, Runner tasks, Broker calls, or report exports. Its workflow-integrity validator refuses to
represent a Finding unless Validation, Critic, Candidate promotion, and Evidence completeness all
passed.

Metric calculation is a pure reducer. A transactional service binds the exact suite, observation
set, regression policy, optional baseline, deadline, and idempotency key before producing immutable
local JSON/Markdown artifacts. Baselines are themselves content-addressed and bound to the complete
suite digest. Ordinary CI regenerates the local fixture, detects drift, and runs this same offline
gate; importing future external suites remains an adapter concern.

## 14. M6.2 external benchmark snapshot boundary

External benchmark acquisition is outside VulnLoom. The importer receives only an already-present
local directory, a content-addressed manifest, and a plan bound to one registered adapter digest.
It performs two complete bounded no-follow scans around normalization, closing both initial drift
and scan/parse TOCTOU windows. It never invokes a file from the snapshot.

The BountyBench adapter reads only official bounty metadata labels. The AutoPenBench adapter treats
task text and flags as sensitive source data and discards them; a separate sealed sidecar supplies
CWE mappings because upstream vulnerability keywords are not a reliable taxonomy boundary.
Normalized suites contain only digests, versions, CWE labels, and stable identities. Import artifacts
and SQLite checkpoints are separate from raw snapshots, and adapter outputs can feed the existing
M6.1 evaluator without granting it filesystem or network capability.
