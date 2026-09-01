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

## 15. M6.3a precomputed analyzer Observation boundary

The analyzer import layer accepts one already-present CodeQL SARIF, Trivy JSON, Checkov JSON, or
Kubesec JSON file plus an optional sealed CWE map. Acquisition and execution are outside this
boundary. The protocol has no URL, command, environment, credential, Docker, Broker, or Submission
field.

`AnalyzerResultSnapshot` binds the exact Target/version, tool version, rules digest, and input
bytes. A registered adapter converts that input to `AnalyzerObservationSet`, which persists only
rule and message digests, normalized CWE labels, severity, and safe relative source locations.
Checkov/Kubesec findings without an explicit CWE mapping are exclusions rather than guessed labels.

The service verifies the actual bytes it parses and performs another full manifest check after
normalization. It then claims a transactional checkpoint and publishes a read-only,
content-addressed artifact. Analyzer observations are deliberately not pipeline observations: their
schema cannot represent Candidate state, Validation, Critic approval, Evidence completeness, or a
Finding identity. Later correlation must cross the ordinary Candidate→Finding gates.

## 16. M6.3b explicit analyzer evaluation boundary

Evaluation consumes one sealed BenchmarkSuite, an exact collection of AnalyzerObservationSets, and
an `AnalyzerTruthAlignment`. Alignment entries are explicit reviewed labels, not inferred matches:
equal CWE values alone do not increase recall. The reducer verifies each match remains inside its
case, Target version, ObservationSet digest, and truth identity, and that the declared CWE is present
on both sides.

Metrics are deterministic at two levels: aggregate coverage across tools and a separate slice per
analyzer. Policy applies thresholds to both, requires named analyzers and a complete case×analyzer
matrix, and compares exact-suite baselines. This prevents another tool's match from hiding a
regression in one adapter.

All semantic and resource checks precede the SQLite STARTED checkpoint. Results are local immutable
JSON/Markdown objects. The evaluator has no analyzer execution, filesystem target access, Runner,
Broker, network, credential, Candidate transition, Finding promotion, or Submission capability.

## 17. M6.4a analyzer execution protocol boundary

The Control Plane registers one exact source-only analyzer contract: analyzer and tool version,
image ID, rules digest, Observation adapter digest, absolute in-image executable, complete argv,
explicit safe environment, and `/workspace/output/output.json`. Plans bind that registration and its
registry to an exact Target Snapshot/Manifest, active Scope and policy, static Sandbox Profile,
Runner request, deadline, and idempotency key.

The analyzer registry materializes `DockerTool` entries directly from the sealed argv. Workers cannot
append arguments, select a tag, pull an image, add network, enable target-code execution, inherit the
host environment, or choose a host path. M6.4a's concrete service uses only `OfflineSandboxRunner`;
`protocol_completed` proves orchestration semantics and cleanup, not analyzer execution, and cannot
contain an `AnalyzerResultSnapshot`.

This boundary has no Candidate/Finding transition or Broker/Submission path. Future real executors
must capture and seal output before scratch cleanup, then pass it through the existing M6.3a adapter.
Target-build modes remain outside this source-only protocol and require an exact untrusted-build
Approval before any runner allocation.

## 18. M6.4b admitted analyzer execution boundary

The real execution service is deliberately narrower than the protocol: it reconstructs and compares
one exact Checkov or Kubesec registration, verifies the sealed CWE sidecar, then claims a separate
Docker-execution checkpoint. The Docker registry derives both argv and tool-specific successful
exit codes; callers cannot append flags or reinterpret another tool's failure code.

Attached stdout is bounded by the trusted host adapter and published as an immutable object only
after regular-file, no-follow, size, and digest checks. The container is always removed and absence
verified. A completed Runner result must contain exactly one output, and that output must complete
the existing M6.3a snapshot/import transaction before the outer outcome can complete.

Image installation remains operator/CI provisioning, not a product capability. Runtime cannot pull,
resolve tags, use the network, execute target builds, access Docker from inside the Worker, promote a
Candidate, create a Finding, or submit a report.

## 19. M6.4c sealed Trivy database boundary

Trivy is admitted as one exact 0.73.0 factory. Its registration embeds a `TrivyDatabaseSnapshot`
whose content address covers exactly the DB v2 metadata and Bolt database files. That digest is also
the registration rules digest and an explicit Task input. The static analyzer profile adds one fixed
`/workspace/analyzer-data` slot; it is read-only, resolved only through `RegisteredObjectStore`, and
included in post-create Docker mount verification.

The sealed argv enables only the vulnerability scanner and disables database/check/Java/VEX updates,
version checks, telemetry, and dependency API lookups. The service verifies the DB before claiming
its checkpoint and again after container cleanup, closing the normal scan/import drift window. A
successful Runner output still has no workflow authority: it must become a M6.3a Trivy Observation
artifact before the Docker execution transaction can complete.

## 20. M6.4d sealed CodeQL query boundary

CodeQL is admitted as one exact 2.26.2 query-only factory over a `CodeQLSnapshot` that binds the
Target/version/Manifest, prebuilt database, query pack, suite, precompiled query artifacts, and all
member digests. Database construction is absent from the protocol. The original object is mounted
read-only and verified before checkpoint claim and again after container cleanup.

Because CodeQL writes query results into its database, the registered executable is a narrow
wrapper inside the exact analyzer image. It copies only the database into the Runner's bounded
output tmpfs with no-follow reads and exact file/entry/byte checks, then invokes one fixed
`database analyze` command against that copy. Query caches are confined to bounded `/tmp`; SARIF
source contents, snippets, query help, downloads, URLs, shell commands, and runtime arguments are
not representable. Completed stdout must pass bounded immutable capture and the existing M6.3a
CodeQL import before the outer transaction completes.

## 21. M6.5 analyzer execution qualification boundary

The qualification layer is a trusted fan-in, not a Worker or executor. It accepts only completed
M6.4 Docker outcomes recorded in the authoritative completed-execution store and binds each case/analyzer cell to the exact execution plan, registration,
cleanup proof, imported M6.3a ObservationSet, Target/version/Manifest, and Scope version. The outer
plan additionally seals the BenchmarkSuite, reviewed truth alignment, M6.3b evaluation plan, and
required analyzer matrix.

All provenance, digest, lifecycle, matrix, and alignment checks run before a qualification
checkpoint. The existing M6.3b service remains the only metric reducer and immutable result
publisher. M6.5 owns no Runner, Docker adapter, network, credentials, domain state transition, or
Submission path.

## 22. M6.6 four-analyzer qualification admission

The rootless admission environment now composes all four admitted analyzers over one Target
provenance and one authoritative execution store. Per-analyzer probes remain separate, while the
campaign probe verifies missing-cell and outcome-drift rejection before completing the exact
Checkov/Kubesec/Trivy/CodeQL matrix through M6.5 and M6.3b. This is composition evidence only and
does not expand any Worker, image, argv, filesystem, network, or workflow authority.

## 23. M7.1a offline typed Agent Runtime boundary

The first Agent Runtime is a trusted Control Plane loop over a deterministic offline replay adapter.
Its content-addressed registration fixes provider/model identity, supported Worker roles, adapter
implementation digest, and output ceiling. A run plan binds that registration to an exact
`TaskEnvelope`, context digest, decision schema, budgets, deadlines, and idempotency key.

Each step exposes only typed digests, the Worker role, Task tool allowlist, and remaining budgets.
Untrusted output must validate as one exact terminal decision or one typed tool proposal. The Runtime
never executes that proposal: it reduces raw arguments to digests and returns a `ToolIntent` for a
future, separately authorized Broker boundary. Unauthorized tools, malformed arguments, identity
drift, oversized output, exhausted tokens, and elapsed wall budget fail closed.

The checkpoint store persists only STARTED state or a bounded terminal outcome. Raw model output and
raw tool arguments are discarded, and an interrupted adapter call requires explicit recovery instead
of automatic replay. There is no live provider, socket, endpoint, credential resolver, Runner,
Broker call, Approval consumption, domain transition, or Submission path in M7.1a.

## 24. M7.1b Control Plane credential lease and local fake provider

Serializable provider configuration now binds a content-addressed credential reference instead of
offering an API-key-returning method. The reference names one explicitly allowed Control Plane
environment variable; the provider resolves only an initialization-time allowlisted reference into a non-serializable byte buffer.
The lease is scoped to one adapter call and zeroed on normal completion or exception.

The `local_fake_provider` adapter proves this lifecycle without network ambiguity. Its registration
binds the credential reference, adapter implementation, provider/model identity, roles, and budgets.
It compares a sealed request digest and credential digest in memory, releases the lease, then returns
a fixed structured reply. Neither the secret nor the reference is copied into the Agent step request,
outcome, or checkpoint.

This is Control Plane object-lifecycle isolation, not a live-provider or OS-isolation claim. The
adapter has no socket, URL, DNS, proxy, HTTP client, SDK, Runner, Broker, tool execution, Approval,
domain reducer, or Submission capability.

## 25. M7.2 sealed model-context boundary

Context assembly is a trusted Control Plane reducer over transient source records. Every source must
match the Task's ordered `input_refs` exactly; callers cannot omit, append, substitute, or reorder a
record. The assembler normalizes text, rejects unsafe controls, applies the fixed Evidence redactor,
and enforces raw-fragment, redacted-fragment, total-byte, fragment-count, deadline, and wall budgets.

The resulting content-addressed snapshot binds Task, Target, Scope, input-reference digests,
redaction policy, and ordered fragments. Persisted fragments contain only reference digests,
redacted text, content digests, and an immutable `untrusted` marker. The store uses atomic publication
and no-follow, regular-file, read-only, size, schema, identity, and digest verification.

An Agent run may bind the exact snapshot ID; the Runtime must reload and revalidate it before the
STARTED checkpoint, while step requests receive only that ID. M7.2 does not read
raw Evidence bodies, select context autonomously, render provider messages, grant permissions, call a
model or tool, open a socket, or change domain state.

## 26. M7.3 fixed provider-message envelope

Each Worker role maps to one built-in, content-addressed system template. Callers cannot supply system
text or a template version. The user message is canonical strict JSON: trusted control metadata and
budgets occupy a separate object, while every redacted fragment remains inside an explicitly
untrusted array. JSON escaping prevents fragment text from changing the message shape; authorization
still comes only from typed Runtime/Broker checks, never from prompt precedence.

The envelope binds the exact plan, Task digest, context snapshot, Target/Scope digests, model
registration, template, decision schema, tool allowlist, budgets, step, and messages. Its validators
reparse JSON with duplicate-key rejection and revalidate every fragment. System, user, total-byte,
and rendering wall limits are independent.

For context-bound runs, the Runtime rebuilds the first envelope before its STARTED checkpoint and
seals the envelope ID into the step request. Retries render a new envelope for their step and
remaining output budget. Offline adapters receive the transient envelope but retain only its ID.
M7.3 adds no live transport, SDK, socket, tool execution, domain reducer, or Submission path.

## 27. M7.4 provider transport admission protocol

The M7.4 boundary separates serializable admission metadata from transient provider bytes. A sealed
admission names one exact canonical DNS hostname, TLS port 443, canonical request path, credential
reference, adapter implementation, request/response ceilings, and timeout. Redirects and proxies are
disabled, DNS revalidation is required, raw responses are never persistent, the attempt limit is one,
and `network_enabled` is fixed false.

For one exact StepRequest/Message Envelope pair, trusted code derives a digest-only transport request.
The provider-shaped request body, credential lease, and raw response use mutable transient buffers
that are zeroed before return. Strict JSON, exact response shape, provider/model identity, byte and
wall limits are checked before an `AgentModelReply` exists. Attempts and successful receipts contain
only digests, counts, stable status, and cleanup evidence.

The admitted adapter is an in-memory behavior fake: it deliberately has no DNS, socket, HTTP client,
SDK, proxy, or retry implementation. This proves the protocol and lifecycle only. A real HTTPS adapter
requires a later production Admission proving process isolation, exact egress, DNS/rebinding and TLS
behavior, bounded streaming capture, rate limits, and redacted operational logging.

## 28. M7.5 subprocess-pinned HTTPS provider transport

M7.5 introduces a fixed Control Plane adapter, not a Worker network capability. Its registration and
transport admission bind one implementation digest, provider/model, credential reference, exact
hostname/path, limits, rate, and IP policy. Production admissions require port 443 and globally
routable DNS answers. The separately typed Admission probe requires a `.test` hostname, loopback-only
answers, an exact port, and a content-bound test CA.

Each call re-resolves the hostname, validates every answer, and selects one canonical numeric IP.
Credential and provider-message bytes are framed over stdin to a one-shot fixed Python module. The
child runs in isolated mode with a minimal environment, root cwd, closed descriptors, no shell, a new
process group, resource limits, discarded stderr, and bounded stdout. Timeout and overflow kill the
entire group before control returns.

The child creates one TLS 1.2+ connection to the pinned IP while preserving the admitted hostname for
SNI/certificate verification. It verifies the actual peer, performs exactly one POST to the admitted
path, forbids redirects/compression, bounds headers and streams at most the admitted body size. A
small non-secret frame returns peer/TLS proof plus raw response bytes; the parent revalidates and
discards them after strict typed parsing. Only digest-only attempts and receipts remain.

There is no provider SDK or arbitrary provider wire mapping yet: the endpoint must implement the
sealed VulnLoom response contract. The default test suite remains offline. Production Admission uses
a real loopback TLS server and child process, never a public provider.

## 29. M7.6 provider egress authorization lifecycle

M7.6 separates transport configuration from permission to use it. A content-addressed issuer policy
limits one trusted Control Plane issuer to explicit provider IDs, networked transport modes, and a
maximum grant lifetime. The Authority turns one exact transport Admission into an immutable grant
that also binds its credential reference, adapter implementation, purpose, issuer, and validity
window. Model registration binds the exact grant ID.

Grant and revocation records are atomically published as read-only content-addressed objects. A
SQLite lifecycle ledger provides independent STARTED/COMPLETED checkpoints, idempotency conflict
rejection, and active/revoked state. Expiry is derived from the immutable grant time window. Unsafe,
writable, linked, oversized, malformed, missing, unfinished, revoked, expired, or Admission-drifted
objects all fail closed.

The HTTPS adapter reopens and validates the grant object and lifecycle ledger on every call before
DNS, rate accounting, credential acquisition, or process creation. Thus a registration or Admission
constructed in memory cannot itself authorize egress, and completed revocation takes effect before
another external action. This is a local trusted-Control-Plane authority, not a cryptographic remote
signer; M7.6 adds no public provider call, provider codec/SDK, tool execution, or Submission path.

## 30. M7.7 sealed OpenAI Responses codec

M7.7 replaces the temporary VulnLoom-shaped live wire body with one content-addressed
`openai-responses-v1` codec. Its registration binds the provider identity, exact `/v1/responses`
path, implementation digest, Agent decision schema, and codec byte/wall limits. The subprocess model
registration must bind that exact codec ID, while offline and fake adapters cannot bind one.

The encoder has no arbitrary-parameter input. It maps only the trusted two-message envelope and
registered model/output budget, fixes storage and streaming off, disables truncation, and requests a
strict JSON Schema response without advertising provider tools. The decoder accepts only one
completed assistant `output_text`, exact model identity, bounded usage and strict JSON. Refusals,
incomplete responses, native tool calls, annotations, multiple outputs, duplicate keys and unknown
protocol fields are rejected before an `AgentModelReply` exists.

The output text is validated again as the existing typed decision. Thus `propose_tool` remains an
inert Control Plane intent, never a provider-native tool execution. Request and response buffers keep
the M7.5 zeroing/cleanup lifecycle. Tests use golden JSON and loopback TLS only; no public-provider
qualification, SDK, production credential, streaming, session continuation, Approval or Submission
path is added.

## 31. M7.8 typed Agent intent handoff to Tool Broker

M7.8 introduces a trusted Control Plane handoff service rather than giving the model an execution
adapter. The Agent proposes one opaque commitment for a preconstructed typed `BrokerCall`; its
persisted `AgentToolIntent` contains only invocation and argument digests. The handoff plan binds that
commitment to the complete Agent plan/outcome provenance and the full immutable Broker call. No code
reconstructs HTTP parameters from model prose or recovers the original Agent arguments.

Before a STARTED checkpoint, the service reopens the authoritative Agent run, requires a cleaned
`tool_proposed` outcome, compares the exact intent commitment, and calls the Broker's static
preflight. The Broker then independently enforces Scope, Policy, Sandbox Profile, Tool Registry,
network grants, DNS/peer pinning, budgets, credential admission and action-bound Approval. Thus the
handoff is orchestration only; Tool Broker and Sandbox remain the permission boundaries.

The separate SQLite lifecycle supports idempotent completed replay and fail-closed conflict/recovery.
One Agent intent gets one attempt, except that an `approval_required` result may authorize one exact
second attempt bound to the prior handoff. A completed Broker response must become an
`AgentToolObservation` containing only typed metadata, content digests and Evidence refs. It cannot
change Candidate/Finding state. Phase 3 composes the service with a real pinned Broker socket and
Evidence Store against a temporary authorized fixture, without adding public egress or Agent-owned
network capability.

## 32. M7.9 sealed Tool Observation continuation

M7.9 closes one bounded feedback cycle without turning the Agent into an autonomous tool runner. A
content-addressed `AgentContinuationPlan` binds the authoritative root plan/outcome, completed handoff
outcome and Observation, rebuilt context snapshot, cumulative budget ledger, and a derived Agent run.
The derived Validator Task receives a new identity but must inherit every authorization and provenance
field. Its tool allowlist is empty, its tool-call budget is zero, and its model/wall budgets can only
shrink.

The trusted service reads only the Observation's exact Evidence refs through the content-addressed
Evidence Store. It applies no-follow, size and digest verification, runs the fixed redactor again, and
assembles each response as bounded untrusted context. Before its STARTED checkpoint, execution reopens
the root Agent and handoff checkpoints, reopens the read-only context object, rereads all Evidence, and
requires an identical snapshot. Callers cannot inject a transcript or substitute a context source.

The continuation ledger uniquely consumes one Observation. Completed replay is idempotent; conflicting
keys, duplicate consumption and unfinished STARTED rows fail closed. The child Runtime is limited to
one step. `complete` and `blocked` remain terminal; a second tool proposal is rejected by the zero-tool
Task and stored as a stable failure. The Admission composition joins the isolated loopback provider,
pinned Broker and temporary authorized target, but adds no public network authority or domain-state
transition.

## 33. M7.10 fixed two-tool Session ledger

M7.10 composes the existing Runtime, handoff, Evidence and continuation boundaries under one
content-addressed `AgentSessionPlan`. The plan begins only after an authoritative completed first
tool round. It derives one new Validator Task with a single remaining tool call, a bounded redacted
Observation context, inherited authority and deadline, and a content-addressed finite set of exact
read-only Broker-call commitments. Those commitments appear only in trusted message control; context
fragments remain untrusted and cannot add options.

The Session store claims the first Observation before another provider action and records cumulative
tokens, steps, consumed tool calls, provider turns, Broker attempts and remaining wall time. A listed
second proposal still enters the ordinary M7.8 handoff and Broker. A successful second Observation
enters the ordinary M7.9 zero-tool continuation; a third proposal therefore becomes a stable failure.
An Approval-required second handoff moves the Session to a durable wait state. Only one explicit
M7.8 attempt-2 retry with an independently valid Approval may resume it, and crash recovery never
replays provider or Broker actions automatically.

The fixed shape permits at most three provider turns and two successful tool calls. It introduces no
general recursion, model-built request parameters, Agent-owned transport, public target/provider,
target build, Candidate/Finding transition, report export or Submission capability.

## 34. M7.11 immutable Session audit and deterministic terminal projection

M7.11 is an offline verifier over the completed M7.10 chain. Its digest-only plan binds the exact
Session plan and outcome without persisting the full authorized calls. Before an audit checkpoint is
claimed, the service reopens the Session, both Agent run stores, every handoff, the terminal
continuation and every referenced Evidence object. It revalidates the typed objects, reconstructs the
ordered Observation set, proves the selected call belongs to the sealed authorized set, and recomputes
all token, step, tool, provider, Broker and wall-time accounting.

The resulting content-addressed bundle contains only object IDs and digests, Target/Scope provenance,
Approval decision digests, Evidence refs, typed budgets, cleanup proofs and one deterministic terminal
recommendation. `denied` projects to a blocked recommendation; all other terminal states retain their
completed, blocked, failed or timed-out meaning. Neither model prose nor confidence participates in
the projection, and the recommendation has no domain-state command.

Bounded JSON and Markdown artifacts are atomically published as read-only objects and never copy
Evidence content, URLs, credentials, provider wire data or tool arguments. The separate SQLite
STARTED/COMPLETED lifecycle permits idempotent completed reads but refuses conflict and unfinished
recovery. This layer performs no provider, Broker, Runner, Docker, target-build, Candidate/Finding,
report-export or Submission action.

## 35. M8.1 human Validation Intake and sealed plan binding

M8.1 adds an offline Control Plane decision boundary between an audited Agent recommendation and the
existing Validation Orchestrator. A digest-only `AgentValidationIntakePlan` binds the exact read-only
M7.11 Audit artifact and recommendation, immutable CandidateSet/Candidate, current Target/Scope, and
an independently constructed typed `ValidationPlan`. The service reopens the Audit artifact and
CandidateSet through their authoritative stores before both plan creation and decision recording.

The human command is limited to `accept`, `reject`, or `defer` with a fixed reason code and exact
digest bindings. A non-completed recommendation cannot be accepted. An accepted record means only
that a reviewer selected that exact plan for a later explicit Validation entry point; the Intake
service has no Runner or Broker dependency and does not queue or mutate the Candidate, consume an
Approval, create Evidence, or execute any request.

The separate SQLite STARTED/COMPLETED ledger persists only identities, digests, the stable decision,
reason code, reviewer, and the digest-only record. Reused recommendations or Validation plans,
conflicting commands, unfinished checkpoints, expired decisions, Scope drift, Candidate drift, and
ValidationPlan drift fail closed. The later caller must still invoke `ValidationService` explicitly
and pass all existing M4.4/M4.5 Scope, Policy, Profile, Broker, budget, Evidence, and Approval gates.

## 36. M8.2 completed Validation outcome provenance binding

M8.2 is an offline verifier over one Validation that has already completed through the existing
explicit `ValidationService` entry point. Its content-addressed plan binds the accepted M8.1 record,
Audit bundle, immutable CandidateSet/Candidate, exact ValidationPlan, completed outcome digest,
ValidationRun, typed result, and sorted Evidence refs. The service has no Runner, Broker, provider,
Docker, network, Approval, target-build, or Submission dependency.

Before claiming a binding checkpoint, the service reopens every authoritative object and recomputes
the complete Validation provenance chain: Scope and Target version, original `PROPOSED` Candidate,
Runner request/result identity, ordered Broker call/result identities, forced timeout/policy result,
run plan and resource accounting, final Candidate state, Evidence collection and bundle sealing. A
missing or unfinished Validation, expired or non-accepted Intake, replaced outcome, foreign Evidence,
cross-target replay, or internally inconsistent completed row fails closed.

The resulting `AgentValidationOutcomeBinding` contains only IDs, digests, typed result/state and
completion time. Its independent STARTED/COMPLETED ledger uniquely consumes the Intake record,
Validation plan and outcome. Completed replay is idempotent; conflicting consumption and unfinished
recovery are refused without replaying Validation or performing cleanup actions against external
systems. This binding is provenance for a later Critic milestone, not a Critic verdict or authority
to create a Finding.
