# Authorized Red Team

Authorized Red Team is VulnLoom's fourth product entry. It is designed for targets that the operator owns
or is explicitly contracted to assess. This entry does not weaken the shared Scope, Policy, Approval,
Broker, Runner, Evidence, Candidate, Critic, Finding, or Report boundaries.

## First trusted local slice

The first slice establishes the control-plane contract without performing network traffic:

```text
approved Scope + canonical HTTP(S) base URL
  → fixed black/grey-box red-team mode
  → content-addressed Rules of Engagement
  → resumable Flow checkpoint
  → typed read-only Recon action
  → offline fake adapter
  → redacted Observation
  → budget/stop-condition transition
```

`WorkflowMode` separates visibility from execution strength. The current Red Team slice fixes autonomy to
`a2_bounded_execution`, execution to `red_team`, and visibility to `black_box` or `grey_box`. It must not be
described as the future A4 campaign engine.

Rules of Engagement bind the exact Scope version, target, allowed phase, test classes, impact partition,
deadline, action budget, consecutive-failure budget, and an opaque emergency-contact reference. V1 admits
only the `recon` phase and `read_only` impact. State change, real credentials, external callback, lateral
movement, and persistence are explicitly prohibited rather than left implicit.

The target URL must already be canonical, contain no credentials/query/fragment, and exactly match an
approved `NetworkTargetScope` host, scheme, and port. Scope and policy are rechecked before Flow start and
before every new action. A model or adapter cannot add a target or impact class.

## State and recovery

Flow status follows an explicit state machine:

```text
planned → running → completed
                  ↘ cancelled | timed_out | failed | killed
```

Plans, checkpoints, action claims, and observations are stored transactionally in SQLite. Action identity
and idempotency keys are unique. An interrupted adapter leaves a `STARTED` claim; recovery requires the
next numbered attempt and is limited to three. If the third attempt is interrupted, the Flow closes as
`failed` with cleanup unproven. Replaying a completed action is read-only and does not call the adapter.

The Kill Switch remains usable when Scope has been revoked or expired, provided the immutable Scope
identity/version still matches. It can only reduce authority and immediately makes the Flow terminal.

## CLI and API boundary

The local `vulnloom red-team` command exposes the same application service intended for a future HTTP API:

- `start` creates and starts a bounded Flow;
- `prepare-recon` emits a typed action command;
- `run-recon-offline` runs only the deterministic fake adapter;
- `status`, `cancel`, `kill`, and `expire` inspect or narrow Flow state.

There is intentionally no live Recon flag in this slice. The CLI accepts no Cookie, Authorization header,
API key, Provider credential, raw response, shell command, or arbitrary tool identifier. Offline observations
contain only outcome, optional status code, reason code, cleanup proof, redaction proof, and time; admitted live
observations may additionally bind the digest-only Attack Surface Snapshot described below.

## R3: admitted local HTTP Recon

R3 adds one deliberately narrow live path: an `HTTP_HEAD` action may be routed through the existing trusted
Tool Broker only when an immutable, content-addressed `IsolatedLocalReconAdmission` binds one exact private,
non-loopback IPv4 fixture, host, port, scheme, and expiry. The Sandbox Profile must contain exactly the same
single network grant, and the Broker must enforce the admission's exact resolved-IP set. This extra constraint
rejects DNS drift even when the replacement address is another otherwise permitted private address.

The Broker rechecks Scope, Policy, network grant, DNS result, and actual socket peer at every redirect hop.
It performs a credential-free, body-free HEAD with bounded redirects, response bytes, request count, and
connect/read/total time. Socket timeouts become typed Recon timeouts. A cancelled or killed Flow cannot reach
the adapter. No live flag has been added to the normal CLI: the real-socket acceptance test is disabled unless
`VULNLOOM_RED_TEAM_INTEGRATION=1` is set and it starts only a temporary local fixture process.

Successful calls produce a content-addressed `AttackSurfaceSnapshot` embedded in the transactional
Observation. It contains only URL digests, the verified peer, status, redirect count, policy-record digests,
and Evidence references. The Broker Evidence sink allowlists response headers and redacts textual data; raw
URLs, cookies, Authorization material, and raw responses do not enter the Snapshot or Red Team database.

This milestone does not add public scanning, CIDR or path enumeration, active exploitation, credential use,
callbacks, lateral movement, persistence, or model-driven action selection. The next slice can build a bounded
attack-surface reducer over these trusted observations before any stronger action class is considered.

## R4: deterministic Attack Surface inventory

R4 reduces multiple successful R3 observations into an immutable `AttackSurfaceInventory` without making a
network call. A content-addressed `AttackSurfaceReductionPlan` binds the exact Flow plan, authoritative
checkpoint, Target, Scope version, Observation IDs, Snapshot IDs, deadline, budgets, and idempotency key.
Only completed HTTP HEAD actions with successful, redacted, cleanup-complete observations are admitted.

Before a STARTED checkpoint is written, the service reloads every source from the Red Team ledger and checks
the action, Flow, Target, Scope, requested URL digest, observation time, Snapshot identity, and every Evidence
object. Missing Evidence, stale Flow checkpoints, revoked Scope, empty live inputs, or exceeded budgets fail
closed without creating a partial reduction.

Endpoint identity is the stable digest of requested URL digest, final URL digest, and verified peer IP.
Repeated observations merge deterministically into sorted status codes, redirect counts, Observation IDs,
Snapshot IDs, and Evidence references. The Inventory contains no raw URL, request/response body, headers,
Cookie, Authorization material, or provider data.

The reduction ledger has explicit STARTED and COMPLETED states. Completed replay returns the same sealed
Inventory; unfinished work refuses automatic replay and permits only an explicit, maximum-three-attempt
recovery. The CLI exposes `prepare-surface-reduction`, `run-surface-reduction-offline`, and `surface-status`;
these commands reuse the same application service intended for a future API and never invoke Recon adapters.

## R5: verified TLS Service Identity

R5 adds a separate `tls.inspect` Broker capability and a typed, read-only TLS inspection plan. It accepts only
a canonical, query-free HTTPS URL, one test class, and bounded connect/handshake/total time. It has no request
body, headers, credential reference, redirect, protocol downgrade, or arbitrary socket option. The Registry
binds the exact resolver and transport implementation digests, while Scope, Policy, Profile network grant,
DNS result, exact local admission IP set, and actual socket peer are checked before an identity is accepted.

The pinned transport connects to the Broker-selected numeric IP but retains the authorized hostname for SNI
and certificate verification. Its TLS context must require CA verification, hostname verification, and TLS
1.2 or newer. A successful result contains only the endpoint URL digest, verified peer, negotiated TLS version,
cipher name/bits, leaf-certificate SHA-256, Policy digests, and Evidence references. Certificate bytes, subject,
SAN text, raw endpoint, headers, credentials, and provider responses are never returned or persisted.

`ServiceIdentitySnapshot` is deliberately narrower than a generic service fingerprint: it asserts only facts
from that verified TLS session. The R4 reducer now accepts both HTTP Attack Surface and TLS Service Identity
observations, preserves TLS-only inventories, and links identities to matching HTTP endpoints by URL digest and
peer IP. All source action, Flow, Target, Scope, timestamp, Snapshot and Evidence bindings are rechecked before
the transactional reduction completes.

Normal CLI commands still cannot start live network Recon. The TLS acceptance test is disabled unless
`VULNLOOM_RED_TEAM_TLS_INTEGRATION=1` is set; it creates a temporary CA-trusted certificate and a server bound
only to a local private non-loopback address, verifies the pinned TLS session, and proves process cleanup.

## R6: deterministic Attack Surface Drift

R6 compares two completed, content-addressed Inventories without running Recon or opening a socket. A typed
`AttackSurfaceDriftPlan` binds the exact baseline/current reduction and Inventory IDs, stable Target, current
Scope version, resource limits, deadline, and idempotency key. The baseline may come from an older version of
the same Scope, but the current Inventory must match the currently approved Scope; Target and Scope identity
must remain equal, and baseline time must strictly precede current time and comparison time.

The pure comparison groups HTTP endpoints and TLS identities by their digest-only authorized endpoint key.
It reports endpoint addition/removal, peer-set, final-destination, HTTP status, redirect behavior, TLS identity,
TLS version, cipher, and leaf-certificate digest changes. Each changed surface carries only content-addressed
endpoint/Snapshot/Evidence references. A Drift Report is an observation about sealed facts, not a Candidate,
Finding, vulnerability conclusion, state-changing test, or instruction to expand Scope.

Both source outcomes are reloaded from the authoritative reduction ledger and every Evidence object is checked
before claim and completion. The drift ledger uses STARTED/COMPLETED checkpoints, idempotent completed replay,
explicit recovery, and at most three attempts. The CLI commands `prepare-surface-drift`,
`run-surface-drift-offline`, and `surface-drift-status` call the same application service intended for a future
API. They expose no live network switch, raw URL, certificate, response, credential, or Provider material.

## R7: operator-sealed Endpoint Seed Sets

R7 accepts only a finite JSON array of exact paths supplied by an identified operator. Each `EndpointSeedSet`
is content-addressed and binds the current running Flow checkpoint, Target, Scope/version, operator reference,
seal time, expiry, and idempotency key. Paths must be canonical ASCII absolute paths beneath the Flow target's
base path. Schemes, authorities, query strings, fragments, percent encoding, backslashes, repeated slashes,
and dot segments are rejected rather than normalized.

An `EndpointReconPlan` deterministically maps every sealed seed to exactly one `HEAD` step with redirects
disabled. It has explicit step, request, per-request time, total time, and recovery-attempt limits. Preparing a
plan transactionally reserves its request count against the remaining RoE action budget for the exact source
checkpoint, so multiple plans cannot independently spend the same budget.

The application service reloads Scope, Flow, checkpoint, Seed Set, and Plan bindings before dispatch and again
before completion. Adapter results must match the exact step and URL digests; Evidence references must already
exist. Completed runs replay without adapter calls, interruptions remain STARTED for explicit bounded recovery,
and timeout or cleanup failure is represented explicitly. Outcomes and status output contain URL digests, not
raw paths or endpoints.

The CLI provides `seal-endpoint-seeds`, `prepare-endpoint-recon`, `run-endpoint-recon-offline`, and
`endpoint-recon-status`. The seed input is a bounded, no-follow regular file. The only executable adapter in R7
is deterministic and offline. There is deliberately no crawler, wordlist enumeration, discovered-URL queue,
DNS or port discovery, live Endpoint Recon adapter, or public scanning switch.

Local R7 verification completed with 1427 tests passed, 27 integration tests skipped, and 85.85% total
coverage. Ruff, 373 JSON Schema parses, `git diff --check`, and the 451-test CUC/DeepSeek compatibility slice
also passed without making an external model call or network request.

## R8: exact Endpoint execution through the Flow ledger

R8 gives every prepared plan an explicit action-budget reservation. A reservation begins `active`; each
authoritative Flow action consumes exactly one request and the final request moves it to `consumed`. Operator
cancellation and deadline expiry release only the unconsumed remainder. Consumed actions remain in the Flow
checkpoint and cannot be rolled back or made available to another plan.

Endpoint execution now creates deterministic `RedTeamReconCommand` values and reuses the existing transactional
action claim, Observation, checkpoint, Policy and Evidence path. Recovery replays completed actions without a
second Broker call. It rejects a non-authoritative Endpoint plan, a changed Scope, a terminal Flow, an unrelated
action inserted after the source checkpoint, inconsistent reservation progress, or altered Observation lineage.

The pinned HTTP adapter accepts an optional exact URL-digest allowlist. When that allowlist is present,
`max_redirects` must be zero. A successful Endpoint step must return an `AttackSurfaceSnapshot` whose requested
and final URL digests both equal the sealed step, with zero redirects and an existing redacted Evidence object.
Responses cannot add seeds or schedule another request.

The local CLI adds cancellation, expiry and reservation-aware status but intentionally has no live execution
command. Default tests use the fake pinned Broker. The opt-in `VULNLOOM_RED_TEAM_INTEGRATION=1` test extends the
existing isolated private-address fixture to execute a sealed path and prove process cleanup; it never targets a
public service.

Local R8 verification completed with 1438 tests passed, 27 integration tests skipped, and 85.87% total
coverage. Ruff, 374 JSON Schema parses, `git diff --check`, and the 589-pass/9-skip model-provider and
CUC/DeepSeek compatibility slice passed without an external model call or public network request. The opt-in
isolated private-address HTTP process test also passed separately, including the sealed Endpoint path and process
cleanup assertions.

## R9: recurring exact Endpoint check triggers

R9 introduces `EndpointCheckSchedule` as a Control Plane trigger, not a network executor. A schedule seals one
Scope/version, canonical Target, operator reference, exact path set, fixed UTC interval, authorization window,
Flow stop conditions and Endpoint Recon limits. Every due slot creates a new bounded Flow, Seed Set and Recon
Plan; it never reuses a long-running Flow and never calls the Broker or a Recon adapter.

Schedule checkpoints have explicit `active`, `paused`, `cancelled` and `expired` states. Each content-addressed
run is `started`, `materialized`, `timed_out` or `failed`. A STARTED run requires the next numbered recovery
attempt and allows at most three. Replaying a materialized slot returns the existing run without creating a
second Flow. A new slot is rejected while the prior Flow, reservation or Recon run has not reached a provably
clean terminal state.

If materialization crosses its deadline, the service cancels any partially created, unexecuted Endpoint
reservation and Flow before closing the run. Unproven cleanup or exhausted recovery attempts pauses the
schedule fail-closed. Scope expiry/version drift, a foreign operator, invalid path, non-due trigger, overlapping
run and stale checkpoint are rejected transactionally.

The local CLI exposes schedule create, trigger/recover, status, pause/resume, cancel and expire operations over
the same application service intended for a future API. Its projections contain only identifiers, counts,
digests and lifecycle state. There is no daemon, cron parser, public discovery, crawler, live execution flag,
notification adapter or Web UI in R9.

Local R9 verification completed with 1450 tests passed, 27 integration tests skipped, and 85.77% total
coverage. Ruff, 377 JSON Schema parses, `git diff --check`, and the 589-pass/9-skip model-provider and
CUC/DeepSeek compatibility slice passed without an external model call or network request.

## R11.1–R11.2: sealed Attack Graph and isolated execution boundary

R11's first slice extends the read-only RoE into a still-bounded external Web attack-chain control plane.
`AttackGraph` binds an exact Flow, Target, Scope/version, one finite `AttackObjective`, and 3–32
content-addressed `AttackAction` values. Actions form an ordinal DAG: the first and only Initial Access action
declares `state_change`; later actions verify the test session and goal Evidence; the final action is the only
Cleanup action and must directly depend on the Objective verification. Objective Evidence alone leaves the
chain running; terminal success requires successful cleanup. Runtime code cannot insert a node, replace a path,
or skip a dependency.

Every action requires a separate `EXECUTE_RED_TEAM_ACTION` Approval whose digest is the action digest. Initial
Access and Cleanup additionally require the existing Policy Engine's exact `MUTATE_TARGET_STATE` Approval. Approval for
another node, the whole Graph, or an expired action cannot be reused. External callback, lateral movement,
persistence, and real credentials remain prohibited by the RoE. Attack Action schemas contain no callback,
payload, shell, header, Cookie, credential, or response-body field.

`AttackChainCheckpoint` and action claims/Observations are stored transactionally in a separate SQLite ledger.
A completed action replays without another adapter call; interruption permits only the next bounded attempt.
Timeout, failure, unproven cleanup, Scope drift, missing prerequisites, missing Approval, and the parent Flow
Kill Switch all fail closed. Every allow or rejection creates a redacted `AttackActionAuditRecord` containing
only digests, a reason code, Approval IDs, and time.

If a non-cleanup action fails or times out after dispatch, the chain enters `cleanup_required` instead of a
terminal state. Only the graph's already sealed Cleanup action may run, with its own execution and mutation
Approvals; success then records the deferred failed/timed-out terminal result, while cleanup failure closes as
`cleanup_unproven`. This prevents a failure result from silently abandoning test state.

The new `post_exploitation` Sandbox Profile is non-root, read-only-root, capability-free, networkless, and
unable to execute Target code. It mounts immutable Evidence plus bounded scratch and exposes only
`red_team.evidence_read` and `red_team.result_write`. Real Web actions and transport remain outside that Worker.

R11.2 adds `IsolatedAttackChainAdmission` and a trusted adapter that binds one expiring private non-loopback
fixture, exact ordered action/method/URL digests, expected status/body digests, one target-only Validation
Profile grant, and the Broker's exact resolved-IP set. Requests have no body, header, credential, redirect, or
dynamic target field. The Broker rechecks Scope, Policy, mutation Approval, DNS pinning, peer and budgets for
every action; results become digest-only redacted Evidence references.

Default tests remain offline. The explicit `VULNLOOM_R11_ATTACK_CHAIN_INTEGRATION=1` acceptance starts only a
local private-address process and proves the exact `POST → GET → GET → DELETE` chain, goal-before-cleanup
remaining nonterminal, target-state cleanup, process cleanup and sensitive-header redaction. At the R11.2
boundary, attack-path, detection-opportunity and defensive-improvement reporting remained the final slice.

Local R11.2 verification completed with 1499 tests passed, 30 integration tests skipped, 85.42% coverage,
Ruff, 417 JSON Schema parses, and `git diff --check`. The separately enabled private-address process test
passed once. No public target or external model was contacted.

## R11.3: deterministic Attack Path Report

R11.3 closes the defensive reporting slice with a separate `Attack Path Report` domain object. It is not a
disclosure `Report`, does not require or create a Candidate/Finding, and cannot authorize another action. The
plan binds one authoritative successful chain, its final cleaned checkpoint, Target, Scope/version, operator
reference, deadline and idempotency key.

Each successful graph action becomes one digest-only `AttackPathStep`. Its Observation Evidence is checked by
bounded no-follow content-addressed reads before the report checkpoint is claimed. A fixed trusted mapping
creates one typed `DetectionOpportunity` and one finite `DefensiveImprovement` for session creation, session
use, protected-resource access and session revocation. No model or free-form recommendation can add another
path, target, control or claim that current telemetry already detects the action.

The transactional report ledger supports completed replay, conflict rejection, explicit recovery and at most
three attempts. Deadline expiry is a typed terminal outcome. JSON and Markdown artifacts are written through
bounded temporary files into a read-only content-addressed directory, verified with no-follow reads and removed
on failed publication. Artifacts contain action/evidence digests and enums, but no target path, endpoint,
request/response, header, Cookie, credential or secret field.

With the R11.2 isolated multi-step execution proof and this Evidence-backed defensive report, the scoped R11
milestone is complete. This does not enable public scanning, lateral movement, persistence, real credentials,
automatic Finding promotion, external report submission or production-target execution.

Local R11.3 verification completed with 1505 tests passed, 30 integration tests skipped, 85.39% coverage,
Ruff, 424 JSON Schema parses, and `git diff --check`. The isolated private-address process acceptance also
passed again separately. No external model or public target was contacted.

## R11.4: architecture and pressure hardening

R11.4 closes two cross-aggregate failure modes found during an end-to-end architecture review. Each chain now
reserves its complete action count in the authoritative parent Flow ledger before its own ledger is created.
Recon claims and competing chains serialize their budget checks with immediate SQLite transactions, while the
chain ledger retains a second reservation check. A crash between the two ledgers can leave a retryable reserved
budget, but cannot create an executable chain without budget or allow `max_actions` to be exceeded.

The chain contract now seals a separate cleanup deadline: it follows the normal action deadline by no more than
300 seconds and remains inside both Scope and Flow validity. A timeout, kill, cancellation, parent-checkpoint
advance, or interrupted state-changing adapter call therefore cannot be mislabeled as a clean terminal state.
The chain moves to `cleanup_required`, atomically abandons any uncertain started claim, and admits only the
original Cleanup action with fresh exact approvals, current Scope, monotonic parent-ledger provenance, and an
unexpired cleanup window. Deserialized checkpoints also verify their failure count, objective observation, and
all-success shape, while attack reports enforce exact action-to-detection-to-control mappings.

The new offline stress cases cover repeated over-reservation, cross-connection contention, mixed Recon/Chain
budget use, deadline-edge compensation, cleanup-window expiry, kill after confirmed or uncertain mutation,
parent checkpoint drift, idempotent replay, and tampered terminal data. No live network, model, crawler, public
scan, exploit submission, or external service is enabled by this hardening.

Local R11.4 verification completed with 1514 tests passed, 30 integration tests skipped, 85.41% coverage,
Ruff, 424 JSON Schema parses, and `git diff --check`. The opt-in private-process acceptance safely skipped on
this host because no private non-loopback IPv4 was available; it was not counted as a new pass. See
`docs/R11-ARCHITECTURE-HARDENING.md` for the reviewed control/data flows, failure matrix, and residual risks.

## B1 Observation-driven bounded replanning

B1 在现有 `RedTeamFlowPlan` 上增加了一个不可信提议层，而没有把目标或执行权交给 Agent。Control Plane 只签发
短期、内容寻址的 `RedTeamReplanToolView`：它绑定当前 checkpoint、全部权威 Observation ID、原 Target URL
摘要、Scope 版本、剩余 Action 预算，以及有限的 Action kind/test class。视图不包含原始 URL；
`RedTeamReplanProposal` 也没有 URL、命令、header、body 或任意参数字段。

准入时服务重新读取 Plan、最新 checkpoint、Observation 及其来源 Action，从封存 Plan 派生目标，重新执行
Policy 判定，并在 SQLite `BEGIN IMMEDIATE` 事务中为恰好一个 Action 预留预算。并发或重复提议不能越过
`max_actions`；取消和到期只释放尚未消费的预留，已消费的权限不能回滚。相同 Proposal 的重放直接返回最初的
Admission，即使 checkpoint 已前进也不会生成第二份权限；相同 idempotency key 的不同内容被拒绝。

执行要求调用方提交与 Admission 中 Action ID 精确绑定的 `EXECUTE_RED_TEAM_ACTION` Approval。服务再次核对
Scope、Policy request 摘要、命令和 Admission 状态，然后才复用既有 Recon 状态机；成功、失败、超时和 cleanup
unknown 均保留原有终态语义。离线验收完成了 `HTTP_HEAD → TLS_INSPECT → HTTP_HEAD` 的两轮观察驱动调整，
两轮始终使用同一封存 Target，并覆盖缺失/伪造 Observation、过期视图、策略或 Approval 漂移、预算竞争、取消、
到期、超时、清理失败和幂等重放。测试只使用离线 adapter，没有访问网络、调用真实模型或执行真实攻击。

因此 B1 达到 `offline_tested`。B2 才会在明确封存的路径集合上增加类型化 Web/API 只读观察；B1 不提供
crawler、字典枚举、动态 Target 扩展或任意 HTTP 请求能力。

B5.1 为成功且 cleanup-proven 的 Replan 执行增加 `ReplanExecutionReceipt`。Receipt 绑定 Admission、源/结果
checkpoint、Action、Observation 和实际通过的 exact Approval；它只证明历史执行，固定不携带再次执行权限。
崩溃发生在权威 Action 完成与 Receipt 写入之间时，可通过同一 Command 的只读重放补写 Receipt，不会再次调用
adapter。

## B2.1 operator-sealed path GET observation

B2.1 在 R7/R8 的 `EndpointSeedSet`、请求预算预留和 Flow ledger 上增加第二种且仅有的路径方法 `GET`。GET 计划
仍由操作员精确封存的 canonical path 派生；同一计划只能包含一种方法。通用 `prepare_recon`、通用
`execute_recon` 和 B1 Tool View 都拒绝 `HTTP_GET`，因此调用方不能绕过 Endpoint Plan 自行构造 GET 权限。

执行沿用已准入的 pinned HTTP Broker，但仅在 adapter 获得显式 URL digest allowlist 且 redirects=0 时接受 GET。
请求没有 header、credential、body 或 query 扩展，响应上限固定为 64 KiB。正文只进入既有脱敏 Evidence Store；
新 `WebResponseSnapshot` 和 Endpoint outcome 只保存 method、状态码、Peer、响应字节数、正文 SHA-256、Policy
摘要和 Evidence ID，不包含 URL、正文或完整响应。requested/final URL digest 必须相同，伪造重定向绑定、原始
正文扩展字段、多 Snapshot 或缺失 Evidence 均 fail-closed。

离线 Broker 纵切已证明 sealed GET 的执行、Flow action 记账、预算消费、幂等重放，以及未封存路径、通用 Recon
绕过、缺失 Web Snapshot、超时和 cleanup-unproven 拒绝/终态。已发出的失败或超时请求仍消耗 Action 预算，不能
通过失败回滚获得额外请求。普通 CLI 没有新增 live GET 开关；本轮没有打开 socket、访问公网、调用真实模型或
执行真实攻击。B2.1 达到 `offline_tested`，尚不等同于 B2 完成或生产支持。

## B2.2 sealed OpenAPI document observation

B2.2 是 B2.1 之后的纯离线 reducer，不会发送第二个请求。Control Plane 只接受一条已成功且 cleanup proven 的
operator-sealed GET，重新读取权威 Endpoint Plan/outcome、当前 Flow checkpoint、Observation、
`WebResponseSnapshot` 和内容寻址 Evidence；任一来源、Scope/version、正文摘要或 checkpoint 漂移都 fail-closed。

解析面固定为 64 KiB 内的 OpenAPI 3.0/3.1 JSON，并有 path、operation、node、depth、server、墙钟和最多三次
恢复预算。重复 JSON key、非 object operation、无有限 HTTP method 的 path、URL-like/转义/遍历 path 以及预算
超限全部在写 STARTED checkpoint 前拒绝。`servers` 和任何层级的 `$ref` 仅计数后丢弃，服务没有 resolver、HTTP
adapter 或 Target 扩展接口，因此不会访问或信任文档声明的外部 authority。

结果只保留 canonical path template、`GET/HEAD/OPTIONS/PATCH/POST/PUT/DELETE` 方法集合和内容摘要。
每个 `OpenApiPathDiscovery` 都固定 `execution_authorized=false`，文档 Observation 固定
`target_expansion_authorized=false`；它们既不是 Endpoint Seed，也不是 Action。独立 SQLite ledger 提供幂等重放、
STARTED 恢复和完成态内容一致性。离线测试覆盖成功、拒绝、结构预算、超时、恢复、schema 注入与无部分结果。
B2.2 达到 `offline_tested`，不等同于生产支持，也没有新增 live CLI 开关。

## B2.3 reviewed OpenAPI discovery promotion

B2.3 把“发现”与“加入 Seed Set”之间建模为独立人工审核边界。`OpenApiDiscoveryPromotionPlan` 绑定 completed
OpenAPI Observation、当前 Flow checkpoint、Target、Scope/version、操作员身份和显式 selection。每个 selection
引用权威 discovery ID；参数化 path template 必须由操作员给出一个 canonical concrete path，并逐段匹配。未选项、
未知 ID、模板错配、重复路径、外部 URL 和没有 GET/HEAD 的 discovery 均不能晋升。

Promotion ledger 与 `endpoint_seed_sets` 使用同一 SQLite connection。claim 只写 STARTED，不发布 Seed；完成事务
同时写入新的 `EndpointSeedSet` 和内容寻址 Outcome，因此崩溃或超时不会留下“promotion 未完成但 Seed 已可用”的
中间状态。遗留 STARTED 需显式恢复且最多三次；完成态幂等重放必须得到相同 Seed Set。晋升后的 Seed 仍不含执行权，
后续请求必须重新经过 Endpoint Plan、动作预算、Scope/Policy 和既有 Broker 边界。离线纵切已证明具体化路径可进入
HEAD 计划，但没有执行请求，也没有新增 live CLI。

## B4.0 authorization-derived passive asset discovery

B4.0 修正了“固定 Target”与教育行业实体范围授权之间的产品边界。系统可以从 FOFA、Quake、Shodan、被动 DNS、
证书透明度、ICP registry 或控制方清单发现候选资产，但查询必须由可信控制面从当前批准 Scope 和独立封存的
`AssetDiscoveryAuthorization` 生成。协议只允许 typed domain、exact-host 或 ICP selector，不包含任意测绘 DSL；
平台 token 不出现在 Plan、Worker、模型上下文、普通日志或结果对象中。本阶段只有离线 fake adapter，没有真实
平台客户端或公网开关。

授权模式分为 `exact_assignment`、`entity_bound`、`platform_category` 和 `supply_chain_with_approval`。每条来源记录
先成为无执行权的 `DiscoveredAsset`，并绑定查询、来源、观察时间和 digest-only 来源证据。准入 reducer 综合根域、
ICP、控制方清单、证书/官方链接/产品指纹以及跨法人或明确排除证据：精确 Scope endpoint 和强实体归属可自动
admit，弱线索或供应链关系进入 `approval_required`，明确越界则拒绝。Logo、标题、产品指纹或高危端口不构成漏洞
证据，也不能单独证明资产归属。

SQLite ledger 为每个已完成来源查询保存无 raw response 的 checkpoint，并在 STARTED/COMPLETED 状态间原子发布
admitted `AuthorizedAsset`；恢复不会重复请求已完成来源。中断、超时、预算超限、Scope 或
selector 漂移、adapter session/credential cleanup 未证明时都不发布部分资产。`AuthorizedAsset` 仅表示可以进入
后续 Target materialization，固定不授予主动请求、扫描、Candidate 或 Finding 权限。任何实际 HTTP/TLS/端口确认
仍需进入既有 Target、Policy、预算、Approval 和 Tool Broker 链。

## B4.1 opaque Test Identity Admission

B4.1 把 `Test Identity`、`Credential Reference` 和 `Test Identity Admission` 固定为三个不同领域概念。Test
Identity 是控制方或目标授权方专门提供的测试主体；Credential Reference 只是可信 Vault/Broker 可解析的内容寻址
locator；Admission 只声明该主体可用于精确 Scope/version、Target、用途、opaque role 和时间窗。用户名、密码、
Cookie、Token、Vault path 与任何 credential bytes 都不属于这些 Pydantic、SQLite、schema、日志或模型对象。

可信 Control Plane 注册 `TestIdentityRecord` 时必须证明 identity ref 已列入 Scope、Target scheme/host/port 精确
命中网络范围、用途映射到允许 test class、有效期完全落在 Scope 内，并绑定 custody proof digest 和 issuer ref。
首版用途为 authentication、read-only role observation 和 state-change validation；第三方真实账户在 schema 中固定
为 false。Admission 只允许单次未来 Session 使用，始终固定禁止 credential access、authentication、Session 和
state change。所有用途都声明后续需要 `USE_REAL_CREDENTIALS` Approval，state-change 还必须同时要求
`MUTATE_TARGET_STATE` Approval，但 B4.1 本身不消费 Approval 或执行这些动作。

Registry 支持只收窄权限的 digest-only revocation。权威 `active_admission` 每次重新读取 active Record、Scope、
Target 和 Admission 有效期，因此撤销身份会立即使历史 Admission 不可用。SQLite Admission ledger 提供原子发布、
幂等重放、STARTED checkpoint 和最多三次显式恢复；超时、漂移或恢复耗尽不发布部分 Admission。Outcome 明确证明
没有获取 credential material、没有持久化秘密、没有创建 Session 且 cleanup complete。本阶段无 Vault adapter、
真实凭据、登录请求、网络访问或状态变更。

## B4.2 Vault credential lease、Approval binding 与隔离 Session

B4.2 将 `Credential Lease` 与 `Isolated Test Session` 固定为独立于 B4.1 Admission 的两个领域边界。Admission
仍然不是 bearer capability；Session Plan 必须重新绑定 active Admission、Record、Test Identity、Credential
Reference、Scope/version、精确 Target、单一用途和角色，以及排除 `requested_at` 后稳定的 exact Action digest。
Action 必须声明 credential use，read-only 用途禁止 state mutation，state-change 用途则必须显式声明 mutation；
external callback、Submission 和 untrusted build 一律在本纵切拒绝。

执行前由既有 `PolicyEngine` 以当前时间重放 Action，`USE_REAL_CREDENTIALS` Approval 必须同时匹配 Engagement、
Target、Scope policy version、Action digest、granted 状态和有效期；state-change 还需第二份同摘要的
`MUTATE_TARGET_STATE` Approval。任何 Approval 缺失、过期、摘要或 Target 漂移都发生在 Vault acquire 前，因此
不会触达秘密材料。执行前后还会重读 active Test Identity Admission，使撤销和过期立即生效。

当前 `OfflineCredentialVault` 只接受 `fixture:` 材料，Lease 是不可序列化的私有 bytearray；
`OfflineIsolatedSessionAdapter` 不创建 socket、不发起认证、不改变状态，只消费一次只读 view 并生成同 Plan
内容绑定的瞬时 Session handle。成功、adapter 拒绝和超时路径都在 `finally` 中清零 Lease 与 Session material；
持久化 receipt 只有 digest、时间、单次使用和 cleanup proof，不含用户名、密码、Cookie、Token、Vault path、
认证响应或 Session material。

独立 SQLite ledger 使用 STARTED/COMPLETED checkpoint、幂等重放和最多三次显式恢复。只有审批、绑定、单次
Session 和双重清理均成立才原子发布 Outcome；中断或超时保留 STARTED 且不发布部分 receipt。本阶段没有真实
Vault、真实账户、登录请求、网络访问、状态变更、模型调用或攻击；后续真实认证流程必须作为新的隔离纵切重新
获得授权与运行期证明。

## B4.3 local authentication、logout proof 与 role differential

B4.3 只在纯内存 `local_offline_fixture` 中执行受控认证动作，不访问真实 Target。每个角色必须使用不同的
Test Identity、不同 Admission 和各自的单次 Credential Lease；B4.2 的 Action Approval 绑定进一步加入
authorization-context digest，把 Admission、identity、purpose 和 role 封入 Action digest。Session ledger 对
Admission 建立唯一消费约束，不能通过更换 Plan 或幂等键重复取得 Session。

`OfflineRoleAuthenticationAdapter` 只接受与 credential ref 的内存 proof 匹配的 `fixture:` 材料和 read-only
role-observation purpose。它在一个短生命周期
内存 handle 中记录 fixture 的 allow/deny 决定，不创建 socket、不保存认证响应，并在 B4.2 finally 路径完成登出与
材料清零。只有 handle 已释放、已清零且 post-logout reuse 明确被拒绝时，才能生成 `SessionLogoutProof` 和无秘密的
`LocalAuthenticationObservation`；B4.2 receipt 会如实记录本地 fixture authentication 已执行，但仍固定证明没有
网络请求和目标状态变化。

`RoleDifferentialService` 只比较两个已完成且 cleanup complete 的 Session，它要求两个不同身份/角色绑定同一 Scope、
Target、fixture 和剥离 authorization context 后的 exact Action intent。结果只有 `same` 或 `different`，不推断哪一
角色“应当”拥有权限，也不自动宣称越权。Observation schema 固定禁止 Candidate、Finding 和 vulnerability claim；
后续若要形成漏洞假设，仍必须经过独立 Evidence Requirement、Validation 和 Critic 流程。

角色比较使用独立 STARTED/COMPLETED ledger，支持幂等、最多三次显式恢复和无部分发布。身份撤销、Scope/Target、
fixture、Action、身份/角色、Session Outcome、认证 Observation 或 logout proof 漂移都会 fail-closed。本阶段没有
真实账户、真实 Target 登录、HTTP/浏览器请求、外部网络、状态变化、模型调用或攻击。

## B4.4 local business invariant 与 compensated state mutation

B4.4 在纯内存 `local_offline_fixture` 中固定第一条业务流程不变量：只有 publisher role 应能把一个 draft 变为
published。`OfflinePublicationFlowAdapter` 只接受与 credential ref proof 匹配的 `fixture:` 材料、
state-change purpose 和精确 `fixture_publish_draft` action；不创建 socket、不接触真实 Target，也不接受任意写动作。

执行继续由 B4.2 Session 控制，exact Action 必须同时具备 `USE_REAL_CREDENTIALS` 与
`MUTATE_TARGET_STATE` Approval。Adapter 在内存权威状态上实际执行 draft→published，记录变更前/后内容寻址快照，
并在 Session close 中以补偿动作恢复 draft。`StateRestorationProof` 要求恢复前后 semantic digest 相同、修订号在
before→mutated→restored 间严格单调；只有状态确实变化、恢复已验证、Session/Lease 均释放清零时才能物化 Outcome。

通用 Session cleanup 使用嵌套释放：恢复证明阶段即使抛错也必须继续清零 Credential Lease，保持 STARTED checkpoint
且不发布完成 receipt。未授权角色若被安全 fixture 拒绝则不发生变更；故意未强制策略的 fixture 只产生
`violated` Signal，schema 固定禁止 Candidate、Finding 和 vulnerability claim。独立 materialization ledger 支持
幂等、超时、最多三次显式恢复和无部分发布。当前证明只覆盖进程内合成 fixture，不构成 Docker/OS 隔离、真实账号、
真实 HTTP/浏览器状态变化或生产回滚证明。

## B5.1 offline A3 Adaptive Flow qualification

B5.1 首先固定资格协议，不把 B1 的“两轮测试曾经通过”直接当作 A3 产品声明。`AdaptiveFlowQualificationPlan`
只引用一个权威 Flow、最终 checkpoint 和按顺序排列的至少两份 `ReplanExecutionReceipt`；不包含原始 Target URL、
命令、凭据、模型输出或执行参数，也不能请求 A4 Campaign 或新增执行权限。

资格服务逐轮重读 Flow、Scope、Admission、Action、Observation、源/结果 checkpoint 和 Receipt，要求每轮都使用同一
Target，源 Observation 与权威 checkpoint 一致，下一轮从上一轮结果继续，exact Approval 已证明，Observation
成功、脱敏且 cleanup complete。最终 Flow 必须 cleanly terminal，不得存在 started Action、reserved Replan 或外部
预算预留。单轮、乱序、缺失 Receipt、Scope 撤销、未终止 Flow 和来源漂移均在资格 checkpoint 前拒绝。

通过后只产生内容寻址 `AdaptiveCoverageLedger` 和 `A3_ADAPTIVE_FLOW` 资格事实；Ledger 记录实际覆盖的 Action kind、
test class、Observation 和 cleanup，不宣称未覆盖面安全，不创建 Candidate/Finding，也不把 Flow 升级为 A4。
独立 ledger 支持幂等、STARTED/COMPLETED、超时和最多三次显式恢复。本纵切只达到 `offline_tested`，未运行真实
容器、私网靶场、模型或攻击；实际隔离 A3 准入和 A4 Campaign 资格仍是后续工作。

## Next development sequence

Authorized Red Team 的当前后续顺序以 `docs/DEVELOPMENT-PLAN.md` 为准：共享 S1 与 B1 已关闭，B2.1 已完成精确
路径 GET，B2.2 已把已封存 OpenAPI 文档降为无执行权的摘要发现，B2.3 已完成显式人工选择与原子 Seed promotion，
B2.4 已把 sealed GraphQL SDL 降为无执行权、无参数披露的 Query field 摘要。B2 至此达到 `offline_tested` 并关闭；
B3.1 已为未认证敏感数据暴露固定首个版本化 Evidence Requirement，并以确定性 Assessment 区分 Candidate 资格、
负例和不确定，仍不创建 Candidate 或 Finding。B3.2 已从权威 sealed GET 物化脱敏 Observation/redaction/Cleanup
Assertion，并证明单批来源不能自证独立 replay 或 Critic。B3.3 已只读比较两份独立 sealed GET materialization，
物化 replay/redaction Validation Assertion。B3.4 已消费与 Validation 分离的完整类型化审查，物化四项 Critic
Assertion；完整链只能给出 Candidate 资格，仍不创建 Candidate 或 Finding。B3 至此达到 `offline_tested` 并关闭。
B4.0 已完成授权派生资产发现与三态准入；B4.1 已完成控制方测试身份的 opaque admission contract；B4.2 已完成
离线 Vault credential lease、exact Approval binding 与隔离 Session 生命周期；B4.3 已完成本地 fixture 认证、登出
清理与角色差异 Observation；B4.4 已完成本地业务不变量、双 Approval 状态变更和可验证补偿恢复。下一步推进隔离
靶场 A3/A4 资格。任何新
Action 仍必须重新封存并经过 Scope、预算、Policy 和必要 Approval；不加入 crawler、字典枚举、公网扫描、动态
的未授权 Target 扩展、真实第三方账户、横向移动或持久化。
