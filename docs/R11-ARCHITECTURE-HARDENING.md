# R11 整体架构审查与压力加固

状态：R11.4，2026-09-20。本文记录 R11.1–R11.3 关闭后的跨聚合审查、已修复风险和剩余边界。

## 审查范围

审查从父 `RedTeamFlowPlan/Checkpoint` 开始，沿 `AttackGraph → AttackChainPlan → Approval/Policy →
AttackActionCommand → trusted adapter/Broker → Observation → Cleanup → Attack Path Report` 追踪控制流、数据流、
SQLite 事务、幂等恢复和失败分支。重点不是增加攻击能力，而是验证以下安全不变量在并发、超时、Kill、崩溃和
持久化篡改时仍成立：

- 所有动作共享父 Flow 的 `max_actions`，不能从不同入口分别超卖；
- 状态变更或状态不确定后，任何失败都不能伪装成已清理终态；
- Cleanup 只能是原图末节点，仍需精确执行批准和 Policy 批准；
- Worker 不取得凭据、任意网络、payload、header、Cookie 或 Provider token；
- 报告只能投影权威成功链和 Evidence，不能反向授权动作或直接生成 Finding。

## 加固后的控制流

```text
approved Scope + running Flow checkpoint
                 |
                 v
        seal finite AttackGraph
                 |
                 v
 parent Flow budget reservation -- fail closed / idempotent retry
                 |
                 v
 secondary Chain reservation + PLANNED -> RUNNING
                 |
      exact action Approval + Policy + prerequisites
                 |
                 v
 trusted adapter/Broker -> redacted Observation -> transactional checkpoint
                 |
       +---------+----------------------------+
       |                                      |
 ordinary success                      failure/timeout/kill/drift
       |                                      |
 objective evidence                   CLEANUP_REQUIRED
       |                                      |
       +--------------- sealed Cleanup <------+
                               |
                      cleaned terminal state
                               |
                  Evidence-backed defensive report
```

## 已修复发现

### 1. 父 Flow 动作预算可被跨入口超卖

原实现只在 `prepare()` 读取一次 `checkpoint.actions_used`。多个 Chain 可基于同一 checkpoint 同时通过预检，普通
Recon 也看不到 Chain 的计划动作数。现在 Chain 在创建前以 `chain_plan_id` 在父 Flow ledger 持久化完整动作预留；
Recon claim 和新预留均以 `BEGIN IMMEDIATE` 串行检查：

```text
actions_used + started_actions + external_reservations + requested <= max_actions
```

Chain ledger 再执行第二层按 Flow 聚合的预留检查。父预留先于 Chain 创建，因此跨库崩溃最多留下可由同一 plan
幂等恢复的保守预留，不会生成无预算的可执行 Chain。

### 2. 普通 deadline 到期后无法补偿 Cleanup

`AttackChainPlan` 现在同时封存普通动作 deadline 和 Cleanup deadline。清理窗口必须严格晚于普通窗口、最长 300 秒，
且不得超过 Scope 或父 Flow 的有效期。非 Cleanup 仍在普通 deadline fail-closed；只有图中唯一 Cleanup 可使用清理
窗口。trusted live adapter 的 Task deadline 和 admission expiry 使用相同边界，避免服务层与传输层语义漂移。

### 3. Kill/Cancel/checkpoint 漂移可能掩盖未清理状态

父 Flow 停止或前进时，Chain 会检查已成功的 state-change 节点和未完成的 adapter claim。没有潜在副作用时可终止；
存在已知或不确定副作用时只能进入 `cleanup_required`。中断 claim 与该状态转换在一个 Chain 事务中标记为 abandoned，
防止唯一 started-action 约束阻塞 Cleanup。

漂移后的 Cleanup 不是通用绕过：服务重新读取原父 checkpoint 和最新 checkpoint，要求同一 Flow、单调 revision、
不回退的 action 计数、原 observation 前缀、当前 Scope/version、未过期清理窗口，以及 Cleanup 自身的精确执行与
mutation Approval。其他 Action 继续拒绝。

### 4. 终态与防御报告可被结构合法但语义错误的数据伪造

checkpoint 反序列化现在复核失败计数与节点状态、Objective observation 必须属于成功节点、`planned` 的初始形态，
以及 `goal_reached` 的全节点成功形态。Attack Path Report 要求每个 Action 恰好对应固定 Detection Opportunity，
每个 Opportunity 恰好对应固定 Defensive Control，且 Evidence refs 与 path step 完全相同。

## 压力与失败矩阵

- 同一父 checkpoint 连续 25 次竞争超额 Chain，只有既有合法预留保留；
- 两个独立 SQLite connection 同时竞争只容纳一个 Chain 的预算，恰好一个成功；
- Recon 与 Chain 混合使用父预算，超过剩余额度时在 adapter 前拒绝；
- 已 started 但中断的 Recon 会计入后续预留检查；
- 普通 deadline 后、Cleanup deadline 前允许独立获批的补偿清理；边界时刻及之后零 adapter 调用；
- 已确认 mutation 后 Kill、不确定 mutation 中断后 Kill、父 checkpoint 前进均收敛到 Cleanup；
- 完成重放不重复 adapter 调用或重复预算；
- 篡改成功 checkpoint 和错误 detection/control 映射在模型边界拒绝。

## 剩余风险与明确边界

- 父 Flow 与 Chain 使用两个 SQLite ledger。当前顺序刻意选择“先保守预留、后创建 Chain”；极端进程崩溃可能留下
  不可用但安全的孤儿预留。未来若需要自动释放，应增加显式 reservation 生命周期和人工可审计恢复，不能静默回收。
- SQLite 事务解决同一共享数据库上的并发；多主机部署需要单写者或支持串行化事务的外部存储，不能直接复制文件。
- Scope 已撤销或清理窗口已过期时仍拒绝 Cleanup；系统保留 `cleanup_required` 事实供人工处置，不伪造完成证明。
- 本次没有增加 crawler、字典枚举、公网扫描、真实凭据、外部回连、横向移动、持久化、自动 Finding 或 Submission。

## 验证结果

默认离线套件：1514 passed、30 skipped，覆盖率 85.41%。Ruff、424 个 JSON Schema 解析和
`git diff --check` 通过。显式 R11 私网进程验收在本机因没有私有非回环 IPv4 而安全跳过；既有 R11.2 验收记录仍
保留，但本轮不把该 skip 声称为新的通过结果。未调用真实模型、未访问公网、未提交外部系统。
