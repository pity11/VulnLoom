# 安全与沙盒设计

## 1. 威胁模型

VulnLoom 假定以下内容都可能恶意：

- 被测仓库、依赖、构建脚本和附件。
- 网页、API 响应、错误信息和日志。
- LLM 输出以及网页中的 Prompt Injection。
- Worker 生成的脚本、路径和工具参数。
- 伪装成 Evidence 的模型叙述。

需要保护的资产包括宿主机、个人文件、模型密钥、披露平台账号、其他 Engagement 数据、原始 Evidence 和授权方隐私信息。

## 2. Sandbox Profile

### Static Profile

- 无网络。
- 源码只读挂载到固定路径。
- 根文件系统只读；`/tmp` 和输出目录使用限额 tmpfs/volume。
- 非 root，`cap-drop=ALL`，`no-new-privileges`。
- 禁止挂载 Docker socket、SSH agent 和用户主目录。
- 默认不执行目标代码。

### Validation Profile

- 每次 Validation Run 创建新容器。
- 只加入该 Target 的专用网络。
- 默认无 DNS、无互联网出口、不能访问宿主网关和云元数据地址。
- 只开放 Scope 声明的目标地址、端口、协议和速率。
- 限制 CPU、内存、PID、文件大小、打开文件数和墙钟时间。
- 结束后销毁可写层；Evidence 经 Broker 单向导出。

### Report Profile

- 无目标网络和互联网。
- 只读挂载脱敏 Evidence Bundle。
- 不能读取原始 Cookie、Authorization 和身份数据。
- 输出只能写到该 Report 的临时目录。

M4.1 已将这些要求编码为类型化 Profile 与 Runner preflight。M4.3 的 Docker adapter 已在真实
rootless Linux 容器中证明 network-none Profile 的非 root、只读根、只读源码、cap-drop、
NoNewPrivs、限额 tmpfs、无默认路由、无 Docker socket、超时终止与容器清理。生产门禁同时
要求 seccomp、cgroup v2 与可执行的内存、CPU quota、PID 控制。Target-only egress 不在 Worker
中实现，Runner 会 fail-closed 拒绝该模式。

## 3. 网络策略

网络允许规则以解析后的 IP 和端口执行，而不仅是 URL 字符串：

1. Tool Broker 验证 URL 属于 Scope。
2. 独立解析 DNS，拒绝未授权地址范围。
3. Runner 在网络层配置 egress allowlist。
4. 发起连接后记录实际对端 IP。
5. 重定向每一跳重新判定。

OAST、Webhook 或外部回连使用一次性 Approval 和一次性 callback 标识，不能开放通用互联网出口。

M4.2 的 Broker 已实现逐跳 Scope/Profile 判定、DNS pin、peer IP 一致性、危险地址拒绝和
redirect 重新授权。M4.3 新增 Broker-owned live HTTP/HTTPS adapter：只连接策略选择的数字 IP，
不读取代理环境，TLS 仍校验授权 hostname，实际 peer 回传 Broker 复核，响应经过大小限制和脱敏
后才进入 Evidence Store。真实 socket 测试已证明 Host 与 pinned peer 分离以及单向脱敏 Evidence
数据流。专用 rootless Linux 准入测试进一步证明 Worker 无法访问 live sibling container 或 daemon
gateway，Broker 在 transport 前拒绝实际 gateway，并在 redirect 第二跳阻止 DNS 漂移到 metadata。

M4.4 将 Runner 与 Broker 接入事务性 Validation Orchestrator。所有绑定在 `STARTED` checkpoint
之前重新验证；Runner 未完成时不会继续 Broker，Broker 的拒绝、缺审批和超时不能被 judge
覆盖。执行成功默认仍是 `INCONCLUSIVE`，judge 引用非本次采集 Evidence 时整个流程 fail-closed。
未完成 checkpoint 不自动重放，避免重复副作用。

M4.5 的确定性 HTTP 裁决要求人工计划提前绑定确切 call、状态码和最终原始正文 SHA-256。
正文不进入 Broker result；普通路径只接收摘要与脱敏 Evidence。裁决前 Evidence Store 使用
`O_NOFOLLOW`、常规文件/大小检查和内容摘要复核，损坏、缺失或符号链接对象都会 fail-closed。
任何断言不匹配都保持 `INCONCLUSIVE`，不能由状态码单独触发复现结论。
Judge 默认只接受 live pinned HTTP Registry 摘要；offline Registry 只能在测试代码显式注入其摘要，
不能使用生产默认配置形成复现结论。

## 4. 凭据策略

- Worker 环境从空环境开始，仅注入显式白名单变量。
- 模型密钥只存在于 Control Plane 的 Model Adapter。
- 平台 token 只存在于未来的 Submission Adapter。
- 测试身份通过 Broker 中的 opaque credential reference 使用，Agent 看不到原始值。
- 日志和 Evidence 写入前统一清理 Header、Cookie、Token、私钥和 PII。
- secret scanner 只是补充门禁，不能替代凭据不下发的架构。

## 5. 不可信附件

附件先进入 quarantine：

- 按流下载并限制原始大小。
- 计算 SHA-256 和 MIME/格式识别。
- 解压前枚举成员；拒绝绝对路径、`..`、设备文件和越界符号链接。
- 限制成员数量、单文件大小、总展开大小和压缩比。
- 解压目录使用 `noexec,nodev,nosuid`。
- 分析前生成 manifest；未知二进制不得在宿主机执行。

M1 实现采用逐成员解压，不调用 `extractall()`；拒绝符号链接、硬链接、设备文件、命名管道、路径大小写/Unicode 归一化冲突和加密 ZIP。成功结果通过原子重命名发布为只读 Target Snapshot，失败或超时清除未完成目录。

## 6. Evidence 安全

- Evidence 采用内容寻址，记录来源、时间、Target 版本、工具版本和策略版本。
- 原始 Evidence 与模型可见摘要分离。
- 普通 SQLite/FTS 只索引脱敏摘要，不保存完整 HTTP 包。
- 报告引用 Evidence ID，不复制隐私数据。
- Evidence 变更会产生新对象，不能原地覆盖。

## 7. 安全测试清单

- 子 Agent 无法读取父进程密钥。
- Worker 无法访问宿主文件、Docker socket 或其他 Target 网络。
- DNS rebinding、重定向和 IPv6 不能绕过 Scope。
- 恶意 tar/zip 不能写出 quarantine。
- Prompt Injection 不能改变工具白名单或 Approval 状态。
- 超时会终止整个进程组并清理容器、网络和 volume。
- 原始凭据不进入日志、FTS、报告或错误消息。
