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

## 3. 网络策略

网络允许规则以解析后的 IP 和端口执行，而不仅是 URL 字符串：

1. Tool Broker 验证 URL 属于 Scope。
2. 独立解析 DNS，拒绝未授权地址范围。
3. Runner 在网络层配置 egress allowlist。
4. 发起连接后记录实际对端 IP。
5. 重定向每一跳重新判定。

OAST、Webhook 或外部回连使用一次性 Approval 和一次性 callback 标识，不能开放通用互联网出口。

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
