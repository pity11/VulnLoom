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

M5.2 报告服务不读取或复制 Evidence 正文，只在状态变化前用 `O_NOFOLLOW`、大小和摘要复核对象。
报告文本统一经过内置脱敏器，Markdown 进一步转义 HTML 与图片/链接控制字符，避免本地预览触发
嵌入式外部资源。Markdown/JSON 写入随机临时目录后原子发布为只读内容寻址对象；失败会清理临时
目录。checkpoint 只保存 plan digest 和已脱敏 outcome，不保存原始报告计划文本。该路径没有网络、
披露凭据或 Submission adapter。

M5.3 的人工审批不是自由文本或模型结论，而是绑定 reviewer、Report/artifact/Evidence/Scope/Diff
摘要和期限的类型化命令。SQLite 对每个 review plan 只接受一个决定，内容变化、并发冲突、过期批准
和损坏 artifact 均 fail-closed。本地导出只在受控 Report Store 内生成新内容对象，不接受任意路径；
CLI 不包含网络调用。`SUBMITTED` 仍不可达，平台 token 也未引入任何 Worker 或 Report 流程。

M6.1 benchmark 服务只读取严格 schema 校验、内容寻址的本地 suite、observation、baseline 和
policy，不拥有 Runner、Broker、Disclosure adapter 或任何 credential provider。评测协议再次编码
Candidate→Finding 门禁，无法表示绕过 Validation、Critic、promotion 或 Evidence 完整性的 Finding。
结果在受控 store 中经临时目录原子发布，读取使用 `O_NOFOLLOW`、常规文件与大小/摘要检查；写入失败
清理临时目录，遗留 STARTED checkpoint 必须人工恢复。普通 CI 只重建本地 fixture 并离线计算指标，
不下载外部 benchmark。

M6.2 不提供外部数据获取器。目录 snapshot 在 manifest 生成与 import 时都拒绝 symlink、特殊文件、
非归一化/碰撞路径和资源超限；所有读取使用 `O_NOFOLLOW`，规范化之后再次全量复核以阻止 TOCTOU。
ZIP/TAR 不由该 adapter 处理，不能把未检查归档直接当作 snapshot。BountyBench adapter 不读取脚本和
报告正文；AutoPenBench 的 flag、task 与潜在凭据不会写入 suite、artifact、checkpoint、事件或 CLI
摘要。adapter 没有 Runner/Broker/Docker/网络依赖，ImportPlan 也没有 URL、token 或 Submission 字段。

M6.3a 只导入预先生成的本地 CodeQL/Trivy/Checkov/Kubesec JSON/SARIF。输入使用 `O_NOFOLLOW` 打开，
限制大小与解析时间，对实际解析字节复核 SHA-256，并在规范化后再次复核文件以关闭 TOCTOU 窗口。
重复 JSON key、非法 UTF-8、symlink、特殊文件、陈旧 CWE map、数量超限与超时均 fail-closed。

工具原始 message、Trivy Secret match、Kubesec object/selector/reason 和原始 rule ID 不进入只读 artifact、
checkpoint 或 CLI 摘要；只保留消息/规则摘要和必要的安全相对位置。Observation schema 不含执行、网络、
凭据、Approval、Candidate、Finding、Validation 或 Critic 权限，因此工具命中不能绕过生产门禁。

M6.4d 的 CodeQL 查询不会直接写入密封数据库。`CodeQLSnapshot` 绑定 Target/version/Manifest、预建 DB、
query pack、suite、预编译查询和全部文件摘要；原始对象只读挂载并在容器清理后复核。精确 wrapper 使用
no-follow 复制并核对文件数、entry 数和总字节，只把副本放入 Runner 有容量上限的 output tmpfs。
CodeQL cache 只能写 `/tmp`；SARIF 禁止 file contents、snippets 和 query help，并在成功退出后才送入
有界 attached capture。复制/查询/捕获/导入/复核/容器删除任一步失败，外层执行都不能完成。

M6.4d 不提供 CodeQL 下载、pack 安装或 database create API。数据库构建和任何 Target 编译继续要求
独立 `RUN_UNTRUSTED_BUILD` Approval；Admission 行为 fixture 只证明隔离和清理，不冒充真实 CodeQL
bundle、许可、query pack 或预建数据库的运营资格。

M6.5 只聚合权威 Docker store 中已完成的 M6.4 执行证明，不启动分析器。资格服务要求完整 case×analyzer 矩阵，并在 checkpoint
前重新计算 execution plan、registration、outcome、ObservationSet、suite、alignment 与 evaluation plan
摘要；同时复核 Target/version/Manifest、Scope、完成状态和 cleanup。失败、超时、取消、清理不完整、缺项、
重复或漂移均拒绝，且不会留下 qualification/evaluation checkpoint。

资格 outcome 只能携带既有 M6.3b gate 结果，不能创建 Candidate/Finding 或改变报告状态。该层没有 Runner、
Docker、Broker、socket、credential、Target build、secret scanner、Approval 消费或 Submission 字段。

M6.6 在 rootless Admission 中复核完整四工具组合。一个 case 的全部 execution binding 必须共享 Target
ID/version、Manifest 与 Scope ID/version；任一 analyzer 缺失或 completed outcome 与权威 store 不一致时，
qualification 和 evaluation store 都必须保持为空。完整组合仍只产出评测指标，不授予工具命中任何
Candidate/Finding、报告或 Submission 权限。

M7.1a 的 Agent Runtime 只接受离线 replay adapter。模型注册和运行计划不携带 endpoint、API key、token
或任意环境变量；请求只包含摘要、role、显式工具白名单和预算。模型输出被视为不可信数据，必须满足固定
schema、身份、token、墙钟和字节上限。工具提案只产生参数摘要，不执行 Runner/Broker，也不能消费 Approval
或触发领域状态。原始响应与原始参数不落 checkpoint；adapter 中断后的 STARTED 记录拒绝自动重放。

M7.1b 新增的 credential reference 只允许 Control Plane provider 读取启动时显式准入的精确环境变量；未注册
引用在访问环境前拒绝，且 provider 不复制完整宿主
环境。读取值进入不可序列化的 lease 缓冲，正常、错误和超时路径都在返回前归零；缺失/错误凭据只产生通用
adapter failure 并保留 STARTED checkpoint。local-fake adapter 无 socket/URL/SDK，凭据、引用和无关环境值
不进入 Worker request、outcome、SQLite 或错误消息。此处不声称 Python 进程内存可抵御宿主级取证；live
provider 仍需独立进程/网络/日志与响应捕获 Admission。

M7.2 只允许与 Task `input_refs` 完整同序匹配的瞬时 source 进入 assembler，并由可信代码执行规范化、控制
字符拒绝和 `builtin-v2` 脱敏。原始/脱敏单片、总字节、fragment 数和墙钟都有独立上限。snapshot 中所有
内容固定标记为 untrusted，因此 prompt injection 文本不能修改工具白名单、Approval 或 Scope；真正工具
授权仍只在 Broker/Sandbox。上下文对象只读、no-follow、内容寻址并绑定 Task/Target/Scope/redaction policy。
M7.2 不读取完整认证响应或原始 Evidence body，也不声称脱敏器能替代上游最小化；未知敏感格式仍应在加入
context 前由人工或专用 normalizer 排除。绑定 snapshot 的 Runtime 如果没有显式 context store，或重读时发现
对象不可写性/内容/Task 绑定漂移，会在 STARTED checkpoint 前拒绝。

M7.3 的 system message 来自固定内置模板，user message 是重复键拒绝的确定性 JSON。脱敏 context 只能位于
`untrusted_context` 字符串字段；即使正文包含伪造 control JSON 或“忽略前文”，也不能修改 envelope 的
工具白名单、预算、schema 或 `can_execute_tools=false`。Runtime 继续独立验证工具提案，Broker/Sandbox 才是
真正权限边界。renderer 对 system/user/总字节和墙钟分别设限，并在 checkpoint 前拒绝首步渲染失败。
adapter 和 SQLite 只保留 envelope digest，不持久化 message/context 正文。

M7.4 将 provider 出口配置收缩为内容寻址的 Admission 对象：exact canonical DNS hostname、TLS 443、单一
path、credential reference、adapter digest、请求/响应上限和 timeout。当前 schema 固定
`network_enabled=false`、redirect/proxy 关闭、DNS revalidation 开启、raw response 不持久化且只允许一个
attempt。StepRequest 与 Message Envelope 的 Task/step/context/schema/tools/output 任一绑定漂移，都在凭据读取
前拒绝。瞬时 provider request、credential lease 和 raw response 使用可归零缓冲；正常、拒绝和超时路径均
强制清理。attempt/receipt 与 SQLite 只含摘要、计数、稳定错误码和清理证明。

M7.4 的 `admission_fake` 不解析或连接 hostname，不创建 DNS/socket/HTTP/SDK/proxy，也不声称真实 TLS、DNS
rebinding、速率限制或进程级隔离已经通过生产准入。真实 provider 出口仍必须通过独立 Admission；不得通过
修改 schema 或替换 adapter 绕过该里程碑。

M7.5 的 live adapter 只存在于可信 Control Plane。生产 Admission 固定 exact hostname:443、global-only DNS、
固定 implementation digest、单次 POST、单 attempt 和每分钟请求上限；loopback Admission probe 则固定
`.test`、loopback-only、exact port 与 sealed CA。每次调用都重解析 hostname，并要求全部 DNS answer 满足同一
IP policy，阻止私网/metadata 混入。子进程连接 numeric IP，同时以 admitted hostname 做 TLS SNI/certificate
校验并复核实际 peer，因此连接阶段不会再次按 hostname 解析。

provider child 使用固定 module、Python `-I`、空白名单环境、`/` cwd、close-fds、无 shell、新进程组、资源
上限、stderr 丢弃和父层 bounded stdout。credential 不进入环境或 argv，只在 parent lease 和 stdin frame 中
短暂存在；frame 在写入后归零，child 退出即销毁其地址空间。超时、overflow 和异常路径强制杀死/回收进程组。
response 在 child 流式设限，并由 parent 再次限长、验证 peer/TLS、strict JSON 与 provider/model identity，随后
归零。日志/checkpoint 只保留 endpoint-free digests、peer IP digest、TLS version、计数、状态和 cleanup proof。

该边界不允许 arbitrary URL/header/method、redirect、proxy、compression、自动 retry 或 SDK。Phase 3 只用
loopback TLS fixture 证明进程与 socket 行为，不证明任何公网 provider 的可用性、服务条款、数据驻留或运营
授权；生产 exact-host Admission 必须由运营方单独签发。

M7.6 将“单独签发”变为代码边界。只有本地受信 `AgentProviderEgressIssuerPolicy` 明确允许的 provider、networked
mode 和期限才能产生 grant；no-network fake、错误用途、未知 issuer 与超期申请不能进入 STARTED checkpoint。
grant 精确绑定 Admission、credential reference 与 adapter digest，并由 model registration 绑定其 ID。

grant/revocation 对象原子发布、内容寻址且只读，每次读取执行 no-follow、常规文件、不可写、大小、schema、ID
和摘要复核。ledger 对签发/撤销使用独立 STARTED/COMPLETED；遗留操作、冲突、到期或 revocation 全部拒绝。
live adapter 在每次 DNS、速率计数、凭据读取和子进程创建之前重读 lifecycle，因此撤销不会依赖长驻内存缓存。
本地 SQLite authority 是可信 Control Plane 状态，不是跨主机密码学签名系统；M7.6 不引入远程 signer key、
provider SDK、公开调用入口或新的 Worker 权限。

M7.7 把 live wire protocol 收缩到内容寻址的 `openai-responses-v1` codec。live registration 必须绑定 exact
codec ID 和 Admission path；offline/fake adapter 不能携带 codec。encoder 没有任意参数入口，固定关闭 store、
stream 与 provider tools，并只发送已验证的 system/user envelope 和 strict decision schema。

decoder 只接受 exact model 的 completed assistant `output_text`，并拒绝 incomplete、refusal、native tool
call、annotation、多输出、重复 JSON key、未知字段、超限与超时。嵌套文本必须再次通过
`AgentDecisionPayload`；任何工具提案仍无执行权。codec 不记录 raw request/response，继续复用 M7.5 的缓冲
归零、bounded capture 和 digest-only receipt。该里程碑不授权公网 Provider、真实密钥、SDK、流式会话或
Submission。

M7.8 不把模型输出提升为可执行调用。Agent 只能提交一个预承诺 Broker call 的 digest；可信 Control Plane
独立构造完整 typed `BrokerCall`，handoff 在 checkpoint 前从权威 Agent store 重读 `tool_proposed` outcome，
验证 exact Task/Scope/Policy/Profile/Registry/tool/budget/deadline 和 commitment。任何摘要、role、call 或
checkpoint 漂移都在 DNS、凭据与 transport 前拒绝。

实际执行继续进入既有 Tool Broker，因此 network grant、DNS/peer pinning、metadata 拒绝、credential admission、
状态变化 Approval 与请求预算不会由 Agent 绕过。handoff 不接收 socket、Docker、adapter 或 secret。首次
`approval_required` 仅允许一次绑定前序结果的重试；completed、denied、failed、timed-out 或遗留 STARTED
均不能自动重放。

成功只产生 digest-only `AgentToolObservation` 和 Evidence refs；URL、header、body、credential、完整响应与
Agent 原始参数不进入 handoff checkpoint。Observation 没有 Candidate/Finding/Submission 字段，不能改变领域
状态。Phase 3 的 live composition 只连接临时授权 fixture，不增加公网能力。

M7.9 只允许 completed handoff 的 Observation 进入一次后续 Agent run。可信服务从 root Agent store、handoff
store、Evidence Store 和只读 context store 逐项重读；调用方不能提供 transcript、Evidence 正文或新的授权
字段。派生 Task 继承 exact engagement/Target/Scope/Policy/Profile/Registry/model/deadline，allowed tools 为空、
tool-call budget 为零，model/wall budget 只能减少。

Evidence 按 exact ref 使用 no-follow、大小和 SHA-256 校验读取，并再次经过固定脱敏器；即使响应正文包含
prompt injection，它仍只作为 `untrusted_context`。缺失/链接/摘要漂移、context 可写或漂移、预算耗尽、
deadline、非 completed handoff、cleanup 不完整、Observation 重放和遗留 STARTED 都在 provider 调用前
fail-closed。continuation 不能产生可执行 tool intent、Approval、Candidate/Finding 或 Submission；再次工具提案
只会形成稳定失败。

M7.10 只在 M7.9 之外增加一个固定第二工具轮次，不提供通用 Agent loop。第二轮 Task 的权限、绝对 deadline
和剩余预算从权威首轮链派生；模型只看到可信 control 中有限、内容寻址的 opaque call commitments。每个
commitment 对应控制面预构造且经 Broker preflight 的 exact read-only 调用，模型不能生成 URL、HTTP 参数、
credential、Scope 或 network grant。

Session 在每个外部动作前重读 Agent/handoff/Observation/Evidence/context checkpoint 并扣减累计预算；未列
commitment、重复消费、跨轮漂移、第三次工具提议、超时、清理不完整和遗留 STARTED/RESUMING 均 fail-closed。
Approval-required 只进入持久等待，不自动审批或轮询；唯一恢复路径是带有效 Approval 的 M7.8 attempt-2，且
不会扩大两次成功 tool-call 上限。Session outcome 没有 Candidate/Finding/Report/Submission 状态转换能力。

M7.11 在离线路径中重新打开 completed Session 及其全部 Agent、handoff、continuation 和 Evidence checkpoint，
并独立重算轮次顺序、exact call commitment、Approval decision digest、Target/Scope 绑定、累计预算和 cleanup。
调用方不能提供 transcript、Evidence 正文或模型摘要；缺失、分叉、重复、跨 Session 重放、摘要漂移、预算回增、
未清理或 Evidence 完整性失败都会在审计 artifact 发布前 fail-closed。

审计 bundle、SQLite 与只读 JSON/Markdown 只含 digest、ID、计数、稳定终态和 Evidence ref，不含 URL、credential、
provider request/response、工具参数或 Evidence 正文。确定性 recommendation 没有领域状态命令，不得替代
Validation、Critic、Finding promotion、人工 Approval 或 Submission。

M6.3b 的 alignment 是评测标签，不是领域授权。只有显式列出的 match 才参与 recall；同 CWE 不自动匹配。
服务在 checkpoint 前复核 suite/case/Target/ObservationSet/truth/CWE 全部绑定，并限制 set、Observation、
match 数量和墙钟时间。跨 case、摘要漂移、一个 Observation 多 truth、CWE 不相容和不完整输入均拒绝。

评测结果只有指标、violation 和内容摘要，不包含原始分析器消息或执行权限。required-analyzer、完整矩阵、
逐工具阈值和 baseline 防止聚合指标掩盖单工具退化。整个路径没有 Target 文件访问、Runner、Broker、
Docker、socket、credential、Approval 或状态机调用，无法创建 Candidate/Finding 或触发 Submission。

M6.4a 新增的是 source-only 执行协议，不是新的任意命令入口。Registration 必须固定绝对可执行文件、完整
argv、exact image ID、规则和 adapter 摘要；argv 禁止占位符、URL 和运行时追加参数。Analyzer Worker 使用
只读源码、无网络、非 root、无 capability、只读根和显式空基线环境，Profile/Registry/Policy/Target 任一
摘要漂移都会在 checkpoint 前拒绝。

M6.4a concrete service 只接受 Offline Runner，因此不会启动进程、容器、Docker 或 socket，也不会生成
分析器输出。未来真实执行必须复用 M4.3 rootless 准入并证明输出提取与清理；任何目标 build script 都不
属于 source-only 模式，必须新增精确 `RUN_UNTRUSTED_BUILD` Approval 校验后才能分配 Runner 资源。

M6.4b 的真实执行只准入固定 Checkov/Kubesec factory，并复用 M4.3 Docker 强制边界。镜像必须由控制面
预先解析为 exact ID；运行期固定 `--pull never` 和 `network=none`，不持有 Docker socket、宿主凭据或
Broker 权限。attached stdout 先进入有界可信临时文件，再经 no-follow、常规文件、大小/摘要复核和原子
只读发布；失败、超时、OOM、超限或非准入退出码都不返回输出引用。只有 M6.3a 导入和脱敏 artifact 完成
后外层 checkpoint 才完成。Phase 3 Admission 在 rootless Linux 上真实运行两种工具；本地 rootful
Docker Desktop 结果只算功能回归。

M6.4c 只增加固定 Trivy 0.73.0 vulnerability filesystem scan。离线 DB 必须先在执行边界之外获取，
再密封为只含 `db/metadata.json` 与 `db/trivy.db` 的只读内容寻址对象；schema、路径、文件类型、权限、
大小和摘要在 checkpoint 前及容器清理后各复核一次。Worker 只能看到只读 `/workspace/analyzer-data`，
argv 固定 `--scanners vuln` 以及 offline/update/version/telemetry 禁用参数，因此 secret、misconfiguration
和 license scanner 均不可启用。DB 下载、Target build、Broker、Docker socket 和 Submission 仍不在执行 API 中。

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

M8.1 的人工 Validation Intake 只持久化 Audit/Candidate/ValidationPlan 摘要、稳定决定和 reviewer identity。
它不依赖 Runner 或 Broker，不能从 Agent summary、tool intent 或 Evidence 正文生成执行参数，也不能把 accepted
解释为 Approval、Candidate 状态迁移或已执行 Validation。所有权威对象在 checkpoint 前重新打开并复核。
