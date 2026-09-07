# M9.15：真实模型最小接入

本入口只发送仓库固定的合成连通性消息（M9.15 Responses 或 M9.16 CUC PONG），不读取项目源码、Candidate、Evidence 或任意用户提示词。
它不运行 Agent 工作流或工具，不连接研究目标。通过表示固定结构化响应、传输及清理检查通过，
不表示模型的漏洞研究质量、目标验证能力或整个 pilot 已通过真实 Provider 验收。

## 准备独立出口配置

运营方先通过既有 `AgentProviderEgressAuthority` 签发当前有效的 `MODEL_INFERENCE` grant。
签发时必须审阅 exact provider hostname、credential reference、adapter、期限和配额；probe 的
prepare/run 命令都不会签发或续期 grant。运行时应始终使用同一套权威 egress store 与 probe ledger。

M9.15 Responses 配置由以下四个既有类型组成：`AgentModelRegistration`、`AgentProviderTransportAdmission`、
`ModelCredentialReference` 和 `AgentProviderCodecRegistration`。`ProviderProbeConfig` 进一步要求：

- `live_https` 和固定 subprocess HTTPS adapter、固定 Responses codec（CUC 专用分支见文末）；不允许代理、重定向或自定义 CA。
- 所有 provider、credential、codec、admission 身份精确匹配；registration 引用已签发的 grant。
- registration 的角色固定为 `reporter`，输出预算最多 512 tokens。
- 请求和响应各最多 32768 bytes，transport 超时最多 20 秒，codec 超时最多 2 秒，每分钟最多一次请求。

以下示例只构造无密钥的配置，不签发授权，也不调用网络。模型标识和 grant ID 必须替换为运营方审阅过的值；
示例 endpoint 来自现有 OpenAI Responses codec，不代表任意模型已完成兼容性验收。

```python
from pathlib import Path
from vulnloom.adapters import ModelCredentialReference
from vulnloom.agent_runtime import (
    SUBPROCESS_HTTPS_ADAPTER_DIGEST, AgentModelRegistration,
    AgentProviderCodecRegistration, AgentProviderTransportAdmission,
    AgentProviderTransportLimits,
)
from vulnloom.agent_runtime.provider_probe_models import ProviderProbeConfig
from vulnloom.domain.protocol import WorkerRole

reference = ModelCredentialReference.create(environment_variable="VULNLOOM_PROVIDER_API_KEY")
admission = AgentProviderTransportAdmission.create_live_https(
    provider_id="openai", hostname="api.openai.com", request_path="/v1/responses",
    credential_reference_id=reference.reference_id,
    adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
    limits=AgentProviderTransportLimits(
        max_request_bytes=32768, max_response_bytes=32768,
        timeout_seconds=10, max_requests_per_minute=1,
    ),
)
codec = AgentProviderCodecRegistration.create(provider_id="openai")
registration = AgentModelRegistration.create_subprocess_https(
    provider_id="openai", model="REPLACE_WITH_APPROVED_EXACT_MODEL",
    adapter_digest=SUBPROCESS_HTTPS_ADAPTER_DIGEST,
    credential_reference_id=reference.reference_id,
    transport_admission_id=admission.admission_id,
    egress_grant_id="REPLACE_WITH_ISSUED_GRANT_ID",
    provider_codec_id=codec.codec_id, supported_roles=(WorkerRole.REPORTER,),
    max_output_tokens=256,
)
config = ProviderProbeConfig(
    registration=registration, admission=admission,
    credential_reference=reference, codec=codec,
)
Path("provider-probe-config.json").write_text(config.model_dump_json(indent=2))
```

将 Key 通过本地凭据管理工具注入 Control Plane 进程所引用的那个环境变量。不要把值写进配置、命令参数、
仓库或聊天。凭据提供器只解析该引用；现有传输子进程通过有界内存帧接收凭据，不继承父进程完整环境。
这里复用现有环境变量凭据提供器，不新增系统 Keychain 集成。

## 准备和运行

prepare 不读取 Key、不做 DNS、不发送请求。输出的是待审阅的密封计划，最长窗口 300 秒且不能超过 grant：

```bash
vulnloom provider-probe-prepare \
  --config-file provider-probe-config.json \
  --egress-store .vulnloom/provider-egress \
  --probe-db .vulnloom/provider-probes.db \
  --idempotency-key provider-smoke-001 \
  --ttl-seconds 120 > provider-probe-plan.json
```

检查 prepare 退出码为 0 后再运行。run 必须显式选择 Provider 联网：

```bash
vulnloom provider-probe-run \
  --config-file provider-probe-config.json \
  --egress-store .vulnloom/provider-egress \
  --probe-db .vulnloom/provider-probes.db \
  --plan-file provider-probe-plan.json \
  --allow-provider-network
```

run 不接受自定义消息、Target、Scope、工具参数或原始 Key。固定消息允许的工具集合和调用预算均为零。
Responses 分支仅精确的 `complete` 测试响应能够通过；工具建议、blocked、额外引用、错误摘要、拒绝、超限和畸形响应均拒绝。

## 结果和失败处理

成功返回 0；拒绝或超时返回 1。输出仅包含密封结果身份、稳定状态、已校验的 token 计数、过程/清理标记、
attempt/receipt 摘要与完成时间。CLI 输入错误统一输出 `provider_probe_rejected`，不打印异常正文或 traceback。
`cleanup_verified=false` 表示出现了无法完整证明清理状态的异常，不得视为成功。

权威 probe ledger 对 plan、幂等键和 grant 加唯一约束。一份 grant 在该 ledger 只允许一次尝试：
成功、失败和超时均消费它；完成重放只读且仍要求当前授权和窗口有效。STARTED 表示中断或未完成写入，
必须人工核查和显式恢复，不能删除 ledger 或更换数据库路径来重试。需要新的尝试时应取得新的独立授权。

请求字节和输出 token 上限不是货币金额上限，服务商账户的费用配额仍须由运营方设置。模型调用可能计费，
即使本地响应验证失败。当前实现没有后台监控、自动重试、自动授权或失败后切换 Provider。

本地测试使用 fake DNS/process 和合成响应，不读取真实凭据、不连接公网 Provider。既有 opt-in loopback TLS
与 Phase 3 Admission 验证复用的传输边界；真实 Provider 兼容性、实际模型标识和账户配额仍须独立实测记录。


## M9.16：CUC 专用 Chat PONG 分支

接口信息由运营方提供；2026-09-07 固定 PONG 真实调用已验收通过，通用 CUC 模型适配器尚未实现：

| 项目 | 固定值 |
|---|---|
| 网关 | `https://openai.cuc.edu.cn` |
| 请求路径 | `/v1/chat/completions` |
| 请求模型 | `cuc/deepseek` |
| 可接受响应模型 | `deepseek-v4-flash`、`deepseek-v4-flash-0731` |
| 真实凭据引用 | `CUC_DEEPSEEK_API_KEY` |
| 单次请求 | `Reply with exactly PONG.`，非流式，输出上限 256 tokens |
| 默认预算 | 请求/响应各 32768 bytes，transport 10 秒，无重试 |

本分支直接使用受限 HTTPS transport，不连接本地 `codex-responses-shim`。`SHIM_DUMMY_KEY` 和
`PI_CUC_DEEPSEEK_APIKEY` 不是该分支的真实凭据引用。通用 Responses codec 的精确模型身份规则不变。
CUC 专用 codec 只处理固定 PONG，不能作为任意 Chat Completions Agent 接口使用。

运营方可先通过 `vulnloom.agent_runtime.provider_probe.cuc_probe_admission()` 读取并审阅完整的
固定端点与预算，再通过既有 Control Plane 流程独立签发对应 inference grant。该函数不读 Key、
不签发授权、不访问网络。提供已签发 grant 后，以下命令只读校验并输出无密钥配置：

```bash
vulnloom provider-cuc-probe-config \
  --egress-store .vulnloom/provider-egress \
  --grant-id REPLACE_WITH_ISSUED_GRANT_ID > cuc-probe-config.json
```

检查退出码为 0 后，用前述 `provider-probe-prepare` 和 `provider-probe-run`，将配置路径替换成
`cuc-probe-config.json`；仍需真实 Key 的环境注入、有效 grant、同一权威 probe ledger 和显式联网开关。
Key 不存在时不要运行或消费一次性 grant。命令不会从 shim 或其他项目搜集、复制凭据。

只接受单个 `assistant` 的内容在去除首尾空白后精确匹配 `PONG`、`PONG.`、`PONG!` 或反引号包裹的
`PONG`；同时必须满足 `finish_reason=stop`、有效用量和两个精确后端名。
模型名大小写变化、额外前后缀、请求别名作为响应名，以及工具调用/拒绝/多选择/截断响应均拒绝。
通过后，结果的 `response_model` 记录实际命中的白名单名称；返回正文与可选 reasoning 内容仍被丢弃。
已通过的 live-010 记录为 `response_content_punctuation_match`，不是字节级精确 PONG。
响应模型 `deepseek-v4-flash-0731`、输入 10 / 输出 4 tokens、receipt 非空、清理通过且 grant 已撤销。
结果 ID 为 `a204b843419035391ceb1e33e37e3280db60e1bcc29a09aa3327d8f0f340d3b8`；
完整脱敏结论与测试记录见 [PHASE3-ADMISSION.md](./PHASE3-ADMISSION.md)。

vLLM 空扩展和 usage 字段使用明确白名单；未知字段仍拒绝。性能指标只接受有界有限 int/float，
排除 bool/NaN/Infinity；token 计数必须为整数并满足总量等式。诊断只保存闭集分类、计数、
固定字段类型或未知 usage 键名 SHA-256，不记录正文、未知键名、字段值或凭据。
设置 Key 和 PONG 通过均不授予研究工具、研究目标网络或领域状态变更权限。
