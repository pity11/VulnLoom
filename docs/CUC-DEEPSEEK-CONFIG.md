# CUC DeepSeek configuration

This document configures a locally supplied CUC API key without storing the
credential in Git. It also records the exact endpoint and model identities that
VulnLoom accepts.

## Fixed provider contract

| Setting | Value |
| --- | --- |
| Base URL | `https://openai.cuc.edu.cn/v1` |
| Request endpoint | `POST /v1/chat/completions` |
| Requested model | `cuc/deepseek` |
| Accepted response models | `deepseek-v4-flash`, `deepseek-v4-flash-0731` |
| Real credential variable | `CUC_DEEPSEEK_API_KEY` |

The CUC gateway is configured as an OpenAI-compatible **Chat Completions**
provider. Do not point a Responses-only client directly at `/v1/responses`.
Such a client needs a separately reviewed Responses-to-Chat shim.

The response `model` field is an upstream implementation identity, not the
requested alias. Identity validation must use the explicit mapping above; do
not disable the check or accept arbitrary prefixes.

## Create the private environment file

From the repository root:

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` locally and set only the value after the equals sign:

```dotenv
CUC_DEEPSEEK_API_KEY=PASTE_THE_NEW_KEY_HERE
```

Do not put the key in this document, `.env.example`, command history, issue
text, test fixtures, logs, or model context. `.env` and `.env.*` are ignored by
Git; `.env.example` is the intentionally tracked exception.

For a generic Control Plane integration, read these non-secret values from the
same file:

```dotenv
VULNLOOM_MODEL_BASE_URL=https://openai.cuc.edu.cn/v1
VULNLOOM_MODEL_NAME=cuc/deepseek
```

`VULNLOOM_MODEL_API_KEY` is retained for the future generic provider adapter.
The current VulnLoom CUC probe intentionally reads only
`CUC_DEEPSEEK_API_KEY`. Do not copy either credential into a Worker environment.

## Load the configuration safely

VulnLoom does not implicitly parse `.env`. Supply `CUC_DEEPSEEK_API_KEY` to the
Control Plane through a local credential manager or a bounded dotenv parser.
Only select the referenced variable; do not evaluate the file as shell code or
export its entire contents. A file loader should check ownership, private file
permissions, regular-file/no-symlink status, size and duplicate definitions.
Do not enable shell tracing (`set -x`) or put credentials in command arguments.

## Minimal connectivity check

Use the built-in grant-bound workflow in [PROVIDER-PROBE.md](./PROVIDER-PROBE.md).
It sends only the fixed synthetic PONG message with no project source,
Candidate, Evidence or arbitrary user prompt. The accepted response text, after
trimming whitespace, is exactly one of: `PONG`, `PONG.`, `PONG!`, or backtick-wrapped
`PONG`. The response model must match one of the two exact identities above.
No raw response is printed or saved; use the sealed result and closed diagnostics.

As of 2026-09-07, live-010 passed with `deepseek-v4-flash-0731`, a non-null receipt,
validated usage and verified cleanup. Content classified as
`response_content_punctuation_match`. The single-use grant was revoked.
This validates the fixed PONG probe, not a general CUC Chat adapter or research
workflow. See [PHASE3-ADMISSION.md](./PHASE3-ADMISSION.md) for the evidence record.

## VulnLoom's built-in probe boundary

### Separate fixed JSON compatibility probe

`provider-cuc-probe-config --structured` selects the independent
`cuc-chat-structured-probe-v1` contract. It uses the same required `--egress-store`
and `--grant-id` arguments and does not issue a grant, read a credential, or call
the provider. Its output is consumed by the existing `provider-probe-prepare`
and explicitly opted-in `provider-probe-run` commands documented in
[PROVIDER-PROBE.md](./PROVIDER-PROBE.md).

The only request is a code-owned synthetic prompt asking for
`{"status":"ok","count":3}`. The response must be a JSON object with exactly
these fields and values; key order and JSON whitespace may vary. Markdown,
duplicate keys, extra fields, numeric coercion, tool instructions and nonempty
wire-level tool calls are rejected. The response schema, prompt and wire contract
are bound into a separate codec digest and fixture identity. A PONG plan or
result cannot be reused as structured acceptance.

Both modes retain the existing single-request ledger, explicit inference grant,
bounded HTTPS process transport, redacted diagnostics and cleanup checks.
Completed replay does not call the provider again; interrupted execution requires
explicit recovery. Results persist only acceptance metadata, not model content.

**Status:** live acceptance passed on 2026-09-08 in one user-authorized request
(`cuc-structured-live-001`): HTTP 200, TLSv1.3, response model
`deepseek-v4-flash-0731`, validated input/output usage 34/10 tokens, non-null
receipt and verified cleanup. The single-use grant was revoked and no retry was
made. Sealed configuration, plan, result and the one completed ledger entry were
rechecked offline. See [PHASE3-ADMISSION.md](./PHASE3-ADMISSION.md).
This is a fixed schema compatibility probe, not a general Chat adapter,
arbitrary-prompt interface, or research workflow integration. The earlier live
PONG acceptance remains unchanged.

### PONG boundary

VulnLoom already contains a fixed, tool-free CUC PONG codec at
`src/vulnloom/agent_runtime/provider_probe_cuc.py`. It pins the hostname,
endpoint, requested model, accepted response identities, request size, response
size, timeout, and rate limit. Running it additionally requires a valid,
explicit model-inference egress grant; setting the environment variable alone
does not create that authority.

See [PROVIDER-PROBE.md](./PROVIDER-PROBE.md) for the grant-bound prepare/run
workflow. Until a general CUC adapter is admitted, do not use the probe codec as
an arbitrary Chat Completions interface.

## Preflight without exposing the key

The following checks file presence and permissions without loading or printing
its contents. The credential loader must separately validate that the referenced
variable is populated before a live request.

```bash
test -f .env
test ! -L .env
test "$(stat -f '%Lp' .env 2>/dev/null || stat -c '%a' .env)" = 600
```

Before committing, confirm that the private file remains untracked:

```bash
git status --short --ignored .env .env.example
```

Expected behavior: `.env` is ignored and `.env.example` is tracked.
