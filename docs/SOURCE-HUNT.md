# Source Hunt V1

Source Hunt is VulnLoom's trusted local white-box workflow. It operates only on an already-ingested,
authorized `TargetSnapshot`; it does not clone repositories, access public targets, or invoke a model by
itself.

## Implemented vertical slice

```text
approved Snapshot + Scope
  → integrity-checked Python/JavaScript/TypeScript navigation index
  → bounded, resumable investigation
  → redacted on-demand source windows
  → PROPOSED Candidate
  → exact Build/Harness/Fuzz/Sanitizer/PoV sandbox plan
  → Approval Gate + isolated Runner
  → Evidence + ValidationRun
  → independent Critic
  → approval-bound Finding
  → evidence-backed report draft
```

The application services are provider-neutral and reusable by a future HTTP API. An `SourceInvestigator`
adapter receives only typed observations; provider credentials and network transport remain behind the
trusted model adapter boundary. A failed model decision does not mutate the investigation checkpoint.

Repository processing is bounded by file count, aggregate bytes, per-file bytes, partition size, query
count, observation count, and deadlines. Source files are not copied into the index. Each requested source
window is opened beneath the exact materialized Snapshot without following symlinks, checked against its
manifest size and SHA-256, limited to a small line/byte window, and redacted before persistence or model
exposure.

Candidate materialization is deliberately one-way into the shared domain: Source Hunt can create only a
`PROPOSED` Candidate. Validation requires a fixed five-stage plan and exact `RUN_UNTRUSTED_BUILD`
approval. Promotion re-reads the authoritative Validation and Critic stores and requires a separate exact
`MUTATE_TARGET_STATE` approval; a proposal or model response cannot directly create a Finding.

Every successful execution stage must also publish exactly one typed, content-addressed receipt. Receipts
form a digest chain beginning at the Candidate digest. Fuzz receipts require non-zero coverage and a Crash
fingerprint; Sanitizer and PoV receipts must preserve that fingerprint, and the final receipt must explicitly
prove independent replay. Free-form logs can accompany a receipt but cannot substitute for one.

R9 adds a sealed native tool registry and a strict `vulnloom.source-tool-report.v1` adapter. The trusted
adapter rejects duplicate JSON keys, registry/image/argv/environment drift, excess output, raw prose, and
incomplete Crash identity before generating the stage receipt. A Crash Signature is computed from the
sanitizer, failure class, signal, and normalized address-free top frames; the triggering input digest is kept
separate so different inputs for the same defect deduplicate into one transactional Crash record.

The fixed native Benchmark compiles an intentionally vulnerable C fixture, uses observed prefix coverage to
grow the triggering input, requires a genuine ASAN heap-buffer-overflow, repeats the input in the sanitizer
stage, and replays it again in a fresh PoV container. The resulting PoV artifact binds Candidate, input,
Crash Signature, sanitizer, execution and Benchmark case. Closing and reopening the execution and Crash
stores before qualification is covered by the offline regression suite.

## Local CLI contract

The `vulnloom source-hunt` command contains the stable local control surface:

- `start`, `query`, `status`, `complete`, `cancel`, and `expire` manage investigation checkpoints;
- `materialize-candidate` validates a typed proposal and writes an immutable CandidateSet;
- `prepare-execution` creates the fixed, deterministic sandbox plan and reports the required approval
  digest.

`prepare-execution` accepts an image digest and tool-registry digest, never an arbitrary command. Actual
execution is intentionally deployment-owned: the trusted Control Plane must provide registered
`source.build`, `source.harness`, `source.fuzz`, `source.sanitizer`, and `source.pov_replay` adapters plus an
approval record. The default test suite uses the fake Runner; the opt-in Docker test proves the complete
five-container isolation and cleanup boundary without accessing a network.

The native fixed-Benchmark acceptance is opt-in and never pulls an image during execution:

```bash
docker build --platform linux/amd64 --network none --pull=false \
  -f tests/fixtures/r9_native/Dockerfile -t vulnloom-r9-native:local .
VULNLOOM_R9_NATIVE_INTEGRATION=1 \
  .venv/bin/pytest -q tests/test_source_hunt_docker_integration.py -k real_native
```

The Runner keeps `/tmp` non-executable. Only an Approval-gated Validation profile with
`execute_target_code=true` receives an executable, bounded `/workspace/output` tmpfs; Static and Report
profiles retain `noexec`. The source mount and root filesystem remain read-only.

## Current boundary

V1 completes the safe Source Hunt orchestration and shared Candidate-to-report evidence chain. R9 now also
closes its fixed-Benchmark acceptance with a dedicated C coverage/ASAN adapter, persistent Crash
deduplication, and independently replayed PoV qualification. A1.1 now provides the offline-tested trusted
Project Recipe Registry and Approval-bound Build→Test orchestration described in `PROJECT-RECIPES.md`; it has
not yet passed real Docker project admission. The Python adapter provides AST navigation;
JavaScript/TypeScript currently provides conservative navigation only. UBSAN/MSAN variants, automatic harness
synthesis, patch generation, and blind-holdout quality gates remain later depth work and must not be inferred
from the fixed Benchmark adapter or A1.1.

No Source Hunt command accepts a Provider secret, full private endpoint, disclosure token, or raw
Authorization response. Network integration and real model calls remain explicit, disabled-by-default
activities outside this workflow.

## Next development sequence

Source Hunt 的当前后续顺序以 `docs/DEVELOPMENT-PLAN.md` 为准：S1 已关闭，A1.1 已完成 Registry 与离线执行
合同；下一步是本地无网络 Docker recipe Admission，再推进 JavaScript/TypeScript 深度、受限 Harness 与更多
运行时证据、Blind Holdout 质量门禁，以及只读 Patch proposal 和双重复测。固定 native Benchmark 或 A1.1
离线结果不得外推为通用项目自动构建或广泛漏洞发现能力。
