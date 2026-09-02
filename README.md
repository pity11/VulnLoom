# VulnLoom

VulnLoom is an in-development vulnerability research system for **explicitly authorized targets**. It currently ingests trusted local targets, maps Python Web source code, generates deterministic security Candidates, and provides controlled validation building blocks. The target product will validate Candidates in isolated environments, challenge them through an independent review step, and produce auditable report drafts for human review.

The goal is not autonomous exploitation of public targets. VulnLoom is designed to improve the recall, evidence quality, and reporting efficiency of white-box security research while enforcing scope, network boundaries, credential isolation, and human approval in code.

## Initial scope

- White-box analysis of Python Web and API projects.
- Planned controlled dynamic validation in local Docker Compose test environments.
- IDOR/BOLA, SSRF, path traversal, injection, insecure deserialization, authorization flaws, and sensitive data exposure.
- Planned human-reviewable report drafts for vendors, EduSRC, CNVD/CNNVD, and similar disclosure channels.
- No scanning of unauthorized public targets, automatic platform submission, or automatic CVE requests.

## Core principles

1. **A Candidate is not a Finding.** An agent may propose a candidate, but it only becomes a finding after reproducible evidence and an independent disproof check pass deterministic gates.
2. **The Control Plane owns privileged actions.** Workers do not receive platform credentials, change authorization scope, or submit reports.
3. **Every validation uses an ephemeral sandbox.** Source code is mounted read-only, output is stored separately, and network access is denied by default.
4. **Tools go through a Broker.** Agents receive typed, limited, and auditable capabilities instead of an unrestricted host shell.
5. **Evidence comes before narrative.** Every impact claim in a report must trace back to code, an observed request and response, or a reproducible test.
6. **Human approval is mandatory where it matters.** State-changing tests, external callbacks, real credentials, and report submission require explicit approval.

## Documentation

- [CONTEXT.md](./CONTEXT.md): domain terminology and shared language.
- [AGENTS.md](./AGENTS.md): mandatory engineering constraints for coding agents.
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md): layers, components, and deployment topology.
- [docs/WORKFLOW.md](./docs/WORKFLOW.md): agent orchestration, state machines, and verdict rules.
- [docs/SECURITY.md](./docs/SECURITY.md): sandbox, network, credential, attachment, and evidence security.
- [docs/DATA-MODEL.md](./docs/DATA-MODEL.md): core entities and domain events.
- [docs/ROADMAP.md](./docs/ROADMAP.md): milestones and acceptance criteria.
- [docs/PHASE3-ADMISSION.md](./docs/PHASE3-ADMISSION.md): reproducible M4.3 production-isolation admission evidence.
- [docs/EXTERNAL-BENCHMARKS.md](./docs/EXTERNAL-BENCHMARKS.md): supported upstream layouts and local-snapshot safety boundary.
- [docs/REFERENCE-PROJECTS.md](./docs/REFERENCE-PROJECTS.md): reference projects, adopted ideas, and rejected assumptions.

## Project layout

```text
VulnLoom/
├── src/vulnloom/
│   ├── adapters/           # Model-provider configuration boundary
│   ├── agent_runtime/      # Typed offline model replay and proposal boundary
│   ├── analyzers/          # Python AST and optional Semgrep analysis
│   ├── benchmark/          # Deterministic offline metrics and regression gates
│   ├── broker/             # Typed tool mediation and HTTP policy enforcement
│   ├── critic/             # Deterministic independent counterevidence review
│   ├── domain/             # Domain objects, state machines, and protocols
│   ├── evidence/           # Redaction, hashing, and evidence storage
│   ├── hypotheses/         # Deterministic Candidate generation
│   ├── ingestion/          # Archive, Git, and OCI target ingestion
│   ├── policy/             # Scope and approval enforcement
│   ├── reporting/          # Evidence-consistent offline report drafts
│   ├── runners/            # Offline and Docker sandbox runners
│   ├── storage/            # Event and validation persistence
│   ├── validation/         # Plans, orchestration, and deterministic judging
│   └── cli.py              # Current command-line entry point
├── benchmarks/             # Sealed local ground-truth fixtures and baselines
├── docs/                   # Architecture, workflow, security, and roadmap
├── schemas/                # Exported JSON Schema contracts
├── scripts/                # Schema and development utilities
└── tests/                  # Offline tests and opt-in integration probes
```

An HTTP API, live model-provider adapter, and disclosure submission adapters are planned components;
they are not present in the current tree. M7.1a-M8.10 include deterministic replay, fixed provider
messages, scoped credentials, isolated pinned HTTPS transport, typed Broker handoff, and a fixed
two-tool Session ledger, human-gated Validation/Critic/Finding Intakes, and Approval-gated promotion.
Benchmark and analyzer imports consume only sealed, pre-obtained local data and never fetch suites,
rules, databases, or images.

## First end-to-end path

The target end-to-end product path is deliberately narrow:

```text
Approved scope
→ Import one Python Web repository
→ Produce static security signals
→ Build a cross-file SourceGraph
→ Let a human select one Candidate
→ Start the test application in Docker
→ Validate the Candidate
→ Run an independent Critic
→ Produce a Markdown report draft
```

The current implementation reaches deterministic validation, Evidence bundling, independent counterevidence review, offline Evidence-backed report drafts, digest-bound human approval, approved local export, and an offline benchmark regression gate. External disclosure remains a separate future stage.

Public asset discovery, automatic submission, and general-purpose autonomous shell access remain out of scope until this path meets its precision, isolation, and evidence-retention goals.

## Current implementation

### Phase 0: domain and safety foundation

- Immutable Pydantic domain models and exported JSON Schema contracts.
- Separate Candidate state machine and deterministic Candidate-to-Finding gate.
- Scope Policy Engine and approvals bound to specific action digests.
- Evidence redaction, content addressing, and integrity verification.
- SQLite event log with idempotency conflict detection.
- Typed Control Plane/Worker protocol and an explicit Worker environment allowlist.
- `engagement-create`, `scope-approve`, and `status` CLI commands.
- An OpenAI-compatible model-provider configuration boundary; no network model call is made yet.

### M1: secure target ingestion

- Streaming, size-limited quarantine for ZIP and TAR artifacts.
- Member-by-member archive extraction without `extractall()`.
- Validation of normalized paths, symbolic links, special files, file counts, individual sizes, total expanded size, and compression ratio.
- Exact commit pinning for local Git repositories by reading Git objects without checkout, hooks, or target-code execution.
- Static classification of Kubernetes, Helm, Terraform, Dockerfile, and Compose files.
- Registration of OCI image references by `sha256` digest without pulling images or connecting to Docker.
- Atomic, read-only Target Snapshots with file-level SHA-256 manifests and idempotent reuse.
- Idempotent `TargetIngested` events; failures and timeouts do not leave partial snapshots.

### M2: Python Web Source Mapper

- Python AST indexing without importing or executing target code.
- Route discovery for Flask, FastAPI, Starlette, and Django.
- Structured functions, cross-file calls, authentication and authorization guards, ownership checks, dangerous sinks, and input-propagation paths.
- Content-addressed `SourceGraph` and `StaticSignal` output. A signal is a hypothesis for validation, never a Finding.
- File size and SHA-256 verification before analysis; tampering, path escape, resource-limit violations, and timeouts fail closed.
- Optional Semgrep adapter restricted to pre-registered local rules, with metrics and version checks disabled and no inherited API keys.
- Idempotent `SourceGraphBuilt` summary events. Full graphs are stored separately as read-only objects instead of being copied into the normal event log.
- Scope identity, version, and validity are rechecked before every source-mapping run.
- CI runs lint, schema-drift checks, and the full test suite on Python 3.12, 3.13, and 3.14.

### M3: deterministic Candidate generation

- Converts integrity-checked `SourceGraph` objects into typed, human-reviewable Candidates.
- Merges complementary signals for the same route and sink without treating analyzer output as a Finding.
- Maps supported sink classes to CWE, preconditions, a security invariant, and the cheapest disproof task.
- Binds every Candidate to the exact Target version, SourceGraph digest, Scope identity, and Scope version.
- Uses stable Candidate UUIDs and SHA-256 duplicate fingerprints; repeated generation is byte-stable.
- Excludes parse failures, visibly guarded object lookups, and external matches that cannot be classified safely.
- Stores each `CandidateSet` as an immutable content-addressed object and records only a redacted summary event.

### M4.1: sandbox contracts and offline runner

- Defines immutable Static, Validation, and Report sandbox profiles with non-root identities, fixed mount slots, network modes, and resource ceilings.
- Rejects writable roots, Linux capabilities, host-path mounts, unregistered writable paths, and profile-purpose mismatches at schema validation time.
- Binds every Worker task to an exact Target version, Scope identity, policy digest, and sandbox-profile digest.
- Accepts only typed registered-tool invocations with argument arrays and logical working directories—never arbitrary shell command strings.
- Provides a `SandboxRunner` adapter contract and a deterministic offline implementation for success, refusal, timeout, cancellation, resource exhaustion, checkpoint/resume, idempotency, and cleanup paths.

### M4.2: Tool Broker and typed HTTP

- Adds an immutable capability registry whose digest is bound into every queued Worker task.
- Requires a tool to be present in the Registry, Task allowlist, and Sandbox Profile while also matching the current Scope, policy digest, and Worker role.
- Accepts HTTP methods, normalized credential-free URLs, safe headers, opaque credential/body references, and explicit time/size/redirect budgets—never raw credentials or request bodies.
- Derives state-changing behavior from the HTTP method in trusted code and requires exact, unexpired approvals for mutations and credential use.

- Reauthorizes every redirect, resolves every hop, pins the selected IP, verifies the reported peer, and rejects loopback, link-local metadata, multicast, unspecified, mixed-dangerous, and configured host-gateway addresses.
- Returns only policy records, URL digests, peer metadata, Evidence IDs, final response-body SHA-256 digests, and budget usage; raw response bodies and sensitive headers stay outside the normal result path.
- Uses deterministic offline resolver and transport adapters. No real HTTP request or network isolation claim is introduced in M4.2.

### M4.3: ephemeral Docker Runner

- Adds a trusted Docker CLI adapter that uses argument arrays only; Workers never receive the Docker socket or the host process environment.
- Resolves content mounts through a Control Plane-owned registry, pins exact image IDs, disables pulls, and replaces image entrypoints with registered absolute tool executables.
- Applies and re-inspects a read-only root, non-root UID/GID, dropped capabilities, `no-new-privileges`, seccomp, no network, resource limits, read-only content, and bounded `noexec,nosuid,nodev` tmpfs mounts.
- Kills timed-out Workers, removes containers and anonymous storage, and refuses to report a normal result unless absence is verified.
- Includes opt-in real-container probes for isolation, secret non-inheritance, timeout, and cleanup.
- Adds a live Broker-owned HTTP/HTTPS transport that connects directly to the policy-selected IP, preserves the authorized hostname for HTTP Host and TLS verification, ignores proxy environment variables, verifies the actual peer, and enforces response limits.
- Binds the selected resolver and transport implementation digest into the Tool Registry; queued work is rejected if offline and live adapters are swapped.
- Resolves request bodies by content digest and credentials through separate opaque providers; neither raw material is copied into Broker results or HTTP Evidence metadata.
- Stores only redacted response transcripts in the Evidence Store. Sensitive response headers, raw URLs, credential material, binary bodies, email addresses, and JSON-shaped secrets are excluded or redacted.
- Requires rootless mode, seccomp, cgroup v2, and enforceable memory, CPU-quota, and PID controls by default. Engines that only advertise partial isolation fail closed before container creation.
- Discovers daemon-managed network gateways for the Broker denylist. Docker Workers reject direct `target_only` networking and remain network-disabled; authorized target access belongs to the trusted Broker.
- A dedicated Ubuntu 24.04 admission workflow runs Docker Engine 29.7.2 as a delegated rootless user service and proves Worker isolation from a live sibling container and daemon gateway, host-gateway denial before Broker transport, redirect-time DNS rebinding rejection, deterministic validation, timeout handling, and cleanup.

### M4.4: transactional Validation Orchestrator

- Seals each human-selected Candidate content digest, exact Target/Scope provenance, networkless Runner request, and bounded Broker calls into a content-addressed `ValidationPlan`.
- Rechecks Candidate state, current Scope validity, policy digest, Validator role, profile digest, and Candidate input binding before writing a `STARTED` checkpoint.
- Runs the sandbox step before Broker calls, stops on the first non-completed result, and maps denials, missing approvals, timeouts, and failures to fail-closed domain outcomes.
- Persists one idempotent `ValidationOutcome` in SQLite. Completed plans replay without re-execution; an interrupted `STARTED` plan requires explicit recovery and is never retried automatically.
- Separates execution from verdict. The production default remains `INCONCLUSIVE`; only a trusted deterministic judge may return `REPRODUCED`, and it may cite only Evidence IDs collected by that run.
- Produces an `EvidenceBundle` and advances `Candidate` only through the existing state machine. It cannot create or promote a `Finding`.
- Adds `validation-run-offline`, which exercises the control-plane path without target execution, Broker calls, sockets, or a reproduced claim.

### M4.5: deterministic HTTP assertions

- Adds a content-addressed `HttpResponseAssertion` selected before execution and bound to one exact Broker call.
- Requires both an exact HTTP status and SHA-256 of the raw final response body. Status-only checks cannot produce a reproduced verdict.
- Keeps raw response bodies out of Broker results; only the body digest, bounded metadata, and redacted Evidence reference cross the trusted boundary.
- Adds `DeterministicHttpJudge`: by default it trusts only the live pinned HTTP Registry; an exact match returns the precommitted `REPRODUCED` or `NOT_REPRODUCED` result, while an offline Registry or any mismatch remains `INCONCLUSIVE`.
- Verifies every Evidence object through a no-follow, size-bounded, content-integrity read before judging or sealing an `EvidenceBundle`.
- Adds an opt-in composition probe covering a real ephemeral Docker Validator, a Broker-owned pinned HTTP connection to a temporary authorized fixture, Evidence capture, exact verdict, state transition, and cleanup.
- The composition probe also passes in the dedicated rootless Linux admission workflow. Local Docker Desktop runs retain an explicit rootful test-only exception and cannot independently qualify production.

### M5.1: deterministic Critic and independent disproof review

- Seals Candidate, reproduced ValidationRun, EvidenceBundle, Scope version, validation context, and a distinct review context into a content-addressed `CriticPlan`.
- Requires separate validation and review producers and assesses security controls, reachability, environment parity, and version binding exactly once.
- Uses a fixed reducer: confirmed counterevidence rejects; any inconclusive angle leaves the Candidate validated but unpromotable; only four evidence-backed ruled-out angles advance it to `CRITIC_REVIEWED`.
- Rechecks every referenced Evidence object with no-follow, size, digest, and Target-version validation before changing state.
- Persists STARTED/COMPLETED SQLite checkpoints, returns completed outcomes idempotently, and refuses unfinished automatic replay.
- Performs no target execution, Broker call, network access, report submission, or Finding promotion. The final promotion gate separately rechecks current Scope, reproduced-run Evidence coverage, Critic binding, and duplicate review.

### M5.2: Evidence-consistent offline report drafts

- Seals the Finding, promoted Candidate, approved EvidenceBundle, Scope version, channel, bounded narrative, and exact section citations into a content-addressed `ReportDraftPlan`.
- Requires code-location, request/response, reproduction, and impact claims to cite Evidence IDs from the Finding's bundle; every bundled Evidence object is rechecked for no-follow access, size, digest, and Target version.
- Redacts report text before persistence, escapes active HTML and Markdown image/link syntax, and never copies Evidence bodies into the draft.
- Renders deterministic generic, EduSRC, CNVD, vendor, and CVE-draft headings to immutable local Markdown and JSON artifacts.
- Uses STARTED/COMPLETED SQLite checkpoints, content-addressed artifact directories, bounded writes, idempotent completed replay, fail-closed recovery, and temporary-output cleanup.
- Produces only `draft` review status. It has no network adapter, platform credential, approval mutation, or submission path.

### M5.3: human review, revision diff, and approved local export

- Groups report revisions into a stable Finding/channel family and binds every version after the first to the exact preceding Report digest.
- Produces deterministic structured diffs for consecutive redacted revisions, including text and Evidence-reference changes; unchanged, unrelated, skipped, or unredacted revisions are rejected.
- Seals the exact Report digest, artifact digest, EvidenceBundle, Scope version, reviewer, diff, decision deadline, and approval expiry into typed review protocol objects.
- Applies only explicit `approve`, `request_changes`, or `reject` commands through the Control Plane state machine. Any content or citation change invalidates the sealed request.
- Allows local export only from `human_approved`, before approval expiry, with an exact ReviewRecord and artifact match. Local export writes a new immutable Markdown/JSON artifact with `exported` status.
- Adds offline `report-review-diff`, `report-review-offline`, and `report-export-local` CLI paths. None has a network or Submission adapter.

### M6.1: deterministic offline benchmark and regression gate

- Seals local benchmark cases, ground-truth Findings, pipeline observations, policies, and baselines as typed content-addressed objects.
- Rejects any observed Finding that did not pass reproduced Validation, accepted independent Critic review, Candidate promotion, and complete Evidence gates.
- Computes Candidate recall, Finding precision, duplicate rate, Evidence completeness, policy violations, elapsed time, total cost, and cost per Finding with deterministic reducers.
- Applies absolute thresholds and exact-suite baseline comparisons, emitting stable violation codes and a failing CLI exit status for CI.
- Persists STARTED/COMPLETED SQLite checkpoints and immutable local JSON/Markdown results with bounded no-follow reads and temporary-output cleanup.
- Includes a generated local microbenchmark and baseline in `benchmarks/m6_1`; ordinary CI verifies fixture drift and runs the offline regression gate.
- Adds `benchmark-evaluate-offline`. It consumes only sealed local files and has no Runner, Broker, network, credential, or Submission dependency.

### M6.2: external benchmark local-snapshot adapters

- Adds versioned BountyBench and AutoPenBench adapters for pre-obtained local directory snapshots; neither adapter accepts a URL or downloads data.
- Seals every regular file by normalized path, size, and SHA-256, rejects symlinks and special files, and enforces file-count, per-file, total-size, and deadline budgets before and after normalization.
- Reads only `bounty_metadata.json` labels from BountyBench. Prompt, report, exploit, setup, patch, and verification contents are never copied into normalized suites.
- Reads AutoPenBench `data/games.json` in trusted code but persists only safe identities; task text and flags are discarded. CWE labels must come from a sealed `vulnloom-autopenbench-cwe.json` sidecar.
- Emits typed exclusions for unsupported or missing labels and rejects malformed JSON, duplicate keys, stale mappings, ambiguous identities, adapter drift, and snapshot mutation.
- Stores normalized suites as immutable local objects with transactional import checkpoints and adds `benchmark-snapshot-manifest-local` and `benchmark-import-offline`.

### M6.3a: unified precomputed analyzer observations

- Normalizes local CodeQL SARIF 2.1.0, Trivy JSON, Checkov JSON, and Kubesec JSON through versioned adapters without running those tools.
- Seals the Target/version, tool version, rules digest, result digest, optional CWE mapping, adapter digest, resource limits, deadline, and idempotency key.
- Persists only rule/message digests, normalized CWEs, severity, and safe relative locations; it discards raw messages, secret matches, and Kubernetes object identities.
- Keeps analyzer observations structurally separate from pipeline `BenchmarkObservation`: they cannot carry Candidate, Validation, Critic, or Finding state.
- Adds `analyzer-result-manifest-local` and `analyzer-observations-import-offline`; neither command accepts a URL or executes a binary.

### M6.3b: explicit cross-analyzer evaluation

- Requires a sealed, explicit Observation-to-ground-truth alignment; matching CWE labels alone never count as a detection.
- Revalidates case, Target version, ObservationSet digest, truth ownership, and CWE compatibility before creating a checkpoint.
- Computes overall and per-analyzer truth recall, observation precision, duplicate rate, and exclusion rate for CodeQL, Trivy, Checkov, and Kubesec.
- Supports required-analyzer and full case-matrix gates plus exact-suite baseline regressions; per-analyzer checks prevent aggregate results from hiding one tool's regression.
- Includes `benchmarks/m6_3`, fixture-drift checks, and `run_m6_3_regression_gate.py` in ordinary CI.
- Adds `analyzer-evaluate-offline`, which creates only local immutable JSON/Markdown results and cannot alter Candidate or Finding state.
- Accepts directories only. ZIP/TAR acquisition and extraction remain outside this adapter; callers must use an independently hardened quarantine path before presenting a directory.

### M6.4: sealed analyzer execution

- Runs exact Checkov, Kubesec, Trivy, and CodeQL registrations through the hardened Docker Runner with inspected image IDs, `--pull never`, `network=none`, read-only inputs/root, non-root identity, bounded resources, and mandatory cleanup.
- Captures analyzer output within a trusted byte limit and completes the outer checkpoint only after the existing M6.3a adapter creates redacted Observations.
- Restricts Trivy to its sealed read-only DB v2 and vulnerability scanner; DB/check/Java/VEX updates, secret scanning, telemetry, and version checks are disabled.
- Binds CodeQL 2.26.2 to a Target/version/Manifest and one sealed prebuilt DB/query snapshot. A narrow wrapper copies the DB into bounded tmpfs because CodeQL writes query results, while the original DB and query pack remain read-only and are reverified after cleanup.
- Does not expose analyzer/package downloads, arbitrary commands, Target builds, Candidate/Finding promotion, or Submission. CodeQL database construction remains separately `RUN_UNTRUSTED_BUILD` Approval-gated.

### M7.1a: offline typed Agent Runtime

- Seals an exact offline replay implementation, provider/model identity, supported Worker roles, and
  output ceiling in a content-addressed registration.
- Binds each run to an exact `TaskEnvelope`, context and decision-schema digests, step/token/wall
  budgets, deadlines, and an idempotency key.
- Validates untrusted structured decisions and returns only terminal summary digests or a typed,
  argument-digest-only tool intent. It never executes the proposed tool.
- Persists transactional STARTED/COMPLETED checkpoints without raw model output or raw tool arguments;
  interrupted calls require explicit recovery and are not replayed automatically.
- Uses no model socket, SDK, endpoint, credential, Runner, Broker, Approval, domain transition, or
  Submission path.

### M7.1b: credential lease and local fake provider

- Replaces direct API-key string resolution with an initialization-time allowlisted,
  content-addressed reference to one explicit Control Plane environment variable.
- Holds secret bytes only in a non-serializable lease that is zeroed on success, exception, and
  timeout-result paths.
- Adds a registration-bound local fake adapter to test provider identity and credential lifecycle
  without a socket, URL, SDK, proxy, or inherited environment.
- Keeps the credential value and unrelated environment entries out of Worker requests, outcomes,
  checkpoints, schemas, and error messages.

### M7.2: sealed and bounded model context

- Requires transient context sources to match the Task's ordered input references exactly.
- Normalizes and redacts content in trusted code, rejects unsafe controls, and enforces fragment,
  total-byte, count, deadline, and wall-clock limits.
- Stores only explicitly untrusted, redacted fragments in immutable content-addressed snapshots bound
  to the exact Task, Target, Scope, references, and redaction policy.
- Revalidates no-follow, regular-file, read-only, size, schema, identity, and digest properties on
  every stored read; failed publication removes temporary files.
- Binds only the context snapshot ID into Agent run plans and step requests. It performs no provider,
  network, tool, Approval, or domain-state action; the Runtime reloads the snapshot before creating
  its STARTED checkpoint.

### M7.3: fixed provider-message envelopes

- Maps every Worker role to one built-in, content-addressed system template; callers cannot supply
  system text or template versions.
- Renders canonical strict JSON with typed control metadata separated from escaped, explicitly
  untrusted context fragments.
- Binds the plan, Task/context/model/template/schema, Target/Scope digests, tool allowlist, budgets,
  step, and messages into one envelope ID sealed into the step request.
- Rejects duplicate keys, template/system/control/trust drift, request mismatch, byte overages, and
  rendering timeouts before the first model call.
- Passes messages transiently to offline adapters while checkpoints and adapter audit lists retain
  only digests. Prompt text remains non-authoritative; Runtime/Broker enforce permissions.

### M7.4: provider transport admission protocol

- Adds a content-addressed admission object for one exact provider hostname, TLS port, canonical
  path, credential reference, adapter digest, request/response limits, and timeout.
- Fixes redirects and proxies off, DNS revalidation on, raw-response persistence off, one attempt,
  and `network_enabled=false`; schema validation rejects any relaxation.
- Derives a digest-only transport request from the exact StepRequest and Message Envelope, while the
  serialized message body exists only in a zeroed transient buffer.
- Exercises credential acquisition, bounded response capture, strict JSON parsing, identity checks,
  typed rejection/timeout outcomes, receipts, and cleanup through an in-memory admission fake.
- Stores only request/response digests, counts, identities, stable status, and cleanup proof. It opens
  no DNS, socket, HTTP, SDK, proxy, tool, Approval, or Submission path.

### M7.5: subprocess-pinned HTTPS provider transport

- Adds a fixed `subprocess_https_provider` adapter with a content-bound implementation digest; no
  caller-supplied executable, argv, header, URL, proxy, retry, or SDK is accepted.
- Separates production `live_https` admissions (exact port 443 and global-only DNS) from
  `loopback_https_probe` admissions (`.test`, loopback-only, and a sealed test CA).
- Re-resolves the exact hostname for every request, rejects mixed or forbidden answers, pins one
  numeric IP, and verifies the connected peer, TLS 1.2+ version, SNI, and hostname.
- Sends credential and message bytes over a fixed binary stdin frame to an isolated Python process
  launched with `-I`, `/` cwd, closed file descriptors, a tiny environment, no shell, bounded
  stdout, discarded stderr, resource limits, and forced process-group cleanup.
- Allows one POST to one canonical path, forbids redirects and encoded responses, applies header/body
  and parent/child wall limits, and records only peer digests, TLS version, counters, and cleanup.
- Enforces a sealed per-minute rate limit with no automatic retry. Live transport remains library-only
  and no public provider is contacted by CI; Phase 3 uses a real loopback TLS subprocess probe.

### M7.6: issued provider-egress lifecycle

- Adds content-addressed issuer policies that limit exact provider IDs, networked transport modes,
  and grant lifetimes; no-network fake modes cannot receive an egress grant.
- Issues immutable grants bound to one transport Admission, credential reference, adapter, purpose,
  issuer, validity window, and idempotency key, then binds the exact grant ID into model registration.
- Atomically publishes read-only grant/revocation objects and records STARTED/COMPLETED issuance and
  revocation checkpoints in a transactional lifecycle ledger.
- Reopens and verifies the grant, ledger state, expiry, and exact Admission binding before every DNS
  lookup, rate slot, credential lease, or child process. Revoked, expired, unfinished, linked,
  writable, malformed, or drifted grants fail closed.
- Keeps the authority local and library-only. It adds no remote signer, provider SDK/codec, public
  provider call, arbitrary URL, tool execution, Approval consumption, or Submission capability.

### M7.7: sealed OpenAI Responses codec

- Adds a content-addressed `openai-responses-v1` codec bound into every subprocess HTTPS model
  registration and to the exact admitted `/v1/responses` path.
- Emits only fixed non-streaming, non-stored requests with disabled truncation and the registered
  strict Agent decision JSON Schema; callers cannot add tools, metadata, sessions, or parameters.
- Accepts only one completed assistant `output_text` with exact model identity and typed usage, then
  strictly parses it as `AgentDecisionPayload`. Incomplete, refusal, tool-call, duplicate-key,
  oversized, timed-out, and protocol-drift responses fail closed.
- Keeps provider-native tool execution disabled. A structured tool proposal remains an inert intent
  that must pass the existing Runtime and Broker enforcement boundaries.
- Uses offline golden fixtures and the existing opt-in loopback TLS process probe; CI does not call a
  public provider or use a real provider credential.

### M7.8: typed Agent intent handoff to Tool Broker

- Binds one authoritative completed Agent run and digest-only tool intent to an independently built,
  exact typed `BrokerCall`; no model text is translated into executable parameters.
- Restricts handoff to Validator tasks and rechecks Task, Scope, Policy, Sandbox Profile, Tool
  Registry, tool budget, call commitment, deadline, and Agent checkpoint before dispatch.
- Leaves all network, DNS pinning, credentials, side-effect, and Approval enforcement inside the
  existing Tool Broker. The Agent never receives a socket, Docker handle, secret, or adapter.
- Adds transactional STARTED/COMPLETED handoff checkpoints. Only an approval-required first attempt
  can be retried once with a new exact Broker call and independently verified Approval.
- Converts every completed Broker result into a digest-only `AgentToolObservation` containing typed
  counts and Evidence references, never raw Agent arguments, URLs, credentials, or response bodies.
- Tests both offline state-machine paths and an opt-in live pinned-Broker composition against a
  temporary authorized service; no public target, Candidate/Finding transition, or Submission is added.

### M7.9: sealed Tool Observation continuation

- Derives one new Validator Task from an authoritative completed Agent → Broker chain while
  preserving the exact engagement, Target/version, Scope/version, Policy, Profile, Registry, model,
  and absolute deadline bindings.
- Fixes the derived Task to an empty tool allowlist and `tool_calls=0`; the one-step continuation may
  finish as complete or blocked, while another tool proposal becomes a terminal failure.
- Reopens each exact Evidence ref through the content-addressed Evidence Store, re-redacts it, and
  rebuilds the same bounded read-only context snapshot before any provider call. Observation and
  Evidence text remain explicitly untrusted model context.
- Accounts for tokens, prior steps, the consumed Broker call, and remaining wall time in a typed
  budget ledger. Exhaustion, expiry, authority drift, missing Evidence, or incomplete cleanup fails
  before the continuation checkpoint.
- Adds a unique-Observation STARTED/COMPLETED SQLite lifecycle with idempotent completed replay and
  fail-closed conflict/recovery. Its rows contain only typed outcomes and digests, never Evidence,
  provider response, URL, credential, Candidate/Finding, or Submission content.
- Phase 3 composes the real isolated loopback TLS provider, real pinned Broker, redacted Evidence
  Store, and zero-tool continuation against a temporary authorized target; no public egress is used.

### M7.10: sealed fixed two-tool Agent session

- Adds a content-addressed `AgentSessionPlan`, cumulative token/step/tool/provider/Broker budget
  ledger, and SQLite lifecycle around one already completed tool round, one optional second tool
  round, and one mandatory zero-tool terminal continuation.
- Derives the second Validator Task with the exact inherited Target/Scope/Policy/Profile/Registry,
  model, and absolute deadline, while shrinking all budgets and fixing the total session to at most
  three provider turns and two consumed tool calls.
- Exposes only a trusted, content-addressed `AgentAuthorizedCallSet` in message control. Each option
  is a Control-Plane-built exact read-only `BrokerCall` commitment; the model cannot construct or
  alter URL, method, headers, body, credential, network, or authorization fields.
- Reopens every Agent, handoff, Observation, Evidence, and context checkpoint before the next
  action. Unlisted or duplicate commitments, drift, exhausted budgets, missing cleanup, and a third
  tool proposal fail closed without another Broker call.
- Pauses an Approval-required second handoff without polling or approving it. One explicit,
  Approval-bound M7.8 retry may resume the session; its extra Broker attempt is counted even though
  the total successful tool-call budget remains exactly two.
- Phase 3 uses three isolated loopback provider subprocesses and two exact pinned-Broker reads of a
  temporary authorized target. No public target/provider, arbitrary loop, target build, domain-state
  transition, report export, or Submission path is introduced.

### M7.11: immutable Agent session audit and deterministic projection

- Reopens the authoritative Session, Agent run, handoff, continuation and Evidence stores before
  producing one content-addressed `AgentSessionAuditBundle`; callers cannot provide a transcript or
  substitute a model-generated summary.
- Recomputes ordered round identities, exact call commitments, Approval decision digests,
  Target/Scope provenance, cumulative token/step/tool/provider/Broker budgets and cleanup proofs.
- Projects only `completed`, `blocked`, `failed` or `timed_out` with a stable reason code and verified
  Evidence refs. The recommendation is not a Candidate/Finding/Report transition or an authorization.
- Publishes bounded, read-only JSON/Markdown containing only digests, IDs, typed counts and statuses;
  it never copies Evidence bodies, URLs, credentials, provider requests/responses or tool parameters.
- Uses a separate SQLite STARTED/COMPLETED checkpoint with idempotent completed replay and fail-closed
  conflict/recovery. Artifact failure cleans temporary files and refuses automatic replay.
- Extends the loopback Phase 3 composition by creating the audit from the real M7.10 session and
  proving a tampered chain is rejected without adding runtime network or execution authority.

### M8.1: human Validation Intake and sealed plan binding

- Reopens the immutable M7.11 Audit artifact and CandidateSet, then binds their exact digests to a
  Control-Plane-built typed `ValidationPlan`; no Agent prose or Evidence body becomes a request.
- Accepts only a human `accept`, `reject`, or `defer` command bound to the exact Audit, Candidate and
  Validation plan. A blocked, failed or timed-out recommendation cannot be accepted.
- Produces only a digest-only immutable decision record. The service has no Runner or Broker and
  does not queue Validation, mutate Candidate state, consume Approval, build a Target or submit data.
- Uses an independent STARTED/COMPLETED SQLite ledger; drift, expiry, duplicate consumption,
  conflicting decisions and unfinished recovery fail closed.

### M8.2: completed Validation outcome provenance binding

- Runs only after an explicit existing Validation entry point has completed; it cannot execute,
  resume, retry, queue, approve, or alter that Validation.
- Reopens the accepted Intake, Audit artifact, CandidateSet, exact Validation checkpoint, current
  Scope and every referenced Evidence object before creating a binding checkpoint.
- Recomputes Runner/Broker identities, ordered calls, forced timeout/policy results, run accounting,
  final Candidate state and EvidenceBundle consistency; drift fails closed.
- Persists only IDs, digests, typed result/state and timestamps in a unique STARTED/COMPLETED ledger.
  Idempotent replay is read-only and conflicting Intake/plan/outcome consumption is rejected.
- Does not call a Runner, Broker, provider, Docker, network, Approval, Target build, Critic, Finding,
  report export, public target, or Submission path.

### M8.3: human Critic Intake and sealed plan binding

- Reopens a reproduced M8.2 binding, Audit artifact, CandidateSet, completed Validation checkpoint
  and Evidence before binding one independently constructed exact `CriticPlan`.
- Accepts only explicit human accept, reject or defer commands. Acceptance records selection but does
  not execute the Critic, mutate Candidate state, create a review/Finding, or export a report.
- Persists only IDs, digests, typed decisions and timestamps; conflict, expiry, drift and unfinished
  recovery fail closed without Runner, Broker, provider, network, Approval or Submission access.

### M8.4: completed Critic outcome provenance binding

- Runs only after the accepted M8.3 exact `CriticPlan` has completed through the existing explicit
  deterministic Critic entry point; the binding service cannot invoke, retry or recover Critic.
- Reopens the M8.2 binding, Validation checkpoint, Evidence, Critic plan/outcome and current Scope,
  validating review identity, independent context, ruleset, counterevidence, rationale and time.
- Enforces the exact verdict/state mapping: accepted to `CRITIC_REVIEWED`, rejected to `REJECTED`,
  inconclusive to unchanged `VALIDATED`.
- Persists only IDs, digests, typed verdict/state and timestamps in a unique STARTED/COMPLETED ledger.
  It does not mutate the original Candidate or create a Finding, report, build, Approval or Submission.

### M8.5: human Finding promotion Intake

- Requires an accepted M8.4 binding, exact critic-reviewed Candidate, reproduced Validation and
  Evidence provenance, accepted CriticReview, and the authoritative store's unique latest,
  content-addressed duplicate-clear proof.
- Binds one trusted-control-plane-built exact `FindingPromotionPlan`; Agent prose, Critic rationale
  and Evidence content cannot construct root-cause, affected-version, impact or severity fields.
- Records only an explicit human accept, reject or defer selection in a digest-only checkpoint.
  Acceptance does not call Candidate promotion, create a Finding, mutate state or draft a report.
- Drift, expiry, duplicate results, non-accepted Critic verdicts, conflicting consumption and
  unfinished recovery fail closed without Runner, Broker, provider, network or Submission access.

### M8.6: Approval-gated deterministic Finding promotion

- Requires both an unexpired accepted M8.5 record and a granted `MUTATE_TARGET_STATE` Approval bound
  to the exact Intake record, PromotionPlan, Candidate, Finding ID, Scope and two declared effects.
- Reopens the complete Validation, Evidence, Critic, duplicate-check and Intake provenance chain,
  then calls only the existing pure Candidate-to-Finding state transition.
- Atomically records the promoted immutable Candidate and verified Finding in a unique
  STARTED/COMPLETED result ledger. Completed replay is idempotent; conflicts and unfinished recovery
  fail closed.
- Agent output cannot supply Approval or promotion fields, and the service has no Runner, Broker,
  provider, build, public-network, report-generation or Submission capability.

### M8.7: human Report Intake

- Requires one completed, sealed M8.6 promotion outcome containing a promoted Candidate and verified
  Finding, plus the authoritative reproduced Validation and EvidenceBundle provenance.
- Binds a trusted-control-plane-built exact `ReportDraftPlan`, including report family, channel and
  complete Evidence-cited sections. This first version accepts only version 1 drafts and persists
  only IDs, digests, typed decision and timestamps.
- Accepts only explicit human accept, reject or defer. Acceptance does not draft a Report, read report
  prose into an Agent context, export an artifact, approve disclosure or create a Submission.
- Plan drift, missing or altered promotion checkpoints, Evidence corruption, expiry, conflicts and
  unfinished recovery fail closed without Runner, Broker, provider, target or network calls.

### M8.8: accepted Intake deterministic local draft binding

- Requires an unexpired human-accepted M8.7 record and reopens the complete M8.6, Critic,
  Validation, Evidence and exact `ReportDraftPlan` provenance chain before drafting.
- Seals the ordered typed Evidence catalog into a digest-only execution plan, then invokes only the
  existing deterministic offline report service with trusted control-plane inputs.
- Produces one immutable local report artifact that remains `DRAFT`, plus a prose-free outcome
  binding. It cannot approve, export or submit the report, mutate Candidate/Finding state, build a
  target, or access Runner, Broker, provider or network capabilities.
- Drift, expiry, non-accepted Intake, pre-existing unbound drafts, conflicts and unfinished
  checkpoints fail closed. Completed execution is read-only and idempotent.

### M8.9: human Report review Intake

- Reopens one completed M8.8 binding, its exact DRAFT Report and immutable artifact, plus the same
  ordered typed Evidence catalog used for drafting.
- Binds a trusted-control-plane-built exact `ReportReviewPlan`; human input is limited to accepting,
  rejecting or deferring entry into the later review operation.
- Persists only IDs, digests, typed selection and timestamps. Acceptance does not call the review
  service or change the Report from `DRAFT`, and grants no report approval or export authority.
- Artifact/Evidence corruption, plan drift, expiry, conflicts and unfinished recovery fail closed
  without Runner, Broker, provider, target, network, export or Submission access.

### M8.10: Approval-gated deterministic Report review

- Requires an unexpired accepted M8.9 record, an independently issued exact human
  `ReportReviewCommand`, and a granted `REVIEW_REPORT` Approval bound to that command and its single
  expected state effect.
- Reopens the M8.8 DRAFT, artifact, Evidence catalog and M8.9 checkpoint before invoking only the
  existing deterministic human-review state machine.
- Records the resulting review in the existing authoritative store and publishes a prose-free
  outcome binding. The source DRAFT remains immutable; completed replay is read-only and idempotent.
- Missing/revoked Approval, decision or provenance drift, expiry, pre-existing unbound reviews and
  unfinished recovery fail closed. No report export, public network or Submission capability is
  present.

## Local development

VulnLoom requires Python 3.12 or later.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest --cov=vulnloom --cov-report=term-missing
.venv/bin/python scripts/export_schemas.py
.venv/bin/python scripts/export_benchmark_fixtures.py
.venv/bin/python scripts/run_m6_1_regression_gate.py
.venv/bin/python scripts/export_analyzer_evaluation_fixtures.py
.venv/bin/python scripts/run_m6_3_regression_gate.py

# Optional; requires a local Alpine 3.22 image and Docker engine.
VULNLOOM_DOCKER_INTEGRATION=1 .venv/bin/pytest tests/test_runner_docker_integration.py

# Optional; opens one temporary loopback-only HTTP server.
VULNLOOM_SOCKET_INTEGRATION=1 .venv/bin/pytest tests/test_live_http_integration.py

# Optional; combines one real Docker Worker and one temporary authorized HTTP fixture.
VULNLOOM_COMPOSITION_INTEGRATION=1 \
  .venv/bin/pytest tests/test_validation_composition_integration.py
```

## Basic usage

Target ingestion requires an approved Scope that is still valid and explicitly includes either the artifact digest or the Git URL and commit.

```bash
vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  artifact-quarantine --engagement-id <uuid> --source source.zip

# Add the returned source_name, kind, and artifact_id to a Scope,
# then have that Scope approved by an authorized reviewer.
vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  target-ingest-archive --scope-file scope.json --source source.zip

vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  target-ingest-git --scope-file scope.json --source /local/repo \
  --repository-url https://example.invalid/project.git --commit <full-commit>

vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  target-register-image --scope-file scope.json \
  --image-ref ghcr.io/example/app --digest sha256:<digest>

# Build an offline Python Web SourceGraph from a verified filesystem snapshot.
vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  source-map --snapshot-id <manifest-sha256> --scope-file scope.json \
  --analysis-store .vulnloom/analysis

# Generate deterministic validation hypotheses. This does not execute or validate them.
vulnloom --db .vulnloom/events.db \
  candidate-generate --graph-id <graph-sha256> --scope-file scope.json \
  --analysis-store .vulnloom/analysis --candidate-store .vulnloom/candidates

# Exercise a pre-sealed ValidationPlan through the offline control-plane path.
# The plan must not contain Broker calls.
vulnloom --db .vulnloom/events.db \
  validation-run-offline --scope-file scope.json \
  --candidate-store .vulnloom/candidates \
  --candidate-set-id <candidate-set-sha256> --candidate-id <candidate-uuid> \
  --plan-file validation-plan.json --validation-db .vulnloom/validation.db \
  --evidence-store .vulnloom/evidence

# Compare two consecutive, already-redacted Report revisions without network access.
vulnloom report-review-diff --before report-v1.json --after report-v2.json

# Apply a pre-sealed human decision to an immutable local Report artifact.
vulnloom --db .vulnloom/events.db report-review-offline \
  --scope-file scope.json --artifact-file report-artifact.json \
  --evidence-bundle-file evidence-bundle.json --evidence-catalog-file evidence.json \
  --review-plan-file review-plan.json --review-command-file review-command.json

# Mark an exactly approved Report as locally exported. This never sends it anywhere.
vulnloom --db .vulnloom/events.db report-export-local \
  --scope-file scope.json --artifact-file approved-artifact.json \
  --review-record-file review-record.json --export-plan-file export-plan.json

# Evaluate a sealed local benchmark. Exit status 2 means the regression gate failed.
vulnloom benchmark-evaluate-offline \
  --suite-file suite.json --observations-file observations.json \
  --plan-file benchmark-plan.json --benchmark-db .vulnloom/benchmarks.db \
  --result-store .vulnloom/benchmark-results

# Seal an already-present local BountyBench directory without executing its files.
vulnloom benchmark-snapshot-manifest-local \
  --source /local/bountytasks --kind bountybench \
  --upstream-revision <full-commit> --license-spdx Apache-2.0

# Normalize a sealed local external snapshot. The plan binds the manifest and adapter digest.
vulnloom benchmark-import-offline \
  --source /local/bountytasks --snapshot-file snapshot.json \
  --plan-file import-plan.json --import-db .vulnloom/benchmark-imports.db \
  --suite-store .vulnloom/benchmark-suites

# Seal a precomputed local analyzer output and optional explicit CWE map.
vulnloom analyzer-result-manifest-local \
  --output codeql.sarif --analyzer codeql --target-id <uuid> \
  --target-version <exact-version> --tool-version <version> \
  --rules-digest <sha256> --cwe-map analyzer-cwe.json

# Normalize the sealed file without running the analyzer.
vulnloom analyzer-observations-import-offline \
  --output codeql.sarif --cwe-map analyzer-cwe.json \
  --snapshot-file analyzer-snapshot.json --plan-file analyzer-plan.json

# Evaluate sealed analyzer observations against an explicit reviewed alignment.
vulnloom analyzer-evaluate-offline \
  --suite-file suite.json --alignment-file alignment.json \
  --observation-set-file codeql-observations.json \
  --observation-set-file trivy-observations.json \
  --plan-file analyzer-evaluation-plan.json

# Validate a sealed source-only analyzer execution plan without running the tool.
vulnloom --store .vulnloom/targets analyzer-execution-check-offline \
  --scope-file scope.json --snapshot-id <manifest-sha256> \
  --registration-file analyzer-registration.json \
  --plan-file analyzer-execution-plan.json
```

`validation-run-offline` accepts an already sealed, typed `ValidationPlan`. It rejects plans containing Broker calls, does not execute target code or open sockets, and defaults to an `INCONCLUSIVE` verdict. Live Broker/Docker composition currently exists as a library and opt-in integration-test path, not as a production CLI or HTTP API.

The report review commands accept only sealed JSON contracts and content-addressed local objects. `report-export-local` changes the Report to `exported` only inside the local store; it has no destination URL, disclosure adapter, or `submitted` transition. Benchmark evaluation consumes precomputed typed pipeline observations. External benchmark and analyzer imports only normalize pre-obtained local data. `analyzer-execution-check-offline` validates the sealed M6.4a control-plane contract but deliberately produces no analyzer output. M6.4b-d add library-only, exact-image, network-disabled Checkov/Kubesec/Trivy/CodeQL execution, and every output must pass the same M6.3a import boundary. M6.5 requires a complete, content-bound execution matrix before invoking M6.3b; M6.6 proves that four-analyzer composition in rootless Admission, including missing-cell and drift refusal. No CLI path installs or runs analyzers.

## Model credential boundary

`ModelProviderConfig.credential_reference` identifies one explicit Control Plane environment variable without containing its value. M7.1b-M7.6 resolve it into a short-lived, zeroed Control Plane lease. M7.5 passes its bytes only to a one-shot isolated HTTPS child over a bounded stdin frame; M7.6 requires an active, exact, operator-issued egress grant before the credential is read. The Worker never receives the reference or value. Keys never appear in `TaskEnvelope`, Worker environments, Agent requests, checkpoints, event logs, or Evidence summaries. `.env.example` lists variable names only, and real `.env` files are ignored by Git.

## Safety status

VulnLoom is under active development. The current release provides the trusted domain foundation, secure local target ingestion, offline static source mapping, deterministic Candidate generation, a hardened Docker adapter, live pinned Broker transport, transactional validation orchestration, deterministic HTTP assertions, redacted Evidence storage, offline benchmark gates, precomputed multi-analyzer normalization, sealed Checkov/Kubesec/Trivy/CodeQL execution, execution-to-evaluation qualification, and a typed Agent Runtime with scoped credential leases, sealed context/messages, subprocess-pinned HTTPS transport, operator-issued egress lifecycle enforcement, exact Agent-to-Broker handoff, sealed Observation continuation, and a fixed two-tool Session ledger, plus opt-in probes for real containers, analyzers, sockets, and full validation composition.

Live Docker/Broker validation, the report workflow, and provider transport are exposed through typed library paths, not a production HTTP API or provider CLI. The rootless Linux and OS-level egress admission gate passes; provider transport is qualified only against a local TLS fixture, not a public provider. External disclosure/CVE submission workflows, provider-specific response adapters, and dedicated Kubernetes, Terraform, or Helm vulnerability analyzers are not implemented yet.

Use VulnLoom only on systems, source code, and test environments for which you have explicit authorization.
