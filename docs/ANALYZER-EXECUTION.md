# Analyzer Execution Protocol

M6.4a defines the source-only analyzer execution boundary without running an analyzer.

## Sealed inputs

- An already verified `TargetSnapshot` present in an active approved Scope.
- One `AnalyzerToolRegistration` containing exact analyzer/tool versions, image ID, rules and
  Observation-adapter digests, absolute executable, complete argv, explicit safe environment, and
  the fixed output path `/workspace/output/output.json`.
- One `AnalyzerExecutionPlan` binding the Target manifest, Scope/policy, registration/registry,
  static Sandbox Profile, Runner request, deadline, and idempotency key.

There is no shell string, placeholder expansion, URL, image tag, pull operation, inherited host
environment, credential field, Docker socket, Broker call, or Submission field. The current mode is
only `source_only`; target builds are not representable.

## Offline semantics

`OfflineAnalyzerExecutionService` revalidates all Pydantic boundaries and Scope/Target provenance
before writing a STARTED checkpoint. It then uses `OfflineSandboxRunner`, which starts no process,
container, network, or analyzer. A successful lifecycle is named `protocol_completed` and its
`analyzer_result_snapshot` is always null.

The CLI command `analyzer-execution-check-offline` exists to exercise this contract. It does not
claim filesystem, process, container, or network isolation beyond the already-tested Runner model.

## Real execution admission

A later adapter must reuse the M4.3 rootless Docker boundary, materialize its `DockerTool` only from
the sealed registry argv, capture and integrity-check `output.json` before scratch cleanup, and feed
that sealed file through M6.3a. Checkov/Kubesec should be admitted before database-backed tools.
Trivy must use a sealed offline database. CodeQL database construction or any other target build
requires a separate exact `RUN_UNTRUSTED_BUILD` Approval and is outside M6.4a.

Analyzer output cannot directly create a Candidate or Finding and cannot replace Validation,
Critic, Evidence, duplicate, or human Approval gates.
