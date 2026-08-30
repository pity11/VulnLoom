# Analyzer Execution Protocol

M6.4a defines the source-only analyzer protocol. M6.4b adds narrowly admitted real Checkov and
Kubesec execution through the existing Docker boundary.

## Sealed inputs

- An already verified `TargetSnapshot` present in an active approved Scope.
- One `AnalyzerToolRegistration` containing exact analyzer/tool versions, image ID, rules and
  Observation-adapter digests, absolute executable, complete argv, explicit safe environment, and
  a fixed output mode. The admitted M6.4b tools use bounded attached stdout.
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

`DockerAnalyzerExecutionService` accepts only the exact Checkov 3.3.15 and Kubesec 2.14.2 factory
registrations. The operator provisions an image outside execution; the plan then binds its inspected
image ID. Runtime uses `--pull never`, `network=none`, a read-only root and source mount, non-root
identity, no capabilities, no-new-privileges, bounded cgroup resources, and a secret-free exact
environment. The service has no image-pull or arbitrary-command API.

The Runner captures stdout into a bounded trusted temporary file while attached to the container.
It rejects empty, oversized, non-regular, symlinked, or digest-changing output and atomically
publishes a read-only content-addressed object before deleting the container. A failed or timed-out
run cannot publish an output reference. Checkov accepts only exit 0; the pinned Kubesec contract
accepts its finding exit 2 as well as 0, encoded on that one sealed Docker tool.

Successful bytes are immediately sealed as an `AnalyzerResultSnapshot` and passed to the existing
M6.3a adapter. The outer execution checkpoint becomes completed only after the M6.3a Observation
checkpoint and immutable artifact complete. Raw messages and rule identities remain outside the
outcome; it contains only the already-redacted Observation representation.

The Phase 3 admission workflow provisions versioned images, resolves them to exact IDs, and repeats
both end-to-end probes under the production rootless Linux policy. Local Docker Desktop runs are
functional regression evidence only, not production isolation qualification.

Trivy must use a sealed offline database. CodeQL database construction or any other target build
requires a separate exact `RUN_UNTRUSTED_BUILD` Approval and is outside M6.4b.

Analyzer output cannot directly create a Candidate or Finding and cannot replace Validation,
Critic, Evidence, duplicate, or human Approval gates.
