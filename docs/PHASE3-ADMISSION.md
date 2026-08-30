# Phase 3 Admission Record

## Decision

**PASS.** M4.3 satisfies the production-isolation prerequisites for beginning Phase 3. This decision
does not claim that the Critic, Finding orchestration, or report generation already exists.

The baseline admission run is GitHub Actions
[`33307142075`](https://github.com/pity11/VulnLoom/actions/runs/33307142075) for commit
`9bc669f8e123c8f48e47c690c33559b6014e9e92`. The standard Python CI for the same commit is
[`33307142076`](https://github.com/pity11/VulnLoom/actions/runs/33307142076). Both completed
successfully on 2026-08-30.

## Enforced admission criteria

| Boundary | Required proof | Result |
|---|---|---|
| Engine | Rootless daemon, seccomp, cgroup v2, memory limit, CPU quota, and PID limit support | PASS |
| Worker identity | Non-root UID/GID, no capabilities, `NoNewPrivs`, no inherited host secret | PASS |
| Filesystem | Read-only root and source, bounded hardened tmpfs, no Docker socket | PASS |
| Worker network | No default route; cannot reach a live sibling container or daemon gateway | PASS |
| Broker gateway policy | Actual daemon gateways discovered and denied before transport | PASS |
| DNS rebinding | Redirect hop is re-resolved; metadata-address drift is denied before a second socket | PASS |
| Timeout and cleanup | Timed-out Worker is killed; container and anonymous storage absence is verified | PASS |
| Full composition | Rootless Runner, pinned Broker, redacted Evidence, deterministic judge, state transition, and cleanup | PASS |
| Analyzer execution | Versioned Checkov/Kubesec resolved to exact image IDs, network-disabled source-only execution, bounded output, M6.3a import, and cleanup | Enforced for M6.4b runs |

## Reproduction

The admission workflow is [`.github/workflows/phase3-admission.yml`](../.github/workflows/phase3-admission.yml).
It installs pinned Docker Engine 29.7.2 packages on Ubuntu 24.04, runs the daemon as a delegated
systemd user service, pulls the test fixture image before execution, and then runs all real isolation
and composition probes with the production-default `DockerEnginePolicy`.

Local Docker Desktop probes remain useful regression checks, but their explicit rootful test-only
exception cannot replace this admission workflow.

Beginning with M6.4b, the same workflow provisions Checkov 3.3.15 and Kubesec 2.14.2 before the
test phase, then runs both through `DockerAnalyzerExecutionService`. Provisioning may access the
registry; the tested runtime path uses the inspected image ID, `--pull never`, and `network=none`.
The historical M4.3 PASS above remains unchanged; the new row is considered PASS only after the
updated workflow succeeds for the M6.4b commit.
